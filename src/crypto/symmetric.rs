use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use lru::LruCache;
use rand::{rngs::OsRng, TryRngCore};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;

use super::DerivedKeyMaterial;

#[derive(Debug, Error)]
pub enum SymmetricError {
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Invalid ciphertext length")]
    InvalidCiphertextLength,
    #[error("Nonce reuse detected - potential replay attack")]
    NonceReuse,
    #[error("Nonce counter overflow - session must be rekeyed")]
    NonceCounterOverflow,
}

/// SymmetricCrypto provides AES-256-GCM encryption with counter-based nonces.
///
/// Uses a 4-byte random session prefix combined with an 8-byte counter to form
/// the 12-byte GCM nonce. This prevents nonce reuse catastrophes that can occur
/// with purely random nonces.
pub struct SymmetricCrypto {
    cipher: Aes256Gcm,
    /// 4-byte random prefix unique to this session, combined with counter for nonce
    session_prefix: [u8; 4],
    /// Atomic counter for nonce generation - prevents nonce reuse
    nonce_counter: AtomicU64,
}

impl SymmetricCrypto {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        // Generate a random 4-byte session prefix for nonce construction
        let mut session_prefix = [0u8; 4];
        OsRng
            .try_fill_bytes(&mut session_prefix)
            .expect("OS RNG failure");
        Self {
            cipher,
            session_prefix,
            nonce_counter: AtomicU64::new(0),
        }
    }

    /// Generate a counter-based nonce: [4-byte session prefix][8-byte counter]
    fn generate_nonce(&self) -> Result<[u8; 12], SymmetricError> {
        // Use fetch_add to atomically increment and get the previous value
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        if counter == u64::MAX {
            return Err(SymmetricError::NonceCounterOverflow);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.session_prefix);
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        Ok(nonce)
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        let nonce_bytes = self.generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SymmetricError::EncryptionFailed)?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, SymmetricError> {
        if data.len() < 12 + 16 {
            return Err(SymmetricError::InvalidCiphertextLength);
        }

        let nonce = Nonce::from_slice(&data[0..12]);
        let ciphertext = &data[12..];

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| SymmetricError::DecryptionFailed)?;

        Ok(plaintext)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFrame {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedFrame {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(12 + self.ciphertext.len());
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(&self.ciphertext);
        output
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SymmetricError> {
        if data.len() < 12 + 16 {
            return Err(SymmetricError::InvalidCiphertextLength);
        }

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[0..12]);
        let ciphertext = data[12..].to_vec();

        Ok(Self { nonce, ciphertext })
    }
}

/// Maximum number of seen nonces to track for replay detection.
const MAX_SEEN_NONCES: usize = 100_000;

pub struct SessionCrypto {
    encryptor: SymmetricCrypto,
    decryptor: SymmetricCrypto,
    outbound_seq: AtomicU64,
    inbound_seq: AtomicU64,
    /// LRU cache for replay detection. Uses write lock for atomic check-and-insert.
    seen_nonces: Arc<RwLock<LruCache<[u8; 12], ()>>>,
}

impl SessionCrypto {
    pub fn from_key_material(key_material: &DerivedKeyMaterial) -> Self {
        let (enc_key, dec_key) = key_material.split();
        let encryptor = SymmetricCrypto::new(enc_key.expose_secret());
        let decryptor = SymmetricCrypto::new(dec_key.expose_secret());

        Self {
            encryptor,
            decryptor,
            outbound_seq: AtomicU64::new(0),
            inbound_seq: AtomicU64::new(0),
            seen_nonces: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(MAX_SEEN_NONCES).unwrap(),
            ))),
        }
    }

    pub fn encrypt_outbound(&self, plaintext: &[u8]) -> Result<EncryptedFrame, SymmetricError> {
        // Use the encryptor's generate_nonce() to get proper session prefix + counter
        let nonce_bytes = self.encryptor.generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .encryptor
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SymmetricError::EncryptionFailed)?;

        // Maintain outbound_seq for monitoring/metrics
        self.outbound_seq.fetch_add(1, Ordering::SeqCst);

        Ok(EncryptedFrame {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    pub fn decrypt_inbound(&self, frame: &EncryptedFrame) -> Result<Vec<u8>, SymmetricError> {
        {
            let mut seen = self.seen_nonces.write().unwrap_or_else(|e| e.into_inner());
            if seen.peek(&frame.nonce).is_some() {
                tracing::warn!("Nonce reuse detected - potential replay attack");
                return Err(SymmetricError::NonceReuse);
            }
            seen.put(frame.nonce, ());
        }

        let nonce = Nonce::from_slice(&frame.nonce);

        let result = self
            .decryptor
            .cipher
            .decrypt(nonce, frame.ciphertext.as_ref());

        // Always increment counter regardless of success/failure for timing consistency
        self.inbound_seq.fetch_add(1, Ordering::SeqCst);

        match result {
            Ok(plaintext) => Ok(plaintext),
            Err(_) => {
                // Decryption failed - remove the reserved nonce slot so legitimate
                // retransmissions of the same nonce can still be processed
                let mut seen = self.seen_nonces.write().unwrap_or_else(|e| e.into_inner());
                seen.pop(&frame.nonce);
                Err(SymmetricError::DecryptionFailed)
            }
        }
    }

    pub fn outbound_seq(&self) -> u64 {
        self.outbound_seq.load(Ordering::SeqCst)
    }

    pub fn inbound_seq(&self) -> u64 {
        self.inbound_seq.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DerivedKeyMaterial;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = b"Hello, world!";

        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_empty() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = b"";

        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_large() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = vec![0u8; 64 * 1024];

        let ciphertext = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_decrypt_invalid_tag() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = b"Hello, world!";

        let mut ciphertext = crypto.encrypt(plaintext).unwrap();
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;

        let result = crypto.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = b"Hello, world!";

        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let truncated = &ciphertext[..10];

        let result = crypto.decrypt(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_crypto_roundtrip() {
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let key_material_alice = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let key_material_bob = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let alice = SessionCrypto::from_key_material(&key_material_alice);
        let bob = SessionCrypto::from_key_material(&key_material_bob);

        let plaintext1 = b"First message";
        let plaintext2 = b"Second message";

        let frame1 = alice.encrypt_outbound(plaintext1).unwrap();
        let frame2 = alice.encrypt_outbound(plaintext2).unwrap();

        let decrypted1 = bob.decrypt_inbound(&frame1).unwrap();
        let decrypted2 = bob.decrypt_inbound(&frame2).unwrap();

        assert_eq!(plaintext1, decrypted1.as_slice());
        assert_eq!(plaintext2, decrypted2.as_slice());

        assert_eq!(alice.outbound_seq(), 2);
        assert_eq!(bob.inbound_seq(), 2);
    }

    #[test]
    fn test_encrypted_frame_serialization() {
        let frame = EncryptedFrame {
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            ciphertext: vec![
                13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
            ],
        };

        let bytes = frame.to_bytes();
        let restored = EncryptedFrame::from_bytes(&bytes).unwrap();

        assert_eq!(frame.nonce, restored.nonce);
        assert_eq!(frame.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_different_nonces() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);
        let plaintext = b"Hello, world!";

        let ct1 = crypto.encrypt(plaintext).unwrap();
        let ct2 = crypto.encrypt(plaintext).unwrap();

        assert_ne!(ct1[0..12], ct2[0..12]);
    }

    #[test]
    fn test_session_crypto_nonce_format_validation() {
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let alice = SessionCrypto::from_key_material(&alice_km);
        let bob = SessionCrypto::from_key_material(&bob_km);

        let plaintext = b"Test message for nonce validation";

        // Alice encrypts a message
        let frame = alice.encrypt_outbound(plaintext).unwrap();

        // Verify nonce structure: [4-byte session prefix][8-byte counter]
        assert_eq!(frame.nonce.len(), 12);

        // Extract counter from bytes 4-11
        let counter_bytes: [u8; 8] = frame.nonce[4..12].try_into().unwrap();
        let counter = u64::from_le_bytes(counter_bytes);
        assert_eq!(counter, 0); // First message has counter 0

        // CRITICAL: Bob decrypts Alice's message with swapped keys
        let decrypted = bob.decrypt_inbound(&frame).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Send another message - verify counter increments and prefix stays same
        let frame2 = alice.encrypt_outbound(plaintext).unwrap();
        let counter_bytes2: [u8; 8] = frame2.nonce[4..12].try_into().unwrap();
        let counter2 = u64::from_le_bytes(counter_bytes2);
        assert_eq!(counter2, 1); // Second message has counter 1

        // Session prefix should remain constant
        assert_eq!(&frame.nonce[0..4], &frame2.nonce[0..4]);

        // Bob can decrypt second message
        let decrypted2 = bob.decrypt_inbound(&frame2).unwrap();
        assert_eq!(plaintext, decrypted2.as_slice());
    }

    #[test]
    fn test_unique_session_prefixes() {
        // Verify different SessionCrypto instances have different session prefixes
        // even with the same keys (prevents nonce collision across sessions)
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);

        let session1 = SessionCrypto::from_key_material(&km);
        let session2 = SessionCrypto::from_key_material(&km);

        let plaintext = b"Test";

        let frame1 = session1.encrypt_outbound(plaintext).unwrap();
        let frame2 = session2.encrypt_outbound(plaintext).unwrap();

        // Extract session prefixes
        let prefix1 = &frame1.nonce[0..4];
        let prefix2 = &frame2.nonce[0..4];

        // Different instances should have different random session prefixes
        // Note: there's a 1 in 4 billion chance this fails spuriously
        assert_ne!(prefix1, prefix2, "Session prefixes should be unique");
    }

    #[test]
    fn test_nonce_replay_protection() {
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let alice = SessionCrypto::from_key_material(&alice_km);
        let bob = SessionCrypto::from_key_material(&bob_km);

        let plaintext = b"Message to replay";

        // Alice sends message
        let frame = alice.encrypt_outbound(plaintext).unwrap();

        // Bob decrypts successfully the first time
        let decrypted = bob.decrypt_inbound(&frame).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());

        // Replay attack: send same frame again
        let replay_result = bob.decrypt_inbound(&frame);

        // Should fail with NonceReuse error
        assert!(replay_result.is_err());
        match replay_result {
            Err(SymmetricError::NonceReuse) => {
                // Expected - replay protection working
            }
            _ => panic!("Expected NonceReuse error on replay attack"),
        }
    }

    #[test]
    fn test_high_volume_unique_nonces() {
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);

        let session = SessionCrypto::from_key_material(&km);

        let plaintext = b"Test";
        let mut seen_nonces = std::collections::HashSet::new();

        // Generate 10,000 frames and verify all nonces are unique
        for i in 0..10_000 {
            let frame = session.encrypt_outbound(plaintext).unwrap();

            // Verify nonce is unique
            assert!(
                seen_nonces.insert(frame.nonce),
                "Duplicate nonce at iteration {}",
                i
            );

            // Verify counter is incrementing correctly
            let counter_bytes: [u8; 8] = frame.nonce[4..12].try_into().unwrap();
            let counter = u64::from_le_bytes(counter_bytes);
            assert_eq!(counter, i as u64);
        }

        assert_eq!(seen_nonces.len(), 10_000);
    }

    #[test]
    fn test_bidirectional_communication() {
        // Test full bidirectional communication between Alice and Bob
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let alice = SessionCrypto::from_key_material(&alice_km);
        let bob = SessionCrypto::from_key_material(&bob_km);

        // Alice -> Bob
        let msg1 = b"Hello Bob";
        let frame1 = alice.encrypt_outbound(msg1).unwrap();
        let decrypted1 = bob.decrypt_inbound(&frame1).unwrap();
        assert_eq!(msg1, decrypted1.as_slice());

        // Bob -> Alice
        let msg2 = b"Hello Alice";
        let frame2 = bob.encrypt_outbound(msg2).unwrap();
        let decrypted2 = alice.decrypt_inbound(&frame2).unwrap();
        assert_eq!(msg2, decrypted2.as_slice());

        // Alice -> Bob again
        let msg3 = b"How are you?";
        let frame3 = alice.encrypt_outbound(msg3).unwrap();
        let decrypted3 = bob.decrypt_inbound(&frame3).unwrap();
        assert_eq!(msg3, decrypted3.as_slice());

        // Verify sequence counters
        assert_eq!(alice.outbound_seq(), 2);
        assert_eq!(alice.inbound_seq(), 1);
        assert_eq!(bob.outbound_seq(), 1);
        assert_eq!(bob.inbound_seq(), 2);
    }

    #[test]
    fn test_out_of_order_delivery() {
        // Test that out-of-order frames are handled correctly (no replay protection issue)
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];
        let alice_km = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let bob_km = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);

        let alice = SessionCrypto::from_key_material(&alice_km);
        let bob = SessionCrypto::from_key_material(&bob_km);

        // Alice sends 3 messages
        let msg1 = b"Message 1";
        let msg2 = b"Message 2";
        let msg3 = b"Message 3";

        let frame1 = alice.encrypt_outbound(msg1).unwrap();
        let frame2 = alice.encrypt_outbound(msg2).unwrap();
        let frame3 = alice.encrypt_outbound(msg3).unwrap();

        // Bob receives them out of order: 2, 1, 3
        let dec2 = bob.decrypt_inbound(&frame2).unwrap();
        assert_eq!(msg2, dec2.as_slice());

        let dec1 = bob.decrypt_inbound(&frame1).unwrap();
        assert_eq!(msg1, dec1.as_slice());

        let dec3 = bob.decrypt_inbound(&frame3).unwrap();
        assert_eq!(msg3, dec3.as_slice());
    }
}
