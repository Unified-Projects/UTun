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
    /// This is safe for GCM as long as the session prefix is unique per key
    /// and the counter doesn't overflow (2^64 messages per session is plenty).
    fn generate_nonce(&self) -> Result<[u8; 12], SymmetricError> {
        // Use fetch_add to atomically increment and get the previous value
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);

        // Check for overflow (extremely unlikely but safety first)
        if counter == u64::MAX {
            return Err(SymmetricError::NonceCounterOverflow);
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.session_prefix);
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        Ok(nonce)
    }

    fn nonce_from_counter(counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0..8].copy_from_slice(&counter.to_le_bytes());
        nonce
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

    pub fn encrypt_with_counter(
        &self,
        plaintext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, SymmetricError> {
        let nonce_bytes = Self::nonce_from_counter(counter);
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

    pub fn decrypt_with_counter(
        &self,
        data: &[u8],
        _counter: u64,
    ) -> Result<Vec<u8>, SymmetricError> {
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
///
/// This should be large enough to cover the expected reordering window in
/// the network path. For most applications, 100,000 provides ample margin.
/// At 1 million packets/second, this covers 100ms of traffic.
///
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
        // Use expose_secret() to access the underlying key bytes
        // The wrapper types will zeroize memory when they go out of scope
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
        let seq = self.outbound_seq.fetch_add(1, Ordering::SeqCst);
        let nonce_bytes = SymmetricCrypto::nonce_from_counter(seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .encryptor
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| SymmetricError::EncryptionFailed)?;

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
            // Reserve the nonce slot atomically with the check
            seen.put(frame.nonce, ());
        }

        let nonce = Nonce::from_slice(&frame.nonce);

        let plaintext = match self
            .decryptor
            .cipher
            .decrypt(nonce, frame.ciphertext.as_ref())
        {
            Ok(pt) => pt,
            Err(_) => {
                // Decryption failed - remove the reserved nonce slot so legitimate
                // retransmissions of the same nonce can still be processed
                let mut seen = self.seen_nonces.write().unwrap_or_else(|e| e.into_inner());
                seen.pop(&frame.nonce);
                return Err(SymmetricError::DecryptionFailed);
            }
        };

        self.inbound_seq.fetch_add(1, Ordering::SeqCst);

        Ok(plaintext)
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
    fn test_counter_mode() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext1 = b"Message 1";
        let plaintext2 = b"Message 2";
        let plaintext3 = b"Message 3";

        let ct1 = crypto.encrypt_with_counter(plaintext1, 0).unwrap();
        let ct2 = crypto.encrypt_with_counter(plaintext2, 1).unwrap();
        let ct3 = crypto.encrypt_with_counter(plaintext3, 2).unwrap();

        let pt1 = crypto.decrypt_with_counter(&ct1, 0).unwrap();
        let pt2 = crypto.decrypt_with_counter(&ct2, 1).unwrap();
        let pt3 = crypto.decrypt_with_counter(&ct3, 2).unwrap();

        assert_eq!(plaintext1, pt1.as_slice());
        assert_eq!(plaintext2, pt2.as_slice());
        assert_eq!(plaintext3, pt3.as_slice());
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
}
