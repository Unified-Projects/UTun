//! Unit tests for the crypto layer

use rand::RngCore;
use utun::crypto::{
    hybrid_kem::{DerivedKeyMaterial, HybridCiphertext, HybridKeyPair, HybridPublicKey},
    symmetric::{SessionCrypto, SymmetricCrypto},
};

// Import constants directly
use utun::crypto::hybrid_kem::{
    HYBRID_PUBLIC_KEY_BYTES, HYBRID_SECRET_KEY_BYTES,
    KYBER768_PUBLIC_KEY_BYTES as MLKEM768_PUBLIC_KEY_BYTES, MCELIECE460896_PUBLIC_KEY_BYTES,
};

mod hybrid_kem_tests {
    use super::*;

    #[test]
    fn test_key_pair_generation() {
        let kp = HybridKeyPair::generate();

        // Verify key sizes
        assert_eq!(kp.public_key().as_bytes().len(), HYBRID_PUBLIC_KEY_BYTES);
        assert_eq!(kp.secret_key().as_bytes().len(), HYBRID_SECRET_KEY_BYTES);

        // Verify components
        assert_eq!(
            kp.public_key().mlkem_public_key().len(),
            MLKEM768_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            kp.public_key().mceliece_public_key().len(),
            MCELIECE460896_PUBLIC_KEY_BYTES
        );
    }

    #[test]
    fn test_public_key_serialization() {
        let kp = HybridKeyPair::generate();
        let pk_bytes = kp.serialize_public_key();
        let pk_restored = HybridKeyPair::deserialize_public_key(&pk_bytes).unwrap();

        assert_eq!(kp.public_key().as_bytes(), pk_restored.as_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let bob = HybridKeyPair::generate();

        // Encapsulate to Bob
        let (shared_a, ciphertext) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

        // Bob decapsulates
        let shared_b = bob.decapsulate(&ciphertext).unwrap();

        // Shared secrets must match
        assert_eq!(shared_a.as_bytes(), shared_b.as_bytes());
    }

    #[test]
    fn test_bidirectional_exchange() {
        let alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        // Encapsulate to Bob
        let (shared_a_to_b, ct_a) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let shared_b_from_a = bob.decapsulate(&ct_a).unwrap();

        // Encapsulate to Alice
        let (shared_b_to_a, ct_b) = HybridKeyPair::encapsulate(alice.public_key()).unwrap();
        let shared_a_from_b = alice.decapsulate(&ct_b).unwrap();

        // Verify directions match
        assert_eq!(shared_a_to_b.as_bytes(), shared_b_from_a.as_bytes());
        assert_eq!(shared_b_to_a.as_bytes(), shared_a_from_b.as_bytes());

        // Verify directions are different (different keys produce different secrets)
        assert_ne!(shared_a_to_b.as_bytes(), shared_b_to_a.as_bytes());
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_pk = vec![0u8; 100];
        let result = HybridPublicKey::from_bytes(&invalid_pk);
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_too_short() {
        let invalid_ct = vec![0u8; 100];
        let result = HybridCiphertext::from_bytes(&invalid_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_derived_key_split() {
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        for i in 0..32 {
            enc_key[i] = i as u8;
            mac_key[i] = (i + 32) as u8;
        }

        let dkm = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let (enc_key_out, mac_key_out) = dkm.split();

        // Verify split - use expose_secret() for wrapper types
        assert_eq!(&enc_key, enc_key_out.expose_secret());
        assert_eq!(&mac_key, mac_key_out.expose_secret());
    }
}

mod symmetric_tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_basic() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Hello, Quantum-Safe World!";
        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_empty() {
        let key = [42u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"";
        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_large_payload() {
        let key = [0xAB; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = vec![0x42u8; 65536]; // 64KB
        let ciphertext = crypto.encrypt(&plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_different_ciphertext_each_time() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Same message";
        let ct1 = crypto.encrypt(plaintext).unwrap();
        let ct2 = crypto.encrypt(plaintext).unwrap();

        // Ciphertexts should differ (random nonce)
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_decrypt_modified_ciphertext() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Original message";
        let mut ciphertext = crypto.encrypt(plaintext).unwrap();

        // Modify ciphertext
        ciphertext[20] ^= 0xFF;

        // Decryption should fail
        let result = crypto.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_truncated_ciphertext() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        // Too short (no MAC)
        let short_ct = vec![0u8; 10];
        let result = crypto.decrypt(&short_ct);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_mode_encryption() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Counter mode test";

        // Encrypt with counters
        let ct1 = crypto.encrypt_with_counter(plaintext, 0).unwrap();
        let ct2 = crypto.encrypt_with_counter(plaintext, 1).unwrap();

        // Same counter produces same output
        let ct1_again = crypto.encrypt_with_counter(plaintext, 0).unwrap();
        assert_eq!(ct1, ct1_again);

        // Different counters produce different output
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_session_crypto_roundtrip() {
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut enc_key);
        rand::thread_rng().fill_bytes(&mut mac_key);

        let key_material = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let session = SessionCrypto::from_key_material(&key_material);

        let plaintext = b"Session encrypted message";
        let frame = session.encrypt_outbound(plaintext).unwrap();

        // For bidirectional, we need separate sessions with swapped keys
        let swapped = DerivedKeyMaterial::from_parts(&mac_key, &enc_key);
        let peer_session = SessionCrypto::from_key_material(&swapped);

        let decrypted = peer_session.decrypt_inbound(&frame).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
