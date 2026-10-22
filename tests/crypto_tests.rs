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
    fn test_session_crypto_roundtrip() {
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut enc_key);
        rng.fill_bytes(&mut mac_key);

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

/// Known-answer tests pinning the outputs of the key derivation primitives used on the wire.
/// Any change to these values breaks interoperability with deployed peers.
mod kdf_known_answer_tests {
    use hkdf::Hkdf;
    use sha2::{Digest, Sha256, Sha384};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn test_sha256_known_answer() {
        let mut hasher = Sha256::new();
        hasher.update(b"abc");
        assert_eq!(
            hasher.finalize().to_vec(),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    /// RFC 5869 test case 3: HKDF-SHA256 with no salt and empty info.
    #[test]
    fn test_hkdf_sha256_rfc5869_case3() {
        let hkdf = Hkdf::<Sha256>::new(None, &[0x0b; 22]);
        let mut okm = [0u8; 42];
        hkdf.expand(&[], &mut okm).unwrap();
        assert_eq!(
            okm.to_vec(),
            hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
        );
    }

    /// Mirrors the session key split performed by the source and destination tunnels.
    #[test]
    fn test_hkdf_sha256_session_key_split() {
        let session_key: Vec<u8> = (0u8..32).collect();
        let hkdf = Hkdf::<Sha256>::new(None, &session_key);

        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        hkdf.expand(b"encryption", &mut enc_key).unwrap();
        hkdf.expand(b"authentication", &mut mac_key).unwrap();

        assert_eq!(
            enc_key.to_vec(),
            hex("c4d9879f1d607713798b3a15a36cb130ff3291ee8092b96698d472087fa8af4c")
        );
        assert_eq!(
            mac_key.to_vec(),
            hex("14bc679bee7fe1886cb4e6c8df18677bf577476989dfd84934f9c628b700da9f")
        );
    }

    /// Mirrors the hybrid KEM derivation: HKDF-SHA384 salted with the ciphertext.
    #[test]
    fn test_hkdf_sha384_hybrid_kem_derivation() {
        let ikm: Vec<u8> = (0u8..64).collect();
        let salt: Vec<u8> = (0u8..128).map(|i| i.wrapping_mul(7)).collect();
        let mut info = Vec::new();
        info.extend_from_slice(b"UTun-Hybrid-KEM-v1-derive");
        info.extend_from_slice(&salt[..32]);

        let hkdf = Hkdf::<Sha384>::new(Some(&salt), &ikm);
        let mut okm = [0u8; 64];
        hkdf.expand(&info, &mut okm).unwrap();

        assert_eq!(
            okm.to_vec(),
            hex("015555838f228dd31096377498466de390b9102e594ec541e875787b6590ee6036dead9aa1c6a929013f424229527ac0c33ae151104c1510583a6c793300b95f")
        );
    }
}
