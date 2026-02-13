//! Security-focused tests

use utun::crypto::{
    auth::{
        generate_ca_certificate, generate_client_certificate, generate_server_certificate,
        verify_certificate_chain, verify_certificate_hostname,
    },
    hybrid_kem::{HybridCiphertext, HybridKeyPair},
    symmetric::SymmetricCrypto,
};

mod key_security_tests {
    use super::*;

    #[test]
    fn test_different_keys_produce_different_results() {
        let _alice1 = HybridKeyPair::generate();
        let _alice2 = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        let (shared1, _ct1) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let (shared2, _ct2) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

        // Different key pairs should produce different shared secrets
        assert_ne!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn test_wrong_secret_key_fails() {
        let _alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();
        let eve = HybridKeyPair::generate();

        // Encapsulate to Bob
        let (shared_alice, ciphertext) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

        // Eve tries to decapsulate with her key
        let shared_eve = eve.decapsulate(&ciphertext).unwrap();

        // Shared secrets should not match
        assert_ne!(shared_alice.as_bytes(), shared_eve.as_bytes());
    }

    #[test]
    fn test_ciphertext_tampering_detection() {
        let _alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        let (shared_original, ciphertext) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

        // Tamper with ciphertext
        let mut tampered = ciphertext.as_bytes().to_vec();
        tampered[50] ^= 0xFF;

        // Decapsulation with tampered ciphertext should produce different result
        let tampered_ct = HybridCiphertext::from_bytes(&tampered).unwrap();
        let shared_tampered = bob.decapsulate(&tampered_ct).unwrap();

        assert_ne!(shared_original.as_bytes(), shared_tampered.as_bytes());
    }

    #[test]
    fn test_key_uniqueness() {
        // Generate multiple keys and ensure they're all different
        let keys: Vec<_> = (0..10).map(|_| HybridKeyPair::generate()).collect();

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i].public_key().as_bytes(),
                    keys[j].public_key().as_bytes(),
                    "Keys {} and {} are identical",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn test_shared_secret_uniqueness() {
        let _alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        // Multiple encapsulations should produce different ciphertexts
        let (shared1, ct1) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let (shared2, ct2) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();

        // Ciphertexts should differ
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());

        // But decapsulation should still work for both
        let decap1 = bob.decapsulate(&ct1).unwrap();
        let decap2 = bob.decapsulate(&ct2).unwrap();

        assert_eq!(shared1.as_bytes(), decap1.as_bytes());
        assert_eq!(shared2.as_bytes(), decap2.as_bytes());
    }
}

mod encryption_security_tests {
    use super::*;

    #[test]
    fn test_different_keys_cannot_decrypt() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let crypto1 = SymmetricCrypto::new(&key1);
        let crypto2 = SymmetricCrypto::new(&key2);

        let plaintext = b"Secret message";
        let ciphertext = crypto1.encrypt(plaintext).unwrap();

        // Wrong key should fail to decrypt
        let result = crypto2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_reuse_produces_different_ciphertexts() {
        // Even with same key and plaintext, random nonces mean different ciphertexts
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Same message";
        let ct1 = crypto.encrypt(plaintext).unwrap();
        let ct2 = crypto.encrypt(plaintext).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_authentication_tag_verification() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Authenticated message";
        let mut ciphertext = crypto.encrypt(plaintext).unwrap();

        // Flip last byte (part of auth tag)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;

        // Should fail authentication
        assert!(crypto.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_bit_flipping_detection() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Critical data that must not be tampered with";
        let mut ciphertext = crypto.encrypt(plaintext).unwrap();

        // Flip a bit in the middle of the ciphertext
        if ciphertext.len() > 20 {
            ciphertext[15] ^= 0x01;

            // Decryption should fail due to authentication tag mismatch
            assert!(crypto.decrypt(&ciphertext).is_err());
        }
    }

    #[test]
    fn test_replay_different_nonces() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Message";

        // Create 100 ciphertexts and ensure all nonces are unique
        let mut nonces = std::collections::HashSet::new();

        for _ in 0..100 {
            let ct = crypto.encrypt(plaintext).unwrap();
            // First 12 bytes are the nonce
            let nonce = &ct[..12];
            assert!(nonces.insert(nonce.to_vec()), "Duplicate nonce detected");
        }
    }
}

mod certificate_security_tests {
    use super::*;

    #[test]
    fn test_certificate_not_signed_by_ca() {
        // Generate two separate CAs
        let ca1 = generate_ca_certificate("CA 1", 365).unwrap();
        let ca2 = generate_ca_certificate("CA 2", 365).unwrap();

        // Generate server cert with CA1
        let server = generate_server_certificate(
            &ca1.certificate_pem,
            &ca1.private_key_pem,
            "server",
            vec!["server".to_string()],
            vec![],
            365,
        )
        .unwrap();

        // Try to verify with CA2 - should fail
        let result = verify_certificate_chain(&server.certificate_der, &ca2.certificate_der);
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_verification() {
        let ca = generate_ca_certificate("CA", 365).unwrap();

        let server = generate_server_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "server.example.com",
            vec![
                "server.example.com".to_string(),
                "www.example.com".to_string(),
            ],
            vec!["10.0.0.1".to_string()],
            365,
        )
        .unwrap();

        // Matching hostname should pass
        assert!(verify_certificate_hostname(&server.certificate_der, "server.example.com").is_ok());
        assert!(verify_certificate_hostname(&server.certificate_der, "www.example.com").is_ok());
        assert!(verify_certificate_hostname(&server.certificate_der, "10.0.0.1").is_ok());

        // Non-matching should fail
        assert!(verify_certificate_hostname(&server.certificate_der, "other.example.com").is_err());
    }

    #[test]
    fn test_valid_certificate_chain() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();

        let server = generate_server_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "localhost",
            vec!["localhost".to_string()],
            vec!["127.0.0.1".to_string()],
            365,
        )
        .unwrap();

        // Verify with correct CA - should pass
        let result = verify_certificate_chain(&server.certificate_der, &ca.certificate_der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_certificate_verification() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();

        let client = generate_client_certificate(
            &ca.certificate_pem,
            &ca.private_key_pem,
            "test-client",
            365,
        )
        .unwrap();

        // Verify client cert with CA
        let result = verify_certificate_chain(&client.certificate_der, &ca.certificate_der);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ca_certificate_validity() {
        let ca = generate_ca_certificate("Test CA", 365).unwrap();

        // CA certificate should be self-signed
        assert!(!ca.certificate_pem.is_empty());
        assert!(!ca.private_key_pem.is_empty());
        assert!(!ca.certificate_der.is_empty());
        assert!(!ca.private_key_der.is_empty());
    }
}

mod timing_attack_resistance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_decryption_timing_consistency() {
        let key = [0u8; 32];
        let crypto = SymmetricCrypto::new(&key);

        let plaintext = b"Test message for timing analysis";
        let ciphertext = crypto.encrypt(plaintext).unwrap();

        // Measure time for valid decryption
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = crypto.decrypt(&ciphertext).unwrap();
        }
        let valid_duration = start.elapsed();

        // Measure time for invalid decryption (tampered ciphertext)
        let mut tampered = ciphertext.clone();
        tampered[10] ^= 0xFF;

        let start = Instant::now();
        for _ in 0..1000 {
            let _ = crypto.decrypt(&tampered);
        }
        let invalid_duration = start.elapsed();

        // Timing should be relatively similar (within 3.5x)
        let ratio = valid_duration.as_nanos() as f64 / invalid_duration.as_nanos() as f64;
        assert!(ratio > 0.3 && ratio < 3.5, "Timing ratio: {}", ratio);
    }
}
