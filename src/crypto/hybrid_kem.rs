use hkdf::Hkdf;
use pqcrypto_classicmceliece::mceliece460896;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use sha2::Sha384;
use std::ops::Deref;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Constants for key sizes
// Kyber768 (equivalent to ML-KEM-768)
pub const KYBER768_PUBLIC_KEY_BYTES: usize = 1184;
pub const KYBER768_SECRET_KEY_BYTES: usize = 2400;
pub const KYBER768_CIPHERTEXT_BYTES: usize = 1088;
pub const KYBER768_SHARED_SECRET_BYTES: usize = 32;

// Classic McEliece 460896
pub const MCELIECE460896_PUBLIC_KEY_BYTES: usize = 524160;
pub const MCELIECE460896_SECRET_KEY_BYTES: usize = 13608; // Actual library size
pub const MCELIECE460896_CIPHERTEXT_BYTES: usize = 156; // Actual library size
pub const MCELIECE460896_SHARED_SECRET_BYTES: usize = 32;

// Hybrid combined sizes
pub const HYBRID_PUBLIC_KEY_BYTES: usize =
    KYBER768_PUBLIC_KEY_BYTES + MCELIECE460896_PUBLIC_KEY_BYTES;
pub const HYBRID_SECRET_KEY_BYTES: usize =
    KYBER768_SECRET_KEY_BYTES + MCELIECE460896_SECRET_KEY_BYTES;
pub const HYBRID_CIPHERTEXT_BYTES: usize =
    KYBER768_CIPHERTEXT_BYTES + MCELIECE460896_CIPHERTEXT_BYTES;
pub const DERIVED_KEY_BYTES: usize = 64;

const HKDF_INFO_BASE: &[u8] = b"UTun-Hybrid-KEM-v1";

#[derive(Debug, Error)]
pub enum HybridKEMError {
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid secret key")]
    InvalidSecretKey,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("HKDF expansion failed")]
    HkdfExpandFailed,
}

/// Wrapper type for encryption keys that automatically zeroizes memory on drop.
/// Use `expose_secret()` to access the underlying key bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey {
    data: [u8; 32],
}

impl EncryptionKey {
    /// Create a new EncryptionKey from raw bytes
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }

    /// Expose the secret key material. Use with caution.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Deref for EncryptionKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::fmt::Debug for EncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionKey")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for EncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl PartialEq<[u8; 32]> for EncryptionKey {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.data == other
    }
}

/// Wrapper type for MAC keys that automatically zeroizes memory on drop.
/// Use `expose_secret()` to access the underlying key bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MacKey {
    data: [u8; 32],
}

impl MacKey {
    /// Create a new MacKey from raw bytes
    pub fn new(data: [u8; 32]) -> Self {
        Self { data }
    }

    /// Expose the secret key material. Use with caution.
    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.data
    }
}

impl Deref for MacKey {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::fmt::Debug for MacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MacKey")
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for MacKey {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl PartialEq<[u8; 32]> for MacKey {
    fn eq(&self, other: &[u8; 32]) -> bool {
        &self.data == other
    }
}

#[derive(Clone)]
pub struct HybridPublicKey {
    data: Vec<u8>,
}

impl HybridPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridKEMError> {
        if bytes.len() != HYBRID_PUBLIC_KEY_BYTES {
            return Err(HybridKEMError::InvalidKeyLength);
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn mlkem_public_key(&self) -> &[u8] {
        &self.data[0..KYBER768_PUBLIC_KEY_BYTES]
    }

    pub fn mceliece_public_key(&self) -> &[u8] {
        &self.data[KYBER768_PUBLIC_KEY_BYTES..]
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    data: Vec<u8>,
}

impl HybridSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridKEMError> {
        if bytes.len() != HYBRID_SECRET_KEY_BYTES {
            return Err(HybridKEMError::InvalidKeyLength);
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Clone)]
pub struct HybridCiphertext {
    data: Vec<u8>,
}

impl HybridCiphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridKEMError> {
        if bytes.len() != HYBRID_CIPHERTEXT_BYTES {
            return Err(HybridKEMError::InvalidKeyLength);
        }
        Ok(Self {
            data: bytes.to_vec(),
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn mlkem_ciphertext(&self) -> &[u8] {
        &self.data[0..KYBER768_CIPHERTEXT_BYTES]
    }

    pub fn mceliece_ciphertext(&self) -> &[u8] {
        &self.data[KYBER768_CIPHERTEXT_BYTES..]
    }
}

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct DerivedKeyMaterial {
    data: [u8; DERIVED_KEY_BYTES],
}

impl DerivedKeyMaterial {
    /// Split the derived key material into encryption and MAC keys.
    /// Returns zeroizing wrapper types that automatically clear memory on drop.
    pub fn split(&self) -> (EncryptionKey, MacKey) {
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&self.data[0..32]);
        mac_key.copy_from_slice(&self.data[32..64]);
        (EncryptionKey::new(enc_key), MacKey::new(mac_key))
    }

    pub fn from_parts(enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Self {
        let mut data = [0u8; DERIVED_KEY_BYTES];
        data[0..32].copy_from_slice(enc_key);
        data[32..64].copy_from_slice(mac_key);
        Self { data }
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_BYTES] {
        &self.data
    }
}

pub struct HybridKeyPair {
    mlkem_sk: Box<kyber768::SecretKey>,
    mc_sk: Box<mceliece460896::SecretKey>,
    combined_public_key: HybridPublicKey,
    combined_secret_key: HybridSecretKey,
}

impl HybridKeyPair {
    pub fn generate() -> Self {
        let (mlkem_pk, mlkem_sk) = kyber768::keypair();
        let (mc_pk, mc_sk) = mceliece460896::keypair();

        let mut combined_pk_data = Vec::with_capacity(HYBRID_PUBLIC_KEY_BYTES);
        combined_pk_data.extend_from_slice(mlkem_pk.as_bytes());
        combined_pk_data.extend_from_slice(mc_pk.as_bytes());

        let mut combined_sk_data = Vec::with_capacity(HYBRID_SECRET_KEY_BYTES);
        combined_sk_data.extend_from_slice(mlkem_sk.as_bytes());
        combined_sk_data.extend_from_slice(mc_sk.as_bytes());

        let combined_public_key = HybridPublicKey {
            data: combined_pk_data,
        };
        let combined_secret_key = HybridSecretKey {
            data: combined_sk_data,
        };

        Self {
            mlkem_sk: Box::new(mlkem_sk),
            mc_sk: Box::new(mc_sk),
            combined_public_key,
            combined_secret_key,
        }
    }

    pub fn public_key(&self) -> &HybridPublicKey {
        &self.combined_public_key
    }

    pub fn secret_key(&self) -> &HybridSecretKey {
        &self.combined_secret_key
    }

    pub fn encapsulate(
        peer_pk: &HybridPublicKey,
    ) -> Result<(DerivedKeyMaterial, HybridCiphertext), HybridKEMError> {
        let peer_mlkem_pk_bytes = peer_pk.mlkem_public_key();
        let peer_mc_pk_bytes = peer_pk.mceliece_public_key();

        let peer_mlkem_pk = kyber768::PublicKey::from_bytes(peer_mlkem_pk_bytes)
            .map_err(|_| HybridKEMError::InvalidPublicKey)?;
        let peer_mc_pk = mceliece460896::PublicKey::from_bytes(peer_mc_pk_bytes)
            .map_err(|_| HybridKEMError::InvalidPublicKey)?;

        let (mlkem_ss, mlkem_ct) = kyber768::encapsulate(&peer_mlkem_pk);
        let (mc_ss, mc_ct) = mceliece460896::encapsulate(&peer_mc_pk);

        let mut combined_ct_data = Vec::with_capacity(HYBRID_CIPHERTEXT_BYTES);
        combined_ct_data.extend_from_slice(mlkem_ct.as_bytes());
        combined_ct_data.extend_from_slice(mc_ct.as_bytes());

        let combined_ct = HybridCiphertext {
            data: combined_ct_data,
        };

        let salt = combined_ct.as_bytes();
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&mlkem_ss.as_bytes()[0..32]);
        ikm.extend_from_slice(&mc_ss.as_bytes()[0..32]);

        let hkdf = Hkdf::<Sha384>::new(Some(salt), &ikm);
        let mut okm = [0u8; DERIVED_KEY_BYTES];

        // Build comprehensive info string with domain separation
        let mut info = Vec::new();
        info.extend_from_slice(HKDF_INFO_BASE);
        info.extend_from_slice(b"-derive"); // KEM derivation marker (must match decapsulate)
        info.extend_from_slice(&combined_ct.data[..32.min(combined_ct.data.len())]); // CT prefix for context

        hkdf.expand(&info, &mut okm)
            .map_err(|_| HybridKEMError::HkdfExpandFailed)?;

        let derived_key = DerivedKeyMaterial { data: okm };

        Ok((derived_key, combined_ct))
    }

    pub fn decapsulate(
        &self,
        ciphertext: &HybridCiphertext,
    ) -> Result<DerivedKeyMaterial, HybridKEMError> {
        let mlkem_ct_bytes = ciphertext.mlkem_ciphertext();
        let mc_ct_bytes = ciphertext.mceliece_ciphertext();

        let mlkem_ct = kyber768::Ciphertext::from_bytes(mlkem_ct_bytes)
            .map_err(|_| HybridKEMError::InvalidCiphertext)?;
        let mc_ct = mceliece460896::Ciphertext::from_bytes(mc_ct_bytes)
            .map_err(|_| HybridKEMError::InvalidCiphertext)?;

        let mlkem_ss = kyber768::decapsulate(&mlkem_ct, &self.mlkem_sk);
        let mc_ss = mceliece460896::decapsulate(&mc_ct, &self.mc_sk);

        let salt = ciphertext.as_bytes();
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(&mlkem_ss.as_bytes()[0..32]);
        ikm.extend_from_slice(&mc_ss.as_bytes()[0..32]);

        let hkdf = Hkdf::<Sha384>::new(Some(salt), &ikm);
        let mut okm = [0u8; DERIVED_KEY_BYTES];

        // Build comprehensive info string with domain separation
        let mut info = Vec::new();
        info.extend_from_slice(HKDF_INFO_BASE);
        info.extend_from_slice(b"-derive"); // KEM derivation marker (must match encapsulate)
        info.extend_from_slice(&ciphertext.data[..32.min(ciphertext.data.len())]); // CT prefix for context

        hkdf.expand(&info, &mut okm)
            .map_err(|_| HybridKEMError::HkdfExpandFailed)?;

        let derived_key = DerivedKeyMaterial { data: okm };

        Ok(derived_key)
    }

    pub fn serialize_public_key(&self) -> Vec<u8> {
        self.combined_public_key.as_bytes().to_vec()
    }

    pub fn deserialize_public_key(bytes: &[u8]) -> Result<HybridPublicKey, HybridKEMError> {
        HybridPublicKey::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = HybridKeyPair::generate();
        assert_eq!(
            keypair.public_key().as_bytes().len(),
            HYBRID_PUBLIC_KEY_BYTES
        );
        assert_eq!(
            keypair.secret_key().as_bytes().len(),
            HYBRID_SECRET_KEY_BYTES
        );
    }

    #[test]
    fn test_public_key_serialization() {
        let keypair = HybridKeyPair::generate();
        let pk_bytes = keypair.serialize_public_key();
        let pk_restored = HybridKeyPair::deserialize_public_key(&pk_bytes).unwrap();
        assert_eq!(pk_bytes, pk_restored.as_bytes());
    }

    #[test]
    fn test_encapsulation_decapsulation() {
        let _alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        let (alice_derived, ciphertext) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let bob_derived = bob.decapsulate(&ciphertext).unwrap();

        assert_eq!(alice_derived.data, bob_derived.data);
    }

    #[test]
    fn test_bidirectional_exchange() {
        let alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        let (alice_to_bob_key, alice_to_bob_ct) =
            HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let bob_received = bob.decapsulate(&alice_to_bob_ct).unwrap();

        let (bob_to_alice_key, bob_to_alice_ct) =
            HybridKeyPair::encapsulate(alice.public_key()).unwrap();
        let alice_received = alice.decapsulate(&bob_to_alice_ct).unwrap();

        assert_eq!(alice_to_bob_key.data, bob_received.data);
        assert_eq!(bob_to_alice_key.data, alice_received.data);
        assert_ne!(alice_to_bob_key.data, bob_to_alice_key.data);
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_bytes = vec![0u8; 100];
        let result = HybridPublicKey::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ciphertext() {
        let keypair = HybridKeyPair::generate();

        let invalid_ct1 =
            HybridCiphertext::from_bytes(&vec![0u8; HYBRID_CIPHERTEXT_BYTES]).unwrap();
        let invalid_ct2 =
            HybridCiphertext::from_bytes(&vec![1u8; HYBRID_CIPHERTEXT_BYTES]).unwrap();

        let result1 = keypair.decapsulate(&invalid_ct1);
        let result2 = keypair.decapsulate(&invalid_ct2);

        if result1.is_ok() && result2.is_ok() {
            assert_ne!(result1.unwrap().data, result2.unwrap().data);
        } else {
            assert!(result1.is_err() || result2.is_err());
        }
    }

    #[test]
    fn test_derived_key_split() {
        let _alice = HybridKeyPair::generate();
        let bob = HybridKeyPair::generate();

        let (derived, _) = HybridKeyPair::encapsulate(bob.public_key()).unwrap();
        let (enc_key, mac_key) = derived.split();

        assert_eq!(enc_key.expose_secret().len(), 32);
        assert_eq!(mac_key.expose_secret().len(), 32);
        assert_ne!(enc_key.expose_secret(), mac_key.expose_secret());
    }

    #[test]
    fn test_derived_key_from_parts() {
        let enc_key = [1u8; 32];
        let mac_key = [2u8; 32];

        let derived = DerivedKeyMaterial::from_parts(&enc_key, &mac_key);
        let (restored_enc, restored_mac) = derived.split();

        assert_eq!(&enc_key, restored_enc.expose_secret());
        assert_eq!(&mac_key, restored_mac.expose_secret());
    }
}
