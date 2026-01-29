use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

use super::{DerivedKeyMaterial, HybridCiphertext, HybridKeyPair, HybridPublicKey, SessionCrypto};

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("Key rotation in progress")]
    RotationInProgress,
    #[error("Peer public key not available")]
    NoPeerPublicKey,
    #[error("Key rotation failed")]
    RotationFailed,
    #[error("Session not established")]
    NoSession,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
    #[error("Hybrid KEM error: {0}")]
    HybridKEM(#[from] crate::crypto::HybridKEMError),
}

#[derive(Debug, Clone, PartialEq)]
enum RotationState {
    Idle,
    Initiated,
    AwaitingAck,
}

pub struct KeyManager {
    current_crypto: RwLock<Option<Arc<SessionCrypto>>>,
    next_crypto: RwLock<Option<SessionCrypto>>,
    key_pair: RwLock<HybridKeyPair>,
    peer_public_key: RwLock<Option<HybridPublicKey>>,
    rotation_state: RwLock<RotationState>,
    last_rotation: RwLock<Instant>,
    rotation_interval: Duration,
    rehandshake_window: Duration,
    rotation_count: AtomicU64,
}

impl KeyManager {
    pub fn new(rotation_interval_seconds: u64, rehandshake_seconds: u64) -> Self {
        Self {
            current_crypto: RwLock::new(None),
            next_crypto: RwLock::new(None),
            key_pair: RwLock::new(HybridKeyPair::generate()),
            peer_public_key: RwLock::new(None),
            rotation_state: RwLock::new(RotationState::Idle),
            last_rotation: RwLock::new(Instant::now()),
            rotation_interval: Duration::from_secs(rotation_interval_seconds),
            rehandshake_window: Duration::from_secs(rehandshake_seconds),
            rotation_count: AtomicU64::new(0),
        }
    }

    pub async fn set_peer_public_key(&self, pk: HybridPublicKey) {
        let mut peer_pk = self.peer_public_key.write().await;
        *peer_pk = Some(pk);
    }

    pub async fn get_our_public_key(&self) -> Vec<u8> {
        let key_pair = self.key_pair.read().await;
        key_pair.serialize_public_key()
    }

    pub async fn establish_initial_key(
        &self,
        peer_pk_bytes: &[u8],
    ) -> Result<Vec<u8>, KeyManagerError> {
        let peer_pk = HybridPublicKey::from_bytes(peer_pk_bytes)?;
        self.set_peer_public_key(peer_pk.clone()).await;

        let (key_material, ciphertext) = HybridKeyPair::encapsulate(&peer_pk)?;
        let session_crypto = SessionCrypto::from_key_material(&key_material);

        let mut current_crypto = self.current_crypto.write().await;
        *current_crypto = Some(Arc::new(session_crypto));

        let mut last_rotation = self.last_rotation.write().await;
        *last_rotation = Instant::now();

        Ok(ciphertext.as_bytes().to_vec())
    }

    pub async fn process_handshake_response(
        &self,
        ciphertext: &[u8],
    ) -> Result<(), KeyManagerError> {
        let hybrid_ciphertext = HybridCiphertext::from_bytes(ciphertext)?;

        let key_pair = self.key_pair.read().await;
        let key_material = key_pair.decapsulate(&hybrid_ciphertext)?;
        drop(key_pair);

        let session_crypto = SessionCrypto::from_key_material(&key_material);

        let mut current_crypto = self.current_crypto.write().await;
        *current_crypto = Some(Arc::new(session_crypto));

        let mut last_rotation = self.last_rotation.write().await;
        *last_rotation = Instant::now();

        Ok(())
    }

    pub async fn get_session_crypto(&self) -> Result<Arc<SessionCrypto>, KeyManagerError> {
        let current_crypto = self.current_crypto.read().await;
        current_crypto
            .as_ref()
            .cloned()
            .ok_or(KeyManagerError::NoSession)
    }

    pub async fn should_rotate(&self) -> bool {
        let last_rotation = self.last_rotation.read().await;
        let elapsed = Instant::now().duration_since(*last_rotation);
        let threshold = self
            .rotation_interval
            .saturating_sub(self.rehandshake_window);
        elapsed > threshold
    }

    pub async fn initiate_rotation(&self) -> Result<Vec<u8>, KeyManagerError> {
        let peer_pk_guard = self.peer_public_key.read().await;
        let peer_pk = peer_pk_guard
            .as_ref()
            .ok_or(KeyManagerError::NoPeerPublicKey)?
            .clone();
        drop(peer_pk_guard);

        let mut rotation_state = self.rotation_state.write().await;
        if *rotation_state != RotationState::Idle {
            return Err(KeyManagerError::RotationInProgress);
        }
        *rotation_state = RotationState::Initiated;
        drop(rotation_state);

        let new_key_pair = HybridKeyPair::generate();
        let (key_material, ciphertext) = HybridKeyPair::encapsulate(&peer_pk)?;

        let pending_session = SessionCrypto::from_key_material(&key_material);

        let mut next_crypto = self.next_crypto.write().await;
        *next_crypto = Some(pending_session);
        drop(next_crypto);

        let mut key_pair = self.key_pair.write().await;
        *key_pair = new_key_pair;
        drop(key_pair);

        let mut rotation_state = self.rotation_state.write().await;
        *rotation_state = RotationState::AwaitingAck;

        Ok(ciphertext.as_bytes().to_vec())
    }

    pub async fn complete_rotation(&self, ciphertext: &[u8]) -> Result<(), KeyManagerError> {
        let rotation_state_guard = self.rotation_state.read().await;
        if *rotation_state_guard != RotationState::AwaitingAck {
            return Err(KeyManagerError::RotationFailed);
        }
        drop(rotation_state_guard);

        let hybrid_ciphertext = HybridCiphertext::from_bytes(ciphertext)?;

        let key_pair = self.key_pair.read().await;
        let key_material = key_pair.decapsulate(&hybrid_ciphertext)?;
        drop(key_pair);

        let new_session = SessionCrypto::from_key_material(&key_material);

        let mut current_crypto = self.current_crypto.write().await;
        *current_crypto = Some(Arc::new(new_session));
        drop(current_crypto);

        let mut next_crypto = self.next_crypto.write().await;
        *next_crypto = None;
        drop(next_crypto);

        let mut rotation_state = self.rotation_state.write().await;
        *rotation_state = RotationState::Idle;
        drop(rotation_state);

        let mut last_rotation = self.last_rotation.write().await;
        *last_rotation = Instant::now();
        drop(last_rotation);

        self.rotation_count.fetch_add(1, Ordering::SeqCst);

        Ok(())
    }

    pub async fn handle_rotation_request(
        &self,
        peer_pk_bytes: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeyManagerError> {
        let peer_pk = HybridPublicKey::from_bytes(peer_pk_bytes)?;
        self.set_peer_public_key(peer_pk.clone()).await;

        let hybrid_ciphertext = HybridCiphertext::from_bytes(ciphertext)?;

        let old_key_pair = self.key_pair.read().await;
        let key_material = old_key_pair.decapsulate(&hybrid_ciphertext)?;
        drop(old_key_pair);

        let new_session = SessionCrypto::from_key_material(&key_material);

        let new_key_pair = HybridKeyPair::generate();
        let (_response_key_material, response_ciphertext) = HybridKeyPair::encapsulate(&peer_pk)?;

        let mut key_pair = self.key_pair.write().await;
        *key_pair = new_key_pair;
        drop(key_pair);

        let mut current_crypto = self.current_crypto.write().await;
        *current_crypto = Some(Arc::new(new_session));
        drop(current_crypto);

        let mut last_rotation = self.last_rotation.write().await;
        *last_rotation = Instant::now();
        drop(last_rotation);

        self.rotation_count.fetch_add(1, Ordering::SeqCst);

        Ok(response_ciphertext.as_bytes().to_vec())
    }

    pub fn get_rotation_count(&self) -> u64 {
        self.rotation_count.load(Ordering::SeqCst)
    }

    // Additional methods for handshake support
    pub fn generate_ephemeral_keypair(&self) -> HybridKeyPair {
        HybridKeyPair::generate()
    }

    pub fn encapsulate_hybrid(
        &self,
        public_key: &HybridPublicKey,
    ) -> Result<(DerivedKeyMaterial, HybridCiphertext), KeyManagerError> {
        HybridKeyPair::encapsulate(public_key).map_err(KeyManagerError::HybridKEM)
    }

    pub fn decapsulate_hybrid(
        &self,
        keypair: &HybridKeyPair,
        ciphertext: &HybridCiphertext,
    ) -> Result<DerivedKeyMaterial, KeyManagerError> {
        keypair
            .decapsulate(ciphertext)
            .map_err(KeyManagerError::HybridKEM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_key_manager_creation() {
        let km = KeyManager::new(3600, 300);
        assert_eq!(km.get_rotation_count(), 0);
        assert!(km.get_session_crypto().await.is_err());
    }

    #[tokio::test]
    async fn test_public_key_exchange() {
        let km1 = KeyManager::new(3600, 300);
        let km2 = KeyManager::new(3600, 300);

        let pk1 = km1.get_our_public_key().await;
        let pk2 = km2.get_our_public_key().await;

        let pk1_obj = HybridPublicKey::from_bytes(&pk1).unwrap();
        let pk2_obj = HybridPublicKey::from_bytes(&pk2).unwrap();

        km1.set_peer_public_key(pk2_obj).await;
        km2.set_peer_public_key(pk1_obj).await;

        assert!(km1.peer_public_key.read().await.is_some());
        assert!(km2.peer_public_key.read().await.is_some());
    }

    #[tokio::test]
    async fn test_initial_key_establishment() {
        let km1 = KeyManager::new(3600, 300);
        let km2 = KeyManager::new(3600, 300);

        let pk1 = km1.get_our_public_key().await;
        let pk2 = km2.get_our_public_key().await;

        let ct1 = km1.establish_initial_key(&pk2).await.unwrap();

        let pk1_obj = HybridPublicKey::from_bytes(&pk1).unwrap();
        km2.set_peer_public_key(pk1_obj).await;
        km2.process_handshake_response(&ct1).await.unwrap();

        assert!(km1.get_session_crypto().await.is_ok());
        assert!(km2.get_session_crypto().await.is_ok());
    }

    #[tokio::test]
    async fn test_should_rotate() {
        let km = KeyManager::new(1, 0);
        assert!(!km.should_rotate().await);

        sleep(Duration::from_secs(2)).await;
        assert!(km.should_rotate().await);
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let km1 = KeyManager::new(3600, 300);
        let km2 = KeyManager::new(3600, 300);

        let pk1 = km1.get_our_public_key().await;
        let pk2 = km2.get_our_public_key().await;

        let ct1 = km1.establish_initial_key(&pk2).await.unwrap();

        let pk1_obj = HybridPublicKey::from_bytes(&pk1).unwrap();
        km2.set_peer_public_key(pk1_obj).await;
        km2.process_handshake_response(&ct1).await.unwrap();

        let initial_count1 = km1.get_rotation_count();
        let initial_count2 = km2.get_rotation_count();

        let rotation_ct = km1.initiate_rotation().await.unwrap();
        let new_pk1 = km1.get_our_public_key().await;

        let response_ct = km2
            .handle_rotation_request(&new_pk1, &rotation_ct)
            .await
            .unwrap();

        km1.complete_rotation(&response_ct).await.unwrap();

        assert_eq!(km1.get_rotation_count(), initial_count1 + 1);
        assert_eq!(km2.get_rotation_count(), initial_count2 + 1);

        assert!(km1.get_session_crypto().await.is_ok());
        assert!(km2.get_session_crypto().await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_session_access() {
        let km = KeyManager::new(3600, 300);

        let pk2 = HybridKeyPair::generate().serialize_public_key();
        km.establish_initial_key(&pk2).await.unwrap();

        let km = Arc::new(km);
        let mut handles = vec![];

        for _ in 0..10 {
            let km_clone = km.clone();
            let handle = tokio::spawn(async move {
                km_clone.get_session_crypto().await.unwrap();
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_rotation_state_machine() {
        let km = KeyManager::new(3600, 300);

        let pk2 = HybridKeyPair::generate().serialize_public_key();
        km.establish_initial_key(&pk2).await.unwrap();

        let _rotation_ct = km.initiate_rotation().await.unwrap();

        let result = km.initiate_rotation().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(KeyManagerError::RotationInProgress)));

        let pk2_obj = HybridPublicKey::from_bytes(&pk2).unwrap();
        let (_, response_ct) = HybridKeyPair::encapsulate(&pk2_obj).unwrap();
        km.complete_rotation(response_ct.as_bytes()).await.unwrap();

        let state = km.rotation_state.read().await;
        assert_eq!(*state, RotationState::Idle);
    }

    #[tokio::test]
    async fn test_no_peer_public_key_error() {
        let km = KeyManager::new(3600, 300);
        let result = km.initiate_rotation().await;
        assert!(matches!(result, Err(KeyManagerError::NoPeerPublicKey)));
    }

    #[tokio::test]
    async fn test_invalid_ciphertext() {
        let km = KeyManager::new(3600, 300);

        let pk2 = HybridKeyPair::generate().serialize_public_key();
        km.establish_initial_key(&pk2).await.unwrap();

        let invalid_ct = vec![0u8; 100];
        let result = km.process_handshake_response(&invalid_ct).await;
        assert!(result.is_err());
    }
}
