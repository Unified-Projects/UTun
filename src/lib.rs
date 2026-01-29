//! UTun - Quantum-safe tunnel system
//!
//! UTun provides a secure, quantum-resistant tunneling solution using
//! post-quantum cryptography (ML-KEM-768 + Classic McEliece 460896) for
//! key exchange and AES-256-GCM for symmetric encryption.

pub mod cert;
pub mod config;
pub mod crypto;
pub mod health;
pub mod network;
pub mod tunnel;

pub use config::{load_config, Config};
pub use health::{HealthCheckResult, HealthMonitor, HealthStatus};
