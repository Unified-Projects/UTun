//! Health check system for monitoring tunnel status

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Starting,
    Connecting,
    Healthy,
    Degraded,
    Unhealthy,
}

impl HealthStatus {
    pub fn is_ready(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }

    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub uptime_seconds: u64,
    pub last_successful_operation: Option<u64>,
    pub error_count: u64,
    pub tunnel_established: bool,
    pub message: String,
    pub consecutive_missed_pongs: Option<u8>,
    pub average_rtt_us: Option<u64>,
    pub reconnection_attempts: Option<u32>,
}

pub struct HealthMonitor {
    status: Arc<RwLock<HealthStatus>>,
    start_time: Instant,
    last_success: Arc<RwLock<Option<Instant>>>,
    error_count: AtomicU64,
    tunnel_established: AtomicBool,
    consecutive_missed_pongs: Arc<RwLock<Option<u8>>>,
    average_rtt_us: Arc<RwLock<Option<u64>>>,
    reconnection_attempts: Arc<RwLock<Option<u32>>>,
}

impl HealthMonitor {
    pub fn new() -> Self {
        Self {
            status: Arc::new(RwLock::new(HealthStatus::Starting)),
            start_time: Instant::now(),
            last_success: Arc::new(RwLock::new(None)),
            error_count: AtomicU64::new(0),
            tunnel_established: AtomicBool::new(false),
            consecutive_missed_pongs: Arc::new(RwLock::new(None)),
            average_rtt_us: Arc::new(RwLock::new(None)),
            reconnection_attempts: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the current health status
    pub async fn set_status(&self, status: HealthStatus) {
        let mut s = self.status.write().await;
        *s = status;
    }

    /// Get the current health status
    pub async fn status(&self) -> HealthStatus {
        *self.status.read().await
    }

    /// Mark tunnel as established
    pub fn mark_tunnel_established(&self) {
        self.tunnel_established.store(true, Ordering::Relaxed);
    }

    /// Check if tunnel is established
    pub fn is_tunnel_established(&self) -> bool {
        self.tunnel_established.load(Ordering::Relaxed)
    }

    /// Record a successful operation
    pub async fn record_success(&self) {
        let mut last = self.last_success.write().await;
        *last = Some(Instant::now());

        // If we're degraded and seeing successes, upgrade to healthy
        let current_status = self.status().await;
        if current_status == HealthStatus::Degraded {
            self.set_status(HealthStatus::Healthy).await;
        }
    }

    /// Record an error
    pub async fn record_error(&self) {
        let count = self.error_count.fetch_add(1, Ordering::Relaxed);

        // If we're getting too many errors, degrade health
        if count > 10 {
            let current_status = self.status().await;
            if current_status == HealthStatus::Healthy {
                self.set_status(HealthStatus::Degraded).await;
            }
        }
    }

    /// Set consecutive missed pongs
    pub async fn set_consecutive_missed_pongs(&self, count: u8) {
        *self.consecutive_missed_pongs.write().await = Some(count);
    }

    /// Set average RTT in microseconds
    pub async fn set_average_rtt_us(&self, rtt_us: u64) {
        *self.average_rtt_us.write().await = Some(rtt_us);
    }

    /// Set reconnection attempts
    pub async fn set_reconnection_attempts(&self, attempts: u32) {
        *self.reconnection_attempts.write().await = Some(attempts);
    }

    /// Get comprehensive health check result
    pub async fn check_health(&self) -> HealthCheckResult {
        let status = self.status().await;
        let uptime = self.start_time.elapsed().as_secs();
        let error_count = self.error_count.load(Ordering::Relaxed);
        let tunnel_established = self.is_tunnel_established();

        let last_successful_operation = {
            let last = self.last_success.read().await;
            last.map(|t| t.elapsed().as_secs())
        };

        let consecutive_missed_pongs = *self.consecutive_missed_pongs.read().await;
        let average_rtt_us = *self.average_rtt_us.read().await;
        let reconnection_attempts = *self.reconnection_attempts.read().await;

        let message = match status {
            HealthStatus::Starting => "Service is starting up".to_string(),
            HealthStatus::Connecting => "Establishing tunnel connection".to_string(),
            HealthStatus::Healthy => "All systems operational".to_string(),
            HealthStatus::Degraded => format!("Service degraded: {} errors", error_count),
            HealthStatus::Unhealthy => "Service is unhealthy".to_string(),
        };

        HealthCheckResult {
            status,
            uptime_seconds: uptime,
            last_successful_operation,
            error_count,
            tunnel_established,
            message,
            consecutive_missed_pongs,
            average_rtt_us,
            reconnection_attempts,
        }
    }

    /// Wait for the service to become ready
    /// Returns true if ready within timeout, false otherwise
    pub async fn wait_for_ready(&self, timeout: Duration) -> bool {
        let start = Instant::now();

        loop {
            let status = self.status().await;
            if status.is_ready() {
                return true;
            }

            if start.elapsed() > timeout {
                return false;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Automatic health monitoring task
    pub async fn monitor_task(&self, check_interval: Duration) {
        let mut interval = tokio::time::interval(check_interval);

        loop {
            interval.tick().await;

            // Check if we haven't had success in a while
            let last_success = {
                let last = self.last_success.read().await;
                last.map(|t| t.elapsed())
            };

            let current_status = self.status().await;

            match last_success {
                Some(elapsed) if elapsed > Duration::from_secs(30) => {
                    // No success in 30 seconds - degrade
                    if current_status == HealthStatus::Healthy {
                        self.set_status(HealthStatus::Degraded).await;
                    }
                }
                Some(elapsed) if elapsed > Duration::from_secs(60) => {
                    // No success in 60 seconds - unhealthy
                    if current_status != HealthStatus::Unhealthy {
                        self.set_status(HealthStatus::Unhealthy).await;
                    }
                }
                None if current_status == HealthStatus::Connecting => {
                    // Still trying to connect - check if timeout exceeded
                    if self.start_time.elapsed() > Duration::from_secs(30) {
                        self.set_status(HealthStatus::Unhealthy).await;
                    }
                }
                _ => {}
            }
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HealthMonitor {
    fn clone(&self) -> Self {
        Self {
            status: self.status.clone(),
            start_time: self.start_time,
            last_success: self.last_success.clone(),
            error_count: AtomicU64::new(self.error_count.load(Ordering::Relaxed)),
            tunnel_established: AtomicBool::new(self.tunnel_established.load(Ordering::Relaxed)),
            consecutive_missed_pongs: self.consecutive_missed_pongs.clone(),
            average_rtt_us: self.average_rtt_us.clone(),
            reconnection_attempts: self.reconnection_attempts.clone(),
        }
    }
}
