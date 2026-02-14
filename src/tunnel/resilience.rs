use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::Duration;

/// Tracks tunnel metrics for observability
pub struct TunnelMetrics {
    pub demux_restarts: AtomicUsize,
    pub channel_full_events: AtomicUsize,
    pub frames_dropped: AtomicUsize,
    pub lock_wait_duration_us: AtomicU64,
    pub heartbeat_timeouts: AtomicUsize,
    #[allow(dead_code)]
    pub reconnection_attempts: AtomicUsize,
}

impl Default for TunnelMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelMetrics {
    pub fn new() -> Self {
        Self {
            demux_restarts: AtomicUsize::new(0),
            channel_full_events: AtomicUsize::new(0),
            frames_dropped: AtomicUsize::new(0),
            lock_wait_duration_us: AtomicU64::new(0),
            heartbeat_timeouts: AtomicUsize::new(0),
            reconnection_attempts: AtomicUsize::new(0),
        }
    }

    pub fn record_demux_restart(&self) {
        self.demux_restarts.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            "Demux restart recorded. Total restarts: {}",
            self.demux_restarts.load(Ordering::Relaxed)
        );
    }

    pub fn record_channel_full(&self) {
        self.channel_full_events.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            "Channel full event recorded. Total: {}",
            self.channel_full_events.load(Ordering::Relaxed)
        );
    }

    pub fn record_frame_dropped(&self) {
        self.frames_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_lock_wait(&self, duration: Duration) {
        self.lock_wait_duration_us
            .fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
    }

    pub fn record_heartbeat_timeout(&self) {
        self.heartbeat_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn record_reconnection_attempt(&self) {
        self.reconnection_attempts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_demux_restarts(&self) -> usize {
        self.demux_restarts.load(Ordering::Relaxed)
    }

    pub fn get_channel_full_events(&self) -> usize {
        self.channel_full_events.load(Ordering::Relaxed)
    }

    pub fn get_frames_dropped(&self) -> usize {
        self.frames_dropped.load(Ordering::Relaxed)
    }
}

/// Circuit breaker to prevent infinite restart loops
pub struct CircuitBreaker {
    restart_count: AtomicUsize,
    last_restart: RwLock<Instant>,
    window_duration: Duration,
    max_restarts_in_window: usize,
    is_open: AtomicBool,
}

impl CircuitBreaker {
    pub fn new(window_duration: Duration, max_restarts_in_window: usize) -> Self {
        Self {
            restart_count: AtomicUsize::new(0),
            last_restart: RwLock::new(Instant::now()),
            window_duration,
            max_restarts_in_window,
            is_open: AtomicBool::new(false),
        }
    }

    /// Check if a restart should be allowed
    pub async fn should_allow_restart(&self) -> bool {
        let mut last_restart = self.last_restart.write().await;
        let now = Instant::now();
        let elapsed = now.duration_since(*last_restart);

        // Reset counter AND close breaker if window has passed
        if elapsed > self.window_duration {
            self.restart_count.store(0, Ordering::Relaxed);
            self.is_open.store(false, Ordering::Relaxed);
            *last_restart = now;
        }

        // Check if breaker is open AFTER window check
        if self.is_open.load(Ordering::Relaxed) {
            tracing::error!("Circuit breaker is OPEN - blocking restart to prevent loop");
            return false;
        }

        let count = self.restart_count.fetch_add(1, Ordering::Relaxed) + 1;

        if count > self.max_restarts_in_window {
            tracing::error!(
                "Circuit breaker TRIPPED: {} restarts in {:?} (max: {})",
                count,
                elapsed,
                self.max_restarts_in_window
            );
            self.is_open.store(true, Ordering::Relaxed);
            false
        } else {
            tracing::info!(
                "Circuit breaker: restart {} of {} allowed in current window",
                count,
                self.max_restarts_in_window
            );
            true
        }
    }

    /// Manually reset the circuit breaker
    pub async fn reset(&self) {
        tracing::info!("Circuit breaker manually reset");
        self.is_open.store(false, Ordering::Relaxed);
        self.restart_count.store(0, Ordering::Relaxed);
        *self.last_restart.write().await = Instant::now();
    }

    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::Relaxed)
    }
}

/// Watchdog for monitoring demux task health
pub struct DemuxWatchdog {
    demux_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    demux_healthy: Arc<AtomicBool>,
    circuit_breaker: Arc<CircuitBreaker>,
    metrics: Arc<TunnelMetrics>,
}

impl DemuxWatchdog {
    pub fn new(circuit_breaker: Arc<CircuitBreaker>, metrics: Arc<TunnelMetrics>) -> Self {
        Self {
            demux_handle: Arc::new(RwLock::new(None)),
            demux_healthy: Arc::new(AtomicBool::new(false)),
            circuit_breaker,
            metrics,
        }
    }

    /// Register a demux task for monitoring
    pub async fn register_demux(&self, handle: JoinHandle<()>) {
        let mut demux_handle = self.demux_handle.write().await;
        *demux_handle = Some(handle);
        self.demux_healthy.store(true, Ordering::Relaxed);
        tracing::debug!("Demux task registered with watchdog");
    }

    /// Check if demux is healthy
    pub fn is_healthy(&self) -> bool {
        self.demux_healthy.load(Ordering::Relaxed)
    }

    /// Mark demux as unhealthy (called when task exits)
    pub fn mark_unhealthy(&self) {
        self.demux_healthy.store(false, Ordering::Relaxed);
        self.metrics.record_demux_restart();
    }

    /// Spawn watchdog monitoring task
    pub fn spawn_watchdog<F>(&self, mut reconnect_fn: F) -> JoinHandle<()>
    where
        F: FnMut() + Send + 'static,
    {
        let demux_handle = self.demux_handle.clone();
        let demux_healthy = self.demux_healthy.clone();
        let circuit_breaker = self.circuit_breaker.clone();
        let metrics = self.metrics.clone();

        tokio::spawn(async move {
            let mut check_interval = tokio::time::interval(Duration::from_secs(1));
            check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                check_interval.tick().await;

                let handle_guard = demux_handle.read().await;
                if let Some(ref handle) = *handle_guard {
                    if handle.is_finished() {
                        drop(handle_guard);

                        tracing::error!("Demux task exited unexpectedly - triggering recovery");
                        demux_healthy.store(false, Ordering::Relaxed);
                        metrics.record_demux_restart();

                        // Check circuit breaker before attempting restart
                        if !circuit_breaker.should_allow_restart().await {
                            tracing::error!(
                                "Circuit breaker prevented restart - manual intervention required"
                            );
                            break;
                        }

                        // Trigger reconnection
                        reconnect_fn();
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_allows_normal_restarts() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 5);

        // First 5 restarts should be allowed
        for i in 1..=5 {
            assert!(
                cb.should_allow_restart().await,
                "Restart {} should be allowed",
                i
            );
        }
    }

    #[tokio::test]
    async fn test_circuit_breaker_trips_on_excessive_restarts() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 5);

        // First 5 restarts allowed
        for _ in 1..=5 {
            assert!(cb.should_allow_restart().await);
        }

        // 6th restart should trip breaker
        assert!(!cb.should_allow_restart().await);
        assert!(cb.is_open());
    }

    #[tokio::test]
    async fn test_circuit_breaker_resets_after_window() {
        let cb = CircuitBreaker::new(Duration::from_millis(100), 2);

        // First 2 restarts allowed
        assert!(cb.should_allow_restart().await);
        assert!(cb.should_allow_restart().await);

        // 3rd would trip
        assert!(!cb.should_allow_restart().await);

        // Wait for window to pass
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again
        assert!(cb.should_allow_restart().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_manual_reset() {
        let cb = CircuitBreaker::new(Duration::from_secs(60), 2);

        // Trip the breaker
        assert!(cb.should_allow_restart().await);
        assert!(cb.should_allow_restart().await);
        assert!(!cb.should_allow_restart().await);
        assert!(cb.is_open());

        // Reset manually
        cb.reset().await;
        assert!(!cb.is_open());
        assert!(cb.should_allow_restart().await);
    }

    #[test]
    fn test_metrics_recording() {
        let metrics = TunnelMetrics::new();

        metrics.record_demux_restart();
        assert_eq!(metrics.get_demux_restarts(), 1);

        metrics.record_channel_full();
        assert_eq!(metrics.get_channel_full_events(), 1);

        metrics.record_frame_dropped();
        assert_eq!(metrics.get_frames_dropped(), 1);
    }
}
