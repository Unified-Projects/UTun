//! Health check system tests

use std::time::Duration;
use utun::health::{HealthMonitor, HealthStatus};

#[tokio::test]
async fn test_health_monitor_initialization() {
    let monitor = HealthMonitor::new();

    // Should start in Starting state
    let status = monitor.status().await;
    assert_eq!(status, HealthStatus::Starting);
}

#[tokio::test]
async fn test_health_status_transitions() {
    let monitor = HealthMonitor::new();

    // Starting -> Connecting
    monitor.set_status(HealthStatus::Connecting).await;
    assert_eq!(monitor.status().await, HealthStatus::Connecting);

    // Connecting -> Healthy
    monitor.mark_tunnel_established();
    monitor.set_status(HealthStatus::Healthy).await;
    assert_eq!(monitor.status().await, HealthStatus::Healthy);
    assert!(monitor.is_tunnel_established());
}

#[tokio::test]
async fn test_health_check_result() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Healthy).await;
    monitor.mark_tunnel_established();

    let result = monitor.check_health().await;

    assert_eq!(result.status, HealthStatus::Healthy);
    assert!(result.tunnel_established);
    assert_eq!(result.error_count, 0);
    assert_eq!(result.message, "All systems operational");
}

#[tokio::test]
async fn test_error_recording() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Healthy).await;

    // Record errors
    for _ in 0..15 {
        monitor.record_error().await;
    }

    let result = monitor.check_health().await;
    assert_eq!(result.error_count, 15);
    // Should degrade to Degraded after 10 errors
    assert_eq!(result.status, HealthStatus::Degraded);
}

#[tokio::test]
async fn test_success_recording() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Degraded).await;

    // Recording success should upgrade to Healthy
    monitor.record_success().await;

    let status = monitor.status().await;
    assert_eq!(status, HealthStatus::Healthy);
}

#[tokio::test]
async fn test_wait_for_ready() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Starting).await;

    // Spawn a task to set healthy status after a delay
    let monitor_clone = monitor.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        monitor_clone.set_status(HealthStatus::Healthy).await;
    });

    // Should wait and return true once healthy
    let ready = monitor.wait_for_ready(Duration::from_secs(5)).await;
    assert!(ready);
}

#[tokio::test]
async fn test_wait_for_ready_timeout() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Starting).await;

    // Should timeout since we never set it to ready
    let ready = monitor.wait_for_ready(Duration::from_millis(100)).await;
    assert!(!ready);
}

#[tokio::test]
async fn test_health_status_is_ready() {
    assert!(HealthStatus::Healthy.is_ready());
    assert!(HealthStatus::Degraded.is_ready());
    assert!(!HealthStatus::Starting.is_ready());
    assert!(!HealthStatus::Connecting.is_ready());
    assert!(!HealthStatus::Unhealthy.is_ready());
}

#[tokio::test]
async fn test_health_status_is_healthy() {
    assert!(HealthStatus::Healthy.is_healthy());
    assert!(!HealthStatus::Degraded.is_healthy());
    assert!(!HealthStatus::Starting.is_healthy());
    assert!(!HealthStatus::Connecting.is_healthy());
    assert!(!HealthStatus::Unhealthy.is_healthy());
}

#[tokio::test]
async fn test_health_check_uptime() {
    let monitor = HealthMonitor::new();
    monitor.set_status(HealthStatus::Healthy).await;

    // Wait at least 1 second for uptime to register
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let result = monitor.check_health().await;
    assert!(result.uptime_seconds >= 1);
}
