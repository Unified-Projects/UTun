use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cert;
mod cli;
mod config;
mod crypto;
mod health;
mod network;
mod tunnel;

use cert::execute_cert_command;
use cli::{Cli, Command};
use health::HealthCheckResult;
use tunnel::{dest::DestError, source::SourceError};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    init_logging(&cli)?;

    match cli.command {
        Command::Source(args) => run_source(cli.config, args).await,
        Command::Dest(args) => run_dest(cli.config, args).await,
        Command::Cert(cmd) => execute_cert_command(cmd),
        Command::Health(args) => check_health(args).await,
        Command::Version => print_version(),
    }
}

fn init_logging(cli: &Cli) -> anyhow::Result<()> {
    let level = cli.log_level.as_str();
    let format = cli.log_format.as_str();

    let subscriber = tracing_subscriber::registry().with(tracing_subscriber::EnvFilter::new(level));

    match format {
        "json" => {
            subscriber
                .with(tracing_subscriber::fmt::layer().json())
                .init();
        }
        "plain" => {
            subscriber.with(tracing_subscriber::fmt::layer()).init();
        }
        _ => {
            subscriber.with(tracing_subscriber::fmt::layer()).init();
        }
    }

    Ok(())
}

type SharedHealthMonitor = Arc<RwLock<Option<Arc<health::HealthMonitor>>>>;

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetricsConfigSnapshot {
    enabled: bool,
    bind_ip: String,
    port: u16,
}

impl MetricsConfigSnapshot {
    fn from_config(config: &config::MetricsConfig) -> Self {
        Self {
            enabled: config.enabled,
            bind_ip: config.metrics_bind_ip.clone(),
            port: config.metrics_port,
        }
    }
}

struct MetricsState {
    running: bool,
    last_config: MetricsConfigSnapshot,
    health_handle: SharedHealthMonitor,
}

impl MetricsState {
    fn new(config: &config::MetricsConfig) -> Self {
        Self {
            running: config.enabled,
            last_config: MetricsConfigSnapshot::from_config(config),
            health_handle: Arc::new(RwLock::new(None)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: SystemTime,
    len: u64,
}

async fn read_file_stamp(path: &Path) -> std::io::Result<FileStamp> {
    let metadata = tokio::fs::metadata(path).await?;
    Ok(FileStamp {
        modified: metadata.modified()?,
        len: metadata.len(),
    })
}

fn spawn_config_watcher(config_path: PathBuf) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut last_stamp = read_file_stamp(&config_path).await.ok();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

        loop {
            interval.tick().await;
            match read_file_stamp(&config_path).await {
                Ok(stamp) => {
                    let changed = last_stamp.map_or(true, |prev| prev != stamp);
                    if changed {
                        last_stamp = Some(stamp);
                        if tx.send(()).await.is_err() {
                            break;
                        }
                    }
                }
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::NotFound {
                        if last_stamp.is_some() {
                            tracing::warn!(
                                "Config file {} not found; keeping current configuration",
                                config_path.display()
                            );
                        }
                        last_stamp = None;
                    } else {
                        tracing::warn!(
                            "Failed to read config metadata for {}: {}",
                            config_path.display(),
                            err
                        );
                    }
                }
            }
        }
    });
    rx
}

fn load_source_settings(
    config_path: &Path,
    args: &cli::SourceArgs,
) -> anyhow::Result<(
    config::SourceConfig,
    config::CryptoConfig,
    config::MetricsConfig,
)> {
    let mut config = config::load_config(config_path)?;

    let mut source_config = config
        .source
        .ok_or_else(|| anyhow::anyhow!("Source configuration not found in config file"))?;

    // Apply CLI overrides
    if let Some(ip) = &args.listen_ip {
        source_config.listen_ip = ip.clone();
    }
    if let Some(port) = args.listen_port {
        source_config.listen_port = port;
    }
    if let Some(host) = &args.dest_host {
        source_config.dest_host = host.clone();
    }
    if let Some(port) = args.dest_tunnel_port {
        source_config.dest_tunnel_port = port;
    }
    if let Some(port) = args.metrics_port {
        config.metrics.metrics_port = port;
    }

    Ok((source_config, config.crypto, config.metrics))
}

fn load_dest_settings(
    config_path: &Path,
    args: &cli::DestArgs,
) -> anyhow::Result<(
    config::DestConfig,
    config::CryptoConfig,
    config::MetricsConfig,
)> {
    let mut config = config::load_config(config_path)?;

    let mut dest_config = config
        .dest
        .ok_or_else(|| anyhow::anyhow!("Destination configuration not found in config file"))?;

    // Apply CLI overrides
    if let Some(ip) = &args.listen_ip {
        dest_config.listen_ip = ip.clone();
    }
    if let Some(port) = args.tunnel_port {
        dest_config.tunnel_port = port;
    }
    if let Some(port) = args.metrics_port {
        config.metrics.metrics_port = port;
    }

    Ok((dest_config, config.crypto, config.metrics))
}

async fn update_metrics_state(
    metrics_state: &mut MetricsState,
    new_metrics: &config::MetricsConfig,
    new_monitor: Arc<health::HealthMonitor>,
) {
    let new_snapshot = MetricsConfigSnapshot::from_config(new_metrics);

    if metrics_state.running {
        if metrics_state.last_config != new_snapshot {
            tracing::warn!("Metrics configuration changed; restart required to apply new settings");
        }
        let mut slot = metrics_state.health_handle.write().await;
        *slot = Some(new_monitor);
    } else if new_snapshot.enabled {
        tracing::warn!(
            "Metrics enabled in config, but metrics server was disabled at startup; restart required"
        );
    }

    metrics_state.last_config = new_snapshot;
}

async fn wait_for_run_handle<E>(handle: tokio::task::JoinHandle<Result<(), E>>, label: &str) {
    match tokio::time::timeout(std::time::Duration::from_secs(30), handle).await {
        Ok(result) => {
            if let Err(e) = result {
                tracing::error!("{} run task panicked: {}", label, e);
            }
        }
        Err(_) => {
            tracing::warn!("{} shutdown timed out after 30 seconds", label);
        }
    }
}

async fn reload_source_config(
    config_path: &Path,
    args: &cli::SourceArgs,
    source: &mut Arc<tunnel::SourceContainer>,
    run_handle: &mut Option<tokio::task::JoinHandle<Result<(), SourceError>>>,
    metrics_state: &mut MetricsState,
) -> anyhow::Result<()> {
    let (source_config, crypto_config, metrics_config) =
        match load_source_settings(config_path, args) {
            Ok(settings) => settings,
            Err(err) => {
                tracing::error!("Config reload failed: {}", err);
                return Ok(());
            }
        };

    tracing::info!("Config change detected, validating new source configuration");
    let new_source = match tunnel::SourceContainer::new(source_config, crypto_config).await {
        Ok(container) => Arc::new(container),
        Err(err) => {
            tracing::error!("Config reload rejected: {}", err);
            return Ok(());
        }
    };

    if let Err(err) = new_source.start().await {
        tracing::error!(
            "Config reload rejected: new source failed to start: {}",
            err
        );
        return Ok(());
    }

    tracing::info!("Switching to new source configuration");
    source.stop().await;
    if let Some(handle) = run_handle.take() {
        wait_for_run_handle(handle, "Source").await;
    }

    let source_run = new_source.clone();
    let new_handle = tokio::spawn(async move { source_run.run().await });
    *source = new_source;
    *run_handle = Some(new_handle);

    update_metrics_state(metrics_state, &metrics_config, source.health_monitor()).await;
    tracing::info!("Source configuration reloaded successfully");
    Ok(())
}

async fn reload_dest_config(
    config_path: &Path,
    args: &cli::DestArgs,
    dest: &mut Arc<tunnel::DestContainer>,
    run_handle: &mut Option<tokio::task::JoinHandle<Result<(), DestError>>>,
    metrics_state: &mut MetricsState,
) -> anyhow::Result<()> {
    let (dest_config, crypto_config, metrics_config) = match load_dest_settings(config_path, args) {
        Ok(settings) => settings,
        Err(err) => {
            tracing::error!("Config reload failed: {}", err);
            return Ok(());
        }
    };

    tracing::info!("Config change detected, validating new destination configuration");
    let new_dest = match tunnel::DestContainer::new(dest_config, crypto_config).await {
        Ok(container) => Arc::new(container),
        Err(err) => {
            tracing::error!("Config reload rejected: {}", err);
            return Ok(());
        }
    };

    if let Err(err) = new_dest.start().await {
        tracing::error!(
            "Config reload rejected: new destination failed to start: {}",
            err
        );
        return Ok(());
    }

    tracing::info!("Switching to new destination configuration");
    dest.stop().await;
    if let Some(handle) = run_handle.take() {
        wait_for_run_handle(handle, "Destination").await;
    }

    let dest_run = new_dest.clone();
    let new_handle = tokio::spawn(async move { dest_run.run().await });
    *dest = new_dest;
    *run_handle = Some(new_handle);

    update_metrics_state(metrics_state, &metrics_config, dest.health_monitor()).await;
    tracing::info!("Destination configuration reloaded successfully");
    Ok(())
}

async fn run_source(config_path: PathBuf, args: cli::SourceArgs) -> anyhow::Result<()> {
    let (source_config, crypto_config, metrics_config) = load_source_settings(&config_path, &args)?;

    let mut metrics_state = MetricsState::new(&metrics_config);

    // Create and run source container
    tracing::info!("Starting UTun source container");
    let mut source = Arc::new(tunnel::SourceContainer::new(source_config, crypto_config).await?);

    // Start metrics server with health monitor
    if metrics_state.running {
        {
            let mut slot = metrics_state.health_handle.write().await;
            *slot = Some(source.health_monitor());
        }
        tokio::spawn(start_metrics_server(
            metrics_state.last_config.bind_ip.clone(),
            metrics_state.last_config.port,
            metrics_state.health_handle.clone(),
        ));
    }

    source.start().await?;

    // Spawn the main run loop
    let source_run = source.clone();
    let mut run_handle = Some(tokio::spawn(async move { source_run.run().await }));

    let mut reload_rx = spawn_config_watcher(config_path.clone());
    let mut shutdown = Box::pin(wait_for_shutdown_signal());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            change = reload_rx.recv() => {
                if change.is_none() {
                    break;
                }
                let _ = reload_source_config(
                    &config_path,
                    &args,
                    &mut source,
                    &mut run_handle,
                    &mut metrics_state,
                ).await;
            }
        }
    }

    // Graceful shutdown
    tracing::info!("Initiating graceful shutdown...");
    source.stop().await;
    if let Some(handle) = run_handle.take() {
        wait_for_run_handle(handle, "Source").await;
    }

    tracing::info!("Shutdown complete");
    Ok(())
}

async fn run_dest(config_path: PathBuf, args: cli::DestArgs) -> anyhow::Result<()> {
    let (dest_config, crypto_config, metrics_config) = load_dest_settings(&config_path, &args)?;

    let mut metrics_state = MetricsState::new(&metrics_config);

    // Create and run destination container
    tracing::info!("Starting UTun destination container");
    let mut dest = Arc::new(tunnel::DestContainer::new(dest_config, crypto_config).await?);

    // Start metrics server with health monitor
    if metrics_state.running {
        {
            let mut slot = metrics_state.health_handle.write().await;
            *slot = Some(dest.health_monitor());
        }
        tokio::spawn(start_metrics_server(
            metrics_state.last_config.bind_ip.clone(),
            metrics_state.last_config.port,
            metrics_state.health_handle.clone(),
        ));
    }

    dest.start().await?;

    // Spawn the main run loop
    let dest_run = dest.clone();
    let mut run_handle = Some(tokio::spawn(async move { dest_run.run().await }));

    let mut reload_rx = spawn_config_watcher(config_path.clone());
    let mut shutdown = Box::pin(wait_for_shutdown_signal());

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            change = reload_rx.recv() => {
                if change.is_none() {
                    break;
                }
                let _ = reload_dest_config(
                    &config_path,
                    &args,
                    &mut dest,
                    &mut run_handle,
                    &mut metrics_state,
                ).await;
            }
        }
    }

    // Graceful shutdown
    tracing::info!("Initiating graceful shutdown...");
    dest.stop().await;
    if let Some(handle) = run_handle.take() {
        wait_for_run_handle(handle, "Destination").await;
    }

    tracing::info!("Shutdown complete");
    Ok(())
}

fn print_version() -> anyhow::Result<()> {
    println!("utun {}", env!("CARGO_PKG_VERSION"));
    println!("Rust version: {}", rustc_version_runtime::version());
    println!(
        "Build timestamp: {}",
        option_env!("BUILD_TIMESTAMP").unwrap_or("unknown")
    );
    Ok(())
}

/// Wait for a shutdown signal (SIGTERM or SIGINT/Ctrl+C)
async fn wait_for_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C (SIGINT)");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM");
        }
    }
}

async fn check_health(args: cli::HealthArgs) -> anyhow::Result<()> {
    use std::time::Duration;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()?;

    match client.get(&args.endpoint).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<HealthCheckResult>().await {
                    Ok(health) => {
                        if health.status.is_ready() {
                            println!("Health check passed: {}", health.message);
                            std::process::exit(0);
                        } else {
                            eprintln!("Health check failed: {}", health.message);
                            std::process::exit(1);
                        }
                    }
                    Err(_) => {
                        // Fallback to simple status check
                        println!("Health check passed (legacy format)");
                        std::process::exit(0);
                    }
                }
            } else {
                eprintln!("Health check failed: HTTP {}", response.status());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Health check failed: {}", e);
            std::process::exit(1);
        }
    }
}

async fn start_metrics_server(bind_ip: String, port: u16, health_monitor: SharedHealthMonitor) {
    use warp::Filter;

    let metrics = warp::path("metrics".to_string()).map(|| {
        use prometheus::{Encoder, TextEncoder};
        let encoder = TextEncoder::new();
        let metric_families = prometheus::gather();
        let mut buffer = vec![];

        match encoder.encode(&metric_families, &mut buffer) {
            Ok(_) => {}
            Err(e) => {
                tracing::error!("Failed to encode metrics: {}", e);
                return "Error encoding metrics".to_string();
            }
        }

        match String::from_utf8(buffer) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to convert metrics to UTF-8: {}", e);
                "Error converting metrics to UTF-8".to_string()
            }
        }
    });

    let health_monitor_filter = warp::any().map(move || health_monitor.clone());

    let health = warp::path("health".to_string())
        .and(health_monitor_filter)
        .and_then(|health_monitor: SharedHealthMonitor| async move {
            let monitor = {
                let guard = health_monitor.read().await;
                guard.clone()
            };

            match monitor {
                Some(monitor) => {
                    let result = monitor.check_health().await;
                    Ok::<_, warp::Rejection>(warp::reply::json(&result))
                }
                None => {
                    // Fallback for when no health monitor is available
                    Ok::<_, warp::Rejection>(warp::reply::json(
                        &serde_json::json!({"status": "healthy"}),
                    ))
                }
            }
        });

    let routes = metrics.or(health);

    let addr: std::net::IpAddr = bind_ip.parse().unwrap_or_else(|_| {
        tracing::warn!("Invalid bind IP '{}', defaulting to 127.0.0.1", bind_ip);
        "127.0.0.1".parse().unwrap()
    });

    tracing::info!("Starting metrics server on {}:{}", addr, port);
    warp::serve(routes).run((addr, port)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn toml_path(path: &Path) -> String {
        path.display().to_string().replace('\\', "\\\\")
    }

    fn write_dest_config(
        path: &Path,
        ca_cert: &Path,
        server_cert: &Path,
        server_key: &Path,
        tunnel_port: u16,
    ) -> std::io::Result<()> {
        let content = format!(
            r#"# Test destination config
[dest]
listen_ip = "127.0.0.1"
tunnel_port = {tunnel_port}
max_connections_per_service = 1
connection_timeout_ms = 1000
target_connect_timeout_ms = 1000

[[dest.exposed_services]]
name = "http"
port = 80
target_ip = "127.0.0.1"
target_port = 80
protocol = "tcp"

[dest.connection_filter]
allowed_source_ips = []

[auth]
use_mtls = true
ca_cert_path = "{ca_cert}"
server_cert_path = "{server_cert}"
server_key_path = "{server_key}"
verify_client_cert = true

[crypto]
kem_mode = "mlkem768"
key_rotation_interval_seconds = 3600
rehandshake_before_expiry_seconds = 300

[logging]
level = "info"
format = "json"
include_timestamp = true

[metrics]
enabled = false
metrics_port = 9091
metrics_bind_ip = "127.0.0.1"
"#,
            tunnel_port = tunnel_port,
            ca_cert = toml_path(ca_cert),
            server_cert = toml_path(server_cert),
            server_key = toml_path(server_key),
        );
        std::fs::write(path, content)
    }

    #[tokio::test]
    async fn test_dest_config_swap_blue_green() -> anyhow::Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let ca_cert = temp_dir.path().join("ca.crt");
        let server_cert = temp_dir.path().join("server.crt");
        let server_key = temp_dir.path().join("server.key");
        std::fs::write(&ca_cert, "ca")?;
        std::fs::write(&server_cert, "server")?;
        std::fs::write(&server_key, "key")?;

        let config_path = temp_dir.path().join("config.toml");
        write_dest_config(&config_path, &ca_cert, &server_cert, &server_key, 0)?;

        let args = cli::DestArgs {
            listen_ip: None,
            tunnel_port: None,
            metrics_port: None,
        };

        let (dest_config, crypto_config, metrics_config) = load_dest_settings(&config_path, &args)?;
        let mut metrics_state = MetricsState::new(&metrics_config);
        let mut dest = Arc::new(tunnel::DestContainer::new(dest_config, crypto_config).await?);
        dest.start().await?;
        let original = dest.clone();
        let mut run_handle = Some(tokio::spawn(async { Ok::<(), DestError>(()) }));

        // Invalid config should be rejected and not swap containers.
        let missing_ca = temp_dir.path().join("missing-ca.crt");
        write_dest_config(&config_path, &missing_ca, &server_cert, &server_key, 0)?;
        reload_dest_config(
            &config_path,
            &args,
            &mut dest,
            &mut run_handle,
            &mut metrics_state,
        )
        .await?;
        assert!(Arc::ptr_eq(&dest, &original));

        // Valid config should swap to a new container.
        write_dest_config(&config_path, &ca_cert, &server_cert, &server_key, 0)?;
        reload_dest_config(
            &config_path,
            &args,
            &mut dest,
            &mut run_handle,
            &mut metrics_state,
        )
        .await?;
        assert!(!Arc::ptr_eq(&dest, &original));

        dest.stop().await;
        if let Some(handle) = run_handle.take() {
            wait_for_run_handle(handle, "Destination").await;
        }

        Ok(())
    }
}
