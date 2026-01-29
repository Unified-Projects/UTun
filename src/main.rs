use clap::Parser;
use std::sync::Arc;
use tokio::signal;
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
use health::{HealthCheckResult, HealthStatus};

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

async fn run_source(config_path: std::path::PathBuf, args: cli::SourceArgs) -> anyhow::Result<()> {
    let mut config = config::load_config(&config_path)?;

    let mut source_config = config
        .source
        .ok_or_else(|| anyhow::anyhow!("Source configuration not found in config file"))?;

    // Apply CLI overrides
    if let Some(ip) = args.listen_ip {
        source_config.listen_ip = ip;
    }
    if let Some(port) = args.listen_port {
        source_config.listen_port = port;
    }
    if let Some(host) = args.dest_host {
        source_config.dest_host = host;
    }
    if let Some(port) = args.dest_tunnel_port {
        source_config.dest_tunnel_port = port;
    }
    if let Some(port) = args.metrics_port {
        config.metrics.metrics_port = port;
    }

    // Create and run source container
    tracing::info!("Starting UTun source container");
    let source = Arc::new(tunnel::SourceContainer::new(source_config, config.crypto).await?);

    // Start metrics server with health monitor
    if config.metrics.enabled {
        let health_monitor = source.health_monitor();
        tokio::spawn(start_metrics_server(
            config.metrics.metrics_bind_ip.clone(),
            config.metrics.metrics_port,
            Some(health_monitor),
        ));
    }

    source.start().await?;

    // Spawn the main run loop
    let source_run = source.clone();
    let run_handle = tokio::spawn(async move { source_run.run().await });

    // Wait for shutdown signal
    wait_for_shutdown_signal().await;

    // Graceful shutdown
    tracing::info!("Initiating graceful shutdown...");
    source.stop().await;

    // Wait for run loop to complete with timeout
    match tokio::time::timeout(std::time::Duration::from_secs(30), run_handle).await {
        Ok(result) => {
            if let Err(e) = result {
                tracing::error!("Run task panicked: {}", e);
            }
        }
        Err(_) => {
            tracing::warn!("Shutdown timed out after 30 seconds");
        }
    }

    tracing::info!("Shutdown complete");
    Ok(())
}

async fn run_dest(config_path: std::path::PathBuf, args: cli::DestArgs) -> anyhow::Result<()> {
    let mut config = config::load_config(&config_path)?;

    let mut dest_config = config
        .dest
        .ok_or_else(|| anyhow::anyhow!("Destination configuration not found in config file"))?;

    // Apply CLI overrides
    if let Some(ip) = args.listen_ip {
        dest_config.listen_ip = ip;
    }
    if let Some(port) = args.tunnel_port {
        dest_config.tunnel_port = port;
    }
    if let Some(port) = args.metrics_port {
        config.metrics.metrics_port = port;
    }

    // Create and run destination container
    tracing::info!("Starting UTun destination container");
    let dest = Arc::new(tunnel::DestContainer::new(dest_config, config.crypto).await?);

    // Start metrics server with health monitor
    if config.metrics.enabled {
        let health_monitor = dest.health_monitor();
        tokio::spawn(start_metrics_server(
            config.metrics.metrics_bind_ip.clone(),
            config.metrics.metrics_port,
            Some(health_monitor),
        ));
    }

    dest.start().await?;

    // Spawn the main run loop
    let dest_run = dest.clone();
    let run_handle = tokio::spawn(async move { dest_run.run().await });

    // Wait for shutdown signal
    wait_for_shutdown_signal().await;

    // Graceful shutdown
    tracing::info!("Initiating graceful shutdown...");
    dest.stop().await;

    // Wait for run loop to complete with timeout
    match tokio::time::timeout(std::time::Duration::from_secs(30), run_handle).await {
        Ok(result) => {
            if let Err(e) = result {
                tracing::error!("Run task panicked: {}", e);
            }
        }
        Err(_) => {
            tracing::warn!("Shutdown timed out after 30 seconds");
        }
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

async fn start_metrics_server(
    bind_ip: String,
    port: u16,
    health_monitor: Option<std::sync::Arc<health::HealthMonitor>>,
) {
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
        .and_then(
            |health_monitor: Option<std::sync::Arc<health::HealthMonitor>>| async move {
                match health_monitor {
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
            },
        );

    let routes = metrics.or(health);

    let addr: std::net::IpAddr = bind_ip.parse().unwrap_or_else(|_| {
        tracing::warn!("Invalid bind IP '{}', defaulting to 127.0.0.1", bind_ip);
        "127.0.0.1".parse().unwrap()
    });

    tracing::info!("Starting metrics server on {}:{}", addr, port);
    warp::serve(routes).run((addr, port)).await;
}
