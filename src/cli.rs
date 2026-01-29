use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Re-export CertCommand from cert module
pub use crate::cert::CertCommand;

#[derive(Parser)]
#[command(name = "utun")]
#[command(author, version, about = "Quantum-safe tunnel system", long_about = None)]
pub struct Cli {
    /// Configuration file path
    #[arg(short, long, global = true, default_value = "/etc/utun/config.toml")]
    pub config: PathBuf,

    /// Log level (debug, info, warn, error)
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    /// Log format (json, plain)
    #[arg(long, global = true, default_value = "json")]
    pub log_format: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run as source container (forward proxy)
    Source(SourceArgs),

    /// Run as destination container
    Dest(DestArgs),

    /// Certificate management
    #[command(subcommand)]
    Cert(CertCommand),

    /// Check health status
    Health(HealthArgs),

    /// Show version information
    Version,
}

#[derive(clap::Args)]
pub struct HealthArgs {
    /// Health check endpoint (HTTP)
    #[arg(long, default_value = "http://localhost:9090/health")]
    pub endpoint: String,

    /// Timeout in seconds
    #[arg(long, default_value = "5")]
    pub timeout: u64,
}

#[derive(clap::Args)]
pub struct SourceArgs {
    /// Override listen IP
    #[arg(long)]
    pub listen_ip: Option<String>,

    /// Override listen port
    #[arg(long)]
    pub listen_port: Option<u16>,

    /// Override destination host
    #[arg(long)]
    pub dest_host: Option<String>,

    /// Override destination tunnel port
    #[arg(long)]
    pub dest_tunnel_port: Option<u16>,

    /// Override metrics port
    #[arg(long)]
    pub metrics_port: Option<u16>,
}

#[derive(clap::Args)]
pub struct DestArgs {
    /// Override listen IP
    #[arg(long)]
    pub listen_ip: Option<String>,

    /// Override tunnel port
    #[arg(long)]
    pub tunnel_port: Option<u16>,

    /// Override metrics port
    #[arg(long)]
    pub metrics_port: Option<u16>,
}
