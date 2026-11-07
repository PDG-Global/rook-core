#![forbid(unsafe_code)]

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rookd::{config::Config, server};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "rookd", version, about = "Security-first HTTP reverse proxy")]
struct Cli {
    #[arg(short, long, default_value = "rookd.toml")]
    config: PathBuf,

    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;
    if cli.check {
        server::validate_local(&config)?;
        println!("Configuration is valid: {}", cli.config.display());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    server::run(config).await
}
