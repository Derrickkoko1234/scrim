//! The scrim-server binary: serves bare Git repositories over smart HTTP.

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, bail};
use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Self-hosted Git remote for Scrim for Git.
#[derive(Parser)]
struct Config {
    /// Directory containing the bare repositories to serve.
    #[arg(long, env = "SCRIM_REPO_ROOT")]
    repo_root: PathBuf,

    /// Address to listen on. Defaults to loopback only because there is no
    /// authentication yet.
    #[arg(long, env = "SCRIM_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::parse();
    if !config.repo_root.is_dir() {
        bail!(
            "repo root {} is not an existing directory",
            config.repo_root.display()
        );
    }
    let repo_root = config
        .repo_root
        .canonicalize()
        .with_context(|| format!("cannot resolve repo root {}", config.repo_root.display()))?;

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))?;
    tracing::warn!(
        "scrim-server is UNAUTHENTICATED: anyone who can reach {} can read and write every repository",
        listener.local_addr()?
    );
    tracing::info!(repo_root = %repo_root.display(), address = %listener.local_addr()?, "serving");

    axum::serve(listener, scrim_server::router(repo_root))
        .with_graceful_shutdown(async {
            // If the signal handler cannot be installed, keep serving rather than exit.
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
            tracing::info!("shutting down");
        })
        .await
        .context("server error")
}
