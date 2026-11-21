//! The scrim-server binary: serves bare Git repositories over smart HTTP.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

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
    let mut env_filter = EnvFilter::new("info");
    if let Ok(from_env) = EnvFilter::try_from_default_env() {
        env_filter = from_env;
    }
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let config = Config::parse();
    if !config.repo_root.is_dir() {
        bail!(
            "repo root {} is not an existing directory",
            config.repo_root.display()
        );
    }
    let repo_root = match config
        .repo_root
        .canonicalize()
        .with_context(|| format!("cannot resolve repo root {}", config.repo_root.display()))
    {
        Ok(repo_root) => repo_root,
        Err(error) => return Err(error),
    };

    let listener = match tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))
    {
        Ok(listener) => listener,
        Err(error) => return Err(error),
    };
    let local_address = match listener
        .local_addr()
        .context("cannot read listener address")
    {
        Ok(local_address) => local_address,
        Err(error) => return Err(error),
    };
    tracing::warn!(
        "scrim-server is UNAUTHENTICATED: anyone who can reach {} can read and write every repository",
        local_address
    );
    tracing::info!(repo_root = %repo_root.display(), address = %local_address, "serving");

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
