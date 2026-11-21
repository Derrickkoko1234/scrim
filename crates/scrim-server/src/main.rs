//! The scrim-server binary: serves bare Git repositories over smart HTTP.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, bail};
use clap::Parser;
use scrim_server::{MAX_TOKEN_BYTES, SecretString, TokenAuth};
use secrecy::ExposeSecret;
use tokio::io::AsyncReadExt;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of bytes read from `--token-file` before rejecting it as
/// oversized: [`MAX_TOKEN_BYTES`] plus at most one trailing `\r\n`.
const MAX_TOKEN_FILE_BYTES: usize = MAX_TOKEN_BYTES + 2;

/// Recommended minimum token length in bytes before emitting a weak-token warning.
const RECOMMENDED_MIN_TOKEN_BYTES: usize = 16;

/// Self-hosted Git remote for Scrim for Git.
#[derive(Parser)]
struct Config {
    /// Directory containing the bare repositories to serve.
    #[arg(long, env = "SCRIM_REPO_ROOT")]
    repo_root: PathBuf,

    /// Address to listen on. Defaults to loopback; place behind a
    /// TLS-terminating reverse proxy if binding externally.
    #[arg(long, env = "SCRIM_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Authentication token required for all HTTP requests. Prefer passing
    /// `SCRIM_TOKEN` or `--token-file` in production so the token does not
    /// appear in process listings.
    #[arg(
        long,
        env = "SCRIM_TOKEN",
        hide_env_values = true,
        conflicts_with = "token_file",
        required_unless_present = "token_file"
    )]
    token: Option<String>,

    /// Path to a file containing the authentication token.
    #[arg(
        long,
        env = "SCRIM_TOKEN_FILE",
        conflicts_with = "token",
        required_unless_present = "token"
    )]
    token_file: Option<PathBuf>,
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

    let auth = match load_token_auth(config.token, config.token_file).await {
        Ok(auth) => auth,
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
    tracing::info!(repo_root = %repo_root.display(), address = %local_address, "serving");

    axum::serve(listener, scrim_server::router(repo_root, auth))
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

/// Loads the configured token from `--token` or `--token-file` and builds a [`TokenAuth`].
async fn load_token_auth(
    token: Option<String>,
    token_file: Option<PathBuf>,
) -> anyhow::Result<TokenAuth> {
    let secret_token = if let Some(raw_token) = token {
        // Allocate an exact-sized Box<str> directly so String -> Box<str>
        // cannot shrink/reallocate an unzeroized copy in freed heap memory.
        let raw_token = Zeroizing::new(raw_token);
        SecretString::from(Box::<str>::from(raw_token.as_str()))
    } else if let Some(path) = token_file {
        match read_token_file(&path).await {
            Ok(secret) => secret,
            Err(error) => return Err(error),
        }
    } else {
        bail!("either --token or --token-file must be provided");
    };

    let token_len = secret_token.expose_secret().len();
    let auth = match TokenAuth::new(secret_token) {
        Ok(auth) => auth,
        Err(error) => {
            return Err(anyhow::Error::new(error)).context("invalid authentication token");
        }
    };

    if token_len < RECOMMENDED_MIN_TOKEN_BYTES {
        tracing::warn!(
            min_recommended_bytes = RECOMMENDED_MIN_TOKEN_BYTES,
            "configured authentication token is short; consider using a longer random token"
        );
    }

    Ok(auth)
}

/// Opens a regular file at `path` without blocking on FIFOs or special files.
async fn open_regular_token_file(path: &Path) -> anyhow::Result<tokio::fs::File> {
    let mut open_options = tokio::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        // O_NONBLOCK prevents open() from blocking indefinitely on a FIFO with
        // no writer while still following symlinks (e.g. secret volume mounts).
        open_options.custom_flags(libc::O_NONBLOCK);
    }

    let file = match open_options.open(path).await {
        Ok(file) => file,
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot open token file {}", path.display()));
        }
    };
    let metadata = match file.metadata().await {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot inspect token file {}", path.display()));
        }
    };
    if !metadata.is_file() {
        bail!("token file {} must be a regular file", path.display());
    }
    Ok(file)
}

/// Reads an authentication token from `path`, capping the read and stripping at
/// most one trailing `\r\n` or `\n`.
async fn read_token_file(path: &Path) -> anyhow::Result<SecretString> {
    let file = match open_regular_token_file(path).await {
        Ok(file) => file,
        Err(error) => return Err(error),
    };

    // Pre-allocate the full cap so read_to_end never reallocates token bytes
    // into a larger buffer and leaves an unzeroized prefix behind.
    let mut raw_bytes = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_FILE_BYTES + 1));
    let mut limited = file.take((MAX_TOKEN_FILE_BYTES + 1) as u64);
    if let Err(error) = limited.read_to_end(&mut raw_bytes).await {
        return Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot read token file {}", path.display()));
    }
    if raw_bytes.len() > MAX_TOKEN_FILE_BYTES {
        bail!(
            "token file {} exceeds maximum size of {MAX_TOKEN_FILE_BYTES} bytes",
            path.display()
        );
    }

    let mut text = match String::from_utf8(std::mem::take(&mut *raw_bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            // Wipe invalid bytes before dropping so secret fragments do not linger.
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            bail!("token file {} is not valid UTF-8", path.display());
        }
    };

    // Strip a single trailing newline (`\r\n` or `\n`) commonly written by editors,
    // leaving any other whitespace intact so invalid tokens fail validation.
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }

    // Build an exact-sized Box<str> directly from the slice so String -> Box<str>
    // cannot shrink/reallocate and leave an unzeroized copy in freed heap memory.
    Ok(SecretString::from(Box::<str>::from(text.as_str())))
}
