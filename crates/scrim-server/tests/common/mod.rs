//! Helpers shared by the integration tests: an isolated git environment and a
//! server running on an ephemeral port.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Arc,
};

use axum::Router;
use base64::{Engine, engine::general_purpose::STANDARD};
use scrim_server::{PolicyStore, SecretString, TokenAuth};
use tempfile::TempDir;

/// Shared authentication token used across integration tests.
pub const TEST_TOKEN: &str = "scrim-test-token-0123456789abcdef";

/// Builds a [`TokenAuth`] from `token`, panicking if the token is invalid.
pub fn token_auth(token: &str) -> TokenAuth {
    match TokenAuth::new(SecretString::from(token.to_owned())) {
        Ok(auth) => auth,
        Err(error) => panic!("failed to construct test TokenAuth: {error}"),
    }
}

/// Builds a [`TokenAuth`] configured with [`TEST_TOKEN`].
pub fn test_auth() -> TokenAuth {
    token_auth(TEST_TOKEN)
}

/// Formats an HTTP `Authorization: Bearer ...` header value.
pub fn bearer_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Formats an HTTP `Authorization: Basic ...` header value from `user:password`.
pub fn basic_header(credentials: &str) -> String {
    format!("Basic {}", STANDARD.encode(credentials.as_bytes()))
}

/// Escapes `value` for safe inclusion inside single quotes in POSIX `sh`.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Runs real `git` commands with no access to the developer's own config.
pub struct GitSandbox {
    home: TempDir,
}

impl GitSandbox {
    pub fn new() -> Self {
        let home = match TempDir::new() {
            Ok(home) => home,
            Err(error) => panic!("failed to create git sandbox home: {error}"),
        };
        Self { home }
    }

    /// Runs `git <args>` in `dir`, panicking with git's output on failure.
    pub fn git(&self, dir: &Path, args: &[&str]) -> Output {
        self.git_with_env(dir, args, &[])
    }

    /// Runs `git <args>` in `dir` without asserting that the command succeeded.
    pub fn try_git(&self, dir: &Path, args: &[&str]) -> Output {
        self.try_git_with_env(dir, args, &[])
    }

    /// Like [`GitSandbox::try_git`] with extra environment variables.
    pub fn try_git_with_env(
        &self,
        dir: &Path,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> Output {
        let path = match std::env::var_os("PATH") {
            Some(path) => path,
            None => panic!("PATH is not set"),
        };
        match Command::new("git")
            .args([
                "-c",
                "user.name=Scrim Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(extra_env.iter().copied())
            .output()
        {
            Ok(output) => output,
            Err(error) => panic!("failed to run git {args:?}: {error}"),
        }
    }

    /// Like [`GitSandbox::git`] with extra environment variables.
    pub fn git_with_env(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let output = self.try_git_with_env(dir, args, extra_env);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Returns a `credential.helper=...` git `-c` config value that answers
    /// `get` requests with `username` and `password`.
    pub fn credential_helper_config(&self, username: &str, password: &str) -> String {
        let user = shell_single_quote(username);
        let pass = shell_single_quote(password);
        format!(
            "credential.helper=!f() {{ if [ \"$1\" = \"get\" ]; then printf 'username=%s\\npassword=%s\\n' {user} {pass}; fi; }}; f"
        )
    }

    /// Creates an empty bare repository whose HEAD is `refs/heads/main`.
    pub fn init_bare(&self, path: &Path) {
        if let Err(error) = std::fs::create_dir_all(path) {
            panic!(
                "failed to create repository directory {}: {error}",
                path.display()
            );
        }
        self.git(path, &["init", "--bare", "--initial-branch=main"]);
    }

    /// Creates a bare repository at `path` with one commit on `refs/heads/main`.
    pub fn init_bare_with_commit(&self, path: &Path) {
        self.init_bare(path);
        let work = match TempDir::new() {
            Ok(work) => work,
            Err(error) => panic!("failed to create work temp dir: {error}"),
        };
        self.git(work.path(), &["init", "--initial-branch=main"]);
        if let Err(error) = std::fs::write(work.path().join("hello.txt"), "hello\n") {
            panic!("failed to write hello.txt: {error}");
        }
        self.git(work.path(), &["add", "hello.txt"]);
        self.git(work.path(), &["commit", "-m", "first"]);
        let path = match path.to_str() {
            Some(path) => path,
            None => panic!("repository path is not valid UTF-8: {}", path.display()),
        };
        self.git(work.path(), &["push", path, "HEAD:refs/heads/main"]);
    }
}

/// Starts the server on an ephemeral loopback port and returns its base URL.
pub async fn spawn_server(repo_root: PathBuf, auth: TokenAuth) -> String {
    serve_router(scrim_server::router(repo_root, auth)).await
}

/// Like [`spawn_server`], with members and branch rules from `policy_store`.
pub async fn spawn_server_with_store(
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
) -> String {
    serve_router(scrim_server::router_with_policy_store(
        repo_root,
        policy_store,
    ))
    .await
}

/// Serves `router` on an ephemeral loopback port and returns its base URL.
async fn serve_router(router: Router) -> String {
    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) => panic!("failed to bind server listener: {error}"),
    };
    let address = match listener.local_addr() {
        Ok(address) => address,
        Err(error) => panic!("failed to read server address: {error}"),
    };
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, router).await {
            panic!("server failed: {error}");
        }
    });
    format!("http://{address}")
}
