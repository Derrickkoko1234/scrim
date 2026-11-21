//! Helpers shared by the integration tests: an isolated git environment and a
//! server running on an ephemeral port.

#![allow(dead_code)] // Each test binary uses a different subset.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::TempDir;

/// Runs real `git` commands with no access to the developer's own config.
pub struct GitSandbox {
    home: TempDir,
}

impl GitSandbox {
    pub fn new() -> Self {
        Self {
            home: TempDir::new().unwrap(),
        }
    }

    /// Runs `git <args>` in `dir`, panicking with git's output on failure.
    pub fn git(&self, dir: &Path, args: &[&str]) -> Output {
        self.git_with_env(dir, args, &[])
    }

    /// Like [`GitSandbox::git`] with extra environment variables.
    pub fn git_with_env(&self, dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
        let output = Command::new("git")
            .args([
                "-c",
                "user.name=Scrim Test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", self.home.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .envs(extra_env.iter().copied())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Creates an empty bare repository whose HEAD is `refs/heads/main`.
    pub fn init_bare(&self, path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        self.git(path, &["init", "--bare", "--initial-branch=main"]);
    }

    /// Creates a bare repository at `path` with one commit on `refs/heads/main`.
    pub fn init_bare_with_commit(&self, path: &Path) {
        self.init_bare(path);
        let work = TempDir::new().unwrap();
        self.git(work.path(), &["init", "--initial-branch=main"]);
        std::fs::write(work.path().join("hello.txt"), "hello\n").unwrap();
        self.git(work.path(), &["add", "hello.txt"]);
        self.git(work.path(), &["commit", "-m", "first"]);
        self.git(
            work.path(),
            &["push", path.to_str().unwrap(), "HEAD:refs/heads/main"],
        );
    }
}

/// Starts the server on an ephemeral loopback port and returns its base URL.
pub async fn spawn_server(repo_root: PathBuf) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, scrim_server::router(repo_root))
            .await
            .unwrap();
    });
    format!("http://{address}")
}
