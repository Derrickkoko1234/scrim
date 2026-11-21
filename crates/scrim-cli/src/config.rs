//! Configuration and credential storage for the Scrim CLI.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow, bail};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Loaded Scrim CLI configuration.
pub struct ScrimConfig {
    /// Normalized base URL of the Scrim server (no trailing slash).
    pub server: Option<String>,
    /// Bearer token for authenticating to the Scrim server.
    pub token: Option<SecretString>,
}

impl std::fmt::Debug for ScrimConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token_state = if self.token.is_some() {
            Some("[REDACTED]")
        } else {
            None
        };
        f.debug_struct("ScrimConfig")
            .field("server", &self.server)
            .field("token", &token_state)
            .finish()
    }
}

#[derive(Deserialize)]
struct RawConfig {
    server: Option<String>,
    token: Option<String>,
}

impl Drop for RawConfig {
    fn drop(&mut self) {
        if let Some(tok) = self.token.as_mut() {
            tok.zeroize();
        }
    }
}

#[derive(Serialize)]
struct SerializableConfig<'a> {
    server: &'a str,
    token: &'a str,
}

/// Validates and normalizes a Scrim server URL by trimming whitespace and
/// trailing slashes.
///
/// # Errors
///
/// Returns an error if the URL is malformed, does not use `http` or `https`,
/// lacks a host, contains embedded credentials, or includes a query string or
/// fragment.
pub fn normalize_server_url(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        bail!("server URL cannot be empty");
    }
    if trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("server URL must not contain whitespace");
    }
    if !trimmed.starts_with("https://") && !trimmed.starts_with("http://") {
        bail!("server URL must start with http:// or https://");
    }

    let parsed = match reqwest::Url::parse(trimmed) {
        Ok(url) => url,
        Err(err) => return Err(anyhow!("invalid server URL: {err}")),
    };
    if !parsed.has_host() {
        bail!("server URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("server URL must not contain embedded credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("server URL must not contain a query string or fragment");
    }

    Ok(trimmed.to_owned())
}

/// Resolves the path to `config.toml` according to CLI flags and environment
/// variables.
///
/// Precedence (first non-empty match wins):
/// 1. `--config <PATH>` or `SCRIM_CONFIG`
/// 2. `SCRIM_CONFIG_DIR` -> `<dir>/config.toml`
/// 3. `XDG_CONFIG_HOME` -> `<dir>/scrim/config.toml`
/// 4. `HOME` (or `USERPROFILE` on Windows) -> `<home>/.config/scrim/config.toml`
pub fn resolve_config_path(
    cli_config: Option<&Path>,
    env_lookup: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = cli_config
        && !path.as_os_str().is_empty()
    {
        return Ok(path.to_path_buf());
    }

    if let Some(path) = non_empty_env(env_lookup, "SCRIM_CONFIG") {
        return Ok(PathBuf::from(path));
    }

    if let Some(dir) = non_empty_env(env_lookup, "SCRIM_CONFIG_DIR") {
        return Ok(PathBuf::from(dir).join("config.toml"));
    }

    if let Some(xdg) = non_empty_env(env_lookup, "XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("scrim").join("config.toml"));
    }

    if let Some(home) = non_empty_env(env_lookup, "HOME") {
        return Ok(PathBuf::from(home)
            .join(".config")
            .join("scrim")
            .join("config.toml"));
    }

    #[cfg(windows)]
    if let Some(profile) = non_empty_env(env_lookup, "USERPROFILE") {
        return Ok(PathBuf::from(profile)
            .join(".config")
            .join("scrim")
            .join("config.toml"));
    }

    Err(anyhow!(
        "cannot determine config file path: set --config, SCRIM_CONFIG, SCRIM_CONFIG_DIR, XDG_CONFIG_HOME, or HOME"
    ))
}

fn non_empty_env(env_lookup: &dyn Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    match env_lookup(key) {
        Some(value) if !value.is_empty() => Some(value),
        _ => None,
    }
}

/// Loads `config.toml` from `path`, returning `Ok(None)` if the file does not
/// exist.
pub fn load_config(path: &Path) -> anyhow::Result<Option<ScrimConfig>> {
    let contents = match fs::read_to_string(path) {
        Ok(text) => Zeroizing::new(text),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read config file {}", path.display()));
        }
    };

    let mut raw: RawConfig = match toml::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to parse config file {}", path.display()));
        }
    };

    let server = match raw.server.take() {
        Some(url) if !url.trim().is_empty() => Some(match normalize_server_url(&url) {
            Ok(normalized) => normalized,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("invalid server URL in config file {}", path.display())
                });
            }
        }),
        _ => None,
    };

    let token = match raw.token.take() {
        Some(mut tok) => {
            let trimmed = tok.trim();
            let result = if trimmed.is_empty() {
                None
            } else {
                Some(SecretString::from(trimmed))
            };
            tok.zeroize();
            result
        }
        None => None,
    };

    Ok(Some(ScrimConfig { server, token }))
}

/// Saves `server` and `token` to `path` with restricted permissions (`0o700`
/// for newly created directories, `0o600` for the file on Unix).
pub fn save_config(path: &Path, server: &str, token: &SecretString) -> anyhow::Result<()> {
    let normalized_server = match normalize_server_url(server) {
        Ok(url) => url,
        Err(err) => return Err(err),
    };

    let parent = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };

    if let Err(err) = create_restricted_dir_all(parent) {
        return Err(err);
    }

    let payload = SerializableConfig {
        server: &normalized_server,
        token: token.expose_secret(),
    };
    let toml_text = match toml::to_string_pretty(&payload) {
        Ok(text) => Zeroizing::new(text),
        Err(err) => return Err(anyhow!("failed to serialize config: {err}")),
    };

    write_secret_file_atomic(path, parent, toml_text.as_bytes())
}

fn create_restricted_dir_all(dir: &Path) -> anyhow::Result<()> {
    if dir.exists() {
        return Ok(());
    }

    let mut missing = Vec::new();
    let mut current = Some(dir);
    while let Some(candidate) = current {
        if candidate.exists() {
            break;
        }
        missing.push(candidate.to_path_buf());
        current = candidate.parent();
    }

    for component in missing.into_iter().rev() {
        if component.as_os_str().is_empty() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&component) {
                Ok(()) => {
                    if let Err(err) =
                        fs::set_permissions(&component, fs::Permissions::from_mode(0o700))
                    {
                        return Err(anyhow!(err)).with_context(|| {
                            format!(
                                "failed to set 0700 permissions on directory {}",
                                component.display()
                            )
                        });
                    }
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(anyhow!(err)).with_context(|| {
                        format!("failed to create directory {}", component.display())
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            match fs::create_dir(&component) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(anyhow!(err)).with_context(|| {
                        format!("failed to create directory {}", component.display())
                    });
                }
            }
        }
    }

    Ok(())
}

fn write_secret_file_atomic(path: &Path, parent: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let pid = std::process::id();
    let mut last_err = None;

    for _ in 0..16 {
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".config.toml.tmp.{pid}.{seq}");
        let tmp_path = parent.join(tmp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let file = match options.open(&tmp_path) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                last_err = Some(err);
                continue;
            }
            Err(err) => {
                return Err(anyhow!(err)).with_context(|| {
                    format!(
                        "failed to create temporary config file {}",
                        tmp_path.display()
                    )
                });
            }
        };

        let write_result = write_and_rename(file, &tmp_path, path, contents);
        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        return write_result;
    }

    match last_err {
        Some(err) => Err(anyhow!(err)).context("failed to allocate temporary config file"),
        None => Err(anyhow!("failed to allocate temporary config file")),
    }
}

fn write_and_rename(
    mut file: fs::File,
    tmp_path: &Path,
    dest_path: &Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    if let Err(err) = file.write_all(contents) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to write config file {}", tmp_path.display()));
    }
    if let Err(err) = file.flush() {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to flush config file {}", tmp_path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = fs::set_permissions(tmp_path, fs::Permissions::from_mode(0o600)) {
            return Err(anyhow!(err)).with_context(|| {
                format!("failed to set 0600 permissions on {}", tmp_path.display())
            });
        }
    }
    if let Err(err) = file.sync_all() {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to sync config file {}", tmp_path.display()));
    }
    drop(file);

    if let Err(err) = fs::rename(tmp_path, dest_path) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to replace config file {}", dest_path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn env_from_pairs(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_owned(), (*v).to_owned());
        }
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn resolves_config_path_by_precedence() {
        let env = env_from_pairs(&[
            ("SCRIM_CONFIG", "/env/config.toml"),
            ("SCRIM_CONFIG_DIR", "/env_dir"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/home/alice"),
        ]);

        let cli_path = match resolve_config_path(Some(Path::new("/cli/my.toml")), &env) {
            Ok(path) => path,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(cli_path, PathBuf::from("/cli/my.toml"));

        let scrim_config = match resolve_config_path(None, &env) {
            Ok(path) => path,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(scrim_config, PathBuf::from("/env/config.toml"));

        let env_dir = env_from_pairs(&[
            ("SCRIM_CONFIG", ""),
            ("SCRIM_CONFIG_DIR", "/env_dir"),
            ("XDG_CONFIG_HOME", "/xdg"),
            ("HOME", "/home/alice"),
        ]);
        let resolved = match resolve_config_path(None, &env_dir) {
            Ok(path) => path,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(resolved, PathBuf::from("/env_dir/config.toml"));

        let env_xdg = env_from_pairs(&[("XDG_CONFIG_HOME", "/xdg"), ("HOME", "/home/alice")]);
        let resolved = match resolve_config_path(None, &env_xdg) {
            Ok(path) => path,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(resolved, PathBuf::from("/xdg/scrim/config.toml"));

        let env_home = env_from_pairs(&[("XDG_CONFIG_HOME", ""), ("HOME", "/home/alice")]);
        let resolved = match resolve_config_path(None, &env_home) {
            Ok(path) => path,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(
            resolved,
            PathBuf::from("/home/alice/.config/scrim/config.toml")
        );
    }

    #[test]
    fn normalizes_and_validates_server_urls() {
        let http = match normalize_server_url("http://127.0.0.1:8080///") {
            Ok(url) => url,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(http, "http://127.0.0.1:8080");

        let https = match normalize_server_url("  https://git.example.com/scrim/  ") {
            Ok(url) => url,
            Err(err) => panic!("unexpected error: {err}"),
        };
        assert_eq!(https, "https://git.example.com/scrim");

        assert!(normalize_server_url("git.example.com").is_err());
        assert!(normalize_server_url("ftp://git.example.com").is_err());
        assert!(normalize_server_url("https://").is_err());
        assert!(normalize_server_url("https://user:pass@git.example.com").is_err());
        assert!(normalize_server_url("https://git.example.com?foo=bar").is_err());
        assert!(normalize_server_url("https://git.example.com#section").is_err());
        assert!(normalize_server_url("https://git.example.com/bad path").is_err());
    }

    #[test]
    fn config_roundtrip_permissions_and_debug_redaction() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let config_dir = dir.path().join("nested").join("scrim");
        let config_path = config_dir.join("config.toml");
        let secret = SecretString::from("scrim_super_secret_token_12345");

        if let Err(err) = save_config(&config_path, "https://scrim.example.com/", &secret) {
            panic!("save_config failed: {err}");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_meta = match fs::metadata(&config_dir) {
                Ok(m) => m,
                Err(err) => panic!("metadata failed: {err}"),
            };
            assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);

            let file_meta = match fs::metadata(&config_path) {
                Ok(m) => m,
                Err(err) => panic!("metadata failed: {err}"),
            };
            assert_eq!(file_meta.permissions().mode() & 0o777, 0o600);
        }

        let loaded = match load_config(&config_path) {
            Ok(Some(cfg)) => cfg,
            Ok(None) => panic!("expected config to exist"),
            Err(err) => panic!("load_config failed: {err}"),
        };
        assert_eq!(loaded.server.as_deref(), Some("https://scrim.example.com"));
        let loaded_token = match &loaded.token {
            Some(tok) => tok,
            None => panic!("expected token to be present"),
        };
        assert_eq!(
            loaded_token.expose_secret(),
            "scrim_super_secret_token_12345"
        );

        let debug_output = format!("{loaded:?}");
        assert!(
            !debug_output.contains("scrim_super_secret_token_12345"),
            "Debug output leaked secret: {debug_output}"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }
}
