# Changelog

All notable changes to Scrim for Git are documented in this file.

## [0.1.0] - 2026-11-25

Initial public release of Scrim for Git (`scrim` / `git-scrim` CLI, `scrim-server`, `scrim-policy`, and `scrim-crypto`).

### Highlights

- **Private branches (HTTP & SSH):** Per-member ref hiding (`scrim branch private`), protocol v0 downgrade with `allow*SHA1InWant` disabled, `deepen-not` and symbolic/detached `HEAD` guards, case-insensitive `pre-receive` authorization, thin-pack `REF_DELTA` smuggling protection, and audited merge-leak protection.
- **Built-in versioned secrets:** XChaCha20-Poly1305 per-scope secret encryption wrapped with `age` X25519 keys (`.scrim/secrets/<scope>.enc` and `.scrim/keys/<scope>.toml`), runtime injection (`scrim run`), dotenv export, CI zero-disk `SCRIM_KEY` support, offline team recipient management (`scrim secrets recipients`), automatic key rotation on revocation, and `pre-receive` plaintext `.env` and credential scanning.
- **Encrypted private files:** Deterministic AES-256-SIV file encryption via Git's long-running `filter-process` protocol (`scrim private`), readable non-member placeholders, offline team recipient management (`scrim private recipients`), and fail-closed overlap protection. Works on any Git host, including GitHub.
- **Server-side blob withholding:** Per-member isolated `gix` object-graph pack filtering (`scrim private add --withhold`) for both SHA-1 and SHA-256 repositories, non-commit ref hiding, `scrim clone` automatic partial-clone + sparse-checkout setup over both HTTP and SSH, and `pre-receive` withheld-path/republishing guards.
- **Operations, security & distribution:**
  - Git-over-SSH transport via `russh` (Ed25519/ECDSA-only, per-`exec` revocation checks) alongside smart HTTP.
  - Per-token listing and revocation (`scrim token`), SSH key management (`scrim ssh-key`), safe group deletion (`scrim group rm`), repository listing (`scrim repo list`), and append-only audit log (`scrim audit`).
  - Optional OS keychain identity storage on macOS and Windows (`scrim keygen --keychain`, `scrim keychain enable|disable`).
  - Fail-closed external mirroring (`scrim mirror`).
  - Redis epoch-keyed policy cache (`fred`) with automatic fallback to PostgreSQL.
  - Streaming Cloudflare R2 backups, verified restores, and retention pruning (`scrim-server backup --keep`, `scrim-server backups list|prune`, `scrim-server restore`).
  - Minimum Git version enforcement (`>= 2.40.0`; `>= 2.44.1` for `scrim mirror`).
  - Prebuilt CLI binaries, shell/PowerShell installers, Homebrew formula, and GHCR container image (`ghcr.io/derrickkoko1234/scrim`).
