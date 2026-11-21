# Scrim — Project Plan

## What Scrim is

Scrim adds access control inside Git repositories: private branches, private files and folders, and built-in secrets management. It works with the standard `git` client. Developers keep using `git clone`, `git push` and `git pull`; Scrim adds what Git is missing.

The name comes from theatre: a scrim is a stage curtain that looks solid or see-through depending on how it is lit. Everyone shares the same repository, and each person sees as much as their access allows.

Public naming follows Git's trademark policy: the product is "Scrim for Git", and the name never combines with "Git" into a single word.

Scrim has two parts, both written in Rust:

- **`scrim` CLI**: a Git extension, installed like git-lfs. It handles login, keys, encryption filters, secrets and access management. It can also be called as `git scrim …`.
- **`scrim-server`**: a Git remote that enforces per-user visibility. It decides which branches, commits and file contents each user receives, and which pushes it accepts.

There is no web UI. All work happens in the terminal; the server exposes an admin API that the CLI talks to.

## The problem

Git access is all-or-nothing per repository. A person either sees the entire repo, every branch and every file, or nothing. Teams work around this with extra repositories, submodules, `.env` files passed around in chat, and third-party secret managers. Each workaround adds friction, and leaks still happen, such as a `.env` committed by mistake.

## Goals

1. Private branches that only named members can see, fetch or push.
2. Private files and folders inside a shared repository, readable only by named members.
3. Secrets stored and versioned with the code, injected at runtime, with no external tool.
4. Full compatibility with the standard `git` client and existing workflows.
5. A security model that is written down, tested and honest about what it guarantees.
6. Fully open source, so anyone can audit how their code and secrets are protected.

## Non-goals

- Replacing or forking the `git` client.
- A forge: no web code browser, pull requests, issues or CI.
- Hosting other people's repositories as a SaaS in v1. The server is self-hosted.

## Open source and licensing

Scrim is open source from the first commit. A tool that encrypts and gates people's code has to be auditable to be trusted, and open source is how developer tools spread.

| Component | License | Why |
|---|---|---|
| `scrim-cli`, `scrim-crypto`, `scrim-policy` | MIT OR Apache-2.0 (dual) | The Rust ecosystem standard. Companies can adopt the CLI and embed the crates without legal review |
| `scrim-server` | AGPL-3.0 | Anyone can self-host and modify it, but anyone offering it as a hosted service must publish their changes. This stops a closed, resold copy of the server |

- Contributions use the Developer Certificate of Origin: each commit carries a `Signed-off-by` line, enforced by a CI check.
- The repository includes `LICENSE-MIT`, `LICENSE-APACHE` and `LICENSE-AGPL`, a `SECURITY.md` with a private vulnerability reporting address, and a `CONTRIBUTING.md`.
- Each crate's `Cargo.toml` declares its license, and `cargo-deny` checks every dependency license in CI.

## Core concepts

| Concept | Meaning |
|---|---|
| Member | A person or machine (such as CI) with a Scrim account and a keypair |
| Group | A named set of members, such as `core` or `contractors` |
| Branch rule | A ref glob (`refs/heads/private/*`) mapped to the groups that can see it |
| Path rule | A path glob (`config/billing/**`) mapped to the groups that can read it |
| Secret scope | An environment (`dev`, `staging`, `prod`) mapped to the groups that can read its secrets |
| Audit log | An append-only record of every access change, grant and revoke |

Policy is stored on the server in Postgres. `scrim access …` commands change it, and every change is written to the audit log.

## Architecture

```
Developer machine                         scrim-server (axum + tokio)
─────────────────                         ───────────────────────────
git  ──── smart HTTP (later SSH) ───────▶ Transport layer
  │                                         │  spawns git upload-pack / receive-pack
  │  clean/smudge filter                    │  with per-user config (hidden refs)
  ▼                                         ▼
scrim CLI ─────── admin API (HTTPS) ────▶ Policy engine ──▶ Postgres (members, groups,
  │                                         │                rules, audit log)
  │  keys in ~/.config/scrim                ├─▶ Redis (policy cache)
  ▼                                         ├─▶ Pre-receive guards (merge leaks,
scrim-crypto (age, AES-SIV,                 │    plaintext secret scan)
XChaCha20-Poly1305)                         └─▶ Bare repos on disk, backups to R2
```

**Request flow for a fetch:** authenticate the token → load the member's policy (from the Redis cache, falling back to Postgres) → compute the refs that member may not see → spawn `git upload-pack` through `tokio::process` with those refs hidden → stream the response back through axum.

`scrim-policy` (rule matching) and `scrim-crypto` are shared by the server and the CLI, so both sides apply identical rules.

## Security model

This section states what each feature protects and what it does not.

**Private branches**
- Guaranteed: non-members never see hidden refs in the ref list, cannot fetch objects that are reachable only from hidden refs, and cannot push to hidden refs.
- Not hidden: objects shared with visible branches, which those members can already see.
- Leak path handled: merging a private branch into a visible one. A pre-receive guard rejects pushes that would expose commits reachable only from hidden refs. The member can squash instead or pass an explicit override flag that is logged.

**Private files (encrypted, works on any remote)**
- Guaranteed: file contents are encrypted on the client with AES-SIV. Non-members and the server see only ciphertext.
- Not hidden: the path name, approximate size and when the file changed.
- Trade-off: AES-SIV is deterministic, so Git does not see every file as modified on each run. As a result, identical content produces identical ciphertext. This is documented.

**Private files (withheld, Scrim server only)**
- Guaranteed: the server never sends the file's bytes to non-members.
- Not hidden: the tree entry, which shows the file name and its blob hash.

**Secrets**
- Values are encrypted with XChaCha20-Poly1305 under a data key for each scope. That key is wrapped separately for each member's age (X25519) public key.
- Revoking a member rotates the data key and re-encrypts everything in their scopes. A former member keeps whatever they already decrypted, so the CLI lists every secret in their scopes for rotation at its source (database passwords, API keys).

**Keys and memory**
- Each member's private key lives in `~/.config/scrim`, with optional OS keychain storage through the `keyring` crate.
- Machine members (CI) receive their key through an environment variable, `SCRIM_KEY`.
- Key material and decrypted values are held in `secrecy`/`zeroize` types so they are wiped from memory after use.

**Crypto rules**
- Scrim implements no primitives of its own. It uses audited crates only: `age`, and the RustCrypto `aes-siv` and `chacha20poly1305` crates.

## Milestones

### M0: Foundations (weeks 1–2)

Learn Git's internals by building a server that only passes requests through.

- Read Pro Git chapter 10 (Git Internals), the Git protocol v2 docs, and the `gitprotocol-http` docs.
- Set up the Cargo workspace, CI (`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`, `cargo deny`), license files and the DCO check.
- Build an axum server that serves bare repos over smart HTTP by spawning `git upload-pack` and `git receive-pack` through `tokio::process`, streaming stdin and stdout.
- Add basic token auth.
- Build the end-to-end test harness (see Testing).

**Done when:** you can clone, fetch and push through your own server with token auth, and an end-to-end test proves it.

### M1: Private branches (weeks 3–5)

- Postgres schema and migrations with `sqlx`: members, groups, memberships, branch rules, audit log.
- `scrim-policy`: given a member and a repo, return the hidden ref patterns. Glob matching with `globset`.
- Spawn Git per request with `-c transfer.hideRefs=<pattern>` for each hidden pattern, and turn off `uploadpack.allowTipSHA1InWant`, `uploadpack.allowReachableSHA1InWant` and `uploadpack.allowAnySHA1InWant`.
- Pre-receive guard that blocks pushes leaking hidden commits into visible branches.
- CLI (built with `clap`): `scrim login`, `scrim init` (connect a repo to the server), `scrim group create|add|remove`, `scrim access grant|revoke|list`, `scrim branch private <glob> --group <name>`.
- Leak tests under protocol v0 and v2 (see Testing).

**Done when:** the leak test suite proves that a non-member cannot list, fetch by hash, or push to a private branch, and that the merge guard blocks leaking pushes.

### M2: Secrets (weeks 6–8)

- Storage in the repo: `.scrim/secrets/<scope>.enc` (encrypted values) and `.scrim/keys/<scope>.toml` (the data key wrapped for each member with `age`). Secrets are versioned with the code and work offline.
- CLI commands: `scrim secrets set KEY=value --scope dev`, `get`, `list`, `rm`, `scrim run --scope dev -- <command>` (injects secrets as environment variables), `scrim secrets export --format dotenv`.
- Revocation flow: `scrim access revoke` rewraps keys, re-encrypts values and prints the secrets to rotate at their source.
- Pre-receive scan that rejects plaintext `.env` files and common secret patterns.
- CI support: machine members, with `SCRIM_KEY` read from the environment.

**Done when:** a team can replace `.env` sharing entirely. Revoking a member stops them from decrypting new commits, and the server rejects pushes that contain a plaintext `.env`.

### M3: Private files with encryption (weeks 9–11)

- A Git clean/smudge filter named `scrim`, enabled through `.gitattributes` and run as a long-running filter process (Git's `filter.<name>.process` protocol) for speed. Path rules map paths to groups, and each group has its own data key.
- Deterministic authenticated encryption with AES-SIV.
- Non-members get a placeholder file on checkout instead of an error.
- CLI commands: `scrim private add <glob> --group <name>`, `scrim private rm <glob>`, `scrim private status`.
- Works against any remote, GitHub included.

**Done when:** private paths round-trip for members, non-members see placeholders, `git status` stays clean, and the same repo works when pushed to GitHub.

### M4: Server-side withholding (weeks 12–15)

- For repos hosted on `scrim-server`: walk the object graph per member with `gix` (gitoxide) and build packs that exclude blobs at private paths, either with gitoxide's pack writer or by feeding the object list to `git pack-objects --stdin`.
- Configure non-member clones as partial clones (promisor remote), with sparse checkout excluding withheld paths, so checkout does not fail on missing blobs.
- The CLI sets up this configuration automatically during `scrim clone`.

**Done when:** a non-member's clone checks out cleanly, and a wire-capture test proves no protected blob bytes were sent.

### M5: Hardening and operations (weeks 16–18)

- SSH transport alongside HTTP, using `russh`.
- Mirroring to GitHub: push visible branches only, with private paths encrypted.
- `scrim audit` to read the audit log from the CLI.
- Backups of bare repos and Postgres to Cloudflare R2.
- Deployment through Dokploy, from a container image published by CI.
- Performance: Redis policy cache, and clone and fetch benchmarks on a large public repo with `criterion` and end-to-end timings.
- Fuzzing the filter protocol and policy parser with `cargo-fuzz`.
- A full threat-model review against the Security model section.

**Done when:** Scrim runs in production for your own projects, with backups, both transports and benchmark numbers recorded.

**v1 = M0 through M3.** M4 and M5 follow once v1 is in daily use.

## Tech stack

| Area | Choice |
|---|---|
| Language | Rust (stable), 2021 edition or later |
| Async runtime | Tokio |
| HTTP server | axum, with tower middleware for auth and tracing |
| Database | PostgreSQL via `sqlx` (compile-time checked queries, migrations) |
| Cache | Redis via `fred` |
| Git transport | System `git` (2.40 or later), spawned with `tokio::process` |
| Git object access | `gix` (gitoxide), from M4 |
| SSH | `russh`, from M5 |
| Key wrapping | `age` (X25519) |
| File encryption | `aes-siv` (RustCrypto) |
| Secret encryption | `chacha20poly1305` (XChaCha20-Poly1305) |
| Secret handling | `secrecy`, `zeroize`, `keyring` |
| CLI | `clap` |
| Config files | `serde` + `toml` |
| Logging | `tracing` |
| Errors | `thiserror` in libraries, `anyhow` in binaries |
| Tests | `cargo test`, `assert_cmd`, `tempfile`, `testcontainers` (Postgres, Redis) |
| Release | `cargo-dist`: prebuilt binaries for macOS, Linux and Windows, a Homebrew tap, a shell installer, and `cargo install scrim-cli` |
| Backups | Cloudflare R2 |
| Deployment | Dokploy |

**Crate names on crates.io:** `scrim` is taken by an unrelated project, so the crates are `scrim-cli` (installs the `scrim` and `git-scrim` binaries), `scrim-server`, `scrim-crypto` and `scrim-policy`.

## Repository structure

```
scrim/
├── Cargo.toml          # workspace
├── crates/
│   ├── scrim-cli/      # scrim and git-scrim binaries        (MIT OR Apache-2.0)
│   ├── scrim-server/   # axum app: transport, admin API, guards (AGPL-3.0)
│   ├── scrim-policy/   # rule matching shared by server and CLI (MIT OR Apache-2.0)
│   └── scrim-crypto/   # key wrapping, secret and file encryption (MIT OR Apache-2.0)
├── tests/
│   └── e2e/            # spins up the server, runs git as multiple users
├── docs/
│   └── security-model.md
├── LICENSE-MIT
├── LICENSE-APACHE
├── LICENSE-AGPL
├── SECURITY.md
└── CONTRIBUTING.md
```

## Testing

Security claims are only as good as their tests. The end-to-end harness starts a real server with Postgres and Redis in containers, creates several members with different access, and runs real `git` commands as each of them.

Required leak tests:

- A non-member's `git ls-remote` does not list hidden refs.
- A non-member cannot fetch a hidden commit by its exact hash, under protocol v0 and v2.
- A non-member cannot push to a hidden ref, create one or delete one.
- Pushing a merge of a private branch into a visible branch is rejected.
- A non-member's checkout of an encrypted path yields a placeholder, never plaintext.
- After revocation, the former member cannot decrypt secrets or files committed afterward.
- A plaintext `.env` push is rejected.
- (M4) Packet capture shows no protected blob bytes on the wire.

Every security bug found later becomes a new test in this list before it is fixed.

## Risks

| Risk | Mitigation |
|---|---|
| Protocol v2 handles object requests differently from v0 | Leak tests run under both protocols on every CI run |
| Revoked members keep what they already saw | Documented. The CLI lists secrets to rotate at their source |
| Deterministic encryption reveals repeated content | Documented in the security model. The choice keeps `git status` usable |
| Spawning `git` per request is slow at scale | Redis policy cache now, benchmarks in M5, and gitoxide available for moving hot paths in-process |
| Behaviour differs between Git versions | Minimum server Git version enforced, and the client version is checked by the CLI |
| A dependency introduces a vulnerability or license conflict | `cargo-deny` and `cargo-audit` run in CI on every change |
