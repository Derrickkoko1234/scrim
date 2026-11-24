# Scrim for Git

Scrim adds access control inside Git repositories: private branches, private files and folders, and built-in secrets management. It works with the standard `git` client. You keep using `git clone`, `git push` and `git pull`; Scrim adds what Git is missing.

A scrim is a theatre curtain that looks solid or see-through depending on how it is lit. Everyone shares the same repository, and each person sees as much as their access allows.

> **Status: early development.** Milestones M0–M5 are implemented: private branches over smart HTTP and SSH (`russh`), repo-versioned encrypted secrets (`scrim secrets`, `scrim run`, CI `SCRIM_KEY`, and `pre-receive` `.env`/credential scanning), encrypted private files via Git's clean/smudge filter (`scrim private`), server-side blob withholding (`gix` per-member object-graph filtering and `scrim clone` partial sparse checkouts), optional OS keychain identity storage, fail-closed external mirroring (`scrim mirror`), audited policy logs (`scrim audit`), Redis policy caching, and Cloudflare R2 backups. See the [roadmap](docs/ROADMAP.md), [security model](docs/security-model.md), [benchmarks](docs/benchmarks.md), [release guide](docs/releasing.md), and [Dokploy deployment guide](deploy/dokploy/README.md).

## Install

```sh
# Shell installer (macOS, Linux)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/Derrickkoko1234/scrim/releases/latest/download/scrim-cli-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Derrickkoko1234/scrim/releases/latest/download/scrim-cli-installer.ps1 | iex"

# Homebrew
brew install Derrickkoko1234/scrim/scrim-cli

# From crates.io (installs `scrim` and `git-scrim`)
cargo install scrim-cli --locked
```

Prebuilt CLI binaries for macOS (Apple silicon and Intel), Linux (`x86_64` and `arm64`), and Windows (`x86_64`) are attached to each [release](https://github.com/Derrickkoko1234/scrim/releases). The server is distributed as a container image at `ghcr.io/derrickkoko1234/scrim`.

**Requirements:** both `scrim` and `scrim-server` require Git **2.40.0 or newer** on `PATH` and check the version before running Git commands (`scrim-server` refuses to start on older Git). `scrim mirror` requires Git **2.44.1 or newer** because its fail-closed history scan depends on `GIT_NO_LAZY_FETCH=1`.

## Why

Git access is all-or-nothing per repository: a person sees every branch and every file, or nothing. Teams work around this with extra repositories, submodules, `.env` files passed around in chat, and third-party secret managers. Each workaround adds friction, and leaks still happen.

## What it does

- **Private branches** that only named groups can see, fetch or push over smart HTTP or SSH. Non-members never see the refs, cannot fetch their commits by hash, and cannot merge them into visible branches by accident.
- **Private files and folders** inside a shared repository. Contents are encrypted on the client with AES-256-SIV, so they stay protected on any remote, GitHub included (`scrim mirror`, or fully serverless with `scrim private recipients`). Repos hosted on `scrim-server` can also withhold protected blob bytes from non-members entirely (`scrim clone` over HTTP or SSH).
- **Secrets** stored and versioned with the code, encrypted per environment with XChaCha20-Poly1305, and injected at runtime with `scrim run`. No external secret manager and no `.env` files (works with `scrim-server` or offline via `scrim secrets recipients`).
- **Operations & auditing** built in: manage API tokens (`scrim token`), SSH keys (`scrim ssh-key`), repositories (`scrim repo list`), and access/override logs (`scrim audit`), mirror public refs safely (`scrim mirror`), and run streaming Cloudflare R2 backups with retention pruning (`scrim-server backup --keep`, `scrim-server backups list|prune`).

```sh
scrim branch private 'refs/heads/private/*' --group core
scrim private add 'config/billing/**' --group finance
scrim secrets set DATABASE_URL=postgres://… --scope dev
scrim run --scope dev -- cargo run
scrim clone team/app.git
scrim ssh-key add ~/.ssh/id_ed25519.pub
scrim audit --limit 20
scrim mirror github
```

## How it works

Scrim has two parts, both written in Rust:

- **`scrim` CLI**: a Git extension, installed like git-lfs and also callable as `git scrim`. It handles login, keys, encryption filters, secrets and access management.
- **`scrim-server`**: a self-hosted Git remote that enforces per-user visibility. It decides which branches, commits and file contents each user receives, and which pushes it accepts.

There is no web UI. Everything happens in the terminal.

Scrim implements no cryptographic primitives of its own. It uses audited crates only: `age`, and RustCrypto's `aes-siv` and `chacha20poly1305`. The [security model](docs/security-model.md) states what each feature protects and what it does not.

### OS keychain storage (macOS, Windows)

By default `scrim keygen` writes your age identity to `~/.config/scrim/identity.age` (`0600`). To keep it in the macOS Keychain or Windows Credential Manager instead:

```sh
scrim keygen --keychain          # store a new identity in the OS keychain
scrim keychain enable            # move an existing identity.age into the keychain
scrim keychain disable           # move it back to identity.age (0600)
```

Entries use service `scrim-for-git` and account `<member>@<server>`. `SCRIM_KEY` still takes precedence for CI. Other platforms report that keychain storage is unsupported.

### Performance

Unrestricted members clone and fetch at plain-git speed. Restricted members (paths withheld, refs hidden) pay for server-side object selection: on `git/git` (86k commits, 323 MiB), a restricted clone takes about 2× plain `git` and an incremental fetch about 3×, because the selection walk scales with history. Criterion micro-benchmarks, end-to-end HTTP and SSH timings, reproduction commands, and findings are in [docs/benchmarks.md](docs/benchmarks.md).

### Full-stack tests

`DATABASE_URL=postgres://… REDIS_URL=redis://localhost:6379 cargo test -p scrim-server --test full_stack -- --ignored` exercises `scrim-server` with real PostgreSQL, the Redis policy cache, and real `git`/`ssh` clients over both HTTP and SSH (run in CI's *PostgreSQL + Redis* job).

## License

| Component | License |
|---|---|
| `scrim-cli`, `scrim-crypto`, `scrim-policy` | [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE), at your option |
| `scrim-server` | [AGPL-3.0](LICENSE-AGPL) |

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Every commit needs a DCO `Signed-off-by` line.

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md). Do not open a public issue.

---

Git and the Git logo are either registered trademarks or trademarks of Software Freedom Conservancy, Inc., corporate home of the Git Project, in the United States and/or other countries. Scrim is not affiliated with or endorsed by the Git Project.
