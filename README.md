# Scrim for Git

Scrim adds access control inside Git repositories: private branches, private files and folders, and built-in secrets management. It works with the standard `git` client. You keep using `git clone`, `git push` and `git pull`; Scrim adds what Git is missing.

A scrim is a theatre curtain that looks solid or see-through depending on how it is lit. Everyone shares the same repository, and each person sees as much as their access allows.

> **Status: early development.** Milestones M1–M3 (Scrim v1 — private branches, repo-versioned encrypted secrets with CI `SCRIM_KEY` and pre-receive `.env`/secret scanning, and encrypted private files via Git's clean/smudge filter) and M4 (server-side withholding via `gix` per-member object-graph filtering, `uploadpack.packObjectsHook`, `pre-receive` withheld-path/blob guards, `/api/v1/path-rules`, `scrim private --withhold`, and `scrim clone` partial sparse checkouts) are implemented; Milestone M5 (hardening and operations) is next. See the [roadmap](docs/ROADMAP.md).

## Why

Git access is all-or-nothing per repository: a person sees every branch and every file, or nothing. Teams work around this with extra repositories, submodules, `.env` files passed around in chat, and third-party secret managers. Each workaround adds friction, and leaks still happen.

## What it will do

- **Private branches** that only named groups can see, fetch or push. Non-members never see the refs, cannot fetch their commits by hash, and cannot merge them into visible branches by accident.
- **Private files and folders** inside a shared repository. Contents are encrypted on the client, so they stay protected on any remote, GitHub included. Repos hosted on `scrim-server` can also withhold the bytes from non-members entirely.
- **Secrets** stored and versioned with the code, encrypted per environment, and injected at runtime with `scrim run`. No external secret manager and no `.env` files.

```sh
scrim branch private 'refs/heads/private/*' --group core
scrim private add 'config/billing/**' --group finance
scrim secrets set DATABASE_URL=postgres://… --scope dev
scrim run --scope dev -- cargo run
```

*(Planned interface; subject to change.)*

## How it works

Scrim has two parts, both written in Rust:

- **`scrim` CLI**: a Git extension, installed like git-lfs and also callable as `git scrim`. It handles login, keys, encryption filters, secrets and access management.
- **`scrim-server`**: a self-hosted Git remote that enforces per-user visibility. It decides which branches, commits and file contents each user receives, and which pushes it accepts.

There is no web UI. Everything happens in the terminal.

Scrim implements no cryptographic primitives of its own. It uses audited crates only: `age`, and RustCrypto's `aes-siv` and `chacha20poly1305`. The [security model](docs/ROADMAP.md#security-model) states what each feature protects and what it does not.

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
