# Contributing to Scrim

Thanks for your interest in Scrim. This guide covers how to propose changes and what every contribution needs.

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Security vulnerabilities go through [SECURITY.md](SECURITY.md), never a public issue or pull request.
- The [roadmap](docs/ROADMAP.md) describes the milestones, architecture and security model.

## Developer Certificate of Origin

Scrim uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) instead of a CLA. By signing off a commit, you certify that you wrote the change or otherwise have the right to submit it under the project's licenses.

Every commit must carry a `Signed-off-by` line matching the commit author:

```
Signed-off-by: Your Name <you@example.com>
```

Add it automatically with `git commit -s`. To sign off commits you already made, run `git rebase --signoff main`. A CI check rejects pull requests with unsigned commits.

## Licensing of contributions

Contributions are licensed under the license of the crate they change:

- `scrim-cli`, `scrim-crypto` and `scrim-policy`: MIT OR Apache-2.0
- `scrim-server`: AGPL-3.0

## Pull requests

- Keep each pull request focused on one change.
- Add or update tests for behaviour you change. Security fixes add a regression test first.
- Make sure these pass locally before you push:

  ```sh
  cargo fmt --all --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all
  cargo deny check
  ```

- New dependencies must have licenses that `cargo deny` accepts. Do not add a dependency for a few lines of code.
- Scrim implements no cryptographic primitives of its own. Cryptography uses the audited crates listed in the roadmap.
