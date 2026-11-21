# Security policy

Scrim protects source code and secrets, so security reports get priority over all other work.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/Derrickkoko1234/scrim/security/advisories/new)**

Do not open a public issue, pull request or discussion about a vulnerability before it is fixed.

Please include:

- What an attacker can see or do that they should not, such as reading a private branch, file or secret.
- Steps to reproduce, ideally with the `git` and `scrim` commands used.
- The Scrim version or commit, your Git version and your OS.

## What to expect

- An acknowledgement within 3 business days.
- An assessment and a planned fix timeline within 10 business days.
- Credit in the advisory and release notes, unless you prefer to stay anonymous.

Every confirmed vulnerability gets a regression test before it is fixed.

## Scope

In scope: the `scrim` CLI, `scrim-server`, and the `scrim-crypto` and `scrim-policy` crates, including any way to defeat the guarantees in the [security model](docs/ROADMAP.md#security-model).

Not vulnerabilities: limitations the security model already documents, such as visible path names of encrypted files, identical ciphertext for identical content, and data a revoked member decrypted before revocation.

## Supported versions

Scrim has no releases yet. Until 1.0, only the latest commit on `main` receives fixes.
