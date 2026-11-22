# Scrim fuzz targets

[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) harnesses for the
parsers that read untrusted input. This crate is excluded from the main
workspace because libFuzzer instrumentation needs a nightly toolchain; the
stable `cargo test --workspace` run still calls every entry point through
unit tests in `scrim-cli` and `scrim-server`.

## Setup

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Exercises |
| --- | --- |
| `policy_globs` | ref/path glob and group validation, `BranchPolicy`/`PathPolicy`/`WithholdPolicy` compilation and lookups |
| `crypto_envelopes` | encrypted file blobs, placeholders, group-key, scope-key and encrypted-secrets TOML files |
| `filter_protocol` | `scrim filter-process` pkt-line framing, handshake and clean/smudge dispatch (in memory) |
| `server_parsers` | `upload-pack` request filter, SSH `exec` commands, `pack-objects` hook args/stdin, `pre-receive` ref updates, `diff-tree` output, secret scanner |

## Running

From the repository root:

```sh
cargo +nightly fuzz list
cargo +nightly fuzz run policy_globs
cargo +nightly fuzz run server_parsers -- -max_total_time=300
```

Crashes are written to `fuzz/artifacts/<target>/`; reproduce one with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.
