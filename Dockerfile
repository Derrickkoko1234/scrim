# syntax=docker/dockerfile:1

ARG RUST_IMAGE=rust:1-trixie
FROM ${RUST_IMAGE} AS builder

WORKDIR /usr/src/scrim

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# Pure Rust + ring/rustls requires no libssl-dev or external C libraries beyond
# the standard C toolchain already present in rust:1-trixie.
RUN cargo build --release --locked --bin scrim-server \
    && strip /usr/src/scrim/target/release/scrim-server

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        postgresql-client \
        tini \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 scrim \
    && useradd --system --uid 10001 --gid scrim --home-dir /var/lib/scrim --shell /usr/sbin/nologin scrim \
    && install -d -o scrim -g scrim -m 0750 /var/lib/scrim \
    && install -d -o scrim -g scrim -m 0750 /var/lib/scrim/repos \
    && install -d -o scrim -g scrim -m 0700 /var/lib/scrim/ssh \
    && install -d -o scrim -g scrim -m 0700 /var/lib/scrim/run

COPY --from=builder /usr/src/scrim/target/release/scrim-server /usr/local/bin/scrim-server

LABEL org.opencontainers.image.source="https://github.com/Derrickkoko1234/scrim" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.description="Self-hosted Git remote enforcing per-user visibility for Scrim for Git"

ENV SCRIM_REPO_ROOT=/var/lib/scrim/repos \
    SCRIM_LISTEN=0.0.0.0:8080 \
    XDG_RUNTIME_DIR=/var/lib/scrim/run \
    RUST_LOG=info

USER scrim
WORKDIR /var/lib/scrim

EXPOSE 8080 2222
VOLUME ["/var/lib/scrim"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/scrim-server"]
