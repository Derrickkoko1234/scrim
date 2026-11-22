# Deploying Scrim on Dokploy

This directory contains a production Docker Compose stack for running `scrim-server` with PostgreSQL 17 and Redis 7 under Dokploy.

## Stack layout

- **`postgres`** (`postgres:17-alpine`): Stores members, tokens, groups, branch/path rules, SSH keys, and the audit log in `postgres_data`.
- **`redis`** (`redis:7-alpine`): Ephemeral in-memory policy cache (`128mb`, `allkeys-lru`, persistence disabled).
- **`scrim-server`**: Runs as non-root user `scrim` (`10001:10001`) with a read-only root filesystem, `scrim_data` mounted at `/var/lib/scrim`, smart HTTP on `8080`, and Git-over-SSH on `2222`.

> **Hook execution note:** `scrim-server` creates a `0700` hook directory containing symlinks for `pre-receive` and `pack-objects` plus its Unix callback socket. Setting `XDG_RUNTIME_DIR=/var/lib/scrim/run` places this directory on `scrim_data` (which allows execution and is not swept by temp cleaners), and `/tmp` is mounted with `exec` as a fallback.

## Environment variables

Set these in Dokploy's **Environment** tab before deploying:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `POSTGRES_PASSWORD` | Yes | — | Password for PostgreSQL and `DATABASE_URL` |
| `POSTGRES_USER` | No | `scrim` | PostgreSQL user |
| `POSTGRES_DB` | No | `scrim` | PostgreSQL database name |
| `SCRIM_IMAGE` | No | `ghcr.io/derrickkoko1234/scrim:main` | Container image tag to deploy |
| `SCRIM_SSH_PORT` | No | `2222` | Host port mapped to container SSH port `2222` |
| `RUST_LOG` | No | `info` | Tracing filter (`info`, `debug`, `scrim_server=debug`) |

For Cloudflare R2 backups (`scrim-server backup` / `scrim-server restore`), uncomment the `SCRIM_R2_*` entries in [`docker-compose.yml`](docker-compose.yml) (or pass them via `--env-file`) and set:

- `SCRIM_R2_ENDPOINT`
- `SCRIM_R2_BUCKET`
- `SCRIM_R2_ACCESS_KEY_ID`
- `SCRIM_R2_SECRET_ACCESS_KEY`
- `SCRIM_R2_PREFIX`

## Dokploy configuration

1. **Create a Compose service** pointing at `deploy/dokploy/docker-compose.yml` from this repository.
2. **TLS for HTTP (`8080`)**:
   - In Dokploy's **Domains** tab for the Compose stack, add your domain (e.g., `git.example.com`) targeting service `scrim-server` on container port `8080`.
   - Enable HTTPS (Let's Encrypt) so Traefik terminates TLS in front of `scrim-server`.
   - Health checks hit unauthenticated `GET /healthz`, which returns `200 OK` (`{"status":"ok"}`).
3. **TCP port forwarding for SSH (`2222`)**:
   - `docker-compose.yml` publishes `${SCRIM_SSH_PORT:-2222}:2222` directly on the host.
   - Allow TCP port `2222` (or your chosen `SCRIM_SSH_PORT`) in your server firewall / security group.
   - On first startup, `scrim-server` auto-generates an Ed25519 host key at `/var/lib/scrim/ssh/host_ed25519_key` (`0600`) inside the persistent `scrim_data` volume.

## First-run bootstrap

After the stack is healthy, create the initial admin member and capture the one-time API token:

```sh
docker compose exec scrim-server scrim-server bootstrap-admin --name admin
```

Store the printed token securely and use it with `scrim login` against `https://git.example.com`.

## Backups and restore (Cloudflare R2)

`scrim-server` ships built-in R2 backup and restore subcommands that archive bare repositories (`SCRIM_REPO_ROOT`) and PostgreSQL (`DATABASE_URL`, using `pg_dump` / `psql` bundled in the image).

### Scheduled backup

Run via Dokploy **Schedules** (or host cron) against the running `scrim-server` container:

```sh
docker compose exec -T scrim-server scrim-server backup
```

### Restore

Stop writes if possible, then restore from R2 into `SCRIM_REPO_ROOT` and `DATABASE_URL`:

```sh
docker compose exec -T scrim-server scrim-server restore
```

## Upgrading safely

1. Pin `SCRIM_IMAGE` to a release tag (e.g., `ghcr.io/derrickkoko1234/scrim:0.5.0`) rather than `:main` in production.
2. Run a backup before upgrading:
   ```sh
   docker compose exec -T scrim-server scrim-server backup
   ```
3. Update `SCRIM_IMAGE` in Dokploy and redeploy (`docker compose pull && docker compose up -d`).
4. Pending PostgreSQL migrations are applied automatically on startup; the SSH host key and repositories persist in `scrim_data`.
