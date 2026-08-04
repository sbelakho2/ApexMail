# Legacy Bare-Metal (systemd) Deployment — SUPERSEDED

> **⚠️ This deployment model is NOT canonical. It is preserved for historical
> reference only.**

## Canonical path

ApexMail is deployed via **Docker Compose + GHCR images over SSH (Hetzner)**.
See [`../DEPLOYMENT.md`](../DEPLOYMENT.md) for the single supported deploy flow,
and [`.github/workflows/deploy.yml`](../../.github/workflows/deploy.yml) +
[`.github/workflows/deploy-hetzner.yml`](../../.github/workflows/deploy-hetzner.yml)
for the CI that implements it.

## Why this was archived

The bare-metal `deploy.sh` script (which ran Rust binaries under systemd and
static file-served the marketing site) directly **contradicted** the
Docker-Compose/GHCR model:

- `deploy.sh` explicitly forbade Docker Compose and GitHub Actions.
- It aborted if the `apexmail-nginx` Docker container was running.
- It deployed an `auth-server` binary that has no Dockerfile target and no CI
  build step — so it could only run from a hand-built release on the host.
- It required `gh` CLI and host systemd units that drift from the container
  stack the rest of the platform uses.

Running two mutually-exclusive deploy models from the same repository caused
the "clashing paths" failures reported in production. Unifying on the
compose/GHCR model removes the ambiguity.

## Contents

- `deploy.sh` — the old bare-metal deploy entrypoint (read-only reference).
- `auth-server.service` — the systemd unit for the now-removed `auth-server`
  binary (the auth workload is handled by `api-server` in the canonical stack).
- `apexmail.conf` — legacy bare-metal nginx config (pushed by the old
  `push-nginx`/`push-configs` Makefile targets). Reads certs from
  `/etc/letsencrypt/live/apexmail.ee/` and serves static files from
  `/var/www/...`, which conflicts with the canonical container nginx at
  `deploy/nginx/nginx.conf` (mounted by `docker-compose.prod.yml`, reads certs
  from `/etc/nginx/ssl/`). Kept for reference only.
- `status.apexmail.ee.conf` — orphan server block that duplicated the
  `status.apexmail.ee` vhost already defined in the canonical
  `deploy/nginx/nginx.conf`. Kept for reference only.

## If you ever need to revive this

Do not edit this script in place. Instead, open a new ADR under `docs/adr/`
documenting why a bare-metal path is needed and reconcile it against the
canonical compose stack so the two cannot diverge again.
