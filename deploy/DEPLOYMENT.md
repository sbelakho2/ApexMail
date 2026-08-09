# ApexMail Deployment — Canonical Path

This document defines the **single supported deployment model** for ApexMail.
There is exactly one path; alternatives live under `deploy/legacy-systemd/` and
`deploy/legacy-k8s/` and are explicitly **superseded**.

## TL;DR

```
push to main
  → .github/workflows/deploy.yml      builds + pushes images to GHCR (:latest + :<sha>)
  → .github/workflows/deploy-hetzner.yml   SSHes to the host, pulls :latest, `docker compose up -d`
```

Local production-parity run:

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml --env-file .env up -d
```

## Canonical service → image map

These are the **only** image names that may appear in a compose file or CI
build step. The namespace (`ghcr.io/<owner>/<repo>`) is derived from
`github.repository` in CI — it is never hardcoded.

| Compose service key   | Canonical image                              | Built by `deploy.yml` target | Dockerfile binary |
| --------------------- | -------------------------------------------- | ---------------------------- | ----------------- |
| `api-server`          | `ghcr.io/<ns>/api-server`                    | `api-server`                 | `api-server`      |
| `mta`                 | `ghcr.io/<ns>/mta`                           | `mta`                        | `mta-server`      |
| `imap-server`         | `ghcr.io/<ns>/imap-server`                   | `imap-server`                | `imap-server`     |
| `mailstore`           | `ghcr.io/<ns>/mailstore`                     | `mailstore`                  | `mailstore`       |
| `worker`              | `ghcr.io/<ns>/worker`                        | `worker`                     | `worker`          |
| `enterprise`          | `ghcr.io/<ns>/enterprise`                    | `enterprise`                 | `enterprise`      |
| `tracking-service`    | `ghcr.io/<ns>/tracking-service`              | (deploy/Dockerfile.tracking) | `tracking-service`|
| `observability`       | `ghcr.io/<ns>/observability`                 | `observability`              | `observability`   |
| `marketing`           | `ghcr.io/<ns>/marketing`                     | (apps/marketing-zola)        | nginx static      |

Notes:

- The MTA image is named **`mta`** (matching the CI build target and the
  compose service key). The binary inside that image is still `mta-server`;
  only the image *name* is unified. There is no `mta-server` image tag.
- `imap-server` and `mailstore` are first-class members of the canonical set:
  they appear in `docker-compose.prod.yml` (ports 993 and gRPC 50051), are
  built by `deploy.yml` from the `imap-server` / `mailstore` Dockerfile
  targets, and are pulled + started by `deploy-hetzner.yml` alongside the
  other services. Do not remove them from any of the three places.
- `ops-service` is intentionally **not** built or deployed — it had no compose
  consumer and existed only as drift.
- The dev `docker-compose.yml` builds the `mta` service from the `smtp-edge`
  target (a lighter edge listener for local/dev use). Production uses the full
  `mta` target image from GHCR. This dev/prod divergence is intentional and
  documented; it is not a naming conflict.

## Legacy / not-deployed crates

These crates exist in the workspace but are **not** part of the production
stack. Do not add them to compose, do not deploy them:

- **`auth-server`** (`services/mail-server/crates/auth-server`) — legacy
  duplicate of the auth flows now served by `api-server` (`/v1/auth/*`,
  `/api/auth/*`). Not referenced in any compose file, not built by
  `deploy.yml`, not running on production. Do not use.
- **`submission`** (`services/mail-server/crates/submission`, binary
  `submission-server`) — dev/duplicate SMTP-submission implementation.
  Production SMTP submission (ports 25/465/587) is served exclusively by
  `mta`. Not referenced in any compose file, not built by `deploy.yml`.
- **`smtp-edge`** — dev-only. The dev `docker-compose.yml` `mta` service
  builds the `smtp-edge` Dockerfile stage for local use; production uses the
  full `mta` image. Never referenced in `docker-compose.prod.yml`.

## TLS certificate management (production)

- All TLS consumers (nginx, mta, imap-server) read from the **single
  certbot-managed tree** `${TLS_CERT_DIR:-./deploy/nginx/ssl}` (host:
  `/opt/apexmail/deploy/nginx/ssl`). The `certbot` service renews it every
  12 h (`deploy/scripts/certbot-renew-loop.sh`); the deploy hook installs
  `fullchain.pem`/`privkey.pem`/`ca-chain.pem` at the tree root chowned to
  uid 101 (nginx) and reopens `live/` + `archive/` to 0755 with 0644 pem
  files so the mta/imap containers (non-root uid 10001) can read them.
- `nginx`, `mta` and `imap-server` load certs at startup; after a renewal
  they pick up the new cert on the next container restart / nginx reload
  (deploys do this automatically).
- The host `/etc/letsencrypt` tree is **legacy** — it is no longer mounted
  by any compose service and nothing renews it. Do not use it for new
  TLS wiring.
- **`status.apexmail.ee`** — the nginx vhost exists (proxies to
  `api-server:3000`) but the hostname has **no DNS A record**, so it is not
  included in the Let's Encrypt certificate and is unreachable. Once an A
  record (`status.apexmail.ee → <server IP>`) is added at the registrar,
  issue the cert with:
  `certbot certonly --webroot -w /var/www/certbot -d <all 12 current domains> -d status.apexmail.ee --expand`
  and reload nginx.

## Tag strategy

- CI (`deploy.yml`) publishes **`:<short-sha>`** and **`:latest`** for every
  image on each push to `main`.
- `docker-compose.prod.yml` pins every service to **`:latest`** so
  `docker compose pull` always resolves to a CI-built image.
- Immutable per-commit tracking is preserved via the `:<short-sha>` tags.
- **Never** pin to a `vX.Y.Z` tag unless CI is also taught to produce that tag.
  (Earlier `v1.0.0`/`v1.0.1` pins referred to tags CI never published, which
  broke `docker compose pull`.)

## Required GitHub secrets (no hardcoded defaults)

The deploy workflows fail fast if any of these are absent:

| Secret                    | Purpose                                                        |
| ------------------------- | -------------------------------------------------------------- |
| `HETZNER_SSH_HOST`        | Production host IP/hostname (**required**, no default)         |
| `HETZNER_SSH_USER`        | SSH user (**required**, no default)                            |
| `HETZNER_SSH_PRIVATE_KEY` | Private key matching the host's `authorized_keys`              |
| `HETZNER_KNOWN_HOSTS`     | Output of `ssh-keyscan -H <HETZNER_SSH_HOST>`                  |
| `APEXMAIL_PROD_ENV`       | Full `.env` contents (see `deploy/scripts/HETZNER_DEPLOY.md`)  |
| `GHCR_DEPLOY_TOKEN`       | PAT with `read:packages` for the host's `docker login ghcr.io` |

## Drift guard

The CI job `deploy-image-name-guard` (in `deploy.yml`) asserts that every
`image:` reference in `docker-compose*.yml` matches the canonical service map
above — including `imap-server` and `mailstore`. If you add a service or
rename an image, update this map **and** the guard together — the build will
fail otherwise.

## Manual fallback (NOT the production path)

The `Makefile` targets and `deploy/scripts/deploy.sh` are a manual/emergency
fallback only. They build images **locally on the host** and tag them with
GHCR-style names — those images are never pushed to GHCR, and the produced
stack can drift from CI. Production is deployed exclusively by the two
workflows above.
