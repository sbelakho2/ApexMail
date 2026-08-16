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
| `status-server`       | `ghcr.io/<ns>/status-server`                 | `auth-server`                | `auth-server`     |
| `billing-service`     | `ghcr.io/<ns>/billing-service`               | `billing-service`            | `billing-service` |

Notes:

- The MTA image is named **`mta`** (matching the CI build target and the
  compose service key). The binary inside that image is still `mta-server`;
  only the image *name* is unified. There is no `mta-server` image tag.
- `imap-server` and `mailstore` are first-class members of the canonical set:
  they appear in `docker-compose.prod.yml` (ports 993 and gRPC 50051), are
  built by `deploy.yml` from the `imap-server` / `mailstore` Dockerfile
  targets, and are pulled + started by `deploy-hetzner.yml` alongside the
  other services. Do not remove them from any of the three places.
- `status-server` (the public status page + status API behind
  `status.apexmail.ee` and `apexmail.ee/api/status-data`) is built from the
  Dockerfile's **`auth-server`** stage — the image is published as
  `status-server`, matching its compose service key and the nginx upstream
  name. The stage is not renamed to avoid touching the `auth-server` crate
  references; only the image name is canonical.
- `billing-service` binds `0.0.0.0:4100` (no host port mapping — it is
  service-auth protected and only reachable on the internal Docker networks).
  Its production Stripe credentials come from the Docker secrets
  `stripe_secret_key` / `stripe_webhook_secret` (`PROD_STRIPE_SECRET_KEY_FILE`
  / `PROD_STRIPE_WEBHOOK_SECRET_FILE` in the deployment `.env`); the webhook
  secret is mandatory — the binary fail-fasts at startup without it.
- The dev `docker-compose.yml` builds the `mta` service from the **`mta`**
  target (same stage as production). There is no separate dev edge listener;
  the legacy `smtp-edge` crate/stage was removed.

## Legacy / removed crates

The following crates were **removed** from the workspace — they were legacy
duplicates that production never used and have no residual references:

- **`submission`** (binary `submission-server`) — duplicate SMTP-submission
  implementation. Production SMTP submission (ports 25/465/587) is served
  exclusively by `mta`.
- **`smtp-edge`** — dev-only edge listener superseded by `mta`; its Dockerfile
  stage and dev-compose target were removed.
- **`ops-service`** — had no compose consumer and existed only as drift; its
  test-only consumers (fuzz/load/perf/smoke/integration tests) were removed
  with it.
- **`bounce-analytics`** — unreferenced; its functionality lives in
  `worker-processors`/`mta`.

> `auth-server` (`services/mail-server/crates/auth-server`) is **deployed**
> — as the `status-server` service/image (see the canonical map above). It is
> not a standalone image name; the crate's binary serves the status page/API.

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
- **`status.apexmail.ee`** — first-class service (`status-server` in
  `docker-compose.prod.yml`, proxied by nginx). Its A record resolves to the
  production host and the Let's Encrypt certificate covers it — the cert
  currently contains all 13 domains (apexmail.ee, www, api, app, admin,
  control, enterprise, track, mail, smtp, imap, autoconfig, status).
  After a renewal, the certbot deploy-hook copies `live/apexmail.ee/*` to the
  tree root (`fullchain.pem`/`privkey.pem`/`ca-chain.pem`); if you ever issue
  an expanded cert manually, run `deploy/scripts/issue-letsencrypt.sh` again
  (it re-copies and reloads nginx) or re-run the deploy-hook.

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
above — including `imap-server`, `mailstore` and `status-server`. If you add
a service or rename an image, update this map **and** the guard together —
the build will fail otherwise.

## Manual fallback (NOT the production path)

The `Makefile` targets and `deploy/scripts/deploy.sh` are a manual/emergency
fallback only. They build images **locally on the host** and tag them with
GHCR-style names — those images are never pushed to GHCR, and the produced
stack can drift from CI. Production is deployed exclusively by the two
workflows above.
