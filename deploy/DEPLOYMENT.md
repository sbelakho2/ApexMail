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
| `worker`              | `ghcr.io/<ns>/worker`                        | `worker`                     | `worker`          |
| `enterprise`          | `ghcr.io/<ns>/enterprise`                    | `enterprise`                 | `enterprise`      |
| `tracking-service`    | `ghcr.io/<ns>/tracking-service`              | (deploy/Dockerfile.tracking) | `tracking-service`|
| `observability`       | `ghcr.io/<ns>/observability`                 | `observability`              | `observability`   |
| `marketing`           | `ghcr.io/<ns>/marketing`                     | (apps/marketing-zola)        | nginx static      |

Notes:

- The MTA image is named **`mta`** (matching the CI build target and the
  compose service key). The binary inside that image is still `mta-server`;
  only the image *name* is unified. There is no `mta-server` image tag.
- `ops-service` is intentionally **not** built or deployed — it had no compose
  consumer and existed only as drift.
- The dev `docker-compose.yml` builds the `mta` service from the `smtp-edge`
  target (a lighter edge listener for local/dev use). Production uses the full
  `mta` target image from GHCR. This dev/prod divergence is intentional and
  documented; it is not a naming conflict.

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
above. If you add a service or rename an image, update this map **and** the
guard together — the build will fail otherwise.
