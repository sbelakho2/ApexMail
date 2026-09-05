# ApexMail Architecture — Single Source of Truth

> **This document is the authoritative reference for the ApexMail production
> architecture.** All other docs (README, DEPLOYMENT.md and its
> redirect deploy/scripts/HETZNER_DEPLOY.md)
> defer to this file. If something here contradicts another doc, this doc wins.

## Quick Reference

| What | Value |
|---|---|
| **Production host** | The Hetzner host (Finland) — address in deploy config (`DEPLOY_HOST` / the host's own clone at `/opt/apexmail`); not hardcoded anywhere in this doc or the pipeline |
| **Domain** | `apexmail.ee` + 12 subdomains (13 certified hostnames — see §3) |
| **Deployment method** | Self-hosted CI pipeline (`ci/pipeline.sh`) running ON the deploy host — builds, scans and deploys locally; no registry, no runner |
| **Deployment trigger** | Push to `main` → the host's 5-minute pipeline timer fetches and runs `ci/pipeline.sh` (images → migrate → deploy → verify) |
| **Manual fallback** | `make deploy` / `make deploy-service` → `deploy/scripts/deploy.sh` (emergency/hotfix only) |
| **Canonical compose file** | `docker-compose.prod.yml` (overlay on `docker-compose.yml`) |
| **Canonical nginx config** | `deploy/nginx/nginx.conf` (bind-mounted into the nginx container) |
| **TLS cert** | Let's Encrypt, 13 SANs, auto-renewed via the certbot container (nginx reloads in place; mta/imap-server restart via the host-side renewal watcher) |

---

## 1. Services (all in Docker)

Every service runs as a Docker container on a single host. No bare-metal
processes, no systemd services, no Kubernetes.

| Container | Image | Ports | Purpose |
|---|---|---|---|
| `apexmail-nginx-1` | `nginx:1.27-alpine` | 80, 443 | Reverse proxy, TLS termination, autoconfig |
| `apexmail-api-server-1` | `…/api-server:latest` | 3000 (internal; dev binds 8080) | REST API + SSR web UI (Axum) |
| `apexmail-marketing-1` | `…/marketing:latest` | 8080 (internal) | Marketing site (Zola static) |
| `apexmail-mta-1` | `…/mta:latest` | 25, 587, 465, 2525, 2526 | SMTP inbound + submission (STARTTLS/implicit TLS), VERP bounce + ISP FBL receivers |
| `apexmail-imap-server-1` | `…/imap-server:latest` | 993 | IMAPS mail access |
| `apexmail-mailstore-1` | `…/mailstore:latest` | 50051 (internal) | gRPC mail storage backend |
| `apexmail-worker-1` | `…/worker:latest` | 9093 (metrics, internal) | Background job processor |
| `apexmail-enterprise-1` | `…/enterprise:latest` | 3008 (internal; dev binds 3002) | Enterprise features |
| `apexmail-tracking-1` | `…/tracking-service:latest` | 3001 (internal; dev publishes 127.0.0.1:3001) | Email open/click tracking |
| `apexmail-status-server-1` | `…/status-server:latest` | 3000 (internal) | Status page + status API |
| `apexmail-sales-autopilot-1` | `…/sales-autopilot:latest` | 3010 (internal) | Internal sales engine (CRM, campaigns, inbox); public only via `api.apexmail.ee/sales-api/u/` |
| `apexmail-billing-service-1` | `…/billing-service:latest` | 4100 (internal) | Plans, metering, invoices, Stripe webhooks |
| `apexmail-compliance-1` | `…/compliance:latest` | 3011 (internal) | Audit log, DSR/GDPR automation, secrets rotation |
| `apexmail-ai-service-1` | `…/ai-service:latest` | 3012 (internal) | Grounded AI assistant (docs corpus from `docs/`) |
| `apexmail-pdf-renderer-1` | `…/pdf-renderer:latest` | 3004 (internal) | Typst-based invoice/report PDF rendering (prod-activated via `profiles: !override []`) |
| `apexmail-analytics-worker-1` | `…/analytics-worker:latest` | — | Events compaction → cold storage, retention, reconciliation (cron; keeps Postgres `events` bounded) |
| `apexmail-migrator-1` (one-shot) | `…/migrator:latest` | — | sqlx migration chain; runs via `--profile migrate` before every `up`, never long-running |
| `apexmail-observability` | `…/observability:latest` | 4400 (internal, monitoring profile) | Metrics/alerts/SLO aggregation + Redis eviction monitoring |
| `apexmail-postgres-backup-1` | `…/postgres-backup:latest` (built from `deploy/hardening/Dockerfile.postgres-backup`) | — | Nightly encrypted pg_dump backups + offsite rsync |
| `apexmail-clickhouse-backup-1` | `…/clickhouse-backup:latest` (built from `deploy/hardening/Dockerfile.clickhouse-backup`) | — | Nightly encrypted ClickHouse table dumps + offsite rsync |
| `apexmail-redis-backup-1` | `…/redis-backup:latest` (built from `deploy/hardening/Dockerfile.redis-backup`) | — | Nightly encrypted Redis snapshots (`redis-cli --rdb`) + offsite rsync |
| `apexmail-analytics-backup-1` | `…/analytics-backup:latest` (built from `deploy/hardening/Dockerfile.analytics-backup`) | — | Nightly encrypted tar of the analytics cold-storage volume |
| `apexmail-postgres` | `postgres:16.8-alpine` | 5432 (internal in prod; dev publishes 127.0.0.1:5432) | Primary database |
| `apexmail-redis` | `redis:7.4-alpine` | 6379 (internal in prod; dev publishes 127.0.0.1:6379) | Cache, queues, KiwiCaptcha challenges |
| `apexmail-clickhouse` | `clickhouse/clickhouse-server:24.8-alpine` | 8123, 9000 (internal in prod; dev publishes loopback) | Analytics |
| `apexmail-certbot-1` | `certbot/certbot:v2.11.0` | — | TLS cert renewal (every 12h) |

Monitoring profile (`--profile monitoring`, activated by the pipeline and
`deploy.sh`): prometheus (9090), grafana (3000, dev host port 3003), loki
(3100), tempo (3200), alertmanager (9093), otel-collector (4317/4318), the
node/blackbox/postgres/redis/clickhouse exporters, and the two locally-built
sidecars `apexmail/clickhouse-exporter` and `apexmail/synthetic-monitor`
(date-pinned tags — NOT built by the pipeline).

---

## 2. Network Topology

```
Internet
   │
   ├── :80 ──────────────────┐
   ├── :443 ─────────────────┤
   │                  ┌───────┴────────┐
   │                  │  Docker Nginx  │  TLS termination (Let's Encrypt cert)
   │                  │  (nginx.conf)  │  ACME challenge catch-all
   │                  └───────┬────────┘
   │                          │ (Docker network: apexmail_frontend)
   │          ┌───────────────┼───────────────┐
   │          │               │               │
   │    ┌─────┴─────┐  ┌──────┴──────┐  ┌─────┴──────┐
   │    │ Marketing │  │ API Server  │  │  Status    │
   │    │ :8080     │  │ :3000       │  │  :3000     │
   │    └───────────┘  └──────┬──────┘  └────────────┘
   │                          │ (Docker network: apexmail_data)
   │                    ┌─────┴──────┐
   │                    │ Postgres   │
   │                    │ Redis      │
   │                    │ ClickHouse │
   │                    └────────────┘
   │
    ├── :25 ────────────┐
    ├── :587 ───────────┤  (Docker proxy → direct to containers)
    ├── :465 ───────────┤
    ├── :993 ───────────┘
    │            ┌──────────────┐     ┌──────────────┐
    │            │ MTA (mta)    │     │ IMAP Server  │
    │            │ :25 :587:465 │     │ :993         │
    │            └──────┬───────┘     └──────┬───────┘
   │                   │                    │
   │                   └──────┬─────────────┘
   │                          │ (gRPC)
   │                   ┌──────┴───────┐
   │                   │  Mailstore   │
   │                   │  :50051      │
   │                   └──────────────┘
   │
   └── :22 ── SSH (management only)
```

**Key principle:** HTTP/HTTPS traffic flows through the Docker nginx. Mail
traffic (SMTP/IMAP) goes directly to the mail containers via Docker port
mapping. Nginx does NOT proxy mail protocols.

---

## 3. TLS Certificates

### Domains covered (13 SANs)
```
apexmail.ee, www.apexmail.ee, api.apexmail.ee, app.apexmail.ee,
admin.apexmail.ee, control.apexmail.ee, enterprise.apexmail.ee,
track.apexmail.ee, mail.apexmail.ee, smtp.apexmail.ee,
imap.apexmail.ee, autoconfig.apexmail.ee, status.apexmail.ee
```

### Cert paths on the host
The certbot container manages the whole tree under
`/opt/apexmail/deploy/nginx/ssl/` (its `/etc/letsencrypt`). All TLS consumers
read from that single tree:

| Host path | Mounted in | Used for |
|---|---|---|
| `/opt/apexmail/deploy/nginx/ssl/` | `apexmail-certbot-1:/etc/letsencrypt/` | certbot renew + deploy hook |
| `/opt/apexmail/deploy/nginx/ssl/` | `apexmail-nginx-1:/etc/nginx/ssl/` | Docker nginx (root `fullchain.pem`/`privkey.pem`) |
| `/opt/apexmail/deploy/nginx/ssl/` | `apexmail-mta-1` + `apexmail-imap-server-1` → `/opt/apexmail/certs/` | Mail services (read `live/<domain>/…`) |

### Renewal flow
1. `apexmail-certbot-1` runs `certbot renew` every 12h
   (`deploy/scripts/certbot-renew-loop.sh`)
2. On success, the loop's deploy hook (`/usr/local/bin/apexmail-deploy-hook.sh`,
   generated by the loop script) copies `live/apexmail.ee/{fullchain,privkey,chain}`
   to the tree root (`fullchain.pem`/`privkey.pem`/`ca-chain.pem`) chowned to
   uid 101 (nginx) and reopens `live/` + `archive/` (0755 dirs, 0644 pems) so
   the non-root mta/imap containers can read them
3. nginx picks up the new cert via its 60s reload-sentinel watcher loop;
   mta/imap load certs at startup and are restarted automatically by the
   host-side systemd watcher (`deploy/hardening/apexmail-tls-renew-restart.path`
   → `tls-renew-restart.sh`, installed by `deploy.sh`) — once per renewal,
   guarded by the flag file's mtime. Deploys also recreate the containers.
4. The certbot container maps `/opt/apexmail/deploy/nginx/ssl` as its
   `/etc/letsencrypt`

### Initial issuance
Run `deploy/scripts/issue-letsencrypt.sh` on the host. Uses webroot validation
via the nginx ACME challenge catch-all (`.well-known/acme-challenge/`).

---

## 4. Nginx Architecture

**Single canonical config:** `deploy/nginx/nginx.conf`

This file is bind-mounted into the nginx container at `/etc/nginx/nginx.conf`.

### HTTP (port 80) — ONE catch-all server
```
listen 80 default_server;
server_name _;
```
Serves:
- `/.well-known/acme-challenge/` → certbot webroot (for ALL domains)
- `/.well-known/autoconfig/` → Thunderbird autoconfig XML
- `/mail/config-v1.1.xml` → Thunderbird direct autoconfig URL
- Everything else → 301 redirect to HTTPS

### HTTPS (port 443) — per-domain servers
- `apexmail.ee`, `www.apexmail.ee` → `marketing:8080` (+ trailing-slash 301
  canonicalisation for extensionless page paths; `/api/status-data` proxies
  to the status backend)
- `app.apexmail.ee`, `api.apexmail.ee` → `api-server:3000` (api also routes
  `/sales-api/u/` → `sales-autopilot:3010`, the only public sales surface)
- `admin.apexmail.ee`, `control.apexmail.ee` → `api-server:3000`
- `track.apexmail.ee` → `tracking:3001`
- `enterprise.apexmail.ee` → `enterprise:3008`
- `status.apexmail.ee` → `status-server:3000` (exact-match `/status*`,
  `/v1/health` and `/api/status-data` locations only — everything else 404s)
- `autoconfig.apexmail.ee` → static XML served by nginx
- Anything else: a `default_server` catch-all answers **421 Misdirected
  Request** (unknown Host/SNI never falls through to the marketing vhost)

All HTTPS vhosts send security headers (HSTS, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy) and apply the declared
`limit_req` zones (`global`, `login`, `signup`, `admin`) to the relevant
locations.

**No legacy `apexmail.conf` or site-fragment configs.** Those are archived in
`deploy/legacy-systemd/`.

---

## 5. DNS Records

All A records point at the production host's address (managed in the DNS
provider; the address is a deploy-time fact, deliberately not hardcoded in
this repository — see §9).

| Type | Host | Value |
|---|---|---|
| A | `apexmail.ee` (and `www`, `api`, `app`, `admin`, `control`, `mail`, `smtp`, `imap`, `autoconfig`, `track`, `enterprise`) | the Hetzner host address (in deploy config / DNS provider) |
| MX | `apexmail.ee` | `10 mail.apexmail.ee` |
| TXT | `apexmail.ee` | `v=spf1 mx a -all` |
| TXT | `_dmarc.apexmail.ee` | `v=DMARC1; p=quarantine; rua=mailto:admin@apexmail.ee` |

---

## 6. Mail Server Configuration

### SMTP (submission — for email clients sending mail)
- **Host:** `mail.apexmail.ee` (or `smtp.apexmail.ee` — both resolve, both covered by cert)
- **Port:** 587 with STARTTLS
- **Auth:** PLAIN / LOGIN (after STARTTLS)
- **Container:** `apexmail-mta-1` (binary: `mta-server`)
- **Cert:** `/opt/apexmail/certs/live/apexmail.ee/fullchain.pem` + `privkey.pem`
  (the certbot tree bind-mounted read-only; `TLS_CERT_PATH`/`TLS_KEY_PATH`)

### IMAP (for email clients reading mail)
- **Host:** `mail.apexmail.ee` (or `imap.apexmail.ee`)
- **Port:** 993 (implicit TLS / IMAPS) — the only supported mode; port 143
  is closed by policy (SSL-only autoconfig, no STARTTLS on plaintext)
- **Container:** `apexmail-imap-server-1` (binary: `imap-server`)
- **Cert:** same certbot tree mount; `INBOUND_CERT_PATH`/`INBOUND_KEY_PATH`
  point at `live/apexmail.ee/{fullchain,privkey}.pem`

### Autoconfig (Thunderbird / Apple Mail auto-discovery)
- **URL:** `http://autoconfig.apexmail.ee/mail/config-v1.1.xml`
- **Also:** `http://apexmail.ee/.well-known/autoconfig/mail/config-v1.1.xml`
- **Config:** IMAPS `mail.apexmail.ee:993` SSL, SMTP `mail.apexmail.ee:587` STARTTLS

### Thunderbird setup for sabelakho@apexmail.ee
- **Incoming:** IMAPS, `mail.apexmail.ee`, port **993**, SSL/TLS
- **Outgoing:** SMTP, `mail.apexmail.ee`, port **587**, STARTTLS
- **Username:** full email address

---

## 7. Deployment Flow

The canonical deployment is the **self-hosted pipeline** (`ci/pipeline.sh`)
running **on the deploy host** — there is no GitHub Actions runner, no
registry, and no SSH hop (the GHCR/GitHub-Actions flow is decommissioned and
archived under `.github/workflows-archive/`; see `ci/README.md`).

```
push to main
  │
  ▼
host pipeline timer (every 5 min) → ci/pipeline.sh run (on the host)
  ├── fetch        git fetch/checkout of the pushed ref
  ├── …            build/test/validate stages (cargo, contract checks)
  ├── 05 images    deploy.sh --build-only: builds ALL 21 images LOCALLY
  │                (15 mail-server Dockerfile targets: api-server, mta,
  │                 imap-server, mailstore, worker, enterprise,
  │                 observability, status-server, billing-service,
  │                 sales-autopilot, compliance, analytics-worker,
  │                 pdf-renderer, ai-service, migrator — plus 6 separate
  │                 Dockerfiles: marketing, tracking-service,
  │                 postgres-backup, clickhouse-backup, redis-backup,
  │                 analytics-backup), tags :<short-sha> + :latest,
  │                 Trivy-gates EVERY runtime image defined by the compose
  │                 files, writes the signed image-digests.txt manifest
  ├── 06 migrate   _sqlx_migrations backup + migrator one-shot (gate before up)
  ├── 07 deploy    docker compose up -d --profile monitoring
  │                (digest-manifest tamper guard; nginx reload)
  └── 08 verify    per-service health, HTTP probes, SMTP banner, TLS
                   (auto-rollback to the previous :<sha> pins on failure —
                   deploy/rollback-plan.md)
```

**For manual deploys / hotfixes** (`make deploy` → `deploy/scripts/deploy.sh`,
emergency only), see `deploy/DEPLOYMENT.md`. The pipeline and the manual
path share the same build implementation and the same migration gate.

---

## 8. File Map — What Lives Where

### Canonical (authoritative)
| Path | Purpose |
|---|---|
| `ci/pipeline.sh` (+ `ci/stages/`, `ci/lib.sh`, `ci/README.md`) | **The CI/CD pipeline** — runs on the deploy host via a 5-min systemd timer (`ci/install.sh` installs it) |
| `docker-compose.prod.yml` | Production service definitions |
| `docker-compose.yml` | Base (dev) service definitions |
| `deploy/nginx/nginx.conf` | **The only nginx config** (mounted into container) |
| `deploy/scripts/issue-letsencrypt.sh` | First-time cert issuance |
| `deploy/scripts/certbot-renew-loop.sh` | Auto-renewal loop (runs in certbot container; installs the renewal deploy hook) |
| `deploy/hardening/tls-renew-restart.sh` (+ the systemd `.path`/`.service` units) | Host-side watcher that restarts mta + imap-server once per cert renewal (installed by `deploy.sh`) |
| `deploy/hardening/scripts/*-backup-encrypt.sh` | Nightly encrypted backup schedulers (postgres, clickhouse, redis, analytics-cold) |
| `deploy/scripts/entrypoint-wrapper.sh` | Container secret env bridging + DATABASE_URL/REDIS_URL assembly |
| `deploy/scripts/hetzner-bootstrap.sh` | One-time host setup |
| `deploy/scripts/verify-deployment.sh` | Post-deploy cache-coherence verification (legal pages) |
| `deploy/DEPLOYMENT.md` | CI/CD pipeline reference |
| `deploy/scripts/HETZNER_DEPLOY.md` | Redirect → `deploy/DEPLOYMENT.md` (merged) |
| `deploy/rollback-plan.md` | Rollback procedure (SHA-based) |
| `ARCHITECTURE.md` | **This file** — the single source of truth |

### Legacy (archived, not used)
| Path | What |
|---|---|
| `deploy/legacy-systemd/` | Old bare-metal deploy.sh + systemd units + old nginx configs |
| `deploy/legacy-k8s/` | Old Kubernetes manifests, Helm chart, Kustomize overlays |
| `deploy/legacy-evaluation/` | Aspirational staging + canary specs (never implemented) |
| `.github/workflows-archive/` | The decommissioned GitHub-Actions/GHCR deployment (replaced by `ci/pipeline.sh`) |

### Do NOT use
| Path | Why |
|---|---|
| `Makefile` | Manual/emergency fallback only (`deploy/scripts/deploy.sh` builds images on the host). Canonical deployment is the host pipeline: `ci/pipeline.sh`. Not for routine production deploys. |

Note: `deploy/monitoring/` is NOT legacy — its alert rule fragments
(`deploy/monitoring/alerts/*.yml`) are mounted by the prometheus service and
the Grafana dashboards + incident policy live there. (The legacy standalone
status-page container — status_server.py, its Dockerfile, systemd unit,
nginx confs and probe scripts — was removed; the prod status surface is the
`status-server` compose service.)

---

## 9. Key Decisions

1. **Docker Compose, not K8s or bare-metal** — Simpler, single-host, no
   orchestration overhead. The pipeline running on the host builds the
   images locally and brings up the stack. (K8s and systemd archived in
   `deploy/legacy-*/`.)

2. **Single nginx config, not per-domain fragments** — The catch-all HTTP
   server handles ACME challenges for all domains. HTTPS blocks are in the same
   file. No `sites-enabled/`, no `conf.d/`.

3. **Cert covers ALL 13 hostnames** (see §3) — One cert, renewed atomically.
   The renewal hook copies it to the tree paths nginx/mta/imap read; nginx
   reloads in place and the host-side watcher restarts mta/imap once per
   renewal.

4. **Mail ports are direct, not proxied** — SMTP/IMAP go straight to the
   container via Docker port mapping. Nginx only handles HTTP/HTTPS. This avoids
   stream/mail module complexity.

5. **KiwiCaptcha for auth** — Native Rust PoW CAPTCHA, inline nonce'd script.
   No external services. Challenge state in Redis.

6. **No hardcoded IPs in canonical files** — The pipeline runs on the host
   itself; manual deploys take the host from `DEPLOY_HOST`. No production
   IP appears in this document or the deploy config by design.
