# ApexMail Architecture — Single Source of Truth

> **This document is the authoritative reference for the ApexMail production
> architecture.** All other docs (README, DEPLOYMENT.md, HETZNER_DEPLOY.md)
> defer to this file. If something here contradicts another doc, this doc wins.

## Quick Reference

| What | Value |
|---|---|
| **Production host** | `95.216.226.51` (Hetzner, Finland) |
| **Domain** | `apexmail.ee` + 9 subdomains |
| **Deployment method** | Docker Compose + GHCR images via GitHub Actions |
| **Deployment trigger** | Push to `main` → CI builds images → SSH deploy to host |
| **Canonical compose file** | `docker-compose.prod.yml` (overlay on `docker-compose.yml`) |
| **Canonical nginx config** | `deploy/nginx/nginx.conf` (bind-mounted into the nginx container) |
| **TLS cert** | Let's Encrypt, 10 SANs, auto-renewed via certbot container |
| **CI workflows** | `.github/workflows/deploy.yml` (build+push) + `deploy-hetzner.yml` (SSH deploy) |

---

## 1. Services (all in Docker)

Every service runs as a Docker container on a single host. No bare-metal
processes, no systemd services, no Kubernetes.

| Container | Image | Ports | Purpose |
|---|---|---|---|
| `apexmail-nginx-1` | `nginx:1.27-alpine` | 80, 443 | Reverse proxy, TLS termination, autoconfig |
| `apexmail-api-server-1` | `…/api-server:latest` | 3000 (internal) | REST API + SSR web UI (Axum) |
| `apexmail-marketing-1` | `…/marketing:latest` | 8080 (internal) | Marketing site (Zola static) |
| `apexmail-mta` | `…/mta:latest` | 25, 587, 465 | SMTP inbound + submission (STARTTLS) |
| `apexmail-imap` | `…/imap-server:latest` | 143, 993 | IMAP/IMAPS mail access |
| `apexmail-mailstore` | `…/api-server:latest` | 50051 (internal) | gRPC mail storage backend |
| `apexmail-worker-1` | `…/worker:latest` | 3006 (internal) | Background job processor |
| `apexmail-enterprise-1` | `…/enterprise:latest` | 3002 (internal) | Enterprise features |
| `apexmail-tracking-1` | `…/tracking-service:latest` | 3001 (internal) | Email open/click tracking |
| `apexmail-postgres` | `postgres:16.8-alpine` | 5432 (localhost) | Primary database |
| `apexmail-redis` | `redis:7.4-alpine` | 6379 (localhost) | Cache, queues, KiwiCaptcha challenges |
| `apexmail-clickhouse` | `clickhouse:24.8-alpine` | 8123, 9000 (localhost) | Analytics |
| `apexmail-certbot-1` | `certbot/certbot:v2.11.0` | — | TLS cert renewal (every 12h) |

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
   ├── :143 ───────────┤
   ├── :993 ───────────┘
   │            ┌──────────────┐     ┌──────────────┐
   │            │ MTA (mta)    │     │ IMAP Server  │
   │            │ :25 :587:465 │     │ :143 :993    │
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

### Domains covered (10 SANs)
```
apexmail.ee, www.apexmail.ee, api.apexmail.ee, app.apexmail.ee,
admin.apexmail.ee, control.apexmail.ee, mail.apexmail.ee,
smtp.apexmail.ee, imap.apexmail.ee, autoconfig.apexmail.ee
```

### Cert paths on the host
The cert is stored in multiple locations because different containers read from
different mount points:

| Host path | Mounted in | Used for |
|---|---|---|
| `/etc/letsencrypt/live/apexmail.ee/` | — | Certbot's canonical location |
| `/opt/apexmail/deploy/nginx/ssl/` | `apexmail-nginx-1:/etc/nginx/ssl/` | Docker nginx |
| `/opt/apexmail/certs/` | `apexmail-mta:/etc/ssl/`, `apexmail-imap:/opt/apexmail/certs/` | Mail services |

### Renewal flow
1. `apexmail-certbot-1` runs `certbot renew` every 12h (`deploy/scripts/certbot-renew-loop.sh`)
2. On success, the deploy hook (`deploy/scripts/deploy-cert-hook.sh`) copies the
   renewed cert to ALL three paths above
3. Reloads `apexmail-nginx-1`, restarts `apexmail-mta` + `apexmail-imap`
4. The certbot container maps `/opt/apexmail/deploy/nginx/ssl` as its `/etc/letsencrypt`

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
- `apexmail.ee`, `www.apexmail.ee` → `marketing:8080`
- `app.apexmail.ee` → `api-server:3000`
- `admin.apexmail.ee`, `control.apexmail.ee` → `api-server:3000`
- `status.apexmail.ee` → `api-server:3000`

**No legacy `apexmail.conf` or site-fragment configs.** Those are archived in
`deploy/legacy-systemd/`.

---

## 5. DNS Records

| Type | Host | Value |
|---|---|---|
| A | `apexmail.ee` | `95.216.226.51` |
| A | `www.apexmail.ee` | `95.216.226.51` |
| A | `api.apexmail.ee` | `95.216.226.51` |
| A | `app.apexmail.ee` | `95.216.226.51` |
| A | `admin.apexmail.ee` | `95.216.226.51` |
| A | `control.apexmail.ee` | `95.216.226.51` |
| A | `mail.apexmail.ee` | `95.216.226.51` |
| A | `smtp.apexmail.ee` | `95.216.226.51` |
| A | `imap.apexmail.ee` | `95.216.226.51` |
| A | `autoconfig.apexmail.ee` | `95.216.226.51` |
| MX | `apexmail.ee` | `10 mail.apexmail.ee` |
| TXT | `apexmail.ee` | `v=spf1 mx a -all` |
| TXT | `_dmarc.apexmail.ee` | `v=DMARC1; p=quarantine; rua=mailto:admin@apexmail.ee` |

---

## 6. Mail Server Configuration

### SMTP (submission — for email clients sending mail)
- **Host:** `mail.apexmail.ee` (or `smtp.apexmail.ee` — both resolve, both covered by cert)
- **Port:** 587 with STARTTLS
- **Auth:** PLAIN / LOGIN (after STARTTLS)
- **Container:** `apexmail-mta` (binary: `mta-server`)
- **Cert:** `/etc/ssl/mta.crt` + `/etc/ssl/mta.key`

### IMAP (for email clients reading mail)
- **Host:** `mail.apexmail.ee` (or `imap.apexmail.ee`)
- **Port:** 993 (implicit TLS / IMAPS) — **recommended**
- **Port:** 143 (plaintext + STARTTLS upgrade) — also works
- **Container:** `apexmail-imap` (binary: `imap-server`)
- **Cert:** `/opt/apexmail/certs/apexmail.crt` + `.key`

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

```
push to main
  │
  ▼
deploy.yml (GitHub Actions)
  ├── cargo check + clippy + tests (pr-gate)
  ├── image-name drift guard
  ├── build 8 images (runtime-base, api-server, mta, worker,
  │   enterprise, tracking-service, observability, marketing)
  ├── tag :<short-sha> + :latest
  ├── push to ghcr.io/sbelakho2/apexmail/
  └── Trivy security scan
  │
  ▼ (on success)
deploy-hetzner.yml (GitHub Actions)
  ├── SSH to HETZNER_SSH_HOST
  ├── rsync compose files + deploy/ to /opt/apexmail/
  ├── render .env from APEXMAIL_PROD_ENV secret
  ├── docker compose pull (all images)
  ├── docker compose up -d --remove-orphans
  ├── nginx reload
  └── verify health
```

**For manual deploys / hotfixes**, see `deploy/scripts/HETZNER_DEPLOY.md`.

---

## 8. File Map — What Lives Where

### Canonical (authoritative)
| Path | Purpose |
|---|---|
| `docker-compose.prod.yml` | Production service definitions |
| `docker-compose.yml` | Base (dev) service definitions |
| `deploy/nginx/nginx.conf` | **The only nginx config** (mounted into container) |
| `deploy/scripts/issue-letsencrypt.sh` | First-time cert issuance |
| `deploy/scripts/certbot-renew-loop.sh` | Auto-renewal loop (runs in certbot container) |
| `deploy/scripts/deploy-cert-hook.sh` | Post-renewal cert deployment |
| `deploy/scripts/entrypoint-wrapper.sh` | Container secret env bridging |
| `deploy/scripts/hetzner-bootstrap.sh` | One-time host setup |
| `deploy/scripts/health-check.sh` | Status page health probes |
| `deploy/DEPLOYMENT.md` | CI/CD pipeline reference |
| `deploy/scripts/HETZNER_DEPLOY.md` | Operator deploy guide |
| `deploy/rollback-plan.md` | Rollback procedure (SHA-based) |
| `ARCHITECTURE.md` | **This file** — the single source of truth |

### Legacy (archived, not used)
| Path | What |
|---|---|
| `deploy/legacy-systemd/` | Old bare-metal deploy.sh + systemd units + old nginx configs |
| `deploy/legacy-k8s/` | Old Kubernetes manifests, Helm chart, Kustomize overlays |
| `deploy/legacy-evaluation/` | Aspirational staging + canary specs (never implemented) |

### Do NOT use
| Path | Why |
|---|---|
| `Makefile` | References nonexistent `deploy/systemd/` and legacy nginx config. Only `verify` target is still valid. |
| `deploy/monitoring/` | Standalone status-page container not in the prod compose stack |

---

## 9. Key Decisions

1. **Docker Compose, not K8s or bare-metal** — Simpler, single-host, no
   orchestration overhead. CI builds images, SSH deploys them. (K8s and systemd
   archived in `deploy/legacy-*/`.)

2. **Single nginx config, not per-domain fragments** — The catch-all HTTP
   server handles ACME challenges for all domains. HTTPS blocks are in the same
   file. No `sites-enabled/`, no `conf.d/`.

3. **Cert covers ALL 10 domains** — One cert, renewed atomically. The renewal
   hook copies it to 3 paths (nginx, mta, imap) and reloads all services.

4. **Mail ports are direct, not proxied** — SMTP/IMAP go straight to the
   container via Docker port mapping. Nginx only handles HTTP/HTTPS. This avoids
   stream/mail module complexity.

5. **KiwiCaptcha for auth** — Native Rust PoW CAPTCHA, inline nonce'd script.
   No external services. Challenge state in Redis.

6. **No hardcoded IPs in canonical files** — The CI workflow takes the host
   from `HETZNER_SSH_HOST` secret. The IP `95.216.226.51` appears in this doc
   for reference only.
