# ApexMail

Rust-first transactional email platform with SSR browser surfaces, tracking, analytics, and mail transport services.

## Architecture Overview

All services run in Docker containers on a single Hetzner host. The full
architecture — network topology, service map, TLS/cert flow, DNS records, mail
server config, deployment pipeline, and file locations — is documented in
**[ARCHITECTURE.md](ARCHITECTURE.md)** (the single source of truth).

| Service | Purpose | Port(s) |
|---------|---------|---------|
| `api-server` | REST API + SSR web UI (Axum) | 3000 (internal) |
| `mta` | SMTP inbound + submission (STARTTLS) | 25, 587, 465 |
| `imap-server` | IMAP/IMAPS mail access | 993 |
| `marketing` | Marketing site (Zola static) | 8080 (internal) |
| `nginx` | Reverse proxy, TLS termination | 80, 443 |
| `postgres` | Primary database | 5432 |
| `redis` | Cache, queues, KiwiCaptcha challenges | 6379 |
| `clickhouse` | Analytics | 8123, 9000 |

## Tech Stack

- Rust and Cargo for the application runtime
- PostgreSQL 16+
- Redis 7+
- Zola for the static marketing source
- Docker Compose for local dependencies

## Getting Started

### Prerequisites

- Rust toolchain
- Docker and Docker Compose
- PostgreSQL and Redis if not using Docker locally
- Zola only if you need to regenerate marketing exports

### Installation

```bash
git clone https://github.com/sbelakho2/ApexMail.git
cd ApexMail
cp .env.example .env

docker compose up -d postgres redis
cargo test --manifest-path services/mail-server/Cargo.toml
```

### Common Commands

```bash
# Run the full Rust test suite
cargo test --manifest-path services/mail-server/Cargo.toml

# Run a specific crate
cargo test --manifest-path services/mail-server/Cargo.toml -p api-server

# Start the main API surface
cargo run --manifest-path services/mail-server/Cargo.toml -p api-server

# Rebuild static marketing output when needed
zola build --root apps/marketing-zola
```

### Compose Smoke Verification

Use the repo-local smoke script to exercise the monitoring slice, the hardened prod compose subset, and the Alertmanager to Observability delivery path:

```bash
# Bring up monitoring plus the prod smoke subset
./tools/run-compose-smoke.sh up

# Verify endpoints and container health
./tools/run-compose-smoke.sh verify

# Inject a synthetic alert and confirm it lands in Observability
./tools/run-compose-smoke.sh alert

# Stop the smoke-test containers and remove target/apexmail-smoke
./tools/run-compose-smoke.sh down
```

`./tools/run-compose-smoke.sh full` runs `up`, `verify`, and `alert` in one pass. The script keeps temporary TLS and JWT material under `target/apexmail-smoke` so Docker Desktop on macOS can mount it reliably.

### Local Compose Overrides

Local development uses Docker Compose's default merge behavior for [docker-compose.yml](docker-compose.yml) plus [docker-compose.override.yml](docker-compose.override.yml). The override file swaps the hardened production-oriented base service definitions for developer-friendly local settings such as direct host port bindings and writable service defaults.

Use the default local merge for day-to-day development:

```bash
docker compose up -d postgres redis
```

Use the hardened production overlays explicitly when validating production wiring:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Project Structure

```text
apexmail/
├── apps/
│   ├── ai/                  # Non-JS application assets
│   └── marketing-zola/      # Zola marketing source and generated public output
├── services/
│   └── mail-server/
│       └── crates/          # Rust application crates
├── packages/
│   ├── sdk-go/
│   ├── sdk-java/
│   ├── sdk-php/
│   ├── sdk-python/
│   └── sdk-ruby/
├── Lobster/                 # Standalone Lobster-language calculator proof of concept kept as an in-repo experiment
├── tools/                   # Python and shell operational tooling
└── deploy/                  # Deployment manifests and configs
```

`Lobster/` is not part of the ApexMail mail runtime. It is a small, separate proof-of-concept app kept in the repository as a language/UI experiment.

## API Reference

### Authentication

All API requests require authentication via API key in the `X-API-Key` header:

```bash
# Using X-API-Key header (for API keys)
curl -H "X-API-Key: am_live_your_api_key" https://api.apexmail.ee/v1/messages

# Bearer token is used for dashboard JWT sessions only
```

### Endpoints

#### Messages

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/messages` | Send a message |
| GET | `/v1/messages` | List messages |
| GET | `/v1/messages/:id` | Get message details |
| DELETE | `/v1/messages/:id` | Cancel a scheduled message |

#### Domains

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/domains` | Add a domain |
| GET | `/v1/domains` | List domains |
| GET | `/v1/domains/:id` | Get domain details |
| POST | `/v1/domains/:id/verify` | Verify domain DNS |
| DELETE | `/v1/domains/:id` | Remove a domain |

#### Templates

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/templates` | Create a template |
| GET | `/v1/templates` | List templates |
| GET | `/v1/templates/:id` | Get template details |
| PUT | `/v1/templates/:id` | Update a template |
| DELETE | `/v1/templates/:id` | Delete a template |
| POST | `/v1/templates/:id/render` | Preview template rendering |

#### Suppressions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/suppressions` | Add to suppression list |
| GET | `/v1/suppressions` | List suppressions |
| DELETE | `/v1/suppressions/:email` | Remove from suppression list |

#### Events

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/events` | List events |
| GET | `/v1/events/:id` | Get event details |

#### Webhooks

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/webhooks` | Create a webhook |
| GET | `/v1/webhooks` | List webhooks |
| PUT | `/v1/webhooks/:id` | Update a webhook |
| DELETE | `/v1/webhooks/:id` | Delete a webhook |

#### Analytics

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/analytics/overview` | Get analytics overview |
| GET | `/v1/analytics/time-series` | Get time-series data |
| GET | `/v1/analytics/reputation` | Get sender reputation |

## Event Types

ApexMail tracks the following event types:

| Event | Description |
|-------|-------------|
| `queued` | Message accepted and queued for delivery |
| `sent` | Message sent to recipient's mail server |
| `delivered` | Message delivered to recipient |
| `opened` | Recipient opened the message |
| `clicked` | Recipient clicked a link |
| `bounced` | Message bounced (hard or soft) |
| `complained` | Recipient marked as spam |
| `unsubscribed` | Recipient unsubscribed |

## Configuration

See `.env.example` for all available configuration options.

### Key Configuration

| Variable | Description | Required |
|----------|-------------|----------|
| `EMAIL_TRANSPORT_TYPE` | `ses` (default) or `smtp` | No (defaults to `ses`) |
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `JWT_PRIVATE_KEY_PEM` | RSA private key used for JWT signing | Yes |
| `JWT_PUBLIC_KEY_PEM` | RSA public key used for JWT verification | Yes |
| `KIWI_ENABLED` | Enable server-side login CAPTCHA verification (`true`/`false`) | No |
| `KIWI_SECRET_KEY` | KiwiCaptcha HMAC secret key for challenge signing | When enabled |
| `TRACKING_ENCRYPTION_KEY` | 128-bit key for tracking IDs | Yes |
| `TRACKING_SIGNATURE_KEY` | 256-bit key for signatures | Yes |
| `S3_ENDPOINT` | S3-compatible storage endpoint | Yes |

## Deployment

ApexMail ships to production via **Docker Compose + GHCR images**, deployed by
GitHub Actions over SSH to the Hetzner host. `deploy.yml` builds **all ten
service images** (`api-server`, `mta`, `imap-server`, `mailstore`, `worker`,
`enterprise`, `tracking-service`, `observability`, `marketing`,
`status-server`) and pushes
them to GHCR; `deploy-hetzner.yml` then pulls them on the host and runs
`docker compose up -d`. The full, authoritative procedure — including the
service→image map, tag strategy, required secrets, and drift guard — lives in
**[`deploy/DEPLOYMENT.md`](deploy/DEPLOYMENT.md)**, which is the single
source of truth for deployment.

The `Makefile` + `deploy/scripts/deploy.sh` path is a **manual/emergency
fallback only** (it builds images locally on the host and never pushes them);
do not use it for routine production deploys.

The legacy bare-metal (systemd) and Kubernetes deployment paths are **superseded**
but preserved for reference under [`deploy/legacy-systemd/`](deploy/legacy-systemd/)
and [`deploy/legacy-k8s/`](deploy/legacy-k8s/). Do not use them for production.

### Local Development

```bash
# Start dependencies
docker compose up -d postgres redis

# Build and run auth-server
cargo build --release --manifest-path services/mail-server/Cargo.toml
./services/mail-server/target/release/auth-server

# Build marketing site
zola build --root apps/marketing-zola
```

## Security

- All API keys are hashed using SHA-256 before storage
- Tracking IDs use AES-128-GCM encryption
- JWT tokens have configurable expiry
- Rate limiting is applied per tenant
- DKIM signing for all outbound email (SES Easy DKIM 2048-bit or self-hosted keys)
- SPF/DMARC validation for inbound email
- Dual delivery transport: AWS SES (primary) with self-hosted SMTP opt-in
- Optional KiwiCaptcha protection on login routes for both web and control-plane apps (native Rust proof-of-work CAPTCHA)

## License

Proprietary - Bel Consulting OÜ

ApexMail is a brand of Bel Consulting OÜ, Estonia.

**Company Details:**
- Bel Consulting OÜ
- Sakala 7-2, 10141 Tallinn, Estonia
- Registry Code: 16588745
- VAT: EE102951727

## Support

For support inquiries, contact: support@apexmail.ee
