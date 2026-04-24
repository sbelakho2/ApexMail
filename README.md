# ApexMail

Rust-first transactional email platform with SSR browser surfaces, tracking, analytics, and mail transport services.

## Architecture Overview

ApexMail now runs as a Rust-focused monorepo. The browser surfaces are served by the Rust `api-server`, tracking is handled by a dedicated Rust service, and the marketing site is generated statically with Zola.

### Runtime Services

| Service | Description | Port |
|---------|-------------|------|
| `api-server` | REST API plus SSR `web` and `control-plane` surfaces | 3000 |
| `tracking-service` | Open pixel, click tracking, unsubscribe handling | 3001 |
| `enterprise` | Enterprise-only routes and support surfaces | 3002 |
| `worker-processors` | Background job processing | N/A |
| `mta` | SMTP handling and mail transfer | 25, 587, 465 |

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
cd apexmail

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
├── tools/                   # Python and shell operational tooling
└── deploy/                  # Deployment manifests and configs
```

## API Reference

### Authentication

All API requests require authentication via API key in the `X-API-Key` header:

```bash
# Using X-API-Key header (for API keys)
curl -H "X-API-Key: am_live_your_api_key" https://api.yourdomain.com/v1/messages

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
| `JWT_SECRET` | Secret for JWT signing (32+ chars) | Yes |
| `MCAPTCHA_ENABLED` | Enable server-side login CAPTCHA verification (`true`/`false`) | No |
| `MCAPTCHA_SITE_KEY` | mCaptcha site key for verification API | When enabled |
| `MCAPTCHA_SECRET` | mCaptcha secret for verification API | When enabled |
| `TRACKING_ENCRYPTION_KEY` | 128-bit key for tracking IDs | Yes |
| `TRACKING_SIGNATURE_KEY` | 256-bit key for signatures | Yes |
| `S3_ENDPOINT` | S3-compatible storage endpoint | Yes |

## Deployment

### Docker

```bash
# Build all images
docker compose build

# Start all services
docker compose up -d
```

### Kubernetes

Kubernetes deployment documentation is planned for a future release. For now, use Docker Compose for production deployments.

## Security

- All API keys are hashed using SHA-256 before storage
- Tracking IDs use AES-128-GCM encryption
- JWT tokens have configurable expiry
- Rate limiting is applied per tenant
- DKIM signing for all outbound email (SES Easy DKIM 2048-bit or self-hosted keys)
- SPF/DMARC validation for inbound email
- Dual delivery transport: AWS SES (primary) with self-hosted SMTP opt-in
- Optional mCaptcha protection on login routes for both web and control-plane apps (see `docs/security/mcaptcha-login.md`)

## License

Proprietary - Bel Consulting OÜ

ApexMail is a brand of Bel Consulting OÜ, Estonia.

**Company Details:**
- Bel Consulting OÜ
- Sakala 7-2, 10141 Tallinn, Estonia
- Registry Code: 16192499
- VAT: EE102951727

## Support

For support inquiries, contact: support@apexmail.ee
