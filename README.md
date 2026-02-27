# ApexMail

Enterprise-grade transactional email platform with multi-tenant architecture, comprehensive tracking, and analytics capabilities.

## Architecture Overview

ApexMail is a monorepo containing multiple services that work together to provide a complete email delivery platform:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ApexMail Platform                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   API App   │  │ Tracking App│  │ Analytics   │  │       MTA App       │ │
│  │  (Hono)     │  │  (Hono)     │  │    App      │  │   (smtp-server)     │ │
│  │  Port 3000  │  │  Port 3001  │  │  Port 3002  │  │  Ports 25/2525/2526 │ │
│  └─────┬───────┘  └─────┬───────┘  └─────┬───────┘  └──────────┬──────────┘ │
│        │                │                │                     │            │
│        └────────────────┴────────────────┴─────────────────────┘            │
│                                    │                                        │
│                          ┌─────────┴─────────┐                              │
│                          │                   │                              │
│                    ┌─────▼─────┐       ┌─────▼─────┐                        │
│                    │  Worker   │       │   Shared  │                        │
│                    │  (Jobs)   │       │ Packages  │                        │
│                    └───────────┘       └───────────┘                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Apps

| App | Description | Port |
|-----|-------------|------|
| `@apexmail/api` | REST API for message sending, domain management, templates | 3010 |
| `tracking-service` (Rust) | Open pixel, click tracking, unsubscribe handling — `services/mail-server/crates/tracking-service` | 3001 |
| `@apexmail/analytics` | Parquet compaction, reconciliation, DuckDB queries | 3002 |
| `@apexmail/control-plane` | Internal administration dashboard for platform owners | 3020 |
| `@apexmail/worker` | Background job processing (email delivery, webhooks) | N/A |
| `@apexmail/mta` | Inbound email, bounce, and feedback loop processing | 25, 2525, 2526 |

### Packages

| Package | Description |
|---------|-------------|
| `@apexmail/lib` | Shared utilities (logger, crypto, storage, cache, queue) |
| `@apexmail/db` | Database access layer with repositories |

## Tech Stack

- **Runtime**: Node.js 20.11+
- **Language**: TypeScript 5.3+
- **Package Manager**: pnpm 8.14+
- **Build System**: Turborepo
- **API Framework**: Hono 4.x
- **Database**: PostgreSQL 15+
- **Cache/Queue**: Redis 7+
- **Storage**: S3-compatible (MinIO, AWS S3, Cloudflare R2)
- **Analytics**: DuckDB, Apache Parquet

## Getting Started

### Prerequisites

- Node.js 20.11 or higher
- pnpm 8.14 or higher
- PostgreSQL 15+
- Redis 7+
- S3-compatible storage (MinIO for local development)

### Installation

```bash
# Clone the repository
git clone https://github.com/sbelakho2/ApexMail.git
cd apexmail

# Install dependencies
pnpm install

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
vim .env

# Run database migrations
pnpm db:migrate

# Start development servers
pnpm dev
```

### Development Commands

```bash
# Start all services in development mode
pnpm dev

# Build all packages and apps
pnpm build

# Run tests
pnpm test

# Run end-to-end tests
pnpm test:e2e

# Run linting
pnpm lint

# Run type checking
pnpm typecheck

# Format code
pnpm format
```

## Project Structure

```
apexmail/
├── apps/
│   ├── api/                 # REST API service
│   │   ├── src/
│   │   │   ├── routes/      # API route handlers
│   │   │   ├── middleware/  # Auth, rate limiting, etc.
│   │   │   └── config.ts    # App configuration
│   │   └── package.json
│   ├── worker/              # Background job processor
│   │   ├── src/
│   │   │   └── processors/  # Email, webhook, analytics jobs
│   │   └── package.json
│   ├── mta/                 # Mail Transfer Agent
│   │   ├── src/
│   │   │   └── servers/     # Inbound, bounce, FBL servers
│   │   └── package.json
│   ├── tracking/            # Open/click tracking service
│   │   └── package.json
│   └── analytics/           # Analytics and reporting
│       └── package.json
├── packages/
│   ├── lib/                 # Shared utilities
│   │   └── src/
│   │       ├── cache/       # Redis wrapper
│   │       ├── crypto/      # Encryption utilities
│   │       ├── logger/      # Pino logger wrapper
│   │       ├── queue/       # Job queue abstraction
│   │       ├── storage/     # S3 storage wrapper
│   │       └── result.ts    # Result<T,E> monad
│   └── db/                  # Database layer
│       └── src/
│           ├── repositories/# Domain repositories
│           ├── pool.ts      # Connection pooling
│           └── transaction.ts
├── tools/
│   └── migrations/          # SQL migration files
├── .env.example             # Environment template
├── package.json             # Root package.json
├── pnpm-workspace.yaml      # pnpm workspace config
├── turbo.json              # Turborepo config
└── tsconfig.base.json      # Base TypeScript config
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
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `JWT_SECRET` | Secret for JWT signing (32+ chars) | Yes |
| `MCAPTCHA_ENABLED` | Enable server-side login CAPTCHA verification (`true`/`false`) | No |
| `MCAPTCHA_SITE_KEY` | mCaptcha site key for verification API | When enabled |
| `MCAPTCHA_SECRET` | mCaptcha secret for verification API | When enabled |
| `NEXT_PUBLIC_MCAPTCHA_ENABLED` | Enable login widget rendering in frontend apps | Should match server |
| `NEXT_PUBLIC_MCAPTCHA_WIDGET_URL` | mCaptcha widget URL to embed in login pages | When frontend enabled |
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
- DKIM signing for all outbound email
- SPF/DMARC validation for inbound email
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
