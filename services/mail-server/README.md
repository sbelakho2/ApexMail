# ApexMail Mail Server

A modular, security-focused mail server written in Rust for ApexMail.

> **⚠️ STANDALONE SERVER - HIGH-PERFORMANCE EMAIL INFRASTRUCTURE**
>
> This mail server is completely self-contained:
> - **Outbound:** Direct SMTP delivery with DKIM signing
> - **Inbound:** SMTP server on port 25
> - **Storage:** PostgreSQL + local blob storage
> - **Purpose-built mail infrastructure with full delivery control**

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                         PROTOCOL EDGES                                │
│                                                                       │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────────┐    │
│  │ smtp-edge   │   │ submission  │   │   outbound-queue        │    │
│  │ (Port 25)   │   │ (Port 587)  │   │                         │    │
│  │             │   │             │   │   Sends emails via      │    │
│  │ Inbound     │   │ Client      │   │   direct SMTP with      │    │
│  │ SMTP        │   │ Sending     │   │   DKIM signing          │    │
│  └──────┬──────┘   └──────┬──────┘   └───────────┬─────────────┘    │
│         │                 │                       │                  │
└─────────┼─────────────────┼───────────────────────┼──────────────────┘
          │                 │                       │
          │  gRPC           │  gRPC                 │  gRPC
          ▼                 ▼                       ▼
┌──────────────────────────────────────────────────────────────────────┐
│                         CORE SERVICES                                 │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │                    mailstore-core                                │ │
│  │                                                                  │ │
│  │  • Message storage (immutable blobs, SHA-256 addressed)         │ │
│  │  • Mailbox management (folders, flags, UIDs)                    │ │
│  │  • User/account management                                      │ │
│  │  • Quota enforcement                                            │ │
│  │  • PostgreSQL metadata backend                                  │ │
│  └─────────────────────────────────────────────────────────────────┘ │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Purpose |
|-------|---------|
| `mail-proto` | gRPC/Protobuf definitions for inter-service communication |
| `mail-common` | Shared types, utilities, and error handling |
| `mailstore-core` | Central message storage and mailbox management |
| `smtp-edge` | Inbound SMTP server (port 25) |
| `submission` | Authenticated client submission (port 587) |
| `outbound-queue` | Outbound delivery with retry logic and DKIM |

## Configuration

Configuration is via environment variables or `/etc/apexmail/mail.toml`:

```toml
[server]
hostname = "mail.apexmail.ee"
domain = "apexmail.ee"

[database]
url = "postgresql://mail:password@localhost/maildb"
max_connections = 20

[storage]
blob_path = "/var/lib/apexmail/blobs"
index_path = "/var/lib/apexmail/index"

[tls]
cert_path = "/etc/letsencrypt/live/mail.apexmail.ee/fullchain.pem"
key_path = "/etc/letsencrypt/live/mail.apexmail.ee/privkey.pem"

[dkim]
selector = "apexmail2026"
private_key_path = "/etc/apexmail/dkim/apexmail2026.private"

[outbound]
# Direct SMTP delivery with enterprise-grade infrastructure
max_retries = 5
retry_delay_seconds = 300
concurrent_deliveries = 10
```

### Login CAPTCHA (KiwiCaptcha)

KiwiCaptcha enforcement for interactive login flows is configured in the Rust UI/application layer (`api-server` plus `ui-foundation`), not in the SMTP/mail transport runtime itself.

Use these docs for setup and behavior:

- `docs/deployment/configuration.md` (Login CAPTCHA section)
- `docs/deployment/quickstart.md` (optional local setup and smoke checks)

## Building

```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --release

# Run tests
cargo test
```

## Deployment

```bash
# Build Docker image
docker build -t apexmail/mail-server .

# Run with docker-compose
docker-compose up -d mail-server
```

## Integration Notes

Internal integrations now communicate with the mail server through its Rust-owned HTTP and gRPC surfaces.

## What's New

- **MFA / Admin 2FA TOTP** — Multi-factor authentication for admin accounts using time-based one-time passwords
- **Dark mode** — Marketing Zola templates now respect `prefers-color-scheme` with full dark mode support
- **HSTS preload** — `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` header on all HTTPS responses
- **CSRF protection** — All auth POST forms (login, signup, forgot-password, reset-password) include CSRF tokens
- **DSAR rate limiting** — GDPR data-subject request endpoints enforce per-user (1/24h), per-tenant (100/24h), and per-IP rate limits
- **Cursor pagination** — All list endpoints now support cursor-based pagination across all 5 SDKs (Go, Java, PHP, Python, Ruby)

## Security Features

- Memory-safe Rust implementation
- TLS 1.3 for all connections
- DKIM signing for outbound mail
- SPF/DMARC verification for inbound
- Rate limiting and abuse prevention
- MFA (TOTP) for admin accounts
- HSTS preload header
- CSRF token protection on all auth forms
- DSAR rate limiting for GDPR compliance
- Minimal external API dependencies

## License

Proprietary — Bel Consulting OÜ 2026

ApexMail is a brand of Bel Consulting OÜ, Estonia.
