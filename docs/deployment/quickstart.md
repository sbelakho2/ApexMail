# Quick Start Guide

Get ApexMail running locally in under 10 minutes.

> **Note (2026-04):** The `web` and `control-plane` browser surfaces are served by the Rust `api-server`, and the repo no longer depends on a Node workspace.

## Prerequisites

- **Rust** 1.75+ (for backend service)
- **Docker** and Docker Compose
- **Git**

## 1. Clone the Repository

```bash
git clone https://github.com/sbelakho2/ApexMail.git
cd ApexMail
```

## 2. Run Bootstrap Script

The bootstrap script sets up the entire development environment:

```bash
./tools/bootstrap.sh
```

This script installs the pinned Rust and Go toolchains under `.toolchain/` for local development.

After it finishes, activate the toolchain:

```bash
source .toolchain/env.sh
```

## 3. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Essential configuration:

```env
# PostgreSQL
POSTGRES_USER=apexmail
POSTGRES_DB=apexmail

# Redis (optional password)
REDIS_PASSWORD=

# Tracking Service (required - min 32 chars)
TRACKING_SECRET_KEY=your-secure-tracking-secret-minimum-32-characters

# URLs
TRACKING_BASE_URL=http://localhost:3001

# Optional: login CAPTCHA protection (mCaptcha)
MCAPTCHA_ENABLED=false
# Required only when enabling CAPTCHA
# MCAPTCHA_SITE_KEY=...
# MCAPTCHA_SECRET=...
```

For the repo Docker Compose stack, store the Postgres password in the repo-local secret file:

```bash
printf '%s' 'your-secure-password' > secrets/postgres_password.txt
chmod 600 secrets/postgres_password.txt
```

If you run Rust services directly outside Compose, keep your normal `DB_PASSWORD` or `DATABASE_URL` settings aligned with that secret.

Generate secure secrets:

```bash
# Generate tracking secret
openssl rand -base64 32
```

## 4. Start Services

### Start Infrastructure

```bash
docker compose up -d
```

This starts:
- PostgreSQL (port 5432)
- Redis (port 6379)
- Tracking service (port 3001, metrics on 9092)
- Mailpit (port 8025 - dev SMTP)

### Start Development Services

```bash
cargo run --manifest-path services/mail-server/Cargo.toml -p api-server

# Browser surfaces:
#   http://127.0.0.1:3000 -> web
#   http://localhost:3000 -> control-plane
```

## 5. Verify Installation

Open your browser and navigate to:

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://127.0.0.1:3000 | User web interface |
| Control Plane | http://localhost:3000 | Admin interface |
| Tracking Health | http://localhost:3001/health | Backend health check |
| Mailpit | http://localhost:8025 | Dev email inbox |
| Prometheus Metrics | http://localhost:9092/metrics | Service metrics |

### Health Check

```bash
curl http://localhost:3001/health
```

Expected response:
```json
{
  "status": "healthy"
}
```

Readiness check (includes dependencies):
```bash
curl http://localhost:3001/ready
```

### Optional Login CAPTCHA Smoke Test

If you enable mCaptcha, verify both login surfaces:

1. Set these env values and restart the local dev services:

```env
MCAPTCHA_ENABLED=true
MCAPTCHA_SITE_KEY=your-site-key
MCAPTCHA_SECRET=your-secret
```

2. Open both login pages:
  - `http://127.0.0.1:3000/login` (web)
  - `http://localhost:3000/login` (control-plane)

3. Confirm expected behavior:
  - Widget is visible on both pages.
  - Submitting without solving CAPTCHA shows a CAPTCHA-required error.
  - Solving CAPTCHA allows normal auth flow.

## 6. Send Your First Email

### Get API Key

1. Log into the dashboard at http://127.0.0.1:3000
2. Navigate to Settings → API Keys
3. Create a new API key with `messages:write` scope

### Send Test Email

```bash
curl -X POST http://localhost:3001/v1/messages \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "test@example.com",
    "from": "hello@localhost",
    "subject": "Hello from ApexMail!",
    "html": "<h1>It works!</h1><p>Your ApexMail installation is ready.</p>"
  }'
```

> **Note**: In development mode, emails are captured by Mailpit at http://localhost:8025

## 7. View Development Emails

Open Mailpit to see captured emails:

```
http://localhost:8025
```

Mailpit intercepts all outgoing emails in development, allowing you to test without sending real emails.

---

## Project Structure

```
apexmail/
├── apps/
│   ├── ai/               # AI application surface
│   ├── marketing-zola/   # Marketing static site (Zola)
│   └── ...
│
├── services/
│   └── mail-server/      # Rust backend
│       └── crates/
│           ├── tracking-service/  # Tracking endpoints and redirect flows
│           ├── api-server/        # API + SSR browser surfaces
│           └── ...                # 30+ crates
│
├── packages/
│   ├── sdk-go/           # Go SDK
│   ├── sdk-java/         # Java SDK
│   ├── sdk-php/          # PHP SDK
│   ├── sdk-python/       # Python SDK
│   └── sdk-ruby/         # Ruby SDK
│
├── docs/                 # Documentation
└── tools/                # Scripts & utilities
```

---

## Common Commands

| Command | Description |
|---------|-------------|
| `cargo run --manifest-path services/mail-server/Cargo.toml -p api-server` | Start the main API and SSR surfaces |
| `cargo test --manifest-path services/mail-server/Cargo.toml` | Run the Rust test suite |
| `zola build --root apps/marketing-zola` | Rebuild the static marketing output |
| `docker compose up -d` | Start backend services |
| `docker compose logs -f tracking` | View tracking service logs |

### Rust Commands

```bash
# Build tracking service
cd services/mail-server
cargo build -p tracking-service

# Run tests
cargo test -p tracking-service

# Run with debug logging
RUST_LOG=debug cargo run -p tracking-service
```

---

## Troubleshooting

### Database Connection Failed

```
Error: connect ECONNREFUSED 127.0.0.1:5432
```

**Solution**: Ensure PostgreSQL is running:
```bash
docker compose up -d postgres
docker compose logs postgres
```

### Redis Connection Failed

```
Error: connect ECONNREFUSED 127.0.0.1:6379
```

**Solution**: Ensure Redis is running:
```bash
docker compose up -d redis
```

### Tracking Service Won't Start

Check logs:
```bash
docker compose logs tracking
```

Common issues:
- `TRACKING_SECRET_KEY must be set` - Set in `.env`
- `secrets/postgres_password.txt` missing or mismatched - Write the intended password to that file and restart the affected Compose services.

### Port Already in Use

```bash
# Find what's using the port
lsof -ti:3001 | xargs kill -9

# Or restart Docker
docker compose down && docker compose up -d
```

### Toolchain Out of Sync

```bash
./tools/bootstrap.sh
source .toolchain/env.sh
```

---

## Next Steps

1. **Verify Domain**: [Domain Configuration](./configuration.md)
2. **Set Up Webhooks**: [Webhook Configuration](../api/webhooks.md)
3. **Explore the API**: [API Documentation](../api/sdk-reference.md)
4. **Production Deployment**: Use `docker-compose.prod.yml`

---

## Getting Help

- 📖 [Full Documentation](../README.md)
- 💬 [GitHub Discussions](https://github.com/sbelakho2/ApexMail/discussions)
- 🐛 [Issue Tracker](https://github.com/sbelakho2/ApexMail/issues)
- 📧 [Email Support](mailto:support@apexmail.ee)
