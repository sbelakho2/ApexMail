# Quick Start Guide

Get ApexMail running locally in under 10 minutes.

> **Note (2026-02):** The backend uses a Rust tracking service. TypeScript is used only for the frontend apps.

## Prerequisites

- **Node.js** 20.11.0 or later (for frontend apps)
- **Rust** 1.75+ (for backend service)
- **pnpm** 8.14.0 or later
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

This script will:
1. ✅ Verify prerequisites (Node.js, pnpm, Docker, Rust)
2. ✅ Install dependencies
3. ✅ Start infrastructure services (PostgreSQL, Redis)
4. ✅ Run database migrations
5. ✅ Seed development data
6. ✅ Build the Rust tracking service

## 3. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Essential configuration:

```env
# PostgreSQL
POSTGRES_USER=apexmail
POSTGRES_PASSWORD=your-secure-password
POSTGRES_DB=apexmail

# Redis (optional password)
REDIS_PASSWORD=

# Tracking Service (required - min 32 chars)
TRACKING_SECRET_KEY=your-secure-tracking-secret-minimum-32-characters

# URLs
TRACKING_BASE_URL=http://localhost:3001
```

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

### Start Frontend Apps

```bash
# Start all frontend apps
pnpm dev

# Or start individually:
pnpm --filter @apexmail/web dev         # Dashboard (port 3000)
pnpm --filter @apexmail/control-plane dev  # Admin (port 4000)
pnpm --filter @apexmail/marketing dev   # Marketing site (port 4100)
```

## 5. Verify Installation

Open your browser and navigate to:

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | User web interface |
| Control Plane | http://localhost:4000 | Admin interface |
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

## 6. Send Your First Email

### Get API Key

1. Log into the dashboard at http://localhost:3000
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
│   ├── billing/          # Billing service
│   ├── control-plane/    # Admin dashboard (Next.js)
│   ├── marketing/        # Marketing site (Next.js)
│   ├── testing/          # Playwright tests
│   └── web/              # User dashboard (Next.js)
│
├── services/
│   └── mail-server/      # Rust backend
│       └── crates/
│           ├── tracking-service/  # Main HTTP server
│           ├── api-server/        # API routes
│           └── ...                # 30+ crates
│
├── packages/
│   ├── db/               # Database schema
│   ├── lib/              # Shared TypeScript utils
│   ├── sdk-node/         # Node.js SDK
│   ├── sdk-python/       # Python SDK
│   └── ...               # More SDKs
│
├── docs/                 # Documentation
└── tools/                # Scripts & utilities
```

---

## Common Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start all frontend apps in dev mode |
| `pnpm build` | Build all TypeScript packages |
| `pnpm test` | Run TypeScript tests |
| `pnpm lint` | Lint all packages |
| `pnpm typecheck` | Type check all packages |
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
- `POSTGRES_PASSWORD must be set` - Set in `.env`

### Port Already in Use

```bash
# Find what's using the port
lsof -ti:3001 | xargs kill -9

# Or restart Docker
docker compose down && docker compose up -d
```

### Dependencies Out of Sync

```bash
pnpm install
pnpm build
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
