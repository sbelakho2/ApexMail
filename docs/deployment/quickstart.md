# Quick Start Guide

Get ApexMail running locally in under 10 minutes.

## Prerequisites

- **Node.js** 20.11.0 or later
- **pnpm** 8.14.0 or later
- **Docker** and Docker Compose
- **Git**

## 1. Clone the Repository

```bash
git clone https://github.com/yourorg/apexmail.git
cd apexmail
```

## 2. Run Bootstrap Script

The bootstrap script sets up the entire development environment:

```bash
./tools/bootstrap.sh
```

This script will:
1. ✅ Verify prerequisites (Node.js, pnpm, Docker)
2. ✅ Install dependencies
3. ✅ Start infrastructure services (PostgreSQL, Redis)
4. ✅ Run database migrations
5. ✅ Seed development data
6. ✅ Generate TypeScript types

## 3. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Essential configuration:

```env
# Database
DATABASE_URL="postgresql://apexmail:apexmail@localhost:5432/apexmail"

# Redis
REDIS_URL="redis://localhost:6379"

# JWT Secret (generate a secure random string)
JWT_SECRET="your-secure-jwt-secret-minimum-32-characters"

# Encryption Key (32 bytes base64)
ENCRYPTION_KEY="generate-with-openssl-rand-base64-32"
```

Generate secure secrets:

```bash
# Generate JWT secret
openssl rand -base64 32

# Generate encryption key
openssl rand -base64 32
```

## 4. Start Development Servers

Start all services in development mode:

```bash
pnpm dev
```

Or start individual services:

```bash
# API server only
pnpm --filter @apexmail/api dev

# Web dashboard only
pnpm --filter @apexmail/web dev

# Worker processes only
pnpm --filter @apexmail/worker dev
```

## 5. Verify Installation

Open your browser and navigate to:

| Service | URL | Description |
|---------|-----|-------------|
| Dashboard | http://localhost:3000 | Web interface |
| API | http://localhost:3001 | REST API |
| API Docs | http://localhost:3001/docs | OpenAPI documentation |
| Tracking | http://localhost:3002 | Tracking pixel/links |

### Health Check

```bash
curl http://localhost:3001/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "database": "healthy",
    "redis": "healthy",
    "worker": "healthy"
  }
}
```

## 6. Create Test Account

### Via CLI

```bash
pnpm cli user:create \
  --email admin@example.com \
  --password "SecurePassword123!" \
  --role admin
```

### Via API

```bash
curl -X POST http://localhost:3001/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePassword123!",
    "name": "Admin User"
  }'
```

## 7. Send Your First Email

### Get API Key

1. Log into the dashboard at http://localhost:3000
2. Navigate to Settings → API Keys
3. Create a new API key with `messages:send` scope

### Send Test Email

```bash
curl -X POST http://localhost:3001/api/v1/messages \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "test@example.com",
    "from": "hello@localhost",
    "subject": "Hello from ApexMail!",
    "html": "<h1>It works!</h1><p>Your ApexMail installation is ready.</p>"
  }'
```

> **Note**: In development mode, emails are captured by Mailpit at http://localhost:8025

## 8. View Development Emails

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
│   ├── api/          # REST API (Hono)
│   ├── web/          # Dashboard (Next.js)
│   ├── worker/       # Background jobs (BullMQ)
│   ├── mta/          # Email server (Postfix)
│   ├── tracking/     # Open/click tracking
│   ├── analytics/    # Analytics engine
│   ├── ai/           # AI inference
│   ├── compliance/   # Security & GDPR
│   ├── sales-autopilot/  # CRM
│   ├── ops/          # Operations/monitoring
│   └── testing/      # Test infrastructure
│
├── packages/
│   ├── db/           # Database layer
│   └── lib/          # Shared utilities
│
├── docs/             # Documentation
└── tools/            # Scripts & utilities
```

---

## Common Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Start all services in dev mode |
| `pnpm build` | Build all packages |
| `pnpm test` | Run all tests |
| `pnpm lint` | Lint all packages |
| `pnpm typecheck` | Type check all packages |
| `pnpm db:migrate` | Run database migrations |
| `pnpm db:seed` | Seed development data |
| `pnpm db:studio` | Open Prisma Studio |

---

## Troubleshooting

### Database Connection Failed

```
Error: connect ECONNREFUSED 127.0.0.1:5432
```

**Solution**: Ensure PostgreSQL is running:
```bash
docker compose up -d postgres
```

### Redis Connection Failed

```
Error: connect ECONNREFUSED 127.0.0.1:6379
```

**Solution**: Ensure Redis is running:
```bash
docker compose up -d redis
```

### Port Already in Use

```
Error: listen EADDRINUSE :::3000
```

**Solution**: Kill the process using the port:
```bash
lsof -ti:3000 | xargs kill -9
```

Or use a different port:
```bash
PORT=3100 pnpm --filter @apexmail/api dev
```

### Migration Failed

```
Error: P3009 migrate found failed migrations
```

**Solution**: Reset the database:
```bash
pnpm db:reset
```

> ⚠️ This will delete all data!

### Dependencies Out of Sync

```
Error: Cannot find module '@apexmail/lib'
```

**Solution**: Rebuild dependencies:
```bash
pnpm install
pnpm build
```

---

## Next Steps

1. **Verify Domain**: [Domain Verification Guide](./configuration.md#domain-verification)
2. **Configure SMTP**: [SMTP Setup Guide](./configuration.md#smtp-configuration)
3. **Set Up Webhooks**: [Webhook Configuration](../api/webhooks.md)
4. **Deploy to Production**: [Docker Deployment](./docker.md)

---

## Getting Help

- 📖 [Full Documentation](../README.md)
- 💬 [GitHub Discussions](https://github.com/yourorg/apexmail/discussions)
- 🐛 [Issue Tracker](https://github.com/yourorg/apexmail/issues)
- 📧 [Email Support](mailto:support@apexmail.io)
