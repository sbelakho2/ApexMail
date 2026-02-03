# Architecture Overview

## System Architecture

ApexMail is built as a modular monorepo with clear service boundaries:

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Load Balancer                              │
│                         (nginx/HAProxy/Cloudflare)                      │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web App       │    │   API Service   │    │ Tracking Service│
│   (Next.js 14)  │    │   (Hono)        │    │   (Hono)        │
│   Port: 3000    │    │   Port: 3001    │    │   Port: 3002    │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                      │
         ▼                      ▼                      ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │   Workers       │
│   (Primary DB)  │    │  (Cache/Queue)  │    │   (BullMQ)      │
└─────────────────┘    └─────────────────┘    └────────┬────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │  Postfix MTA    │
                                              │  (Email Sending)│
                                              └─────────────────┘
```

## Service Breakdown

### Frontend Services

| Service | Port | Technology | Purpose |
|---------|------|------------|---------|
| Web | 3000 | Next.js 14 | Dashboard, UI |
| API | 3001 | Hono | REST API |
| Tracking | 3002 | Hono | Open/click tracking |

### Backend Services

| Service | Port | Technology | Purpose |
|---------|------|------------|---------|
| Worker | - | BullMQ | Background jobs |
| Analytics | 3010 | ClickHouse | OLAP queries |
| AI | 3012 | ONNX Runtime | ML inference |
| Compliance | 3013 | Hono | Security/GDPR |
| Sales Autopilot | 3014 | Hono | CRM |
| Ops | 9090 | Hono | Monitoring/SLOs |

### Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| Database | PostgreSQL 15+ | Primary data store |
| Cache | Redis 7+ | Caching, queues |
| MTA | Postfix | Email delivery |
| Search | DuckDB | Analytics queries |

## Monorepo Structure

```
apexmail/
├── apps/
│   ├── api/                 # REST API service
│   ├── web/                 # Next.js frontend
│   ├── worker/              # Background job processor
│   ├── mta/                 # Postfix configuration
│   ├── tracking/            # Open/click tracking
│   ├── analytics/           # Analytics engine
│   ├── ai/                  # AI inference service
│   ├── compliance/          # Security & GDPR
│   ├── sales-autopilot/     # CRM module
│   ├── ops/                 # Operations & monitoring
│   └── testing/             # Test infrastructure
│
├── packages/
│   ├── db/                  # Database layer
│   └── lib/                 # Shared utilities
│
├── tools/
│   ├── bootstrap.sh         # Development setup
│   ├── migrate/             # Database migrations
│   └── verify-routes.js     # Route verification
│
└── docs/                    # Documentation
```

## Design Principles

### 1. Zero Paid SaaS Dependencies (Core)
The core email pipeline runs entirely self-hosted:
- PostgreSQL for data storage
- Redis for caching and queues
- Postfix for email delivery
- No OpenAI, Twilio, SendGrid required

### 2. Pluggable Integrations
All optional integrations are adapter-based:
```typescript
// Example: Billing adapter
interface BillingAdapter {
  createCustomer(data: CustomerData): Promise<Customer>;
  createSubscription(customerId: string, plan: Plan): Promise<Subscription>;
}

// Stripe implementation (optional)
class StripeAdapter implements BillingAdapter { ... }

// Null implementation (billing disabled)
class NullBillingAdapter implements BillingAdapter { ... }
```

### 3. Thin Interface Pattern
All external dependencies wrapped in internal interfaces:
```
packages/lib/
├── logger/     # Wraps pino
├── crypto/     # Wraps Node crypto
├── storage/    # Wraps S3/local
├── http/       # Wraps fetch
└── cache/      # Wraps Redis
```

### 4. Schema-First Development
- API schemas defined with Zod
- Database schemas with typed migrations
- Startup fingerprint validation

## Data Flow

### Email Sending Flow
```
1. API receives send request
2. Validation (syntax, MX, suppression)
3. Write to outbox (transactional)
4. Worker picks up job
5. Render template
6. Queue to Postfix
7. Track delivery events
8. Update status
```

### Event Collection Flow
```
1. Postfix sends email
2. Recipient opens/clicks
3. Tracking service logs event
4. Event written to PostgreSQL
5. CDC syncs to ClickHouse
6. Analytics queries served
```

## Security Model

- All traffic TLS 1.2+
- JWT authentication with refresh tokens
- RBAC with granular permissions
- Audit logging with cryptographic signing
- Secret rotation with encryption at rest

## Scalability

- Horizontal scaling via stateless services
- PostgreSQL read replicas for queries
- Redis cluster for high availability
- Postfix cluster with IP pooling
- Worker autoscaling based on queue depth

## Related Documentation

- [Control Plane Isolation](./control-plane-isolation.md) - Security boundaries
- [Analytics & Data Science](./analytics-data-science.md) - ML modules (STO, Churn, NLP)
- [Data Flow](./data-flow.md) - Message lifecycle
