# Architecture Overview

> **Implementation Note (2026-02):** The backend services have been consolidated into a single Rust mail-server binary. This document reflects the current production architecture.

## System Architecture

ApexMail uses a Rust-first architecture with SSR browser surfaces, a dedicated tracking service, and Zola-generated marketing exports:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                              Load Balancer                              │
│                         (nginx reverse proxy)                           │
└────────────────────────────────────────────────────────────────────────┘
                                 │
            ┌───────────────────────┴───────────────────────┐
            │                                               │
            ▼                                               ▼
    ┌─────────────────────────┐                    ┌─────────────────────────┐
    │       API Server        │                    │    Tracking Service     │
    │     (Rust/Axum)         │                    │      (Rust/Axum)        │
    │ REST + SSR browser UI   │                    │ redirects / webhooks    │
    │ Port: 3000              │                    │ Port: 3001              │
    │ Metrics: 9090           │                    │ Metrics: 9092           │
    └────────────┬────────────┘                    └────────────┬────────────┘
              │                                              │
    ┌───────────┼───────────────┬───────────────┐              │
    │           │               │               │              │
    ▼           ▼               ▼               ▼              ▼
┌─────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐  ┌─────────────┐
│PostgreSQL│ │ ClickHouse  │ │    Redis    │ │ Mailpit │  │ marketing-  │
│  (OLTP) │ │   (OLAP)    │ │   (Cache)   │ │(DevSMTP)│  │ zola export  │
└─────────┘ └─────────────┘ └─────────────┘ └─────────┘  └─────────────┘
```

Marketing pages are generated from `apps/marketing-zola` and served through the Rust browser-surface stack.

## Service Breakdown

### Browser and API Services (Rust)

| Service | Port | Technology | Purpose |
| ------- | ---- | ---------- | ------- |
| API Server | 3000 | Rust/Axum + `ui-foundation` | REST API plus SSR `web` and `control-plane` surfaces |
| Tracking | 3001 | Rust/Axum | Tracking redirects, pixels, unsubscribe flows, webhooks |

### Supporting Runtime Outputs

| Service | Port | Technology | Purpose |
| ------- | ---- | ---------- | ------- |
| Marketing Export | n/a | Zola static export | Generated marketing documents consumed by production routing |
| Metrics | 9090 / 9092 | Prometheus | Observability endpoints for Rust services |

### Infrastructure (Docker)

| Component | Technology | Purpose |
|-----------|------------|---------|
| Database | PostgreSQL 16 | Primary OLTP data store |
| Analytics | ClickHouse 24.8 | OLAP analytics (billions of events) |
| Cache | Redis 7 | Caching, rate limiting |
| Email Delivery | AWS SES (shared) + Hetzner SMTP (dedicated IPs) | Hybrid per-message routing |
| SMTP (dev) | Mailpit | Local email testing |

## Monorepo Structure

```
apexmail/
├── apps/
│   ├── ai/                  # AI application surface
│   ├── marketing-zola/      # Marketing static site source
│   └── ...
│
├── services/
│   └── mail-server/         # Rust mail server
│       └── crates/
│           ├── tracking-service/   # Tracking endpoints and redirect flows
│           ├── api-server/         # REST API + SSR browser surfaces
│           ├── analytics/          # Analytics engine
│           ├── mta/                # SMTP handling
│           ├── worker-processors/  # Background jobs
│           ├── ddos-protection/    # 5-layer DDoS defense (ML, PoW, SMTP)
│           ├── waf-engine/         # AST-based SQLi/XSS WAF
│           ├── ids-engine/         # Intrusion detection/prevention
│           ├── spam-filter/        # Bayesian spam & phishing filter
│           ├── sandbox/            # Attachment static analysis
│           ├── ato-protection/     # Account takeover prevention
│           ├── dlp-engine/         # Data loss prevention
│           ├── threat-intel/       # IP/domain threat intelligence
│           └── ...                 # 45+ crates total
│
├── packages/
│   ├── sdk-go/              # Go SDK
│   ├── sdk-java/            # Java SDK
│   ├── sdk-php/             # PHP SDK
│   ├── sdk-python/          # Python SDK
│   ├── sdk-ruby/            # Ruby SDK
│   └── ...                  # More SDKs
│
├── tools/
│   ├── bootstrap.sh         # Development setup
│   ├── migrate/             # Database migrations
│   ├── chaos/               # Chaos testing
│   └── verify-routes.ts     # Route verification
│
└── docs/                    # Documentation
```

## Design Principles

### 1. Purpose-Built Email Infrastructure
The core email pipeline uses enterprise-grade infrastructure:
- PostgreSQL for data storage with row-level security
- Redis for caching and rate limiting
- Rust for high-performance request handling
- Minimal external dependencies for core operations

### 2. Pluggable Integrations
All optional integrations are adapter-based:
```rust
// Example: Storage adapter trait
pub trait StorageAdapter: Send + Sync {
    async fn store(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn retrieve(&self, key: &str) -> Result<Vec<u8>>;
}

// S3 implementation (optional)
impl StorageAdapter for S3Adapter { ... }

// Local filesystem (development)
impl StorageAdapter for LocalAdapter { ... }
```

### 3. Thin Interface Pattern
All external dependencies wrapped in internal interfaces via Rust crates:
```
services/mail-server/crates/
├── apexmail-db/      # Database abstraction
├── apexmail-lib/     # Shared utilities
├── rate-limiter/     # Redis-backed rate limiting
├── dns-resolver/     # DNS lookups
└── mail-common/      # Email types
```

### 4. Schema-First Development
- API schemas defined in OpenAPI
- Database schemas with typed migrations
- Startup health validation

## Data Flow

### Email Sending Flow
```
1. API receives send request (tracking-service)
2. Validation (syntax, MX, suppression)
3. Write to PostgreSQL queue
4. Worker processor picks up job
5. Render template
6. Send via SMTP
7. Track delivery events
8. Update status
```

### Event Collection Flow
```
1. Email sent via SMTP
2. Recipient opens/clicks
3. Tracking service logs event
4. Event written to PostgreSQL
5. Analytics crate aggregates data
6. Dashboard queries via API
```

## Security Model

- All traffic TLS 1.2+
- API key authentication
- Row-level security in PostgreSQL
- Audit logging
- Secret rotation with encryption at rest

### Security Crate Stack (8 systems, 230 tests)

The mail server embeds 8 dedicated Rust security crates providing defense-in-depth:

| Layer | Crate | Threat Coverage |
|-------|-------|-----------------|
| Network Edge | `ddos-protection` | Volumetric floods, protocol attacks, SMTP abuse |
| Network Edge | `threat-intel` | Known malicious IPs/domains (Spamhaus feeds) |
| Network Edge | `ids-engine` | Intrusion signatures, port scans, SYN floods |
| Application | `waf-engine` | SQLi, XSS, path traversal, command injection |
| Application | `ato-protection` | Impossible travel, credential stuffing, session hijacking |
| Application | `spam-filter` | Spam, phishing, URL fraud |
| Content | `sandbox` | Malware attachments, macro exploits |
| Content | `dlp-engine` | PII leakage, secrets, confidential data |

See [Security Systems Reference](../security/Security_Systems.md) for complete implementation details.

### Email Authentication Stack

ApexMail implements comprehensive email authentication:

| Protocol | RFC | Purpose |
|----------|-----|---------|
| SPF | RFC 7208 | Authorize sending IPs |
| DKIM | RFC 6376 | Cryptographic message signing |
| DMARC | RFC 7489 | Policy enforcement & reporting |
| ARC | RFC 8617 | Preserve auth across forwarding |
| MTA-STS | RFC 8461 | Enforce TLS (not opportunistic) |
| TLSRPT | RFC 8460 | TLS connection reporting |
| BIMI | Draft | Brand logo display in inbox |

See [Email Authentication Guide](../security/email-authentication.md) for implementation details.

## Scalability

- Horizontal scaling via stateless Rust service
- PostgreSQL read replicas for queries
- Redis cluster for high availability
- Connection pooling via deadpool

## Related Documentation

- [Data Flow](./data-flow.md) - Message lifecycle
- [Queue System](./queue-system.md) - PostgreSQL-native queues
- [MTA Configuration](./mta-configuration.md) - SMTP handling
- [Email Authentication](../security/email-authentication.md) - ARC, MTA-STS, BIMI, TLSRPT
- [Inbox Placement Testing](../user-guide/inbox-placement-testing.md) - Deliverability monitoring
