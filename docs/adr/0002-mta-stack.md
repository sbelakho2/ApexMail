# ADR 0002: MTA Stack

## Status
Accepted — **Amended by [ADR 0011](./0011-dual-delivery-ses-primary.md)**

> **Amendment (2026-02):** Outbound delivery now defaults to **AWS SES** as the primary transport. The self-hosted MTA (Rust-native SMTP, not Postfix) is retained as an opt-in path for operators who need full IP control. See [ADR 0011](./0011-dual-delivery-ses-primary.md) for the full decision record. The inbound MTA architecture described below is unchanged.

> **Implementation Note (2026-02):** The MTA is implemented as a Rust crate (`services/mail-server/crates/mta/`). Postfix is not deployed as a separate container. SMTP handling is native Rust.

## Date
2024-01-15

## Context
ApexMail requires a Mail Transfer Agent (MTA) that:
- Handles high-volume outbound email (100k+ emails/hour)
- Supports advanced authentication (DKIM, SPF, DMARC, ARC, BIMI)
- Enables per-domain rate limiting and IP pooling
- Provides enterprise-grade reliability and full delivery control

## Decision
We chose a **Rust-native SMTP stack with hybrid outbound transport**: AWS SES is the shared default path, while self-hosted Rust SMTP remains available for operators who need dedicated IP control.

### Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                      API Layer                              │
│              (Message ingestion, validation)                │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   PostgreSQL Queue                          │
│            (Transactional outbox pattern)                   │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    Worker Layer                             │
│        (Render templates, apply rules, queue to MTA)        │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                 Outbound Delivery Layer                     │
│                                                             │
│  ┌────────────────────┐  ┌──────────────────────────────┐  │
│  │ AWS SES shared pool│  │ Rust-native SMTP nodes       │  │
│  │ Default shared path│  │ Dedicated-IP / warmup path   │  │
│  └────────────────────┘  └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Outbound Transport Configuration
- AWS SES for the shared pool path
- Rust-native SMTP for dedicated-IP traffic and full IP control
- TLS 1.2+ enforcement on the self-hosted SMTP path
- Per-IP warmup and rate isolation for dedicated-IP traffic
- Opportunistic DANE support and IPv4/IPv6 dual-stack sending on the SMTP path

### Authentication Stack
| Protocol | Implementation |
|----------|----------------|
| DKIM | AWS Easy DKIM for SES shared sending; self-hosted signing on the Rust SMTP path |
| SPF | DNS-based records for both SES shared sending and dedicated-IP SMTP |
| DMARC | Policy + RUA/RUF report ingestion |
| ARC | Signing for forwarded messages |
| BIMI | VMC certificate caching |
| MTA-STS | Strict transport enforcement |
| TLS-RPT | Failure report ingestion |

### IP Pool Strategy
- **Shared Pool**: Growth tier tenants, automatic warm-up
- **Dedicated IPs**: Scale tier tenants, isolated reputation
- **Warm-Up**: Geometric progression (50 → 100 → 200 → ...)

## Consequences

### Positive
- Complete control over sending infrastructure
- No per-email costs
- Full authentication support
- Flexible IP pooling

### Negative
- Requires IP reputation management
- Complex warm-up process
- Need monitoring for deliverability

### Risks Mitigated
- IP blacklisting: Real-time RBL checks before send
- Reputation damage: Circuit breaker (3% error threshold)
- Authentication failures: Continuous DNS health monitoring

## Related ADRs
- ADR 0001: Database Choice (queue storage)
- ADR 0004: AI Local Inference (send-time optimization)
