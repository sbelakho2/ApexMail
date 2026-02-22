# ADR 0002: MTA Stack

## Status
Accepted

## Date
2024-01-15

## Context
ApexMail requires a Mail Transfer Agent (MTA) that:
- Handles high-volume outbound email (100k+ emails/hour)
- Supports advanced authentication (DKIM, SPF, DMARC, ARC, BIMI)
- Enables per-domain rate limiting and IP pooling
- Provides enterprise-grade reliability and full delivery control

## Decision
We chose **Postfix** as the MTA with the following configuration:

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
│                   Postfix Cluster                           │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  MTA Node 1 │  │  MTA Node 2 │  │  MTA Node 3 │        │
│  │  Shared IP  │  │  Shared IP  │  │ Dedicated IP│        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

### Postfix Configuration
- TLS 1.2+ enforcement (no SSLv2/v3, TLSv1.0/1.1)
- Per-IP queue directories for isolation
- Opportunistic DANE support
- IPv4/IPv6 dual-stack sending

### Authentication Stack
| Protocol | Implementation |
|----------|----------------|
| DKIM | OpenDKIM with weekly rotation (selector: `apexmail{YYYYWW}`) |
| SPF | DNS-based, include mechanism |
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
