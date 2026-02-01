# ADR 0005: SLO Management

## Status
Accepted

## Date
2024-02-01

## Context
ApexMail requires a robust observability stack for:
- Service Level Objectives (SLOs) tracking
- Error budget management
- Alerting with escalation
- Incident management
- Status page for customers

## Decision
We built a comprehensive **Operations & SLOs** module:

### Architecture
```
apps/ops/
├── src/
│   ├── slo/            # SLO/SLI management
│   ├── metrics/        # Prometheus-compatible metrics
│   ├── alerts/         # Alert management
│   ├── incidents/      # Incident workflows
│   ├── status/         # Public status page
│   ├── trust/          # Trust center
│   ├── health/         # Health checks
│   └── tracing/        # Distributed tracing
```

### SLO Framework

#### Default SLOs
| SLO | Target | Window | Burn Rate Alert |
|-----|--------|--------|-----------------|
| API Availability | 99.9% | 30 days | >10x = page |
| API Latency (p95) | <200ms | 30 days | >5x = warn |
| Email Delivery | 99.5% | 30 days | >10x = page |
| Email Processing | <5min | 30 days | >3x = warn |
| Web Availability | 99.9% | 30 days | >10x = page |

#### Error Budget Calculation
```typescript
interface SLOStatus {
  sloId: string;
  currentValue: number;      // e.g., 99.85%
  target: number;            // e.g., 99.9%
  errorBudgetTotal: number;  // e.g., 43.2 min/month
  errorBudgetRemaining: number;
  errorBudgetConsumed: number;
  burnRate: number;          // Current rate of budget consumption
  status: 'healthy' | 'at_risk' | 'breached';
}
```

### Metrics Collection
- Prometheus-compatible `/metrics` endpoint
- Default metrics: HTTP, email, queue, database, cache
- Custom metrics via simple API
- Histograms with configurable buckets

### Alert Management
- Multi-channel notifications (Slack, Email, PagerDuty, Webhook)
- Escalation policies with time-based progression
- Alert deduplication (5-minute window)
- Silence/acknowledge workflows

### Incident Management
- Structured incident lifecycle: investigating → identified → monitoring → resolved
- Role assignment: commander, communication, technical, scribe
- Timeline tracking with all events
- Post-mortem automation for critical/high incidents

### Health Checks
- HTTP, TCP, database, Redis, storage checks
- Configurable intervals and timeouts
- Unhealthy threshold: 3 consecutive failures
- Automatic status page updates

### Distributed Tracing
- OpenTelemetry integration
- Automatic context propagation
- Trace sampling (configurable rate)
- Local span collection for debugging

## Consequences

### Positive
- Proactive issue detection via burn rates
- Clear error budget visibility
- Automated incident workflows
- Customer-facing status transparency

### Negative
- Additional infrastructure to maintain
- Metric cardinality management needed
- Alert fatigue if not tuned properly

### Monitoring Stack
- **Metrics**: Prometheus (self-hosted)
- **Alerting**: Alertmanager → Slack/Email
- **Tracing**: OpenTelemetry → Jaeger (optional)
- **Logging**: Pino → stdout (collected by infrastructure)

## Related ADRs
- ADR 0001: Database Choice (metrics storage)
- ADR 0002: MTA Stack (email SLOs)
- ADR 0004: AI Local Inference (AI service SLOs)
