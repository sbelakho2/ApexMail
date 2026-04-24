# ADR 0009: Observability Architecture

## Status

Accepted

**Implementation Note (2026-02):** Implementation has been migrated to Rust using `metrics_exporter_prometheus` and `tracing` crates. Historical browser-runtime snippets were removed; see [monitoring.md](../operations/monitoring.md) for current metrics documentation.

## Date

2024-01-19

## Context

Email infrastructure requires comprehensive observability:

1. **Delivery Tracking**: Every email must be traceable end-to-end
2. **Performance Monitoring**: Latency and throughput are critical SLIs
3. **Anomaly Detection**: Unusual patterns may indicate issues or abuse
4. **Debugging**: Support teams need visibility into failures
5. **Compliance**: Audit logs required for security compliance

## Decision

We implement a **Three Pillars** observability stack:

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     Data Collection Layer                         │
├──────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │   API       │ │   Worker    │ │   MTA       │ │  Tracking   │ │
│  │   Service   │ │   Service   │ │   Service   │ │   Service   │ │
│  └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘ │
│         │               │               │               │         │
│         ▼               ▼               ▼               ▼         │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │           OpenTelemetry Collector (Agent Mode)               │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Processing Layer                              │
├──────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────┐  │
│  │            OpenTelemetry Collector (Gateway)               │  │
│  └────────────────────────────────────────────────────────────┘  │
│         │                    │                    │               │
│         ▼                    ▼                    ▼               │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐       │
│  │   Traces    │      │   Metrics   │      │    Logs     │       │
│  │   (Tempo)   │      │ (Prometheus)│      │   (Loki)    │       │
│  └─────────────┘      └─────────────┘      └─────────────┘       │
└──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Visualization Layer                           │
├──────────────────────────────────────────────────────────────────┤
│  ┌────────────────────────────────────────────────────────────┐  │
│  │                     Grafana                                 │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │  │
│  │  │Dashboard │ │  Alerts  │ │ Explorer │ │  OnCall  │       │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Pillar 1: Distributed Tracing

Every email journey is traced:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

Trace propagation through async workers:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Pillar 2: Metrics

Key performance indicators:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

Prometheus scrape configuration:

```yaml
# deploy/prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'apexmail-tracking'
    static_configs:
      - targets: ['tracking:9092']
    metrics_path: /metrics
    
  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']
        
  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

### Pillar 3: Structured Logging

JSON-formatted logs with correlation:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

Log levels and when to use them:

| Level | Use Case |
|-------|----------|
| `error` | Operation failed, requires attention |
| `warn` | Unexpected but handled condition |
| `info` | Business events (email sent, webhook triggered) |
| `debug` | Detailed operational info (request/response) |
| `trace` | Granular debugging (loop iterations, state changes) |

### Dashboards

Pre-built Grafana dashboards:

1. **Service Health**
   - Request rate and error rate
   - Latency percentiles (p50, p95, p99)
   - Active connections
   - Resource utilization

2. **Email Delivery**
   - Emails sent/delivered/failed over time
   - Delivery latency distribution
   - Bounce rate by domain
   - Queue depth and processing rate

3. **Tenant Overview**
   - Per-tenant email volume
   - Quota utilization
   - Error rates by tenant
   - API usage patterns

4. **MTA Health**
   - Postfix queue size
   - Connection states
   - DNS lookup latency
   - TLS handshake success rate

### Alerting Rules

Critical alerts:

```yaml
# Prometheus alerting rules
groups:
  - name: apexmail
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) /
          sum(rate(http_requests_total[5m])) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: High error rate detected
          
      - alert: QueueBacklog
        expr: email_queue_depth > 10000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: Email queue backlog growing
          
      - alert: DeliveryLatencyHigh
        expr: histogram_quantile(0.95, rate(email_delivery_latency_bucket[5m])) > 30000
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: Email delivery latency exceeds 30s at p95
```

## Consequences

### Positive

- **Full Visibility**: Every request traceable end-to-end
- **Fast Debugging**: Correlated logs and traces speed up investigation
- **Proactive Alerts**: Issues detected before user impact
- **Capacity Planning**: Metrics inform scaling decisions

### Negative

- **Data Volume**: High cardinality data requires storage management
- **Performance Impact**: Instrumentation adds latency (~1-2ms)
- **Complexity**: Three systems to maintain and query

### Mitigations

- Use sampling for high-volume traces (keep 10% of normal traffic)
- Configure retention policies (7 days traces, 90 days metrics, 30 days logs)
- Use exemplars to link metrics to traces
- Train team on unified query patterns

## References

- [OpenTelemetry Documentation](https://opentelemetry.io/docs/)
- [Grafana Best Practices](https://grafana.com/docs/grafana/latest/best-practices/)
- [Google SRE Book - Monitoring](https://sre.google/sre-book/monitoring-distributed-systems/)
