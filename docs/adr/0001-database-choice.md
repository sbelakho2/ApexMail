# ADR 0001: Database Choice

## Status
Accepted

> **Implementation Note (2026-02):** PostgreSQL is the primary OLTP database. ClickHouse is deployed as the OLAP engine for enterprise-scale analytics (`services/mail-server/crates/analytics/src/clickhouse_engine.rs`). ClickHouse runs as a separate Docker container with MergeTree tables partitioned by month, supporting billions of events with sub-second queries. Connection pooling for PostgreSQL is handled by the Rust tracking service using `deadpool-postgres`.

## Date
2024-01-15

## Context
ApexMail requires a database solution that can:
- Handle high-volume transactional email metadata (millions of events/day)
- Support complex queries for analytics and reporting
- Provide ACID guarantees for critical operations
- Enable partitioning for data retention policies
- Work without paid SaaS dependencies

## Decision
We chose **PostgreSQL 15+** as the primary database with the following architecture:

### Primary Database (PostgreSQL)
- OLTP workloads: messages, recipients, campaigns, users
- System-versioned temporal tables for audit history
- Connection pooling via PgBouncer (transaction mode)
- Native partitioning for event logs

### Analytics Layer (ClickHouse)
- OLAP workloads: aggregations, reporting, dashboards
- MergeTree tables with monthly partitioning
- Materialized views for automatic rollups
- 730-day TTL with columnar compression
- Sub-second queries on billions of rows

### Connection Configuration
```
Pool Sizes:
- API: 20 connections
- Worker: 30 connections  
- MTA: 10 connections
Total: 100 max connections to PostgreSQL
```

## Consequences

### Positive
- Zero licensing costs
- Mature ecosystem with excellent tooling
- Native JSON support for flexible schemas
- Excellent partitioning support
- Strong ACID guarantees

### Negative
- Requires careful connection pool management
- Partitioning requires upfront planning
- Need separate OLAP solution for heavy analytics

### Risks Mitigated
- Connection exhaustion: PgBouncer with strict limits
- Schema drift: Startup fingerprint validation
- Data loss: WAL archiving + continuous PITR

## Related ADRs
- ADR 0002: MTA Stack (queue storage)
- ADR 0005: SLO Management (metrics storage)
