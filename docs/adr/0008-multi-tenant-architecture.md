# ADR 0008: Multi-Tenant Architecture

## Status

Accepted

> **Implementation Note (2026-02):** Multi-tenant isolation is implemented in the Rust tracking service using Axum state extractors. Historical browser-runtime snippets were removed to keep this ADR aligned with the live repository.

## Date

2024-01-18

## Context

ApexMail serves multiple organizations with varying requirements:

1. **Data Isolation**: Each tenant's email data must be strictly isolated
2. **Resource Fairness**: No tenant should impact others' performance
3. **Scalability**: System must scale per-tenant without affecting others
4. **Compliance**: Some tenants require regional data residency
5. **Billing**: Usage tracking must be tenant-specific

## Decision

We implement a **Silo Model** multi-tenant architecture:

### Isolation Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                     ApexMail Platform                        │
├─────────────────────────────────────────────────────────────┤
│  Control Plane (Shared)                                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   Auth      │ │   Billing   │ │  Routing    │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
├─────────────────────────────────────────────────────────────┤
│  Data Plane (Per-Tenant Isolation)                          │
│  ┌───────────────────────┐  ┌───────────────────────┐       │
│  │    Tenant A           │  │    Tenant B           │       │
│  │  ┌─────────────────┐  │  │  ┌─────────────────┐  │       │
│  │  │   PostgreSQL    │  │  │  │   PostgreSQL    │  │       │
│  │  │   (Schema A)    │  │  │  │   (Schema B)    │  │       │
│  │  └─────────────────┘  │  │  └─────────────────┘  │       │
│  │  ┌─────────────────┐  │  │  ┌─────────────────┐  │       │
│  │  │   Redis Queue   │  │  │  │   Redis Queue   │  │       │
│  │  └─────────────────┘  │  │  └─────────────────┘  │       │
│  │  ┌─────────────────┐  │  │  ┌─────────────────┐  │       │
│  │  │   MTA Instance  │  │  │  │   MTA Instance  │  │       │
│  │  └─────────────────┘  │  │  └─────────────────┘  │       │
│  └───────────────────────┘  └───────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

### Database Schema Isolation

Each tenant gets a dedicated PostgreSQL schema:

```sql
-- Create tenant schema
CREATE SCHEMA tenant_abc123;

-- Tenant-specific tables
CREATE TABLE tenant_abc123.emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_address TEXT NOT NULL,
    to_addresses TEXT[] NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Row-level security for additional protection
ALTER TABLE tenant_abc123.emails ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant_abc123.emails
    USING (current_setting('app.tenant_id') = 'abc123');
```

### Tenant Context Propagation

Every request includes tenant context:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Resource Quotas

Per-tenant limits enforced at multiple layers:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Regional Data Residency

Support for region-specific deployments:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Tenant Provisioning

Automated tenant setup:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

### Tenant-Aware Metrics

Metrics include tenant dimension:

```text
Historical implementation example removed. Refer to the current Rust services and runtime notes in this document for the live implementation.
```

## Consequences

### Positive

- **Strong Isolation**: Data breaches contained to single tenant
- **Noisy Neighbor Prevention**: Resource limits per tenant
- **Compliance**: Regional data residency supported
- **Scalability**: Scale each tenant independently
- **Debugging**: Clear tenant boundaries aid troubleshooting

### Negative

- **Operational Complexity**: More resources to manage
- **Cost**: Higher infrastructure costs than shared model
- **Provisioning Time**: New tenant setup takes longer

### Mitigations

- Automate tenant provisioning with Terraform/Pulumi
- Use Kubernetes namespaces for resource isolation
- Implement tenant pooling for small accounts
- Cache tenant configuration for fast lookups

## References

- [Multi-tenant SaaS Patterns (AWS)](https://aws.amazon.com/partners/programs/saas-factory/)
- [PostgreSQL Row Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Kubernetes Multi-tenancy](https://kubernetes.io/docs/concepts/security/multi-tenancy/)
