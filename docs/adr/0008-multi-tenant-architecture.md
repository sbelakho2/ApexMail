# ADR 0008: Multi-Tenant Architecture

## Status

Accepted

> **Implementation Note (2026-02):** Multi-tenant isolation is implemented in the Rust tracking service. The TypeScript middleware examples below are historical; actual implementation is in Rust using Axum state extractors.

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

```typescript
// Middleware extracts tenant from API key
export const tenantMiddleware = async (c: Context, next: Next) => {
  const apiKey = c.req.header('Authorization')?.replace('Bearer ', '');
  const tenant = await resolveTenant(apiKey);
  
  c.set('tenant', tenant);
  
  // Set PostgreSQL session variable for RLS
  await c.get('db').execute(
    sql`SELECT set_config('app.tenant_id', ${tenant.id}, true)`
  );
  
  await next();
};
```

### Resource Quotas

Per-tenant limits enforced at multiple layers:

```typescript
interface TenantQuotas {
  // API rate limits
  requestsPerMinute: number;
  requestsPerDay: number;
  
  // Email limits
  emailsPerMonth: number;
  emailsPerSecond: number;
  maxRecipients: number;
  maxAttachmentSize: number;
  
  // Storage limits
  maxStorageBytes: number;
  maxWebhooks: number;
  maxDomains: number;
  maxApiKeys: number;
}

// Enforce quota before processing
const enforceQuota = async (tenantId: string, resource: string) => {
  const usage = await getUsage(tenantId, resource);
  const quota = await getQuota(tenantId, resource);
  
  if (usage >= quota) {
    throw new QuotaExceededError(resource, usage, quota);
  }
};
```

### Regional Data Residency

Support for region-specific deployments:

```typescript
interface TenantConfig {
  id: string;
  region: 'us-east' | 'eu-west' | 'ap-southeast';
  dataResidency: {
    emails: string;     // Region where emails are stored
    logs: string;       // Region where logs are stored
    analytics: string;  // Region where analytics are processed
  };
}

// Route requests to appropriate region
const routeToRegion = (tenant: TenantConfig) => {
  return endpoints[tenant.region];
};
```

### Tenant Provisioning

Automated tenant setup:

```typescript
async function provisionTenant(params: CreateTenantParams) {
  // 1. Create tenant record
  const tenant = await db.tenants.create({
    id: generateTenantId(),
    name: params.name,
    region: params.region,
  });

  // 2. Create database schema
  await db.execute(sql`CREATE SCHEMA ${sql.identifier(tenant.schemaName)}`);
  
  // 3. Run migrations
  await runMigrations(tenant.schemaName);
  
  // 4. Provision MTA resources
  await mta.provisionForTenant(tenant.id);
  
  // 5. Create default API key
  const apiKey = await createApiKey(tenant.id);
  
  // 6. Initialize billing
  await billing.createSubscription(tenant.id, params.plan);
  
  return { tenant, apiKey };
}
```

### Tenant-Aware Metrics

Metrics include tenant dimension:

```typescript
// Prometheus metrics with tenant label
const emailsSent = new Counter({
  name: 'apexmail_emails_sent_total',
  help: 'Total emails sent',
  labelNames: ['tenant_id', 'status', 'region'],
});

// Increment with tenant context
emailsSent.inc({
  tenant_id: tenant.id,
  status: 'delivered',
  region: tenant.region,
});
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
