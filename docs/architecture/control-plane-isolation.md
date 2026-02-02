# Control Plane Architecture

## Overview

ApexMail maintains strict separation between **customer-facing services** and **internal control plane services**. This document describes the architecture and ensures no accidental data or process mixing.

**CRITICAL SECURITY:** Customers CANNOT access the Control Plane even with direct links.

## Security Layers

### Layer 1: Network Isolation
```
┌─────────────────────────────────────────────────────────────────┐
│                     PUBLIC INTERNET                             │
│                           │                                     │
│           ┌───────────────┼───────────────┐                    │
│           ▼               │               │                    │
│   ┌───────────────┐       │       ┌───────┴───────┐           │
│   │ Customer Web  │       │       │   BLOCKED!    │           │
│   │  (port 3000)  │       │       │               │           │
│   └───────────────┘       │       └───────────────┘           │
│                           │                                    │
│                    ═══════╪════════                           │
│                    VPN / IP WHITELIST                         │
│                    ═══════╪════════                           │
│                           │                                    │
│           ┌───────────────▼───────────────┐                   │
│           │      Control Plane UI         │                   │
│           │        (port 3020)            │                   │
│           │   + Session Auth              │                   │
│           │   + MFA Required              │                   │
│           └───────────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

### Layer 2: Authentication Separation

| Aspect | Customer Auth | Control Plane Auth |
|--------|---------------|-------------------|
| Cookie Name | `session` | `cp_session` |
| Token Type | `{ tid: "tenant_id", ... }` | `{ type: "control_plane", ... }` |
| API Key Header | `x-api-key` | `x-control-plane-key` |
| MFA | Optional | **Required** |
| Session Duration | 24 hours | 8 hours |

### Layer 3: API Key Blocking

Customer API keys are **explicitly blocked** at the Control Plane:

```typescript
// Sales Autopilot middleware
app.use('*', blockCustomerAuth()); // Blocks x-api-key headers
app.use('/api/v1/*', controlPlaneAuth()); // Requires cp auth
```

### Layer 4: IP Whitelisting (Production)

```bash
# Environment variable
CONTROL_PLANE_IP_WHITELIST=10.0.0.0/8,192.168.1.100
```

## Process Isolation Map

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CUSTOMER FACING (Tenant Isolated)                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│   │   Customer Web   │────▶│   Customer API   │────▶│     Worker       │   │
│   │   (Next.js)      │     │   (Hono)         │     │   (Processing)   │   │
│   │   Port: 3000     │     │   Port: 3001     │     │                  │   │
│   └──────────────────┘     └──────────────────┘     └──────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│                            ┌──────────────────┐                            │
│                            │  Tenant Database │                            │
│                            │  (Per-tenant)    │                            │
│                            └──────────────────┘                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

                    ═══════════════════════════════════════
                         STRICT PROCESS BOUNDARY
                    ═══════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│                     CONTROL PLANE (Owner/Internal Only)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│   │ Control Plane UI │────▶│ Sales Autopilot  │────▶│   Compliance     │   │
│   │   (Next.js)      │     │   (Hono)         │     │   (Hono)         │   │
│   │   Port: 3020     │     │   Port: 3010     │     │   Port: 3011     │   │
│   └──────────────────┘     └──────────────────┘     └──────────────────┘   │
│                                     │                                       │
│                                     ▼                                       │
│                            ┌──────────────────┐                            │
│                            │ Control Database │                            │
│                            │ (Owner data)     │                            │
│                            └──────────────────┘                            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Port Allocation

| Service | Port | Purpose | Access Level |
|---------|------|---------|--------------|
| Customer Console | 3000 | Customer-facing web UI | Tenant Auth |
| Customer API | 3001 | Tenant email/webhook API | API Keys |
| Sales Autopilot | 3010 | CRM, lead gen, drip campaigns | Internal Only |
| Compliance | 3011 | GDPR, risk, audit | Internal Only |
| Control Plane UI | 3020 | Owner admin dashboard | Owner Auth |
| MTA | 2525 | SMTP relay | Internal |
| Tracking | 3002 | Pixel/click tracking | Public |
| Analytics | 3003 | Event processing | Internal |

## Key Principles

### 1. No Shared Authentication

- **Customer API** uses tenant API keys and JWT tokens
- **Control Plane** uses separate owner credentials
- API keys from customers CANNOT access control plane endpoints

### 2. No Shared Databases Tables

```sql
-- Customer tables (in tenant schema)
tenants.messages
tenants.domains
tenants.templates
tenants.webhooks

-- Control plane tables (in internal schema)
internal.autopilot_leads
internal.autopilot_campaigns
internal.risk_profiles
internal.audit_logs
```

### 3. No Route Leakage

The Customer Console sidebar explicitly EXCLUDES control plane routes:

```typescript
// apps/web/src/components/layout/sidebar.tsx
// NOTE: CRM, Lead Scoring, Sales features are NOT in customer console
// They exist ONLY in apps/control-plane
```

### 4. Network Isolation (Production)

```yaml
# docker-compose.yml example
services:
  customer-api:
    networks:
      - customer-network
    
  sales-autopilot:
    networks:
      - control-plane-network  # Separate network!
    
  control-plane-ui:
    networks:
      - control-plane-network
```

## Control Plane Features

### Sales Autopilot (`apps/sales-autopilot`)

| Feature | Endpoint | Purpose |
|---------|----------|---------|
| Lead Discovery | `/api/v1/discovery/*` | Scrape SaaS directories |
| Enrichment | `/api/v1/enrichment/*` | Company data lookup |
| CRM | `/api/v1/leads/*` | Pipeline management |
| Campaigns | `/api/v1/campaigns/*` | Drip sequence automation |
| Inbox Sentinel | `/api/v1/inbox/*` | Reply classification |
| Calendar | `/api/v1/calendar/*` | Demo scheduling |
| Promos | `/api/v1/promos/*` | Ad injection config |

### Compliance (`apps/compliance`)

| Feature | Endpoint | Purpose |
|---------|----------|---------|
| Risk Scoring | `/api/risk/*` | Tenant risk assessment |
| Content Scan | `/api/content/*` | Spam/phishing detection |
| Audit Logs | `/api/audit/*` | Tamper-proof logging |
| GDPR | `/api/gdpr/*` | DSAR automation |
| Secrets | `/api/secrets/*` | Key rotation |

## Verification

To verify isolation is working:

```bash
# Customer API should NOT have control plane routes
curl http://localhost:3001/api/v1/leads  # Should 404

# Control Plane should NOT have customer routes  
curl http://localhost:3010/api/v1/messages  # Should 404

# Each service has its own health endpoint
curl http://localhost:3001/health  # Customer API
curl http://localhost:3010/health  # Sales Autopilot
curl http://localhost:3011/health  # Compliance
```

## Deployment Recommendations

### Development
- Run all services locally with different ports
- Use separate `.env` files for customer vs control plane

### Production
- Deploy customer services in one Kubernetes namespace
- Deploy control plane services in separate namespace
- Use network policies to block cross-namespace traffic
- Control plane UI should be behind VPN or IP whitelist

## Related ADRs

- [ADR 0003: Sales Autopilot](../adr/0003-sales-autopilot.md)
