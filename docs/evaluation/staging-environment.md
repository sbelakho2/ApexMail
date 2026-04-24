# Staging Environment Specification

> Internal document — Bel Consulting OÜ
>
> **Implementation Note (2026-02):** Staging deploys the Rust tracking service. The api/worker Docker images referenced below are historical; current deployment uses only the `tracking` image.

## Overview

The staging environment is a near-identical mirror of production, used for pre-release validation, integration testing, and stakeholder demos. All releases **must** pass through staging before production deployment.

---

## Infrastructure

| Component | Staging | Production |
|-----------|---------|------------|
| **Server** | Hetzner Cloud ARM (sized to mirror production) | Same |
| **Region** | Falkenstein (fsn1) | Falkenstein (fsn1) |
| **OS** | Ubuntu 24.04 ARM64 | Same |
| **PostgreSQL** | 16.x — dedicated instance | Same version |
| **Redis** | 7.x — dedicated instance | Same version |
| **Docker** | Same Compose stack (`docker-compose.staging.yml`) | `docker-compose.prod.yml` |
| **Zone.ee** | Separate zone (`staging.apexmail.dev`) | `apexmail.dev` |

### Key Differences from Production

- Staging runs on a **separate Hetzner Cloud ARM server — never co-located with production workloads.
- DNS is under `*.staging.apexmail.dev` via a dedicated Zone.ee zone.
- Outbound email is routed through a **sink MTA** — no real deliveries leave staging.
- Stripe is configured in **test mode** — use Stripe test card numbers only.
- Webhook endpoints point to internal mock receivers.

---

## Access Control

| Role | Access Level |
|------|-------------|
| Engineering | Full SSH + admin panel access |
| Product / QA | Admin panel access only (via SSO) |
| External stakeholders | Demo-only access — time-limited accounts |

SSH access is managed via Hetzner SSH key project membership. Keys are rotated quarterly.

```bash
# SSH into staging
ssh deploy@staging.apexmail.dev
```

---

## Deployment

Staging deploys are triggered automatically on merge to `main`, or manually via CI.

### Automatic (CI)

Every merge to `main` triggers the staging pipeline:

1. Build Docker image (`tracking`).
2. Push to container registry with `staging-<sha>` tag.
3. SSH into staging server, pull images, run migrations, restart services.
4. Run integration test suite against staging.
5. Post result to the team channel.

### Manual

```bash
# From the project root
./tools/deploy.sh staging          # deploys current HEAD
./tools/deploy.sh staging v1.2.3   # deploys specific tag
```

### Rollback

```bash
./tools/deploy.sh staging --rollback   # reverts to previous image set
```

---

## Seed Data

Staging is seeded with realistic but synthetic data for testing all plan tiers.

### Test Tenants

| Tenant | Plan | Contacts | Campaigns |
|--------|------|----------|-----------|
| `acme-free` | Free | 500 | 5 |
| `acme-starter` | Starter ($25) | 5 000 | 20 |
| `acme-pro` | Pro ($65) | 25 000 | 50 |
| `acme-growth` | Growth ($150) | 100 000 | 100 |
| `acme-scale` | Scale ($350) | 500 000 | 200 |
| `acme-enterprise` | Enterprise ($800) | 1 000 000 | 500 |
| `acme-payg` | PAYG | 10 000 | 30 |

### Seed Script

There is no dedicated repo-local seed helper anymore. Staging data should be provisioned through database snapshots, migrations, and the Rust-owned admin flows.

---

## Data Refresh from Production

A weekly anonymised snapshot of production data can be loaded into staging for realistic testing.

### Process

1. **Export** — `pg_dump` on production with `--no-owner`.
2. **Anonymise** — `tools/anonymise-dump.sh` replaces PII:
   - Email addresses → `user-<hash>@staging.apexmail.dev`
   - Names → randomised from a dictionary
   - Stripe customer IDs → `cus_test_<random>`
   - API keys → regenerated
3. **Import** — Restore into staging PostgreSQL.
4. **Verify** — Run `tools/verify-anonymisation.sh` to confirm no PII leakage.

```bash
# Full refresh (run on staging server)
./tools/refresh-staging.sh --from-production
```

> ⚠️ **GDPR note:** The anonymisation step is mandatory. Never load raw production data into staging.

---

## Stripe Test Mode

Staging uses Stripe **test mode** API keys (`sk_test_...`, `pk_test_...`).

- Test card: `4242 4242 4242 4242`, any future expiry, any CVC.
- Webhooks: Stripe test webhooks are forwarded to `staging.apexmail.dev/api/webhooks/stripe`.
- Billing cycles, invoicing, and subscription changes all function identically to production.

---

## Monitoring

Staging has its own Prometheus + Grafana stack at `grafana.staging.apexmail.dev`.

Alerts are configured but routed to `#staging-alerts` (informational only — not paged).

---

## Maintenance

| Task | Frequency |
|------|-----------|
| Data refresh from production | Weekly (Sunday 03:00 UTC) |
| Seed data regeneration | On demand / after schema changes |
| SSL certificate renewal | Automated via Let's Encrypt (certbot) |
| Server OS updates | Monthly, coordinated with production schedule |
| Docker image prune | Weekly cron (`docker system prune -af --filter "until=168h"`) |

---

*Last updated: 2026-02-09*
