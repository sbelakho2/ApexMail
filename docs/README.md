# ApexMail Documentation

Enterprise-grade transactional email platform.

> This file is the canonical documentation index. The former `SUMMARY.md`
> was merged into this page and removed (nothing referenced it).

## Documentation Structure

```text
docs/
├── adr/                    # Architecture Decision Records (0001–0015 + TEMPLATE)
├── api/                    # API Documentation
│   ├── endpoints/          # Per-resource endpoint reference (messages, webhooks, …)
│   ├── authentication.md, changelog.md, errors.md, rate-limits.md
│   ├── sdk-reference.md, sdk-support-levels.md, streaming.md, system-health.md
│   ├── versioning.md, webhooks.md, inbox-placement.md, openapi.yaml
├── architecture/           # System Architecture (overview, data-flow, queue-system, …)
├── audit/                  # Repository audits (full-repo-audit-2026-09-05.md)
├── compliance/             # Policies & compliance ops (acceptable-use-policy, data-retention,
│                           #   gdpr-compliance, incident-response, baa-template, dsar-rate-limiting, …)
├── deployment/             # Deployment Guides (quickstart, configuration, migrations, PRODUCTION_SETUP,
│                           #   HETZNER_SIMULATION_CHECKLIST, ses-setup, cdn-configuration, …)
├── development/            # Development Guides (contributing, style-system, navigation-taxonomy, …)
├── domains/                # Sending-domain guides (spf, dkim, dmarc, return-path, tracking-domain,
│                           #   rotation, provider-troubleshooting)
├── engineering/            # Engineering standards (accessibility-compliance, analytics-taxonomy,
│                           #   performance-budgets, automated-qa, third-party-scripts)
├── enterprise/             # Enterprise Features (README, sso, sub-accounts, whitelabel,
│                           #   template-approval, log-streaming, compliance, private-cloud, support, qbr)
├── evaluation/             # Performance evaluation (load-testing.md, baselines/)
├── getting-started/        # First-send guides (overview, account-creation, domain-verification,
│                           #   first-rest-email, first-smtp-email, first-webhook, production-checklist)
├── glossary/               # email-lifecycle-terms.md, infrastructure-terms.md
├── marketing/              # Marketing-site docs (README, content-standards, billing-definitions,
│                           #   comparison-methodology, comparison-evidence.json, pricing disclosure, …)
├── migration/              # Migration baselines (api-contract-manifest.baseline.json)
├── operations/             # Operations Guides (disaster-recovery, backup-verification, monitoring,
│   │                       #   on-call, slo-management, secret-rotation, warmup-schedule, …)
│   └── runbooks/           # incident-response, db-recovery, redis-failure, mta-degradation,
│                           #   network-partition, crypto-incidents, traffic-spike-ddos, …
├── security/               # Security Documentation (Security_Systems, rbac-implementation,
│                           #   framework-status, kiwicaptcha-login, email-authentication, …)
├── sending/                # Sending guides (rest-api, smtp, batch, scheduling, cancellation,
│                           #   idempotency, attachments, tags, test-mode, …)
├── tool-contracts/         # Internal per-tool engineering contracts (postgres, redis, clickhouse,
│                           #   hetzner, ses, stripe, prometheus, zone-ee)
├── user-guide/             # End-user docs (getting-started, contacts, delivery-options, glossary,
│                           #   inbox-placement-testing, troubleshooting)
├── pricing.md, pricing-authority.md, sla.md, quickstart.md
├── ddos_analysis_report.md, api-route-audit-report.md, recovered-files-analysis.md
└── README.md               # This index
```

## Quick Links

### Getting Started

- [Quick Start Guide](quickstart.md)
- [Getting Started series](getting-started/overview.md)
- [API Reference](api/endpoints/index.md)
- [OpenAPI Specification](api/openapi.yaml)
- [API Changelog & Deprecation Policy](api/changelog.md)
- [Architecture Overview](architecture/overview.md)

### Sending Email

- [REST API](sending/rest-api.md) · [SMTP Relay](sending/smtp.md) · [Batch](sending/batch.md)
- [Scheduling](sending/scheduling.md) · [Cancellation](sending/cancellation.md) · [Idempotency](sending/idempotency.md)
- [Domains: SPF / DKIM / DMARC](domains/spf.md)

### Enterprise Features

- [Enterprise Overview](enterprise/README.md)
- [Single Sign-On (SSO)](enterprise/sso.md) · [Sub-Accounts](enterprise/sub-accounts.md) · [White-Label](enterprise/whitelabel.md)
- [Template Approval](enterprise/template-approval.md) · [Log Streaming](enterprise/log-streaming.md)
- [Compliance & Data Governance](enterprise/compliance.md) (GDPR workflows production; HIPAA/SOC 2 planned — see [framework status](security/framework-status.md))
- [Private Cloud](enterprise/private-cloud.md) · [Support tiers](enterprise/support.md) · [QBR](enterprise/qbr.md)

### Billing & Plans

- [Pricing Reference](pricing.md) · [Pricing Authority](pricing-authority.md)
- [Billing Lifecycle](architecture/billing-lifecycle.md) · [Billing API](api/endpoints/billing.md)
- [Billing definitions](marketing/billing-definitions.md)

### Webhooks & Integrations

- [Webhook Delivery Guide](api/webhooks.md)
- [Authentication Reference](api/authentication.md)
- [Rate Limits](api/rate-limits.md)

### Security & Compliance

- [Security Systems Reference](security/Security_Systems.md)
- [Framework Status (SOC 2 / HIPAA / GDPR)](security/framework-status.md)
- [Login KiwiCaptcha Protection](security/kiwicaptcha-login.md)
- [RBAC Implementation](security/rbac-implementation.md)
- [Acceptable Use Policy](compliance/acceptable-use-policy.md) · [Data Retention](compliance/data-retention.md)

### Operations

- [Disaster Recovery](operations/disaster-recovery.md) · [Backup Verification](operations/backup-verification.md) · [DR Testing](operations/disaster-recovery-testing.md)
- [Monitoring](operations/monitoring.md) · [On-Call](operations/on-call.md) · [SLO Management](operations/slo-management.md)
- [Runbooks](operations/runbooks/README.md)

### Development

- [Contributing Guide](development/contributing.md) (root: [CONTRIBUTING.md](../CONTRIBUTING.md))
- [Style System](development/style-system.md) · [UX QA Checklist](development/ux-qa-checklist.md)
- [ADR index](adr/TEMPLATE.md) (records 0001–0015 alongside)
- [Load Testing & Performance Baselines](evaluation/load-testing.md)

## Canonical Sources (avoid restating these elsewhere)

| Topic | Canonical document |
|---|---|
| Plan prices, limits, feature gates | [pricing.md](pricing.md) (+ `pricing-authority.md`) |
| API throughput tiers | [api/rate-limits.md](api/rate-limits.md) |
| Support tiers | [enterprise/support.md](enterprise/support.md) |
| Webhook event catalog | [api/webhooks.md](api/webhooks.md) |
| Deployment | [deploy/DEPLOYMENT.md](../deploy/DEPLOYMENT.md) (repo root) |
| Infrastructure architecture | [ARCHITECTURE.md](../ARCHITECTURE.md) (repo root) |
| Full-repo audit (current verified state) | [audit/full-repo-audit-2026-09-05.md](audit/full-repo-audit-2026-09-05.md) |

## Version

- Documentation Version: 1.1.0
- Last Updated: 2026-09-05

---

## Company Information

ApexMail is a brand of **Bel Consulting OÜ**, Estonia.

- **Company**: Bel Consulting OÜ
- **Address**: Sakala 7-2, 10141 Tallinn, Estonia
- **Registry Code**: 16588745
- **VAT Number**: EE102951727
- **Email**: support@apexmail.ee
- **Website**: https://apexmail.ee
