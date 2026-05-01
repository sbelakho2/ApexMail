# ApexMail Documentation

Enterprise-grade transactional email platform.

## Documentation Structure

```text
docs/
├── adr/                    # Architecture Decision Records
│   ├── 0001-database-choice.md     ✅
│   ├── 0002-mta-stack.md           ✅
│   ├── 0006-testing-strategy.md    ✅
│   ├── 0007-sdk-design-philosophy.md ✅
│   ├── 0008-multi-tenant-architecture.md ✅
│   ├── 0009-observability-architecture.md ✅
│   ├── 0010-security-architecture.md ✅
│   └── 0011-dual-delivery-ses-primary.md ✅
├── api/                    # API Documentation
│   ├── authentication.md           ✅
│   ├── endpoints/
│   │   ├── analytics.md            ✅
│   │   ├── messages.md             ✅
│   │   ├── campaigns.md            ✅
│   │   ├── contacts.md             ✅
│   │   ├── domains.md              ✅
│   │   ├── events.md               ✅
│   │   └── templates.md            ✅
│   ├── errors.md                   ✅
│   ├── openapi.yaml                ✅
│   ├── changelog.md                ✅
│   ├── rate-limits.md              ✅
│   └── webhooks.md                 ✅
├── architecture/           # System Architecture
│   ├── ai-pipeline.md              ✅
│   ├── control-plane-data-contracts.md ✅
│   ├── delivery-transport.md       ✅
│   ├── hybrid-email-infrastructure.md ✅
│   ├── mta-configuration.md        ✅
│   ├── overview.md                 ✅
│   ├── data-flow.md                ✅
│   ├── sales-autopilot.md          ✅
│   ├── billing-lifecycle.md        ✅
│   └── queue-system.md             ✅
├── deployment/             # Deployment Guides
│   ├── HETZNER_SIMULATION_CHECKLIST.md ✅
│   ├── configuration.md            ✅
│   ├── helm.md                     ✅
│   ├── quickstart.md               ✅
│   └── ses-setup.md                ✅
├── development/            # Development Guides
│   ├── application-route-inventory.md ✅
│   ├── contributing.md             ✅
│   ├── interactive-state-matrix.md ✅
│   ├── jtbd-nav-mapping.md         ✅
│   ├── navigation-taxonomy.md      ✅
│   ├── premium-experience-spec.md  ✅
│   ├── premium-performance-budgets.md ✅
│   ├── setup-migration-checklists.md ✅
│   ├── style-system.md             ✅
│   └── ux-qa-checklist.md          ✅
├── enterprise/             # Enterprise Features
│   ├── README.md                   ✅
│   ├── sso.md                      ✅
│   ├── sub-accounts.md             ✅
│   ├── whitelabel.md               ✅
│   ├── template-approval.md        ✅
│   ├── log-streaming.md            ✅
│   ├── compliance.md               ✅
│   ├── private-cloud.md            ✅
│   ├── support.md                  ✅
│   └── qbr.md                      ✅
├── marketing/              # Marketing Website
│   └── README.md                   ✅
├── operations/             # Operations Guides
│   ├── disaster-recovery.md        ✅
│   ├── monitoring.md               ✅
│   ├── on-call.md                  ✅
│   ├── runbooks/
│   │   └── incident-response.md    ✅
│   ├── slo-management.md           ✅
│   └── (additional runbooks)       ✅
├── security/               # Security Documentation
│   ├── Security_Systems.md         ✅
│   ├── rbac-implementation.md      ✅
│   ├── compliance.md               ✅
│   ├── data-protection.md          ✅
│   ├── email-authentication.md     ✅
│   ├── advanced-analytics.md       ✅
│   └── mcaptcha-login.md           ✅
└── user-guide/            # User Documentation
  ├── contacts.md                 ✅
  ├── delivery-options.md         ✅
  ├── getting-started.md          ✅
  ├── glossary.md                 ✅
  ├── inbox-placement-testing.md  ✅
  └── troubleshooting.md          ✅
```

## Quick Links

### Getting Started

- [Quick Start Guide](deployment/quickstart.md)
- [API Reference](api/endpoints/messages.md)
- [OpenAPI Specification](api/openapi.yaml)
- [API Changelog & Deprecation Policy](api/changelog.md)
- [Architecture Overview](architecture/overview.md)

### Analytics & Data Science

- [Analytics API Overview](api/endpoints/analytics.md)
- [Sales Autopilot](architecture/sales-autopilot.md) (NEW)
- Send Time Optimizer (Bayesian STO)
- Churn Prediction Engine
- Subject Line NLP Analyzer
- Campaign Autopilot (Thompson Sampling)
- AI Reply Classification

### Enterprise Features

- [Enterprise Overview](enterprise/README.md)
- [Single Sign-On (SSO)](enterprise/sso.md)
- [Sub-Account Management](enterprise/sub-accounts.md)
- [White-Label Branding](enterprise/whitelabel.md)
- [Template Approval Workflows](enterprise/template-approval.md)
- [Log Streaming](enterprise/log-streaming.md)
- [Compliance & Data Governance](enterprise/compliance.md)
- [Private Cloud Deployment](enterprise/private-cloud.md)
- [Premium Support](enterprise/support.md)
- [Quarterly Business Reviews](enterprise/qbr.md)

### Billing

- [Pricing Reference](pricing.md)
- [Billing Lifecycle](architecture/billing-lifecycle.md) (NEW)

### Email Authentication & Deliverability

- [Email Authentication Guide](security/email-authentication.md) (NEW)
  - ARC (Authenticated Received Chain) - RFC 8617
  - MTA-STS (Strict Transport Security) - RFC 8461
  - BIMI (Brand Indicators for Message Identification)
  - TLSRPT (TLS Reporting) - RFC 8460
- [Advanced Analytics Features](security/advanced-analytics.md) (NEW)
  - Bot Click Detection
  - Reply Rate Tracking
  - Engagement Trust Scoring
  - Gmail Annotations
- [Inbox Placement Testing](user-guide/inbox-placement-testing.md) (NEW)
- [Domain API Reference](api/endpoints/domains.md) (NEW)

### Security Systems

- [Security Systems Reference](security/Security_Systems.md) (NEW — comprehensive coverage of all 8 Rust security crates)
  - DDoS Protection (ddos-protection) — 5-layer defense, ML anomaly detection, SMTP state machine
  - Web Application Firewall (waf-engine) — AST-based SQLi/XSS, OWASP CRS-compatible
  - Intrusion Detection/Prevention (ids-engine) — Signature + protocol + connection tracking
  - Spam & Phishing Filter (spam-filter) — Bayesian + header + content + URL analysis
  - Attachment Sandbox (sandbox) — File magic, SHA-256, OLE2/macro detection
  - Account Takeover Protection (ato-protection) — Haversine impossible travel, device fingerprinting
  - Data Loss Prevention (dlp-engine) — PII/Luhn, Shannon entropy, content policy
  - Threat Intelligence (threat-intel) — IP/domain blocklists, CIDR, reputation scoring
- [Login mCaptcha Protection](security/mcaptcha-login.md) (NEW)
  - Web + control-plane login widget wiring
  - Server-side verification and error semantics
  - Environment variable matrix and smoke checklist

### Operations

- [Security & Compliance](security/compliance.md)
- [Operations Runbooks](operations/runbooks/incident-response.md)
- [Monitoring](operations/monitoring.md)
- [On-Call Procedures](operations/on-call.md)
- [SLO Management](operations/slo-management.md)

### Webhooks & Integrations

- [Webhook Delivery Guide](api/webhooks.md)
- [Authentication Reference](api/authentication.md)
- [Rate Limits](api/rate-limits.md)

### Development

- [Marketing Website](marketing/README.md)
- [Contributing Guide](development/contributing.md)
- [Apex Style System (Premium UI + Apex Icons)](development/style-system.md) (NEW)
- [Control Plane UX Checklist](development/ux-qa-checklist.md) (NEW)
- [Premium Experience Spec](development/premium-experience-spec.md) (NEW)
- [Interactive State Matrix](development/interactive-state-matrix.md) (NEW)
- [Premium Performance Budgets](development/premium-performance-budgets.md) (NEW)
- [Global Navigation Taxonomy](development/navigation-taxonomy.md) (NEW)
- [JTBD Navigation Mapping](development/jtbd-nav-mapping.md) (NEW)
- [Setup & Migration Checklists](development/setup-migration-checklists.md) (NEW)

## Version

- Documentation Version: 1.0.0
- ApexMail Version: 1.0.0
- Last Updated: 2026-04-29

---

## Company Information

ApexMail is a brand of **Bel Consulting OÜ**, Estonia.

- **Company**: Bel Consulting OÜ
- **Address**: Sakala 7-2, 10141 Tallinn, Estonia
- **Registry Code**: 16192499
- **VAT Number**: EE102951727
- **Email**: support@apexmail.ee
- **Website**: https://apexmail.ee
