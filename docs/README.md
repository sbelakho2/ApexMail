# ApexMail Documentation

Enterprise-grade transactional email platform with zero paid SaaS dependencies.

## Documentation Structure

```text
docs/
├── adr/                    # Architecture Decision Records
│   ├── 0001-database-choice.md     ✅
│   ├── 0002-mta-stack.md           ✅
│   ├── 0003-sales-autopilot.md     ✅
│   ├── 0004-ai-local-inference.md  ✅
│   └── 0005-slo-management.md      ✅
├── api/                    # API Documentation
│   ├── authentication.md           ✅
│   ├── endpoints/
│   │   ├── messages.md             ✅
│   │   ├── campaigns.md            ✅
│   │   └── domains.md              ✅ (NEW)
│   ├── errors.md                   ✅
│   ├── rate-limits.md              ✅
│   └── webhooks.md                 ✅
├── architecture/           # System Architecture
│   ├── overview.md                 ✅
│   ├── data-flow.md                ✅
│   ├── control-plane-isolation.md  ✅
│   └── analytics-data-science.md   ✅ (NEW)
├── deployment/             # Deployment Guides
│   ├── quickstart.md               ✅
│   ├── docker.md                   ✅
│   └── configuration.md            ✅
├── development/            # Development Guides
│   ├── getting-started.md          ✅
│   ├── contributing.md             ✅
│   └── style-system.md             ✅ (NEW)
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
│   ├── runbooks/
│   │   └── incident-response.md    ✅
│   └── slo-management.md           ✅
├── security/               # Security Documentation
│   ├── Security_Systems.md         ✅ (NEW — 8 security crates)
│   ├── compliance.md               ✅
│   ├── data-protection.md          ✅
│   ├── email-authentication.md     ✅ (NEW)
│   └── advanced-analytics.md       ✅ (NEW)
└── user-guide/            # User Documentation
    ├── getting-started.md          ✅
    └── inbox-placement-testing.md  ✅ (NEW)
```

## Quick Links

### Getting Started

- [Quick Start Guide](deployment/quickstart.md)
- [API Reference](api/endpoints/messages.md)
- [Architecture Overview](architecture/overview.md)

### Analytics & Data Science

- [Analytics Module Overview](architecture/analytics-data-science.md)
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

### Operations

- [Security & Compliance](security/compliance.md)
- [Operations Runbooks](operations/runbooks/incident-response.md)
- [SLO Management](operations/slo-management.md)

### Development

- [Marketing Website](marketing/README.md)
- [Contributing Guide](development/contributing.md)
- [Apex Style System (Premium UI + Apex Icons)](development/style-system.md) (NEW)

## Version

- Documentation Version: 1.0.0
- ApexMail Version: 1.0.0
- Last Updated: 2026-02-06

---

## Company Information

ApexMail is a brand of **Bel Consulting OÜ**, Estonia.

- **Company**: Bel Consulting OÜ
- **Address**: Sakala 7-2, 10141 Tallinn, Estonia
- **Registry Code**: 16192499
- **VAT Number**: EE102951727
- **Email**: contact@apexmail.ee
- **Website**: https://apexmail.ee
