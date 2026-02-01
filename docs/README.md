# ApexMail Documentation

Enterprise-grade transactional email platform with zero paid SaaS dependencies.

## Documentation Structure

```
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
│   │   └── campaigns.md            ✅
│   ├── errors.md                   ✅
│   ├── rate-limits.md              ✅
│   └── webhooks.md                 ✅
├── architecture/           # System Architecture
│   ├── overview.md                 ✅
│   └── data-flow.md                ✅
├── deployment/             # Deployment Guides
│   ├── quickstart.md               ✅
│   ├── docker.md                   ✅
│   └── configuration.md            ✅
├── development/            # Development Guides
│   ├── getting-started.md          ✅
│   └── contributing.md             ✅
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
│   └── compliance.md               ✅
└── user-guide/            # User Documentation
    └── getting-started.md          ✅
```

## Quick Links

### Getting Started
- [Quick Start Guide](deployment/quickstart.md)
- [API Reference](api/endpoints/messages.md)
- [Architecture Overview](architecture/overview.md)

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

### Operations
- [Security & Compliance](security/compliance.md)
- [Operations Runbooks](operations/runbooks/incident-response.md)
- [SLO Management](operations/slo-management.md)

### Development
- [Marketing Website](marketing/README.md)
- [Contributing Guide](development/contributing.md)

## Version

- Documentation Version: 2.0.0
- ApexMail Version: 2.0.0
- Last Updated: 2025-01-15
