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

- [Getting Started](deployment/quickstart.md)
- [API Reference](api/endpoints/messages.md)
- [Architecture Overview](architecture/overview.md)
- [Security & Compliance](security/compliance.md)
- [Operations Runbooks](operations/runbooks/incident-response.md)

## Version

- Documentation Version: 1.0.0
- ApexMail Version: 1.0.0
- Last Updated: 2026-02-01
