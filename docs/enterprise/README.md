# Enterprise Features Documentation

This section covers ApexMail's enterprise-grade features designed for large organizations with complex requirements.

## Overview

ApexMail Enterprise provides:

- **Single Sign-On (SSO)** - SAML 2.0 and OIDC authentication
- **Sub-Account Management** - Hierarchical multi-tenant architecture
- **White Labeling** - Complete brand customization
- **Template Approval Workflows** - Governance and compliance
- **Log Streaming** - Real-time data export to external systems
- **Compliance Tools** - GDPR, HIPAA, SOC 2 automation
- **Private Cloud Deployment** - Run in your own VPC
- **Premium Support** - SLA-backed response times
- **Quarterly Business Reviews** - Strategic partnership

## Feature Documentation

| Feature | Documentation | Status |
|---------|--------------|--------|
| SSO | [sso.md](./sso.md) | Production |
| Sub-Accounts | [sub-accounts.md](./sub-accounts.md) | Production |
| White Labeling | [whitelabel.md](./whitelabel.md) | Production |
| Template Approval | [template-approval.md](./template-approval.md) | Production |
| Log Streaming | [log-streaming.md](./log-streaming.md) | Production |
| Compliance | [compliance.md](./compliance.md) | Production |
| Private Cloud | [private-cloud.md](./private-cloud.md) | Production |
| Support | [support.md](./support.md) | Production |
| QBR | [qbr.md](./qbr.md) | Production |

## Enterprise API

All enterprise features are accessible via the Enterprise API:

```bash
# Base URL
https://api.apexmail.ee/enterprise/v1

# Authentication
X-API-Key: <enterprise_api_key>
```

See the [API Reference](../api/sdk-reference.md) for complete documentation.

## Getting Started

1. Contact sales to enable Enterprise features
2. Configure SSO for your organization
3. Set up sub-accounts for your teams
4. Configure compliance settings
5. Enable log streaming to your SIEM

## Support

Enterprise customers receive dedicated support. Response commitments are
defined in [support.md](support.md) — the authoritative tier table
(Enterprise: 4-hour contractual first response during business hours);
do not quote numbers from this summary.

Contact: support@apexmail.ee
