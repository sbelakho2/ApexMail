# Business Associate Agreement (BAA) Template

> **Part of:** [Compliance Documentation](./README.md)  
> **Applies to:** Enterprise customers requiring HIPAA compliance  
> **Contact:** [support@apexmail.ee](mailto:support@apexmail.ee) for execution

## Overview

ApexMail offers a Business Associate Agreement (BAA) as part of the **Enterprise** plan. The BAA is required under HIPAA when ApexMail handles, stores, or transmits Protected Health Information (PHI) on behalf of a Covered Entity.

## How to Obtain a Signed BAA

1. **Upgrade to Enterprise plan** — BAA is included with Enterprise ($3,000/mo)
2. **Contact support** — Email [support@apexmail.ee](mailto:support@apexmail.ee) with your tenant ID
3. **Review and sign** — ApexMail will provide the current BAA via DocuSign
4. **Counter-signature** — ApexMail signs within 5 business days

## BAA Scope

The BAA covers:

- **PHI handled by ApexMail** — Email content, metadata, and attachments that contain PHI
- **Subprocessors** — AWS (SES, S3), Hetzner (dedicated IPs), ClickHouse (analytics)
- **Permitted uses** — Email delivery, analytics, storage, and compliance obligations
- **Breach notification** — Notification within 72 hours per HIPAA requirements
- **Termination** — 30-day cure period for material breaches

## What the BAA Includes

| Section | Description |
|---------|-------------|
| Definitions | PHI, Covered Entity, Business Associate, Subprocessor |
| Permitted Uses | Email transmission, storage, analytics, security monitoring |
| Safeguards | Encryption (AES-256 at rest, TLS 1.2+ in transit), access controls, audit logging |
| Subprocessors | Complete list with notice requirements for changes |
| Breach Notification | 72-hour notification, content requirements |
| Termination | Grounds, cure period, return/destruction of PHI |
| Liability | Indemnification, limitation of liability |
| Term | Effective for duration of service agreement |

## Related Resources

- [HIPAA Compliance Overview](./compliance.md)
- [Data Protection](./data-protection.md) — Encryption, tenant isolation, data residency
- [Security Overview](../security/compliance.md)
- [Pricing: Enterprise Plan](../pricing.md) — BAA is included with Enterprise
