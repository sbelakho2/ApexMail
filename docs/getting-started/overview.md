# Overview

ApexMail is an EU-hosted transactional email infrastructure platform providing REST API and SMTP relay for sending, receiving, and tracking email. It is operated by **Bel Consulting OÜ** (trading as ApexMail), a company incorporated in the Republic of Estonia.

## Capabilities

- **REST API** — programmatic email sending with JSON payloads.
- **SMTP Relay** — standards-based relay with STARTTLS.
- **Transactional Streams** — isolated sending configurations for different email types.
- **Broadcast Streams** — one-to-many campaigns with list management.
- **Inbound Email** — receive and process incoming email via webhooks.
- **Deliverability Tooling** — SPF, DKIM, DMARC, dedicated IPs, warm-up, suppression management.
- **Webhooks** — real-time delivery, open, click, bounce, complaint, and inbound events.
- **Analytics** — delivery metrics, engagement tracking, inbox placement.
- **Account & Security** — roles, API scopes, 2FA, SSO, SCIM, audit logs, IP allowlists.

## Deployment Models

| Model | Description |
|---|---|
| **Shared EU Cloud** | Multi-tenant infrastructure in EU data centers. Zero infrastructure responsibility. |
| **Dedicated Tenant** | Isolated infrastructure with dedicated IPs, enhanced SLA, custom retention, private networking. |
| **BYOC** (Bring Your Own Cloud) | ApexMail software deployed in customer-owned cloud accounts. Customer controls infrastructure. |

## Base URL

```
https://api.apexmail.ee/v1
```

## SMTP Endpoint

```
smtp.apexmail.ee:587 (STARTTLS)
```

## Related

- [Account Creation](account-creation.md)
- [First REST Email](first-rest-email.md)
- [First SMTP Email](first-smtp-email.md)
- [Production Checklist](production-checklist.md)
