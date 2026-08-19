+++
title = "SaaS Platform Email Solution"
description = "Multi-tenant email infrastructure for B2B and B2C SaaS. Subaccounts, domain isolation, RBAC, SSO, and white-label delivery."
template = "prose.html"
+++

## SaaS Platforms

Provide your customers with reliable, isolated email infrastructure without building and maintaining your own email layer. ApexMail's subaccount model gives each of your tenants independent domains, API keys, suppression lists, and event streams.

## Audience

SaaS platforms that send email on behalf of their customers: CRMs sending campaign email, e-commerce platforms sending receipts, analytics tools sending reports, security platforms sending alerts.

## Business Context

Platforms that send email for customers inherit every customer's reputation risk. A single spam complaint on a shared IP can degrade delivery for all tenants. Without isolation, platforms cannot attribute delivery problems to specific customers or offer per-tenant compliance controls.

## Core Problem

- Shared IP reputation risk across all platform tenants.
- Inability to isolate billing, usage quotas, and delivery analytics per customer.
- Compliance requirements vary by customer (one needs HIPAA, another needs GDPR only).
- Customers demand visible deliverability metrics and domain-level authentication status.

## ApexMail Solution

- **Subaccounts** — Each tenant gets an independent subaccount with its own API keys, domains, webhooks, suppression lists, dedicated IPs, and event streams.
- **Domain Isolation** — Per-subaccount domain verification and authentication (SPF, DKIM, DMARC) prevents reputation cross-contamination.
- **Custom RBAC** — Platform-level admin, tenant-level admin, and read-only roles. SCIM provisioning on Enterprise.
- **SSO** — SAML 2.0 for platform operators and tenant administrators.
- **Usage Quotas** — Hard and soft limits per subaccount for volume, rate, and concurrency.
- **White-Label** — Remove ApexMail branding from dashboards, email footers, and notification templates.

## Technical Implementation

1. Create a master account for your platform.
2. Provision subaccounts via the API or dashboard for each customer tenant.
3. Each tenant verifies their sending domain(s) independently.
4. Assign dedicated IPs to tenants requiring reputation isolation.
5. Configure per-tenant webhook endpoints for delivery events.
6. Monitor platform-wide delivery health via aggregate analytics.

## Relevant API Endpoints

| Endpoint | Description |
|---|---|
| `POST /v1/subaccounts` | Create a subaccount |
| `GET /v1/subaccounts` | List subaccounts |
| `GET /v1/subaccounts/:id` | Retrieve subaccount details |
| `PATCH /v1/subaccounts/:id` | Update subaccount settings |
| `DELETE /v1/subaccounts/:id` | Deactivate a subaccount |
| `POST /v1/subaccounts/:id/api-keys` | Create subaccount API key |

## Required Plan

Subaccounts are available on Scale (up to 10) and Enterprise (up to 100). Any non-standard deployment arrangement requires a separate architecture and contract review.

## Security Considerations

- Platform operators cannot read tenant email content by default. Content access requires explicit tenant authorization.
- Subaccount API keys are scoped to their subaccount only. Cross-tenant access is prevented at the authorization layer.
- Webhook endpoints are configured per subaccount. HMAC signatures are per-subaccount secret.
- Audit logs record all subaccount creation, deletion, and permission changes.

## Compliance Considerations

- Each subaccount maintains independent suppression lists, domain authentication, and event retention.
- DPA coverage for subaccounts requires the platform's DPA with ApexMail. Contractual flow-down to tenants is the platform's responsibility.
- Data-location requirements apply at the platform level and must be confirmed for the active deployment and applicable agreement.
- Platform operators are responsible for their tenants' acceptable use compliance.

## Known Limitations

- Subaccount isolation is logical on Shared Cloud plans. A separately contracted deployment may define additional isolation requirements, but it is not a public plan entitlement.
- Cross-subaccount analytics require the platform to aggregate subaccount event data externally.
- White-label branding is available on the Enterprise plan.

## Recommended Next Action

[Contact sales](/contact/sales/) for a subaccount architecture review and volume pricing for multi-tenant deployment.
