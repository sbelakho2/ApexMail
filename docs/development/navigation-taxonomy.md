# Global Navigation Taxonomy

Canonical taxonomy for product surfaces.

## Primary Product Surfaces

- Customer Console (`web` surface served by `services/mail-server/crates/api-server`)
- Control Plane (`control-plane` surface served by `services/mail-server/crates/api-server`)
- Marketing (`marketing-zola` routes served from `apps/marketing-zola` exports)

## Customer Console Taxonomy

- Dashboard
- Campaigns
- Contacts
- Lists
- Templates
- Reports
- Activity
- AI Insights
- Settings
  - Account
  - Team
  - Billing
  - Dedicated IPs

Rules:
- Labels must be noun-first and parallel.
- Feature discoverability must align with role + plan entitlements.

## Control Plane Taxonomy

- Operations Dashboard
- CRM / Sales Pipeline
- Risk / Compliance
- GDPR / Privacy Operations
- Content / CMS
- Inbox / Support Operations

Rules:
- Keep operations flows grouped by decision context.
- Avoid mixing customer-facing labels with internal operator language.

## Marketing Information Taxonomy

- Product
- Solutions
- Security & Compliance
- Pricing
- Documentation
- Proof (case studies, benchmarks)

Rules:
- Match conversion pathways to role intent (technical, compliance, executive).
- Keep naming parity across SSR browser surfaces and Zola-generated marketing surfaces.

## Naming Contract

- Avoid mixed verb+noun siblings in same nav group.
- Use stable labels over time to preserve user memory.
- Changes require docs updates and release-note mention.
