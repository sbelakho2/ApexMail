+++
title = "Migration Solution"
description = "Migrate from SendGrid, Postmark, Mailgun, SES, or Resend to ApexMail. IP warm-up, domain transition, template migration, and parallel-send validation."
template = "prose.html"
+++

## Migration

Move your transactional email infrastructure to ApexMail without disruption. This solution covers domain transition, IP warm-up, template migration, webhook compatibility, and parallel-send validation.

## Audience

Engineering teams migrating from SendGrid, Postmark, Mailgun, Amazon SES, or Resend. Operations teams managing the cutover. Compliance teams verifying data residency requirements.

## Business Context

Email provider migration is a high-risk operation. Dropped delivery during cutover means lost revenue. IP warm-up without automation risks blacklisting. Domain reputation must be preserved across providers. Without a structured migration plan, teams risk extended delivery degradation.

## Core Problem

- IP reputation is provider-specific and cannot be transferred.
- Domain authentication records (SPF, DKIM, DMARC) require coordinated DNS changes.
- Template syntax differs between providers.
- Webhook payloads and event types are not standardized.
- Parallel sending during validation requires dual-provider routing.

## ApexMail Solution

- **Managed IP Warm-Up** — Automated warm-up schedule for dedicated IPs, with throttling and reputation monitoring.
- **Domain Transition Guide** — Step-by-step DNS configuration for SPF, DKIM, DMARC, and custom return-path.
- **Template Import** — Map existing templates to ApexMail's template format with variable and layout preservation.
- **Webhook Compatibility** — Standardized event types with payload mapping documentation.
- **Parallel Send Validation** — Route a configurable percentage of traffic through ApexMail while maintaining your existing provider.

## Technical Implementation

1. Create an ApexMail account and verify your sending domain.
2. Copy the domain-specific DKIM record or records generated in the Domains settings alongside your existing provider's selectors.
3. Add the generated ApexMail SPF mechanism to the existing SPF record; do not remove a previous provider until the transition is validated.
4. Set DMARC policy to `p=none` during transition to collect reports without enforcement.
5. Import templates using the Template API.
6. Configure webhook endpoints for event delivery.
7. Begin parallel sending at 10% volume, increasing incrementally while monitoring delivery metrics.
8. After validation period, route 100% through ApexMail and remove legacy provider configuration.

## Relevant API Endpoints

| Endpoint | Description |
|---|---|
| `POST /v1/emails` | Send an email |
| `POST /v1/emails/batch` | Batch send up to 1,000 emails |
| `POST /v1/templates` | Create a template |
| `GET /v1/templates` | List templates |
| `PUT /v1/templates/:id` | Update a template |

## Relevant Webhook Events

| Event | Trigger |
|---|---|
| `email.delivered` | Receiving server accepted the message |
| `email.bounced` | Hard or soft bounce |
| `email.delayed` | Message deferred by receiving server |

## Required Plan

| Plan | Dedicated IP | Support |
|---|---|---|
| Growth | 1 included dedicated IP | Email support |
| Scale | 3 included dedicated IPs | Priority support |
| Enterprise | 10 included dedicated IPs | Dedicated support |

## Security Considerations

- DNS changes should be implemented during a maintenance window.
- Monitor DMARC aggregate reports (RUA) throughout the transition period.
- Keep both provider API keys active until full validation is complete.

## Compliance Considerations

- Confirm data-location and DPA requirements during account or Enterprise review; a technical cutover does not itself create a residency or compliance commitment.
- Customer retains responsibility for recipient consent continuity during migration.

## Known Limitations

- Parallel sending may result in duplicate delivery events during the validation window.
- IP warm-up requires 2-4 weeks for dedicated IPs.
- Template migration requires manual review for complex conditional logic.

## Recommended Next Action

[Contact sales](/contact/sales/) for a migration assessment and dedicated IP eligibility review.
