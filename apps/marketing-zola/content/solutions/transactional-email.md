+++
title = "Transactional Email Solution"
description = "Application-driven transactional email: password resets, receipts, notifications. REST API and SMTP relay with signed webhooks and EU/EEA-oriented deployment options."
template = "prose.html"
+++

## Transactional Email

Send application-generated email through ApexMail's REST API or SMTP relay. Every message is tracked from acceptance to delivery with per-message event history.

## Audience

Engineering teams building applications that send automated email: password resets, account verification, purchase receipts, shipping notifications, security alerts, and system status updates.

## Business Context

Transactional email is mission-critical infrastructure. Delayed password resets block users. Missing receipts create support tickets. Dropped notifications damage trust. The email layer must be fast, observable, and reliable without distracting engineering from product work.

## Core Problem

- Deliverability varies by recipient provider, domain reputation, and authentication quality.
- Embedded SMTP libraries add maintenance burden and obscure delivery failures.
- Without per-message webhook events, teams cannot detect silent delivery failures.
- Queue buildup during provider outages requires retry logic and timeout management.

## ApexMail Solution

- **REST API** (`POST /v1/messages`) — JSON payloads with idempotency keys. Submit and forget.
- **SMTP Relay** (`smtp.apexmail.ee:587` with STARTTLS) — Drop-in for existing SMTP clients.
- **Isolated sending configuration** — Dedicated IPs, custom domains, and suppression-list settings can be scoped per email type.
- **Signed Webhooks** — Real-time `delivered`, `bounced`, `complained`, `opened`, `clicked` events, each with a unique event ID and HMAC signature.
- **Idempotency** — Deduplicate submissions using client-supplied keys. Resubmit safely after network errors.

## Technical Implementation

1. Create an API key in **Dashboard → Settings → API Keys**.
2. Verify your sending domain (SPF, DKIM, custom return-path).
3. Configure a dedicated sending domain (and, on eligible plans, a dedicated IP) for your email type.
4. Send via REST or SMTP.
5. Register a webhook endpoint to receive delivery events.
6. Monitor delivery metrics in the dashboard or via the analytics API.

## Relevant API Endpoints

| Endpoint | Description |
|---|---|
| `POST /v1/messages` | Send an email |
| `GET /v1/messages/:id` | Retrieve email status and events |
| `POST /v1/messages/:id/cancel` | Cancel a scheduled send |
| `POST /v1/messages/batch` | Send up to 100 messages in one request |

## Relevant Webhook Events

| Event | Trigger |
|---|---|
| `message.sent` | Message accepted for delivery |
| `message.delivered` | Receiving server accepted the message |
| `message.bounced` | Hard or soft bounce |
| `message.complained` | Recipient reported as spam |
| `message.opened` | Open detected (tracking pixel) |
| `message.clicked` | Link click detected |

## Required Plan

| Plan | Monthly Volume | Support |
|---|---|---|
| Free | 30,000 emails | Community |
| Starter | 50,000 emails | Email support |
| Pro | 150,000 emails | Email support |
| Growth | 500,000 emails | Email support |
| Scale | 2,000,000 emails | Priority support |
| Enterprise | 5,000,000 emails | Dedicated support |

## Security Considerations

- API keys are scoped per environment (live/test). Test keys route to test mailboxes.
- Webhooks are HMAC-signed. Validate signatures before processing events.
- TLS 1.2+ required for all API and SMTP connections.
- Message content encrypted at rest. Content retention configurable per plan.

## Compliance Considerations

- EU/EEA-oriented deployment options; confirm active data locations and transfer safeguards for the deployment.
- DPA is available under the applicable ApexMail agreement.
- HIPAA availability and BAAs are not currently offered.
- Customer responsible for recipient consent and opt-out management.

## Known Limitations

- Event history is retained 30 days by default (7 days on the Free plan); message content 7 days by default, plan-dependent up to 730 days.
- Attachment size limited to 25 MB per message.
- Open and click tracking require HTML body with tracking pixel/links.

## Recommended Next Action

[Create a free account](https://app.apexmail.ee/signup) and send your first email via the REST API or SMTP relay.
