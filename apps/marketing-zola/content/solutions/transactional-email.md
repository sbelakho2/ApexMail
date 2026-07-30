+++
title = "Transactional Email Solution"
description = "Application-driven transactional email: password resets, receipts, notifications. EU-hosted REST API and SMTP relay with signed webhooks."
template = "page.html"
+++

# Transactional Email

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

- **REST API** (`POST /v1/emails`) — JSON payloads with idempotency keys. Submit and forget.
- **SMTP Relay** (`smtp.apexmail.ee:587` with STARTTLS) — Drop-in for existing SMTP clients.
- **Transactional Streams** — Isolate sending configurations (dedicated IP, custom domain, suppression list) per email type.
- **Signed Webhooks** — Real-time `delivered`, `bounced`, `complained`, `opened`, `clicked` events, each with a unique event ID and HMAC signature.
- **Idempotency** — Deduplicate submissions using client-supplied keys. Resubmit safely after network errors.

## Technical Implementation

1. Create an API key in **Dashboard → Settings → API Keys**.
2. Verify your sending domain (SPF, DKIM, custom return-path).
3. Create a transactional stream for your email type.
4. Send via REST or SMTP with the stream name in the payload.
5. Register a webhook endpoint to receive delivery events.
6. Monitor delivery metrics in the dashboard or via the analytics API.

## Relevant API Endpoints

| Endpoint | Description |
|---|---|
| `POST /v1/emails` | Send an email |
| `GET /v1/emails/:id` | Retrieve email status and events |
| `DELETE /v1/emails/:id/schedule` | Cancel a scheduled send |
| `POST /v1/emails/batch` | Send up to 1,000 emails in one request |

## Relevant Webhook Events

| Event | Trigger |
|---|---|
| `email.accepted` | API accepted the request |
| `email.delivered` | Receiving server accepted the message |
| `email.bounced` | Hard or soft bounce |
| `email.complained` | Recipient reported as spam |
| `email.opened` | Open detected (tracking pixel) |
| `email.clicked` | Link click detected |
| `email.delayed` | Message deferred by receiving server |

## Required Plan

| Plan | Monthly Volume | Support |
|---|---|---|
| Free | 30,000 emails | Community |
| Developer | 50,000 emails | 2 business days |
| Pro | 150,000 emails | 1 business day |
| Growth | 500,000 emails | 8 business hours |
| Business | 2,000,000 emails | 4 business hours |
| Enterprise | 5,000,000+ emails | Negotiated |

## Security Considerations

- API keys are scoped per environment (live/test). Test keys route to test mailboxes.
- Webhooks are HMAC-signed. Validate signatures before processing events.
- TLS 1.2+ required for all API and SMTP connections.
- Message content encrypted at rest. Content retention configurable per plan.

## Compliance Considerations

- EU data residency. All processing and storage in EEA data centers.
- DPA available on Business and Enterprise plans.
- BAA review eligibility for Enterprise and Dedicated Tenant plans.
- Customer responsible for recipient consent and opt-out management.

## Known Limitations

- Free plan content stored for 24 hours only.
- Attachment size limited to 25 MB per message.
- Open and click tracking require HTML body with tracking pixel/links.

## Recommended Next Action

[Create a free account](https://app.apexmail.ee/signup) and send your first email via the REST API or SMTP relay.
