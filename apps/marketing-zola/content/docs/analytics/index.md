+++
title = "Analytics"
description = "Delivery, engagement, and event-level visibility for messages sent through ApexMail."
template = "prose.html"
weight = 2
+++

## Annotated Timeline

| Stage | What it answers | Where it comes from |
|---|---|---|
| API acceptance | Did ApexMail accept the request? | `POST /v1/messages` response and the `message.accepted` event |
| Recipient-MX acceptance | Did the receiving server accept the message? | Per-attempt SMTP responses, `message.delivered`, `message.bounced`, `message.deferred` |
| Engagement | Did the recipient open or click? | `message.opened` and `message.clicked` when tracking is enabled for the message |
| Inbox placement | Did the message reach the inbox rather than spam? | Provider reputation telemetry (Google Postmaster Tools, Microsoft SNDS) — a separate signal from MX acceptance |
| Downstream processing | Did your systems receive the event? | Webhook delivery attempts and signature-verification status |

Recipient-MX acceptance does not establish inbox placement: a `250` response means the receiving server accepted the message, not that it reached the inbox. Read the sections in that order when diagnosing a report.

## What You Can Track

ApexMail exposes message-level analytics so you can follow delivery and recipient engagement without stitching together multiple systems.

- Delivery lifecycle events such as queued, delivered, bounced, and complained states.
- Engagement signals such as opens and clicks when tracking is enabled for the message.
- Event history queries through the events API for downstream dashboards or incident review.

## How Teams Use It

- Confirm whether a production issue is a send failure, inbox-placement issue, or recipient-side engagement drop.
- Feed event history into customer support tooling, BI dashboards, or compliance audit trails.
- Compare delivery behavior across campaigns, transactional flows, and private cloud deployments.

## Next Steps

- Use the [API Reference](/docs/api/) to send a tracked message.
- Exercise a request interactively in the [API Explorer](/api-explorer/).
- Pair analytics with [Webhooks](/docs/webhooks/) when you need downstream processing from delivery events.