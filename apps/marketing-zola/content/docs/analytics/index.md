+++
title = "Analytics"
description = "Delivery, engagement, and event-level visibility for messages sent through ApexMail."
template = "prose.html"
weight = 2
+++

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
- Exercise a request interactively in the [API Explorer](/api-console/).
- Pair analytics with [Webhooks](/docs/webhooks/) when you need downstream processing from delivery events.