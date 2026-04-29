+++
title = "Webhooks"
description = "Deliver ApexMail events to your own systems for automation, observability, and support workflows."
template = "prose.html"
weight = 4
+++

## Why Webhooks

Polling works for debugging, but production systems usually want event delivery as changes happen. Webhooks let you push mail events into your own queue workers, CRMs, support tooling, or analytics pipelines.

## Typical Event Consumers

- Update customer timelines when a message is delivered or bounced.
- Trigger remediation flows when complaint or suppression-related events appear.
- Sync open and click activity into marketing or lifecycle automation systems.

## Integration Guidance

- Make webhook handlers idempotent because event delivery can be retried.
- Verify request authenticity before processing payloads.
- Hand off heavy downstream work to an internal queue instead of doing it inline in the webhook handler.

For request-driven inspection alongside event delivery, use the [API Reference](/docs/api) and [Analytics](/docs/analytics) guides together.