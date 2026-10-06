# First-response SLO

This page defines the platform's measured first-response commitment. It exists
so the number is auditable rather than claimed.

## Definition

A first response is the first reply the platform queues to an inbound lead.
Leads arrive through three channels:

- a contact form submission (`contact_form`),
- an inbound sales email (`inbound_email`),
- a qualified chat conversation (`chat_lead`).

Each lead writes one `first_response_requests` row in the same transaction as
the lead itself. The mailbot claims pending requests, produces a grounded
draft and stores it for review. Approving the draft queues the reply on the
priority lane (`email_queue.priority = 100`).

## The measured interval

The metric is `first_response_latency_seconds`, a histogram recorded when the
reply is durably enqueued. The interval runs from the platform accepting the
lead (the draft row's `received_at`) to that enqueue.

Human review time is excluded by design: replies are draft-only, and a
reviewer's pace is not something the platform can promise. The metric
therefore measures the automated portion, which is the part the platform
controls and the part an alert can act on.

## Target

| Percentile | Target |
|---|---|
| p50 | 60 seconds |
| p95 | 300 seconds |

The alert `FirstResponseSloBurn` fires when the 30-minute p95 exceeds 300
seconds for 15 minutes. It is a warning, not a page: a burned SLO on this rail
needs investigation, not an emergency response.

## How to read it

- A p95 far below the target with a low request count is normal during quiet
  periods; the histogram only fills when leads arrive.
- A rising p95 with a growing `first_response_requests` backlog means the
  mailbot is not draining: check that `AI_EMAIL_AGENT_ENABLED` is on, that
  the model runtime is reachable, and that no per-tenant draft cap is
  saturated.
- A p95 that moves with the review queue instead of the draft queue means
  drafts are waiting on humans; that is a staffing question, not a platform
  fault, and is visible as a pending count rather than latency.

## Measurement and review

The metric is emitted by the api-server approval path (the only place a
first-response reply is enqueued). The query for a dashboard:

```
histogram_quantile(0.95, sum(rate(first_response_latency_seconds_bucket[30m])) by (le))
```

Re-derive the target from real data after the first month of operation. If
the measured distribution sits far below 300 seconds, tighten the alert
threshold in the same change as this page.
