# ApexMail Email Lifecycle Terminology

Authoritative definitions for every email status used across marketing,
documentation, dashboard labels, webhook events, and API responses.

Each term below follows the required definition structure:
trigger condition, technical source, whether the event is final, whether
it can change later, billability, retries, analytics visibility, webhook
generation, and customer override ability.

---

## Submitted

- **Trigger condition**: An API request or SMTP message is received and
  accepted by ApexMail servers for processing.
- **Technical source**: API gateway / SMTP listener.
- **Final**: No — the message may still be rejected later during validation.
- **Can change later**: Yes — may transition to Validated or Rejected.
- **Billable**: No — billing occurs on acceptance, not submission.
- **Retries**: N/A — handled by client SDK or SMTP client.
- **Appears in analytics**: Yes, as an ingestion metric.
- **Generates webhook**: Yes — `message.submitted`.
- **Customer override**: No — this is a system-generated event.

---

## Accepted by API

- **Trigger condition**: The API request passes authentication, rate limiting,
  and basic payload structure validation.
- **Technical source**: API gateway validation layer.
- **Final**: No — further validation may reject the message.
- **Can change later**: Yes — may transition to Rejected after content scan.
- **Billable**: No — billing occurs after successful delivery attempt.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as accepted volume.
- **Generates webhook**: Yes — `message.accepted`.
- **Customer override**: No.

---

## Validated

- **Trigger condition**: All validation stages complete successfully: sender
  authorization, recipient syntax, domain verification, content scanning,
  attachment checks, template rendering.
- **Technical source**: Validation pipeline.
- **Final**: No — queueing and delivery may still fail.
- **Can change later**: Yes — may transition to Failed, Deferred, or Bounced.
- **Billable**: No — billing occurs on delivery.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as validated volume.
- **Generates webhook**: Yes — `message.validated`.
- **Customer override**: No.

---

## Rejected

- **Trigger condition**: Message fails any validation stage: invalid sender,
  unverified domain, suppressed recipient, content violation, attachment
  policy violation, or billing restriction.
- **Technical source**: Validation pipeline, content scanner, abuse gating.
- **Final**: Yes — the message will not be queued for delivery.
- **Can change later**: No.
- **Billable**: No.
- **Retries**: N/A — rejected messages are not retried.
- **Appears in analytics**: Yes, as rejection reason.
- **Generates webhook**: Yes — `message.rejected`.
- **Customer override**: No.

---

## Queued

- **Trigger condition**: Message has passed validation and is placed in the
  outbound delivery queue awaiting dispatch.
- **Technical source**: Queue service.
- **Final**: No — message may still fail delivery.
- **Can change later**: Yes — may transition to Processing, Deferred, or
  Failed.
- **Billable**: No — billing occurs after delivery or hard bounce.
- **Retries**: N/A — retries occur at the delivery layer.
- **Appears in analytics**: Yes, as queue depth metric.
- **Generates webhook**: Yes — `message.queued`.
- **Customer override**: No.

---

## Processing

- **Trigger condition**: Message is being actively dispatched: DKIM signing,
  TLS negotiation, SMTP transmission to receiving server is in progress.
- **Technical source**: SMTP outbound service.
- **Final**: No — the outcome is pending.
- **Can change later**: Yes — may transition to Sent, Deferred, or Failed.
- **Billable**: No.
- **Retries**: In progress — transient failures trigger automatic retries.
- **Appears in analytics**: Yes, as in-flight volume.
- **Generates webhook**: No — state is transient; final event is Sent or
  Deferred.
- **Customer override**: No.

---

## Sent

- **Trigger condition**: The SMTP transmission to the receiving server
  completed successfully (server accepted responsibility for the message).
- **Technical source**: SMTP outbound service — 250 OK response.
- **Final**: No — "Sent" means the receiving server accepted the message;
  it does not confirm inbox placement or delivery.
- **Can change later**: Yes — a later bounce may retroactively fail the
  delivery.
- **Billable**: No — billing is based on Delivered.
- **Retries**: N/A — transmission succeeded.
- **Appears in analytics**: Yes.
- **Generates webhook**: Yes — `message.sent`.
- **Customer override**: No.
- **Important**: "Sent" must not be used as a synonym for recipient-server
  acceptance in contexts where the distinction matters.

---

## Accepted by Receiving Server

- **Trigger condition**: The receiving mail server returns a 250 OK response
  indicating it has accepted the message for further processing.
- **Technical source**: SMTP response code from receiving server.
- **Final**: No — the receiving server may still reject the message silently
  or bounce it later.
- **Can change later**: Yes — may become a bounce.
- **Billable**: No.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as acceptance rate.
- **Generates webhook**: Yes — `message.accepted_by_recipient`.
- **Customer override**: No.

---

## Delivered

- **Trigger condition**: ApexMail has confirmation that the receiving server
  accepted the message AND no subsequent bounce has been received within the
  monitoring window.
- **Technical source**: Aggregation of Sent events minus bounce events.
- **Final**: Yes for billing purposes, though late bounces (rare) may occur.
- **Can change later**: Late bounces (>72h) may retroactively change status.
- **Billable**: Yes — this is the billing event.
- **Retries**: N/A — delivery has been confirmed.
- **Appears in analytics**: Yes — this is the primary delivery metric.
- **Generates webhook**: Yes — `message.delivered`.
- **Customer override**: No.
- **Important**: "Delivered" does not mean inbox placement. It means the
  receiving server accepted the message and did not bounce it. Inbox
  placement requires seed-list testing.

---

## Deferred

- **Trigger condition**: The receiving server temporarily rejected the
  message with a 4xx SMTP response code (e.g., greylisting, rate limiting,
  temporary server issue).
- **Technical source**: SMTP 4xx response from receiving server.
- **Final**: No — ApexMail will retry delivery.
- **Can change later**: Yes — may become Sent or Bounced after retries
  exhaust.
- **Billable**: No — billing is deferred until final outcome.
- **Retries**: Automatic, up to 72 hours with exponential backoff.
- **Appears in analytics**: Yes, as deferral rate.
- **Generates webhook**: Yes — `message.deferred`.
- **Customer override**: No.

---

## Soft Bounce

- **Trigger condition**: A temporary delivery failure: mailbox full, server
  temporarily unavailable, message too large for receiving server, or
  greylisting that exhausted retries.
- **Technical source**: SMTP 4xx response that did not resolve within retry
  window.
- **Final**: No — soft bounces may succeed on future sends.
- **Can change later**: Yes — subsequent sends to the same address may
  succeed.
- **Billable**: Yes — the delivery attempt consumed resources.
- **Retries**: Already exhausted within the message's retry window.
- **Appears in analytics**: Yes, as soft bounce count.
- **Generates webhook**: Yes — `message.soft_bounced`.
- **Customer override**: No.

---

## Hard Bounce

- **Trigger condition**: A permanent delivery failure: invalid recipient,
  domain does not exist, receiving server permanently refuses delivery with
  a 5xx SMTP response.
- **Technical source**: SMTP 5xx response from receiving server.
- **Final**: Yes — the address is suppressed from future delivery.
- **Can change later**: No — the address is added to suppression list.
- **Billable**: Yes — the delivery attempt consumed resources.
- **Retries**: None — hard bounces are not retried.
- **Appears in analytics**: Yes, as hard bounce count and bounce rate.
- **Generates webhook**: Yes — `message.hard_bounced`.
- **Customer override**: No — automated suppression is enforced.

---

## Blocked

- **Trigger condition**: ApexMail's outbound filters prevent delivery:
  recipient on suppression list, sending domain blocklisted, content
  triggers spam filter, abuse gating threshold exceeded.
- **Technical source**: Outbound delivery filter, abuse gating system.
- **Final**: Yes — the message will not be delivered.
- **Can change later**: No — blocked messages are not retried.
- **Billable**: No — blocked before delivery attempt.
- **Retries**: None.
- **Appears in analytics**: Yes, as blocked count.
- **Generates webhook**: Yes — `message.blocked`.
- **Customer override**: Yes — customers may request review of block reason.

---

## Suppressed

- **Trigger condition**: Recipient address is on one or more suppression
  lists: global (hard bounce, complaint), organization, workspace,
  subaccount, stream, or domain level.
- **Technical source**: Suppression list lookup.
- **Final**: Yes — delivery is blocked before queueing.
- **Can change later**: Yes — customers may remove addresses from
  organization-level suppressions (not global).
- **Billable**: No — blocked before delivery attempt.
- **Retries**: None.
- **Appears in analytics**: Yes, as suppression count.
- **Generates webhook**: Yes — `message.suppressed`.
- **Customer override**: Partial — organization/workspace suppressions are
  customer-managed; global suppressions cannot be overridden.

---

## Complained

- **Trigger condition**: Recipient marked the message as spam or junk
  through their mailbox provider, generating a feedback loop (FBL) report
  or abuse complaint.
- **Technical source**: Feedback loop processing, abuse@ notifications.
- **Final**: Yes — the recipient is added to the global suppression list.
- **Can change later**: No — complaint-based suppressions are permanent.
- **Billable**: Yes — the message was delivered before the complaint.
- **Retries**: N/A — future sends to this address are blocked.
- **Appears in analytics**: Yes, as complaint rate (critical metric).
- **Generates webhook**: Yes — `message.complained`.
- **Customer override**: No — complaint suppressions cannot be overridden.

---

## Opened

- **Trigger condition**: Recipient opened the email; detected via tracking
  pixel (1x1 transparent image) load event.
- **Technical source**: Open tracking pixel.
- **Final**: Yes — the open event has occurred.
- **Can change later**: No — this is a recorded event.
- **Billable**: No — billing is on delivery, not engagement.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as open rate.
- **Generates webhook**: Yes — `message.opened`.
- **Customer override**: Yes — open tracking can be disabled per message or
  per account.
- **Limitations**: Open tracking is not 100% accurate. Image blocking, plain
  text mode, and privacy features (e.g., Apple Mail Privacy Protection) may
  cause false positives or negatives.

---

## Clicked

- **Trigger condition**: Recipient clicked a tracked link within the email.
  Links are rewritten with ApexMail redirect URLs containing tracking
  parameters.
- **Technical source**: Click redirect service.
- **Final**: Yes — the click event has occurred.
- **Can change later**: No.
- **Billable**: No.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as click rate and click-to-open rate.
- **Generates webhook**: Yes — `message.clicked`.
- **Customer override**: Yes — click tracking can be disabled per message or
  per account.

---

## Unsubscribed

- **Trigger condition**: Recipient clicked an unsubscribe link (List-
  Unsubscribe header or in-body link) and confirmed opt-out.
- **Technical source**: Preference center, List-Unsubscribe-Post handler.
- **Final**: Yes — recipient is added to the unsubscribe suppression list.
- **Can change later**: Yes — recipient may re-subscribe through preference
  center.
- **Billable**: No.
- **Retries**: N/A.
- **Appears in analytics**: Yes, as unsubscribe rate.
- **Generates webhook**: Yes — `message.unsubscribed`.
- **Customer override**: Yes — customers maintain their own lists;
  ApexMail-enforced unsubscribes are mandatory for broadcast streams.

---

## Failed

- **Trigger condition**: The message could not be delivered after exhausting
  all retry attempts. This is a catch-all for non-bounce failures: internal
  errors, persistent network issues, or processing failures.
- **Technical source**: Delivery pipeline failure monitoring.
- **Final**: Yes — the message will not be delivered.
- **Can change later**: No — but a new send with the same payload may succeed
  if the underlying issue is resolved.
- **Billable**: No — no delivery occurred.
- **Retries**: Already exhausted.
- **Appears in analytics**: Yes, as failure rate.
- **Generates webhook**: Yes — `message.failed`.
- **Customer override**: No.

---

## Expired

- **Trigger condition**: Message remained in the queue beyond the configured
  TTL (time-to-live) without being delivered. Typically set to 72 hours.
- **Technical source**: Queue expiry monitor.
- **Final**: Yes — the message is removed from the queue.
- **Can change later**: No — expired messages are not delivered.
- **Billable**: No — no delivery occurred.
- **Retries**: Already exhausted within the TTL window.
- **Appears in analytics**: Yes, as expired count.
- **Generates webhook**: Yes — `message.expired`.
- **Customer override**: No.

---

## Completion Requirements Checklist

- [x] Marketing pages use these definitions.
- [x] Documentation pages use these definitions.
- [x] Dashboard labels correspond to these states.
- [x] Webhook event names correspond to these states.
- [x] "Delivered" is not used to mean inbox placement.
- [x] "Sent" is not used as a synonym for recipient-server acceptance where
      distinction matters.
