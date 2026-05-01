# Outbound Delivery Contract

ApexMail has one production delivery contract for customer mail:

1. Public API and authenticated SMTP submission create message records and enqueue delivery work.
2. Delivery workers consume queued work and select the transport backend.
3. SES shared-pool delivery and self-hosted SMTP dedicated-IP delivery are transport backends, not alternate product entry points.
4. The inbound MTA never sends customer-originated outbound mail directly.

Approved outbound entry points are:

- API message routes that persist messages and queue work.
- Submission service sessions that forward authenticated SMTP traffic to the outbound queue.
- Worker transport selection through the email processor transport factory/router.
- The outbound queue service while it remains the queue worker for mail-server deployments.

New direct sender implementations must either replace one of these entry points or be wired behind the worker transport router. Standalone binaries, route-level SMTP clients, and ad hoc provider SDK calls are not approved delivery paths.
