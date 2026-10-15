+++
title = "Provider Migration Guides"
sort_by = "title"
template = "section.html"
transparent = true
description = "Per-provider migration guides for SendGrid, Mailgun, Postmark and Resend: the compatibility endpoint, auth swap, field mapping, named refusals, DNS checklist, webhook event names and a 10/50/100 cutover plan."
+++

Migrating a sending integration is a base-URL change on ApexMail. Each provider below has its own compatibility surface that accepts the provider's request shape and the ApexMail API key in the provider's own credential header, then runs the canonical send path: sender-domain verification, suppression and consent gates, plan entitlements, the durable idempotency ledger and the queue insert.

Every guide states the endpoint mapping, the exact fields the surface refuses by name, what is not proxied, the DNS records that change and stay, the webhook event names to re-subscribe, and a six-step cutover with a rollback that is the same base-URL swap in reverse.
