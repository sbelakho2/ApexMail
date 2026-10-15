+++
title = "Migrate from Mailgun to ApexMail"
description = "Move a Mailgun integration to ApexMail by changing the base URL: POST /v3/{domain}/messages accepts your ApexMail API key in Mailgun's Basic auth slot, with the exact field mapping, named refusals, the messages.mime answer, the DNS checklist and a 10/50/100 cutover plan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail serves `POST /v3/{domain}/messages` on a Mailgun compatibility surface. The route translates the form fields into the canonical send request and then calls the same handler `POST /v1/messages` uses, so sender-domain verification, suppression and consent gates, plan entitlements, the idempotency ledger and the queue insert all run in one place. Your integration keeps its form fields and endpoint shape; the switch is the host and the key.

## Endpoint mapping

| Mailgun endpoint | ApexMail compatibility surface | ApexMail native endpoint |
|---|---|---|
| `POST https://api.mailgun.net/v3/{domain}/messages` (EU: `api.eu.mailgun.net`) | `POST https://api.apexmail.ee/v3/{domain}/messages` | `POST https://api.apexmail.ee/v1/messages` |
| `POST /v3/{domain}/messages.mime` (raw MIME) | Wired and answered `501` after authentication, with the reason | `POST /v1/messages` with structured fields, or an MTA relay over SMTP |
| No batch endpoint in this surface | One request per message | `POST /v1/messages/batch`, up to 100 messages per call |

The `{domain}` path segment is Mailgun's sending domain and must equal the domain of the `from` address. The canonical send path derives the DKIM identity from the sender domain, so a mismatch is refused by name instead of being signed with a different authority.

A successful send answers `200` with `{"id": "<canonical message id>@{domain}", "message": "Queued. Thank you."}`. The id inside the brackets is the canonical message id, the same id `GET /v1/messages/{id}` returns and the same id webhook events carry in `data.messageId`.

`messages.mime` answers a named `501`: `POST /v3/{domain}/messages.mime is not implemented by the ApexMail compatibility surface: raw MIME passthrough would require a second MIME parser in the request path. Use /v3/{domain}/messages with structured fields (from/to/subject/html/text/attachment), or the canonical POST /v1/messages API.`

## Auth swap

Your credential slot stays. Mailgun sends `Authorization: Basic base64("api:<key>")`; replace the key with the ApexMail API key (`am_live_…` or `am_test_…`) and give it the `messages:send` scope. The username carries no authority and is accepted as sent.

| Item | Mailgun today | ApexMail compatibility surface |
|---|---|---|
| Credential header | `Authorization: Basic base64("api:<key>")` | `Authorization: Basic base64("api:am_live_…")` |
| Body type | `application/x-www-form-urlencoded` or `multipart/form-data` | The same two body types |
| Scope | Key permissions, optionally per-domain | `messages:send` |
| Idempotency | Not offered | `Idempotency-Key: <uuid>` on the same route; the same key within 24 hours replays the original response, including the same message id |
| Subject class | Not a provider concept | `X-ApexMail-Category: transactional` (or `service`) makes the send exempt from the marketing preference gate; without the header the send counts as the default `marketing` class and the consent gate applies |

## Field mapping

Canonical field names are the `POST /v1/messages` contract, so the same payload understanding applies after a later move to the native API.

| Mailgun field | Canonical field | Notes |
|---|---|---|
| `from` | `from` | Required; its domain must equal the `{domain}` path segment |
| `to` | `to` | Repeatable or comma-separated; quoted display names keep their commas |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `attachment` (multipart file part) | `attachments[]` | Base64 content, filename and the part's Content-Type; the part Content-Type defaults to `application/octet-stream` |
| `o:tag` | `tags` | Deduplicated |
| `o:deliverytime` | `scheduled_at` | RFC 2822 timestamp, for example `Fri, 15 Oct 2026 12:00:00 -0000` |
| `h:X-Foo` | `headers` | Any header name; `h:Reply-To` folds into the dedicated `reply_to` field |
| `v:my-var` | `metadata` | |
| `X-ApexMail-Category` header | `category` | Validated by the canonical normalizer |
| `o:tracking=yes`, `o:tracking-clicks=yes`, `o:tracking-opens=yes`, `o:dkim=yes` | Accepted no-op | These match the platform defaults |
| `o:testmode=no` | Accepted no-op | Test mode is off, which is the platform behaviour |

## Fields the surface refuses by name

Each of these is a refusal in Mailgun's own error shape `{"message": "…"}` with status `400`, never a silent drop. Several issues in one request are joined into the single message.

| Mailgun construct | Refusal |
|---|---|
| `inline` file part | The canonical send path has no inline-part concept; attach the file instead of embedding it |
| `attachment` sent as a form value | Attachments must be sent as multipart/form-data file parts (`-F attachment=@file`), not as form values |
| `template` (stored templates) | Field has no canonical equivalent |
| `o:campaign` | Field has no canonical equivalent |
| `o:require-tls` | Field has no canonical equivalent |
| `o:skip-verification` | Field has no canonical equivalent |
| `o:tracking=no`, `o:tracking-clicks=no`, `o:tracking-opens=no`, `o:dkim=no` | This surface cannot disable the corresponding platform behaviour; tracking and DKIM signing are deployment-level settings |
| `o:testmode=yes` | The canonical send path has no per-message suppressed-delivery mode; use the platform test-mode surface instead of silently sending |
| Any other `o:*` field, and any unknown form field | No canonical equivalent on the Mailgun compatibility surface |
| `{domain}` that does not match the `from` domain | The path segment must equal the domain of the `from` address because the canonical send path signs with the sender domain |
| Header name sent twice, or two different `Reply-To` values | The duplicate is refused rather than resolved by picking one |

## What is not proxied yet

The compatibility surface serves the send route only. The Mailgun APIs below have no compat route; use the ApexMail native API or the dashboard for the capability.

- Raw MIME sends (`messages.mime`) and the `template` field for Mailgun-stored templates.
- Per-message delivery controls: `o:require-tls`, `o:skip-verification`, `o:dkim=no`, `o:tracking*=no`, `o:testmode=yes`.
- Campaigns (`o:campaign`), mailing lists, and the events/stats APIs.
- Route, domain, webhook and suppression APIs: suppressions live in ApexMail's suppression list; webhook subscriptions use `POST /v1/webhooks`.
- Inbound routing (Mailgun Routes) and stored-message retrieval.
- A batch endpoint on the compat surface; batch sends go through the native API (up to 100 per call).

## DNS: what changes and what stays

Your sending domain stays yours, and ApexMail signs DKIM with a selector generated per domain on that same domain. Add the four records from `GET /v1/domains/:id/dns-records` alongside the Mailgun records; remove the Mailgun records only after the cutover and the retention window.

| Mailgun record | ApexMail equivalent |
|---|---|
| DKIM record under `mx._domainkey` or the provider's DKIM host | Direct TXT record at `<selector>._domainkey.<domain>` with the DKIM public key. A direct TXT record, not a CNAME |
| Mailgun's return-path records (`include:mailgun.org` SPF mechanism, MX on the bounce subdomain) | TXT record at `bounce.<domain>` with the custom MAIL FROM SPF value, and MX record at `bounce.<domain>`, priority 10, pointing at the region's feedback host |
| Branded-link tracking CNAME | No branded-link CNAME required. ApexMail rewrites links to its own tracking paths; a custom tracking domain (CNAME at a subdomain of a verified domain) is available on Pro and above |
| Domain authentication | TXT record at `_dmarc.<domain>` with your DMARC policy |

Checklist:

1. Add the sending domain in the dashboard and fetch its DNS records.
2. Publish the four ApexMail records; leave the Mailgun records in place.
3. Keep the Mailgun return-path records for as long as Mailgun sends, because Mailgun's MAIL FROM domain is its own subdomain.
4. Run domain verification and confirm the DKIM selector resolves.
5. Keep DMARC reporting (rua) enabled through the transition.
6. After the cutover and retention window, remove the Mailgun records and revoke the old key.

## Templates

Mailgun-stored templates (`template` plus `t:variables`) are not proxied, and the field is refused by name. Two conversion paths:

- Render the body in your application and send `html` and `text` through the same compat route. No template migration work, and the send keeps its form fields.
- Create a template through `POST /v1/templates` and send it with `template_id` plus `template_data` on the native `POST /v1/messages`. Placeholders are written `{{variable}}`; an unresolved placeholder is rendered as-is rather than as an empty string, so a missing variable is visible in the preview.

Mailgun template variables travel as `t:name=value` form fields; on the compat route use `v:` metadata or render the values into the body, and move the variables to `template_data` when you adopt the native template API.

## Webhooks

Mailgun webhooks post JSON to your endpoint (`http-post` type). Point the endpoint at ApexMail, subscribe the events you consume, and verify the ApexMail signature: `X-ApexMail-Signature: sha256=<hex>` over the raw request body with `X-ApexMail-Timestamp`. Delivery is at-least-once, so deduplicate on the event `id` field.

| Mailgun event | ApexMail event | Notes |
|---|---|---|
| `accepted` | `message.accepted` | Accepted for delivery |
| `stored` | `message.queued` | Message entered the outbound queue |
| `delivered` | `message.delivered` | Recipient server accepted the message |
| `failed` with permanent severity | `message.bounced` | Hard bounce |
| `failed` with temporary severity | `message.deferred` | 4xx deferral; a retry is scheduled |
| `rejected` | `message.suppressed` | Suppression list or policy refusal |
| `opened` | `message.opened` | |
| `clicked` | `message.clicked` | |
| `complained` | `message.complained` | |
| `unsubscribed` | `recipient.unsubscribed` | |

The payload shape changes with the provider: ApexMail events use the envelope `{id, event, timestamp, data}`, with `data.messageId` on message events and `data.email` on suppression events.

## Cutover plan

The cutover is a host swap per route or per environment, so a rollback is the same swap in reverse. There is no form-field or template rewrite to unwind.

| Step | Action | Exit criteria | Rollback |
|---|---|---|---|
| 1. Provision | Create the account, add and verify the sending domain, create an API key with `messages:send`, subscribe webhook events | Verification passes; a test message sends from a staging environment | No production traffic yet |
| 2. Validate in parallel | Send the same form payloads to `https://api.apexmail.ee/v3/{domain}/messages` with the ApexMail key in the Basic slot; compare responses, ids and webhook events | `200` with the `Queued. Thank you.` body on every test; events arrive with valid signatures | Point the test route back at Mailgun |
| 3. Shift 10% | Route 10% of production sends through the compat route; watch bounce and complaint rates against the AUP thresholds (2% bounce, 0.1% complaint) | Delivery metrics match Mailgun within the agreed tolerance for the observation window | Swap the route back; Mailgun still holds the other 90% |
| 4. Shift 50% | Raise the share to 50% once the window closes clean; keep both providers sending from the same domain | Sustained parity at the higher share | Swap back to 100% Mailgun |
| 5. Cut over to 100% | Route all sends through `POST /v3/{domain}/messages` on ApexMail | Full volume on ApexMail with clean metrics | Swap back; keys stay active during the retention window |
| 6. Retire the old path | Remove the Mailgun DNS records, revoke its key, retire stored-template configuration | Records resolve to ApexMail only | Restore the records from your change record |

## Next steps

- Compare the two platforms feature by feature on the [ApexMail vs Mailgun comparison](/compare/mailgun/).
- Read the [API overview](/docs/api/) and the [OpenAPI specification](/docs/api/openapi/) for the native contract, including batch sends and templates.
- Read [Webhooks](/docs/webhooks/) for the event payload schemas and signature verification.
- [Contact sales](/contact/sales/) for a migration assessment if a raw MIME route or stored templates are part of your production traffic.
