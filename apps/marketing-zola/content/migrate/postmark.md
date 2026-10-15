+++
title = "Migrate from Postmark to ApexMail"
description = "Move a Postmark integration to ApexMail by changing the base URL: POST /email and POST /email/batch accept your ApexMail API key in the X-Postmark-Server-Token header, with MessageStream mapping, named refusals, the DNS checklist and a 10/50/100 cutover plan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail serves `POST /email` and `POST /email/batch` on a Postmark compatibility surface. The routes translate the JSON payloads into the canonical send request and then call the same handlers `POST /v1/messages` and `POST /v1/messages/batch` use, so sender-domain verification, suppression and consent gates, plan entitlements, the idempotency ledger and the queue insert all run in one place. Your integration keeps its payload shape and header; the switch is the host and the token.

## Endpoint mapping

| Postmark endpoint | ApexMail compatibility surface | ApexMail native endpoint |
|---|---|---|
| `POST https://api.postmarkapp.com/email` | `POST https://api.apexmail.ee/email` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.postmarkapp.com/email/batch` | `POST https://api.apexmail.ee/email/batch`, up to 500 messages | `POST https://api.apexmail.ee/v1/messages/batch`, up to 100 messages per call |
| `POST /email/bulk` (template-driven bulk) | Not served | `POST /v1/messages/batch` with explicit bodies, or a template id per message |

A successful send answers `200` with `{"ErrorCode": 0, "Message": "OK", "MessageID": "<canonical message id>"}`. The batch route answers an ordered array with one result object per requested message: `ErrorCode` 0 with the `MessageID`, or a non-zero `ErrorCode` carrying the refusal text for that item, so a partial batch is never reported as a full success. The message id is the canonical id, the same id `GET /v1/messages/{id}` returns and the same id webhook events carry in `data.messageId`.

## Auth swap

Your credential slot stays. Postmark sends `X-Postmark-Server-Token`; replace the value with the ApexMail API key (`am_live_…` or `am_test_…`) and give it the `messages:send` scope.

| Item | Postmark today | ApexMail compatibility surface |
|---|---|---|
| Credential header | `X-Postmark-Server-Token: <server token>` | `X-Postmark-Server-Token: am_live_…` |
| Scope | Server-level token | `messages:send` |
| Idempotency | Not offered | `Idempotency-Key: <uuid>` on the same route; the same key within 24 hours replays the original response, including the same `MessageID` |
| Subject class | `MessageStream` selects the stream | `MessageStream` `outbound` maps to `transactional` and `broadcast` to `marketing`; the `X-ApexMail-Category` header also works and accepts `transactional`, `service` or `marketing` |

## Field mapping

Canonical field names are the `POST /v1/messages` contract, so the same payload understanding applies after a later move to the native API.

| Postmark field | Canonical field | Notes |
|---|---|---|
| `From` | `from` | Required |
| `To` | `to` | Comma-separated string or an array; quoted display names keep their commas |
| `Cc` / `Bcc` | `cc` / `bcc` | |
| `Subject` | `subject` | |
| `HtmlBody` / `TextBody` | `html` / `text` | |
| `ReplyTo` | `reply_to` | |
| `Headers[].Name` / `.Value` | `headers` | `Reply-To` folds into the dedicated `reply_to` field |
| `Attachments[].Name` / `.Content` / `.ContentType` | `attachments[]` (`filename`, `content`, `contentType`) | `ContentType` defaults to `application/octet-stream` |
| `Tag` | `tags` (one tag) | |
| `Metadata` (string values) | `metadata` | Non-string values are refused by name |
| `MessageStream` `outbound` / `broadcast` | `category` `transactional` / `marketing` | |
| `TrackOpens` / `TrackLinks` `true` | Accepted no-op | The platform tracks opens and clicks for every send |
| `X-ApexMail-Category` header | `category` | Validated by the canonical normalizer |

A scheduled send is not part of this surface: Postmark's payload has no scheduling field, so the compat route has none either. Use `scheduled_at` (ISO 8601) on the native `POST /v1/messages`.

## Fields the surface refuses by name

Each of these is a refusal in Postmark's own error shape `{"ErrorCode": <code>, "Message": "…"}`. Validation refusals answer `422`; a missing or invalid token answers `401` with `ErrorCode` 10.

| Postmark construct | Refusal |
|---|---|
| `TemplateId`, `TemplateAlias` | A Postmark template id is not an ApexMail template id; render the body client-side or send an ApexMail `template_id` through the native API |
| `TemplateModel` | The canonical send path has no equivalent for this field |
| `InlineImages`, `Attachments[].ContentID` | The canonical send path has no inline-part concept; attach the file instead of embedding it |
| `TrackOpens: false`, `TrackLinks: false` | The platform tracks opens and clicks for every send; per-message tracking cannot be disabled on this surface |
| Any other `MessageStream` value | Only `outbound` (transactional) and `broadcast` (marketing) map onto the canonical category |
| A batch array longer than 500 messages | A Postmark batch carries at most 500 messages |
| Any other top-level field | No canonical equivalent |
| A non-string value in `Metadata` | Metadata values must be strings |
| `Headers[].Name` sent twice | The duplicate header is refused rather than resolved by picking one |

## What is not proxied yet

The compatibility surface serves the two send routes. The Postmark APIs below have no compat route; use the ApexMail native API or the dashboard for the capability.

- Templates and layouts (`/templates`, `TemplateModel` rendering).
- Message streams administration and per-server configuration.
- Outbound message search, stats and bounce endpoints; bounce data arrives through `message.bounced` events instead.
- The `/email/bulk` endpoint (template-driven bulk sends).
- Inbound webhook configuration. ApexMail's inbound pipeline emits the `inbound` event, and inbound email is available on Business and Enterprise Cloud.
- Suppression management through Postmark's API; suppressions live in ApexMail's suppression list.

## DNS: what changes and what stays

Your sending domain stays yours, and ApexMail signs DKIM with a selector generated per domain on that same domain. Add the four records from `GET /v1/domains/:id/dns-records` alongside the Postmark records; remove the Postmark records only after the cutover and the retention window.

| Postmark record | ApexMail equivalent |
|---|---|
| DKIM record (the TXT or CNAME pair the provider issues per server) | Direct TXT record at `<selector>._domainkey.<domain>` with the DKIM public key. A direct TXT record, not a CNAME |
| Return-path CNAME (the provider's bounce domain) | MX record at `bounce.<domain>`, priority 10, pointing at the region's feedback host, plus a TXT record at `bounce.<domain>` with the custom MAIL FROM SPF value |
| Branded-link tracking CNAME (when link tracking uses your domain) | No branded-link CNAME required. ApexMail rewrites links to its own tracking paths; a custom tracking domain (CNAME at a subdomain of a verified domain) is available on Pro and above |
| Domain authentication | TXT record at `_dmarc.<domain>` with your DMARC policy |

Checklist:

1. Add the sending domain in the dashboard and fetch its DNS records.
2. Publish the four ApexMail records; leave the Postmark records in place.
3. Keep the Postmark records for as long as Postmark sends. Postmark's MAIL FROM domain is provider-specific, so its records are independent of ApexMail's `bounce.<domain>` records.
4. Run domain verification and confirm the DKIM selector resolves.
5. Keep DMARC reporting (rua) enabled through the transition.
6. After the cutover and retention window, remove the Postmark records and revoke the old server token.

## Templates

Postmark templates, layouts and aliases are not proxied, and `TemplateId`, `TemplateAlias` and `TemplateModel` are refused by name. Two conversion paths:

- Render the body in your application and send `HtmlBody` and `TextBody` through the same compat route. No template migration work, and the send keeps its payload shape.
- Create a template through `POST /v1/templates` and send it with `template_id` plus `template_data` on the native `POST /v1/messages`. Placeholders are written `{{variable}}`; an unresolved placeholder is rendered as-is rather than as an empty string, so a missing variable is visible in the preview.

Postmark layouts (a shared wrapper around message templates) map to the template body itself: fold the layout HTML into each ApexMail template, or keep rendering in your application. Mustachio conditionals and loops have no direct equivalent in the placeholder renderer; convert those templates to rendered HTML in your application or split them into per-case templates.

## Webhooks

Postmark webhooks post JSON to your endpoint per message stream. Point the endpoint at ApexMail, subscribe the events you consume, and verify the ApexMail signature: `X-ApexMail-Signature: sha256=<hex>` over the raw request body with `X-ApexMail-Timestamp`. Delivery is at-least-once, so deduplicate on the event `id` field.

| Postmark webhook | ApexMail event | Notes |
|---|---|---|
| `Delivery` | `message.delivered` | Recipient server accepted the message |
| `Bounce` with `Type: HardBounce` | `message.bounced` | Hard bounce |
| `Bounce` with `Type: Transient` | `message.deferred` | 4xx deferral; a retry is scheduled |
| `SpamComplaint` | `message.complained` | |
| `Open` | `message.opened` | |
| `Click` | `message.clicked` | |
| `SubscriptionChange` | `recipient.unsubscribed` | ApexMail emits the unsubscribe direction; re-subscribes are recorded on the preference record |
| `Inbound` | `inbound` | Inbound email is available on Business and Enterprise Cloud |
| `SMTPAPIError` | No event equivalent | Acceptance-time refusals come back on the API response instead |

The payload shape changes with the provider: ApexMail events use the envelope `{id, event, timestamp, data}`, with `data.messageId` on message events and `data.email` on suppression events.

## Cutover plan

The cutover is a host swap per route or per environment, so a rollback is the same swap in reverse. There is no payload or template rewrite to unwind.

| Step | Action | Exit criteria | Rollback |
|---|---|---|---|
| 1. Provision | Create the account, add and verify the sending domain, create an API key with `messages:send`, subscribe webhook events | Verification passes; a test message sends from a staging environment | No production traffic yet |
| 2. Validate in parallel | Send the same payloads to `https://api.apexmail.ee/email` with the ApexMail key in `X-Postmark-Server-Token`; compare responses, `MessageID` values and webhook events | `ErrorCode` 0 on every test; events arrive with valid signatures | Point the test route back at Postmark |
| 3. Shift 10% | Route 10% of production sends through the compat route; watch bounce and complaint rates against the AUP thresholds (2% bounce, 0.1% complaint) | Delivery metrics match Postmark within the agreed tolerance for the observation window | Swap the route back; Postmark still holds the other 90% |
| 4. Shift 50% | Raise the share to 50% once the window closes clean; keep both providers sending from the same domain | Sustained parity at the higher share | Swap back to 100% Postmark |
| 5. Cut over to 100% | Route all sends through `POST /email` (and `/email/batch`) on ApexMail | Full volume on ApexMail with clean metrics | Swap back; tokens stay active during the retention window |
| 6. Retire the old path | Remove the Postmark DNS records, revoke the server token, retire template and stream configuration | Records resolve to ApexMail only | Restore the records from your change record |

## Next steps

- Compare the two platforms feature by feature on the [ApexMail vs Postmark comparison](/compare/postmark/).
- Read the [API overview](/docs/api/) and the [OpenAPI specification](/docs/api/openapi/) for the native contract, including batch sends and templates.
- Read [Webhooks](/docs/webhooks/) for the event payload schemas and signature verification.
- [Contact sales](/contact/sales/) for a migration assessment if Postmark templates or inbound webhooks are part of your production traffic.
