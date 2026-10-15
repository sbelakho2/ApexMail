+++
title = "Migrate from Resend to ApexMail"
description = "Move a Resend integration to ApexMail by changing the base URL: POST /emails and POST /emails/batch accept your ApexMail API key in the Authorization bearer slot you already send, with the exact field mapping, named refusals, the DNS checklist and a 10/50/100 cutover plan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail serves `POST /emails` and `POST /emails/batch` on a Resend compatibility surface. The routes translate the JSON payloads into the canonical send request and then call the same handlers `POST /v1/messages` and `POST /v1/messages/batch` use, so sender-domain verification, suppression and consent gates, plan entitlements, the durable idempotency ledger and the queue insert all run in one place. Your integration keeps its payload shape and bearer header; the switch is the host and the key.

## Endpoint mapping

| Resend endpoint | ApexMail compatibility surface | ApexMail native endpoint |
|---|---|---|
| `POST https://api.resend.com/emails` | `POST https://api.apexmail.ee/emails` | `POST https://api.apexmail.ee/v1/messages` |
| `POST https://api.resend.com/emails/batch` | `POST https://api.apexmail.ee/emails/batch`, up to 100 emails | `POST https://api.apexmail.ee/v1/messages/batch`, up to 100 messages per call |
| `GET /emails/:id` (retrieve) | Not served | `GET /v1/messages/{id}` |

A successful send answers `200` with `{"id": "<canonical message id>"}`. The batch route answers `{"data": […]}` in request order: each position carries either `{"id": …}` or an `error` object with the refusal, so a partial batch is never reported as a full success. The id is the canonical message id, the same id `GET /v1/messages/{id}` returns and the same id webhook events carry in `data.messageId`.

## Auth swap

Your credential slot stays. Resend sends `Authorization: Bearer`; replace the key with the ApexMail API key (`am_live_…` or `am_test_…`) and give it the `messages:send` scope.

| Item | Resend today | ApexMail compatibility surface |
|---|---|---|
| Credential header | `Authorization: Bearer re_…` | `Authorization: Bearer am_live_…` |
| Scope | Full access or sending-only key | `messages:send` |
| Idempotency | `Idempotency-Key` header | The same header, against ApexMail's durable ledger; the same key within 24 hours replays the original response, including the same id |
| Subject class | Not a provider concept | `X-ApexMail-Category: transactional` (or `service`) makes the send exempt from the marketing preference gate; without the header the send counts as the default `marketing` class and the consent gate applies |

## Field mapping

Canonical field names are the `POST /v1/messages` contract, so the same payload understanding applies after a later move to the native API.

| Resend field | Canonical field | Notes |
|---|---|---|
| `from` | `from` | Required |
| `to` | `to` | A single string, an array, or `{email, name}` objects |
| `cc` / `bcc` | `cc` / `bcc` | |
| `subject` | `subject` | |
| `html` / `text` | `html` / `text` | |
| `reply_to` | `reply_to` | |
| `headers` (object) | `headers` | String values |
| `attachments[].filename` / `.content` / `.content_type` | `attachments[]` (`filename`, `content`, `contentType`) | `content_type` defaults to `application/octet-stream` |
| `tags[].name` / `.value` | `tags` | Each pair becomes `"name:value"` |
| `scheduled_at` (ISO 8601) | `scheduled_at` | RFC 3339 timestamps only |
| `X-ApexMail-Category` header | `category` | Validated by the canonical normalizer |

## Fields the surface refuses by name

Each of these is a refusal in Resend's own error shape `{"statusCode": <code>, "name": "<name>", "message": "…"}` with `statusCode` 422 and `name` `validation_error` for validation refusals, `401` `invalid_api_key` or `missing_api_key` for credential refusals, and `403` `restricted_api_key` for a key without the `messages:send` scope.

| Resend construct | Refusal |
|---|---|
| `attachments[].path` | Remote attachment URLs are not fetched; send the file as base64 `content` |
| `template` | Templates have no canonical equivalent on this surface; use the ApexMail native API for templates |
| `topic_id`, `audience_id`, `broadcast_id` | Audiences, topics and broadcasts have no canonical equivalent on this surface; use the native API for lists |
| A natural-language `scheduled_at` (`"in 1 min"`) | An ISO 8601 timestamp (RFC 3339) is required; natural-language schedules are not supported |
| A batch array longer than 100 emails | A Resend batch carries at most 100 emails |
| Any other top-level field | No canonical equivalent |

## What is not proxied yet

The compatibility surface serves the two send routes. The Resend APIs below have no compat route; use the ApexMail native API or the dashboard for the capability.

- Templates (`template`) and the rendered-template path.
- Audiences, contacts, topics and broadcasts; ApexMail campaigns, lists and segments cover these through the native API.
- Domain management (`/domains`): domains are added and verified in the ApexMail dashboard or through `POST /v1/domains`.
- API key management, webhook subscription CRUD and the events log; webhook subscriptions use `POST /v1/webhooks`.
- Attachment fetching from a remote URL, and natural-language scheduling.
- Inbound receiving (`email.received`). ApexMail's inbound pipeline emits the `inbound` event, and inbound email is available on Business and Enterprise Cloud.

## DNS: what changes and what stays

Your sending domain stays yours, and ApexMail signs DKIM with a selector generated per domain on that same domain. Add the four records from `GET /v1/domains/:id/dns-records` alongside the Resend records; remove the Resend records only after the cutover and the retention window.

| Resend record | ApexMail equivalent |
|---|---|
| DKIM record (the provider's TXT record for the domain) | Direct TXT record at `<selector>._domainkey.<domain>` with the DKIM public key. A direct TXT record, not a CNAME |
| Return-path records (the provider's MX and SPF TXT records on its own subdomain) | MX record at `bounce.<domain>`, priority 10, pointing at the region's feedback host, plus a TXT record at `bounce.<domain>` with the custom MAIL FROM SPF value |
| Click-tracking CNAME (when tracking uses your domain) | No branded-link CNAME required. ApexMail rewrites links to its own tracking paths; a custom tracking domain (CNAME at a subdomain of a verified domain) is available on Pro and above |
| Domain authentication | TXT record at `_dmarc.<domain>` with your DMARC policy |

Checklist:

1. Add the sending domain in the dashboard and fetch its DNS records.
2. Publish the four ApexMail records; leave the Resend records in place.
3. Keep the Resend records for as long as Resend sends; its return-path subdomain records are independent of ApexMail's `bounce.<domain>` records.
4. Run domain verification and confirm the DKIM selector resolves.
5. Keep DMARC reporting (rua) enabled through the transition.
6. After the cutover and retention window, remove the Resend records and revoke the old key.

## Templates

Resend templates are not proxied, and `template` is refused by name. Two conversion paths:

- Render the body in your application and send `html` and `text` through the same compat route. No template migration work, and the send keeps its payload shape.
- Create a template through `POST /v1/templates` and send it with `template_id` plus `template_data` on the native `POST /v1/messages`. Placeholders are written `{{variable}}`; an unresolved placeholder is rendered as-is rather than as an empty string, so a missing variable is visible in the preview.

Resend's `{{{variable}}}` triple-brace form and its React Email components render in your application or in your build step; the placeholder renderer accepts `{{variable}}` substitution, so convert those bodies to HTML before creating the ApexMail template.

## Webhooks

Point your endpoint at ApexMail, subscribe the events you consume, and verify the ApexMail signature: `X-ApexMail-Signature: sha256=<hex>` over the raw request body with `X-ApexMail-Timestamp`. Delivery is at-least-once, so deduplicate on the event `id` field.

| Resend event | ApexMail event | Notes |
|---|---|---|
| `email.sent` | `message.accepted` | Accepted for delivery |
| `email.scheduled` | `message.accepted` | The scheduled send is accepted at enqueue time |
| `email.delivered` | `message.delivered` | Recipient server accepted the message |
| `email.delivery_delayed` | `message.deferred` | 4xx deferral; a retry is scheduled |
| `email.bounced` | `message.bounced` | Hard bounce |
| `email.complained` | `message.complained` | |
| `email.opened` | `message.opened` | |
| `email.clicked` | `message.clicked` | |
| `email.failed` (nearest mapping) | `message.bounced` | Acceptance-time refusals come back on the API response instead of an event |
| `email.received` | `inbound` | Inbound email is available on Business and Enterprise Cloud |

The payload shape changes with the provider: ApexMail events use the envelope `{id, event, timestamp, data}`, with `data.messageId` on message events and `data.email` on suppression events.

## Cutover plan

The cutover is a host swap per route or per environment, so a rollback is the same swap in reverse. There is no payload or template rewrite to unwind.

| Step | Action | Exit criteria | Rollback |
|---|---|---|---|
| 1. Provision | Create the account, add and verify the sending domain, create an API key with `messages:send`, subscribe webhook events | Verification passes; a test message sends from a staging environment | No production traffic yet |
| 2. Validate in parallel | Send the same payloads to `https://api.apexmail.ee/emails` with the ApexMail key in the bearer slot; compare responses, ids and webhook events | `200` with an id on every test; events arrive with valid signatures | Point the test route back at Resend |
| 3. Shift 10% | Route 10% of production sends through the compat route; watch bounce and complaint rates against the AUP thresholds (2% bounce, 0.1% complaint) | Delivery metrics match Resend within the agreed tolerance for the observation window | Swap the route back; Resend still holds the other 90% |
| 4. Shift 50% | Raise the share to 50% once the window closes clean; keep both providers sending from the same domain | Sustained parity at the higher share | Swap back to 100% Resend |
| 5. Cut over to 100% | Route all sends through `POST /emails` (and `/emails/batch`) on ApexMail | Full volume on ApexMail with clean metrics | Swap back; keys stay active during the retention window |
| 6. Retire the old path | Remove the Resend DNS records, revoke its key, retire template and audience configuration | Records resolve to ApexMail only | Restore the records from your change record |

## Next steps

- Compare the two platforms feature by feature on the [ApexMail vs Resend comparison](/compare/resend/).
- Read the [API overview](/docs/api/) and the [OpenAPI specification](/docs/api/openapi/) for the native contract, including batch sends and templates.
- Read [Webhooks](/docs/webhooks/) for the event payload schemas and signature verification.
- [Contact sales](/contact/sales/) for a migration assessment if Resend templates, audiences or broadcasts are part of your production traffic.
