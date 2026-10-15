+++
title = "Migrate from SendGrid to ApexMail"
description = "Move a SendGrid integration to ApexMail by changing the base URL: the compatibility surface serves POST /v3/mail/send with an ApexMail API key in the same Authorization header, with the field mapping, named refusals, DNS checklist, webhook names and a 10/50/100 cutover plan."
template = "prose.html"

[extra]
last_updated = "2026-10-15"
og_image = "/images/og-image.png"
+++

ApexMail serves `POST /v3/mail/send` on a SendGrid compatibility surface. The route translates the SendGrid payload into the canonical send request and then calls the same handler `POST /v1/messages` uses, so sender-domain verification, suppression and consent gates, plan entitlements, the idempotency ledger and the queue insert all run in one place. Your integration keeps its request shape; the switch is the base URL and the key.

## Endpoint mapping

| SendGrid endpoint | ApexMail compatibility surface | ApexMail native endpoint |
|---|---|---|
| `POST https://api.sendgrid.com/v3/mail/send` | `POST https://api.apexmail.ee/v3/mail/send` | `POST https://api.apexmail.ee/v1/messages` |
| No batch endpoint in this surface | One request per message | `POST https://api.apexmail.ee/v1/messages/batch`, up to 100 messages per call |

A successful compat send answers `202 Accepted` with an empty body and the canonical message id in `X-Message-Id`. That id is the same id `GET /v1/messages/{id}` returns and the same id webhook events carry in `data.messageId`.

One `personalizations` entry per request: the surface maps exactly one. A payload with several personalizations is refused by name rather than sent with dropped subject or header values.

## Auth swap

Your key slot stays. Send the ApexMail API key (`am_live_…` or `am_test_…`) where the SendGrid key went, and give the key the `messages:send` scope that `POST /v1/messages` also requires.

| Item | SendGrid today | ApexMail compatibility surface |
|---|---|---|
| Credential header | `Authorization: Bearer SG.…` | `Authorization: Bearer am_live_…` |
| Scope | Key permissions | `messages:send` |
| Idempotency | Not offered | `Idempotency-Key: <uuid>` on the same route; the same key within 24 hours replays the original response, including the same `X-Message-Id` |
| Subject class | Not a provider concept | `X-ApexMail-Category: transactional` (or `service`) makes the send exempt from the marketing preference gate; without the header the send counts as the default `marketing` class and the consent gate applies |

## Field mapping

Canonical field names are the `POST /v1/messages` contract, so the same payload understanding applies after a later move to the native API.

| SendGrid field | Canonical field | Notes |
|---|---|---|
| `from` (`{email, name}` or string) | `from` | `"Name <addr>"` when a name is present |
| `personalizations[0].to[]` | `to` | Required; addr-spec strings, `"Name <addr>"` strings, and `{email, name}` objects are all accepted |
| `personalizations[0].cc[]` / `.bcc[]` | `cc` / `bcc` | |
| `personalizations[0].subject` (else top-level `subject`) | `subject` | The personalization value wins when both are present |
| `personalizations[0].headers` merged under top-level `headers` | `headers` | A header set in both places with different values is refused |
| `content[]` with `type` `text/plain` / `text/html` | `text` / `html` | Exactly one part of each type |
| `attachments[].content`, `.filename`, `.type` | `attachments[]` (`filename`, `content`, `contentType`) | `type` defaults to `application/octet-stream` |
| `categories[]` and `X-SMTPAPI` `category`/`categories` | `tags` | Duplicate tags are deduplicated |
| `custom_args` and `X-SMTPAPI` `unique_args` | `metadata` | String values only; a key set in both places with different values is refused |
| `reply_to` | `reply_to` | |
| `send_at` (unix seconds) | `scheduled_at` | |
| `X-ApexMail-Category` header | `category` | Validated by the canonical normalizer |
| `mail_settings.sandbox_mode.enable = false` | Accepted no-op | The documented SDK default |

## Fields the surface refuses by name

Each of these is a refusal in SendGrid's own error shape `{"errors": [{"message", "field", "help"}]}`, never a silent drop. The canonical 400/422 pair is rendered as SendGrid's `400`.

| SendGrid construct | Refusal |
|---|---|
| More than one `personalizations` entry | `more than one 'personalizations' entry is not supported by the ApexMail compatibility surface: per-personalization subject/headers would be dropped — send one request per personalization` |
| `personalizations[].substitutions`, `.dynamic_template_data` | Field has no canonical equivalent |
| `template_id`, `dynamic_template_data` | SendGrid template ids are not ApexMail template ids |
| `attachments[].content_id`, `disposition: "inline"` | The canonical send path has no inline-part concept; attach the file instead of embedding it |
| `content[].type` other than `text/plain` and `text/html` | Only those two parts have a canonical equivalent |
| `asm`, `batch_id`, `ip_pool_name` | No canonical equivalent |
| `mail_settings.*` other than the sandbox no-op | No canonical equivalent |
| `mail_settings.sandbox_mode.enable = true` | No per-message sandbox; use the platform test-mode surface |
| `tracking_settings.*` | No canonical equivalent |
| `X-SMTPAPI` keys other than `category`, `categories`, `unique_args` | No canonical equivalent |
| Any other top-level field | No canonical equivalent |

## What is not proxied yet

The compatibility surface serves the send route only. The SendGrid APIs below have no compat route; use the ApexMail native API or the dashboard for the capability.

- Template storage and rendering (`/v3/templates`, Handlebars `dynamic_template_data`) — see the template section below.
- Suppression management (`/v3/asm/*`, `bypass_list_management`): suppressions live in ApexMail's suppression list, managed in the dashboard or through the native API.
- Stats, message activity and email validation APIs.
- Marketing contacts, lists and single-send campaign APIs.
- Inbound Parse.
- Per-message sandbox mode, per-message tracking toggles and multiple personalizations.

## DNS: what changes and what stays

Your sending domain stays yours, and ApexMail signs DKIM with a selector generated per domain on that same domain. Add the four records from `GET /v1/domains/:id/dns-records` alongside the SendGrid records; remove the SendGrid records only after the cutover and the retention window.

| SendGrid record | ApexMail equivalent |
|---|---|
| DKIM CNAME pair (`s1._domainkey`, `s2._domainkey`) | Direct TXT record at `<selector>._domainkey.<domain>` with the DKIM public key. A direct TXT record, not a CNAME |
| Link branding CNAME (`url…`) | No branded-link CNAME required. ApexMail rewrites links to its own tracking paths; a custom tracking domain (CNAME at a subdomain of a verified domain) is available on Pro and above |
| Bounce domain CNAME | MX record at `bounce.<domain>`, priority 10, pointing at the region's feedback host, plus a TXT record at `bounce.<domain>` with the custom MAIL FROM SPF value |
| Domain authentication | TXT record at `_dmarc.<domain>` with your DMARC policy |

Checklist:

1. Add the sending domain in the dashboard and fetch its DNS records.
2. Publish the four ApexMail records; leave the SendGrid records in place.
3. Keep the root-domain SPF record as it is for as long as SendGrid sends. ApexMail's SPF value lives on the `bounce.<domain>` subdomain (the custom MAIL FROM), so it does not need an entry in the root record.
4. Run domain verification and confirm the DKIM selector resolves.
5. Keep DMARC reporting (rua) enabled through the transition.
6. After the cutover and retention window, remove the SendGrid CNAMEs and any SendGrid mechanism from your records.

## Templates

SendGrid template ids are not ApexMail template ids, and `template_id` with `dynamic_template_data` is refused by name on the compat route. Two conversion paths:

- Render the body in your application and send it as `content[]` through the same compat route. No template migration work, and the send keeps its request shape.
- Create a template through `POST /v1/templates` and send it with `template_id` plus `template_data` on the native `POST /v1/messages`. Placeholders are written `{{variable}}`; an unresolved placeholder is rendered as-is rather than as an empty string, so a missing variable is visible in the preview.

Handlebars helpers (conditionals, loops, `{{#each}}`) have no direct equivalent in the placeholder renderer; convert those templates to rendered HTML in your application or split them into per-case templates.

## Webhooks

Point your endpoint at ApexMail, subscribe the events you consume, and verify the ApexMail signature: `X-ApexMail-Signature: sha256=<hex>` over the raw request body with `X-ApexMail-Timestamp`. Delivery is at-least-once, so deduplicate on the event `id` field.

| SendGrid event | ApexMail event | Notes |
|---|---|---|
| `processed` | `message.accepted` | Accepted for delivery |
| `delivered` | `message.delivered` | Recipient server accepted the message |
| `bounce` | `message.bounced` | Hard bounce |
| `deferred` | `message.deferred` | 4xx deferral; a retry is scheduled |
| `dropped` | `message.suppressed` | Recipient on the suppression list |
| `open` | `message.opened` | |
| `click` | `message.clicked` | |
| `spamreport` | `message.complained` | |
| `unsubscribe`, `group_unsubscribe` | `recipient.unsubscribed` | |
| `group_resubscribe` | No equivalent event | Re-subscribe is recorded on the preference record, not as an event |

## Cutover plan

The cutover is a base-URL swap per route or per environment, so a rollback is the same swap in reverse. There is no payload or template rewrite to unwind.

| Step | Action | Exit criteria | Rollback |
|---|---|---|---|
| 1. Provision | Create the account, add and verify the sending domain, create an API key with `messages:send`, subscribe webhook events | Verification passes; a test message sends from a staging environment | No production traffic yet |
| 2. Validate in parallel | Send the same payloads to `https://api.apexmail.ee/v3/mail/send` with the ApexMail key; compare responses, ids and webhook events | `202` with `X-Message-Id` on every test; events arrive with valid signatures | Point the test route back at SendGrid |
| 3. Shift 10% | Route 10% of production sends through the compat route; watch bounce and complaint rates against the AUP thresholds (2% bounce, 0.1% complaint) | Delivery metrics match SendGrid within the agreed tolerance for the observation window | Swap the route back; SendGrid still holds the other 90% |
| 4. Shift 50% | Raise the share to 50% once the window closes clean; keep both providers sending from the same domain | Sustained parity at the higher share | Swap back to 100% SendGrid |
| 5. Cut over to 100% | Route all sends through `POST /v3/mail/send` on ApexMail | Full volume on ApexMail with clean metrics | Swap back; keys stay active during the retention window |
| 6. Retire the old path | Remove the SendGrid CNAMEs and SPF mechanism, revoke its key, delete leftover template configuration | Records resolve to ApexMail only | Restore the records from your change record |

## Next steps

- Compare the two platforms feature by feature on the [ApexMail vs SendGrid comparison](/compare/sendgrid/).
- Read the [API overview](/docs/api/) and the [OpenAPI specification](/docs/api/openapi/) for the native contract, including batch sends and templates.
- Read [Webhooks](/docs/webhooks/) for the event payload schemas and signature verification.
- [Contact sales](/contact/sales/) for a migration assessment if the refused constructs above are part of your production traffic.
