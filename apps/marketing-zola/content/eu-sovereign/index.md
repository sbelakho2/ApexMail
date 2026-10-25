+++
title = "EU Sovereignty | Built in Europe, Operated Under EU Law"
description = "How ApexMail's EU-sovereign position actually works: an Estonian company under EU law, EU data centres, the fail-closed EU-only routing mode, Ed25519-signed routing receipts, and the subprocessor chain EU-only removes — every claim linked to its evidence."
template = "prose.html"

[extra]
last_updated = "2026-10-16"
og_image = "/images/og-image.png"
mkt_page_mode = "trust"
+++

## The promise, and the honest boundary

ApexMail is an EU company (Bel Consulting OÜ, Tallinn, Estonia). The shared cloud runs on EU data centres (Germany primary, Finland backup). EU-only routing is a real, one-setting mode: every send leaves through ApexMail's own EU MTAs, a send with no own-MTA route is held rather than rerouted, and every accepted message carries an Ed25519-signed routing receipt that any third party can verify against the published public key.

The honest boundary belongs on the same screen: ApexMail's **default** routing is Global, and Global sends are delivered through Amazon Web Services' SES in its configured EU region — an EU region of a US company, covered by the AWS Data Processing Agreement and, where applicable, EU Standard Contractual Clauses. The sentence "your mail never touches a US-controlled provider" is true **under EU-only routing**; it is not true of a Global account, and this site does not claim it platform-wide. The [data location matrix](/data-locations/) states the same scope for storage as this page states for transport.

## An EU company under EU law

The contracting entity is Bel Consulting OÜ (trading as ApexMail), registered in Estonia — registry code 16588745, VAT EE102951727, Sakala tn 7-2, 10141 Tallinn. The governing law of ApexMail's contracts is Estonian law, and the agreed court jurisdiction is the Harju County Court, Tallinn, Estonia. That legal identity is rendered from one canonical record on every page of this site.

Evidence: the [Terms](/terms/) name the contracting entity and governing law; the [DPA](/dpa/) is the Article 28 processing agreement; the [Privacy Policy](/privacy/) states the controller/processor roles; the [About](/about/) page carries the company's registration details.

## EU data centres

The default shared deployment runs on Hetzner Online GmbH infrastructure in Germany (primary) and Finland (backup). Core service data — account data, hashed API keys, sender and recipient addresses, message content, attachments, delivery events and logs, support tickets, analytics and backups — is processed and replicated inside the EEA, with no third-country transfer for those categories. The genuine exceptions are named rather than hidden: optional OAuth sign-in (Google, GitHub) and payment processing (Mollie B.V.) are separated out in the matrix with their own transfer safeguards.

Evidence: the [data location matrix](/data-locations/) lists the primary, backup and processing region for each data category; the [subprocessor register](/subprocessors/) names the entities and their processing and storage countries.

### Payment processor

Mollie B.V. is a payment institution supervised by De Nederlandsche Bank (DNB), with its registered office at Keizersgracht 126, 1015 CW Amsterdam, The Netherlands. Payment data is processed in the Netherlands (EU); card-scheme networks may process it globally under Mollie's Data Processing Agreement.

## EU-only routing: one setting, fail-closed

EU-only routing is the tenant routing mode (`routingMode`, stored as `global` or `eu_only`). Under `eu_only`, every send must leave through ApexMail's **own relay MTAs**; the shared third-party transport (AWS SES) is forbidden for that tenant and the code contains no input that yields a third-party route in EU-only mode.

What happens when the own-MTA route is unavailable is the part that makes the mode a promise rather than a preference: **the message is held** — deferred in queue with a named reason, visible and releasable — it is never failed over to the third-party transport. The same discipline applies when the row's config is unreadable: a stored routing value that cannot be parsed as `global` is read as `eu_only`, because a held message is recoverable and a wrongly routed one is not.

What changes versus Global, plainly:

| | Global (default) | EU-only |
|---|---|---|
| Dedicated-IP sends | ApexMail's own relay MTAs | ApexMail's own relay MTAs |
| Everything else | Shared pool — AWS SES in its configured EU region | ApexMail's own EU MTAs |
| Route unavailable | Provider failover | **Hold with a named reason** — no third-party fallback |

Availability and price: included on [Enterprise](/enterprise/) Cloud and on the Compliance contract line; on self-serve plans it is the **EU-only routing** add-on at **€149/month (US$165/month)** on Pro and above — the exact catalog figure.

Evidence: the [pricing page](/pricing/) renders the add-on and the Compliance line from the billing catalog; the [compliance page](/compliance/) documents the workflow side; the [architecture page](/architecture/) describes the delivery path.

## Signed routing receipts: verify, don't trust

Every accepted message produces one routing receipt signed with Ed25519 (RFC 8032, 64-byte signature). The signature covers exact, recomputable bytes — an LF-separated payload with no padding:

```text
apexmail-routing-receipt/v1
message_id=<platform message id>
tenant_id=<tenant id>
transport=<transport label>
accepted_at=<RFC 3339 UTC>
actual_source_ip=<ip>          ← present only when the transport reported one
```

Any Ed25519 library can re-derive those bytes from the receipt's own published fields and check the signature — without trusting ApexMail's database, API surface or TLS stack. The verification key is served unauthenticated:

- `GET https://api.apexmail.ee/v1/routing/receipts/public-key` — the Ed25519 public key, the scheme label and a key id (`hex(sha256(public_key))[0:16]`) recorded next to every signature, so a key rotation is auditable.
- `POST https://api.apexmail.ee/v1/routing/receipts/verify` — `{payload, signature}`; answers with the verification verdict.

The scheme is fail-closed in both directions: a receipt write without a configured signing key is refused (the acceptance row is not marked accepted), and the services that own the acceptance path refuse to boot in production without a key. An unsigned receipt cannot exist silently.

Evidence: both endpoints are live, unauthenticated surfaces of the public API; the [API documentation](/docs/api/) covers the surrounding contract; the [Compliance contract line](/pricing/) lists signed routing receipts as an included deliverable.

## What EU-only removes from the subprocessor chain

The [subprocessor register](/subprocessors/) is generated from the deployment's own configuration, so the listed set cannot drift from what actually runs. Under EU-only routing, the Amazon Web Services SES entry does not carry a tenant's mail: the message leaves exclusively through ApexMail's own MTAs, operated on Hetzner infrastructure (Hetzner Online GmbH, Germany). The remaining entries are payments (Mollie B.V., Amsterdam) and optional OAuth sign-in (Google, GitHub) — each with its processing country and transfer mechanism stated on the register.

In other words: under EU-only, no US-controlled third party carries the mail. Under Global, AWS SES does — in an EU region, under AWS's DPA and SCCs, and the register says exactly that.

Evidence: the [subprocessor register](/subprocessors/) (generated, drift-gated), the [DPA](/dpa/) Section 5, and the [data location matrix](/data-locations/).

## Sales sending isolation

Mail sent by ApexMail's own sales-autopilot is classified by provenance and routed through a dedicated sales transport slot. It is never dispatched on a customer's SES or relay transport, and when that slot is unconfigured, sales mail is **held** — the customer transport is not called as a fallback. Sales bounces and complaints land in the sales tenant's suppression set, not in customer sending reputation.

Evidence: the isolation is a property of the delivery worker's routing decision, described on the [architecture page](/architecture/); the customer-visible effect (separate reputation domains) matches the sending model documented under [deliverability features](/features/).

## The evidence pack for reviews

For buyers who need the argument in reviewable form rather than prose:

- **Compliance contract line** — 1M emails, EU-only routing included, dedicated IP, **DORA/NIS2 evidence pack**, GDPR processor pack, signed routing receipts, 1-year audit log, SSO. Rendered with its exact price on the [pricing page](/pricing/).
- **GDPR/DPA material** — the [DPA](/dpa/), the [Privacy Policy](/privacy/) and the [compliance workflows page](/compliance/); data-processing documentation is available for review.
- **Honest limits, stated as limits** — HIPAA is not currently offered, ISO 27001 certification is not currently offered, and no standardized SIG/CAIQ/HECVAT pack is a product entitlement; security questionnaires are handled with current review material case by case. Those statements come from the same canonical claims record that gates this site's copy.

Evidence: the [compliance page](/compliance/) links its documentation; [Contact sales](/contact/sales/) for the review process.

## Languages and support

This site and the product's customer surfaces are published in English, German, French and Spanish. Support runs by email (`support@apexmail.ee`) with plan-specific support terms; Business and Enterprise carry the uptime and performance commitments in the [SLA](/sla/), measured from external probes and credited per the plan matrix.

Evidence: the four locale editions of every page (language switcher in the header), the [SLA](/sla/) and the [contact page](/contact/).

## Where to go next

- [Data location matrix](/data-locations/) — where each data category lives.
- [Subprocessor register](/subprocessors/) — the generated vendor list.
- [Compliance workflows](/compliance/) and the [DPA](/dpa/) — the contractual layer.
- [Pricing](/pricing/) — the EU-only add-on (€149/month, Pro and above) and the Compliance line.
- [Enterprise](/enterprise/) — Enterprise Cloud, where EU-only routing is included.
- [ApexMail vs Amazon SES](/compare/amazon-ses/) — the honest comparison with the transport EU-only removes.
- [Architecture](/architecture/) — the delivery path in technical detail.
