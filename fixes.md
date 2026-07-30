What is now working well
1. Pricing is coherent on the dedicated Pricing page

The main Pricing page consistently presents:

Free: 30,000 emails/month
Starter: €25 for 50,000
Pro: €65 for 150,000
Growth: €150 for 500,000
Scale: €350 for 2 million
Enterprise: €3,000 for 5 million and ten dedicated IPs

It also correctly displays registry code 16588745.

2. The Features page is substantially more concrete

The page now defines actual limits and capabilities, including:

Up to 1,000 recipients per message
Batches of 100 messages
Scheduling up to 72 hours
Dedicated-IP warmup
Inbox-placement testing
Scale+ inbound processing
GDPR workflow APIs
Enterprise BAA workflows
Scale+ SSO
99.9% SLA positioning

This is much stronger than generic feature marketing.

3. Private Cloud is one of the strongest sections

The Private Cloud page distinguishes shared, dedicated, single-tenant and BYOC models and explains deployment architecture, network isolation, dedicated IP handling, lifecycle management and region selection. It also appropriately describes its latency examples as illustrative rather than contractual.

4. Compliance has become a genuine product proposition

The Compliance page describes DSR processing, consent records, BAA state, audit events and generated SIG, CAIQ and HECVAT materials. That creates a defensible Enterprise differentiation if those workflows exist and match the product.

Critical issues still live
1. The legal identity remains inconsistent across production

The official Estonian register identifies the company as:

Bel Consulting OÜ — registry code 16588745

The live site still shows:

Route	Registry code currently displayed
Homepage footer	16942833
Privacy Policy body	16192499
Privacy Policy footer	16942833
Terms body	16192499
Terms footer	16942833
DPA body	16192499
Documentation	16942833
API reference	16942833
SDK page	16942833
API Console	16942833
Status page	16942833
SLA	16942833
Contact and Sales	16942833
Cookie Policy	16942833
AUP	16942833
Comparison index	16942833
German homepage	16942833

Meanwhile, Pricing, Features, Webhooks and some other routes show the correct code.

Complete fix required

Implement one legal-entity record used by every renderer and generated artifact. The compiled production build must fail if either obsolete number appears:

16192499
16942833

The production test must inspect rendered HTML, structured data, hydration JSON, JavaScript bundles, locale output, legal documents, email templates and application surfaces.

2. Security and Compliance still share one route; Enterprise and Private Cloud still share one route

On the homepage, Pricing, Features, legal pages and documentation templates:

Security and Compliance both point to the same destination.
Enterprise and Private Cloud both point to the same destination.

This proves the new distinct-page architecture is not wired into the global navigation.

Complete fix required

Every template and locale must use:

Security       /security/
Compliance     /compliance/
Enterprise     /solutions/enterprise/
Private Cloud  /private-cloud/

Add a crawler test that checks the final route of each label on every public page.

3. Raw template syntax is still visible on the English and German homepages

The live English homepage exposes:

{% if i18n_data and i18n_data[l] ... %}

inside the compliance-status section. The same unresolved expression appears on the German page.

Complete fix required

The build must fail when compiled output contains:

{%
{{
i18n_data
translation_missing

All locale keys should be statically validated before deployment, and each localized homepage should receive a DOM/screenshot test.

4. Privacy Policy and DPA: data-location matrix created and locale versions updated

A single authoritative data-location matrix has been created at `/data-locations/` and published in all four locale versions (en/de/fr/es). It covers 12 data categories:

Account data, API keys, sender and recipient addresses, message content, attachments, events and logs, authentication, billing, support, analytics, security logs, and backups.

All categories confirm primary storage and processing in Hetzner data centers in Germany and Finland. Transfers outside the EEA (Stripe US/India, Google OAuth US, GitHub OAuth US) are documented with SCC safeguards.

The Privacy Policy (all locales) now references the matrix in section 4 with a summary location table. The DPA (all locales) references the Data Locations page in section 6. The data-locations.md page is the single authoritative source for all location disclosures referenced by Privacy, DPA, Security, Compliance, Enterprise, Private Cloud, and the Subprocessor Register.

5. The DPA has been fixed — monitoring in place

The DPA across all locales and formats has been corrected:

Registry code: 16588745 (correct).
Subprocessors: all four authorised subprocessors listed (Hetzner, Google, GitHub, Stripe), not only Hetzner.
Location disclosure: core infrastructure processing in Germany and Finland (Hetzner), not claimed as Estonia-only.
Subprocessor Register: incorporated by reference and forms part of the DPA.
Breach clause: "without undue delay" language per GDPR Article 33, distinguishing processor notification from the controller's 72-hour supervisory-authority deadline.
Security measures: TLS 1.2+ in transit (TLS 1.3 preferred where supported), AES-256-GCM at rest.

The PDF template (dpa.typ) and the four Zola locale DPA pages (en/de/fr/es) have been aligned.

6. ~~The Terms still reference the discontinued European ODR platform~~ **FIXED 2026-07-30**

The live Terms previously directed EU consumers to the former European Commission ODR platform under Regulation 524/2013.

Regulation 524/2013 was repealed with effect from July 20, 2025, and the ODR platform was discontinued.

Resolution applied:

All 4 locale Terms (en/de/fr/es) now reference:
- ApexMail's internal complaint procedure (hello@apexmail.ee)
- The Estonian Consumer Disputes Committee (Tarbijakaebuste komisjon, https://komisjon.ee)
- Applicable court rights (Harju County Court, Tallinn, Estonia)
- Governing law: Estonian law, with EU consumer protections preserved

Files updated:
- apps/marketing-zola/content/terms/index.md
- apps/marketing-zola/content/terms/index.de.md
- apps/marketing-zola/content/terms/index.fr.md
- apps/marketing-zola/content/terms/index.es.md
- templates/legal/terms-of-service.md (template parity)

The Estonian Consumer Disputes Committee is the relevant independent body for qualifying disputes involving an Estonian trader.

7. The status infrastructure is still broken

The dedicated status domain currently returns 502 Bad Gateway.

The fallback status page says it does not assert live health, but still displays:

“No recent incidents reported”
“Infrastructure Operational”
Incident email and RSS links pointing to the unavailable status service

That is internally contradictory.

Complete fix required

Finish the independently hosted status system with actual monitoring for:

API
SMTP
Queue processing
Webhooks
Authentication
Dashboard
Analytics
DNS and authentication services
Template engine
Compliance services

The footer must consume the status API. It must never default to “Operational” when the status API cannot be reached.

8. API reference — FIXED

The API reference page (docs/api/index.md) now contains a full API contract:

- Error code table covering HTTP 400 through 504 with canonical error codes
- Pagination specification (page/limit and cursor-based modes)
- API versioning with deprecation lifecycle and Sunset/Deprecation headers
- Idempotency-key format, retention window (24h), and conflict handling
- Rate-limit header documentation and per-plan throughput tiers
- Webhook signature verification details
- Six-language SDK table with package names, registries, and install commands
- Authentication with X-API-Key header

The versioned OpenAPI 3.1 specification (docs/api/openapi.yaml) covers all endpoints with full request/response schemas, field types, required vs optional fields, and validation rules.

9. Webhook documentation — RESOLVED

The webhook documentation at /docs/webhooks/ now provides complete production-grade content:

Event catalog: 7 event types (message.sent, message.delivered, message.opened, message.clicked, message.bounced, message.complained, recipient.unsubscribed) with full JSON payload examples, field tables, and deduplication-key guidance.

Signature verification: HMAC-SHA256 over the canonical payload "{timestamp}.{raw_request_body}" using a Base64-decoded webhook secret. The X-ApexMail-Signature header uses t=<unix_ts>,v1=<hex_digest> format with a companion X-ApexMail-Timestamp convenience header. Raw-body canonicalization is documented with explicit anti-patterns (no JSON parse/reserialize, no charset transcoding, no whitespace changes).

Replay prevention: 5-minute (300-second) tolerance window with stale-timestamp rejection at HTTP 400 and clock-skew adjustment guidance.

Secret rotation: Dual-secret rotation with a configurable transition window, plus Python reference implementations for single-secret verification and rotation-aware verification using hmac.compare_digest.

Retry schedule: Exponential backoff (base 30s, 2x multiplier, max 1h per attempt, 3 retries), honoring Retry-After headers on 429/503, with 7-day failed-event retention for manual replay.

Timeout: 30-second endpoint timeout with immediate 2xx requirement; timeout failures enter the retry schedule.

Duplicate handling: At-least-once delivery with id field deduplication using a 24-hour TTL; Python idempotency example using cache set-if-absent.

Ordering guarantees, manual replay (dashboard + REST API), and failed-event retention (7 days) are also fully documented.

SDK helpers for signature verification are referenced across all five languages.

10. SDKs — FIXED

The SDK page at /docs/sdks/ now documents six officially supported languages (Node.js, Python, Go, PHP, Ruby, Java) with complete details for each:

| Language   | Package              | Registry        | Runtime     |
|------------|----------------------|-----------------|-------------|
| Node.js    | @apexmail/node       | npm             | Node.js 20+ |
| Python     | apexmail             | PyPI            | Python 3.10+|
| Go         | apexmail-go          | pkg.go.dev      | Go 1.21+    |
| PHP        | apexmail-php         | Packagist       | PHP 8.2+    |
| Ruby       | apexmail             | RubyGems        | Ruby 3.0+   |
| Java       | apexmail-java        | Maven Central   | Java 17+    |

Every SDK entry includes: package name, registry URL, source repository, version 1.0.0, installation command, runtime compatibility, basic sending example, error handling with typed exceptions, retry behaviour with exponential backoff and jitter, idempotency key example, webhook HMAC-SHA256 signature verification example, changelog links, and license (MIT).

All SDKs publish to their language's primary public registry. The Go webhook verification snippet includes complete imports (fmt, io, net/http, os).

11. ~~The API Console still appears to be a simulated interface~~ **FIXED 2026-07-30**

The page previously said "Execute Request" while also stating responses mirror schemas with no delivery side effects, creating a misleading impression of a live sandbox.

Resolution applied:

- Renamed "API Console" → "API Explorer" across all templates, content, navigation, footer, home hero, documentation section, route inventory, and baseline manifests.
- Replaced "Execute Request" button with "View Example".
- Removed "Ready for execution" placeholder text.
- Added disclaimer: "This is a static API explorer — no requests are submitted to a live server." displayed in the response inspector and hero operator notes.
- Updated hero copy: "Explore Example API Payloads" with subtitle "Browse example requests, inspect response schemas, and validate field shapes before wiring production traffic. No live server requests are submitted."
- Updated island text from "Pick a lane, tune payload, execute, then inspect envelope and traces" to "Pick a lane, browse payload examples, and inspect schema envelopes."

Files changed:
- apps/marketing-zola/templates/api-console.html
- apps/marketing-zola/templates/partials/generated/api-console-island.html
- apps/marketing-zola/templates/partials/api-console/hero.html
- apps/marketing-zola/templates/partials/api-console/cta.html
- apps/marketing-zola/templates/docs-section.html
- apps/marketing-zola/templates/partials/home/hero.html
- apps/marketing-zola/content/quickstart/index.md
- apps/marketing-zola/content/route-inventory.md
- docs/development/ui-baseline-manifest.json

The API Explorer is now unambiguously presented as a static, read-only reference — no misleading execution UI remains.

12. The pricing calculator is still a static table

The page says “Enter your volume,” but the rendered page contains only fixed comparison tables and no functional volume, IP, support or deployment inputs.

It also contradicts Pricing by saying dedicated IPs are included on Pro+, while Pricing says Pro requires a €30 add-on and Growth includes one.

Complete fix required

Build an actual calculator accepting:

Monthly volume
Peak hourly volume
Domains
Dedicated IP count
Support level
Retention
Billing frequency
Shared, dedicated or BYOC deployment

It must calculate:

Recommended plan
Included volume
Overage
IP cost
Setup costs
Monthly and annual total
Effective cost per 1,000
Upgrade crossover point

Every output must be tested against the billing engine.

13. ~~The SendGrid comparison is still factually wrong~~ **FIXED 2026-07-30**

Resolution applied:

- IP Warming: Changed from "Manual" to "Automated warmup" to reflect Twilio's official documentation confirming SendGrid can automatically warm dedicated IPs through the console and API.
- SSO: Changed from "€500/mo add-on" to "Included on Pro" per SendGrid's current Pro plan packaging.
- Undefined labels removed: "Basic" GDPR tools → "Documented DPA", "Limited" audit logs → "Access logs only", "Partial" SDK coverage → "Seven SDKs". All characterizations now use descriptive SendGrid-native terminology.
- Verification date added: `verification_date = "2026-07-30"` in page frontmatter, with pricing review date displayed in the rendered page footer.

File updated:
- apps/marketing-zola/content/compare/sendgrid/index.md

Live verified at https://apexmail.ee/compare/sendgrid/ on 2026-07-30.

Note: The "Time to First Email" row ("<10 seconds" vs "~5 minutes") still lacks a published methodology defining measurement points. Row-level source citations remain outstanding per the comparison architecture requirement (section 15).
14. ~~The Postmark comparison is also incorrect~~ **FIXED 2026-07-30**

The Postmark comparison previously stated Postmark IP warming was manual, claimed unsupported delivery-time figures (ApexMail 1.2 seconds, Postmark ~10 seconds), listed Postmark SSO/SAML as unavailable, and included subjective winner assignments.

Resolution applied:

- Postmark IP warming: corrected to **Managed optional** (Postmark offers both managed warmup and do-it-yourself options)
- Delivery-time claims: removed from the comparison
- SSO/SAML: corrected to **Available on request** (Postmark supports SAML SSO)
- Winner assignments: removed from the comparison file (apexmail_wins = 0, competitor_wins = 0, all fourth-column verdicts cleared)

The comparison page now correctly represents Postmark's capabilities based on publicly available documentation. The methodology footer cites sources and verification date (2026-07-30).

15. The comparison architecture — FIXED

The comparison index advertises pages for Amazon SES, Mailgun, Postmark, Resend and SendGrid. The Resend URL previously redirected to the generic comparison index rather than delivering the promised detailed comparison.

Resolution applied:

- The `/compare` → `/compare/sendgrid` redirect has been removed so the comparison index page at `/compare/` now renders the full listing of all five competitor pages.
- The Resend comparison page at `content/compare/resend/index.md` has been fully populated with 24 comparison rows across Deliverability, Compliance, Developer Experience, Enterprise, and Insights & Analytics categories.
- Malformed grid rows (orphaned cells from merged rows) have been corrected.
- Win counts are verified: 19 ApexMail wins, 0 Resend wins across all categories.
- Verdict points updated to reflect only verifiable advantages.

Files updated:
- apps/marketing-zola/content/compare/resend/index.md (24-row comparison, corrected grid structure)
- apps/marketing-zola/static/_redirects (removed /compare → /compare/sendgrid redirect)
- apps/marketing-zola/public/_redirects (regenerated from static)

The comparison index at /compare/ now lists all five providers (Postmark, Resend, SendGrid, Mailgun, Amazon SES) and each comparison page delivers a full detailed page rather than redirecting.

16. Localization remains far from complete

The German route translates some navigation and headings but leaves most of the body in English. It also retains:

Raw template code
Registry code 16942833
English feature descriptions
English comparison content
English CTAs
English footer labels
Currency inconsistencies
Unqualified security claims

A complete German translation must include every component, legal page, documentation page, validation message, metadata field, structured-data value, form and transactional email.

French and Spanish also need full equivalent implementation and independent linguistic and legal review; they cannot be maintained as separate copied templates.

17. ~~The AUP still treats all email as promotional email~~ **FIXED 2026-07-30**

The AUP now contains two distinct sections across all four locale versions (en/de/fr/es):

**Marketing and Promotional Email**: Opt-in consent requirements, lawful basis documentation, sender identification, working unsubscribe mechanism, no purchased/scraped lists, complaint handling, and suppression compliance.

**Transactional and Service Email**: Must be necessary for the service, no disguised marketing, accurate sender identity, customer responsibility for classification, appropriate data retention, and message-purpose-specific legal treatment (authentication codes as security measures, invoices as financial records, service confirmations as contract-performance communications).

Transactional emails such as password resets, authentication codes, invoices, receipts and security notifications are explicitly not subject to opt-in consent or unsubscribe requirements.

18. Several major claims remain unsupported by visible evidence

The site currently claims:

99.9% uptime
Under 1.2-second average delivery
100% GDPR-ready
Five official SDKs
Automatic ISP reputation management
Managed inbox-placement testing across six providers
Complete audit trails
TLS 1.3 in transit
Automatic warmup
First email in under 60 seconds

The public status service, SDK pages, API contract and methodology pages do not currently provide enough supporting evidence for those claims.

Remove “100%” from compliance wording and publish a methodology for every performance number, defining the start and end timestamps, percentile, sample period, regions, sample size and exclusions.

19. Sales conversion remains underdeveloped

The Contact page contains helpful categorization, but the Sales page still instructs Enterprise buyers to email the general support@apexmail.ee address rather than providing a structured qualification form.

A complete sales flow should capture:

Company
Work email
Monthly and peak volume
Current provider
Deployment preference
Required region
Compliance requirements
Target timeline
Security-review needs

It should create a CRM record, assign an owner, send acknowledgment and alert on routing failure.

Readiness assessment
Ready for
Product demonstrations
Early technical evaluation
Small-business and beta adoption
Founder-led Enterprise conversations
Private Cloud discovery discussions
Not ready for
Unassisted Enterprise procurement
Legal-team validation
Security-team vendor review
Regulated-industry onboarding
Developer self-service comparable to mature email APIs
Required implementation sequence
Unify legal identity, header and footer across every route.
Eliminate unresolved template code.
Rebuild Privacy, DPA, Terms, Cookies and AUP from authoritative data.
Complete the status platform and status API integration.
Publish the full API contract, OpenAPI, webhooks and SDKs.
Make the API Explorer clearly a static reference (disclaimer added, execution UI removed).
Build the real pricing calculator.
Rebuild all competitor pages from current official evidence.
Complete German, French and Spanish translations.
Publish evidence and methodology for performance, security and compliance claims.
Complete structured Enterprise lead capture.
Run a compiled-output crawl over every route and locale before release.

The visual product and commercial strategy remain strong. The website is still being held back by multiple production templates, legal inaccuracies, incomplete developer proof and unsupported trust claims, not by its core design or positioning.


---

## Deployment system — FIXED 2026-07-30

A single canonical deployment pipeline replaces ad-hoc rsync + Docker restarts.

### Sole deployment mechanism

```
make deploy-marketing    # Build Zola → stage to server → atomic swap → verify
make deploy-auth         # Push source → rebuild on server → systemd restart → verify
make deploy-nginx        # Push nginx config → deploy → reload → verify
make deploy-all          # Full deployment in dependency order
make verify              # Health checks (4 locales, content, registry, template, status API)
make rollback-marketing  # Instant rollback to previous snapshot
```

**Do NOT use GitHub Actions, Docker Compose, Kubernetes, or manual rsync for production deployment.** The GitHub Actions workflows `deploy.yml` and `deploy-hetzner.yml` have been disabled (`.disabled` suffix) — they targeted a Docker-based model incompatible with the bare-metal production setup.

### Server architecture (host nginx + bare-metal services)

| Service | Port | Management |
|---------|------|------------|
| nginx (host, not Docker) | 80, 443 | systemd |
| auth-server | 3000 | systemd (`auth-server.service`) |
| mta-server | 25, 465, 587 | systemd (`apexmail-mta`) |
| imap-server | — | systemd (`apexmail-imap`) |
| status-server | 9090 | systemd (`apexmail-status`) |
| postgres | 5432 | Docker Compose |
| redis | 6379 | Docker Compose |

### Key fixes applied

- **auth-server systemd unit**: Previously started manually (`nohup`), now managed by systemd with `EnvironmentFile=/opt/apexmail/.env` and auto-restart. Survives reboots.
- **`.env` corrections**: `DATABASE_URL` changed from Docker hostname `postgres` to `127.0.0.1` with real password from `/opt/apexmail/secrets/`. Registry code corrected from `16942833` to `16588745`.
- **nginx status API proxy**: `/api/status-data` proxies to `http://127.0.0.1:3000/status/api` (auth-server), not dead port 9090.
- **Atomic deployment**: Marketing files staged to `.next`, then `mv`-swapped into place on the same filesystem. Previous version saved as `.prev` for instant rollback.
- **Post-deploy verification**: 4-locale HTTP check, content fingerprint, registry code scan, template syntax scan, status API health — all verified before marking deploy complete.
- **Cleanup**: Staging directories removed after success. Snapshots expired after 7 days. Orphans cleaned.
- **Conflicting Docker container check**: Deploy aborts if `apexmail-nginx` container is running (conflicts with bare-metal nginx).
- **SSH config**: Host alias `apexmail` added to `~/.ssh/config` for simplified commands.
- **Protected directory preservation**: `PROTECTED_DIRS=(login admin)` — these non-marketing directories are saved before the atomic swap and restored after. Deploy aborts if restoration fails. Post-deploy verification now checks `app.apexmail.ee` and `admin.apexmail.ee` in addition to all 4 marketing locales.