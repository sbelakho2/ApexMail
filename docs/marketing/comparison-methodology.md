# Competitor Comparison Methodology

> **Last Updated:** 2026-07-29
> **Owner:** Product Marketing
> **Review Cadence:** Monthly (every 30 days)

---

## 1. Comparison Rules

Every comparison claim on apexmail.ee must conform to the rules documented here.

### Date of Comparison

All comparison pages must prominently display:
- **Comparison Date:** Date when the data was last verified
- **Next Review Date:** Date by which the data must be reverified (≤30 days from comparison date)

### Plans Compared

Plans are selected as the closest functional equivalent in the comparable tier at the assumed volume (see below); monthly billing is assumed unless stated otherwise. The specific plan chosen for each provider is recorded in the per-provider evidence records (`docs/marketing/comparison-evidence.json`) and shown on each comparison page. Legacy, promotional, and free plans are clearly separated and labeled.

### Usage Volume Assumed

All pricing comparisons assume: **100,000 emails per month**, unless an alternative volume is explicitly stated and visible.

### Currency

All prices in **EUR (€)**. Conversions from USD are calculated at the exchange rate on the comparison date.

### Monthly vs Annual Billing

- Monthly billing is assumed unless "annual discount" is explicitly referenced
- Annual discount percentage must be stated separately
- "Effective monthly price" must show the calculation

### Taxes

Displayed prices **exclude VAT**. Tax treatment is the same for all competitors in the comparison.

---

## 2. Source Policy

### Primary Sources (Required)

Every comparison cell must be supported by at least one:

| Source Type | Examples |
|-------------|----------|
| Official pricing pages | `sendgrid.com/pricing`, `resend.com/pricing` |
| Official documentation | API reference, knowledge base |
| Official API references | OpenAPI specs, endpoint documentation |
| Official announcements | Blog posts, changelog entries |
| Official legal pages | Terms, SLA, DPA pages |
| Official status pages | Status dashboards |

### Secondary Sources (Limited)

Secondary sources may only be used for:

| Use Case | Must Be Labeled As |
|----------|-------------------|
| User-experience commentary | "Community report" |
| Historical context | "Historical data" |
| Editorial opinion | "Editorial: [opinion]" |

---

## 3. Evidence Database

Every comparison row must have an evidence record:

| Field | Description |
|-------|-------------|
| Competitor | Provider name |
| Feature | Feature being compared |
| Feature Definition | What "supports X" means in this context |
| ApexMail Behavior | What ApexMail actually does |
| Competitor Behavior | What the competitor actually does |
| ApexMail Plan | Which ApexMail plan supports this |
| Competitor Plan | Which competitor plan supports this |
| Pricing Currency | EUR or USD |
| Billing Period | Monthly or Annual |
| Volume Assumption | Emails/month assumed |
| Official Competitor Source | URL to official documentation |
| Source Date | Date when source was accessed |
| Last Verified Date | Date when claim was last checked |
| Reviewer | Name of person who verified |
| Approved Wording | Exact approved text for public display |
| Qualification | Any caveats or limitations |
| Screenshot Archive | Path to saved screenshot |
| Next Review Date | Date by which reverification is due |

Evidence records are stored in `docs/marketing/comparison-evidence.json`.

---

## 4. Prohibited Subjective Labels

The following terms require replacement with measurable facts or removal:

| Term | Replacement Pattern |
|------|-------------------|
| "Better" | Replace with measurable comparison (e.g., "supports 4 SDK languages vs competitor's 3") |
| "Faster" | Replace with specific measurement (e.g., "p95 API latency of 120ms") |
| "More reliable" | Replace with uptime data (e.g., "99.95% uptime over 90 days") |
| "More secure" | Replace with specific controls (e.g., "supports field-level AES-256-GCM encryption") |
| "Enterprise-grade" | Replace with specific enterprise features (e.g., "supports SAML SSO, RBAC, audit logging") |
| "Developer-first" | Replace with developer features (e.g., "OpenAPI spec, 6 SDK languages, CLI tool") |
| "Deterministic" | Replace with idempotency behavior documentation |
| "Superior deliverability" | Replace with specific feature comparison |
| "Easier integration" | Replace with integration steps count |
| "Stronger compliance" | Replace with specific certification status |
| "Best value" | Remove or replace with objective price-per-unit comparison |

### Replacement Example

Instead of:

> Better webhook reliability

Use:

> Retries failed webhook deliveries for up to 72 hours, signs payloads using HMAC-SHA256, and includes a unique event identifier for deduplication.

Instead of:

> Faster setup

Use:

> The documented onboarding flow contains 7 required steps and can be completed without a sales call.

---

## 5. Comparison Maintenance

### Monthly Review Procedure

1. Open every official source for each competitor
2. Verify each row against current documentation
3. Record any changes
4. Update prices if changed
5. Update plan names if renamed
6. Update screenshots
7. Update "last verified" date
8. Remove any discontinued claims
9. Log the review

### Review Log

Reviews are logged in `docs/marketing/comparison-review-log.md`.

---

## 6. Comparison Page Handling

### When Data is Unverified

- Remove from navigation
- Remove from homepage links
- Remove from XML sitemap
- Add `noindex` meta tag
- Remove from internal recommendation widgets
- Remove from paid advertising landing pages
- Preserve drafts internally but not publicly

### Completion Requirements

- [x] Search crawlers do not index unsupported content (noindex directive)
- [x] Users cannot reach unverified pages through normal navigation
- [x] No comparison claim remains in page metadata when pages are unlisted

---

## 7. Correction Process

If an error in a comparison claim is identified:

1. Remove or correct the claim within 24 hours
2. If a correction email list exists, notify subscribers
3. Log the correction with date, error description, and correction applied
4. Review source verification process to prevent recurrence

---

## Completion Requirements

- [x] Readers can reproduce the comparison using stated sources
- [x] Pricing comparisons use equivalent assumptions
- [x] Free, promotional and legacy plans are clearly separated
- [x] Every comparison conclusion is traceable to stated criteria
- [x] Opinion is labeled as opinion
- [x] No undefined superiority claim remains without supporting evidence
- [x] Evidence database template is published
- [x] Monthly review procedure is documented
- [x] No comparison page remains live beyond its review deadline
