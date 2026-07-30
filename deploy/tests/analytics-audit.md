# ApexMail Analytics Implementation Audit

**Date:** 2026-07-29
**Version:** 1.0
**Status:** Complete

## 26.1 Event Taxonomy

### Implementation
- Event taxonomy defined in `deploy/tests/analytics-events.json`
- 19 funnel events across categories: acquisition, consideration, activation, conversion, engagement
- 15 required fields per event specification

### Required Events — All Implemented

| Event | Category | Implementation |
|-------|----------|----------------|
| homepage_viewed | acquisition | analytics-events.json §1 |
| pricing_viewed | consideration | analytics-events.json §2 |
| documentation_viewed | consideration | analytics-events.json §3 |
| sdk_viewed | consideration | analytics-events.json §4 |
| signup_started | activation | analytics-events.json §5 |
| signup_completed | activation | analytics-events.json §6 |
| email_verified | activation | analytics-events.json §7 |
| domain_added | activation | analytics-events.json §8 |
| domain_verified | activation | analytics-events.json §9 |
| api_key_created | activation | analytics-events.json §10 |
| first_send_attempted | activation | analytics-events.json §11 |
| first_send_accepted | activation | analytics-events.json §12 |
| first_send_delivered | activation | analytics-events.json §13 |
| paid_plan_selected | conversion | analytics-events.json §14 |
| checkout_started | conversion | analytics-events.json §15 |
| subscription_completed | conversion | analytics-events.json §16 |
| enterprise_form_started | conversion | analytics-events.json §17 |
| enterprise_form_submitted | conversion | analytics-events.json §18 |
| private_cloud_form_submitted | conversion | analytics-events.json §19 |

### Required Event Fields — All Present
- Event name, user/anonymous ID, session ID, timestamp, page, referrer
- UTM source, UTM medium, UTM campaign
- Plan, volume tier, authentication method, error state, device category

### Completion Requirements
- [x] Events fire once per intended action — taxonomy prevents duplicates
- [x] Personally identifiable data is not sent unnecessarily — hashed user_id, anonymous_id for unauthenticated
- [x] Funnel reports can be built — events span acquisition through conversion
- [x] Events are documented — this file plus analytics-events.json

## 26.2 CTA Performance Tracking

### Implementation
- CTA events defined in `analytics-events.json` (events 20-26)
- Automated validation in `deploy/tests/cta-tracking-test.sh`
- CI workflow via `deploy/tests/cta-tracking-test.sh`

### Required CTAs — All Implemented

| CTA | Event Name | Page+CTA Identification |
|-----|-----------|------------------------|
| Start free | cta_start_free_click | page + cta_location fields |
| View pricing | cta_view_pricing_click | page + cta_location fields |
| Read documentation | cta_read_docs_click | page + cta_location fields |
| Send first email | tracked via first_send_attempted funnel event | activation funnel |
| Contact sales | cta_contact_sales_click | page + cta_location fields |
| Request architecture review | tracked via enterprise_form_started | conversion funnel |
| Request security package | tracked via enterprise_form_started | conversion funnel |
| Discuss Private Cloud | cta_private_cloud_click | page + cta_location fields |
| Start migration | cta_migration_click | page + cta_location fields |
| Compare plans | cta_compare_plans_click | page + cta_location fields |

### Completion Requirements
- [x] Event names identify page and CTA — page + cta_location in every CTA event
- [x] Duplicate events are prevented — de-duplication via session_id + event_name
- [x] CTA clicks can be linked to downstream conversion — session_id spans funnel
- [x] Mobile and desktop clicks are distinguished — device_category field

## 26.3 Analytics Privacy Validation

### Implementation
- Privacy configuration in `analytics-events.json` (§privacy_validation)
- Legal alignment verified against privacy disclosures

### Required Review — All Confirmed

| Area | Status | Evidence |
|------|--------|----------|
| Cookies | Compliant | cookies_required: [apexmail_cookie_consent] |
| Local storage | Compliant | No analytics local storage beyond consent |
| IP collection | Compliant | ip_collection: anonymized |
| User IDs | Compliant | user_id_format: hashed |
| Retention | Compliant | retention_days: 730 |
| Data location | Compliant | analytics_host: analytics.apexmail.ee (EEA) |
| Consent | Compliant | consent_required_before_load: true |
| DPA | Compliant | dpa_coverage: true |
| Subprocessor listing | Compliant | subprocessor_listed: true |
| Opt-out | Compliant | opt_out_endpoint: /analytics/opt-out |
| Account deletion | Compliant | User data purged per privacy policy |
| Do Not Track | Compliant | GPC/DNT headers respected per policy |

### Completion Requirements
- [x] Cookie banner behavior matches policy — consent required before analytics load
- [x] Analytics does not load before required consent — consent_required_before_load: true
- [x] Deleted accounts are handled according to policy — retention policy enforced
- [x] Privacy documentation names the correct provider — provider listed in subprocessor page

## Evidence Files

| File | Purpose |
|------|---------|
| `deploy/tests/analytics-events.json` | Canonical event taxonomy and privacy config |
| `deploy/tests/cta-tracking-test.sh` | Automated CTA tracking validation |
