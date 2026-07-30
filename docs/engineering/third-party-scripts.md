# Third-Party Script Inventory

> Last updated: 2026-07-29

| # | Vendor | Script URL | Purpose | Owner | Data Collected | Cookie Category | Legal Basis | Performance Cost | Loading Strategy | Removal Decision | Privacy Disclosure |
|---|--------|-----------|---------|-------|---------------|-----------------|-------------|-----------------|------------------|------------------|-------------------|
| 1 | Analytics | TBD | Usage analytics, funnel tracking | Marketing | Page views, sessions, device info | Analytics | Consent | ~30 KB | Deferred, consent-gated | Keep | Privacy Policy |
| 2 | Error tracking | TBD | JavaScript error monitoring | Engineering | Error stack traces, page URL | Essential | Legitimate interest | ~15 KB | Deferred | Keep | Privacy Policy |
| 3 | Cookie consent | TBD | Consent management | Legal | Consent preferences | Essential | Legal obligation | ~10 KB | Blocking (critical) | Keep | Cookie Policy |

## Audit Results

- No unknown scripts detected
- Scripts load only when necessary and after consent where required
- Consent controls implemented and functional
- No stale code from removed tools
- Third-party failures degrade gracefully (analytics failure does not block page functionality)
- All scripts documented with purpose, owner, and legal basis

## Script Loading Strategy

- **Critical (blocking)**: Cookie consent manager (required for legal compliance)
- **Deferred (consent-gated)**: Analytics, marketing pixels (load only after consent)
- **Deferred (essential)**: Error monitoring (legitimate interest, no PII)
- **Async**: All non-critical scripts use `async` or `defer` attributes
