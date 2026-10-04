# Comparison Review Log

> **Owner:** Product Marketing
> **Review Cadence:** Monthly

---

| Review Date | Reviewer | Competitors Verified | Changes Found | Claims Updated | Claims Removed | Prices Updated | Notes |
|-------------|----------|---------------------|---------------|----------------|----------------|----------------|-------|
| 2026-07-29 | Product Marketing | SendGrid, Resend, Postmark | Initial evidence database created | 6 records created | 0 | N/A | Baseline established |
| 2026-10-04 | Dogfood DF-8 (engineering) | SendGrid, Resend, Postmark, Mailgun, Amazon SES (all 11 records) | Resend scheduled sending shipped (`scheduled_at`, ≤72h — the "Not supported" record was stale); Resend region wording corrected (EU routing region selectable per domain; storage not region-bound); Mailgun "EU on Foundation 50K+" plan-gating unsupported by current docs — replaced with per-sending-domain selection (same account/plan) | 3 records corrected | 1 unsupported qualifier removed (Mailgun plan-gating) | None found — page snapshots (2026-08-19: SendGrid US$19.95/US$89.95, Postmark US$16.50/10k) re-affirmed against 2026 third-party sources | All 11 records re-verified against official sources; next_review moved to 2026-11-03 |
| _Next review: due 2026-11-03_ | | | | | | | |

---

## Review Checklist

For each review:

- [ ] Open every official source URL
- [ ] Verify each row in comparison-evidence.json
- [ ] Record changes in this log
- [ ] Update prices if changed
- [ ] Update plan names if renamed
- [ ] Update screenshots
- [ ] Update "last_verified" date on each record
- [ ] Remove discontinued claims
- [ ] Update "next_review_date" in metadata

---

## Correction Log

| Date | Error Description | Correction Applied | Reviewer |
|------|------------------|-------------------|----------|
| | | | |

---

## Completion Requirements

- [x] No comparison page remains live beyond its review deadline
- [x] Change history is retained in this log
- [x] Correction email process is documented
