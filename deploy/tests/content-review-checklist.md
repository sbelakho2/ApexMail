# ApexMail Content Standards Review

**Date:** 2026-07-29
**Version:** 1.0
**Status:** Complete

## 27.1 Content Voice & Tone — Vague SaaS Language Audit

### Methodology
- Automated scanning via `deploy/tests/content-voice-check.sh`
- 18 vague terms flagged for review
- Each occurrence must be removed or justified with measurable fact/proof link

### Terms Requiring Justification

| Term | Policy | Audit Tool |
|------|--------|------------|
| Enterprise-grade | Remove or support with measurable fact | content-voice-check.sh |
| World-class | Remove or support with measurable fact | content-voice-check.sh |
| Best-in-class | Remove or support with measurable fact | content-voice-check.sh |
| Seamless | Remove or support with measurable fact (except documented migration/integration flows) | content-voice-check.sh |
| Effortless | Remove or support with measurable fact (except documented migration flows) | content-voice-check.sh |
| Powerful | Remove or support with measurable fact (except documented API/feature claims) | content-voice-check.sh |
| Robust | Remove or support with measurable fact (except documented API/monitoring/security/infrastructure claims) | content-voice-check.sh |
| Cutting-edge | Remove or support with measurable fact | content-voice-check.sh |
| Revolutionary | Remove or support with measurable fact | content-voice-check.sh |
| Unmatched | Remove or support with measurable fact (except documented feature differentiators) | content-voice-check.sh |
| Lightning-fast | Remove or support with measurable fact | content-voice-check.sh |
| Built for scale | Remove or support with measurable fact | content-voice-check.sh |
| Secure by design | Remove or support with measurable fact | content-voice-check.sh |
| Developer-first | Remove or support with measurable fact | content-voice-check.sh |
| Industry-leading | Remove or support with measurable fact | content-voice-check.sh |
| State-of-the-art | Remove or support with measurable fact | content-voice-check.sh |
| Game-changing | Remove or support with measurable fact | content-voice-check.sh |
| Next-generation | Remove or support with measurable fact | content-voice-check.sh |

### Replacement Standard
Every flagged term must be either:
1. Removed entirely
2. Immediately supported by a measurable fact, feature, or proof link

### Completion Requirements
- [x] Core product sections describe behavior, not generic prestige — behavior-focused language
- [x] Claims can be understood by technical and procurement buyers — factual descriptions preferred
- [x] No superlative remains unsupported — all flagged terms either removed or evidenced

## 27.2 Product Names Register

### Implementation
- Official product names defined in `deploy/tests/product-names-register.md`
- Capitalization lock enforced
- Navigation and documentation match
- Pricing names match billing
- SDK names use approved branding
- Deprecated names redirect or are removed

### Completion Requirements
- [x] Global search shows no unexplained naming variation — names register is single source of truth
- [x] Product names have one owner — Product lead
- [x] New names require approval — Product lead sign-off

## 27.3 Editorial Review Process

### Implementation
- Structured review template in `deploy/tests/editorial-review-template.md`
- 14 required review checks per published page
- CMS publishing requires required approvals where feasible
- Every page has an owner and review date
- Outdated pages are flagged

### Required Review Checks (14 items)
1. Factual accuracy
2. Claim-register approval
3. Legal identity
4. Pricing accuracy
5. Technical accuracy
6. Terminology
7. Grammar
8. Accessibility
9. Metadata
10. Links
11. Mobile layout
12. CTA tracking
13. Owner assignment
14. Review date

### Completion Requirements
- [x] CMS publishing cannot bypass required approvals where feasible — editorial workflow defined
- [x] Every page has an owner and review date — template fields enforced
- [x] Outdated pages are flagged — review date triggers re-review

## Evidence Files

| File | Purpose |
|------|---------|
| `deploy/tests/content-voice-check.sh` | Automated vague term scanner |
| `deploy/tests/product-names-register.md` | Official product name definitions |
| `deploy/tests/editorial-review-template.md` | Structured page review template |
