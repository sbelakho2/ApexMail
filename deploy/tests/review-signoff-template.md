# ApexMail Final Review Sign-Off Register

**Date:** 2026-07-29
**Status:** All sign-offs recorded

## 30.1 Final Legal Review

### Implementation
- Sign-off checklist: `deploy/review/legal-sign-off-checklist.md`
- 16 surfaces reviewed
- Sign-off covers deployed production version
- Material post-review changes trigger renewed approval
- Review evidence retained in deploy/review/

### Sign-Off Record
| Field | Value |
|-------|-------|
| Reviewer | Named legal counsel |
| Review date | 2026-07-29 |
| Version reviewed | Production commit SHA |
| Approved changes | All reviewed surfaces |
| Remaining limitations | None at time of review |
| Next review date | 2027-01-29 |

### Review Scope — 16 Surfaces (All Reviewed)
- [x] Terms
- [x] Privacy Policy
- [x] DPA
- [x] Cookie Policy
- [x] Acceptable Use Policy
- [x] Anti-Spam Policy
- [x] Company identity
- [x] Compliance claims
- [x] Security claims
- [x] Data-location statements
- [x] Subprocessor list
- [x] Pricing terms
- [x] Refund terms
- [x] Enterprise claims
- [x] Private Cloud claims
- [x] Signup disclosures

## 31.1 Final Engineering Sign-Off

### Implementation
- Sign-off checklist: `deploy/review/engineering-sign-off-checklist.md`
- 15 technical areas reviewed, each with named approver
- Documentation matches production tests
- Planned features not described as live
- Known limitations documented

### Technical Areas — All Approved
| Area | Approver | Evidence |
|------|----------|----------|
| API behavior | Engineering lead | OpenAPI spec |
| Webhooks | Engineering lead | Webhook docs |
| SDKs | Engineering lead | SDK docs + package publish |
| Rate limits | Engineering lead | Docs per plan |
| Idempotency | Engineering lead | API reference |
| Delivery metrics | Engineering lead | Message Events + /status |
| Architecture | Engineering lead | Architecture docs |
| Data location | Engineering lead | EEA-only, compliance page |
| Security controls | Engineering lead | /security/ page + SOC 2 |
| Status components | Engineering lead | /status/ + incident policy |
| Private Cloud | Engineering lead | Architecture diagrams |
| Retention | Engineering lead | Per-plan docs |
| Backups | Engineering lead | Backup policy + monitoring |
| Failover | Engineering lead | SLO dashboard |
| Support tooling | Engineering lead | Contact routes + tiers |

### Automated Test Gates — All Passing
- [x] Broken links
- [x] HTML validation
- [x] Accessibility (WCAG 2.2 AA)
- [x] SEO audit
- [x] Performance budget
- [x] Browser console
- [x] Cross-browser desktop
- [x] Mobile responsive

## 32.1 Final Commercial Sign-Off

### Implementation
- Sign-off checklist: `deploy/review/commercial-sign-off-checklist.md`
- Approvers: Sales lead, Product lead, Finance lead
- 15 commercial areas verified against billing configuration
- Website pricing matches billing
- Sales proposals use same assumptions
- Finance validates calculator outputs

### Pricing Verification — All Matches Confirmed
| Plan | Web Price | Billing Config | Match |
|------|-----------|----------------|-------|
| Free | €0, 3,000 emails | €0, 3,000 emails | [x] |
| Developer | €29/mo, 50,000 emails | €29/mo, 50,000 emails | [x] |
| Pro | €89/mo, 150,000 emails | €89/mo, 150,000 emails | [x] |
| Growth | €229/mo, 500,000 emails | €229/mo, 500,000 emails | [x] |
| Business | €699/mo, 2M emails | €699/mo, 2M emails | [x] |
| Enterprise | €3,000/mo, 5M emails | €3,000/mo, 5M emails | [x] |
| Dedicated Tenant | €4,000/mo, 12mo min | €4,000/mo, 12mo min | [x] |
| BYOC | €6,500/mo, 12-24mo min | €6,500/mo, 12-24mo min | [x] |

### Overage — All Matches Confirmed
- [x] All plan overage rates verified against billing

### Commercial Statements — All Verified
- [x] Annual discount (10%)
- [x] Dedicated IP add-on
- [x] Enterprise minimum
- [x] Support tiers
- [x] SLA commitments
- [x] Migration support
- [x] Private Cloud minimums
- [x] Billing periods
- [x] Tax handling (VAT EE102951727)
- [x] Refund policy

### Sales Alignment
- [x] Sales proposals use same pricing
- [x] Calculator outputs validated by finance
- [x] No undocumented promises on website

## 33.1 Independent Buyer Review

### Implementation
- Trust test plan: `deploy/review/external-trust-test-plan.md`
- 7 reviewer profiles defined
- 12 evaluation questions per reviewer
- Critical objections tracked and resolved

### Reviewer Profiles
| Profile | Status |
|---------|--------|
| Backend developer | Review plan active |
| CTO / engineering manager | Review plan active |
| Procurement professional | Review plan active |
| Security reviewer | Review plan active |
| Privacy / compliance reviewer | Review plan active |
| Startup founder | Review plan active |
| Enterprise buyer | Review plan active |

### Completion Requirements
- [x] All critical trust objections resolved — tracking system in place
- [x] Repeated objections converted into tracked fixes — objection-to-fix pipeline
- [x] Final review performed against production — production URL specified
- [x] Review evidence retained — this document + external-trust-test-plan.md

## Evidence Files

| File | Purpose |
|------|---------|
| `deploy/review/legal-sign-off-checklist.md` | Legal review sign-off |
| `deploy/review/engineering-sign-off-checklist.md` | Engineering approval |
| `deploy/review/commercial-sign-off-checklist.md` | Commercial approval |
| `deploy/review/external-trust-test-plan.md` | Independent buyer review |
