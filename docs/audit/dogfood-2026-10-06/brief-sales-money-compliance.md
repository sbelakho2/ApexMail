# Adversarial file-by-file review — sales, money and compliance slice

You are auditing the ApexMail repo FILE BY FILE, adversarially. Work from the working tree at
/Users/sabelakhoua/IdeaProjects/ApexMail (branch main, dirty tree — that is expected).

## Your slice (every file, none skipped)
1. `services/mail-server/crates/sales-autopilot/` (all .rs)
2. `services/mail-server/crates/sales-knowledge/`, `crates/platform-catalog/`,
   `crates/billing-service/`, `crates/accounting-core/`
3. `services/mail-server/crates/compliance/` (all .rs)
4. `services/mail-server/crates/ai-service/` (all .rs) and `crates/email-grader/`
5. `packages/sdk-php/`, `packages/sdk-python/`, `packages/sdk-java/`, `packages/sdk-ruby/`
   (the generated client surfaces: check they match the documented API, not that they are pretty)

## Bar each file must clear (report a finding when it does not)
- **Money correctness**: a price/limit that disagrees with `crates/platform-catalog` (the canonical
  source); rounding that loses or invents cents; a quota/overage computation that can bill twice
  or not at all; a ledger write outside the transaction that must durably pair with it.
- **Sales correctness**: an autonomy/kill-switch state that can be bypassed; a decision recorded
  without its compliance gate; a suppression or legal-policy check that can be skipped; a retry
  that can send twice.
- **Compliance/honesty**: a claim asserted by a comment/doc that the code does not enforce; a
  GDPR/DSR path that silently drops part of the request; an audit row written after (not inside)
  the change it describes.
- **AI honesty**: a grounded/verified claim that the verifier cannot actually check; a prompt
  version that does not match the template it names; content returned to users that bypasses the
  verifier; a fallback that fabricates an answer on upstream failure.
- **Wiring**: a handler/route/env var that nothing mounts/sets; a table written by no code (or read
  by no code); a metric named in docs but never emitted; an SDK method with no server route.

## Deliverable
Write findings to `docs/audit/dogfood-2026-10-06/findings-sales-money-compliance.md`, one entry per
finding:
```
### <severity: P0|P1|P2|P3> <file>:<line> — <one-line title>
Evidence: <the exact code/datum that proves it, quoted>
Why it is a defect: <one or two sentences>
Suggested fix: <minimal, concrete>
```
Severity: P0 = security/money-loss/user-blocking; P1 = wrong behavior users hit; P2 = wiring/honesty
gap or dead code shipping; P3 = polish.

Rules:
- Read EVERY file in your slice; append `- [x] <path>` progress lines to
  `docs/audit/dogfood-2026-10-06/progress-sales-money-compliance.md` as you go.
- Prove every finding from file contents; no speculation, no style nits.
- Do NOT edit code — this slice reports only.
- Mark clean files `- [x] <path> (clean)`. Work in batches; write progress as you go.
