# Brief — coverage auditor: prove or refute "100% whole-repo, file by file"

You are a rigorous audit agent. Repo root:
/Users/sabelakhoua/IdeaProjects/ApexMail. READ-ONLY: no code edits; your
deliverable is a report.

## Deliverable
`docs/audit/dogfood-2026-10-06/review-coverage-ledger.md`:
1. A per-directory / per-crate coverage ledger: for every top-level directory
   and every `services/mail-server/crates/*` crate, name the artifact(s) that
   reviewed it during this campaign and the older campaigns
   (`docs/audit/dogfood-2026-10-06/*.md`, `docs/audit/**` from prior waves)
   and the DEPTH (file-by-file read / sampled / screened / live-tested). Use
   the file list in `docs/audit/dogfood-2026-10-06/worklist.txt` (3,352 files)
   as the denominator; be explicit where a report's own "what I did not
   reach" section leaves a gap.
2. The UNCOVERED list: every file (or tight group) with no review artifact
   claiming it. Then REVIEW those uncovered files YOURSELF, adversarially:
   read them in full, and report real defects with file:line + why + fix.
   Focus classes: claims-vs-code honesty, forged-success tests (assertions
   that cannot fail), authz gaps (missing scope/tenant checks), error
   swallowing that renders outages as empty/zero, resource leaks
   (unbounded growth, missing timeouts), TOCTOU/races, secret handling.
3. Explicit falsification checks on the campaign's claims: e.g. grep the
   reports for "read in full" vs their own coverage notes; list any directory
   a report claims but does not evidence. Report overstatements as findings.

## Method notes
- Prior coverage known to exist: the 2026-09-30 sub-module audit (15 SMs, 192
  findings), the frontend/delivery/sales/money code reviews, the gates +
  migrations review, apps/ai, SDKs, KiwiCaptcha, infra/CI/deploy, docs +
  protocol + root data, packages/harnesses, plus live planes (mail, money,
  sales/AI/analytics) — all under docs/audit/. The chatbot/mailbot live
  passes are running in parallel; do not duplicate them (exclude
  ai_chat/email_agent/reply_handler from your deep-dive unless the ledger
  shows OTHER nearby files uncovered).
- For each uncovered file you read, cite it in the ledger with a verdict
  (clean / finding N).
- Keep findings actionable; severity P0–P3; no style nits unless they hide a
  real defect class.

Finish with: totals (files led by coverage status), the uncovered list with
verdicts, and an honest bottom line: is "whole-repo, file by file" true,
true-with-exceptions (list them), or overstated?
