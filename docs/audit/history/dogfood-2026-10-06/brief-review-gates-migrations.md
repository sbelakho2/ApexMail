# RIGOROUS adversarial review — the gates and the migrations

You are a rigorous adversarial REVIEW agent (no code edits). Work in
/Users/sabelakhoua/IdeaProjects/ApexMail. A gate that silently passes is worse than no gate; a
migration that loses or duplicates data is worse than no migration. Read FILE BY FILE.

## Slice 1 — every gate in `tools/` (241 files)
`tools/check_*.py`, `tools/*.sh`, `tools/contrast-audit/**` (the JS/Node gates),
`tools/migration_lint.py`, `tools/validate_*.py` if present. For each gate:
- **Can it fail?** Find a concrete input that should be refused and prove the gate refuses it —
  or show that it cannot (a regex that can never match the placeholder data, an assert on a
  string the generator always emits, a skip path that swallows the failure, an `except: pass`,
  a self-test that tests nothing). Run every self-test the gate ships.
- **Is it wired?** Every gate must be invoked from `ci/stages/validate.sh`, `ci/pipeline.sh` or a
  Makefile/CI config; an orphaned gate never runs. Cross-check the list of tools against the
  invocation list and report orphans.
- **Does it cover the whole surface it claims?** e.g. a consistency gate that checks billing +
  docs but not `apps/ai` (this class was found on 2026-10-06), a lint that globs one directory
  while the code has three.
- **Is its failure message actionable and honest?** A gate that fails without saying which file
  and what is wrong costs the next person an hour.

## Slice 2 — `services/mail-server/migrations/**` (216 files)
Read every migration for the queue/ledger/audit/suppression/session tables. Report:
- a constraint or index whose absence allows exactly the bug another crate documents preventing
  (e.g. a hash-chain table without the head-advance trigger, a queue without a dedup key);
- a migration whose down/rollback or idempotence is wrong (`CREATE TABLE` without `IF NOT EXISTS`
  in a re-runnable series, backfills that double on rerun);
- a comment claiming a behaviour the SQL does not implement;
- a `DELETE`/`UPDATE` without a WHERE that the series intends to be scoped.

## Deliverable
`docs/audit/dogfood-2026-10-06/review-gates-migrations.md`, per finding:
### <P0|P1|P2|P3> <file>:<line> — title
Evidence: <the exact snippet/command + observed result>   Why: <one or two sentences>
Fix: <minimal, concrete>
Plus a coverage ledger at the end: every gate name with VERIFIED-CAN-FAIL / CANNOT-FAIL /
ORPHANED, and every migration reviewed `- [x]` (or why not). Report honestly what you did not
reach; an incomplete review that says so beats a broad one that lies.
