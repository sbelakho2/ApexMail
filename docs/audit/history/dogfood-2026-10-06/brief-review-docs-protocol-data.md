# Brief — review: docs claims, protocol, root data, legal templates

You are a rigorous, adversarial reviewer for the ApexMail repo at the
workspace root. READ-ONLY: do not edit any file outside your report.

Deliverable: `docs/audit/dogfood-2026-10-06/review-docs-protocol-data.md` —
findings with severity (P0–P3), `file:line` evidence, why it matters, and a
concrete fix. Mark anything you could not verify as NOT-VERIFIED with the
reason.

The honesty contract to enforce: every factual claim in docs must match the
SHIPPED code/config — no aspirational "implemented" language for absent
features, no stale prices/limits/paths/commands, no docs describing removed
or renamed systems. (House rule from the owner: claims must match shipped
code — implementation, never qualification.)

Scope:
- `docs/**` (253 files). Read in full the load-bearing ones; for the rest do
  a claim-scan. Priorities: `docs/pricing.md` (paths/prices — the knowledge
  gate pins some of it), `docs/architecture/**` (component maps must match
  `services/mail-server/crates/*`), `docs/security/**` (feature-flag and
  HSTS claims), `docs/development/**` (commands that must run),
  `docs/tool-contracts/**` (must match the tools), `docs/operations/**`
  (runbook commands must exist), `docs/api/**` (must match routes mounted in
  api-server `app.rs`), `docs/audit/**` is history — skip except for
  internal contradictions. For each doc that names a file/route/flag/command,
  VERIFY it exists (grep the repo). Example classes already found in other
  slices: an env var documented but never read, a route documented but not
  mounted, a script renamed without the doc.
- `protocol/**` (execution-v1.json, risk-v1/**): validate the schemas parse,
  the risk-v1 fixtures/vectors are internally consistent, and any Rust/PHP
  consumer (grep for the file names) accepts them — a protocol file nothing
  reads is a finding.
- root `data/**` (24 files): the training corpus at the repo root — check
  the manifest.json against the actual files (counts, hashes if claimed),
  that system_prompts.json matches its .sha256, that the misc jsonl files
  are internally valid JSONL, and that any prices in them agree with the
  canonical catalog (services/mail-server/crates/platform-catalog). A
  second, drifted copy of the apps/ai corpus is a finding.
- `templates/compliance/**`, `templates/legal/**`: placeholders vs claimed
  usage (grep for the template ids in code); a template with unresolved
  placeholders that code renders directly is a finding.
- root docs: `README.md`, `fixes.md`, `marketing_audit_v2.md` — claims vs
  reality; `fixes.md` sounds like a changelog of claimed fixes — verify the
  load-bearing ones exist in code or mark NOT-VERIFIED.

Write the report incrementally; finish with a coverage ledger (per-directory
counts; full-read vs claim-scan) and an explicit "what I did not reach".
