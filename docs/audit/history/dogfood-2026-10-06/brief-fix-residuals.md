# Brief — residual fixes filed by the coverage-gap wave (no live-lane conflicts)

You are a fix agent. Repo root: /Users/sabelakhoua/IdeaProjects/ApexMail.
Five precise residuals were FILED with evidence in
`docs/audit/dogfood-2026-10-06/fix-report-coverage-gaps.md` (read the
"Filed" section) and in the coverage ledger. Fix each properly with a
can-fail proof; do NOT touch `crates/ui-foundation/**`,
`crates/api-server/src/routes/{ai_chat,web}.rs`,
`crates/worker-processors/src/reply_handler/**`, `crates/ai-service/**`,
`docs/eval/**`, or `tools/{bots_perf_budget,bots_disclosure_suite}.py` —
live agents own those right now.

## Items
1. `apps/ai/training/new_customer_profiles.py`: 19 stale values (prices/
   limits) vs the canonical catalog — the U-fix agent added an opt-in
   `--check-training-profiles` mode somewhere (verify where); make the
   profiles themselves canonical (derive or fix the literals) and wire the
   check so drift fails, without breaking `validate_pipeline.py`.
2. `deploy/grafana/dashboards/api-performance.json`: the endpoint-label bug
   the U-fix agent found (latent `endpoint` → `path_pattern` label class) —
   fix the queries/labels; confirm all panel `job=` labels exist in
   `deploy/prometheus.yml`.
3. `docs/operations/monitoring.md`: it claims metrics (process_*) that the
   api-server exporter does not expose — correct the doc to the shipped
   metric names (evidence: the U-fix report's U-14 notes).
4. `tools/ui_flash_extract.py::production_split()`: latent OVER-cut (the same
   class fixed in ui_routes.py: the naive first-`#[cfg(test)]` split) — fix
   with the masking approach used in the U-5 fix; prove with a fixture that a
   post-alias entry is extracted; run the flash-copy gate + form-hygiene gate
   afterward (they must stay green against COMMITTED fixtures).
5. `tools/contrast-audit/crop.mjs`: pathname decode bug (per the U-fix
   report) — fix; keep `gate.sh` green.

Also: record verdicts for the two "not reached" groups the coverage ledger
names (tools/contrast-audit support lib: `lib/png.mjs`, `gen-summary.py`,
`crop.mjs`; the remaining Grafana/monitoring dashboards) — read them; fix
anything broken you find (e.g. the crop.mjs item is one).

## Rules
- Every fix: can-fail proof (self-test/probe/mutation) captured in your
  report `docs/audit/dogfood-2026-10-06/fix-report-residuals.md`.
- Run the gates you touch (eval corpora, ui flash/form/link gates against
  committed fixtures, avoid the live-lane fixture churn — if a gate fails
  only because a live sibling is regenerating fixtures, say so and show the
  committed-fixture run).
- No deploy; no docker builds or compose actions (the live campaign owns the
  stack); no edits outside the named files.
