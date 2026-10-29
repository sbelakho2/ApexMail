# Brief — review: remaining packages, test harnesses, load tests, reports

You are a rigorous, adversarial reviewer for the ApexMail repo at the
workspace root. READ-ONLY: do not edit any file outside your report.

Deliverable: `docs/audit/dogfood-2026-10-06/review-packages-harness.md` —
findings with severity (P0–P3), `file:line` evidence, why it matters, and a
concrete fix. Mark anything you could not verify as NOT-VERIFIED with the
reason.

Scope:
- `packages/sdk-go/**`: the Go SDK was NOT covered by the SDK-vs-API pass
  that fixed php/python/java/ruby (see docs/audit/dogfood-2026-10-06/fix-sdks.md
  for the ground-truth table and defect classes it found — check the Go SDK
  for the SAME classes: envelope unwrap on null error, non-2xx handling,
  missing methods the API mounts, path-segment escaping, webhook signature
  comparison, idempotency-key placement). Run `go test ./...` if a Go
  toolchain is available; otherwise state NOT-VERIFIED and do the static pass.
  Compare every method against the real routes (grep api-server `app.rs` and
  `routes/*.rs`).
- `packages/contract/**`, `packages/check_versions.py`, `packages/VERSIONING.md`:
  a version/contract checker that does not check the real versions (or that
  cannot fail) is a finding; verify its inputs exist and its failure path is
  reachable.
- `packages/smtp-auth-proxy/**`: read fully — it sits on the auth path
  (SMTP credentials); verify fail-closed behavior, timing-safe compares, no
  credential logging, and that its configuration matches how compose
  deploys it.
- `tests/browser/**` (root): the Playwright suite used by CI (481 tests).
  Review the harness for manufactured passes: tests that assert nothing,
  skips that hide required coverage, retries that mask flakes, and pages
  asserted against fixtures built by the same broken code. Check the
  a11y/contrast assertions are real (computed styles / axe, not hardcoded).
- `load-tests/**` (13 files): scenarios must assert thresholds and exit
  non-zero on breach; a load test that only prints numbers is a finding.
- `reports/**` (dark-mode-audit, live-dark-audit, visual-parity): inventory
  + spot-check any harness code for the manufactured-pass class; these are
  mostly artifacts — say so if so.

Write the report incrementally; finish with a coverage ledger and an explicit
"what I did not reach".
