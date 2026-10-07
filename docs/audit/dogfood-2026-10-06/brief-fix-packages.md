# FIX FLEET — packages & harness findings (from review-packages-harness.md)

You are a FIX agent with a rigorous mandate. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail. READ
docs/audit/dogfood-2026-10-06/review-packages-harness.md in full first, plus
docs/audit/dogfood-2026-10-06/fix-sdks.md for the ground-truth route table and
the defect classes the php/python/java/ruby pass fixed (the Go SDK must reach
the same bar).

Own these paths ONLY: `packages/sdk-go/**`, `packages/contract/**` (only if
needed), `packages/check_versions.py`, `packages/README.md`,
`load-tests/**`, `tests/browser/**` (harness only), `ci/stages/test.sh` and
`ci/pipeline.conf` ONLY for the browser-suite wiring item. Do NOT touch
`services/mail-server/**`, `apps/**`, `ci/**` beyond those two files,
`deploy/**`, or other `packages/sdk-*` (already fixed).

## Items

Go SDK (fix all; the bar is the live-verified behavior, not the existing tests):
1. GO-1 P1: send `Idempotency-Key` (the server reads that, not
   `X-Idempotency-Key`; see `middleware/idempotency.rs`). Fix the client AND
   the tests that assert the wrong header (they manufacture the green).
2. GO-2..GO-5: decode the real response shapes — bare arrays for
   `Events.List`/`GetByMessage`/`Analytics.Volume`/`Events.Timeseries`/
   `APIKeys.List`; `Events.Get` unwraps... whatever the route actually
   returns; snake_case tags matching the payloads. Use the ground-truth
   shapes from fix-sdks.md's method-vs-route method (capture from the live
   server or read the Rust handlers).
3. GO-6..GO-9: drop `template_id`/`template_data` from send (server 422s),
   capture messages-list pagination meta, stop sending `cursor` to the four
   `deny_unknown_fields` routes, fix the events filter params to the accepted
   set (and expose the accepted ones).
4. GO-10: add the missing mounted-domain methods.
5. GO-11/GO-12: make README/CHANGELOG compile and be true; rewrite the
   manufactured test fixtures to encode the real shapes (no fixture may
   assert a payload no route produces).
6. Run `go test ./...` (if a Go toolchain is absent, say NOT-VERIFIED and
   leave fully-compiling, real-shape code + tests).

Contract: wire `packages/check_versions.py` into the validate stage (required,
matching `ci_check` conventions) since it claims to be the CI gate (CV-1);
fix the zip off-by-one (CV-2); fix `packages/README.md`'s cursor-pagination
claims (CV-3).

smtp-auth-proxy (SP-1): decide from evidence — if compose/deploy does not
consume it, make the package's own docs state exactly that (verified
inactive) without implying an active auth path; if something references it,
implement the proxy. State which and why.

Browser suite (BR-1/BR-3): wire the suite into CI. It runs against the PHP
port locally (`php -S`); in CI, add it to `ci/stages/test.sh` behind a
`CI_BROWSER_SUITE_CHECK` flag (default `required` in pipeline.conf, matching
the UI-gate convention) with a precondition check that fails closed when the
runtime (php + playwright browsers) is missing, and a clear message for
advisory runs. Also stop the cross-engine lane retrying the
adversarial/security suites (BR-3), or mark those as retry-exempt.

Load tests (LT-1..LT-5): fix `http/load-test.js` so k6 can actually start
(thresholds on defined metrics; verified by running k6 locally), threshold the
smoke test for real (fail at meaningful error rates and assert the documented
contract), fix the authenticated scenarios' auth/payload contract against the
real routes, fix the baseline endpoints to mounted routes, and wire or
document the load tests per `tools/README.md` conventions.

## Rules
- No deploy. Local runs only (docker compose stack is fine).
- Every fix needs a regression proof: the failing-before/passing-after command
  + captured output in docs/audit/dogfood-2026-10-06/fix-report-packages.md.
- Where you must change a fixture for the live probe, use the provisioned
  dogfood owner credentials or provision via the documented signup→Mailpit
  flow.
- Report per item: FIXED (evidence) or a named blocker (with what you tried).
