# Lane R5 — transactional emails, error pages, PDF pipeline, and the UI gate battery

You are an extremely rigorous verifier-fixer. **ZERO SKIPS**: every finding is adjudicated with
literal command/output evidence. Read `docs/audit/ui-external-review-2026-10-08/review.md` and
`register.md` FIRST.

## Your scope (files)

- Transactional/security email sources: `crates/api-server/src/routes/admin/forgot_password.rs`,
  `crates/api-server/src/routes/auth.rs` (email builders/presentation), the web-side verification/
  reset/resend shells (read `web.rs` for evidence but DO NOT edit it — report needs to R1),
  `crates/worker-processors` notification drain / system sender presentation.
- Marketing error pages: ONLY `apps/marketing-zola/static/50x.html` and `apps/marketing-zola/static/404.html`
  (R3 owns everything else in that tree).
- PDF: `crates/pdf-renderer/**` (incl. `compiler.rs`, the Typst templates `*.typ`, `invoices.rs`,
  `routes.rs`), plus the invoice/agreement call sites in `crates/billing-service` where the payload
  schema lives (edit only if the renderer contract demands it; keep changes minimal and tested).
- Legal source templates under `docs/legal/**` (review §13) — adjudicate authority/consistency
  findings (revision/roles/links/credits wording); coordinate with R4 in your report where the public
  twin lives in marketing content.
- Gates: review §14.1 (Rust) + §14.2 (Python) + §14.3 (browser/visual infra rows): the test files
  under `crates/ui-foundation/tests/**` + `src/{gate_support? no—R2 owns src}`, `tools/check_ui_*.py`,
  `tools/ui_*.py`, `tools/validate_pricing_drift.py`, `tools/check_marketing_contrast.py`,
  `tools/contrast-audit/**`, `deploy/tests/**`.

## Findings

- §12.1 all email rows (viewport/background resilience, HTML fallback URL, plain-text parity incl.
  the unrequested-code warning, browser shells aligned with API equivalents, invitation honesty —
  §12.1's last row matters: invitation handlers create records without an email; the UI must not
  imply delivery unless the delivery path exists. If the delivery path is missing, IMPLEMENT it —
  the platform already queues system email; find the canonical path and wire it, with tests).
- §12.2 error pages (main landmark/branded focus on 404; unsupported incident assurances on 50x are
  removed; inline fallback styling so an external-stylesheet failure cannot erase presentation).
- §12.3 + §3 P2-4: PDF presentation. The Typst templates exist but the current renderer emits generic
  data-oriented output. Per the standing owner directive, PREFER WIRING the intended layouts over
  relabeling — investigate `crates/pdf-renderer/compiler.rs` (≈778-804 region in the review's tree),
  determine whether Typst compilation is available in the build (vendored binary? feature?); if the
  pipeline genuinely cannot produce the designed layouts without a new dependency that cannot be
  vendored, implement the best faithful presentation the crate can render AND make every label
  truthful; say exactly which path you took with evidence. Also: invoice currency/payment terms from
  authoritative data (not euro-hardcoded), Unknown ≠ Fail in the compliance report, metric-specific
  improvement direction in QBR, percentage units/identity consistency.
- §13 legal templates: authority/consistency rows; do not refresh dates without substantive change.
- §14.1/14.2/14.3: for EVERY row, adjudicate (FIXED-ALREADY w/ proof the gate now does what the
  review asks | fix the gate/test now | stale). Key ones: `form_hygiene_tests` must cover POPULATED
  state fixtures (the P1-4 class of bug); `class_integrity_tests` must parse selectors (comments/
  strings/decimals are not class definitions); `chrome_tests` must include stateful documents/result
  pages/aliases; `golden_tests` stylesheet-version normalization; `link_integrity_tests` quoted/
  unquoted/fragments/hosts/methods; `pixel_parity` independent baselines (self-comparison is not
  parity); `theme_contrast_tests` computed pairs; `dna_verify` must exit non-zero on failure;
  python gates per the review (§14.2 rows: control IDs/error associations, effective submit
  overrides + CSRF binding, host/surface link resolution + fragments, terminology on visible copy,
  missing fixture coverage fails, method/mount preservation, lexical flash extraction, source
  offsets incl. shared renderers, narrow+owned allowlists, pricing drift incl. rendered locale
  strings + dormant snapshots, marketing serving extended to versioned assets).
- §14.3: browser/visual infra — read the current suites (tests/browser playwright, a11y specs,
  widget/asset-mode specs) and adjudicate each row; where a suite exists and covers it, mark
  FIXED-ALREADY with the test name; where the row asks for coverage that is genuinely missing, add it.

## Environment / how to run gates

Test env: `TEST_DATABASE_URL=postgres://apexmail:<secrets/postgres_password.txt value>@127.0.0.1:5432/apexmail`,
`TEST_DATABASE_ADMIN_URL=…:5432/postgres`, `TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`;
browser suite needs `BROWSER_TEST_BASE_URL=http://127.0.0.1:8080` and the live stack (docker context
`colima-local`). Run python gates directly (`python3 tools/<gate>.py --self-test` where supported,
then a real run); run Rust gates with `cargo nextest run -p ui-foundation -E 'test(<gate>)'`.

Constraints: do NOT touch KiwiCaptcha (standing directive), `content/**` (R4), marketing templates
other than the two error pages, or R1/R2-owned Rust files.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r5-emails-pdf-gates.md`: verdict table for §12, §13,
§14 (every row), P2-4; zero-skips appendix with literal commands/outputs; "reported for other lanes";
final orchestrator paragraph (counts + anything left failing with exact error).
