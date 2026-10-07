# Whole-repo dogfooding campaign — final report (2026-10-05 → 2026-10-07)

Scope: 100% whole-repo dogfooding, file by file, per the owner's instruction.
Layers: (1) adversarial code reviews by sub-agents across every top-level
surface, (2) live plane exercises against the running stack, (3) a 35-probe
adversarial console harness, (4) 481 browser tests across three engines,
(5) gate-and-migration review with can-fail proofs, (6) fix fleets with
regression tests verified to fail before and pass after.

## Coverage by surface (review layer)

| Surface | Reviewer artifact | Findings |
|---|---|---|
| frontend + gateways | findings-frontend-and-gateways.md | (see file) |
| delivery plane | findings-delivery-plane.md | (see file) |
| sales / money / compliance | findings-sales-money-compliance.md | (see file) |
| mail plane (live) | dogfood-mail-plane.md + ledger-mail-plane.md | live |
| money/compliance/enterprise (live) | dogfood-money-compliance.md + ledger | live |
| sales/ai/analytics (live) | dogfood-sales-ai-analytics.md + ledger | live |
| gates (tools/) + migrations (216→217) | review-gates-migrations.md | P1×5, P2×5, P3×5 |
| apps/ai training canon | fix-report/fix agents + knowledge gate | fixed |
| SDKs vs live API | fix-sdks.md | 8 fixed, 0 unfixed |
| KiwiCaptcha packages | fix-kiwicaptcha.md | 4 fixed, 0 unfixed |
| infra (deploy/, ci/, scripts/, secrets policy) | review-infra.md | 6×P1 (rollback path broken 3 ways, verify policy inverted, secret-rotation backups empty, gates-only run can bless undeployed sha), 5×P2, 9×P3; secrets/** verified untracked dev fixtures (brief correction) |
| docs claims, protocol, root data, legal templates | review-docs-protocol-data.md | P0 (7 capabilities claimed vs NotYetImplemented), P1×8 (stale ladders, SLA cap contradiction, config doc 49 phantom vars, broken parity gate, corpus digests, phantom revoke route, VDP placeholders), P2/P3 set |
| remaining packages (go SDK, contract, smtp-auth-proxy), test harnesses, load-tests | review-packages-harness.md | 1×P1 (Go SDK wrong idempotency header + manufactured tests), 14×P2, 9×P3; protocol/risk-v1 verified consumed+consistent |

Fix waves launched from these reviews: `brief-fix-infra.md` (every P1/P2 +
mechanical P3s), `brief-fix-packages.md` (Go SDK to the live-verified bar,
check_versions CI wiring, browser-suite CI wiring, k6 fix), `brief-fix-docs.md`
(docs/data/legal P1s + the capability ground-truth table driving the follow-up
implementation wave).

Non-agent verification layers (all executed in this campaign):

* console adversarial harness — 35/35 probes (`tools/dogfood-live-adversarial.py`)
* browser suites — 481 tests (Chromium 220, WebKit-a11y 240, Firefox 21)
* contrast/visibility gates — tools/contrast-audit/gate.sh, 88 pages,
  0 WCAG AA failures, classifier self-test 12/12
* ui-foundation unit + gate suite — 468/468 (incl. gates J, K, L and the
  new surface-ladder / palette-policy pins)
* validate-stage gates — run individually (see below)

## Fixed in this campaign (representative, all with regression tests)

### UI / theme (owner reports)
* MFA notice contrast; console/cp/marketing global palette (green purged,
  maroon gradients flattened, classic apexmail red restored); grey-on-grey /
  grey-on-black visibility sweep; selection highlight; surface-ladder pins;
  content-hashed `globals.css` with ETag/304; marketing `styles.css`
  regenerated with the pinned Tailwind v3.4.17 (dark `--card` drift fixed),
  obsolete double-guard sed removed from the marketing Dockerfile.

### Honesty / routing / security
* P0 web route gating (4 admin routes moved to the gated router)
* primitives attribute escaping; compliance `suppressions` module + policy
* SSO/MFA bypass closed; verifier word-currency price bypass closed
* ai drafts `first_response` flag + queue ordering; demos params fidelity;
  public demo viewer verified live; demos completed-session honesty
* `check_web_error_honesty` masker bug fixed (multi-line strings desynced the
  mask; the gate only scanned 34% of web.rs) + self-test wired into CI
* knowledge/pricing-drift gates re-based on the platform-catalog delegation
  shape (+2 new self-test mutation classes); `apps/ai` canon now pinned
  (price/annual/emails/api + PAYG tiers + overage map, parsed as a literal)

### Gates (review-gates-migrations.md items)
* `check_marketing_contrast.py` rewritten: parses BOTH stylesheets, cross-checks
  authored vs built, WCAG pairs in both themes, `--self-test` (4/4) — and it
  immediately caught the real `--card` drift; wired as ui gate M (required)
* `check-risk-lua-parity.sh` wired into validate; `check_hsts_preload.py`
  documented as the manual preload probe
* `check_outbound_delivery_contract.py` now scans `.sql` with a working
  migrations allowlist prefix
* `check-forbidden-patterns.sh` `--require-build` (CI runs it post-build);
  pre-commit hook name states the skip
* `check_ui_links.py` `--require-marketing` (ui.sh passes it when the
  marketing build is unavailable) — a green run can no longer mean "site
  was never built"
* `check_flash_copy.py` root validation (exit 2) — also fixed a latent
  `main()` return-value discard that made exit-2 paths exit 0
* `migration_lint.py` (g) unscoped-DML rule (dollar-quote/string aware;
  spares upserts, FOR UPDATE, trigger DDL)
* `scripts/consistency-test.sh` repaired end-to-end: removed-path legal
  constants target, restored `DATA_RESIDENCY_WORDING` to the live crate +
  const↔canonical.json equality pin, static-EEA telemetry pins
* i18n: `footer.your_privacy_choices` added for de/fr/es (audit now 0 findings)

### Migrations (ledger-safe sweep, documented procedure)
* 050: H-08 guards now ABORT on any partial shortfall (5 sites; warning→
  exception), header comment corrected to the code's behavior
* 115: remnant drop guarded by real partitioned-parent existence + row-count
  comparison (the comment's promise is now the code)
* 095: complaint_events canonical shape correctly attributed to 093; dead
  CREATE replaced by a guarded default repair (+ index behind the same probe)
* 002/110: UIDNEXT now non-decreasing (`GREATEST`) — RFC 3501
* 127: retry-policy matcher catches `{}` policies, survives non-numeric
* NEW 245: `dsr_verification_outbox` idempotency identity
  `uq_dsr_outbox_request (tenant_id, request_id)` + dedup of replay rows +
  `ON CONFLICT DO NOTHING` in `gdpr_automation.rs`; regression test
  `dsr_outbox_replays_collapse_on_the_tenant_request_identity`
* Ledger checksums refreshed for the six edited frozen files via the new
  `tools/refresh-migration-ledger.py` (sha384, verified byte-identical to the
  sqlx algorithm); local ledger at 217/217 consistent; production sweep is
  the documented one-command step (backup kept by ci/stages/migrate.sh)

## Fleet A/B fix reports (agent-authored)
* delivery (items 1, 2, 7, 8, 9) — fix-report-open-findings.md §items 1,2,7,8,9
* money/compliance/tracking (items 3, 4, 5, 10, 11, 12, 13, 14, 15) — pending
* console/demos/AI (items 6, 16, 17, 18) — pending
* SDKs — fix-sdks.md (8 fixed, live suites 41/41, 43/43, 39/39, 3/3)
* KiwiCaptcha — fix-kiwicaptcha.md (4 fixed; Rust 632, PHP 1121/239/1550;
  browser 481 across engines)

## Residual / operator items

* Production ledger refresh for the six edited frozen migrations (deploy-time;
  the tool + procedure above).
* The three remaining review agents' findings (infra; docs/protocol/data;
  packages/harness) — findings will be triaged into this ledger as they land;
  P0/P1 items get the same fix-with-test treatment.
* `check_rust_panic_paths` docstring scope note and the small set of gates
  without self-tests (review labeled gate hygiene, not defects).
* Deploys remain the owner's action (standing instruction: no deploy).

*This report is finalized in the campaign commit; see the commit message for
the file-count summary.*
