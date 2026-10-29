# External UI/UX review — findings register (2026-10-08)

Source: `review.md` (the pasted external review, 867 lines, sections 1-14). This register maps every
finding to an owning lane and defines the evidence contract. Lanes fill per-item verdicts in their
own lane report; the close-out (`closeout.md`) merges them.

## Rules for every lane

1. **Verdict per finding**: `FIXED-ALREADY` (with the exact file:line + evidence proving the current
   tree satisfies it — a fix counts only if the CURRENT tree shows it, not if a past commit said so),
   `FIXED-NOW` (fail-before evidence + fix + fail-after evidence), or `EXCLUDED` (with the reason —
   only the KiwiCaptcha constraint qualifies).
2. **Zero skips**: every finding is adjudicated. "Could not verify" is not a verdict; if a finding
   cannot be reproduced, prove it with the exact command/output that shows the current behaviour.
3. Fixes must be real and global: shared primitives/templates/builders, never inline one-offs; the
   repo's standing rules apply (no honest-error cop-outs, no docs-removal, claims must match shipped
   code).
4. `cargo fmt` on every touched Rust file; run the affected test suites + the relevant gates
   (`ui-foundation` suite, python ui gates, contrast/layout gates, marketing build where touched).
5. Do NOT touch KiwiCaptcha surfaces (section 11 findings are EXCLUDED by standing owner directive:
   `packages/kiwicaptcha`, its mirrors in marketing resources/public, its build/suites — consume the
   latest version only).
6. Do not `git commit`. Write your lane report under
   `docs/audit/ui-external-review-2026-10-08/lane-<x>.md` with the verdict table + a zero-skips
   appendix (literal command + literal output per finding or per finding group) and a final
   orchestrator paragraph.

## File ownership (no two lanes edit the same file)

| Lane | Owns |
|---|---|
| R1 console+CP Rust | `crates/api-server/src/routes/{web.rs,web/data.rs}`, `crates/ui-foundation/src/{leptos_views.rs,view_data.rs}` |
| R2 shell+primitives+styles | `crates/ui-foundation/src/{shell.rs,primitives.rs,csrf.rs,flash.rs,qr.rs,lib.rs,charts.rs,icons.rs,tokens.rs,ssr.rs,routing.rs,axum_router.rs,fixture_states.rs,tracking_domain.rs,explorer.rs,marketing.rs}`, `crates/ui-foundation/assets/globals.input.css`, `crates/ui-foundation/assets/globals.css`, `crates/ui-foundation/tailwind.config.js`, `crates/ui-foundation/build.rs` |
| R3 marketing build (templates/styles/data/assets) | everything under `apps/marketing-zola/{templates,static,data,config.toml,Dockerfile,nginx.conf,_headers,_redirects,.htaccess,manifest.json,*.svg,*.txt,*.xml,*.yaml,openapi*}`, `tools/check_marketing_serving.py` |
| R4 marketing content (all 177 md + i18n) | `apps/marketing-zola/content/**`, `apps/marketing-zola/i18n.json`, legal templates under `docs/legal/**` referenced by section 13 when they are the marketing-source twin |
| R5 emails/PDF/legal+gates | transactional email sources (api-server `routes/admin/forgot_password.rs`, `routes/auth.rs` email builders, `notification_drain.rs`, `system_sender.rs`), `crates/pdf-renderer/**`, marketing error pages in `apps/marketing-zola/static/50x.html`+`404.html` (only these two files), gates: `crates/ui-foundation/tests/*` + `crates/ui-foundation/src/gate_support.rs`(if not in R2 list) + `tools/check_ui_*.py`, `tools/ui_*.py`, `tools/validate_pricing_drift.py`, `tools/check_marketing_contrast.py`, `tools/contrast-audit/**`, `deploy/tests/**` |

Coordination: R1 must not edit shell/primitives/styles; if a fix needs them, it states the exact
required change in its report (R2 implements). R5 must not edit `web.rs` (R1 owns); it reports
needed handler changes. R3 owns marketing templates; R4 owns marketing content — a content fix that
needs a template change is reported to R3, and vice versa.

## P1 register (section 3) — highest priority

| # | Finding | Where | Provisional status from recon | Lane |
|---|---|---|---|---|
| P1-1 | Editing a campaign can use the create path | leptos_views editor + dispatch | Recon: `/web/campaigns/update` route + golden exist; verify full identity-preserving round trip E2E | R1 |
| P1-2 | Scheduling copy contradicts executable behavior (manual Start vs worker auto-send) | editor + campaigns.rs | Recon: editor copy says "saving a schedule authorizes that automatic send"; sweep ALL scheduling copy incl. detail page | R1 |
| P1-3 | Closed mobile navigation blocks content (320px full-height hit area) | shell.rs + CSS | Recon: artifact CSS claims closed=summary-only; verify in the compiled artifact AND that input.css carries it; re-run the 600-check render harness | R2 |
| P1-4 | Populated bulk tables emit nested forms | leptos_views | Recon: FIXED-ALREADY (row forms are siblings with `form=`; verify in populated fixtures + form_hygiene gate) | R1 (+R5 gate) |
| P1-5 | Live settings rendering removes existing actions (api keys/team/billing/dedicated IPs/webhooks/contacts CSV/CP audit CSV) | data.rs composition | Verify page-by-page live; compose action forms with data-backed tables | R1 |
| P1-6 | Domain Verify DNS targets the wrong route | leptos_views:547-556 + router | Recon: action `/web{base}/verify`; compare with the mounted handler; fix + rendered-form route test | R1 (+R2 if route context) |
| P1-7 | Template editing is not a coherent round trip | editor + handler | Recon: loads values + blank-keeps-stored fixed; verify redirect targets + save semantics consistent | R1 |
| P1-8 | Native select options not escaped | primitives.rs:551-574 | Recon: FIXED-ALREADY (`html_escape` value/label/id/name); prove with hostile-name test | R2 |
| P1-9 | Authored and compiled console styles diverged | globals.input.css vs globals.css | Recon: CONFIRMED — `mobile-nav` rules exist only in the artifact; move all artifact-only blocks into input, regenerate, prove gates green and artifact stable | R2 |
| P1-10 | Translated quickstarts empty | content/quickstart/* | Recon: de/es/fr are 370 lines each — verify bodies are real translations of the EN guide (not stubs) | R4 |
| P1-11 | Translated SLAs omit terms | content/sla/* | Recon: de/es/fr 62 lines vs EN 67 — compare substantive sections; restore equivalent terms | R4 |
| P1-12 | Failed-form replay can restore incorrect controls | axum_router/primitives retention | Verify scoping + checkbox default survival; fix structurally | R2 |
| P1-13 | MFA QR mask formulas 1/2/4 transposed; test decoder shares implementation | qr.rs:156-165 | Recon: code comment says spec orientation restored; MISSING independent-decoder validation — validate with an independent decoder and keep the pin | R2 |

## P2 register (section 3)

| # | Finding | Lane |
|---|---|---|
| P2-1 | Placement detail always static waiting view; wire real results + running/completed/failed | R1 |
| P2-2 | Calculator slider not authoritative (handler reads number field) | R3 |
| P2-3 | Public claims vs catalog (recurring Free 3k, annual savings 16.7% not 10%, dedicated-IP entitlements, SDK availability) | R3 (pages/data) + R4 (content/i18n) |
| P2-4 | Delivered PDFs do not use the designed Typst layouts | R5 |

## Section map (for lanes; full text in review.md)

- §4 global recommendations (4.1 composition, 4.2 copy, 4.3 state language, 4.4 hierarchy, 4.5
  typography, 4.6 spacing, 4.7 depth, 4.8 mobile, 4.9 native controls, 4.10 form feedback, 4.11
  scheduling consent, 4.12 preview vs fidelity, 4.13 pricing authority, 4.14 localization,
  4.15 brand beyond app): R1 (4.1-4.5, 4.11), R2 (4.6-4.10, 4.12), R3 (4.13-4.15).
- §5 shared Rust UI: R1 (leptos_views/view_data/data rows), R2 (all other rows incl. 5.2).
- §6 customer console pages: R1. §7 control plane pages: R1.
- §8 marketing templates (all 71): R3. §9 marketing styles/data/config/assets: R3.
- §10 marketing content (all 177 files, 54 families): R4.
- §11 CAPTCHA: EXCLUDED (KiwiCaptcha constraint) — R2 records the constraint + latest-version check only.
- §12 emails/error pages/PDF: R5 (error pages split with R3 as noted). §13 legal templates: R5+R4 as
  owned. §14 testing/manifests/generated artifacts: R5 (gates) + R2 (`export_visual_fixtures`,
  `pixel_parity`, `theme_contrast_tests`, `dna_verify`, `golden_tests` live in ui-foundation tests →
  R5 owns the test files; R2 owns the src they exercise).
