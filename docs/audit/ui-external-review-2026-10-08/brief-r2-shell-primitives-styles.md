# Lane R2 — shared shell, primitives, quality surfaces, and the console style authority

You are an extremely rigorous verifier-fixer. **ZERO SKIPS**: every finding is adjudicated with
literal command/output evidence. Read `docs/audit/ui-external-review-2026-10-08/review.md` and
`register.md` FIRST.

## Your scope (files — you own these exclusively)

`crates/ui-foundation/src/{shell.rs, primitives.rs, csrf.rs, flash.rs, qr.rs, lib.rs, charts.rs,
icons.rs, tokens.rs, routing.rs, axum_router.rs, fixture_states.rs, tracking_domain.rs, explorer.rs,
marketing.rs}`, `crates/ui-foundation/assets/globals.input.css`, `crates/ui-foundation/assets/globals.css`,
`crates/ui-foundation/tailwind.config.js`, `crates/ui-foundation/build.rs`.

Findings: §3 P1-3 (closed mobile nav hit area), P1-8 (native-select escaping — recon says the
primitive now escapes; PROVE it with a hostile-name test covering value/label/id/name and report
any remaining call-site interpolation), P1-9 (authored vs compiled console styles — CONFIRMED open:
the `.apex-mobile-nav*` rules exist in `assets/globals.css` but NOT in `assets/globals.input.css`;
and there may be more artifact-only blocks), P1-12 (failed-form replay retention/checkbox defaults),
P1-13 (QR mask spec orientation — recon: masks 1/2/4 carry the spec fix with a comment, but the
review's second half stands: an INDEPENDENT decoder must validate the generated codes; the current
test decoder shares the implementation), §4.6-4.10 (spacing/emptiness, depth, mobile behaviour,
native controls, form feedback) and §5.1's remaining rows (axum_router, primitives, shell, charts,
tokens, icons, lib, routing, ssr, flash, csrf, qr, tracking_domain, explorer, marketing,
fixture_states) + §5.2 rows (globals.input.css, globals.css, tailwind.config.js, build.rs, Cargo.toml,
README.md) + §11 CAPTCHA = **EXCLUDED** (record the standing KiwiCaptcha directive; optionally check
whether the vendored mirror is at the latest standalone release — do not edit anything).

## The style-authority repair (P1-9) — the centerpiece

1. Prove the divergence: regenerate the artifact from the input with the repo's own recipe
   (`apps/marketing-zola/tailwindcss -c crates/ui-foundation/tailwind.config.js -i
   crates/ui-foundation/assets/globals.input.css -o /tmp/globals.regen.css`) and diff against
   `assets/globals.css`; enumerate every artifact-only rule/block (the `apex-mobile-nav*` group is
   known; find the rest).
2. Move every artifact-only block INTO `globals.input.css` (with its explanatory comments), then
   regenerate `assets/globals.css` with the same recipe and prove:
   (a) the regenerated artifact contains every previously artifact-only rule;
   (b) the diff between the new artifact and the old one is exactly the intended change set;
   (c) `cargo nextest run -p ui-foundation` is green (class-integrity/contrast/golden gates parse
   this artifact);
   (d) the served console stylesheet still resolves (`/css/styles.css` 200, size sane) after
   `docker compose build api-server && docker compose up -d api-server` (mode/ownership fix already
   exists — verify it still holds for the regenerated file).
3. Fix the closed-state hit area per review §3 P1-3/§4.8 (drawer dimensions/background/scrolling only
   under `[open]`; closed state = summary control only) IN THE INPUT, regenerate, and re-run the
   render harness to prove the interceptions are gone: `cargo nextest run -p ui-foundation` plus the
   chromium-based checks (`chrome_tests`) and, where feasible, the browser suite
   (`BROWSER_TEST_BASE_URL=http://127.0.0.1:8080`, tests/browser) at 390px with the drawer closed.

## Other mandates

- P1-12: retention must be structurally scoped to the matching form and must REPLACE prior
  checked/selected attributes rather than accumulate; add tests that render a failed multi-form
  replay and assert no cross-contamination and no stale `default`/`checked` attributes.
- P1-13: validate the generator with an INDEPENDENT decoder (e.g. Python `segno`/`qrcode` via
  `python3 -c` if installed, else a small spec-based decoder written from ISO/IEC 18004 mask
  formulas — NOT a copy of the generator's logic) for masks 0-7 and at least two versions; keep
  the existing shared-decoder test but add the independent proof.
- §4.6-4.10: apply the review's shared-level refinements (transition-all → property lists, canonical
  timings, native controls vs inert custom exports incl. the "legacy exports are library risks"
  list at the end of §5.1, dialog/accordion/tabs/pagination/toast rows, flash payload cookie budget
  §5.1 flash.rs row, charts geometry/summaries §5.1 charts.rs row, icon class escaping §5.1
  icons.rs row, tokens.rs source-vs-artifact drift visibility).
- Any change that alters rendered HTML will move goldens: regenerate deliberately
  (`crates/ui-foundation/goldens/**`, manifest `docs/development/ui-baseline-manifest.json`) and say
  so in the report.

## Constraints

- Do NOT edit `leptos_views.rs`/`view_data.rs`/`web.rs`/`web/data.rs` (R1), marketing tree (R3/R4),
  emails/PDF/gates test files (R5). If a fix needs those, put the exact needed change in your report.
- KiwiCaptcha: excluded.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r2-shell-styles.md`: verdict table for every §3 P1
item in your scope, every §5.1/§5.2 row you own, §4.6-4.10; the artifact-only-rules inventory
(before/after); zero-skips appendix with literal commands/outputs; "reported for other lanes"; final
orchestrator paragraph.


## ADDENDUM — additional filed items (from lanes R1/R5; implement these too)

1. `axum_router.rs` ~2793: the stale assertion of removed copy (§4.2) — the campaigns bulk bar now
   says "Select the rows you want to act on"; update the assertion to match (keep it asserting the
   interaction, not the implementation).
2. `primitives.rs::status_indicator_config`: add the MFA/secret vocabulary so badges (not plain
   text) can render it: `"enabled" => ("Enabled", "success", DOT_SUCCESS)`,
   `"not_configured" => ("Not configured", "secondary", DOT_OUTLINE)`. Report for R6/fold to switch
   the two data.rs call sites to `DataCell::Status` afterwards.
3. `explorer.rs::sandbox_shell`: the "Back to the API Explorer" link is relative (`/api-explorer`)
   but the page is served from the API origin where that path does not exist — make it absolute
   (`https://apexmail.ee/api-explorer`), same pattern the verify-email page uses.
4. `tests/compare_pricing_parity_gate.rs`: missing python3 currently prints SKIP and returns green —
   make missing required tooling FAIL (`assert!(python3_available(), …)`).
5. Full-suite reds in your files: `axum_router::tests::marketing_routes_include_marketing_shell`
   (re-check against the CURRENT marketing templates/build), and any golden mismatches caused by the
   concurrent view edits — regenerate goldens as your LAST step (the normalizer is fixed now: the
   stylesheet-version replacement no longer doubles the token) and re-run the suite green.
6. Re-export the baseline fixtures (`crates/ui-foundation/baselines/**` via
   `cargo run -p ui-foundation --bin export_visual_fixtures`) after all code changes; the
   `docs/development/ui-baseline-manifest.json` hash must be consistent with what you ship.
