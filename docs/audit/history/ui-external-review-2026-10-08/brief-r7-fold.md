# Lane R7 — fold closer: apply every filed-for-fold item, then regenerate and run the battery

You are the last code lane before the fold. All prior lanes are done and filed exact, verbatim
instructions. Read these FIRST (they contain the exact code/x counts you must apply):
`lane-r1-console.md` §3, `lane-r2-shell-styles.md` §4, `lane-r3-marketing.md` §6,
`lane-r5-emails-pdf-gates.md` §4, `lane-r6-closer.md` §3. Standing rules: register.md (real global
fixes, verdicts with literal fail-before/fail-after evidence, no KiwiCaptcha, no git commit, report +
zero-skips appendix + orchestrator paragraph).

## Your files

`crates/ui-foundation/src/{routing.rs, axum_router.rs, leptos_views.rs}`,
`docs/development/ui-baseline-manifest.json`, `crates/api-server/src/routes/web.rs`,
`crates/api-server/src/routes/auth.rs` (JSON reset twin only),
`apps/marketing-zola/static/css/input.css` + `apps/marketing-zola/templates/**` (forced-colors and the
R4-filed template strings only), `tools/dev-start.sh`, `crates/ui-foundation/tests/**` only for the
specific reds named below.

## Work items

1. **Manifest + routing + render arm for `/lists/{id}/members`** — apply R6's verbatim §3.1, §3.2,
   §3.3 (routing counts web 39→40 total 130→131 with the comment; the manifest entry; the
   `render_web` arm inserted BEFORE the `/lists/…` catch-alls). Then prove the new route renders
   (`GET /lists/l_1/members` live or via a lib test) and the routing tests pass.
2. **`leptos_views.rs` clippy clean** — R2's filed exact fixes: `control_plane_app_layout_with_session`
   `too_many_arguments` (line ~221) and 3× `useless_format!` (~2851, ~2888, ~4281). End: `cargo clippy
   -p ui-foundation` has zero warnings from this file.
3. **`render_native_select` escaping** (leptos_views.rs ~405-421) — escape all six interpolations
   (value/text/id/name/label) at the helper boundary; add a hostile-name test.
4. **`/dashboard` mobile clipping** (R2 filed, proven pre-existing): at 390px the "delivery health"
   card's `p.mt-3.text-xs.text-surface-500.max-w-md` (rect x=−22, w=420) is past-viewport +
   clipped-by-card in light AND dark. Fix the view's mobile layout (no gate weakening); prove with
   the layout audit (`tools/contrast-audit/layout-audit.mjs` or its gate runner) that the two flags
   are gone and nothing else moved.
5. **Failed-POST checkbox-group replay values** — web.rs ~4512 (webhooks `events`), ~4368 (API-key
   scopes), and the placement `providers` group: record each selected value via `fields.set(...)`
   (the map's multi-value path re-checks them). Add/extend a failed-POST test asserting the
   re-checked group round-trips.
6. **Table scroll regions** — the shared row renderer must emit `tabindex="0"` + `role="region"` +
   an `aria-label` on `.apex-table-wrap` (R2: the CSS side is ready). One shared change, every table.
7. **Sales/CP status vocabulary switch** — R2 added `"enabled"`/`"not_configured"` to
   `status_indicator_config`; switch the two `data.rs` call sites (if a `data.rs` edit is required but
   you find it already done, verify) to `DataCell::Status`. Note: `data.rs` is not in your file list —
   if the switch is needed there, do it (R1/R6 are done) and say so.
8. **Marketing forced-colors for the error chrome** (R3's filed item; R3 unrecoverable): add the
   `@media (forced-colors: active)` block to `static/css/input.css` (system colours for CTA/secondary
   buttons, focus outline in `Highlight`) covering the 404/error chrome; rebuild the marketing CSS
   with the restored CLI (see item 10); prove the built artifact carries the rule.
9. **R4-filed template strings** (apply the template side; `i18n.json` is R4's and already updated):
   status.html and the compliance partials render English with zero i18n references, the features
   "Consistent SDKs" string, the email-logs MX-vs-placement sentence, two pricing-FAQ fallback drifts
   — wire them through `i18n.json` (R4 added the keys) or fix the source string; rebuild and prove
   the built pages.
10. **`tools/dev-start.sh` tailwind fallback** — the vendored CLI has been restored (official
    v3.4.17 macos-arm64, verified running). Also make the recipe robust: if the vendored binary is not
    executable on this host, fall back to `tailwindcss` on `PATH`, else fail with the official
    download URL for the host platform (README note). Prove the marketing CSS build runs end-to-end
    on this host with the restored binary (byte-stable vs the R2/R3 artifacts).
11. **`auth.rs` JSON reset twin** — R6 declared: the JSON reset path still requires `active`, so an
    invited user cannot accept via the API twin (browser path works). Bring it to parity (accept the
    invited state's setup token) with a test.
12. **Residual ui-foundation reds** — R6 filed: `form_field_map_repopulates_values_and_renders_errors`
    (static webhooks form vs R2's injection), `marketing_routes_include_marketing_shell` (re-check
    against the CURRENT built marketing pages). Fix each properly (or fix the assertion only if the
    assertion is objectively stale, with evidence).

## Then, as the FINAL steps (order matters)

13. Regenerate goldens: `UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_` (the normalizer
    is fixed — the stylesheet version token no longer doubles), then re-run without the env var and
    show green.
14. Re-export baselines + fixtures: `cargo run -p ui-foundation --bin export_visual_fixtures`; verify
    `docs/development/ui-baseline-manifest.json` consistency and note the new hashes.
15. Run and report (literal outputs): `cargo nextest run -p ui-foundation` (0 skipped),
    `cargo fmt --all --check`-equivalent for ui-foundation+api-server (CI-exact:
    `cd services/mail-server && cargo fmt --check`), `cargo clippy -p ui-foundation -p api-server`,
    all eight Python UI/marketing gates, `tools/contrast-audit/gate.sh`, the layout gate,
    `cargo run -p ui-foundation --bin dna_verify`.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r7-fold.md`: verdict table for items 1-14 with
fail-before/fail-after evidence, the goldens/baselines delta summary, the full gate battery output,
zero-skips appendix, final orchestrator paragraph (counts + anything left failing with exact error).
