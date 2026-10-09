# Lane R7 — fold closer: every filed item applied, goldens/baselines regenerated, full battery

Scope executed exactly per `brief-r7-fold.md` after reading `register.md` and the filed sections of
`lane-r1-console.md` §3, `lane-r2-shell-styles.md` §4, `lane-r3-marketing.md` §6,
`lane-r5-emails-pdf-gates.md` §4, `lane-r6-closer.md` §3. Working tree, no git commit, KiwiCaptcha
untouched. Paths are repo-root-relative unless noted; test env for DB-backed api-server runs is the
one documented in `brief-r1-console.md` §Environment
(`TEST_DATABASE_URL=postgres://apexmail:<pw>@127.0.0.1:5432/apexmail`,
`TEST_DATABASE_ADMIN_URL=…:5432/postgres`,
`TEST_REDIS_URL=redis://:dev-redis-password-minimum-32-chars@127.0.0.1:16379/0`).

---

## 1. Verdict table (items 1–14)

| # | Item | Verdict | Evidence (fail-before → fail-after) |
|---|---|---|---|
| 1 | `/lists/{id}/members` manifest + routing + render arm | **FIXED-NOW** | Fail-before: the new lib assertion fails with the arm removed — `panicked at axum_router.rs:3039: the members route must render the members skeleton, not the list detail` (temporary arm removal, literal output in §2.A). After: `counts_declared_routes`, `concrete_dynamic_manifest_paths_resolve`, `route_coverage_matches_baseline_manifest` all PASS; manifest web 40 / total 131; golden `goldens/web/lists_l_1_members.html` exists; export fixture `web-lists-l_1-members.html` (desktop 1440 + mobile 390). |
| 2 | `leptos_views.rs` clippy clean | **FIXED-NOW** | Fail-before: `cargo clippy -p ui-foundation` → `too_many_arguments` at `leptos_views.rs:221` + 3× `useless_format!` (2851/2888/4281), `generated 4 warnings`. Fix: grouped `ControlPlaneSessionContext` (both call sites + 2 test call sites updated) and dropped the three literal `format!`s. After: `grep -c '-->'` on clippy output = **0**; `grep -c leptos_views.rs` = **0**; no `ui-foundation (lib) generated` line. |
| 3 | `render_native_select` escaping + hostile test | **FIXED-NOW** | Fail-before: the helper interpolated value/text/id/name/label raw (leptos_views.rs:405-421, R2 §4.2). After: all six interpolations `html_escape`d; new `native_select_helper_escapes_every_interpolation` passes (5 hostile `<script>` payloads → 6 escaped occurrences, zero raw). |
| 4 | `/dashboard` mobile clipping | **FIXED-NOW** | Fail-before (layout audit, 390-class mobile): `FLAG web /dashboard [dark/mobile] findings=2` / `[light/mobile] findings=2` — `past-viewport`+`clipped-by-card` on `p.mt-3.text-xs.text-surface-500.max-w-md` rect `x:-22 w:420`. Fix: `max-w-full` on the DNA card, `min-w-0` on the chart wrapper, `max-w-full` on the fixed-width SVG. After: `ok` on all 5 runs (`Done: 0 layout findings across 5 runs`); full layout gate `0 findings across 1196 runs`. |
| 5 | Failed-POST checkbox-group replay | **FIXED-NOW** | The handlers recorded errors but not the selected values. Fix: `FormFieldMap::add_value` (appends; the render pass' grouped path re-checks every posted option), webhooks `events` recorded before any failure exit (incl. the duplicate-URL path now carrying the map), API-key `scopes` + name/expiry replay on every validation/authorization refusal, placement handler moved to the lossless parser + `data-form-id="placement-test-create"` (was a lone `data-form=` typo) + `providers` recorded. Tests: `form_field_map_round_trips_into_the_rendered_form` (grouped replay replaces defaults), `webhook_create_binds_the_checkbox_group` (failed POST → cookie → GET render re-checks), `console_api_key_form_shares_the_json_policy` (escalation replay), `placement_failed_post_replays_the_provider_group` (all four literal outputs in §2.D). |
| 6 | Table scroll regions | **FIXED-NOW** | `primitives::Table::render_html` now emits `tabindex="0" role="region" aria-label="<caption> (scrollable table)"` (generic label when captionless) on `.apex-table-wrap`; the two handwritten `.apex-table-wrap` tables (cp demos, alert rules) get the same attrs. New `table_scroll_region_is_keyboard_reachable_and_named` passes; the CP class swap (`apex-table-wrap--scroll`) still matches (substring). |
| 7 | Status vocabulary switch | **FIXED-NOW** | `web/data.rs::mfa_state_cell` now returns `DataCell::Status("enabled"\|"not_configured")`, rendering through `primitives::status_indicator_config`’s R2-added mappings ("Enabled"/"Not configured"). The loader test was re-pinned to the wire vocabulary + the badge label (`render_data_cell(&Status(...))` contains "Not configured") and to reject `sent`/`draft` **status** cells. `live_loaders_keep_exports_filters_and_honest_labels` PASS. |
| 8 | Marketing forced-colors | **FIXED-NOW** | Fail-before: `grep -c forced-colors apps/marketing-zola/static/css/styles.css` → 0. Fix: `@media (forced-colors: active)` block in `static/css/input.css` (CTA/secondary + `--invert` twins → `ButtonFace/ButtonText`; focus outline `2px solid Highlight` for `a/button/[tabindex]`). Built artifact carries it byte-for-byte (snippet in §2.E); the 404's `class=btn-primary` page links `styles.css?h=6c42d013…`. |
| 9 | R4-filed template strings | **FIXED-NOW** | Wired: status badge/h1/lead/description → `status.title`/`hero_title`/`hero_subtitle`/`description`; compliance badge/h1/lead/CTA → `compliance.hero_badge`/`hero_title`/`hero_subtitle` + `cta.cta_button` (cta.html was already wired — verified 4 refs). Source fixes: `features/details.html` EN fallback now qualifies the SDKs ("in active development and not yet published to public package registries"); `pricing-faq-island.html` EN fallback €0.35/1,000 + "16.7% saving"; `email-logs/timeline.html` carries the explicit "recipient-MX acceptance is not inbox placement" sentence. Built-page proofs in §2.E. **Disclosed partial:** the `compliance/data-retention` heading stays English — no `compliance.*` retention key exists in any locale (R4 added none; verified by dumping every key), and the section is shared policy content, not marketing copy. |
| 10 | `tools/dev-start.sh` tailwind fallback | **FIXED-NOW** | New `resolve_tailwind_cli`: vendored binary → `tailwindcss` on PATH → `error` with the official v3.4.17 URL for the host platform (+ README note in `ui-foundation/README.md`). All three branches exercised against the real function text (§2.F). End-to-end builds on this host with the restored binary: console `globals.css` first reproduced R2's artifact **byte-identically** (`f85852ae…`, before any source change), then after the intentional AA fix two consecutive regenerations are byte-identical (`7179adaa…`); marketing `styles.css` two consecutive builds byte-identical (`6c42d013…`). |
| 11 | `auth.rs` JSON reset twin parity | **FIXED-NOW** | Fail-before (R6 §3.7): the JSON twin required `status='active'`, so an invited user was refused. Fix: accepts `active\|invited` and promotes `invited → active` in the same guarded UPDATE; the response message distinguishes the acceptance. New invited case in `reset_password_arms_and_success_consume_token_and_change_hash`: status becomes `active`, hash rotates, token metadata consumed (3.8 s live run with DB+Redis). |
| 12 | Residual ui-foundation reds | **FIXED-ALREADY (verified) + FIXED-NOW (root cause)** | R6 filed `form_field_map_repopulates_values_and_renders_errors` and `marketing_routes_include_marketing_shell` as red. In the current tree both PASS (targeted run §2.G): R2's later assertion rework plus this fold's `data-form-id="webhook-create"`/`"api-key-create"` markers make the scoped replay coherent, and the marketing-shell test now asserts the inline `#apexmail-calculator` anchor + `/pricing/calculator` route resolution. `leptos_views.rs:4606`-class extraction bug that made the flash gate flag test-only literals is fixed (see item 15 extras). |
| 13 | UPDATE_GOLDENS regeneration | **FIXED-NOW** | Fail-before: `golden_manifest_covers_every_route` → `no golden for [web] /lists/l_1/members`; `golden_web_skeletons…` → `goldens/web/dashboard.html DIFFERS`; +`golden_control_plane…` and `pixel_parity…` (4 failures). After `UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_` → 5/5 PASS; re-run WITHOUT the env var → 5/5 PASS; full suite **529/529, 0 skipped**. Normalizer proof: `grep -o 'globals.css?v=[^"]*' goldens/web/dashboard.html` → `globals.css?v=<css-version>` (single token, no doubling). |
| 14 | Baseline/fixture re-export | **FIXED-NOW** | `APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation --bin export_visual_fixtures` from the repo root (the default path is repo-root-relative — running from `services/mail-server` silently writes `services/mail-server/services/…`; that stray tree was removed, see §2.H): **306 fixtures**, `css_sha256 a9ce52273…`, `marketing_sha256 7b1740b61…`, `renderer_sha256 baf980260…`; `tools/contrast-audit/fixtures` re-exported with the same content; `docs/development/ui-baseline-manifest.json` 40/34/19/38 = 131 matches routing + export. |

Beyond the filed items, the battery exposed four red gates that the fold fixed (each real, each with
literal evidence in §2):

* **contrast gate** — 188 AA failures across 188 runs, one global class: the brand logotype's
  `text-brand-600` ("Apex") is 185 28 28 on the near-black dark surface at **2.74:1** on every
  console/CP page in both dark theme paths. Fix: `.dark .text-brand-600` + the `:root:not(.light)`
  media twin step to `brand-400` (the established 600→400 dark pattern). After: **PASS — 0 AA
  failures across 326 runs**.
* **check_flash_copy.py** — red on 7 sites because `ui_flash_extract`'s `comment_spans` treated the
  char literal `'"'` (`find('"')`) as a string opener; the desync masked braces, so
  `production_split` never removed the `#[cfg(test)]` module and the gate flagged test-only
  literals. Fixed the tokenizer (char literals are opaque; string scan skips comment interiors) +
  made `flash.rs`'s last-resort sentinel canon-compliant ("This notification was too long to
  display."). After: `216 call sites / all green`.
* **extract_ui_strings.py --check** — catalog drift (`committed 494 vs extracted 517` web, etc.).
  Regenerated `docs/development/ui-strings-catalog.json` (also retires the stale
  "Invitation created." flash R6 flagged). After: `PASS catalog in sync`.
* **validate_pricing_drift.py** — pinned the *drifted* EN string `'roughly a 17% discount'`. The
  needle is now **derived from `data/pricing.json`** (`annual_billing_months=10` ⇒ `16.7% saving`,
  cross-checked against `annual_savings_percent`) and the retired `"€0.22–€0.35 contractual"`
  phrase is a stale token. After: `pricing drift validation passed`.

Also fixed: 2 pre-existing `needless_borrow` clippy lints in `api-server/src/routes/explorer.rs:874`
and `routes/admin/mailboxes.rs:88` (clippy gate is now zero-lint for both requested crates).

---

## 2. Zero-skips appendix (literal commands + outputs)

### A. Item 1 — members route, fail-before/after, counts, manifest, fixture

Fail-before (arm temporarily removed; then restored — `/tmp/r7-axum_router-after.rs` holds the
restored file):

```
$ cargo nextest run -p ui-foundation -E 'test(concrete_dynamic_manifest_paths_resolve)'
  test axum_router::tests::concrete_dynamic_manifest_paths_resolve ... FAILED
  panicked at crates/ui-foundation/src/axum_router.rs:3039:9:
  the members route must render the members skeleton, not the list detail
  Summary [0.013s] 1 test run: 0 passed, 1 failed, 526 skipped
```

After (restored):

```
$ cargo nextest run -p ui-foundation -E 'test(concrete_dynamic_manifest_paths_resolve) or test(counts_declared_routes) or test(route_coverage_matches_baseline_manifest)'
  PASS ui-foundation routing::tests::counts_declared_routes
  PASS ui-foundation axum_router::tests::concrete_dynamic_manifest_paths_resolve
  PASS ui-foundation axum_router::tests::route_coverage_matches_baseline_manifest
  Summary [0.107s] 3 tests run: 3 passed, 524 skipped

$ python3 -c "…json manifest…"
manifest routeCounts: {'web': 40, 'control-plane': 34, 'marketing': 19, 'marketing-zola': 38} total 131
web routes: ['/lists', '/lists/new', '/lists/l_1', '/lists/l_1/edit', '/lists/l_1/members']

$ python3 -c "…export manifest…"
members: [{'id': 'web-lists-l_1-members-desktop', …, 'htmlFile': 'web-lists-l_1-members.html', 'viewport': {'width': 1440, …}},
          {'id': 'web-lists-l_1-members-mobile', …, 'viewport': {'width': 390, 'height': 844}}]
```

Files: `routing.rs` (test comment + 40/131), `docs/development/ui-baseline-manifest.json`
(`routeCount` 40 + the entry between `/lists/l_1/edit` and `/templates`), `axum_router.rs`
(`web_route_page_name` members pattern + the render arm **before** both `/lists/…` catch-alls +
the new lib assertion).

### B. Item 2 — clippy fail-before/after

```
$ cargo clippy -p ui-foundation        # BEFORE
warning: this function has too many arguments (8/7)
   --> crates/ui-foundation/src/leptos_views.rs:221:1
warning: useless use of `format!`  --> crates/ui-foundation/src/leptos_views.rs:2851:22
warning: useless use of `format!`  --> crates/ui-foundation/src/leptos_views.rs:2888:16
warning: useless use of `format!`  --> crates/ui-foundation/src/leptos_views.rs:4281:9
warning: `ui-foundation` (lib) generated 4 warnings

$ cargo clippy -p ui-foundation        # AFTER
warning: ui-foundation@0.1.0: marketing output embedded (unstamped): 179 routes
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 2.34s
$ cargo clippy -p ui-foundation | grep -c '\-\->'      → 0
$ cargo clippy -p ui-foundation | grep -c leptos_views.rs → 0
```

`ControlPlaneSessionContext<'a> { user_context, impersonation_banner }` is the grouped shell
options struct; `axum_router.rs` and the two `shell.rs` tests construct it.

### C. Item 3 — hostile select; Item 6 — table region

```
$ cargo nextest run -p ui-foundation -E 'test(native_select_helper_escapes_every_interpolation) or test(table_scroll_region_is_keyboard_reachable_and_named)'
  PASS ui-foundation leptos_views::deferred_feature_view_tests::native_select_helper_escapes_every_interpolation
  PASS ui-foundation primitives::tests::table_scroll_region_is_keyboard_reachable_and_named
```

The table test pins
`class="apex-table-wrap relative w-full overflow-x-auto" tabindex="0" role="region" aria-label="API keys (scrollable table)"`
and the captionless `aria-label="Scrollable data table"`.

### D. Items 5/7/11 — handler replay, MFA status, JSON reset (live DB+Redis)

```
$ TEST_DATABASE_URL=… TEST_DATABASE_ADMIN_URL=… TEST_REDIS_URL=… cargo nextest run -p api-server --lib -E 'test(form_field_map_round_trips_into_the_rendered_form) or test(placement_failed_post_replays_the_provider_group) or test(webhook_create_binds_the_checkbox_group) or test(console_api_key_form_shares_the_json_policy) or test(live_loaders_keep_exports_filters_and_honest_labels) or test(reset_password_arms_and_success_consume_token_and_change_hash)'
  PASS routes::web::tests::form_field_map_round_trips_into_the_rendered_form
  PASS routes::web::adversarial_outage_tests::placement_failed_post_replays_the_provider_group
  PASS routes::web::tests::db_backed::webhook_create_binds_the_checkbox_group
  PASS routes::web::tests::db_backed::console_api_key_form_shares_the_json_policy
  PASS routes::web::data::coverage_loader_tests::live_loaders_keep_exports_filters_and_honest_labels
  PASS routes::auth::adversarial_auth_tests_3::reset_password_arms_and_success_consume_token_and_change_hash
  Summary [2.386s] 6 tests run: 6 passed, 2113 skipped
```

Without the env vars these tests soft-skip (`skipping …: set TEST_DATABASE_URL …`); the run above
was made with the documented env and no `skipping` line appears in the captured output (the reset
test takes 3.79 s — the invited case really seeds/asserts rows; the webhook test 0.47 s).

### E. Items 8/9 — built marketing artifacts

```
$ grep -c forced-colors apps/marketing-zola/static/css/styles.css    # BEFORE → 0
$ apps/marketing-zola/tailwindcss -c apps/marketing-zola/tailwind.config.js -i apps/marketing-zola/static/css/input.css -o apps/marketing-zola/static/css/styles.css --minify
Done in 583ms.
$ shasum -a 256 …/styles.css
6c42d0131c49baa0daa0e1b0206a723005cae48438e5fa280444ab5e1eae2da9   # two consecutive runs: cmp → BYTE-IDENTICAL
$ python3 - <<'EOF'  # extracted from the built artifact
@media (forced-colors:active){.btn-primary,.btn-primary--invert,.btn-secondary,.btn-secondary--invert{background:ButtonFace;border:1px solid ButtonText;color:ButtonText}[tabindex]:focus-visible,a:focus-visible,button:focus-visible{outline:2px solid Highlight;outline-offset:2px}}
EOF
$ grep -o 'btn-primary' public/404.html                     → class=btn-primary (×2)
$ grep -o 'styles.css[^ >"]*' public/404.html               → styles.css?h=6c42d0131c49baa0daa0
```

Built-page proofs (after `zola build`: `Done in 796ms.`):

```
public/de/status/index.html    → "Systemstatus", "Echtzeit-Status der ApexMail-Infrastruktur"
public/de/compliance/index.html→ "Compliance, die Audits übersteht", "Compliance-Infrastruktur", "DSGVO-Workflows, Audit-Trails"
                                 (old EN "Compliance workflows built into" / "Start Free": 0 occurrences)
public/features/index.html     → "SDKs are in active development and not yet published to public package registries"
public/pricing/index.html      → "Enterprise Cloud €0.35 per 1,000 (contractual)", "16.7% saving"
public/email-logs/index.html   → "recipient-MX acceptance is not inbox placement"
public/de/pricing/index.html   → "€0,35 pro 1.000", "16,7 %"
public/de/compliance/index.html→ "How long we keep your data" (no key exists — disclosed partial, §1 item 9)
```

### F. Item 10 — dev-start resolver branches + end-to-end builds

The real `resolve_tailwind_cli` text (extracted from `tools/dev-start.sh`) exercised against a
sandbox filesystem:

```
branch1 vendored-executable:              apps/marketing-zola/tailwindcss
(branch 2, vendored chmod -x, fake on PATH) /tmp/r7-tailwind-HYhE/bin/tailwindcss
(branch 3, neither, PATH=/usr/bin:/bin)   ERROR: Tailwind CLI not found: apps/marketing-zola/tailwindcss is not executable
   on this host and no 'tailwindcss' on PATH. Install the official v3.4.17 build for macos-arm64:
   https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.17/tailwindcss-macos-arm64
   (see services/mail-server/crates/ui-foundation/README.md)
```

End-to-end (restored vendored binary, this host):

```
$ ../../apps/marketing-zola/tailwindcss -c crates/ui-foundation/tailwind.config.js -i crates/ui-foundation/assets/globals.input.css -o crates/ui-foundation/assets/globals.css
$ shasum -a 256 crates/ui-foundation/assets/globals.css
f85852ae9205418d85e303492566a5a1a1004ea83191c2eff63114b9001d69b8   # == the pre-existing R2 artifact (byte-stable)
# after the contrast-gate AA fix (2 new rules in input.css):
7179adaa98e0f610b343051046a8afb2cd2cbd51cf997dcd4c848037722fb978   # two consecutive runs cmp → BYTE-IDENTICAL
```

### G. Item 12 — residual reds verified

```
$ cargo nextest run -p ui-foundation -E 'test(form_field_map_repopulates_values_and_renders_errors) or test(marketing_routes_include_marketing_shell)'
  PASS ui-foundation axum_router::tests::form_field_map_repopulates_values_and_renders_errors
  PASS ui-foundation axum_router::tests::marketing_routes_include_marketing_shell
```

(`marketing_routes_include_marketing_shell` asserts the marketplace shell markers, the inline
`apexmail-calculator` anchor on `/pricing`, and that `/pricing/calculator` still resolves — the
current built Zola pages satisfy all three; R2's addendum rework landed before this fold.)

### H. Items 13/14 — regeneration facts + the export-path note

```
$ UPDATE_GOLDENS=1 cargo nextest run -p ui-foundation golden_
  Summary [0.055s] 5 tests run: 5 passed, 524 skipped
$ cargo nextest run -p ui-foundation golden_      # no env var
  Summary [0.046s] 5 tests run: 5 passed, 524 skipped
$ cargo nextest run -p ui-foundation              # full, no env var
  Summary [1.415s] 529 tests run: 529 passed, 0 skipped

$ APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -q -p ui-foundation --bin export_visual_fixtures   # run from the REPO ROOT
  (writes services/mail-server/crates/ui-foundation/baselines/rust-ui)
baselines manifest: fixtures=306  css=a9ce5227342b0bce…  marketing=7b1740b6198ae4a5…  renderer=baf9802604faed4d…
docs/development/ui-baseline-manifest.json: web 40/40, control-plane 34/34, marketing 19/19, marketing-zola 38/38, total 131
goldens: web 40 files (incl. lists_l_1_members.html), control-plane 34; 73 modified + 1 new vs git
```

Path note (recorded, fixed): the binary's default output path
(`services/mail-server/crates/ui-foundation/baselines/rust-ui`) is **relative to the CWD**. Running
it from `services/mail-server` creates `services/mail-server/services/mail-server/…`; that stray
tree was deleted before the real export (no tracked file was removed — `git status` shows zero
deletions for the tree). Repo-root (or explicit-path) invocation is the correct recipe; the
in-tree README/`R2` recipe was already repo-root-relative.

Goldens/baselines delta summary: every golden/`baselines/rust-ui` page changed **because the CSS URL
content hash changed** (dashboard DNA-block, table region attrs, form `data-form-id` markers, the
new members page) — the five-set regeneration (goldens → baselines → contrast fixtures) was run
**after** the final CSS change and the suite is green on the result.

---

## 3. Final gate battery (literal outputs, in brief order)

```
$ cargo nextest run -p ui-foundation
     Summary [1.415s] 529 tests run: 529 passed, 0 skipped

$ cd services/mail-server && cargo fmt --check
(no output)  EXIT=0

$ cargo clippy -p ui-foundation -p api-server
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 7.71s
(no `ui-foundation (lib) generated` / `api-server (lib) generated` line — zero lints; the only
 ui-foundation warning is the build-script note "marketing output embedded (unstamped): 179 routes";
 dependency crates compliance/billing-service/analytics print their own pre-existing warnings)

$ python3 tools/check_flash_copy.py
flash call sites scanned: 216 (+0 leaked-error-display candidates)
flash copy: all green                                    EXIT=0
$ python3 tools/check_ui_form_hygiene.py tools/contrast-audit/fixtures
checked 302 POST forms / 310 visible controls
form hygiene: all green                                  EXIT=0
$ python3 tools/check_ui_a11y.py tools/contrast-audit/fixtures
checked 153 documents
accessibility: all green                                 EXIT=0
$ python3 tools/check_marketing_contrast.py
marketing token contrast: 34 pair renderings checked across authored+built stylesheets, light+dark themes
marketing token contrast: all pairs pass in both sheets and themes   EXIT=0
$ python3 tools/check_ui_links.py tools/contrast-audit/fixtures
checked 7557 href/action targets, 258 fragment targets
ui links: all green                                      EXIT=0
$ python3 tools/check_ui_terminology.py tools/contrast-audit/fixtures
terminology: all green                                   EXIT=0
$ python3 tools/extract_ui_strings.py --check
extracted strings per namespace: web=517, control-plane=389, flash=216, tracking=27, email=68 (total 1217)
PASS catalog in sync: …/docs/development/ui-strings-catalog.json   EXIT=0
$ python3 tools/validate_pricing_drift.py
pricing drift validation passed                          EXIT=0
$ python3 tools/i18n-audit.py
i18n: 0 finding(s)                                       EXIT=0
$ python3 tools/check_marketing_serving.py
checked 177 built pages under /Users/sabelakhoua/IdeaProjects/ApexMail
marketing serving gate passed                            EXIT=0

$ tools/contrast-audit/gate.sh
  [self-test] PASS — 12/12 checks
  [gate] PASS — AA failures: 0 across 0 runs (115 pages, 326 runs, 195.5s)        EXIT=0

$ tools/contrast-audit/layout-gate.sh
Done: 0 layout findings across 1196 runs.
By kind: {}                                             EXIT=0

$ cargo run -p ui-foundation --bin dna_verify
✓ web dashboard · 270° dial present … ✓ NO old-style labels anywhere (login/signup/mfa)
13/13 rendered-output checks pass                       EXIT=0
```

Fail-before/after contrasts for the two gates that were red mid-fold:

```
contrast gate BEFORE the AA fix:  [gate] FAIL — AA failures: 188 across 188 runs (115 pages, 326 runs, 197.4s)
contrast gate AFTER  the AA fix:  [gate] PASS — AA failures: 0 across 0 runs  (115 pages, 326 runs, 195.5s)
layout gate BEFORE the item-4 fix (AUDIT_ONLY=web:/dashboard): Done: 4 layout findings across 5 runs. By kind: {"past-viewport":2,"clipped-by-card":2}
layout gate AFTER  the item-4 fix (AUDIT_ONLY=web:/dashboard): Done: 0 layout findings across 5 runs. By kind: {}
layout gate AFTER (full):         Done: 0 layout findings across 1196 runs. By kind: {}
```

---

## 4. Files touched by this lane (uncommitted, as required)

Rust: `ui-foundation/src/{routing.rs, axum_router.rs, leptos_views.rs, shell.rs, primitives.rs,
flash.rs}`, `ui-foundation/assets/{globals.input.css, globals.css}`,
`api-server/src/routes/{web.rs, web/data.rs, auth.rs, explorer.rs, admin/mailboxes.rs}`.
Regenerated artifacts: `ui-foundation/goldens/**` (+`web/lists_l_1_members.html`),
`ui-foundation/baselines/rust-ui/**`, `tools/contrast-audit/fixtures/**`,
`docs/development/{ui-baseline-manifest.json, ui-strings-catalog.json}`.
Marketing: `templates/partials/{status/hero.html, compliance/hero.html, features/details.html,
generated/pricing-faq-island.html, email-logs/timeline.html}`,
`static/css/{input.css, styles.css}` (+ rebuilt `public/**`).
Tools/docs: `tools/dev-start.sh`, `tools/ui_flash_extract.py`, `tools/validate_pricing_drift.py`,
`ui-foundation/README.md`. `apps/marketing-zola/data/i18n.json` was **not** edited (R4's).

---

## 5. Zero-skips appendix — every brief line adjudicated

* Items 1–14: all executed (table above); no item was skipped, no item deferred.
* Item 9's `compliance/data-retention` heading is the only disclosed partial: R4 filed the
  partials as "0 i18n_data references ... wire the existing compliance.* keys"; the hero partial
  and the CTA partial are now wired (the CTA already was), and `data-retention.html` has **no key
  to wire** — dumping `data/i18n.json` shows `compliance.*` contains no retention key in de/fr/es
  (closest hits are `features.inbox_cap_4_title`/`pricing.event_history`, both different strings).
  The heading + table are shared policy content; inventing translations without the content
  authority was rejected rather than shipped silently.
* KiwiCaptcha: excluded per the standing directive (never opened).

## 6. Final orchestrator paragraph

Lane R7 executed the complete fold with zero skips. All fourteen filed items landed: the members
route is in the manifest/routing (web 40 / total 131) and renders its own skeleton (lib test with
the arm-removal fail-before); `leptos_views.rs` is clippy-silent (4 warnings → 0), the native
select helper escapes all six interpolations with a hostile-name test, the dashboard's delivery-
health paragraph no longer clips at mobile (2 flags → 0, full layout gate 0/1196), failed-POST
checkbox groups now round-trip in all three handlers (`FormFieldMap::add_value` + `data-form-id`
markers + `data-form=` typo fixed + four tests), every `.apex-table-wrap` is a named keyboard
region, the people tables' MFA state renders through the shared status badge, marketing carries a
real forced-colors block in the built artifact, R4's five template strings are wired/fixed with
built-page proofs, `dev-start.sh` resolves the vendored/PATH/official-URL tailwind CLI (all three
branches exercised) and its recipes reproduce byte-identical sheets, and the JSON reset twin now
accepts the invited state (tested live). Goldens (UPDATE_GOLDENS, 5/5 then 5/5 without the env
var), baselines + contrast fixtures (306 fixtures; css `a9ce5227…`, marketing `7b1740b6…`, renderer
`baf98026…`) and the UI-strings catalog were regenerated; `ui-foundation` is **529/529, 0
skipped**; `cargo fmt --check` is clean; `cargo clippy -p ui-foundation -p api-server` reports zero
lints from both crates; **all ten run Python gates are green** (the eight UI/marketing ones plus
i18n-audit and check_marketing_serving); the contrast gate is **PASS, 0 AA failures across 326
runs** after fixing 188 real AA failures (the `text-brand-600` logotype on dark surfaces at 2.74:1
— one global token-step rule in both dark paths); the layout gate is **0 findings across 1196
runs**; and `dna_verify` is **13/13, EXIT=0**. Three latent gate defects found by running the
battery were also repaired rather than reported around: `ui_flash_extract`'s char-literal
(`'"'`) desync that made the flash gate flag test-only literals (plus one non-canon production
sentinel), the stale UI-strings catalog, and `validate_pricing_drift.py` pinning the retired
"roughly a 17% discount" (now derived from `data/pricing.json`). Nothing is left failing; the only
deliberate deviation is the disclosed data-retention localization gap (no key exists; policy-table
translation is content authority R4's). Working tree is uncommitted per the standing rule.
