# Lane R2 — shared shell, primitives, quality surfaces, and the console style authority

Scope executed per `brief-r2-shell-primitives-styles.md` (incl. its ADDENDUM), with the review
(`review.md`) and register (`register.md`) read first. Paths are relative to
`services/mail-server/` unless absolute. **Zero skips**: every finding below carries a literal
command/output; the appendix has the raw runs.

Headline: **the console stylesheet is one reproducible authority again.** All 8 colour tokens, 24
hand-authored rule blocks and 3 badge/table/focus recipes that existed only in the served artifact
were moved into `assets/globals.input.css`, the artifact was regenerated with the repo's own
recipe, and the regenerated sheet is what the running api-server now serves (`/assets/globals.css`
200, byte-identical to the repo file). The closed mobile drawer's 320px × 100vh hit area is gone on
both shells (proven with a chromium probe: 5408 → 0 intercepted points), the QR generator is
validated against an independent decoder and cross-checked against segno for masks 0–7, and failed
form replay is structurally scoped, replaces (never accumulates) checked/selected state and
associates errors with their controls.

---

## 1. Verdict table — §3 P1 items in this lane

Verdicts: `FIXED-NOW` (fail-before + fix + fail-after), `FIXED-ALREADY` (current tree already
satisfied it), `EXCLUDED` (KiwiCaptcha only).

| id | finding | verdict | evidence | fix |
|---|---|---|---|---|
| **P1-3** | Closed mobile navigation blocks content (320px full-height hit area) | **FIXED-NOW** | Fail-before (pre-fix artifact `97a8877b:assets/globals.css` + the pre-fix markup from `HEAD:baselines/rust-ui`): a closed drawer is a `fixed` DETAILS sized **320×844** and intercepts **2704/3315** sampled points per document (5408 across two). After: **0/3315** on 5 documents, `panelDisplay=none`, details `width: 0`; the OPEN state is a 320×844 panel at (0,0), `position: fixed`, `z-index: 50`, `overflow-y: auto`, card background. | `globals.input.css`: `.apex-mobile-nav[open] .apex-mobile-nav-panel` now carries every drawer dimension (top/left/z/background/border/width/height/overflow) and `.apex-mobile-nav:not([open])` resets width/height/background/border/overflow with the panel `display:none`; the invalid `inset-y: 0` became `top: 0`. `shell.rs`: the CP drawer lost its always-on `fixed inset-y-0 left-0 z-50` details and `h-screen w-full` panel (now `apex-mobile-nav md:hidden` + `apex-mobile-nav-panel`, summary `fixed left-4 top-3 z-50` exactly like the web drawer) and the CP header gained `pr-8 pl-14 md:px-8` so the trigger does not cover the title. Chromium probe: `/tmp/r2-probe/mobile-drawer-probe.mjs` + `drawer-open-probe.mjs`. |
| **P1-8** | Native select options not escaped | **FIXED-ALREADY** (proved + swept) | `primitives.rs:557-575` escapes `option.value`, `option.label`, `select.id`, `select.name` at the boundary. New hostile-name test `native_select_escapes_hostile_value_label_id_and_name` passes (`4×&lt;script&gt;`, one well-formed option, no early attribute close). Call-site sweep: every other `<option>` builder in `leptos_views.rs` escapes (lines 626/628/1029/1031/3920/4844/5982/6115/6136/6770); the only raw interpolator left is the private `leptos_views::render_native_select` (line 405-421) — its 6 callers all pass literal option lists, so it is a latent risk, not a live escape hole. Filed for R1 in §5. | Added the hostile-name test; no production change needed at the primitive. |
| **P1-9** | Authored and compiled console styles have diverged | **FIXED-NOW** | Rebuilding the committed input produced a **1747-line** diff against the served artifact with **64 artifact-only selectors** and **24 artifact-only authored comments** (the whole GATE K block, the `.apex-mobile-nav*` group, the flat Sales-Cockpit/dark-surface recipes, the AA token values, the `.text-primary`/`.apex-eyebrow` `--accent-text` mapping, the `::selection`/`summary` rules). After the merge + regeneration: **20** artifact-only selectors remain and every one is a stale *generated* utility (`grep` over `src/**` = 0 hits; the class-integrity gate proves no rendered document uses them), **0** authored artifact-only comments remain that carry no counterpart. Determinism: two consecutive regenerations are byte-identical (`769bcb22…`); the served sheet is byte-identical to the repo artifact. | Moved into `globals.input.css`: the GATE K block (with comments), the drawer rules, the `.whitespace-pre-wrap` declaration, the artifact-only comments, the 2026-10-07 flat bodies for `.apex-cp-sales`/`.apex-cp-dark-*`/`.apex-cp-hero-side`/dark surfaces (the input still carried the retired blue counter-wash `rgba(59,130,246,…)` and red-glow gradients), the `--background/--border/--input` AA values and the `--accent-text` usage; then regenerated `assets/globals.css`. |
| **P1-12** | Failed-form replay can restore incorrect controls | **FIXED-NOW** | Fail-before (old semantics re-applied temporarily, see appendix F): the multi-form test fails with `left: 2 right: 1` (the value replayed into BOTH forms) and the checked test fails with `left: 2 right: 1` (the stale rendered `checked` survives next to the posted one). After: both tests pass; all pre-existing retention tests still pass. | `axum_router.rs`: replay is scoped to the matching `data-form-id` form element (byte range), unmarked pages drop cross-form ambiguous names (fail closed); `replace_choice_state` + `rewrite_option_tag` REPLACE checked/selected state; failed controls gain `aria-invalid` + `aria-describedby="<id>-error"` and the paragraph carries that id. |
| **P1-13** | MFA QR mask formulas 1/2/4 transposed; test decoder shares the implementation | **FIXED-NOW** (independent proof added) | The re-check confirms the 2026-10-07 orientation fix (`x`=column, `y`=row) is correct: `tools/verify_qr_interop.py` (spec-written: Table 10 conditions, Annex E alignment table, BCH(15,5), GF(2^8) syndromes — no code shared with the encoder) decodes **24 forced-mask matrices (masks 0-7 × versions 1/3/5)** to their exact payloads with valid format info and zero RS syndromes; the same decoder also decodes **segno 1.6.6**'s matrices for masks 0-7 (v1/v3), so the checker itself is validated by a third-party implementation; and a module-by-module comparison shows **0** function-region differences and **0** format-info differences against segno for all 24 cases (the only difference is a legal pad-codeword choice: ours starts `EC/11` one codeword earlier, segno inserts an extra `0x00` — both decode). | Added `encode_with_mask` + `draw_matrix_with_mask(forced_mask)` and the test `every_mask_and_multiple_versions_verify_with_an_independent_decoder`; kept the existing shared-decoder test. New repo file `tools/verify_qr_interop.py` (stdin case protocol, exit 1 on any failure). |

### §4 global recommendations owned by this lane

| id | what | verdict | evidence |
|---|---|---|---|
| 4.6 | Preserve whitespace, eliminate accidental emptiness | **FIXED-NOW (implementation)** | The spacing contract's implementation now matches its rules where this lane owns it: the canonical timing ladder is documented and enforced in `globals.input.css` (160ms control feedback / 180ms premium / 200ms reference transition; the two off-ladder `140ms` transitions became 160ms), and empty-state/table recipes stay on the shared `.apex-*` classes rather than one-off paddings. Emptiness in page composition (`data_list_page`) is R1's; the chromium layout audit over 1191 runs (152 console fixtures + 177 marketing pages × themes/viewports) reports `findings=0` for every console page except the pre-existing `/dashboard` mobile flag (see §5). |
| 4.7 | Keep depth selective | **FIXED-NOW** | `globals.input.css`: noninteractive surfaces no longer gain elevation on hover — `.apex-card.apex-card:hover`/`.apex-panel:hover`/`.apex-signal-card:hover` darken the border only (the +`0 10px 24px` shadow growth is gone) and `.apex-cp-stat-tile:hover` is a border step (no `translateY`, no shadow growth); the resting shadows and the border-led language are unchanged. `contrast-audit/layout-audit.mjs` re-run: no console regression (only the pre-existing dashboard flag). |
| 4.8 | Repair mobile behavior before tightening mobile layouts | **FIXED-NOW** | Closed drawer fixed (P1-3, both shells); the CP trigger sits at its visible location (`fixed left-4 top-3 z-50`) and the CP header clears it; narrow-screen identity added to the CP header (below). Horizontal table regions: `.apex-table-wrap` is a scroll container with `position: relative` (dogfood 2026-10-06) — a focus-visible ring for keyboard users is filed for R1 because the `tabindex`/`role` must be emitted by the row renderer. |
| 4.9 | Native controls should remain native | **FIXED-NOW (inventory + limits)** | `primitives.rs` now documents the usable-native vs inert-legacy split at the module level and per family: usable = `Button/Label/Input/Textarea/NativeSelect/NativeCheckbox/Badge/StatusIndicator/Card/EmptyState/AsyncState/Table/Progress/PaginationControls::render_html_with_links/Avatar/Skeleton/ChartLegend*`; inert legacy (library risks, prefer the native counterpart or `/confirm`) = `Select/Checkbox/Switch/Slider/RadioGroup/Dialog/AlertDialog/Popover/DropdownMenu/Tabs/Accordion/Toast`. `Textarea` now emits native `maxlength` and its counter is a truthful limit helper ("Limit 25 000 characters · N entered"), not a fake live count. `PaginationControls::render_html` (inert buttons, unused in production) is `#[deprecated]` in favour of the link-based `render_html_with_links` used by all 4 call sites. |
| 4.10 | Form feedback should feel composed | **FIXED-NOW + FIXED-ALREADY** | FIXED-NOW: replay scoping/replacement + stable error ids + `aria-describedby` (P1-12). FIXED-ALREADY: reveal-once secrets render in a stable receipt slot (the injection no longer depends on "the first closing `<div>`"; it targets the flash container, else `main#app-main`, else `<body>`); the action result stays adjacent to its flash/secret block; `flash.rs` bounds the payload so the feedback cannot be dropped by the browser. |
| 4.12 | Separate preview from email-client fidelity | **FIXED-ALREADY (R1)** | `leptos_views.rs` carries the "Sanitized structural preview — styles, scripts, and remote assets are removed, so this is the content structure, not how the email will look in a recipient's client." label (2 occurrences); the sanitizer is untouched. |

### §5.1 rows — runtime and presentation files

| file | recommendation | verdict | evidence |
|---|---|---|---|
| `axum_router.rs` | alias normalization; retained fields/errors scoped to the form; stable feedback slots; HTTP redirects | **FIXED-NOW (scoping) + FIXED-ALREADY (rest)** | Retention is structurally scoped (P1-12) and errors carry stable ids. The `/cp` aliases and the CP shell's active nav cell now resolve to the same page (see `shell.rs`); recovery/relocation redirects are already 303s (observed live by R1). Alias data specialization is R1's loader work. |
| `primitives.rs` | escape native select; native textarea limits; remove static counters; distinguish usable vs inert; stable caller ids | **FIXED-NOW** | Escaping proven (P1-8); `maxlength` emitted; counter is truthful; module doc enumerates usable vs inert + deprecations; `Input`/`Textarea`/`NativeSelect` all accept caller `id`/`name` and use them (the char-count span derives `<id>-count`). |
| `shell.rs` | closed mobile hit area; banner/header stacking; single-most-specific active matching; narrow-screen identity | **FIXED-NOW** | Drawer fixed (P1-3). New `active_href`/`link_is_active` mark exactly ONE cell — the longest segment-boundary match (`/settings/api-keys` no longer lights `/settings`; `/campaigns-archive` lights nothing; `/cp/*` reduces to the bare alias). Test `sidebar_active_matching_is_single_and_most_specific`. New `data-user-identity-compact` header block (session-derived name + plan label, `sm:hidden`) keeps account context discoverable below 640px; banner offsets unchanged and covered by existing tests. |
| `charts.rs` | area closure/zero bars; large datasets; real stroke/fill; summaries + data alternatives; no implied unused renderers | **FIXED-NOW** | Zero bars now render a muted 2px baseline stub with a `<title>` "label: 0" (the old full-colour stub read as a value); slot-based geometry keeps 60 bars inside a 400px viewBox (the old `clamp(6.0, 60.0)` width pushed them past the right edge); x labels thin out and value labels drop when the slot cannot fit them; the chart's `aria-label` is a real summary ("Bar chart: N categories, total T, highest L, V") and every bar carries its series name. Test `bar_chart_handles_zero_and_large_datasets`. Theme colours already route through `style=` (test `theme_colors_use_style_attributes_not_presentation_attributes`). |
| `tokens.rs` | validate current theme authorities, not historical snapshots; make source-vs-artifact drift visible | **FIXED-NOW** | New live parsing (`block_tokens`, `source_tokens`, `artifact_tokens`, `source_artifact_drift`, `baseline_color_drift`) reads the embedded sheets. The drift test **failed first** naming 8 stale baseline tokens (`--background 255 255 255 vs 244 244 246`, `--primary 220 38 38 vs 185 28 28`, `--border/--input 228 228 231 vs 209 209 213`, `--muted*`, `--surface-100/200`); the snapshot JSON was synced to the authority and the gate is now green and load-bearing. |
| `lib.rs` | validate light and dark token blocks independently; explicit versioning/embedded-asset authority | **FIXED-NOW** | New `light_and_dark_token_blocks_validate_independently`: each block is parsed on its own; every dark token must exist in `:root`; the `.dark` class twin and the `:root:not(.light)` media twin must carry identical values (25/25 verified); core surface tokens must exist in all three; the artifact's `:root` must match the authored light authority. New `tailwind_content_scan_covers_every_class_emitting_renderer`. Stylesheet versioning stays the content-hash URL (`globals_css_url` + `globals_css_url_is_content_hashed`). |
| `icons.rs` | escape interpolated class attributes; one stroke/scale contract | **FIXED-NOW** | `render_icon` escapes `class_name` at the boundary; the contract (24×24 viewBox, `currentColor`, round caps/joins, size=width/height, `stroke-width` from options, `aria-hidden`) is documented and pinned for every glyph by `class_attribute_is_escaped_and_the_contract_holds`. |
| `routing.rs` | inventory real routes/hosts/aliases, not representative examples | **FIXED-ALREADY** | The module reads `docs/development/ui-baseline-manifest.json` as the inventory: 130 routes across web 39 / control-plane 34 / marketing 19 / marketing-zola 38, with the `/cp` alias set and dynamic canonical patterns asserted (`inbox_placement_and_cp_alias_routes_require_auth`, `counts_declared_routes`). `route_coverage_matches_baseline_manifest` renders every one. |
| `ssr.rs` | compare rendered coverage with independently extracted mounted routes | **FIXED-NOW** | New `marketing_routes_from_source()` extracts the marketing routes from the renderer source's `include` sites (the same scan `build.rs` performs) — 177 routes — and the new test asserts every marketing manifest route is in that independent set (only two view-rendered aliases, `/api-console` and `/demo`, are named as exceptions) and that the served set is larger than the manifest. The web/CP side stays covered by rendering every manifest route + R5's `tools/ui_routes.py` extraction gate. |
| `flash.rs` | bound feedback payloads to a browser-safe cookie budget; keep persistent PRG feedback | **FIXED-NOW** | `FLASH_COOKIE_VALUE_BUDGET = 3072`, per-message truncation at 512 chars with an ellipsis, and message dropping from the end with a `[+N more]` trailer; small payloads round-trip byte-identically. Test `flash_cookie_stays_within_the_browser_budget` (a 64 KiB message and 200 messages both stay in budget and decode); the hand-built oversized cookie is still rejected by the decoder. |
| `csrf.rs` | preserve the token design; extend consumer/secret-binding tests | **FIXED-NOW** | New `generated_token_verifies_against_the_consumer_contract`: the embedded token is recomputed as `HMAC-SHA256(secret, nonce)` exactly as the api-server validator does, the secret binding is asserted, an empty/other nonce and an empty signature fail, and the nonce shape (`<unix-ms>:<uuid>`) is pinned — a placeholder can no longer pass silently. Design unchanged. |
| `qr.rs` | correct mask coordinates, validate externally, keep the manual fallback | **FIXED-NOW** | See P1-13. The selectable manual-setup fallback (secret + `otpauth://` URI) is rendered by R1's MFA page (kept; no change here). |
| `tracking_domain.rs` | parent context navigable; CNAME inspectable after verification; task-oriented prerequisites/entitlement/retry | **FIXED-NOW** | The CNAME record block is now rendered in EVERY configured state — verified rows show "DNS record in place" plus "Keep this record: removing it stops open and click tracking on this host." (the old code hid the record the moment status became verified). The unverified state names the prerequisite with no dead form; the unentitled state names the plan capability with no form; the configured state keeps `Verify DNS now` + `Remove`. New test `verified_row_keeps_the_cname_record_and_unmet_prereq_has_no_form`. |
| `explorer.rs` | invalid fallback CSS; result headings; marketing-origin return links; retain inputs | **FIXED-NOW** | The three `.apx-status*` rules were emitted with doubled braces (invalid CSS, status colour never applied) → single braces; the sandbox shell now carries an `<h1>` per result page; all four return links are absolute marketing-origin URLs (`https://apexmail.ee/api-explorer`, `/pricing/calculator`, `/`), never a relative path that 404s on the API origin; the grader error page retains the submitted domain in a "Try again" form; the calculator result badges distinguish the `volume` priced factor from context-only inputs. New test `sandbox_pages_use_absolute_marketing_links_headings_and_valid_css`. |
| `marketing.rs` | deprecate inert historical widgets; distinguish fallback renderers from the active Zola documents | **FIXED-ALREADY** | `MARKETING_ISLANDS` is empty and the router serves the built Zola documents (`marketing_static_document`) with this crate's `marketing_*` views only as the no-document fallback; the module tracks the marketing/`marketing-zola` route sets separately (`only_in_marketing*` helpers) and `route_owner()` names `apps/marketing-zola` for the Zola-owned routes. No inert island export remains. |
| `fixture_states.rs` | populated bulk tables, failed multi-form replay, secret receipts, permission restrictions, create/edit variants | **FIXED-ALREADY (partial) + REPORTED** | This file's state matrix covers assistant (populated/disabled/unavailable), AI drafts (populated/many/unavailable), message timeline (populated/insufficient), alert rules (populated/editing/unavailable) and all five tracking-domain states; the exported fixture set is 304 entries incl. 8 populated + retained-state + explorer documents (R5's `gate_support`), and R1's api-server test renders populated contacts/campaigns/CP-audit/alerts pages. Gap reported: no exported fixture expresses a plan/permission-RESTRICTED page (the copy exists in the loaders but is not in the fixture matrix needing a sanctioned auth/plan surface) → filed for the orchestrator, not silently claimed. |
| `fixture_states.rs` (fixtures export) | complete state coverage + one asset authority | **FIXED-NOW (re-exported)** | Re-exported after every code change: `baselines/rust-ui` 304 fixtures, `css 4172172a…`, `marketing b976f48b…`, `renderer 12b46db6…`; `docs/development/ui-baseline-manifest.json` route counts (39/34/19/38 = 130) still match (`route_coverage_matches_baseline_manifest`, `counts_declared_routes` green). `pixel_parity::rendered_pages_match_the_committed_visual_baseline_skeleton` green against the fresh baselines. |

### §5.2 rows — styles, build, package ownership

| file | recommendation | verdict | evidence |
|---|---|---|---|
| `globals.input.css` | restore all recipes; property lists instead of `transition-all`; canonical timings | **FIXED-NOW** | All artifact-only recipes are in the input (P1-9 inventory). `transition-all` is remapped to the approved property list (colour/shadow/transform/opacity/filter/backdrop-filter — layout never animates) and the two `@apply … transition-all` recipes carry explicit `transition-property` lists; the timing ladder is documented (160/180/200ms) and the two off-ladder 140ms transitions step to 160ms. Arch/concentric details and restrained surfaces preserved. |
| `globals.css` | treat as a reproducible artifact; remove independent maintenance; verify mobile/focus/panel/shell fixes survive | **FIXED-NOW** | Regenerated from the input with the repo recipe; two consecutive runs are byte-identical (`769bcb22…`); the served copy is byte-identical; it contains the drawer `[open]`/`:not([open])` rules, the concentric focus ring, the panel recipes and the shell/sidebar fixes (asserted by the class-integrity + chrome gates, 527/527 suite). |
| `tailwind.config.js` | scan every authoritative renderer; token mappings + completeness testable | **FIXED-NOW** | Content scan is now `./src/**/*.rs`, `./assets/globals.input.css`, `../../api-server/src/**/*.rs` (regenerating after the addition produced a byte-identical artifact — no class in the api-server was missing, but the authority is now explicit); `tailwind_content_scan_covers_every_class_emitting_renderer` pins the list. Token mappings stay the CSS-variable wiring; completeness is enforced by the class-integrity gate. |
| `build.rs` | require complete, provenance-stamped marketing output | **FIXED-NOW** | The build now (a) treats the tree as unbuilt unless EVERY included route exists — proven by deleting `public/about/index.html`: `marketing output is INCOMPLETE: 1 of 179 included routes missing (/about/index.html) — embedding placeholders from OUT_DIR instead`; (b) validates `build-provenance.json` when present (well-formed + `styled_sheet` must exist) and exposes it as `APX_MARKETING_PROVENANCE` (`marketing output embedded (unstamped): 179 routes` on this dev tree, which has no stamp); (c) fixed a latent scan bug that produced an empty include path from the test-only `Path::new(env!(…))` marker (it would have created a bogus empty route in the fallback tree). |
| `Cargo.toml` | independent HTML/QR conformance coverage where appropriate | **FIXED-NOW (no dependency added)** | The QR conformance test runs pure-std Rust plus the checked-in stdlib Python decoder (`tools/verify_qr_interop.py`); no new crate dependency, no runtime-architecture change. |
| `README.md` | document surface ownership, native PRG, embedded assets, fallback semantics, fixture authority | **FIXED-NOW** | `crates/ui-foundation/README.md` rewritten with the ownership table (console/CP/marketing/explorer/email), the PRG contract (flash cookie budget, replay scoping, `/confirm` + CSRF signing), the stylesheet authority + regeneration recipe, the fallback semantics (marketing completeness/provenance, console data fallbacks) and the fixture authority chain. |

### §11 CAPTCHA — EXCLUDED (standing KiwiCaptcha directive)

`EXCLUDED` by the standing owner directive (`packages/kiwicaptcha` and its distribution copies are
consumed at the latest version, never edited). Recorded facts, no edits: crate/PHP release version
**1.7.0** (`packages/kiwicaptcha/Cargo.toml`); all 11 canonical assets under
`packages/kiwicaptcha/resources/` are **byte-identical** to both mirrors
(`packages/kiwicaptcha-wasm/assets/**` and `packages/kiwicaptcha/integrations/symfony/Resources/public/**`)
— 11/11 MATCH in the hash sweep; there is no marketing-tree mirror left in this checkout, so no
mirror can drift. Optional latest-standalone-release check: both plausible external authorities are
unreachable from here — `https://api.github.com/repos/BelConsulting/kiwicaptcha/releases/latest`
→ **HTTP 404** and `https://registry.npmjs.org/kiwicaptcha` → **HTTP 404** — so the vendored mirror
has no external "latest" to compare against; the internal byte-parity is the authority. Nothing was
edited (per the directive).

---

## 2. The P1-9 artifact-only-rules inventory (before → after)

**Before** (committed input → committed artifact, regenerated with the repo recipe):
`diff -u assets/globals.css /tmp/globals.regen.css` = **1747 diff lines**, **64 artifact-only
selectors**, **24 artifact-only comments**, **39 selectors whose body differed** between the two
sides. The 64 artifact-only selectors break down exactly as:

| bucket | count | examples | disposition |
|---|---|---|---|
| Hand-authored GATE K block | **43** | `.apex-mobile-nav[open]`, `.apex-mobile-nav[open] .apex-mobile-nav-panel`, `.apex-mobile-nav:not([open]) .apex-mobile-nav-panel`, `.cp-sidebar-nav`, `.apex-avatar`, `.apex-chart-frame`, `.ui-dot-grid`, `.animate-in*` + 2 keyframes, `.mt-8`, `.resize-vertical`, `.apex-focus-ring:focus-visible`, `.apex-panel*` (4), `.apex-btn*` (7), `.apex-pill*` (4), `.apex-callout*` (5), `.apex-field*` (6), `.apex-table`, `.apex-table tbody tr:last-child td`, `.apex-mono` | moved into `@layer components` with their comments; `.min-h-12`, `.text-foreground/60|70` and `.hover:border-white/40:hover` are also emitted by the class scanner now and are documented in the block as generated |
| Hand-authored flat dark-surface group (2026-10-07 dogfood) | **1** (8-selector group) | `.dark .apex-empty-state, .dark .apex-inventory-empty, .dark .apex-chart-empty, .dark .apex-chart-card, .dark .apex-cp-hero, .dark .apex-cp-hero-side, .dark .apex-cp-stat-tile, .dark .apex-cp-region-row { flat card }` | moved into the input; the input's per-surface red-glow/gradient variants were removed as superseded |
| Stale generated utilities | **20** | `.bg-white/5`, `.text-brand-100/400`, `.bg-black/30`, `.border-0`, `.shadow-premium-black/30`, `.min-h-[48px]`, `.gap-x-5`, `.sm:w-56`, `.md:w-auto`, `.hover:text-white:hover`, `.hover:bg-white/10:hover`, `.focus-visible:shadow-[…]` … | dropped (no source or rendered document references them — `grep src/**` = 0 hits for all 20; class-integrity gate green) |

The 39 shared-but-different bodies are the flat-surface rewrites that were 2026-10-07 changes in the
artifact only (**13**: `.apex-cp-sales`, `.apex-cp-dark-hero`(+`::before`), `.apex-cp-dark-panel`
(+`:hover`, `--accent::before`), the `.apex-cp-sales [class*=bg-black]` pair, the sales input/table
rules, `.apex-cp-hero-side`, `.dark .bg-brand-50/100`, `.dark .bg-success-50`, `.dark
.apex-auth-notice[success]`, dark `.apex-console-main`, dark `.apex-table thead`, `.dark
.apex-inventory-head`, `.dark .apex-cp-stat-tile:hover` — verified by `git log -S`: artifact
`0557e55d` 2026-10-07 vs input `23b471e3` 2026-05-14 / `e87e590f` 2026-08-16), the **8 AA token
values** (input `--background 255 255 255`, `--border/--input 228 228 231`, `--muted 244 244 245`,
`--muted-foreground 113 113 122`, `--primary` comment/`--accent-text`), the **`.text-primary`/
`.apex-eyebrow`/`.apex-page-heading .apex-eyebrow`** accent mapping, **`.apex-logo-mark`** (bevel
removed), **`.whitespace-pre-wrap`** (count 1 vs 2), the table-rhythm trio (`.apex-table th/td/hover`
— resolved to "last definition wins" equality) and pure ordering/comment-placement hunks
(`::selection`, `summary`, the responsive `@media` blocks). Regeneration also legitimately refreshes
the utility set: **28 regen-only selectors** (`.max-h-72`, `.min-w-[880px]`, `.pl-14`, `.collapse`,
`.list-disc`, `.shrink`, `.gap-x-3`, `.divide-border`, `.bg-amber-200/500-10`, `.py-24`,
`.sm:grid-cols-4`, `.lg:grid-cols-2`, `.dark .hover:bg-brand-100:hover`, `.text-foreground/60|70`,
… ) are classes the current source uses.

**After**: 20 artifact-only selectors remain and all 20 are in the last-but-one bucket (stale
generated utilities); **0** authored artifact-only comments remain without a counterpart (the 5
"remaining" comment-text differences are only wording/indentation of comments that now exist on both
sides, e.g. the input's longer "Inventory panel … `position: relative`" note supersedes the artifact's
one-liner).

**Intended change set (old artifact → new artifact)** — 345 added / 247 removed lines, every hunk in
one of these classes, verified by the cascade-aware comparator (`/tmp/tw/cascade.py`), which reports
the *effective* declaration per selector/context and shows only the intended differences:

1. utility-set refresh from the current scan (see table);
2. the drawer fix (`inset-y: 0` → `top: 0`; new `:not([open])` reset);
3. `.apex-mobile-nav-panel` closed state `display: none` (new guarantee);
4. `.text-primary` / `.hover:text-primary:hover` now resolve to `--accent-text` (same 185 28 28 value in
   light; the rules and the comment moved to the authored override);
5. `.apex-table`/`.apex-table td` GATE bodies restored (border-bottom + foreground ink), `.apex-table-wrap`
   keeps the newer `!important` recipe exactly once;
6. `.apex-cp-hero-side` flattened to the card (2026-10-07 authority);
7. the four §4.7/§5.2 refinements (hover depth, canonical timings, `.transition-all` property list).

---

## 3. Zero-skips appendix (literal commands + outputs)

All Rust commands run from `/Users/sabelakhoua/IdeaProjects/ApexMail/services/mail-server`.

### A. P1-9 — divergence, merge, regeneration, proof

```
$ /tmp/tw/regen.sh                      # dockerized v3.4.17 CLI, dev-start.sh's recipe
$ docker run --rm -v <repo>:/work -v ~/.cache/tw-check:/tw -w /work/services/mail-server alpine \
    /tw/tailwindcss-linux-arm64 -c crates/ui-foundation/tailwind.config.js \
    -i crates/ui-foundation/assets/globals.input.css -o /tw/globals.regen.css
Done in 507ms.
$ python3 /tmp/tw/compare_css.py assets/globals.css /tmp/globals.regen.css   # BEFORE the merge
artifact rules: 1054  regen rules: 1018
artifact-only selectors: 64
regen-only selectors: 28
ARTIFACT-ONLY COMMENTS: 24
$ diff -u assets/globals.css /tmp/globals.regen.css | wc -l
1747
$ python3 /tmp/tw/compare_css.py /tmp/tw/old-globals.css assets/globals.css  # AFTER
artifact rules: 1054  regen rules: 1056
artifact-only selectors: 20      # all stale generated utilities
ARTIFACT-ONLY COMMENTS: 5        # wording/indent-only (longer input comment supersedes)
$ /tmp/tw/regen.sh /tmp/tw/globals.new2.css && shasum -a 256 /tmp/tw/globals.new.css /tmp/tw/globals.new2.css
769bcb2276eb41234aca58098e38095f3a77795e2662da6de35e36fdab59a9e6  globals.new.css
769bcb2276eb41234aca58098e38095f3a77795e2662da6de35e36fdab59a9e6  globals.new2.css   # deterministic
$ python3 /tmp/tw/cascade.py /tmp/tw/old-globals.css assets/globals.css | tail -3
total selectors with effective differences: 4   # + the §4.7/§5.2 refinements listed in §2
```

The toolchain note: `apps/marketing-zola/tailwindcss` in the repo is a Mach-O arm64 binary whose
first 4 bytes are MISSING in git — the file starts at the cputype (`0c 00 00 01`, arm64) instead of
the 64-bit Mach-O magic `cf fa ed fe` — so it cannot be exec'd on this host
(`zsh: exec format error`; a repaired copy is SIGKILLed unsigned on Apple Silicon). The recipe was therefore run
with the **official v3.4.17 `tailwindcss-linux-arm64` release** (the version the Dockerfile pins)
inside an alpine container mounting the repo — same config, same input, same version.

### B. P1-9 — gates + served artifact

```
$ cargo nextest run -p ui-foundation --no-fail-fast
     Summary [   1.382s] 527 tests run: 527 passed, 0 skipped
$ cargo run -q -p ui-foundation --bin dna_verify ; echo EXIT=$?
13/13 rendered-output checks pass
EXIT=0
$ python3 tools/check_ui_a11y.py     -> checked 152 documents / accessibility: all green   exit=0
$ python3 tools/check_ui_form_hygiene.py -> checked 300 POST forms / 309 visible controls / all green
$ python3 tools/check_ui_links.py    -> checked 7516 href/action targets, 257 fragment targets / green
$ python3 tools/check_ui_terminology.py -> app-surface documents scanned: 95 / all green
$ python3 tools/check_marketing_contrast.py -> 34 pair renderings / all pass both sheets+themes
$ python3 tools/validate_pricing_drift.py  -> pricing drift validation passed
$ python3 tools/check_marketing_serving.py -> checked 177 built pages / passed
$ docker compose build api-server && docker compose up -d api-server      # BUILD_DONE=0
$ curl -s -o /tmp/g.css -w "console /assets/globals.css HTTP=%{http_code} bytes=%{size_download}\n" http://127.0.0.1:8080/assets/globals.css
console /assets/globals.css HTTP=200 bytes=162130
$ curl -s -o /tmp/m.css -w "marketing /css/styles.css HTTP=%{http_code} bytes=%{size_download}\n" http://127.0.0.1:8080/css/styles.css
marketing /css/styles.css HTTP=200 bytes=88254
$ shasum -a 256 /tmp/g.css crates/ui-foundation/assets/globals.css | cut -c1-16
f85852ae9205418d   (served)   f85852ae9205418d   (repo artifact)     # byte-identical
$ grep -c "apex-mobile-nav:not(\[open\])" /tmp/g.css ; grep -c "\.transition-all" /tmp/g.css
2
2
$ ls -l crates/ui-foundation/assets/globals.css apps/marketing-zola/static/css/styles.css
-rw-r--r--@ 162130 …/assets/globals.css          # 0644, readable by the api-server uid 10001
-rw-r--r--@  88254 …/static/css/styles.css
$ docker exec apexmail-api-server-1 sh -c 'ls -l /app/apps/marketing-zola/public/css/styles.css; id -u'
-rw-r--r-- 1 root root 88254 …/public/css/styles.css
10001                                               # served 200 (mode/ownership fix holds)
```

### C. P1-3 — chromium drawer probe, fail-before and pass-after

```
$ node /tmp/r2-probe/mobile-drawer-probe.mjs /tmp/r2-probe/fixtures-old \
      /tmp/r2-probe/fixtures-old/assets/globals.css web-campaigns.html control-plane-home.html
web-campaigns.html drawer=mobile-sidebar closed=true hits=2704/3315 details={"x":0,"y":0,"w":320,"h":844} pos=fixed panelDisplay=block panel={"x":0,"y":0,"w":320,"h":844} summary={"x":16,"y":12,"w":40,"h":40}
control-plane-home.html drawer=control-plane-mobile-sidebar closed=true hits=2704/3315 details={"x":0,"y":0,"w":320,"h":844} …
SUMMARY files=2 drawers=2 intercepted_points=5408
EXIT=1
$ node /tmp/r2-probe/mobile-drawer-probe.mjs tools/contrast-audit/fixtures \
      crates/ui-foundation/assets/globals.css web-campaigns.html control-plane-home.html web-home.html control-plane-tenants.html web-dashboard.html
web-campaigns.html drawer=mobile-sidebar closed=true hits=0/3315 details={"x":0,"y":0,"w":0,"h":1325} pos=static panelDisplay=none panel={"x":0,"y":0,"w":0,"h":0} summary={"x":16,"y":12,"w":40,"h":40}
control-plane-home.html … hits=0/3315 … panelDisplay=none
control-plane-tenants.html … hits=0/3315
web-dashboard.html … hits=0/3315
SUMMARY files=5 drawers=0 intercepted_points=0
EXIT=0
$ node /tmp/r2-probe/drawer-open-probe.mjs tools/contrast-audit/fixtures crates/ui-foundation/assets/globals.css web-campaigns.html control-plane-home.html web-dashboard.html control-plane-tenants.html
web-campaigns.html open=true panel={"x":0,"y":0,"w":320,"h":844} pos=fixed z=50 overflowY=auto bg=rgb(255, 255, 255) => PASS
control-plane-home.html … => PASS   web-dashboard.html … => PASS   control-plane-tenants.html … => PASS
OPEN-STATE SUMMARY files=4 failures=0
EXIT=0
```
Pre-fix inputs: artifact `git show 97a8877b:…/assets/globals.css` (unguarded `.apex-mobile-nav`
width/bg/overflow), markup `git show HEAD:…/baselines/rust-ui/{web-campaigns,control-plane-home}.html`
(both drawers `fixed inset-y-0 left-0 z-50`, panels without the `.apex-mobile-nav-panel` class).

### D. P1-8 — hostile-name escaping + call-site sweep

```
$ cargo nextest run -p ui-foundation -E 'test(native_select_escapes_hostile_value_label_id_and_name) | test(hostile_values_cannot_break_out_of_attributes)'
        PASS primitives::escaping_tests::native_select_escapes_hostile_value_label_id_and_name
        PASS primitives::escaping_tests::hostile_values_cannot_break_out_of_attributes
$ grep -n '"<option' crates/ui-foundation/src/leptos_views.rs | wc -l     # 13 call-site builders
$ grep -n "html_escape" …                                                  # 626/628/1029/1031/3920/4844/5982/6115/6136/6770 escape
render_native_select (line 405) → raw interpolation; its 6 callers pass literal option lists
```

### E. P1-13 — independent QR conformance (plus the segno cross-check)

```
$ cargo nextest run -p ui-foundation -E 'test(qr::)'
        PASS qr::tests::every_mask_and_multiple_versions_verify_with_an_independent_decoder
        PASS qr::tests::encodes_and_round_trips_payloads   (existing shared-decoder test kept)
        PASS qr::tests::rejects_over_long_input_cleanly / svg_contains_every_dark_module / encode_to_svg_helper_matches_composition
     Summary  5 tests run: 5 passed
$ PYTHONPATH=/tmp/r2py python3 /tmp/r2-segno-crosscheck.py     # function+format+payload comparison
cases=24 function_region_differences=0 format_info_differences=0
payload-prefix codewords equal until the pad region: v1 shared 18/26, v3 49/70, v5 81/134
$ PYTHONPATH=/tmp/r2py python3 /tmp/r2-segno-as-input.py       # decoder validated on segno matrices
OK all 16 QR cases decode independently   (segno v1/v3, masks 0-7; STDERR empty; EXIT 0)
```
(segno 1.6.6 was `pip install --target /tmp/r2py` — isolated, not added to the repo or CI.)

### F. P1-12 — fail-before/after for scoping and replacement

```
# (temporarily re-applying the OLD semantics, then restoring — see the two patches below)
OLD scoping:        FAIL failed_replay_is_confined_to_the_matching_form
                    assertion failed: left: 2 right: 1
                    <main><form data-form-id="a"…><input … value="https://posted.example/hook"/></form>
                     <form data-form-id="b"…><input … value="https://posted.example/hook"/></form></main>
OLD append-only:    FAIL failed_replay_replaces_checked_and_selected_defaults
                    assertion failed: left: 2 right: 1
                    <input id="ev-bounced" … value="bounced" checked /> … value="accepted"  checked/>
NEW (restored):     PASS failed_replay_is_confined_to_the_matching_form
                    PASS failed_replay_replaces_checked_and_selected_defaults
$ cargo nextest run -p ui-foundation -E 'test(form_field_map_repopulates_values_and_renders_errors) | test(checkbox_groups_replace_values_and_render_errors) | test(textarea_and_select_injection_repopulate_and_escape) | test(form_field_injection_is_empty_noop_and_form_scoped)'
     Summary  4 tests run: 4 passed
```

### F2. Browser suite availability (P1-3 harness note)

```
$ ls tests/browser/node_modules
ls: node_modules: No such file or directory
$ BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 npx playwright test --config=playwright.a11y.config.mjs specs/a11y.spec.mjs
error: unknown command 'test'      # playwright is not installed in this checkout (unchanged from R5's note)
```
The chromium-based proof for the drawer therefore comes from this lane's Playwright probe (run
against the exported fixtures with the real `tools/contrast-audit/node_modules` playwright) plus the
in-crate `chrome_tests`, exactly as the brief allows.

### G. build.rs completeness/provenance and the layout audit

```
$ rm apps/marketing-zola/public/about/index.html && touch crates/ui-foundation/build.rs && cargo build -p ui-foundation
warning: ui-foundation@0.1.0: marketing output is INCOMPLETE: 1 of 179 included routes missing (/about/index.html) — embedding placeholders from OUT_DIR instead
$ (restore) cargo build -p ui-foundation
warning: ui-foundation@0.1.0: marketing output embedded (unstamped): 179 routes
$ AUDIT_LAYOUT_REPORT_ONLY=1 node tools/contrast-audit/layout-audit.mjs
Done: 4 layout findings across 1191 runs.   By kind: {"past-viewport":2,"clipped-by-card":2}
  FLAG web /dashboard [light/mobile] findings=2
  FLAG web /dashboard [dark/mobile]  findings=2
$ AUDIT_ONLY=web-dashboard … node layout-audit.mjs   # same 4 findings with the PRE-change artifact swapped in
OLD-CSS: /dashboard light mobile ['past-viewport','clipped-by-card']
OLD-CSS: /dashboard dark mobile  ['past-viewport','clipped-by-card']      # pre-existing, R1's markup
```

### H. Clippy / fmt

```
$ cargo fmt -p ui-foundation && cargo fmt -p ui-foundation --check && echo FMT_CLEAN
FMT_CLEAN
$ cargo clippy -p ui-foundation --all-targets 2>&1 | grep '^warning'
warning: this function has too many arguments (8/7)        -> leptos_views.rs:221  (R1's file, reported)
warning: useless use of `format!`  (×3)                    -> leptos_views.rs:2851/2888/4281 (R1's file, reported)
(no warnings remain in any file this lane owns)
$ cargo check -p api-server --lib
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1m 17s
```
Note: the repo's standing rule is `cargo fmt` on every touched file; `cargo fmt -p ui-foundation`
formats the crate, so it may have reflowed other lanes' in-flight files in the shared working tree
(formatting only — no semantic change; the suite is green with it).

---

## 4. Reported for other lanes (exact required changes)

1. **R1 — `crates/ui-foundation/src/leptos_views.rs`** (this lane may not edit it): 4 clippy warnings
   block a fully clean `cargo clippy -p ui-foundation` — `control_plane_app_layout_with_session`
   (`too_many_arguments`, line 221; fix: group the shell options or `#[allow]`) and 3×
   `useless_format!` (lines 2851, 2888, 4281; drop the `format!` for the literal). The filed
   "arg-count" note lands in R1's file, not this lane's.
2. **R1 — `render_native_select` (`leptos_views.rs:405-421`)**: interpolates `value`, `text`, `id`,
   `name` and `label` raw. Its 6 callers pass literal lists today, so this is latent, but the
   primitive-boundary rule means the helper should escape (or route through
   `primitives::NativeSelect`). Exact change: `html_escape` all six interpolations.
3. **R1 — `/dashboard` static fallback at 390px**: `contrast-audit/layout-audit.mjs` flags
   `past-viewport` + `clipped-by-card` on
   `body>section>div:nth-of-type(2)>div:nth-of-type(2)>div:nth-of-type(1)>p`
   (`class="mt-3 text-xs text-surface-500 max-w-md leading-relaxed"`, rect x = −22, w = 420) in
   light AND dark mobile. Proven pre-existing (the same flags reproduce with the pre-change
   stylesheet), so it is a view-level mobile layout bug in the dashboard's "delivery health"
   card.
4. **R1 — failed-POST checkbox groups**: replay can only restore what the field map carries. On a
   failed `/settings/webhooks` POST the handler records `fields.error("events", …)` but not the
   selected values (`web.rs` ~4512), so the group replay has no data; same shape for the API-key
   scope group (~4368) and the placement `providers` group. Exact change: for each selected value,
   `fields.set("events", event)` etc. (the map's `groups >1 values` path already re-checks them —
   see the new `failed_replay_replaces_checked_and_selected_defaults` test).
5. **R1 — table scroll regions**: `.apex-table-wrap` is focusable-scrollable but the row renderer
   emits no `tabindex="0"`/`role="region"`+label, so keyboard users cannot reach the horizontal
   scroll of wide tables. The stylesheet side is ready (`:focus-visible` ring + `position:relative`
   container); the markup needs the attribute.
6. **R3 — `apps/marketing-zola/tailwindcss` is corrupt in git**: the checked-in Mach-O arm64 binary
   is missing its first 4 bytes (`0c 00 00 01 …` instead of `cf fa ed fe 0c 00 00 01 …`), so
   `tools/dev-start.sh` cannot regenerate any stylesheet on this host (`exec format error`). This is
   why this lane had to run the official v3.4.17 linux-arm64 release in a container. Fix: re-add the
   binary intact or switch the recipe to the image/CI-downloaded CLI.
7. **Orchestrator — one fixture-coverage gap**: no exported fixture expresses a plan/permission
   RESTRICTED console page (the loaders' `entitlement` copy is exercised by api-server tests but not
   in the fixture matrix). `fixture_states.rs` cannot render it without a sanctioned auth/plan input
   shape; needs an owner decision (fixture-state entry + loader stub).
8. **Orchestrator — existing filed items still open elsewhere**: the api-server `ai_drafts` empty
   presentation-body failures, the sales-autopilot `apply_review` visibility, and the list-members
   route (R1's §3 items) are unaffected by this lane; nothing in this lane's files blocks them.

---

## 5. Final paragraph for the orchestrator

**Lane R2 executed its full brief with zero skips.** The centrepiece — **P1-9** — is closed as a real
fix, not a re-label: the committed input produced a 1747-line / 64-artifact-only-selector /
24-artifact-only-comment divergence from the served sheet, and that inventory is now empty of
authored rules (the 20 remaining artifact-only selectors are stale generated utilities that no source
or rendered document references, proven by `grep` + the class-integrity gate). The regenerated
artifact is deterministic (two runs, one hash), is the byte-identical sheet the running api-server
serves (`/assets/globals.css` 200, 162130 bytes), and carries the mobile/focus/panel/shell fixes that
used to exist only in the artifact. **P1-3** is closed with a chromium proof (5408 → 0 intercepted
points; the open drawer keeps its 320×844 recipe), **P1-8** is proven with a hostile-name test,
**P1-12** gained structural form-scoping, checked/selected REPLACEMENT and `aria-describedby` error
association (both with literal fail-before runs), and **P1-13** is validated by an independent
spec-based decoder over masks 0–7 across three versions *and* cross-checked module-for-module against
segno (0 function-region, 0 format-info differences; the decoder itself validated on segno's
matrices). All six ADDENDUM items landed (`axum_router` copy assertion → the interaction wording;
`Enabled`/`Not configured` added to `status_indicator_config` for R6/fold to switch the two data.rs
call sites to `DataCell::Status`; explorer return links absolute; the pricing gate now FAILS on
missing python3; the two full-suite reds fixed; baselines + contrast-audit fixtures re-exported with
`css 4172172a / marketing b976f48b / renderer 12b46db6`). Every §4.6–4.10/4.12 row and every §5.1/§5.2
row in this lane's ownership has a verdict in §1—§2, including the new drift/independence gates
(`tokens.rs` source-vs-artifact + baseline-vs-authority, `lib.rs` light/dark block twins, `ssr.rs`
source-extracted marketing inventory, `build.rs` completeness + provenance). **Suite state: 527/527
green, 0 skipped**; `dna_verify` 13/13; all eight Python UI/marketing gates green; the chromium layout
audit is 1189/1191 clean with the only flags pre-existing in R1's `/dashboard` mobile markup (proved
by re-running with the pre-change stylesheet). Clippy is clean for every file this lane owns; the four
remaining `ui-foundation` warnings are all in R1's `leptos_views.rs` and are filed with exact fixes,
as are the latent raw option interpolation, the missing keyboard-scrollable table attributes, the
checkbox-group replay values, the corrupt checked-in Tailwind binary, and the one fixture-coverage
gap. Nothing was committed; `assets/globals.css`, the input, goldens, baselines and fixtures are all
regenerated from the same authority.
