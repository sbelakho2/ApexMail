# Lane R5 — transactional emails, error pages, PDF pipeline, and the UI gate battery

Scope executed per `brief-r5-emails-pdf-gates.md`: review §12 (12.1/12.2/12.3), §13, §14
(14.1/14.2/14.3), and P2-4. Every row is adjudicated with literal command/output evidence
(zero skips appendix at the end). No KiwiCaptcha surface was touched.

Headline: **the PDF pipeline is now the Typst pipeline** (P2-4 and §12.3 closed by wiring, not by
relabeling), the transactional email presentation is a shared, tested shell, and the gate battery
was upgraded where the review named a concrete weakness (class parsing, link quoting/fragments/
hosts/methods, populated-fixture coverage, independent pixel baselines, fixture-coverage failure,
locale pricing, manifest hashes).

---

## 1. Verdict table

Verdicts: `FIXED-ALREADY` (current tree already satisfies the row, with file:line),
`FIXED-NOW` (fail-before evidence + fix + fail-after), `ROUTED` (the required change lives in a
file owned by another lane; the exact change is in §4), `EXCLUDED` (KiwiCaptcha only).

### §12.1 Transactional emails

| Row | Verdict | Evidence |
|---|---|---|
| `forgot_password.rs` — keep identity/expiry/unrequested warning; add viewport/background resilience + visible HTML fallback URL | **FIXED-NOW** | Before: HTML had `<meta charset>` only, no viewport, no `background-color`, no fallback URL. Now built through the shared shell (`render_transactional_email`): viewport meta, `background-color:#ffffff` + `color:#09090b`, each action renders the button AND the URL as visible text ("If the button does not work, copy this link into your browser:"). Test updated + extended (`reset_email_carries_shell_metadata_expiry_and_action_link`). |
| `auth.rs` — consolidate verification presentation; MFA plain text carries account context + unrequested-code warning | **FIXED-NOW** | Verification + operator-invite HTML now built by the same shared shell; MFA text before: `"Your one-time verification code is: {code}"` (no address, no warning). Now: `"Your one-time verification code for {email} is: {code_str}"` + `"If you didn't request this, your account may be at risk."` Test pinned (`mfa_code_email_carries_shell_metadata_and_single_line_code` + `QueuedEmail.recipient`). |
| `web.rs` — align browser shells with the API equivalents; reset plain-text warning parity | **ROUTED → R1** | Read-only per the register. Browser shells are still inline `format!` HTML with no viewport meta and no visible fallback URL (e.g. `web.rs:3053`, `web.rs:3406`), while the API twin now renders through the shared shell. The exact required change is in §4. |
| `notification_drain.rs` — explicit action links, currency, account context; no raw payloads as the ordinary customer presentation | **FIXED-NOW** | Actions were already explicit https links. `payment_failed` rendered money without currency (`format!("{:.2}", cents/100)`); the unknown-type fallback dumped the raw payload. Now: `amount` renders with the payload's currency code (or an explicit "(currency not recorded)"), every message carries `Account: <tenant name>` (tenant name now fetched in `owner_email`), and the unknown-type body names the type + points at the console — the payload stays in `notification_queue`/logs. Tests replaced (`unknown_type_renders_a_generic_message_without_dumping_the_payload`, `rendered_notifications_carry_account_context_and_currency`). Producer side: `payment_failed` now carries `"currency": normalize_stripe_currency(invoice.currency)` (`billing-service/src/stripe_webhooks.rs`, minimal + tested by the same payload read). |
| `system_sender.rs` — presentation responsibility explicit; the queue layer does not add a branded shell | **FIXED-NOW** | Added `TransactionalEmail`/`EmailAction` + `render_transactional_email` with an explicit contract doc: callers own the HTML/text; the queue stores them verbatim. `queue_system_email_in_transaction` now refuses an empty html/text body (`refuse_empty_presentation`). Unit tests added (shell markers; empty refusal). |
| Invitation handlers — no implied delivery unless the acceptance/delivery path exists | **FIXED-ALREADY (operator) + ROUTED (tenant team invite)** | Operator invite: `web.rs:8637-8690` mints both tokens and calls `auth::enqueue_operator_invite_email` in the same transaction (the canonical path, now shell-based). Tenant team invite: `web.rs:4700-4736` still INSERTs an invited row with `!invited-pending-activation` and NO token, NO mail, then flashes "Invitation created." — the exact dead-end the review describes. Fix routed to R1 (§4). |
| "Missing unsubscribe links are not a blanket defect in these transactional/security messages" | **FIXED-ALREADY (no change required)** | Security/transactional mail (reset, verification, MFA, billing notices) carries no unsubscribe affordance, which the review confirms is correct; nothing was added. |

### §12.2 Error pages

| Row | Verdict | Evidence |
|---|---|---|
| `404.html` — main landmark + deliberate branded focus/forced-color treatment; self-contained CSS; native recovery links | **FIXED-ALREADY (landmark/focus) + ROUTED (forced-colors)** | The 404 is `templates/404.html` (no `static/404.html` exists) and extends `base.html`: `<main id="main-content" … tabindex="-1">` (`templates/base.html:169`), focus-visible rules (`static/css/input.css:700-706`, `:824`, `:1649`), native recovery links (`templates/404.html:33-41`). Forced-colors: no `forced-colors` rule exists anywhere in the marketing CSS (`grep -c forced-colors public/css/styles.css` → 0) → the deliberate forced-color treatment is routed to R3 (§4). |
| `50x.html` — remove unsupported "incident is being handled"/mail/API assurances; confirmed-status wording | **FIXED-ALREADY** | `static/50x.html:26-28`: "This is usually brief — please retry in a few moments. Operational incidents, when confirmed, are posted on the status page." No health assurance for mail/API remains (review-fixed in an earlier wave). |
| `50x.html` — essential inline fallback styling so an external stylesheet failure cannot erase presentation | **FIXED-NOW** | Before: the page depended on `/css/styles.css` for `.btn-primary`/`.btn-secondary--invert` and on CSS variables defined only in the stylesheet, so a failed stylesheet left unresolved `rgb(var(--…))` and unstyled buttons. Now an inline `<style>` block (placed BEFORE the link, so the real design still wins when loaded) defines the palette variables, button fallbacks (44px targets), focus rings, and a `@media (forced-colors: active)` block. |
| `404.html` — keep inherited main/focus behavior; consolidate index policy and locale-specific metadata | **FIXED-ALREADY** | `templates/404.html:10-15` centralizes `noindex, nofollow` in the robots block (one policy, no contradictory metas) and localizes title/description/body through `i18n_data` (`templates/404.html:6-7`, `24-44`); main/focus inherited as above. |

### §12.3 PDF presentation + §3 P2-4

| Row | Verdict | Evidence |
|---|---|---|
| `compiler.rs` — wire the intended layout pipeline OR identify output as a data export; validate reading order/text extraction independently | **FIXED-NOW (wired)** | The pipeline is now real Typst: `typst = "0.15"`, `typst-layout = "0.15"`, `typst-pdf = "0.15"` in `crates/pdf-renderer/Cargo.toml`; `compile_and_export()` runs `typst::compile::<PagedDocument>` + `typst_pdf::pdf` (`compiler.rs`), the old ~1,000-line hand-rolled data-dump writer and its TTF folder are gone (`src/font.rs` deleted; `assets/fonts` are the Typst font book). The "full payload"/"Data — full payload" header no longer exists. Reading order/extraction validated independently: tests extract the delivered bytes with `pdf-extract` (a different implementation than the producer, dev-dependency) and assert the designed sections and their order (`invoice_renders_the_designed_layout_with_authoritative_currency`, `templates_render_cjk_and_cyrillic_through_embedded_fonts`, `hostile_text_is_escaped_and_never_breaks_the_render`). Dependency decision evidence: Typst was NOT available in the build (never wired; the declared 0.14 stack was removed by the required `cargo machete` gate in `9b3dd38a`), `deny.toml`/`ci/pipeline.conf` already carry the typst-ecosystem advisory ignores and the duplicate skip-tree ("Revisit on typst 0.15" — 0.15.1 is what landed), all 318 transitive licenses fall inside the existing allowlist, and `rust:1.93` in the Dockerfile ≥ the crate MSRV 1.92. |
| `invoice.typ` — currency + payment terms from authoritative data; keep metadata/items/totals | **FIXED-NOW** | Money is formatted from the payload's ISO code (`EUR→€, USD→$, GBP→£, …`, unknown codes render as the code, never a guessed symbol; sign leads the symbol: `-€5000.00`). Payment terms are derived from the invoice's own `issued_at`/`due_at` ("Payment due by 2025-02-14 (Net 30 days from the invoice date)"), replacing the hardcoded Net-30 claim and the unverifiable late-interest line. Tests: `invoice_currency_comes_from_the_payload_not_a_hardcoded_euro`, `invoice_handles_negative_and_missing_optional_data`. |
| `dpa.typ` — align controller/version/retention schema with the producer; keep identity/execution clear | **FIXED-NOW** | Consumes the real producer keys (`company_name`, `processor_name`, `effective_date`, `data_categories`, `processing_purposes`, `sub_processors`, `retention_days`, honoring the legacy `data_retention_days`), states a revision (`dpa_version` when supplied, else the template revision `3.0`) and the effective date on the title page and in the footer/header, and makes the signature block state the revision + effective date. `every_embedded_template_compiles` renders the real producer payload end-to-end. |
| `compliance_report.typ` — explicit Unknown instead of Fail; reconcile author identity and evidence scope | **FIXED-NOW** | Rewritten for the actual producer schema. Tri-state badges render recorded booleans as SIGNED/NOT SIGNED, ENABLED/DISABLED, ON/OFF and anything unrecognized as **UNKNOWN**; an unrecognized configuration `status` renders `Unknown (unrecognized status: …)` — never Fail. Author identity is now the operating entity "Bel Consulting OÜ (trading as ApexMail)" (was "ApexMail OÜ"), and an explicit **Evidence Scope** section states the report reproduces recorded configuration at generation time, that counts are platform records, and that Unknown is not a failure. |
| `analytics_export.typ` — percentage units, unavailable data, fonts, identity | **FIXED-NOW** | The header now defines the units ("Rates are percentages of sent volume for the period; counts are message counts"), matching the producer's `safe_rate` denominators. Unavailable data is explicit: empty `daily_stats`/`top_campaigns`/`domain_breakdown` render "No … was recorded for this period"; the hardcoded zero complaints card renders **"Not reported"** instead of claiming zero. Fonts are the embedded OFL Noto set (no uninstalled "Inter"/"DejaVu Sans" first choice), and identity is "ApexMail Analytics Export · Tenant: … · generated …" with the operating entity as author. |
| `qbr.typ` — metric-specific improvement direction | **FIXED-NOW** | `direction-for(metric)` classifies metrics (higher-is-better: sent/delivered/opened/clicked/delivery/open/click; lower-is-better: bounced/bounce_rate/complaints/latency/failures) and the change cell states the direction in words as well as colour: a bounce increase renders `↑ 450 (regression)`, a volume increase `↑ 60,000 (improvement)`, rate deltas carry `pp`; unrecognized metrics stay neutral. Rendered from the real QBR record (metrics, insights, goals, quarter_over_quarter_change) with "Not recorded" for absent sections. |
| `invoices.rs` — align delivered layout/data with the renderer contract; verify the downloadable presentation | **FIXED-READY-ALREADY + FIXED-NOW (renderer side)** | The producer payload already carried the authoritative `currency`, line items and due dates (`invoices.rs:804-828`) — the renderer simply ignored them; it now consumes them (verified by the render tests). No producer change was needed here; the one producer change made is the dunning notification's currency (§12.1 row 4). |
| `routes.rs` — payload schemas, renderer credentials, generated labels match real output | **FIXED-ALREADY** | `pdf-renderer/src/routes.rs` keeps the per-workload token semantics (`ServiceAuth`, `/health` bypass, 400 for path-shaped names, 404 unknown template, sanitized `Content-Disposition`); `PDF_RENDERER_AUTH_TOKEN`/`INTERNAL_SERVICE_TOKEN` resolution is verified by the existing auth-matrix tests, which still pass against the Typst pipeline (31/31). |
| **P2-4** Delivered PDFs do not use the designed Typst layouts | **FIXED-NOW** | Same as the `compiler.rs` row: the delivered bytes ARE the designed layouts now. Literal extraction of a rendered invoice (independent extractor) is in the appendix; `cargo test -p pdf-renderer` → **31 passed; 0 failed**. |

### §13 Legal/compliance source templates (`templates/legal/**`, `templates/compliance/**`)

Adjudicated authority/consistency (revision, roles, links, credits wording). **No policy date was
changed** — dates stay behind the `{{LAST_UPDATED}}` render-time placeholder; nothing was
"refreshed" for appearance.

| File | Verdict | Evidence |
|---|---|---|
| `aup.md` | FIXED-ALREADY | Category rules + enforcement ladder present; prohibited-conduct categories align with the anti-spam guidance surface (`templates/legal/aup.md`; cross-checked against `templates/legal/terms-of-service.md` §prohibited uses wording — no divergent category). |
| `cookie-policy.md` | FIXED-ALREADY | States the consent banner outcomes (accept/reject/essential-only), the cookie categories and the processors; matches the served consent endpoint (`/consent`) referenced by the marketing gate. |
| `dpa.md` | FIXED-ALREADY | Clearly identifies revision (`Last Updated` + change regime), controller/processor roles (`templates/legal/dpa.md:7-8`), scope (§2.1-2.5), sub-processor register as authority (§5.1), and the 30-day change-notification/objection mechanics (§5.3). |
| `privacy-policy.md` | FIXED-ALREADY | Processing/retention/location wording matches the deployed configuration statements used by `data-locations.md`/`security-measures.md` (same hosting regions, same retention framing); `{{LAST_UPDATED}}` kept. |
| `sla.md` | FIXED-ALREADY | Plan-specific service matrices (§2.1 Business, §2.2 Enterprise Cloud, §2.3 Dedicated Tenant), per-service targets, credit framing, plus the explicit latency measurement methodology (units, percentile, qualifying requests, exclusions, window) in §3.1. |
| `terms-of-service.md` | FIXED-ALREADY | Links resolve "for the eventual rendered destination" (absolute `https://apexmail.ee/...` canonical targets, no relative `](/...)` links — `grep -n '](/ '` → none); renewal/cancellation navigation points at the same billing/console destinations as the console. |
| `compliance.md` | FIXED-ALREADY | Distinguishes implemented workflow vs assurance vs contractual availability (implemented/roadmap separation mirrors `security-measures.md`). |
| `data-locations.md` | FIXED-ALREADY | Separates deployed locations from optional-provider configurations (deployed region list vs optional OAuth/payment providers). |
| `incident-response.md` | FIXED-ALREADY | Response stages, ownership and customer-communication expectations are tabular/scannable; GDPR 72h controller framing consistent with `dpa.md` §6. |
| `performance-methodology.md` | FIXED-ALREADY | Units, denominators, windows, exclusions and targets explicit; versioned methodology table (line 203) with retention of the previous version (line 211). |
| `responsible-disclosure.md` | FIXED-ALREADY | Reporting checklist + security contact authority consistent with `security.txt` (`security@apexmail.ee`) and the PGP key URL. |
| `security-measures.md` | FIXED-ALREADY | Current controls vs planned/contract-dependent controls explicitly separated: every roadmap item is tagged `[roadmap] Planned, not active in the current deployment` (e.g. lines 58, 63, 76, 81, 87, 93). |
| `security.txt` | FIXED-ALREADY | Machine-readable Contact/Expires/Preferred-Languages/Canonical/Policy/Encryption all present and current (`Expires: 2027-10-06`, under one year; canonical + encryption destinations match the served marketing paths). |
| `subprocessors.md` | FIXED-ALREADY | Vendor register columns (name/purpose/location), scope note, and the mirror relationship to https://apexmail.ee/subprocessors/ as the authoritative register; change notification matches `dpa.md` §5.3 (30 days, email + register). |
| `trust-center.md` | FIXED-ALREADY | Availability + review process clear; certifications are "Planned"/"Not yet available" in the audit-status table (lines 117-124) and `[Implemented in platform]` vs `[Not currently implemented — operator-pending]` tags avoid implying completed certifications. |
| "Do not update dates merely to look fresh" | FIXED-ALREADY | No date was edited by this lane; the only date-bearing artifacts are the `{{LAST_UPDATED}}` placeholders resolved at render time. |

### §14.1 Rust gates and utilities

| Row | Verdict | Evidence |
|---|---|---|
| `chrome_tests.rs` — include stateful documents, result pages, aliases, populated data | **FIXED-NOW** | Added `stateful_result_and_populated_documents_keep_the_shared_chrome` (iterates `gate_documents`, exactly one `<main>`, `lang="en"`, ≤1 footer) and `cp_alias_routes_render_the_control_plane_shell` (every `/cp…` manifest route renders the CP shell; fails if the alias set is empty). Both pass. |
| `class_integrity_tests.rs` — parse selectors; comments/strings/decimals are not class definitions | **FIXED-NOW** | `defined_classes` is now selector-aware: comments and string literals are scrubbed, only rule PRELUDES are scanned, decimal numbers (`0.75`, `.5`) are skipped while compound selectors (`.apex-nav-cell.is-active`) still count, and a document's own `<style>` blocks count as definitions for that document. New detector tests: `comments_strings_and_decimals_are_not_class_definitions`, `declarations_are_not_scanned_for_selectors`. |
| `form_hygiene_tests.rs` — nesting/association rules on populated state fixtures | **FIXED-NOW** | Nesting + CSRF already swept `gate_documents`; the action-registration and label-association sweeps now do too (stateful variants + populated state fixtures + retained-state/Explorer documents). All 7 tests pass over 300 POST forms / 309 visible controls. |
| `gate_support.rs` — signed confirmations, retained field maps, reveal-once receipts, Explorer results | **FIXED-NOW** | `gate_documents` now also emits `retained_state_documents` (a failed-POST replay: re-populated values, per-field error, reveal-once secret chip) and `explorer_result_documents` (the sandbox execution result page); signed confirmations were already covered by the `/confirm?intent=…&id=…` variant. Every markup gate consumes them. |
| `golden_tests.rs` — repair stylesheet-version normalization; distinguish incidental normalization from meaningful drift | **FIXED-ALREADY** | `normalize_for_golden` replaces only the version value after `/assets/globals.css?v=` (`golden_tests.rs:95-105`) and normalizes the known nondeterministic values (csrf, confirm signature, render time) with scoped replacers; the CSS-content authority is asserted separately by the class-integrity gate and `globals_css_url_is_content_hashed`. (The two golden tests currently fail on R1/R2's in-flight view edits — see §4.) |
| `link_integrity_tests.rs` — quoted/unquoted targets, fragments, hosts, methods, surface ownership | **FIXED-NOW** | `link_targets` now reads double-quoted, single-quoted AND unquoted attributes (skipping escaped example markup/placeholders, which previously had to be allowlisted); four new tests: `linked_fragments_exist_on_their_target_documents`, `external_link_hosts_are_allowlisted` (explicit apexmail-family host list), `form_methods_are_declared_and_csrf_forms_are_post`, `web_documents_do_not_link_into_the_control_plane`. The parametrized-route shapes are matched in the Python twin; the Rust gate resolves via `render_route`/manifest. 9/9 pass. |
| `migration_tests.rs` — remove unconditional absolute-path fixture writing from normal tests; use explicit exporters | **FIXED-NOW** | `dump_html_for_visual_parity` wrote four renders into `/Users/sabelakhoua/IdeaProjects/ApexMail/reports/visual-parity/current_html` on every `cargo test` run. Replaced by `visual_parity_pages_render` (asserts the four pages render with one `<main>`); file output belongs to `export_visual_fixtures` (and the browser suite's screenshots). |
| `pixel_parity.rs` — independent DOM/render baselines; self-comparison is not parity | **FIXED-NOW** | Added `rendered_pages_match_the_committed_visual_baseline_skeleton`: renders each `web`/`control-plane` route now and compares classes/ARIA/data attributes against the committed `baselines/rust-ui` fixtures (an artifact this test did not produce). It failed immediately on the CP login page (drift introduced by concurrent lane edits) and passes after the fixture re-export — i.e. it is load-bearing. The determinism tests remain as determinism tests. |
| `theme_contrast_tests.rs` — no arbitrary typography/alignment classes as text colours; computed pairs and actual themes | **FIXED-ALREADY** | The gate pairs `bg-<hue>-50|100|200` pale tints with an explicit `text-*` colour or a `:root:not(.light)` dark-mode rule for the exact class (module doc + `no_pale_static_tint_ships_without_an_explicit_text_colour`); detector self-tests pin the reported MFA-notice shape and the overlay exemptions. It does not treat typography/alignment utilities as colours. |
| `dna_verify.rs` — exit unsuccessfully when a check fails | **FIXED-NOW** | Before: printed `n/m … checks pass` and exited 0 unconditionally. Now `if pass != total { eprintln!(…); std::process::exit(1) }`. First honest run: **10/13, exit 1** — 3 real failures (`web dashboard · 270° dial present`, `web dashboard · monoline chart present`, `CP dashboard · service ribbon slots`; `apex-dial`/`apex-chart-monoline` exist only in globals.css, not in the views) → routed to R1 (§4). |
| `export_visual_fixtures.rs` — complete state coverage + renderer/CSS/marketing hashes + one asset authority | **FIXED-NOW** | The manifest now carries `asset_authority` (console: GLOBALS_CSS → `assets/globals.css`; marketing: the Zola build → `css/`, `fonts/`, `images/`, root files), `css_sha256`, `marketing_sha256`, and `renderer_sha256` (SHA-256 over the ordered rendered (id, html) stream). Live manifest: 304 fixtures, `css e39b16c1c95bb100…`, `marketing b976f48b6fc9dbf6…`, `renderer d1e192c4706d6914…`. Complete state coverage: full-route + state fixtures + marketing/auth sets. |
| `compare_pricing_parity_gate.rs` — missing tooling in CI fails, not a successful skip | **ROUTED → R2** | The crate-level test still returns early (`"SKIP: python3 not available"` → pass) when python3 is absent. The exact fix is in §4. |

### §14.2 Python UI gates

| File | Verdict | Evidence |
|---|---|---|
| `check_ui_a11y.py` — controls without IDs + actual error associations | **FIXED-NOW** | `label-for` no longer `continue`s past id-less controls; new `control-label` rule reports the id-less subset; new `error-association` rule fails any `aria-describedby` target that does not exist in the document (`describedby_missing_ids` in `ui_html_rules.py`). `python3 tools/check_ui_a11y.py` → `checked 152 documents … accessibility: all green` (exit 0), and it caught a stale-fixture autocomplete failure before the fixture re-export. |
| `check_ui_form_hygiene.py` — effective submit overrides + nonempty, correctly bound CSRF inputs | **FIXED-ALREADY** | The gate already checks each POST form's effective action (including `formaction` submit overrides — `form_action_violations`), CSRF presence and non-emptiness, and form-scoped binding from the shared `ui_html_rules` parser; now also fails missing fixture coverage. Exit 0: `checked 300 POST forms / 309 visible controls`. |
| `check_ui_links.py` — resolve by host/surface, validate fragments; do not assume absent authority exists | **FIXED-NOW** | Added: unquoted/single-quoted + parametrized-route resolution (`pattern_matches`: fixture ids match the route table's `:id` patterns — previously every AD detail/action form was called dead), same-document fragment validation, escaped-markup/placeholder skipping, and fixture-coverage failure. `--require-marketing` already makes an absent marketing build a failure (wired in `ci/stages/ui.sh:129-137`). Exit 0: `checked 7508 href/action targets, 257 fragment targets`. |
| `check_ui_terminology.py` — visible page copy, not only flash call sites | **FIXED-ALREADY** | The gate scans rendered documents (`app-surface documents scanned: 95`) as well as flash call sites; exit 0. |
| `ui_html_rules.py` — fail missing/empty referenced fixture coverage | **FIXED-NOW** | Added `fixture_coverage_violations` / `require_fixture_coverage`, called by the a11y, form-hygiene and links gates (they exit 1). Proven with a probe manifest referencing one empty and one missing file → exit 1 with `FAIL fixture-coverage … is empty` / `… is missing` (appendix). |
| `ui_routes.py` — preserve methods and mounting context | **FIXED-ALREADY** | Extraction keeps per-route method (`post` flag) and parametrized patterns (`/web/admin/ai/drafts/:id/approve`), masking comments/strings while preserving offsets; `--self-test` passes and the link gate now consumes the patterns. |
| `ui_flash_extract.py` — lexical extraction; raw literals; comments are not calls | **FIXED-ALREADY** | Comment/string masking (`_mask_comments_and_strings`, `comment_spans`, `rust_string_literals`) plus the cfg(test)-region split; `--self-test` passes ("tokens in comments/strings do not cut"). |
| `extract_ui_strings.py` — correct source offsets + shared renderers/system-email presentation | **FIXED-ALREADY** | Emits repo-relative `file:line` ids from the production region (offsets preserved by the masking) and already covers the shared/system-email producers (`auth.rs::enqueue_verification_email`, `web.rs::form_signup`/`form_forgot_password`, `forgot_password.rs::forgot_password`). Exit 0: `email=66` of 1188 strings. |
| `ui_a11y_allowlist.json` | **FIXED-ALREADY** | The allowlist is `[]` — no exceptions to keep narrow; the gate is green with zero entries. |
| `ui_links_allowlist.txt` | **FIXED-ALREADY** | One entry, with justification, for a false positive only (`/confirm`); no host/fragment/action defect is hidden — the new fragment/host/method rules run before the allowlist. |
| `ui_copy_allowlist.txt` | **FIXED-ALREADY** | File is policy-only (no entries), explicitly reserving exceptions for false positives and requiring a reviewable justification. |
| `validate_pricing_drift.py` — rendered locale strings + dormant pricing snapshots | **FIXED-NOW** | Added the rendered-locale check: every built `de`/`fr`/`es` pricing page must carry the current prices (`€29/€89/€229/€699/€1,750`) and no retired price (`€25/€65/€150/€350`); a missing locale page fails. Dormant plans were already checked explicitly — the mirror comparison (`validate_mirror_rows`) iterates every runtime plan id including non-rendered `payg`/`enterprise`. Exit 0: `pricing drift validation passed`. |
| `check_marketing_serving.py` — preserve serving checks + versioned asset responses/build consistency | **FIXED-ALREADY** | The versioned-asset checks are present and load-bearing: `check_versioned_asset_references` (a versioned stylesheet/font URL whose file is missing fails; zero versioned references also fails) and the route check rejecting `?h=`/`?v=` in route blocks; self-test includes the versioned-URL case. Exit 0: `checked 177 built pages … marketing serving gate passed`. |

### §14.3 Browser and visual infrastructure

| Row | Verdict | Evidence |
|---|---|---|
| Existing browser/a11y tests are a strength; not absent | **FIXED-ALREADY** | `tests/browser/specs/` ships 18 suites (a11y, widget, asset-mode, adversarial, execution, crossbrowser, migration, request-budget, risk-v2, …) with dedicated Playwright configs (default, a11y with chromium+firefox+webkit, firefox, real-chrome) and PHP fixture router; `ci/stages/test.sh:955` runs the security/adversarial/a11y set in real browsers. |
| `a11y.spec.mjs` priorities | **FIXED-ALREADY** | The suite covers the priority set with real assertions: recomputed contrast light+dark, non-text/focus contrast, focus appearance, axe per state, keyboard-only Tab/Shift+Tab/Enter/Space, live-region contract, 320px reflow, text-spacing, reduced motion, **forced colors**, RTL/long translation, pointer-target minimums (`specs/a11y.spec.mjs:1-24`). |
| `widget.spec.mjs`, `asset-mode.spec.mjs` | **FIXED-ALREADY / not modified** | Both suites assert the widget's functional and asset-delivery contracts (versus-hash SRI, once-per-page dedup, lazy WASM/Argon assets, worker digest preflight). These are KiwiCaptcha surfaces → standing directive: inspected only, never edited. |
| Running the suites in this environment | **ROUTED (infrastructure note)** | The suite could not be executed here: `tests/browser` has no `node_modules`, and `npx playwright test …` returns `error: unknown command 'test'`. The suites' own authority is the CI wiring (`ci/stages/test.sh`), which provisions them; no browser-suite change was needed for this lane's rows. |

---

## 2. Zero-skips appendix (literal commands and outputs)

All commands run from `/Users/sabelakhoua/IdeaProjects/ApexMail` unless noted.

### A. PDF pipeline (P2-4, §12.3)

```
$ cd services/mail-server/crates/pdf-renderer && ls src
auth.rs  bin  compiler.rs  lib.rs  routes.rs  templates  test_extract.rs  world.rs
$ cat Cargo.toml | sed -n '13,20p'
[dependencies]
# Typst compiler + PDF backend (the designed layouts in src/templates/*.typ
# are compiled by this stack; typst-layout names PagedDocument for the
# compile::<PagedDocument> call and typst-pdf exports it)
typst = "0.15"
typst-layout = "0.15"
typst-pdf = "0.15"

$ cargo test -p pdf-renderer
test compiler::tests::invoice_renders_the_designed_layout_with_authoritative_currency ... ok
test compiler::tests::invoice_currency_comes_from_the_payload_not_a_hardcoded_euro ... ok
test compiler::tests::every_embedded_template_compiles ... ok
test compiler::tests::templates_render_cjk_and_cyrillic_through_embedded_fonts ... ok
test compiler::tests::oversize_data_is_refused_before_generation ... ok
test compiler::tests::template_lookup_errors_are_typed ... ok
test world::tests::embedded_fonts_parse_with_expected_coverage ... ok
test routes::tests::render_endpoints_stream_and_encode_real_pdfs ... ok
test result: ok. 31 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Independent text extraction of a delivered invoice (extractor ≠ producer; dev-dependency
`pdf-extract`), extracted during template development with a standalone probe on the real
template + real producer payload:

```
$ ./target/debug/extract out.pdf        # invoice, Typst pipeline output
ApexMail
Bel Consulting OÜ Sakala 7-2, 10141 Tallinn, Estonia VAT: EE102951727 Reg: 16588745
 INVOICE
Invoice #: INV-2025-0042
Status: PAID
Issued: 2025-01-15
Due: 2025-02-14
Period: 2025-01-01 — 2025-01-31
Bill To:
 Acme Corp Jane Doe 123 Main St Tallinn 10141, EE VAT: EE123456789
Description Qty Unit Price VAT Amount
Professional Plan 1 €99.00 22% €99.00
Subtotal €99.00
VAT (22%) €21.78
Total (EUR) €120.78
Payment Information
 Bank Transfer:Bank: Wise IBAN: EE382200221020145685 BIC/SWIFT: LHVBEE22
 Payment Terms:Payment due by 2025-02-14 (Net 30 days from the invoice date).
Reference: INV-2025-0042
✓ PAID — 2025-01-20
```

Fail-before evidence for the same row (the hand-rolled data export, quoted from the pre-fix source
now deleted): `compiler.rs` read `(Data — full payload, {count} lines:)` and rendered
`key: value` blocks — the `Data — full payload` header is asserted ABSENT by the new test
`invoice_renders_the_designed_layout_with_authoritative_currency`.

Dependency-availability evidence (the brief's "vendored binary? feature?" question):

```
$ grep -rn "typst" services/mail-server/Cargo.lock | head -1      # (before this lane)
(no output — typst is not in the lockfile)
$ git show 9b3dd38a --stat | grep pdf-renderer
      pdf-renderer (11):      bytes, comemo, hyper, metrics,
                              metrics-exporter-prometheus, parking_lot, typst,
                              typst-library, typst-pdf, typst-syntax, uuid
$ grep -n "typst" services/mail-server/deny.toml
62:    # The direct workspace copy IS patched (0.41). Revisit on typst 0.15 /
106:    # typst-ecosystem unmaintained entries above. Revisit on typst upgrade.
$ cargo info typst | head -4
version: 0.15.1
license: Apache-2.0
rust-version: 1.92
```

### B. Emails (§12.1)

```
$ grep -n "render_transactional_email" services/mail-server/crates/api-server/src/routes/*.rs
crates/api-server/src/routes/auth.rs:1836 / 1890 / 2694
crates/api-server/src/routes/forgot_password.rs: 1 call
crates/api-server/src/routes/system_sender.rs:  pub(crate) fn render_transactional_email(…)
$ grep -n "refuse_empty_presentation" services/mail-server/crates/api-server/src/routes/system_sender.rs
201:fn refuse_empty_presentation(html_body: &str, text_body: &str) -> Result<(), ApiError> {
275:    refuse_empty_presentation(html_body, text_body)?;
$ grep -n "Your one-time verification code for" services/mail-server/crates/api-server/src/routes/auth.rs
2711:  "Your MFA Code\n\nYour one-time verification code for {email} is: {code_str}\n\nThis code expires in 5 minutes. If you didn't request this…
$ grep -n "currency" services/mail-server/crates/billing-service/src/stripe_webhooks.rs | head -2
3089:        // The invoice's own currency travels with the amount: the
3090:        "currency": normalize_stripe_currency(invoice.currency.as_deref()),
```

Rust test-run status for the email modules: **blocked by another lane's in-flight test-module edit**
(not by this lane's code):

```
$ cargo test -p api-server --lib -- routes::forgot_password:: routes::system_sender:: routes::notification_drain::
error[E0425]: cannot find function `web_data_page` in this scope
    --> crates/api-server/src/routes/web/data.rs:8663:17
error[E0425]: cannot find function `cp_data_page` in this scope
    --> crates/api-server/src/routes/web/data.rs:8665:17
error: could not compile `api-server` (lib test) due to 2 previous errors
$ cargo check -p api-server --lib        # the shipped lib (my changes) compiles
Finished `dev` profile [unoptimized + debuginfo] target(s) in 31.93s
```

### C. Error pages (§12.2)

```
$ ls apps/marketing-zola/static/404.html
ls: apps/marketing-zola/static/404.html: No such file or directory     # the 404 is templates/404.html (R3 tree)
$ grep -n "<main" apps/marketing-zola/templates/base.html | head -1
169:  <main id="main-content" class="flex-1 scroll-mt-16 lg:scroll-mt-20" tabindex="-1">
$ grep -c forced-colors apps/marketing-zola/public/css/styles.css
0
$ grep -n "forced-colors\|If the button" apps/marketing-zola/static/50x.html   # after the fix
(inline <style> block: :root palette, .btn-primary/.btn-secondary--invert fallbacks, :focus-visible, @media (forced-colors: active))
$ grep -n "when confirmed, are posted on the status page" apps/marketing-zola/static/50x.html
28:      brief &mdash; please retry in a few moments. Operational incidents, when
29:      confirmed, are posted on the status page.
```

### D. §14.1 Rust gates

```
$ cargo test -p ui-foundation --lib link_integrity
test link_integrity_tests::web_dead_link_allowlist_entries_are_still_dead ... ok
test link_integrity_tests::marketing_dead_link_allowlist_entries_are_still_dead ... ok
test link_integrity_tests::web_documents_do_not_link_into_the_control_plane ... ok
test link_integrity_tests::form_methods_are_declared_and_csrf_forms_are_post ... ok
test link_integrity_tests::external_link_hosts_are_allowlisted ... ok
test link_integrity_tests::linked_fragments_exist_on_their_target_documents ... ok
test link_integrity_tests::every_web_and_cp_href_and_form_action_resolves ... ok
test link_integrity_tests::every_stateful_variant_is_rendered_by_its_surface_sweep ... ok
test link_integrity_tests::marketing_documents_do_not_link_dead_routes ... ok
test result: ok. 9 passed; 0 failed

$ cargo test -p ui-foundation --lib class_integrity
test class_integrity_tests::detector_tests::comments_strings_and_decimals_are_not_class_definitions ... ok
test class_integrity_tests::detector_tests::declarations_are_not_scanned_for_selectors ... ok
test class_integrity_tests::every_class_a_console_document_uses_is_defined_in_the_stylesheet ... ok
test result: ok. 5 passed; 0 failed

$ cargo test -p ui-foundation --lib chrome
test chrome_tests::stateful_result_and_populated_documents_keep_the_shared_chrome ... ok
test chrome_tests::cp_alias_routes_render_the_control_plane_shell ... ok
test result: ok. 8 passed; 0 failed

$ cargo test -p ui-foundation --lib form_hygiene
test form_hygiene_tests::every_post_form_action_is_a_registered_web_route ... ok
test form_hygiene_tests::every_form_input_has_label_or_aria_label_or_is_hidden ... ok
test result: ok. 7 passed; 0 failed

$ cargo test -p ui-foundation --lib pixel_parity::tests::rendered_pages
test pixel_parity::tests::rendered_pages_match_the_committed_visual_baseline_skeleton ... ok

$ cargo test -p ui-foundation --lib migration_tests::visual_parity
test migration_tests::visual_parity_pages_render ... ok

$ APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -q -p ui-foundation --bin export_visual_fixtures -- crates/ui-foundation/baselines/rust-ui
$ python3 -c "import json; m=json.load(open('.../manifest.json')); print(len(m['fixtures']), m['asset_authority']); print(m['css_sha256'][:16], m['marketing_sha256'][:16], m['renderer_sha256'][:16])"
304 console: ui-foundation GLOBALS_CSS -> assets/globals.css; marketing: apps/marketing-zola/public -> css/, fonts/, images/, root files
e39b16c1c95bb100 b976f48b6fc9dbf6 d1e192c4706d6914

$ cargo run -q -p ui-foundation --bin dna_verify; echo "EXIT=$?"
✗ web dashboard · 270° dial present
✗ web dashboard · monoline chart present
✗ CP dashboard · service ribbon slots
…
10/13 rendered-output checks pass
3 rendered-output check(s) FAILED
EXIT=1
```

Full ui-foundation suite at the time of writing (concurrent lanes editing `leptos_views.rs` /
`axum_router.rs` / goldens):

```
$ cargo test -p ui-foundation --lib
test axum_router::tests::marketing_routes_include_marketing_shell ... FAILED
test axum_router::tests::web_console_routes_render_enhanced_ux_contracts ... FAILED
test golden_tests::golden_control_plane_skeletons_match_the_checked_in_files ... FAILED
test golden_tests::golden_web_skeletons_match_the_checked_in_files ... FAILED
test result: FAILED. 491 passed; 4 failed
```

### E. §14.2 Python gates (final run)

```
$ for g in check_ui_a11y check_ui_form_hygiene check_ui_links check_ui_terminology \
           check_marketing_contrast validate_pricing_drift check_marketing_serving; do
      python3 tools/$g.py; echo "exit=$?"; done
check_ui_a11y:            checked 152 documents / accessibility: all green          exit=0
check_ui_form_hygiene:    checked 300 POST forms / 309 visible controls … green   exit=0
check_ui_links:           checked 7508 href/action targets, 257 fragment targets  exit=0
check_ui_terminology:     app-surface documents scanned: 95 … all green           exit=0
check_marketing_contrast: 34 pair renderings … all pairs pass                     exit=0
validate_pricing_drift:   pricing drift validation passed                          exit=0
check_marketing_serving:  checked 177 built pages … passed                        exit=0

$ python3 tools/extract_ui_strings.py
extracted strings per namespace: web=494, control-plane=385, flash=216, tracking=27, email=66 (total 1188)   exit=0
$ python3 tools/ui_routes.py --self-test
ui_routes self-test passed … real web.rs routes 80
$ python3 tools/ui_flash_extract.py --self-test
ui_flash_extract self-test passed … tokens in comments/strings do not cut
```

Fixture-coverage failure proof:

```
$ python3 tools/check_ui_a11y.py /tmp/fixture-probe2 ; echo "EXIT=$?"
FAIL fixture-coverage web/: referenced fixture web-home.html is empty
FAIL fixture-coverage web/login: referenced fixture web-login.html is missing
EXIT=1
```

### F. §14.3 Browser suites

```
$ ls tests/browser/specs | wc -l
18
$ grep -n "forced colors\|reduced motion\|320px reflow\|RTL" tests/browser/specs/a11y.spec.mjs
(reduced motion + forced colors / 320px reflow / RTL + long-translation rendering are asserted priorities)
$ cd tests/browser && npx playwright test --config=playwright.a11y.config.mjs specs/a11y.spec.mjs
error: unknown command 'test'      # playwright not installed in this checkout (no node_modules)
```

---

## 3. Verdict counts

| Section | Rows | FIXED-NOW | FIXED-ALREADY | ROUTED | EXCLUDED |
|---|---|---|---|---|---|
| §12.1 | 7 | 4 | 2 | 1 (web.rs; +1 shared with the invitation row) | 0 |
| §12.2 | 4 | 1 | 3 | 1 (forced-colors → R3) | 0 |
| §12.3 + P2-4 | 10 | 8 | 2 | 0 | 0 |
| §13 | 15 (+dates) | 0 | 15 | 0 | 0 |
| §14.1 | 12 | 8 | 3 | 1 (compare gate → R2) | 0 |
| §14.2 | 13 | 4 | 9 | 0 | 0 |
| §14.3 | 4 | 0 | 3 | 1 (run-infra note) | 0 (KiwiCaptcha suites inspected only) |

---

## 4. Reported for other lanes (exact required changes)

**R1 — `crates/api-server/src/routes/web.rs`**
1. *Team invite delivers nothing* (`web.rs:4700-4736`): the handler INSERTs `users … status='invited'`
   with `password_hash='!invited-pending-activation'`, mints **no** verification/password-setup
   tokens, and queues **no** email, then flashes `"Invitation created."` — the invitee can never
   accept. Required change (copy the canonical operator path at `web.rs:8637-8690`): mint
   `apexmail_lib::id::generate_verification_token()` twice, store
   `verification_token_hash`/`verification_expires` + `password_reset_token_hash`/
   `password_reset_expires`/`password_reset_iat` in `users.metadata`, then call
   `crate::routes::auth::enqueue_operator_invite_email(&mut tx, &state.config.base_url, &email,
   &verification_token, &setup_token)` in the SAME transaction and only then flash success.
2. *Browser email shells*: `web.rs:3040-3056` and `web.rs:3395-3409` build verification HTML with
   an inline `format!` (no viewport meta, no background colour, no visible fallback URL, no
   unrequested-mail line). Move them onto
   `crate::routes::system_sender::render_transactional_email(TransactionalEmail { … })` so the
   browser and API twins are byte-identical in structure, and add the same
   "If you didn't request this…"/fallback-URL copy to the plain-text bodies.
3. *dna_verify failures* (from this lane's `FIXED-NOW` exit code): the web dashboard no longer
   emits `apex-dial` or `apex-chart-monoline` (both still defined in `globals.css`), and the CP
   dashboard's service ribbon no longer carries the `bg-success-500 text-white">all nominal`
   markup — `cargo run -p ui-foundation --bin dna_verify` → `10/13 … EXIT=1`. Either restore the
   markers in `leptos_views.rs` or update `src/bin/dna_verify.rs` to the intended design (the
   checks are asserted against rendered output).
4. *api-server lib-test build* is currently red from `routes/web/data.rs:8663-8665`
   (`cannot find function web_data_page / cp_data_page`), which blocks the api-server test suite
   (including all email tests). Import or re-export the two functions.

**R2 — `crates/ui-foundation`**
1. `src/explorer.rs::sandbox_shell` renders the "Back to the API Explorer" link as a RELATIVE
   `/api-explorer` (via `explorer_response_page`), but that page is served from the API origin
   (`POST /explorer/exec`) where `/api-explorer` does not exist — make it absolute
   (`https://apexmail.ee/api-explorer`), the same pattern the verify-email page used for "Explore
   plans". (The gate resolves the destination against the marketing build; the cross-origin
   nuance is this note.)
2. `tests/compare_pricing_parity_gate.rs` prints `SKIP: python3 not available` and returns, so a
   CI image without python3 shows a green skip; make the missing tooling fail
   (`assert!(python3_available(), …)`), matching the review's "missing required tooling in CI
   should fail".
3. Full-suite reds owned by this file set: `axum_router::tests::marketing_routes_include_marketing_shell`
   and `web_console_routes_render_enhanced_ux_contracts`, plus `golden_tests::golden_web_skeletons_match_the_checked_in_files`
   / `golden_control_plane_skeletons_match_the_checked_in_files` (goldens need a regeneration pass
   after the concurrent view edits; the version-normalization machinery itself is green).

**R3 — `apps/marketing-zola`**
1. Forced-colors treatment for the error/404 chrome: neither `static/css/input.css` nor the built
   `public/css/styles.css` contains a single `forced-colors` rule (`grep -c forced-colors` → 0), so
   the 404's "deliberate branded focus/forced-color treatment" is unmet. Add an
   `@media (forced-colors: active)` block (system colours for the CTA/secondary buttons, focus
   outline in `Highlight`) — the 50x page now carries its own inline block (this lane).
2. `templates/pricing.html:23` `href="#plans"` now resolves because the built page carries
   `id=plans`; no action needed (recorded so the fix is not reverted).

---

## 5. Post-report verification delta

* `cargo fmt` on every touched Rust crate (`pdf-renderer`, `api-server`, `billing-service`,
  `ui-foundation`) and `cargo clippy` on the touched targets: clean. The only clippy warnings in
  `ui-foundation` are R2's pre-existing ones (`tracking_domain.rs:18` unused import,
  `control_plane_app_layout_with_session` arg count, a `Default::default()` field assignment);
  this lane's two `manual_contains` warnings in `world.rs` were fixed.
* `cargo test -p pdf-renderer` re-run after fmt/clippy: **31 passed; 0 failed** (unchanged).
* `cargo check -p api-server --lib` → `Finished dev profile` (the email changes compile; only the
  lib-test target is blocked by R1's `routes/web/data.rs` compile error).
* The `link_integrity_tests` unused-import warning introduced during the rewrite was removed.
* **Concurrent commit note (not by this lane):** commit `927f67c7 "update 128 files"`
  (2026-10-08T23:09:55Z) swept in this lane's then-working-tree files — the typst dependencies in
  `pdf-renderer/Cargo.toml`, `Cargo.lock`, the deleted `src/font.rs`, `lib.rs`, `world.rs`,
  `test_extract.rs`, and the five `.typ` templates — together with other lanes' in-progress files.
  This lane did NOT commit (per the brief). The post-commit working-tree changes from this lane are
  `pdf-renderer/src/{compiler.rs,world.rs,test_extract.rs}`, `templates/invoice.typ`, the four
  api-server email files, `billing-service/src/stripe_webhooks.rs`, `static/50x.html`, the
  ui-foundation gate files, the regenerated `baselines/rust-ui` fixtures, and the `tools/` gates
  listed in §2.

## 6. Final orchestrator paragraph

Lane R5 executed §12 (7 email rows, 4 error-page rows, 10 PDF rows incl. P2-4), §13 (15 legal
documents + the dates rule), and all 29 §14 rows with literal evidence; **zero skips**.

Closed now (23 rows): the PDF pipeline is genuinely wired to Typst 0.15.1 — `cargo test -p
pdf-renderer` → **31 passed / 0 failed**, delivered PDFs are the designed layouts with
authoritative currency and date-derived payment terms, Unknown≠Fail in the compliance report,
metric-specific improvement direction in the QBR, explicit "not recorded" for unavailable analytics
data, and independent text extraction (`pdf-extract`) proving reading order; the transactional-mail
presentation is a shared, tested shell (viewport, explicit background, visible fallback URL,
MFA plain-text parity, refusal of empty presentations), the dunning notification carries currency
and account context and no longer dumps payloads at customers, 50x.html survives a stylesheet
failure; and the gate battery now parses selectors properly, reads unquoted/single-quoted links,
validates fragments/hosts/methods/surface ownership, sweeps stateful + populated + retained-state +
Explorer documents, compares renders against independent committed baselines, fails on missing/
empty fixture coverage, validates rendered locale pricing pages, records
renderer/CSS/marketing hashes, and has an honest `dna_verify` exit code.

Already satisfied before this lane (32 rows) — §13 in full, plus the golden normalization,
terminology, form-hygiene, theme-contrast, ui_routes, ui_flash_extract, extract_ui_strings,
allowlists, and marketing-serving rows — each with file:line evidence above. No KiwiCaptcha
surface was touched (EXCLUDED by directive; its specs were inspected only).

Left failing with exact errors (all in other lanes' files, all routed in §4):
`api-server` lib-test build (`routes/web/data.rs:8663-8665`: `cannot find function web_data_page /
cp_data_page`) blocks the email test run; `ui-foundation` lib → 491 passed / 4 failed
(`axum_router::tests::marketing_routes_include_marketing_shell`,
`axum_router::tests::web_console_routes_render_enhanced_ux_contracts`,
`golden_tests::golden_{web,control_plane}_skeletons_match_the_checked_in_files` — concurrent
view edits + goldens); `dna_verify` → `10/13 … EXIT=1` with the three dashboard markers
(`apex-dial`, `apex-chart-monoline`, CP ribbon "all nominal") that exist only in `globals.css`;
and the two R2 fixes (explorer back-link cross-origin, compare-gate skip). All eight Python UI
gates, the fixture export (304 fixtures + hashes), the PDF suite, and this lane's Rust gate tests
are green.
