# Progress — frontend + gateways slice

Owner: adversarial pass, 2026-10-06. Paths are relative to the repo root.
`(full)` = read end-to-end. `(targeted)` = read in windows + grep-driven scan of the
whole file (large generated/markup files); findings recorded in
`findings-frontend-and-gateways.md`.

## ui-foundation (.rs + assets/*.css)

- [x] services/mail-server/crates/ui-foundation/src/lib.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/csrf.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/routing.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/data.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/ssr.rs (full) — P3: doc claims compile-time route validation; it is a test-time function only
- [x] services/mail-server/crates/ui-foundation/src/flash.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/icons.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/tokens.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/view_data.rs (full)
- [x] services/mail-server/crates/ui-foundation/build.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/bin/dna_verify.rs (full) — P3: always exits 0
- [x] services/mail-server/crates/ui-foundation/src/gate_support.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/chrome_tests.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/form_hygiene_tests.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/golden_tests.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/link_integrity_tests.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/class_integrity_tests.rs (full)
- [x] services/mail-server/crates/ui-foundation/tests/compare_pricing_parity_gate.rs (full)
- [x] services/mail-server/crates/ui-foundation/src/axum_router.rs (targeted; 4.1k lines) — P3 dead `let _ = escaped`
- [x] services/mail-server/crates/ui-foundation/src/shell.rs (full) — P1/P2 impersonation banner + user-context never wired
- [x] services/mail-server/crates/ui-foundation/src/primitives.rs (targeted; 4.6k lines) — P1 unescaped attributes/data in Input/Textarea/Select/NativeCheckbox
- [x] services/mail-server/crates/ui-foundation/src/leptos_views.rs (targeted; 8.7k lines) — P3 demo `selected` on every option; P3 dead `citations_script`
- [x] services/mail-server/crates/ui-foundation/src/charts.rs (targeted) — escaping present, clean
- [x] services/mail-server/crates/ui-foundation/src/qr.rs (targeted) — round-trip tested, clean
- [x] services/mail-server/crates/ui-foundation/src/explorer.rs (full) — P3 green status palette contradicts the pinned "no green" policy
- [x] services/mail-server/crates/ui-foundation/src/marketing.rs (targeted)
- [x] services/mail-server/crates/ui-foundation/src/pixel_parity.rs (targeted)
- [x] services/mail-server/crates/ui-foundation/src/migration_tests.rs (targeted)
- [x] services/mail-server/crates/ui-foundation/src/theme_contrast_tests.rs (targeted)
- [x] services/mail-server/crates/ui-foundation/src/bin/export_visual_fixtures.rs (targeted)
- [x] services/mail-server/crates/ui-foundation/assets/globals.css (targeted; 7k lines generated stylesheet; palette tokens checked against the pinned policy)
- [x] services/mail-server/crates/ui-foundation/assets/globals.input.css (targeted)

## api-server routes (web.rs, web/, demos/, assistant*, admin/, kiwicaptcha.rs, csrf.rs, explorer.rs)

- [x] crates/api-server/src/routes/csrf.rs (full) — P3 doc says "against the cookie" but the function never reads a cookie
- [x] crates/api-server/src/routes/kiwicaptcha.rs (full) — fail-closed rate limit, cancel endpoint shape-validated; clean
- [x] crates/api-server/src/routes/demos/mod.rs (full) — P1 false FOR UPDATE/idempotence comment; P2 bound_result doesn't bound; P2 zero-token RNG fallback
- [x] crates/api-server/src/routes/demos/script.rs (full) — clean
- [x] crates/api-server/src/routes/explorer.rs (targeted; 2.9k lines) — SSRF/rate-limit/recipient policy reviewed, hardened; P3 dead `_header_guard`
- [x] crates/api-server/src/routes/web.rs (targeted; 26k lines) — P0 `/web/admin/demos` + `/web/admin/ai/drafts/*` escape the system-tenant gate (see findings); CSRF bridge/`check_csrf`/redirects/tenant-scoped SQL reviewed; P3 OsRng expect
- [x] crates/api-server/src/routes/web/data.rs (targeted; 8k lines) — LoadState/Unavailable honesty contract reviewed; list/assistant/demos/ai-draft loaders checked; P3 demos loader comment says "this operator's sessions" while the query is unfiltered
- [x] crates/api-server/src/routes/admin/mod.rs (full) — P3 scope-guard test is a substring check and does not verify mounting despite its doc
- [x] admin/ai_drafts.rs (targeted; approve/reject core + handlers reviewed) — P0 via the web SSR entry point
- [x] admin/cross_tenant.rs (targeted) — P2 DB failures collapse to zeros
- [x] admin/predictive_analytics.rs (targeted) — P2 DB failures collapse to zeros/empty trends
- [x] admin/proxy.rs (targeted) — SSRF allowlist + DNS pinning reviewed; clean
- [x] admin/secrets.rs (targeted) — redaction + tenant-scoped lifecycle; clean
- [x] admin/sales.rs (targeted; 4.6k lines) — dynamic SQL uses fixed CTE/table constants + binds; clean
- [x] admin/insights.rs (targeted) — interval from a whitelist; ok
- [x] admin/mailboxes.rs, vat.rs, gdpr.rs, audit.rs, audit_search.rs, dashboard.rs, delivery_analytics.rs, growth_analytics.rs, revenue.rs, risk.rs, sse.rs, support.rs, support_analytics.rs, system_health.rs, system_sender.rs, tenants.rs, operators.rs, campaigns.rs, calendar.rs, compliance_overview.rs, content.rs, crm_leads.rs, domains.rs, features.rs, inbox.rs, leads_discovery.rs, warmup.rs, analytics.rs, analytics_export.rs (targeted pattern census: TODO/stub, ignored DB writes, `.unwrap()`, scope guards, SQL interpolation; no further provable defects recorded)
- Note: the brief's `routes/assistant*` has no files on disk; the assistant SSR form lives in `routes/web.rs` (reviewed) and its turn engine in `routes/ai_chat.rs` (outside this slice).

## tests/browser

- [x] tests/browser/package.json, package-lock.json (full)
- [x] tests/browser/playwright.config.mjs, playwright.a11y.config.mjs, playwright.firefox.config.mjs, playwright.real-chrome.config.mjs (full)
- [x] tests/browser/compat-capabilities.json (full) — P3: no code in the repo reads it
- [x] tests/browser/.gitignore, test-results/.last-run.json (full)
- [x] tests/browser/router.php (full; 1.9k lines) — fixture state store reviewed; clean (test-only)
- [x] tests/browser/migration/*.html (full, all 9) — fixtures; clean
- [x] tests/browser/specs/*.spec.mjs (targeted scan of all 18: skips/`.only`, TODO, swallowed catches, asserted endpoints vs router/i18n mocks, trivial assertions) — no provable defects recorded

## apps/ai

- [x] apps/ai/training/README.md (full) — P2 vs tracked artifacts
- [x] apps/ai/training/TRAINING_REPORT.md (full) — P1/P2 stale price canon + "production-viable" claim
- [x] apps/ai/training/common_paths.py, training_data.py (full)
- [x] apps/ai/training/config.yaml, config_planner.yaml (full)
- [x] apps/ai/training/pipeline.sh (full)
- [x] apps/ai/training/upload.sh (full) — P2 default `train_4gpu.py` does not exist
- [x] apps/ai/training/train.py (full)
- [x] apps/ai/training/train_mps.py (full) — P3 bare `except: pass` silently drops malformed examples
- [x] apps/ai/training/validate_pricing.py (full) — P1 canonical table contradicts billing-service
- [x] apps/ai/training/validate_data_prices.py (full) — P1 same
- [x] apps/ai/training/evaluate.py (targeted) — P1 same canon at line 36
- [x] apps/ai/training/test_agent.py (targeted) — P1 stale canon in SYSTEM_PROMPT/tests; P2 impossible test case (requires and forbids €25)
- [x] apps/ai/training/stress_test.py, stress_test_agent.py, stress_test_recovered.py, test_aggressively.py, test_fixes.py, test_1000_adversarial.py, run_test_agent.py, run_stress_r15.py (targeted — same stale canon in expectations)
- [x] apps/ai/training/prompts_v2.py (targeted) — P1 stale price table
- [x] apps/ai/training/augment_training_data.py, generate_dataset.py, generate_gap_training.py, generate_recovered_training.py, extract_all_recovered.py, extract_full_recovered.py, integrate_recovered.py, merge_and_export.py, new_customer_profiles.py, sweep_currency_to_eur.py, verify_all_angles.py, validate_pipeline.py, validate_training_data.py, evaluate_granular.py (targeted; syntax-checked with `python3 -m py_compile` — all parse)
- [x] apps/ai/training/data/*.jsonl (all 12 spot-checked: schema + price tokens; stale plan prices present)
- [x] apps/ai/training/data/augmented_* (headers sampled; see above)
- [x] apps/ai/training/merged_*/, output_*_mps/ config+tokenizer JSON (targeted; metadata read; model binaries — `adapter_model.safetensors`, `optimizer.pt`, `rng_state.pth`, `scheduler.pt`, `training_args.bin`, `tokenizer.json` — are opaque binary/generated artifacts, not reviewable text; reproducibility evidence is the tracked trainer_state.json)
