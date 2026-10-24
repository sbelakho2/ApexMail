# ARK migration — verification coverage and blind spots (2026-10-24)

This document states exactly what the ARK v5 application has been proven to
do, and — with equal precision — what it has **not** been proven to do. It is
the honest boundary of the evidence produced by the campaign that ended at
`ba4e38ed`.

## 1. What is proven

### 1.1 Compiled design law (source-side gates, all required)

| gate | result |
|---|---|
| `tools/check_ark_law.py` — every class in every renderer is `apex-*` or structural; banned legacy patterns, colour utilities, typography utilities, middots | 0 violations |
| `tools/check_ark_mirror.py` — the marketing copy of `ark.css` is byte-identical to the authority | byte-identical |
| cssgen `--check` for both artifacts (console `globals.css`, marketing `styles.css`) | up to date |
| `check_no_stubs`, `check_invariants`, `check_waivers`, `check_capability_claims`, `check_claim_expiry` | pass |
| `check_a11y`, `check_ui_links`, `check_ui_form_hygiene`, `check_ui_terminology` | pass |
| `check_marketing_contrast` (+ self-test), `check_marketing_serving`, `check_docs_architecture_truth` | pass |
| `check_flash_copy`, `check_processor_facts`, `check_prod_billing_wiring`, `check_security_posture`, `check_web_error_honesty`, `check_audit_coverage`, `check_knowledge_consistency`, `check_feature_entitlements`, `check_cargo_cycles`, `check_eval_corpora`, `check_rust_panic_paths`, `check_outbound_delivery_contract`, `check_topology_contracts` | pass |
| `validate_pricing_drift`, `broken-links`, `content-voice-check`, `html-validate`, `seo-validate` | pass |
| `ui-foundation` test suite | 578/578, 0 skipped |
| `cargo clippy -p ui-foundation -p api-server --all-targets` | 0 warnings |

### 1.2 The all-Rust build

Toil removed: `tailwind.config.js` (both) and the vendored Tailwind binary are
deleted. `crates/ui-foundation/src/bin/cssgen.rs` (std only) emits both
stylesheets from the authored authority plus a structural utility whitelist.
A repo test fails if Tailwind returns to the path. The marketing stylesheet no
longer has a separate token source: `static/css/ark.css` is the authority's
twin, `input.css` is gone, and the only marketing-only CSS files left are
`no-js.css` (behavioural rules, token-styled) and `giallo.css` (syntax palette,
ARK tokens).

### 1.3 The rendered surface (pixel walk)

`tools/ark_pixel_dogfood.py` walks **every** rendered document:

* 154 console/control-plane/auth/recipient/error fixtures (the union of the
  `ui-baseline-manifest` routes plus auth and state variants),
* 203 built marketing documents (all locales, docs, legal, comparisons),

each at **1440 light**, **1440 dark (`.dark`)** and **390 mobile**:
1,071 screenshots, and asserts, per document, from computed styles:

* body text resolves to Overpass, `h1` to Spectral, machine data to Overpass Mono;
  the self-hosted fonts load;
* `border-radius` is `0` on every rendered element;
* `box-shadow` and `backdrop-filter` are `none` on every element;
* `background-image` is `none` everywhere except the engraved repeating line
  on evidence/hatch surfaces;
* no banned hue (indigo/purple/green families) appears in any fill;
* every text node clears WCAG AA (4.5 normal / 3.0 large) against its own
  nearest opaque ground, in both themes;
* the stylesheet ships the `:focus-visible { 3px double }` law and the
  wordmark keeps its fixed tones (185 28 28 / 9 9 11 light; 196 80 70 /
  237 241 244 dark);
* at 390px no document scrolls horizontally.

**Result: 0 violations across 357 pages, 1,071 screenshots.**

## 2. Blind spots — what the evidence does NOT cover

Severity: P1 = could hide a user-visible defect on a primary surface;
P2 = real but narrower; P3 = known, accepted for now.

### P1 — the live HTTP stack is not exercised by the pixel walk

The walk renders through the same production renderers with the same compiled
stylesheet, but it does not traverse cookies, CSRF, sessions, RBAC, MFA,
rate limiting or redirects. Those are covered by the api-server suite:
**2,262 / 2,270 pass**. The 8 failures are:
* 5 rate-limiter adversarial tests (Redis window/clock dependent), and
* 1 admin-session authority test, which fails because the local DB has no
  seeded state,
and all 6 remaining reproduce **identically on the pre-campaign commit**
(`95986139`), i.e. they are environment-blocked, not ARK regressions. (Two
further failures were UI regressions and are fixed.)

Action: start the declared Postgres/Redis containers (colima images are
currently missing after the re-provision) and run the suite with
`MARKETING_PUBLIC_DIR` set; then run the live journey harness end to end.

### P1 — email clients and PDFs are styled but not rendered

`render_transactional_email_with_branding` and the invoice document were
restyled to ARK (wordmark, 3px rule, ink primary actions, comma footers), and
the invoice carries its own embedded copy of the vocabulary. But:
* no real mail client has rendered them (Gmail clamp, Outlook word-engine,
  client dark-mode inversion, image blocking);
* `pdf-renderer` (typst) may not embed Spectral/Overpass — the PDF surface was
  not re-checked at all.

Action: render both templates in Gmail/Outlook web + a dark-mode client, and
render one invoice PDF; assert the embedded font families.

### P2 — the KiwiCaptcha widget's own visuals

The widget's runtime classes (`bg-brand-*`, `text-success-*`, `font-mono`,
`tabular-nums`) now resolve to ARK tokens, so the widget adopts the palette.
Its internal layout, thumbnails and animation remain the package's design and
were not visually audited (and must not be redesigned here — separate repo).

### P2 — the media-query dark path is proven by tokens, not by rendering

The walk toggles the `.dark` class. The `prefers-color-scheme` twin is proven
equal by `tokens.rs` (block parity test) and by `check_marketing_contrast`
(both blocks, both sheets), but no browser session was rendered with
`colorScheme: dark` and no `.dark` class. The product path for the zero-JS
console is precisely that media query.

Action: add a fourth walk pass with `color_scheme="dark"` and no class.

### P2 — accessibility is static, not experiential

The gates check one `h1`, landmarks, labels, form hygiene and the focus law.
Not covered: a full keyboard traversal (tab order, focus traps that do not
exist by design but could be re-introduced by markup), the accessibility tree
(axe-core), screen-reader semantics for the ledger/status components, and
colour-blind safety beyond AA ratios.

### P2 — visual taste is not machine-checkable

The walk proves the *rules* hold on every page; it cannot judge composition.
1071 screenshots are committed-ready for review; the human review during the
campaign covered the dashboard, campaigns list and the auth/pricing/marketing
families at a spot level only.

### P3 — smaller known gaps

* `@media print` styling exists in the authority but no printed page was
  produced and checked (invoices are the likely first consumer).
* Motion: the 130ms control transitions were measured frozen; `prefers-
  reduced-motion` was not exercised in the browser (the rule exists).
* Locale quality: de/fr/es were verified for structure (h1, contrast, no
  overflow) and the copy register was reviewed by the content lane; native-
  speaker review is out of scope.
* The standalone nginx-served marketing site (headers, CSP, cache-busting)
  differs from the api-server's embedded copy the walk serves; nginx-only
  behaviours (redirects, `_headers`, gzip/brotli) were not exercised.
* POST-result pages (flash success/failure families) are covered by fixtures
  for representative states only; not every POST outcome has a pixel-checked
  document.
* Performance budgets: CSS is ~82 KB uncompressed; no LCP/CLS budget gate was
  measured.

## 3. How to reproduce the evidence

```sh
# 1. gates
python3 tools/check_ark_law.py && python3 tools/check_ark_mirror.py
cd services/mail-server
cargo run -p ui-foundation --bin cssgen -- --ark crates/ui-foundation/assets/ark.css \
  --include crates/ui-foundation/assets/globals.input.css \
  --content crates/ui-foundation/src --content crates/api-server/src \
  --include crates/ui-foundation/assets/globals.input.css \
  --out crates/ui-foundation/assets/globals.css --check
cargo nextest run -p ui-foundation

# 2. rebuild everything the walk reads
zola --root apps/marketing-zola build
MARKETING_PUBLIC_DIR=$PWD/../../apps/marketing-zola/public \
  APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation \
  --bin export_visual_fixtures -- ../../tools/contrast-audit/fixtures

# 3. the walk (writes tools/contrast-audit/reports/ark-pixel/)
python3 tools/ark_pixel_dogfood.py
```
