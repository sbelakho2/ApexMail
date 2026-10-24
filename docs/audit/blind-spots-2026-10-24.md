# ARK migration — verification record and remaining boundary (2026-10-24)

This document states exactly what the ARK v5 application has been proven to
do by execution, and — with equal precision — what remains unproven. Every
number below comes from a run on this tree, not from a plan.

## 1. Proven by execution

### 1.1 Compiled design law (source-side gates, all required)

| gate | result |
|---|---|
| `tools/check_ark_law.py` — every class in every renderer is `apex-*` or structural; banned legacy patterns, colour utilities, typography utilities, middots | 0 violations |
| `tools/check_ark_mirror.py` — the marketing copy of `ark.css` is byte-identical to the authority | byte-identical (63,046 bytes) |
| cssgen `--check` for both artifacts (console `globals.css`, marketing `styles.css`) | up to date |
| `tools/check_asset_budget.py` — served CSS/font payload ceilings, and zero `.js`/`.mjs` in the served marketing/console asset trees | 0 violations (self-test proves both arms can fail) |
| `check_no_stubs`, `check_invariants`, `check_waivers`, `check_capability_claims`, `check_claim_expiry` | pass |
| `check_ui_a11y`, `check_ui_links`, `check_ui_form_hygiene`, `check_ui_terminology` | pass |
| `check_marketing_contrast` (+ self-test), `check_marketing_serving`, `check_docs_architecture_truth` | pass |
| `validate_pricing_drift`, `broken-links`, `content-voice-check`, `html-validate`, `seo-validate` | pass |
| `ui-foundation` test suite | 578/578, 0 skipped |
| `cargo clippy -p ui-foundation -p api-server --all-targets` | 0 warnings |

### 1.2 The all-Rust build

`tailwind.config.js` (both copies) and the vendored Tailwind binary are
deleted; no Node in the build path. `crates/ui-foundation/src/bin/cssgen.rs`
(std only) emits both stylesheets from the authored authority plus a
structural utility whitelist, and `--check` fails on drift. The marketing
site ships zero client scripts (the budget gate enforces that at the served
tree, not just in templates).

### 1.3 The rendered surface (pixel walk, every pass)

`tools/ark_pixel_dogfood.py` walks **every** rendered document:

* 154 console/control-plane/auth/recipient/error fixtures,
* 203 built marketing documents (all locales, docs, legal, comparisons),

each at **1440 light**, **1440 dark (`.dark` class)**, **1440 dark
(`prefers-color-scheme`, no class)**, **1440 print**, and **390 mobile**.
Per document, from computed styles:

* body text resolves to Overpass, `h1` to Spectral, machine data to Overpass Mono;
* `border-radius` is `0` on every rendered element;
* `box-shadow` and `backdrop-filter` are `none` on every element;
* `background-image` is `none` except the engraved repeating line on
  evidence/hatch surfaces;
* no banned hue (indigo/purple/green families) in any fill;
* every text node clears WCAG AA (4.5 / 3.0 large) against its own nearest
  opaque ground, in every phase;
* **placeholders** clear AA against their control's ground (new arm — it found
  and fixed the 4.28:1 marketing placeholders);
* every **floating surface** (`fixed`/`sticky`) that carries text paints an
  opaque ground (new arm — it found the transparent 390px cookie banner);
* no **scroll trap**: any overflow-scrolling element is focusable or contains
  a focusable element (new arm — it found the nested table/code scroll
  regions, now removed);
* structural a11y: `html[lang]`, exactly one `h1`, a `main` landmark, no
  heading-level skips, every `img` has `alt`, no duplicate ids, no positive
  `tabindex`, every control/button/link has an accessible name;
* the stylesheet ships the `:focus-visible { 3px double }` law and the
  wordmark keeps its fixed tones (185 28 28 / 9 9 11 light; 196 80 70 /
  237 241 244 dark);
* at 390px no document scrolls horizontally;
* under `prefers-reduced-motion: reduce` every transition and animation
  resolves to at most 0.01 ms.

Result: see `tools/contrast-audit/reports/ark-pixel/report.json`
(`pages_checked`, `screenshots`, `violations_total: 0`).

### 1.4 Documents that cannot load `ark.css`

* **Transactional email + branded invitation + invoice** are rendered by the
  product code (`render_transactional_email[_with_branding]`,
  `render_invoice_html`) into `services/mail-server/target/ark-email-preview/`
  and inspected in Chromium by `tools/ark_email_dogfood.py` at 1440 and
  390, light and dark-preferring: square corners, ARK faces declared, paper
  and ink pinned under `prefers-color-scheme: dark`, AA contrast, no banned
  hues, no overflow — 0 violations.
  The same pass found and fixed two real defects: footer links at 2.85:1
  (`#999`), and a white-label email that still carried the ApexMail wordmark.
* **Invoice PDF** (typst): `pdffonts` reports the embedded subsets —
  `Overpass-Bold`, `Overpass-Regular` (and Noto Sans SC for CJK fallback),
  all `emb yes / sub yes`. The renderer's unit suite asserts the same fact
  from the PDF bytes.
* **Recipient pages served by tracking-service** (unsubscribe confirmation,
  preferences centre, success, error, refused click/domain) are ARK
  documents now: paper/ink, Spectral/Overpass/Mono, 3px rule, dark media
  block, destructive action as a rule + word rather than a red fill. The
  live recipient journey renders them with real tokens.

### 1.5 The live HTTP stack (journeys)

Against a native stack (api-server on 8080 + tracking-service on 3001 + PG17
+ Redis + the seeded rich tenant):

| sweep | result |
|---|---|
| `journey-wide.mjs` — every console route × 5 roles × themes × viewports | 0 findings |
| `journey-deep.mjs` — both consoles + visual probes (contrast, clipping, focus walk, tap targets, duplicate ids, unlabeled controls, broken images) | 0 findings |
| `cp-mfa-full.mjs` — operator enrolment + step-up + every CP route | 0 errors, all CP routes walked |
| `journey-recipient.mjs` — real tracking tokens: pixel, click redirect, unsubscribe GET/POST, preferences, malformed tokens | 0 findings |

The axe-core checks in the wide/deep sweeps found one real defect — the
nested table scroll region without keyboard access — fixed in `ark.css`
(wrapped ledgers scroll in their named, focusable region only).

### 1.6 The api-server suite

`cargo nextest run -p api-server` on PostgreSQL 17: 2,270 tests. The only
non-pass in the full parallel run was one test killed by the OS (SIGKILL
under load); it passes in isolation. No assertion failures.

### 1.7 The nginx-served marketing site

`tools/check_marketing_nginx.py` runs the committed `nginx.conf` under the
real nginx binary against the built site: 200s, HTML/CSS/woff2 content
types, CSP/HSTS/nosniff present on HTML **and** assets, immutable cache tier,
gzip, the consent-cookie banner flip through the `sub_filter` hop, the
branded 404, and `/js/*` 404 — 0 violations. This check found a real
production defect: every per-location `add_header Cache-Control` dropped all
six server-level security headers on the responses that mattered (all HTML
and all assets). The cache tiers now come from maps declared at server
level.

## 2. What remains unproven (honest boundary)

Severity: P1 = could hide a user-visible defect on a primary surface;
P2 = real but narrower; P3 = known, accepted.

### P2 — real mail clients

Gmail, Outlook (Word engine), Apple Mail and client dark-mode inversion are
not available here. The documents declare `color-scheme: light only` and use
inline styles only, which is the strongest portable position, but a client
that rewrites colours can still alter the result. Verifying in those clients
requires accounts on those platforms.

### P2 — the KiwiCaptcha widget's own visuals and a11y

The widget is vendored from the KiwiCaptcha repository (owner directive: its
surfaces are never edited here). Its runtime classes resolve to ARK tokens,
but its internal layout, challenge UI and hidden token inputs belong to that
project's accessibility and design; the console's axe pass treats them as
third-party.

### P2 — screen-reader behaviour and marketing axe coverage

The walk's accessibility arm is structural (computed names, landmarks,
heading order, labels, ids); the live sweeps run axe-core against the
console routes. Marketing pages are not axe-scanned (no Node in the build
path; Playwright Python has no axe runner installed). Real screen-reader
walkthroughs (VoiceOver/NVDA) were not performed.

### P2 — visual taste

The walk proves the rules hold on every page; it cannot judge composition.
The human review of this campaign covered the console dashboard, campaigns,
assistant, control-plane alerts/dashboard, auth, pricing (desktop + 390),
docs/API reference, the recipient pages, the three email documents and the
invoice — a broad sample, not every one of the 1,400+ screenshots.

### P3 — smaller known gaps

* The auth-server status page, the sales-autopilot unsubscribe pages and the
  template-renderer starter template were re-homed to ARK and are covered by
  unit tests that assert the law; they are not browser-rendered in this
  campaign (the services are not part of the journey stack).
* Native-speaker review of de/fr/es copy remains out of scope; the locale
  pages pass structure, contrast, overflow and a11y.
* Performance budgets now cover shipped bytes (CSS/fonts/zero-JS). No
  LCP/CLS/INP measurement was made against a network profile.
* POST-outcome pages are represented by fixtures for representative states
  (success/failure/error), not one document per possible outcome.
* Receipt public-key verification answers 503 in the local deployment
  because no receipt signing keypair is configured; that is an operator
  secret, not a code path (production requires it).

## 3. How to reproduce

```sh
# 1. gates
python3 tools/check_ark_law.py && python3 tools/check_ark_mirror.py
python3 tools/check_asset_budget.py && python3 tools/check_asset_budget.py --self-test
cd services/mail-server
cargo run -p ui-foundation --bin cssgen -- --ark crates/ui-foundation/assets/ark.css \
  --include crates/ui-foundation/assets/globals.input.css \
  --content "crates/ui-foundation/src/**/*.rs" --content "crates/api-server/src/**/*.rs" \
  --content crates/ui-foundation/assets/globals.input.css \
  --out crates/ui-foundation/assets/globals.css --check
cargo nextest run -p ui-foundation

# 2. rebuild everything the walk reads
zola --root apps/marketing-zola build
cd services/mail-server
MARKETING_PUBLIC_DIR=$PWD/../../apps/marketing-zola/public \
  APEX_EXPORT_ALL_UI_ROUTES=1 cargo run -p ui-foundation \
  --bin export_visual_fixtures -- ../../tools/contrast-audit/fixtures

# 3. the walks
python3 tools/ark_pixel_dogfood.py      # every page, five passes
python3 tools/ark_email_dogfood.py      # email/invoice documents
python3 tools/check_marketing_nginx.py  # the nginx serving path (needs nginx)

# 4. the live stack + journeys (see docs on the native stack: PG17, Redis,
#    api-server :8080, tracking-service :3001, the rich-tenant seed)
cd tests/browser
node journey-wide.mjs --out /tmp/journey-wide
node journey-deep.mjs --out /tmp/journey-deep
node cp-mfa-full.mjs
TRACKING_SECRET_KEY=... node journey-recipient.mjs --out /tmp/journey-recipient
```
