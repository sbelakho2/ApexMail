# Lane R3 — marketing build (templates / styles / data / config / assets)

Scope: everything under `apps/marketing-zola/` except `content/**` and `i18n.json` (R4), plus
`tools/check_marketing_serving.py` and the marketing-serving arms of
`services/mail-server/crates/api-server/src/app.rs` (the brief's "fix the handler/nginx side if broken").
Constraint honoured: **no KiwiCaptcha asset/mirror was touched** (no file under
`packages/kiwicaptcha`, no mirrored widget asset under any `resources`/`public` tree was opened for
edit; `check-kiwi-marketing-isolation.sh` remains the authority for that boundary).
No `git commit` was made. Recon-first: `review.md` §1/§3/§4.13-4.15/§8.1-8.9/§9 and `register.md`
were read before any edit.

Deliverable sections: §1 gate results, §2 serving adjudications, §3 verdict table (all 71
templates), §4 verdict table (§9 + P2-2/P2-3/§4.13-4.15), §5 zero-skips appendix, §6 other-lane
handoffs, §7 orchestrator paragraph.

---

## 1. Gates run (all with literal commands)

| Gate | Command | Result |
|---|---|---|
| zola build | `zola --root apps/marketing-zola build` | `Creating 151 pages (0 orphan) and 25 sections` — green after every edit batch |
| tailwind CSS | `…/tailwindcss -c apps/marketing-zola/tailwind.config.js -i apps/marketing-zola/static/css/input.css -o apps/marketing-zola/static/css/styles.css --minify` (v3.4.17, the Dockerfile-pinned version) | green; artifact regenerated |
| marketing serving (extended) | `python3 tools/check_marketing_serving.py` | `checked 177 built pages … marketing serving gate passed` (RC 0) |
| serving self-test | `python3 tools/check_marketing_serving.py --self-test` | `self-test: all nine checks can fail (mutants caught)` (RC 0) |
| pricing drift (R5-owned) | `python3 tools/validate_pricing_drift.py` | `pricing drift validation passed` (RC 0) |
| marketing token contrast | `python3 tools/check_marketing_contrast.py` | `all pairs pass in both sheets and themes` (RC 0) |
| compare pricing parity | `python3 tools/check-compare-pricing-parity.py` | `compare pages checked: 5 (15 locale variants) … OK` (RC 0) |
| capability claims | `python3 tools/check_capability_claims.py` | `all green (2 in-flight warning(s))` (RC 0) |
| layout gate (marketing + console) | `sh tools/contrast-audit/layout-gate.sh` | **`Done: 0 layout findings across 1181 runs`, LAYOUT_RC=0** (after fixing an overlap my first nav draft introduced — see §5.9) |
| contrast gate | `sh tools/contrast-audit/gate.sh` | **`[gate] PASS — AA failures: 0 across 0 runs (112 pages, 317 runs, 195.0s)`**, CONTRAST_RC=0 — after fixing the 3 failures it caught in my own work (§5.10) |
| ui links / terminology / form hygiene | `python3 tools/check_ui_links.py` / `check_ui_terminology.py` / `check_ui_form_hygiene.py` | terminology + form hygiene green (`all green`, `175 POST forms … all green`); **ui links flags one stale generated fixture** (`dead-fragment marketing[-zola]/pricing → #plans` inside `baselines/rust-ui/marketing*-pricing.html` written at 23:28:43, before the anchor fix landed in the built page at 23:30:41 — the built source has BOTH `href=#plans` and `id=plans`; a fixture re-export clears it, §6.2) |
| ui a11y | `python3 tools/check_ui_a11y.py` | 1 failure in a **stale ui-foundation baseline fixture** (not an R3 file) — §6.2 |
| i18n audit | `python3 tools/i18n-audit.py` | 127 findings: 126 = the 42 new catalog keys I reference × 3 locales (R4 must add them), 1 pre-existing empty `de.compliance.cta_subtitle` — §6.1 |
| api-server unit test | `cargo test --package api-server --lib static_asset_cache_control_tiers` | **blocked by R1's in-flight `routes/web.rs` E0603** (`function load_template_edit is private`) — §6.3 |

### 1.1 Contrast gate
`sh tools/contrast-audit/gate.sh` — classifier self-test `12/12 PASS`; fixture + curated marketing
audit: **`[gate] PASS — AA failures: 0 across 0 runs (112 pages, 317 runs, 195.0s)`** (RC 0).
The gate *first* caught three AA failures in my own new markup, which were fixed before the passing
run (literal evidence in §5.10).

---

## 2. Serving adjudications (review §1 "observed serving problem" + §9 nginx/Dockerfile)

### 2.1 The observed defect: versioned stylesheet 404 vs bare 200
**Reproduced the defect class, then proved both serving paths correct now.**

*Live api-server (port 3999, `Host: marketing.localhost`), before my change:*
```
$ curl -s -o /dev/null -w "%{http_code}\n" -H 'Host: marketing.localhost' http://127.0.0.1:3999/css/styles.css
404
$ curl -s -o /dev/null -w "%{http_code}\n" -H 'Host: marketing.localhost' "http://127.0.0.1:3999/css/styles.css?h=a8b5e22bcb876a4f8b64"
404
$ … /giallo.css /fonts/InterVariable.woff2 /icon.svg /manifest.json /pgp-key.txt …
404 (every asset path)
```
Root cause (evidence): the running dev binary is stale relative to the tree —
`target/debug/api-server` mtime `2026-10-08 19:20:11`, `app.rs` mtime `2026-10-08 20:06:46`,
`axum_router.rs` mtime `20:56:27`. The current source *does* route `/css` (`nest_service("/css",
ServeDir::new(...))`), and the page-level probes return 200 because built pages are baked in.

*Current tree, handler level:* the extended gate now proves the asset router matches on the **path,
never the query string** (`ServeDir`/`ServeFile`, no `?h=` in any registration) and that **every
root-relative asset referenced by built pages resolves** — which caught two real 404s the review's
defect class covers:
```
$ python3 tools/check_marketing_serving.py   (before the app.rs fix)
  - root-relative assets referenced by built pages have no api-server route (they 404 on the
    marketing host): ['/giallo.css', '/specs/openapi.yaml']
```
`/giallo.css` is loaded by the 14 code-heavy docs/quickstart/architecture pages; `/specs/openapi.yaml`
is the downloadable contract linked from `/docs/api/openapi/`. **FIXED-NOW** in
`crates/api-server/src/app.rs` (`route_service("/giallo.css", ServeFile…)`, `nest_service("/specs",
ServeDir…)`, plus the immutable cache tier and a route test for both). Verified by the gate after the
fix and by the new mutation proof (`/giallo.css` route removed → gate fails).

*Container path, real nginx from the shipped config* (`apps/marketing-zola/nginx.conf`, port-shifted to
18080/18081/18082 against the rebuilt `public/`):
```
$ curl -s -o /dev/null -w "%{http_code} %{content_type} cache=%header{cache-control}\n" \
    "http://127.0.0.1:18080/css/styles.css?h=922cfa1def6dad22792b"
200 text/css cache=public, max-age=31536000, immutable
$ … "/css/styles.css" (bare)
200 text/css cache=public, max-age=31536000, immutable
$ … "/css/styles.css?h=deadbeef" (wrong hash — query must be ignored)
200 text/css cache=public, max-age=31536000, immutable
$ … "/giallo.css?h=abc"       → 200 text/css  immutable
$ … "/fonts/InterVariable.woff2?h=abc" → 200 font/woff2 immutable
$ … "/icon.svg"               → 200 image/svg+xml cache=public, max-age=3600   (Rust-tier parity)
$ … "/manifest.json|robots.txt|sitemap.xml|pgp-key.asc|.well-known/security.txt"
                                 200 … cache=public, max-age=3600             (Rust-tier parity)
$ … "/specs/openapi.yaml"     → 200 application/yaml cache=no-cache
$ … "/nonexistent-page/"      → 404 text/html cache=no-store  <title>Page Not Found | ApexMail</title>
$ … "/forensic/" and "/de/forensic/" → 301
$ curl -s http://127.0.0.1:18080/health → OK
```
Consent substitution (the no-JS server-side flip) verified live on the same server:
```
$ curl -s http://127.0.0.1:18080/ | grep -o 'data-consent-state=[a-z"]*' | head -1
data-consent-state=pending
$ curl -s -H 'Cookie: apexmail_consent=necessary' http://127.0.0.1:18080/ | grep -o 'data-consent-state=[a-z"]*' | head -1
data-consent-state=recorded
```
Cache-tier equivalence was *fixed*, not just verified: the nginx vhost gave `/manifest.json`,
`/robots.txt`, `/sitemap.xml`, `/.well-known/security.txt` and `/pgp-key.asc` **no-store** or 86400
while the api-server's `static_asset_cache_control` tier is 3600; `/icon.svg` was immutable in nginx
and 3600 in Rust. Exact-match locations now mirror the Rust tiers (probe above), and
`static/_headers` carries the same table.

### 2.2 Gate extensions (brief requirement)
`tools/check_marketing_serving.py` gained three checks + four mutations:
1. `check_versioned_asset_references` — every `?h=`/bare asset URL in the 177 built pages must have a
   file in the export (mutation: move `css/styles.css` → caught).
2. `check_asset_router_is_query_agnostic` (+ the referenced-root-asset routing check) — mutation:
   register `/css/styles.css?h=deadbeef` → caught; remove the `/giallo.css` arm → caught.
3. `check_pricing_display_strings` — `pricing.json` display strings must equal their numeric fields,
   annual must mean ten monthly payments, retention and the one-time launch allowance must be
   explicit (mutations: contradicted Free volume → caught; wrong annual → caught).

---

## 3. Verdict table — all 71 templates (review §8)

Legend: **FIXED-NOW** = fail-before evidence in §5 + fix + fail-after/probe; **FIXED-ALREADY** =
current tree already satisfied the finding (evidence in §5); **DORMANT** = explicitly snapshotted
(no live include; grep evidence in §5.3); **RETIRED** = file removed.

### §8.1 Page and layout templates (18)
| File | Verdict | What changed / evidence |
|---|---|---|
| `base.html` | FIXED-NOW | Removed the offscreen `#nav-toggle` checkbox (the offscreen tab stop) — the mobile menu is now a native `<details>` summary. Single robots authority (`{% block robots %}`, reads page **and** section front matter); `giallo.css` loads only on the 14 pages that contain `<pre class="giallo z-code">` (FIXED-NOW: 178 pages → 14). |
| `home.html` | FIXED-NOW | Pricing teaser fully derived from `data/pricing.json` (free/pro/business by pinned plan order); "most verified" removed (replaced by the plans page's defined recommendation label); teaser unit labels localized. |
| `page.html` | FIXED-NOW | One-heading/prose/empty-content contract + explicit `extra.raw_layout` opt-out (template is dormant — zero `template = "page.html"` content pages, §5.3). |
| `section.html` | FIXED-NOW | Section identity h1 when the authored body has none, subsection index, and an empty-index state with real destinations. Rendered check: `/compare/ /contact/ /solutions/` each 1 `<h1>`. |
| `docs-section.html` | FIXED-NOW | First-send onboarding card leads the hub; guides section lists pages **and** subsections; a no-guides state with API/quickstart/support destinations. |
| `prose.html` | FIXED-NOW | Localized "Last updated" label + machine-readable `<time datetime>`; stable section navigation from `page.toc` (heading-anchor links); narrow width kept (`max-w-3xl`). |
| `prose-section.html` | FIXED-NOW | Same localized/machine-readable date; "Related" localized. |
| `macros.html` | FIXED-NOW | `winner_badge(winner, competitor_name, tie_label, unavailable_label)` — labels are caller-provided (Tera macros cannot read globals; contract documented) and the unavailable em dash is `role="img"` + `aria-label` instead of a bare dash. |
| `pricing.html` | FIXED-NOW | Plans/calculator/FAQ anchors (`#plans`, `#apexmail-calculator`, `#pricing-faq`) with `scroll-mt-20`; jump strip; server-submitted estimation explained; stale "Interactive pricing calculator with JS" comment removed. |
| `calculator.html` | FIXED-NOW | Stale JS expectation removed; comment states the form POSTs to the Rust estimator and the estimate renders on the response page. |
| `compare.html` | FIXED-NOW | Concise comparison → methodology → decision-guide path (`#comparison`, `/compare/methodology/`, `#decision-guide`). |
| `compliance.html` | FIXED-NOW | The showcase is labelled illustrative in the template contract and visibly in the island (badge + per-table qualification). |
| `features.html` | FIXED-NOW | Category jump nav (six anchors) before the 38-card inventory; ids added in `features/grid.html`. Overlap with the hero fixed after the layout gate flagged it (0 findings after). |
| `private-cloud.html` | FIXED-NOW | Anchors + jump nav to deployment models / isolation / dedicated IPs / architecture review. |
| `email-logs.html` | FIXED-NOW | Diagnostic-specific description + og/twitter title/description blocks (page previously inherited generic social metadata). |
| `api-explorer.html` | FIXED-NOW | Workbench island bounded to the hero's `max-w-7xl px-4 sm:px-6 lg:px-8` gutters; dark technical surface preserved. |
| `status.html` | FIXED-NOW | Truthful static handoff with one clear live action; repeated amber warning panels collapsed to one neutral panel (see status partials). |
| `404.html` | FIXED-NOW | noindex centralized in base.html's robots block (single robots meta); title/description localized with the same i18n lookups as the actions; recovery destinations preserved. |

### §8.2 Shared chrome (5)
| File | Verdict | What changed / evidence |
|---|---|---|
| `header.html` | FIXED-NOW | Native `<details>` mobile disclosure: summary is the visible, focusable control; panel is a child (closed state genuinely hidden — Chromium probe: `display:none`, h=0) and absolutely positioned against the sticky header when open (h=736px). **Escape promises removed** from the header/CSS comments after a Chromium probe showed Esc does **not** close `<details>` (`openAfterEsc: true`). |
| `footer.html` | FIXED-NOW | Brand column `md:col-span-3` removed (it created an implicit third track in the 2-track sm/md grid). |
| `brand-lockup.html` | FIXED-NOW | `overflow="visible"` + `preserveAspectRatio` so a fallback face or enlarged text cannot clip the wordmark. |
| `cookie-consent.html` | FIXED-NOW | Equivalent necessary-only choices collapse to ONE action (config's necessary+dismiss both record necessary-only; probe shows `["necessary","all"]`), locale policy link kept, body gets reserved space while pending (`padding-bottom: 88px` at 390px). |
| `analytics.html` | FIXED-NOW | Comment-only partial now documents collector ownership (platform access-log pipeline), policy authority (`/cookies/`, consent banner) and the `analytics_enabled`/CSP reality — no collection implied. |

### §8.3 Home partials (5)
| File | Verdict | What changed / evidence |
|---|---|---|
| `hero.html` | FIXED-NOW | Trace labelled "Example trace"; shown payload aligned with the submitted sandbox body (no `from`, real to/subject/html); "accepted by recipient MX" replaced (reserved-recipient execution never proves recipient-MX delivery). |
| `features.html` | FIXED-NOW | Balanced 4-item arrangement (`sm:grid-cols-2 lg:grid-cols-4`), heading gap tightened `mb-24 → mb-12`. |
| `cta.html` | FIXED-NOW | "Book Architecture Review" now leads to the enquiry path (`/contact/sales/?type=private-cloud`). |
| `comparison.html` | DORMANT | Zero includes (grep §5.3). Snapshotted with a dormancy banner; superiority adjectives (`Deterministic`, `Basic`, `Limited`, `Partial`, `Isolated`, unsourced 30/45-day audit numbers) replaced with descriptive/plan-scoped wording and `Not directly comparable` where unverifiable — before any reuse. |
| `security.html` | DORMANT | Zero includes. HIPAA row no longer carries an Active badge: neutral "Not offered" chip, green success dot removed; dormancy banner added. |

### §8.4 Pricing and calculator partials (9)
| File | Verdict | What changed / evidence |
|---|---|---|
| `pricing/hero.html` | FIXED-NOW | Eyebrow/headline/subtitle localized (i18n keys with English fallbacks); red display emphasis kept. |
| `pricing/plans.html` | FIXED-NOW | Volumes, domains, users, IP counts, retention and the launch allowance are **derived from `data/pricing.json`**; `plan_name`/`plan_price`/signup URLs remain the exact strings `validate_pricing_drift.py` pins (documented in-file) — gate green, rendered cards show derived `3,000/50,000/150,000/500,000/2,000,000`, `7/30/60/90-day retention`, "One-time 30,000-email launch allowance (first 30 days)". |
| `pricing/card.html` | FIXED-NOW | Accessible names take localized `plan`/`per month` labels; recommendation badge wraps inside the crown (`max-w-[calc(100%-1.5rem)]`, centred, `leading-tight`). |
| `pricing/calculator.html` | FIXED-NOW | **P2-2**: one authoritative control (number input = what the server reads); the leftover slider tick row ("0 2M … 10M") removed; `(priced factor)` vs `(context only)` labels added per the handler's actual inputs; next-page estimate explained; annual text now states the derived 16.7% saving while keeping the gate-pinned "10×" sentence. |
| `pricing/calculator-interactive.html` | FIXED-ALREADY + FIXED-NOW | Annual select already said "Annual (10 monthly payments)" and the de/fr/es catalog strings already say ≈16.7% saving (§5.6) — no 10%-off wording anywhere; the residual English helper is now localized. |
| `pricing/cta.html` | FIXED-NOW | Sales/help is now the primary action; calculator link is the **local** anchor `#apexmail-calculator`; Start free demoted to secondary. |
| `calculator/hero.html` | FIXED-NOW | States the calculator computes the ApexMail estimate from live plan tables and that competitor figures are static dated list rates, not live quotes. |
| `calculator/competitor-breakdown.html` | FIXED-NOW | Stale claims replaced with current catalog values: `€29/mo + €0.80 per 1,000` / Pro `€89` includes `150,000`; dedicated IPs `€49 first, €69 additional` + included `Growth 1 / Business 1 / Enterprise up to 3`; stale "Scale" support tier fixed; dated assumption line + link to the comparison methodology; prose cells wrap; icon-only cells carry `role="img"` labels (Included / Not included / Limited or paid add-on). |
| `calculator/cta.html` | FIXED-NOW | Free volume and setup fee derived from pricing.json ("5 SDKs in development" corrected to "Client libraries in development" + private-preview/not-published note linking `/docs/sdks/`, matching the SDK status page). |

### §8.5 Features and comparisons (7)
| File | Verdict | What changed / evidence |
|---|---|---|
| `features/hero.html` | FIXED-NOW | P95 ≤ 500ms is labelled an **SLA target (gateway)** and the link says "Target definition and methodology" (canonical.json's claim is a target, not a measurement). |
| `features/grid.html` | FIXED-NOW | 14 undefined bare `text-info` + 14 `bg-info/10` utilities replaced with mapped tokens (`text-info-700`, `bg-info-500/10`); category ids added; narrow-screen 2-up relaxed to `auto-fit minmax(220px,1fr)` with 12px descriptions. |
| `features/details.html` | FIXED-NOW | The tags example no longer claims consent/lawful-basis evidence ("message-level tags are routing/analytics labels … consent records live in the compliance workflow"), and the compliance workflow link is present. |
| `features/cta.html` | FIXED-NOW | Hand-rolled buttons replaced with shared `.btn-primary`/`.btn-secondary` variants (geometry, focus ring, sizing consistent). |
| `compare/hero.html` | FIXED-NOW | One neutral missing-competitor fallback (`this provider`) used everywhere; eyebrow/lead/CTAs localized. |
| `compare/table.html` | FIXED-NOW | Semantic `<table>` with `<caption>`, `<th scope="col">`, `<th scope="colgroup">` section headers and `<th scope="row">` feature cells; the horizontal scroll region is keyboard reachable (`role="region" tabindex="0"` + label); methodology/sources/review date moved **outside** the scroller. Rendered evidence: `/compare/postmark/` has `<table>`, `<caption>`, 22 `scope=row`, 1 `aria-current=page`. |
| `compare/cta.html` | FIXED-NOW | Decision guide carries `id="decision-guide"`; the alternatives strip lists the **complete** five-competitor set and marks the active comparison with `aria-current="page"`; decision copy localized. |

### §8.6 Compliance (4)
| File | Verdict | What changed / evidence |
|---|---|---|
| `compliance/hero.html` | FIXED-NOW | Panel heading hierarchy corrected (h1 → h2); pulsing "live" green dot animation removed from static review information. |
| `auto-dpa.html` | FIXED-NOW | Mock document visibly labelled "Illustrative preview — layout only"; legal/signature boundary note; actions stack on narrow screens. |
| `data-retention.html` | FIXED-NOW | Privacy link uses the stable language-independent anchor `#data-retention` (was `#5-data-retention`); category cells are `<th scope="row">`; retention descriptions wrap (global nowrap removed). |
| `compliance/cta.html` | FIXED-NOW | Enquiry scoped to `/contact/security/?topic=compliance-review`; action/qualification strings localized. |

### §8.7 Private deployment (5)
| File | Verdict | What changed / evidence |
|---|---|---|
| `private-cloud/hero.html` | FIXED-NOW | Architecture strip labelled illustrative, pulsing dot removed, fake `192.168.x.x/24` replaced with an RFC 5737 example range + caption; diagram service/subnet labels localized via `private_cloud.svc_*` keys with fallbacks. |
| `dedicated-ips.html` | FIXED-NOW | Metric named ("Reputation score · status" column header, "Average IP reputation score: 89.4% (illustrative)"); each meter is a labelled `role="progressbar"` bound to its IP and value (89.4 average left as-is — arithmetically correct). |
| `security-isolation.html` | FIXED-NOW | Shared-cloud SLA qualified to Business and Enterprise Cloud (no SLA below), private SLA scoped to contract; `<caption>`, `<th scope="col">` and 7 `<th scope="row">` cells. |
| `latency-comparison.html` | FIXED-NOW | Legend now matches the four bars one-to-one (dark/brand/surface-300/surface-200 with scenario names); "bar lengths are not measured proportional results" added; scenario tags/descriptions localized. |
| `private-cloud/cta.html` | FIXED-NOW | Steps are a semantic `<ol>`/`<li>` ordered process, stack at intermediate widths (`sm:grid-cols-2 lg:grid-cols-4`), timings explicitly indicative. |

### §8.8 Diagnostics and status (6)
| File | Verdict | What changed / evidence |
|---|---|---|
| `email-logs/hero.html` | FIXED-NOW | Secondary jump to the example timeline (`#message-timeline`) plus the event documentation link. |
| `email-logs/timeline.html` | FIXED-NOW | Card surfaces use the themed `bg-card` token (were `bg-white`, broken in dark mode); the section is labelled a worked example and the inert action strip is labelled "Illustrative actions (not active in this static trace)"; elapsed-time context corrected — request accepted 14:32:01.042 → MX accepted 14:37:03.019 is **5m 2s (301.98 s)**, not 1.98 s. |
| `email-logs/cta.html` | FIXED-NOW | "Try Live Demo" → "Run a request in the sandbox", and the copy distinguishes the static timeline from real sandbox execution. |
| `forensic/hero.html` | DORMANT | Zero includes. The inert `disabled` search input was retired (a dead control that looked interactive) and replaced with an example-trace statement; dormancy banner added. |
| `status/hero.html` | FIXED-NOW | The declared monitored-service list (8 services) is now rendered (it was set and never shown while the copy claimed it was); the two stacked amber warning panels collapsed into one neutral handoff to the live status host. |
| `status/subscribe.html` | FIXED-NOW | Renamed "Check service status" with copy that says the links do **not** subscribe; actions stack at narrow widths. |

### §8.9 Generated-named partials (10)
| File | Verdict | What changed / evidence |
|---|---|---|
| `api-explorer-island.html` | FIXED-NOW | Composer textareas get `aria-describedby` help (sandbox constraints,result-page navigation); the inspector is labelled "No request sent" and explains verbatim success/failure rendering; domain lane gets the same treatment. |
| `compliance-demo-island.html` | FIXED-NOW | The Processing Basis Ledger row with six cells under five headers fixed (stray `<td>` removed); the showcase is visibly qualified ("Illustrative sample — not account evidence or a generated review pack") and the questionnaire section states no standard pack is a product entitlement, matching the compliance hero. |
| `deployment-options-island.html` | FIXED-NOW | Radios wrapped in a `<fieldset>` with `<legend>Deployment models</legend>`; `.deploy-radio` is now visually hidden but focusable (Chromium probe: `display:block`, `position:absolute`, `focusable:true`) with the ring painted on the visible label. |
| `pricing-faq-island.html` | FIXED-NOW | Questions/answers localized via `pricing_faq.q1..q6/a1..a6` with English fallbacks (6 items rendered — verified in `public/pricing/index.html`); native `<details>` kept; annual answer retains the accurate 10-payments ≈17% wording. |
| `status-overview-island.html` | FIXED-NOW | Amber operational-warning panel replaced with a neutral handoff ("Component status is maintained on the live status host… this export does not assert component health"). |
| `status-history-island.html` | FIXED-NOW | External-history handoff named; explicitly does not imply no incidents from absent static data. |
| `cookie-consent-island.html` | **RETIRED** | `git rm` (staged deletion). Obsolete script-dependent modal duplicate of the live `partials/cookie-consent.html`; before deletion, repo-wide grep found no references outside the review document itself (§5.3). |
| `pricing-calculator-island.html` | DORMANT | Zero includes → explicitly designated a **catalog snapshot** in-file; Free volume already the recurring 3,000 (not 30,000) and the launch allowance is separate; validator authority kept (R5's gate still pins its tokens; that is stated in the header comment). |
| `render-history-island.html` | DORMANT | Zero includes. "90-Day Retention" wording replaced by plan-based retention (7–730 days per catalog) and a dormancy banner added. |
| `testimonials-island.html` | DORMANT | Zero includes. Obsolete €3,000/mo + 10-IP proof replaced with catalog-derived values (`€1,750/mo`, 3 IPs, 5,000,000 emails — from `data/pricing.json`); the three residual testimonial quote glyphs removed; dormancy banner. |

### The two templates outside the tables (were in the 71-file set, not called out in §8)
| File | Verdict | Evidence |
|---|---|---|
| `partials/api-explorer/hero.html` | FIXED-ALREADY (+ island fixes) | Already states the real sandbox contract and keeps the dark technical surface; the §8.1 api-explorer width finding is fixed at the page level. |
| `partials/api-explorer/cta.html` | FIXED-NOW | "Available SDKs" (implying published availability) corrected to client libraries in development / private preview, consistent with `/docs/sdks/`. |

---

## 4. Verdict table — §9 rows, P2-2, P2-3, §4.13-4.15

### 4.1 Styles, data, configuration, assets (review §9)
| Row | Verdict | Evidence / change |
|---|---|---|
| `input.css` | FIXED-NOW | **Concentric ring repaired**: `box-shadow: 0 0 0 5px var(--surface-50, …)` substituted a channel triplet into a colour position (invalid → the whole declaration was dropped). Now `rgb(var(--surface-50))`/`rgb(var(--surface-300))`; present in the built sheet (`0 0 0 5px rgb(var(--surface-50))`). Global `white-space: nowrap` on every table cell scoped to numeric/identifier cells (`tabular-nums`, `font-mono`, `[data-nowrap]`) with prose wrapping; forced tiny mobile 2-up card grid relaxed to `auto-fit minmax(220px,1fr)`; cookie-bar space reserved. |
| `styles.css` | FIXED-NOW | Regenerated from the authored input with the pinned CLI (`-c … -o … --minify`, v3.4.17); no hand maintenance, token contrast gate green in both sheets/themes. |
| `no-js.css` | FIXED-NOW | Collapsed content genuinely hidden (native `<details>` closed state + the existing `details:not([open])` rule — Chromium probe `display:none`, h=0); deployment radios focusable + labelled with a visible ring; checkbox-hack block and stale Escape claims removed. |
| `giallo.css` | FIXED-ALREADY + FIXED-NOW | Both themes already present (`prefers-color-scheme` + `html.dark` blocks) and it introduces no third colour language; now loaded only where code exists (14 of 178 pages). |
| `tailwind.config.js` | FIXED-NOW | Documented that scales expose explicit 50–950 shades only (no DEFAULT → bare `bg-info`/`text-info` compile to nothing); the last bare utilities in templates removed. |
| `pricing.json` | FIXED-NOW | Now states recurring vs launch allowance explicitly (`free_launch_allowance {emails, emails_display, window_days, applies_to}`), annual semantics (`annual_billing_months: 10`, `annual_savings_percent: 16.7`, note that annual = ten monthly payments), per-plan `retention_days` and derived display strings; the extended serving gate keeps display strings and annual math honest. |
| `canonical.json` | FIXED-ALREADY | No duplicate pricing catalog (R5 gate asserts); HIPAA/certification/penetration wording consistent with the rendered compliance/features/pricing surfaces (§5.7); availability vs operational status separated (HIPAA chip fix). |
| `i18n.json` | FIXED-ALREADY (claims) + ROUTED (coverage) | Annual/quota strings already correct (`Jährlich (10 Monatszahlungen, ca. 16,7 % Ersparnis)` etc.); `3.000`/`30.000` occurrences are the current recurring quota and one-time allowance. 42 template-referenced keys are missing — **reported to R4 with suggested values** (§6.1); I did not edit the file. |
| `en.po` | FIXED-NOW | Status header documents SUPPLEMENTARY/NOT ACTIVE, no template calls `trans()`, `data/i18n.json` is the active catalog. |
| `de.po` | FIXED-NOW | Same status header; glossary/consent terms aligned with the JSON catalog as a reference memory. |
| `es.po` | FIXED-NOW | Same; explicitly notes PO coverage does not supply Markdown bodies (they are `content/**/*.es.md`). |
| `fr.po` | FIXED-NOW | Same. |
| `config.toml` | FIXED-ALREADY | Public URLs, company identity, social metadata and language fallbacks verified explicit (base_url/app/api/status hosts, `og_image`, three `[languages.*]` blocks, empty twitter/github URLs documented as deliberate). |
| `Dockerfile` | FIXED-NOW | Provenance added: `ARG SOURCE_REVISION` + `public/build-provenance.json` stamped after `zola build` (zola/tailwind versions + revision) and `org.opencontainers.image.revision` label; generation comments match the actual steps (CSS build → font-URL cachebust → zola → stamp). |
| `nginx.conf` | FIXED-NOW + verified | Consent substitution, error-page boundaries, cache tiers and versioned-asset handling verified against the real config with real requests (§2.1); exact-match locations bring the metadata artifacts to the api-server's 3600 tier, `/icon.svg` to 3600, `/specs/` to a real YAML content type; `/forensic` relocations present. |
| `staging-parity.json` | FIXED-NOW | Parity expectations extended: cachebusted asset URL resolution (bare vs versioned), localized bodies (not just navigation), result-origin return journeys, consent states. |
| `_headers` | FIXED-NOW | Added `X-XSS-Protection: "0"`, `/giallo.css` immutable, `/icon.svg`+metadata/`/.well-known/*` 3600, `/specs/*` no-cache — equivalent to the nginx and Rust serving paths. |
| `_redirects` | FIXED-NOW | `/forensic` + `/forensic/` (all locales) 301s added, matching the nginx vhost. |
| `.htaccess` | FIXED-NOW | Scope comment (equivalent behaviour, not independent route authority) + `RedirectMatch` rules mirroring `_redirects`/nginx location rules. |
| `manifest.json` | FIXED-ALREADY | Identity/icons current, `display: "browser"`, no service worker/offline implication. |
| `icon.svg` | FIXED-ALREADY | Red mark preserved (`#dc2626` on `#f8fafc`); computed contrast 4.62:1 (logo, non-text). |
| `og-image.svg` | FIXED-NOW | Recomposed inside the current identity: zinc-950 canvas + brand-red glow, Inter wordmark (Apex red / Mail zinc), one bounded headline, one bounded subtitle, three arch-crowned chips with safe text bounds. No blue/slate, no clipping. |
| `og-image.png` | FIXED-NOW | Regenerated from the corrected SVG (1200×630, visually verified). |
| `hero-grid.svg` | FIXED-ALREADY | Decorative intensity subordinate (`rgba(0,0,0,0.03)` strokes); repo grep shows zero template/CSS references — a dormant decorative snapshot, no new pattern family introduced. |
| `openapi.yaml` | FIXED-ALREADY (+ R4 note) | Version `1.0.0` present; endpoint list matches the `/docs/api` reference (messages/batch/{id}/cancel, events, domains/{id}/verify, suppressions, webhooks, api-keys, team, analytics, ips, account, grader); display of the revision beside the download is a content change — reported to R4. |
| `robots.txt` | FIXED-ALREADY | `Allow: /`, canonical host, sitemap; consistent with per-page noindex (404/noidnex compare pages). |
| `security.txt` | FIXED-ALREADY | Contact/canonical/policy present; `Encryption` targets `/pgp-key.asc`; all three roots are routed by the api-server and were probed 200. |
| `config-v1.1.xml` | FIXED-NOW | Outgoing server corrected to the documented relay (`smtp.apexmail.ee:587` STARTTLS) instead of an undocumented `mail.apexmail.ee:465`; IMAPS 993 unchanged; consistent with the firewall service-port list (25/80/443/587/993). |
| `pgp-key.asc` / `pgp-key.txt` | FIXED-ALREADY | `diff -q` → identical; routed and probed 200. |
| Font files | FIXED-ALREADY | woff2 delivered for every face; TTFs retained for non-browser/fallback packaging; `NOTICES.md` attribution intact; the Dockerfile cachebusts font URLs (added `?h=`). |

### 4.2 P2-2 — calculator slider authority (review §3 P2-2)
**FIXED-ALREADY + FIXED-NOW.** The slider was already gone: `partials/pricing/calculator.html`
now has a single `<input type="number" name="volume">` with the explicit comment "One authoritative
volume control: the number input is what the server reads. A disconnected range slider under no-JS
would silently ignore the dragged value." The handler (`routes/explorer.rs`) reads `volume`,
`peak_daily`, `dedicated_ips`, `domains`, `team_users`, `support`, `billing_cycle`. Remaining
cleanup done now: the orphaned slider tick row was removed, priced vs context inputs are labelled,
and the next-page estimate is explained.

### 4.3 P2-3 / §4.13 — public claims vs the catalog
**FIXED-NOW.** Derived surfaces: home teaser (all prices/quotas/retention), plans cards
(limits/retention/launch allowance), calculator CTA (free volume, €0 setup, client-library status),
testimonials snapshot (Enterprise price/IPs/volume), competitor breakdown (current Developer/Pro
figures, €49/€69 add-on, Growth/Business/Enterprise IP entitlements). Where the value is still a
literal, it is **machine-pinned** by R5's `validate_pricing_drift.py` (plans.html name/price/signup
URLs) or cross-checked by my extended serving gate (display strings ↔ numeric fields ↔ annual math,
self-proved by mutations). Annual semantics everywhere = ten monthly payments ⇒ ≈16.7% saving, never
10%.
Catalogue facts used as the authority: Free €0/3,000 recurring **plus** a one-time 30,000-email
allowance (first 30 days); Developer €29/50k; Pro €89/150k; Growth €229/500k; Business €699/2M;
Enterprise Cloud €1,750/5M; retention 7/30/60/90/365/730; dedicated IPs 0/0/0/1/1/3; add-on €49
first / €69 additional.

### 4.4 §4.14 — localization must cover the journey (template-side parts)
**FIXED-NOW (template side).** Every template string the review called hardcoded now has an i18n
lookup with an English fallback: pricing hero/teaser/CTA/FAQ, calculator labels and priced/context
markers, comparison hero/table/decision guide, compliance CTA, status handoffs, private-cloud
diagram/latency labels, diagnostics timeline/CTA, 404 metadata, dates, "Related", jump-nav labels.
The 42 referenced-but-absent catalog keys are listed for R4 (§6.1) with the English fallback as the
suggested value. Verified: German compare hero renders `Marktvergleich`; the German pages keep their
locale links; no template links an English fragment where a localized page exists (privacy link now
uses the language-independent `#data-retention` anchor).

### 4.5 §4.15 — brand beyond the app
**FIXED-NOW.** og-image SVG recomposed in the red/neutral identity + PNG regenerated at 1200×630
(§4.1). Error pages: the marketing 404 keeps its branded focus treatment from base.html, now with a
single centralized noindex and localized metadata (template side), and the container serves the
branded 404 body (`<title>Page Not Found | ApexMail</title>`, probe in §2.1). `static/50x.html` is
R5's file and was left untouched (its diff is R5's inline-fallback work).

---

## 5. Zero-skips appendix (literal commands and outputs)

### 5.1 The 71-file census
```
$ find apps/marketing-zola/templates -type f | wc -l
71
$ find apps/marketing-zola/templates -type f | sort   # 18 page templates + 5 chrome + 38 partials +
                                                     # 10 generated (now 9 after the retirement)
```
Every path above appears in §3 with a verdict; the two files the review text did not tabulate
(`partials/api-explorer/hero.html`, `partials/api-explorer/cta.html`) are adjudicated explicitly in
§3's closing table. Sum: 69 tabulated + 2 = 71.

### 5.2 Fail-before evidence (representative, all reproduced before fixing)
```
$ grep -rn "€[0-9]\|[0-9],[0-9][0-9][0-9]\|most verified\|30,000\|3,000" apps/marketing-zola/templates/ | grep -v i18n_data
templates/home.html:74:  3,000 emails/mo + 30,000 launch allowance
templates/home.html:78:  pro · most verified
templates/home.html:79:  €89
templates/home.html:86:  2M emails · 365-day retention
templates/partials/calculator/competitor-breakdown.html:42: From €45/mo (Starter + overage), or €65 Pro
templates/partials/calculator/competitor-breakdown.html:51: €30/mo add-on (Pro+); included on Growth, Scale, and Enterprise
templates/partials/generated/testimonials-island.html:46: €3,000/mo
templates/partials/generated/testimonials-island.html:50: 10 IPs

$ grep -rnoE '(bg|text|border)-(info|success|warning|danger|primary|accent)("[^-a-zA-Z0-9]|$)' apps/marketing-zola/templates/ | wc -l
14        # bare text-info (features/grid.html)
$ grep -rnoE 'bg-info/[0-9]+' apps/marketing-zola/templates/ | wc -l
14

$ grep -n "box-shadow: 0 0 0 5px var(--surface-50" apps/marketing-zola/static/css/input.css
1634:  box-shadow: 0 0 0 5px var(--surface-50, #fafafa), 0 0 0 6px var(--surface-300, #d4d4d8);

$ grep -n "white-space: nowrap" apps/marketing-zola/static/css/input.css
2015:  white-space: nowrap;      # inside the all-cells table rule

$ grep -rn "mail.apexmail.ee</hostname>" apps/marketing-zola/static/.well-known/autoconfig/mail/config-v1.1.xml   # + 465/SSL
$ grep -rn "587" apps/marketing-zola/content/architecture.md apps/marketing-zola/content/security/index.md
content/architecture.md:176:  └─ SMTP (smtp.apexmail.ee:587, STARTTLS)
content/security/index.md:85: inbound access limited to the mail/web service ports (25, 80, 443, 587, 993)

$ python3 tools/check_marketing_serving.py     # BEFORE the app.rs fix
  - root-relative assets referenced by built pages have no api-server route (they 404 on the marketing host): ['/giallo.css', '/specs/openapi.yaml']
```

### 5.3 Dormancy evidence (grep, not assumption)
```
$ for n in cookie-consent-island pricing-calculator-island render-history-island testimonials-island; do
    echo -n "$n: "; grep -rl "partials/generated/$n" apps/marketing-zola/templates/ | tr '\n' ' '; echo; done
cookie-consent-island: 
pricing-calculator-island: 
render-history-island: 
testimonials-island: 
$ grep -rl "partials/home/comparison.html\|partials/home/security.html\|partials/forensic/hero.html" apps/marketing-zola/templates/
(no output)
$ grep -rn "template = \"page.html\"" apps/marketing-zola/content/ | wc -l
0
```

### 5.4 Serving probes (current tree)
See §2.1 for the full transcript (api-server 3999 before/after, nginx 18080 bare/versioned/wrong-hash,
artifact tiers, consent pending→recorded, branded 404, `/forensic` 301s, `/health`).

### 5.5 Rendering verification after the fixes
```
$ zola --root apps/marketing-zola build
-> Creating 151 pages (0 orphan) and 25 sections
$ python3 tools/check_marketing_serving.py
checked 177 built pages … marketing serving gate passed
$ python3 tools/check_marketing_serving.py --self-test
self-test: all nine checks can fail (mutants caught)
$ python3 tools/validate_pricing_drift.py
pricing drift validation passed
$ grep -o "3,000 emails/month\|50,000 emails/month\|150,000 emails/month\|500,000 emails/month\|2,000,000 emails/month\|1 dedicated IP included\|7-day event retention\|30-day event retention\|60-day event retention\|90-day event retention\|One-time 30,000-email launch allowance (first 30 days)\|1 sending domain\|1 team member" apps/marketing-zola/public/pricing/index.html | sort | uniq -c
   2 1 dedicated IP included
   1 1 sending domain
   1 1 team member
   1 150,000 emails/month
   1 2,000,000 emails/month
   1 3,000 emails/month
   2 30-day event retention
   1 50,000 emails/month
   1 500,000 emails/month
   1 60-day event retention
   1 7-day event retention
   1 90-day event retention
   1 One-time 30,000-email launch allowance (first 30 days)
$ grep -o 'faq-item' apps/marketing-zola/public/pricing/index.html | wc -l
6
$ grep -o 'id=pricing-faq' apps/marketing-zola/public/pricing/index.html | wc -l
1
$ grep -rl "giallo.css" apps/marketing-zola/public --include=index.html | wc -l
14
$ python3 - <<'EOF'  # one-h1 contract on section pages
… <h1> counts for /compare/, /contact/, /solutions/ …
1 / 1 / 1
EOF
```

### 5.6 Annual-semantics evidence (P2-3 floor)
```
$ python3 -c "import json;d=json.load(open('apps/marketing-zola/data/i18n.json'));print(d['de']['calculator']['annual']);print(d['fr']['calculator']['annual']);print(d['es']['calculator']['annual'])"
Jährlich (10 Monatszahlungen, ca. 16,7 % Ersparnis)
Annuel (10 paiements mensuels, env. 16,7 % d'économie)
Anual (10 pagos mensuales, ahorro de aprox. 16,7 %)
$ python3 -c "import json;d=json.load(open('apps/marketing-zola/data/pricing.json'));print(d['annual_billing_months'], d['annual_savings_percent'], d['free_launch_allowance'])"
10 16.7 {'emails': 30000, 'emails_display': '30,000', 'window_days': 30, 'applies_to': 'free'}
$ grep -c "roughly a 17% discount" apps/marketing-zola/public/pricing/index.html
1
```

### 5.7 Claim-consistency evidence (§4.13 / §9 canonical.json)
```
$ grep -rho "HIPAA[^<\"]\{0,60\}" apps/marketing-zola/templates/ | sort | uniq -c | sort -rn
   3 HIPAA availability is not currently offered.
   2 HIPAA availability is not currently offered.{% endif %}
   1 HIPAA availability not currently offered{% endif %}
   1 HIPAA availability is not currently offered. Enterprise can suppo
   1 HIPAA availability and BAAs are not currently offered{% endif %}
   1 HIPAA availability and BAAs are not currently offered.
   1 HIPAA compliance included?
   1 HIPAA Availability{% endif %}
$ python3 tools/check-compare-pricing-parity.py
plan vocabulary: ['Business','Developer','Enterprise Cloud','Free','Growth','Pro']; retired names: ['Scale','Starter']
compare pricing parity OK
```

### 5.8 Real-browser interaction probes (Playwright/chromium, assets intercepted from the built export)
```
$ node /tmp/probe3.mjs
NAV closed: {"open":false,"display":"none","h":0}
    opened: {"open":true,"h":736,"pos":"absolute","maxH":"736px","linksTabbable":10}
    openAfterEsc: true        # <details> is NOT closed by Escape in Chromium → the "Esc closes"
                              # claims were removed rather than promised
RADIO: {"display":"block","position":"absolute","focusable":true,"fieldset":true,"legend":"Deployment models"}
CONSENT body padding-bottom: 88px
CONSENT actions: ["necessary","all",null]   # null = the policy link, not a consent action
```
(First probe ran against production CSS because the built pages reference `https://apexmail.ee/…`
absolutely; the probe was re-run with `page.route` fulfilling every apexmail.ee request from the
local export so the working tree's CSS was measured.)

### 5.9 Layout gate fail-before / pass-after (my own regression, caught and fixed)
```
$ sh tools/contrast-audit/layout-gate.sh      # first run after adding the features jump nav
Done: 8 layout findings across 1181 runs.
FLAGGED pages: marketing /features/ (+ /de/, /fr/, /es/) [light|dark /desktop]: sibling-overlap
$ python3 -c "…violations.json…"
{"kind":"sibling-overlap","path":"body>main#main-content>section:nth-of-type(1)",
 "other":"body>main#main-content>section:nth-of-type(2)","iy":10}

$ # fix: remove the -mt-8 lg:-mt-10 negative margins from the features/pricing jump navs
$ sh tools/contrast-audit/layout-gate.sh
Done: 0 layout findings across 1181 runs.
LAYOUT_RC=0
```

### 5.10 Contrast gate — fail-before (my own regressions), pass-after
```
$ sh tools/contrast-audit/gate.sh        # first run after my template work
[self-test] PASS — 12/12 checks
[gate] FAIL — AA failures: 3 across 3 runs (112 pages, 317 runs, 208.2s)
  marketing /de/ [light]      "Example trace" 82,82,91 on 16,16,18 @2.46
                              (div.term > div.term-bar > span.ml-auto.text-[10px])
  marketing / [light]         "Example trace" 82,82,91 on 16,16,18 @2.46
  marketing /pricing/ [light] "Start Free" 238,238,238 on 238,238,238 @1
                              (a.btn-secondary--invert on a LIGHT section)
CONTRAST_RC=1

$ # fixes: the "Example trace" label now inherits .term-bar's own #a1a1aa (the
$ # fixed dark terminal panel is not a themed surface); the pricing CTA's Start
$ # Free uses .btn-secondary (the invert variant is for dark surfaces only).
$ zola --root apps/marketing-zola build && sh tools/contrast-audit/gate.sh
[gate] PASS — AA failures: 0 across 0 runs (112 pages, 317 runs, 195.0s)
CONTRAST_RC=0
$ sh tools/contrast-audit/layout-gate.sh
By kind: {}
LAYOUT_RC=0
```
Raw logs: `/tmp/contrast_gate.log` (fail-before), `/tmp/contrast_gate2.log` (pass-after),
`/tmp/layout_gate.log` (overlap fail-before), `/tmp/layout_gate2.log` + `/tmp/layout_gate3.log`
(pass-after).

### 5.11 og-image regeneration
```
$ "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --disable-gpu \
    --window-size=1200,630 --screenshot=/tmp/og-image.png "file://…/static/images/og-image.svg"
137458 bytes written to file /tmp/og-image.png
$ python3 -c "from PIL import Image; im=Image.open('/tmp/og-image.png'); print(im.size); im.convert('RGB').save('…/static/images/og-image.png','PNG',optimize=True)"
(1200, 630)
# visually verified: red/near-black identity, no clipped headline/subtitle/chips
```

### 5.12 §9 asset identity checks
```
$ diff -q apps/marketing-zola/static/pgp-key.asc apps/marketing-zola/static/pgp-key.txt
(identical)
$ python3 - <<'EOF'  # icon contrast
icon contrast ratio A-mark on tile: 4.62:1
EOF
$ grep -rn "hero-grid" apps/marketing-zola/templates apps/marketing-zola/content apps/marketing-zola/static/css
(no references — dormant decorative snapshot)
$ grep -n "version:" apps/marketing-zola/static/specs/openapi.yaml
5:  version: "1.0.0"
```

---

## 6. Reported for other lanes

### 6.1 R4 — content + `data/i18n.json`
**(a) 42 template-referenced keys are absent from the catalog** (the i18n gate fails until they are
added; the English fallback inside each template is the suggested value). Sections and keys:

* `home.*` — `teaser_emails_per_month`, `teaser_launch_allowance`, `teaser_emails`,
  `teaser_retention_suffix`, `teaser_choose_plan`, `hero_example_label`
* `pricing.*` — `questions_title`, `questions_body`, `talk_to_sales`, `calculator_hint`, `per_month`
* `calculator.*` — `priced_factor`, `context_only`, `rules_note`
* `compare.*` — `hero_lead`, `hero_cta_secondary`, `decision_label`, `choose_apexmail`,
  `choose_competitor`, `alternatives`, `cta_note`, `feature`, `tie`, `not_available`
* `compliance.*` — `cta_title`, `cta_subtitle` (**de is currently an empty string — the one
  pre-existing i18n finding**), `cta_contact`
* `security.not_offered`
* `private_cloud.*` — `svc_mta`, `svc_queue`, `svc_analytics`, `svc_api`, `svc_lb`, `svc_dns`,
  `latency_vpc_tag/desc`, `latency_region_tag/desc`, `latency_shared_tag/desc`,
  `latency_saas_tag/desc`
* `pricing_faq.*` — `title`, `q1..q6`, `a1..a6`
* `not_found.*` — `meta_title`, `meta_description`
* `a11y.*` — `last_updated`, `on_this_page`, `related`, `pricing_jump`, `compare_jump`,
  `feature_categories`, `private_cloud_jump`, `no_entries`, `no_entries_body`, `no_guides`,
  `no_guides_body`, `empty_page`, `comparison_scroll`, `comparison_caption`, `deployment_models`
  (`a11y.platform_capabilities` already exists)

English values: take the `{% else %}` string of each lookup in the named template (grep the key).
**(b) Content-side items from my rows:** add a stable `#data-retention` anchor to all four
`content/privacy/_index*.md` pages (the compliance link now targets it); show the OpenAPI revision
beside the `/specs/openapi.yaml` download in `content/docs/api/openapi/index.md`; the compare pages'
callout to `/compare/methodology/` is already linked by the template.
**(c)** The compare pages' `pricing_as_of`/`currency_note` front matter is now rendered *outside* the
table scroller; nothing else needed from content.

### 6.2 R5/R2 — stale ui-foundation baseline fixtures (two items)
**(a) `check_ui_a11y.py`** fails on
`services/mail-server/crates/ui-foundation/baselines/rust-ui/marketing-zola-contact-sales.html`
("<input type=email> (work_email) lacks autocomplete"). The live content already has
`autocomplete="email"` (`content/contact/sales.md:36`); the **baseline fixture** is stale.
**(b) `check_ui_links.py`** fails on `dead-fragment marketing[-zola]/pricing → #plans` inside
`baselines/rust-ui/marketing-pricing.html` / `marketing-zola-pricing.html`. The marketing source is
correct — the built page carries **both** sides of the fragment:
```
$ grep -o 'id=plans' apps/marketing-zola/public/pricing/index.html | head -1
id=plans
$ grep -o 'href=#plans' apps/marketing-zola/public/pricing/index.html | head -1
href=#plans
$ stat -f "%Sm %N" -t "%H:%M:%S" …/baselines/rust-ui/marketing-pricing.html …/public/pricing/index.html
23:28:43 …/baselines/rust-ui/marketing-pricing.html
23:30:41 …/apps/marketing-zola/public/pricing/index.html
```
The fixture was exported at 23:28:43, between the pricing jump-nav edit and the plans-anchor edit;
the fixtures are generated artifacts ("derivative artifacts" per review §1). Both clear on the next
export (`APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures`) after the marketing
build — I did not run it because it rewrites ui-foundation baselines (R2/R5-owned) and would capture
other lanes' in-flight state.

### 6.3 R1 — in-flight `api-server` compile error blocks the Rust test run
```
$ cargo test --package api-server --lib static_asset_cache_control_tiers
error[E0603]: function `load_template_edit` is private
  --> crates/api-server/src/routes/web.rs:24130:26
   = `data::load_template_edit` … private function
error: could not compile `api-server` (lib test) due to 1 previous error
```
Both files are R1-owned (`web.rs`, `web/data.rs`). My app.rs change could not be compiled/verified
through cargo because of this; it is additive (`route_service`/`nest_service` arms, one cache-tier
condition, one extra test loop) and `cargo fmt --package api-server` was run clean. Once R1's tree
compiles, `marketing_static_assets_are_cacheable_but_pages_are_not` additionally asserts
`/giallo.css` and `/specs/openapi.yaml` return 200 and that `/giallo.css` is immutable.

### 6.4 R5 — informed changes in `validate_pricing_drift.py` territory
My changes keep every string that gate pins (verified green). To finish the "derive, don't
transcribe" direction in `plans.html`, R5's gate could later replace its
`plan_name = "…"`/`plan_price = "€…"` literal pins with a check that the cards' values come from
`pricing.json` (the file now carries `monthly_price_display`/`included_volume_display` and my gate
verifies display ↔ numeric equality). No change is required for this wave.
Deployment note: `apps/marketing-zola/static/50x.html` (R5's file) was **not touched** by this lane.

### 6.5 Serving owner — leftover observation
The dev api-server process on `127.0.0.1:3999` predates the asset-router fix (binary mtime
19:20 vs sources 20:06/20:56) and therefore serves every marketing asset as 404. Restart/rebuild the
dev server after the wave lands; the source is correct and the extended gate now covers the class.

---

## 7. Orchestrator paragraph

Lane R3 adjudicated all 71 marketing templates (69 review-tabulated + the two api-explorer partials),
every §9 row, P2-2, P2-3/§4.13, the template half of §4.14, §4.15's marketing assets, and the
review's §1 serving defect, with literal evidence throughout and zero skips. The marketing build is
green: zola builds 151 pages/25 sections with 0 orphans; the regenerated Tailwind artifact carries the
concentric-focus repair, scoped nowrap and the relaxed mobile card grid; `check_marketing_serving.py`
(now nine checks, nine self-proved mutants) passes and caught two genuine asset 404s
(`/giallo.css`, `/specs/openapi.yaml`) that are now routed, with the immutable cache tier extended to
match; `validate_pricing_drift.py`, `check_marketing_contrast.py`, `check-compare-pricing-parity.py`,
`check_capability_claims.py`, `check_ui_terminology.py`, `check_ui_form_hygiene.py` and the **layout
gate (0 findings across 1181 runs)** all pass; the **contrast gate passes (0 AA failures, 112 pages,
317 runs)** after it first caught three AA failures in my own new markup (a dark-on-dark example-trace
label and a light-section invert button), which were fixed. Public pricing is now derived from
`data/pricing.json` (home teaser, plan limits/retention/launch allowance, calculator CTA, dormant
snapshots) with gate-checked display↔numeric equality and the annual "ten monthly payments ≈ 16.7%"
semantics stated everywhere; the cookie banner collapses equivalent necessary-only choices; the mobile
menu is a native `<details>` disclosure whose promises match real browser behaviour (Escape claims
removed after a Chromium probe); the footer's implicit grid track, the bare `text-info`/`bg-info/10`
utilities, the inert forensic search control, the six-cells/five-headers compliance table, the 1.98 s
vs 302 s elapsed-time error, the unlabelled reputation meters, the misaligned latency legend, the amber
status panels, the missing giallo load scoping and the clipped blue og-image are all fixed;
`cookie-consent-island.html` is retired, and the four truly dormant partials are explicitly
snapshotted with their misleading claims corrected. Four items need other lanes: R4 must add the 42
i18n keys (full list in §6.1, English fallbacks are the suggested values) plus the privacy
`#data-retention` anchors; the ui-foundation baseline fixtures must be re-exported after this build
(`marketing*-pricing.html` was generated 23:28:43, between two of my edits, so it still lacks
`id=plans` — the built page has it; same batch clears the stale `contact/sales` fixture that fails
`check_ui_a11y.py`); and R1's in-flight `routes/web.rs`/`web/data.rs` E0603 blocks compiling the
api-server test that guards the new asset routes (§6.3) — no R3 file depends on that fix to be
correct, but the Rust assertion should be re-run once R1's tree compiles. No commit was made and no
KiwiCaptcha surface was touched.
