# ApexMail Dark-Mode + WCAG 2.1 Contrast Audit

Generated: 2026-08-22T18:29:09.810Z  
Tool: `tools/contrast-audit/audit.mjs` (DOM walk + full-page screenshots + PNG pixel confirmation)  
Full data: `tools/contrast-audit/reports/violations.json`

## Scope

| Surface | Pages | Themes | Viewport |
|---|---|---|---|
| web (console) | 33 full routes | light, dark (`prefers-color-scheme`), dark-class (`html.dark` explicit-toggle layer) | 1280x900 |
| control-plane | 30 full routes | light, dark, dark-class | 1280x900 |
| marketing (marketing-zola public) | 116 built pages incl. de/es/fr locales | light, dark | 1440x900 |

421 page-theme runs, 0 load errors. Console/CP pages are full-route static HTML exported with `APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures` (zero-JS pages, so static render == production render). Marketing pages are the built `apps/marketing-zola/public` output served over HTTP with `https://apexmail.ee/...` asset URLs mapped locally.

## Headline numbers (AA failures)

| Surface | Theme | Text elements checked | AA fail occurrences | AAA-only fail occurrences | pixel-suspect |
|---|---|---|---|---|---|
| web | light | 1064 | 0 | 116 | 22 |
| web | dark | 1064 | 0 | 107 | 1 |
| web | dark-class | 1064 | 0 | 107 | 1 |
| control-plane | light | 968 | 0 | 107 | 21 |
| control-plane | dark | 968 | 0 | 60 | 2 |
| control-plane | dark-class | 968 | 0 | 60 | 2 |
| marketing | light | 16766 | 0 | 1047 | 127 |
| marketing | dark | 16766 | 0 | 1162 | 39 |

Total: **0 AA-failing text instances** in 0 violation groups; 1306 AAA-only groups; 100 pixel-suspect groups; 2036 low-contrast border groups (13202 instances, WCAG 1.4.11 non-text).

## Systemic patterns (fix these once, fix everywhere)

Grouped by surface + theme + fg/bg/tag across pages (top 40 by occurrences):

| x | pages | surface | theme | element | fg | bg | worst ratio | example |
|---|---|---|---|---|---|---|---|---|

## Worst offenders (lowest ratios, occurrences >= 3)

| ratio | surface | theme | page | element | text | fg | bg | pixel-confirmed |
|---|---|---|---|---|---|---|---|---|

## Focus indicators (keyboard Tab sampling)

2098 focused-element snapshots taken (10 Tab presses per run). **0 snapshots show NO visible focus indicator** (no outline, no box-shadow).


## Border / divider contrast (WCAG 1.4.11, threshold 3:1)

| surface | theme | failing border color-pairs | instances |
|---|---|---|---|
| marketing | light | 745 | 5938 |
| marketing | dark | 641 | 5969 |
| web | light | 148 | 299 |
| web | dark | 115 | 194 |
| web | dark-class | 115 | 194 |
| control-plane | light | 96 | 274 |
| control-plane | dark | 88 | 167 |
| control-plane | dark-class | 88 | 167 |

## Notes, gaps and method

- dark-class exercises the .dark class override layer in ui-foundation globals.css (production console is zero-JS; dark comes from prefers-color-scheme, the .dark layer is the explicit-toggle path).
- verdict fail-aa = WCAG 2.1 AA failure (fix required); fail-aaa = passes AA but fails AAA (enhancement); pixel-suspect = DOM math passes but rendered pixels fall >0.75 short of the threshold (possible occlusion/blend — review screenshots).
- failSource=pixel on gradient/image backgrounds means the rendered pixels are authoritative; on solid backgrounds DOM computed-style math is authoritative and pixelConfirmed records independent pixel agreement.
- Marketing surface fixtures under baselines/rust-ui are byte-identical include_str! copies of apps/marketing-zola/public pages, so the public dir is the single audited source of truth.
- Charts (`ui-foundation/src/charts.rs`, labels use `rgb(var(--muted-foreground))`) do not render in the no-data static fixtures, so no fixture measured them. Token math: muted-foreground is 113 113 122 on white cards in light (5.3:1 pass) and 161 161 170 on 18 18 21 cards in dark (7.3:1 pass). Fix agent should add data-mode fixtures to verify with real charts.
- Mobile viewports (e.g. the `<details>` disclosure navs) were not audited; runs used desktop widths only.
- og/hero images: text baked into images is outside DOM/pixel text audit; screenshots are available for eyeballing.
- The `.dark`-class layer (dark-class runs) never triggers in the shipped zero-JS console (CSP `script-src 'none'`); it exists for the future explicit toggle. RESULT: it is fully consistent — 0 dark-class-only failures vs the media-query dark runs — so a future theme toggle is safe on current content.

## Manual spot-check verification (screenshots in reports/crops/)

| # | Finding | Data | Visual verdict |
|---|---|---|---|
| 1 | web `/dashboard` light, sidebar heading `Main` | 2.56 vs 4.5 | CONFIRMED FAIL — faint gray on white (A-web-dashboard-light-Main.png) |
| 2 | control-plane `/dashboard` light, sidebar `Operations` | 2.56 vs 4.5 | CONFIRMED FAIL — faint (G-cp-dashboard-light-Operations.png) |
| 3 | marketing `/docs/webhooks/` light, code tokens on near-black block | 1.36-1.5 vs 4.5 | CONFIRMED FAIL — dark-gray/dark-blue tokens nearly unreadable (D-webhooks-light-code.png) |
| 4 | marketing `/compare/postmark/` dark, red-600 links on near-black | 4.12 vs 4.5 | CONFIRMED marginal FAIL — readable but dim (H-postmark-dark-redlinks.png) |
| 5 | marketing `/fr/features/` dark, stat `99.9%` | DOM 1.98 (fail) / pixels 19.1 | DOM FALSE POSITIVE — rendered white-on-dark, readable (F-frfeatures-dark-stat.png); layered/gradient bg defeats ancestor bg walk |
| 6 | marketing `/compare/mailgun/` dark, table cell em-dash | 1.08 (fail, pixelSkipped) | TOOL ARTIFACT — with entrance animations disabled the cell is readable (B2-mailgun-dark-cell.png); earlier invisible readings were `.animate-in` opacity fades captured mid-flight |

Lessons encoded in the tool: animations/transitions are force-disabled before measuring (entrance fades otherwise produce phantom fg==bg results), and every finding carries a `pixelConfirmed` flag — entries with `pixelConfirmed: true` or `failSource: dom` + agreeing pixels are highest confidence; `pixelSkipped` entries below the 16000px capture cap rely on DOM math only.

## How to re-run

```bash
cd tools/contrast-audit
npm install
# refresh full-route fixtures (writes tools/contrast-audit/fixtures/):
cd ../../services/mail-server && APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures -- ../../tools/contrast-audit/fixtures && cd ../..
cd tools/contrast-audit && node audit.mjs   # ~6-7 min, 421 runs
python3 gen-summary.py
# crop any finding for visual verification:
node crop.mjs <surface> <page> <theme> "<css-selector>" [out.png]
# CI gate (console+CP full, marketing top-20; zero AA failures; ~100s):
./gate.sh            # or: node audit.mjs --gate
```
