# ApexMail Dark-Mode + WCAG 2.1 Contrast Audit

Generated: 2026-08-22T17:26:47.040Z  
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
| web | light | 1065 | 212 | 310 | 28 |
| web | dark | 1065 | 51 | 82 | 0 |
| web | dark-class | 1065 | 51 | 82 | 0 |
| control-plane | light | 968 | 163 | 245 | 22 |
| control-plane | dark | 968 | 21 | 49 | 2 |
| control-plane | dark-class | 968 | 21 | 49 | 2 |
| marketing | light | 16766 | 1959 | 1908 | 109 |
| marketing | dark | 16766 | 458 | 1311 | 35 |

Total: **2936 AA-failing text instances** in 1072 violation groups; 1853 AAA-only groups; 89 pixel-suspect groups; 2144 low-contrast border groups (13300 instances, WCAG 1.4.11 non-text).

## Systemic patterns (fix these once, fix everywhere)

Grouped by surface + theme + fg/bg/tag across pages (top 40 by occurrences):

| x | pages | surface | theme | element | fg | bg | worst ratio | example |
|---|---|---|---|---|---|---|---|---|
| 330 | 6 | marketing | light | span (mono/code) | #005cc5 | #09090b | 3.16 | curl |
| 314 | 50 | marketing | light | th | #a1a1aa | #f4f4f5 | 2.33 | Field |
| 295 | 116 | marketing | light | p | #a1a1aa | #fafafa | 2.46 | Sakala tn 7-2, 10141 Tallinn, Estonia |
| 241 | 6 | marketing | light | span (mono/code) | #032f62 | #09090b | 1.50 | POST https://api.apexmail.ee/v1/grader |
| 200 | 60 | marketing | dark | a | #dc2626 | #09090b | 4.12 | Architecture page |
| 116 | 116 | marketing | dark | a | #ffffff | #ffffff | 1.00 | Skip to main content |
| 116 | 116 | marketing | light | a | #ffffff | #ffffff | 1.00 | Skip to main content |
| 116 | 3 | marketing | light | span (mono/code) | #d73a49 | #09090b | 4.35 | import |
| 87 | 27 | web | light | h3 | #a1a1aa | #ffffff | 2.56 | Main |
| 84 | 5 | marketing | dark | span | #dc2626 | #09090b | 4.12 | ApexMail |
| 58 | 4 | marketing | light | span (mono/code) | #24292e | #09090b | 1.36 | $APEXMAIL_API_KEY |
| 43 | 29 | control-plane | light | span | #a1a1aa | #ffffff | 2.56 | Operations |
| 41 | 29 | control-plane | light | p | #a1a1aa | #ffffff | 2.56 | ApexMail administration and monitoring |
| 36 | 29 | control-plane | light | h3 | #a1a1aa | #ffffff | 2.56 | Control Plane |
| 35 | 4 | marketing | light | span | #a1a1aa | #fafafa | 2.46 | Confirmations / Alerts / Statements |
| 33 | 10 | marketing | light | span | #a1a1aa | #ffffff | 2.56 | vs |
| 31 | 29 | web | light | span | #a1a1aa | #ffffff | 2.56 | Or continue with |
| 27 | 27 | web | light | input placeholder | #a1a1aa | #fafafa | 2.46 | Search campaigns… |
| 27 | 27 | web | light | span | #dc2626 | #fce9e9 | 4.13 | AM |
| 24 | 21 | web | dark-class | a | #f87171 | #fef2f2 | 2.53 | Campaigns |
| 24 | 21 | web | dark | a | #f87171 | #fef2f2 | 2.53 | Dashboard |
| 24 | 4 | marketing | light | div | #a1a1aa | #f4f4f5 | 2.33 | Enterprise Plan Basis |
| 20 | 4 | marketing | dark | td | #ef4444 | #222022 | 4.30 | Deterministisch |
| 20 | 4 | marketing | light | span (mono/code) | #71717a | #09090b | 4.12 | // Server-side send example |
| 20 | 4 | marketing | light | td | #ef4444 | #fffefe | 3.74 | Deterministisch |
| 20 | 8 | marketing | light | div | #71717a | #f4f4f5 | 4.40 | 5M emails/month |
| 16 | 2 | control-plane | light | p | #71717a | #09090b | 4.12 | Pipeline value |
| 16 | 4 | marketing | dark | div | #ef4444 | #450a0a | 4.29 | 1 |
| 16 | 4 | marketing | light | div | #ef4444 | #fee2e2 | 3.08 | 1 |
| 16 | 4 | marketing | light | span (mono/code) | #71717a | #18181b | 3.67 | api/request.ts |
| 16 | 4 | marketing | light | td | #ef4444 | #fafafa | 3.61 | €0 |
| 16 | 4 | marketing | light | span | #71717a | #f4f4f5 | 4.40 | Same VPC |
| 15 | 15 | marketing | light | p | #71717a | #f4f4f5 | 4.40 | Alternative Comparative Mappings |
| 15 | 1 | marketing | dark | span | #dc2626 | #450a0a | 3.34 | Deliverability |
| 15 | 1 | marketing | light | span | #dc2626 | #fef2f2 | 4.41 | Deliverability |
| 14 | 7 | web | dark | span | #dc2626 | #09090b | 4.12 | * |
| 14 | 7 | web | dark-class | span | #dc2626 | #09090b | 4.12 | * |
| 13 | 13 | marketing | light | div | #a1a1aa | #ffffff | 2.56 | 4 |
| 13 | 13 | marketing | light | p | #a1a1aa | #ffffff | 2.56 | Zero Credit Commitment • Setup: < 300s |
| 12 | 4 | marketing | light | a | #a1a1aa | #ffffff | 2.56 | Service credits |

## Worst offenders (lowest ratios, occurrences >= 3)

| ratio | surface | theme | page | element | text | fg | bg | pixel-confirmed |
|---|---|---|---|---|---|---|---|---|
| 1.12 | marketing | light | /secure-email-for-regulated-saas/ | h3 | Audit and Access Controls | #09090b | #18181b | False |
| 1.36 | marketing | light | /docs/api/grader/ | span | $APEXMAIL_API_KEY | #24292e | #09090b | False |
| 1.36 | marketing | light | /docs/sdks/ | span | apexmail | #24292e | #09090b | False |
| 1.36 | marketing | light | /docs/webhooks/ | span | raw_body: | #24292e | #09090b | False |
| 1.36 | marketing | light | /quickstart/ | span | APEXMAIL_API_KEY | #24292e | #09090b | False |
| 1.50 | marketing | light | /docs/api/grader/ | span | POST https://api.apexmail.ee/v1/gr | #032f62 | #09090b | False |
| 1.50 | marketing | light | /docs/api/openapi/ | span | @redocly/cli lint openapi.yaml | #032f62 | #09090b | False |
| 1.50 | marketing | light | /docs/api/ | span | POST https://api.apexmail.ee/v1/me | #032f62 | #09090b | False |
| 1.50 | marketing | light | /docs/sdks/ | span | clone https://github.com/Bel-Consu | #032f62 | #09090b | False |
| 1.50 | marketing | light | /docs/webhooks/ | span | "evt_s1a2b3c4d5" | #032f62 | #09090b | False |
| 1.50 | marketing | light | /quickstart/ | span | "am_live_xxxxxxxxxxxxxxxxxxxxxxxxx | #032f62 | #09090b | False |
| 2.18 | control-plane | light | /discovery | span | Healthy | #22c55e | #fafafa | True |
| 2.29 | marketing | light | /inbox-placement/ | li | Domain reputation: HIGH / MEDIUM / | #52525b | #18181b | False |
| 2.29 | marketing | light | /secure-email-for-regulated-saas/ | p | Scale and Enterprise include runti | #52525b | #18181b | False |
| 2.33 | marketing | light | /about/ | th | Field | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /architecture/ | th | Area | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /compare/methodology/ | th | Field | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/about/ | th | Feld | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /data-locations/ | th | # | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/dpa/ | th | Element | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/data-locations/ | th | # | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/privacy/ | th | Datenkategorie | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/ | th | Funktion | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/ | div | Enterprise Plan Basis | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/ | div | €3,000/mo | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /de/security/ | th | Kontrolle | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /docs/api/grader/ | th | Method | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /docs/api/openapi/ | th | Area | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /docs/api/ | th | Method | #a1a1aa | #f4f4f5 | True |
| 2.33 | marketing | light | /docs/sdks/ | th | Language | #a1a1aa | #f4f4f5 | True |

## Focus indicators (keyboard Tab sampling)

2098 focused-element snapshots taken (10 Tab presses per run). **0 snapshots show NO visible focus indicator** (no outline, no box-shadow).


## Border / divider contrast (WCAG 1.4.11, threshold 3:1)

| surface | theme | failing border color-pairs | instances |
|---|---|---|---|
| marketing | dark | 757 | 6085 |
| marketing | light | 745 | 5938 |
| web | light | 146 | 299 |
| web | dark-class | 111 | 185 |
| web | dark | 111 | 185 |
| control-plane | light | 96 | 274 |
| control-plane | dark | 89 | 167 |
| control-plane | dark-class | 89 | 167 |

## Notes, gaps and method

- dark-class exercises the .dark class override layer in ui-foundation globals.css (production console is zero-JS; dark comes from prefers-color-scheme, the .dark layer is the explicit-toggle path).
- Entrance animations and transitions are force-disabled before measuring (tailwindcss-animate .animate-in opacity fades otherwise produce phantom fg==bg results mid-flight).
- verdict fail-aa = WCAG 2.1 AA failure (fix required); fail-aaa = passes AA but fails AAA (enhancement); pixel-suspect = DOM math passes but rendered pixels fall >0.75 short of the threshold (possible occlusion/blend — review screenshots).
- failSource=pixel on gradient/image backgrounds means the rendered pixels are authoritative; on solid backgrounds DOM computed-style math is authoritative and pixelConfirmed records independent pixel agreement.
- Marketing surface fixtures under baselines/rust-ui are byte-identical include_str! copies of apps/marketing-zola/public pages, so the public dir is the single audited source of truth.
- Full-page screenshots are capped by the browser at very tall pages (some docs pages exceed it); findings below the captured height are marked pixelSkipped=true and rely on DOM math (validated accurate on solid backgrounds).
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
```
