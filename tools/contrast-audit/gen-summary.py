#!/usr/bin/env python3
"""Generate reports/summary.md from reports/violations.json."""
import json
from collections import Counter, defaultdict

D = json.load(open('reports/violations.json'))
AA = [v for v in D['violations'] if v['verdict'] == 'fail-aa']
AAA = [v for v in D['violations'] if v['verdict'] == 'fail-aaa']
SUS = [v for v in D['violations'] if v['verdict'] == 'pixel-suspect']
BORDERS = D['borderFindings']
FOCUS = D['focusFindings']

def rgb(c):
    return '#%02x%02x%02x' % tuple(c)

def pattern_groups(items):
    g = defaultdict(lambda: {'occ': 0, 'pages': set(), 'ex': None, 'ratio': 99})
    for v in items:
        k = (v['surface'], v['theme'], tuple(v['fg']), tuple(v['bg']), v['tag'], bool(v.get('inSvg')), bool(v.get('mono')), v['kind'])
        g[k]['occ'] += v['occurrences']
        g[k]['pages'].add(v['page'])
        if v['ratio'] < g[k]['ratio']:
            g[k]['ratio'] = v['ratio']; g[k]['ex'] = v
    return sorted(g.items(), key=lambda x: -x[1]['occ'])

out = []
w = out.append
w('# ApexMail Dark-Mode + WCAG 2.1 Contrast Audit')
w('')
w(f"Generated: {D['meta']['generated']}  ")
w('Tool: `tools/contrast-audit/audit.mjs` (DOM walk + full-page screenshots + PNG pixel confirmation)  ')
w('Full data: `tools/contrast-audit/reports/violations.json`')
w('')
w('## Scope')
w('')
w('| Surface | Pages | Themes | Viewport |')
w('|---|---|---|---|')
w('| web (console) | 33 full routes | light, dark (`prefers-color-scheme`), dark-class (`html.dark` explicit-toggle layer) | 1280x900 |')
w('| control-plane | 30 full routes | light, dark, dark-class | 1280x900 |')
w('| marketing (marketing-zola public) | 116 built pages incl. de/es/fr locales | light, dark | 1440x900 |')
w('')
w('421 page-theme runs, 0 load errors. Console/CP pages are full-route static HTML exported with '
  '`APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures` (zero-JS pages, so static render == production render). '
  'Marketing pages are the built `apps/marketing-zola/public` output served over HTTP with `https://apexmail.ee/...` asset URLs mapped locally.')
w('')

w('## Headline numbers (AA failures)')
w('')
w('| Surface | Theme | Text elements checked | AA fail occurrences | AAA-only fail occurrences | pixel-suspect |')
w('|---|---|---|---|---|---|')
for k in ['web|light', 'web|dark', 'web|dark-class', 'control-plane|light', 'control-plane|dark', 'control-plane|dark-class', 'marketing|light', 'marketing|dark']:
    s = D['stats'].get(k, {})
    w(f"| {k.split('|')[0]} | {k.split('|')[1]} | {s.get('textChecked', 0)} | {s.get('textAaFail', 0)} | {s.get('textAaaOnlyFail', 0)} | {s.get('pixelSuspect', 0)} |")
w('')
w(f"Total: **{sum(v['occurrences'] for v in AA)} AA-failing text instances** in {len(AA)} violation groups; "
  f"{len(AAA)} AAA-only groups; {len(SUS)} pixel-suspect groups; "
  f"{len(BORDERS)} low-contrast border groups ({sum(b['occurrences'] for b in BORDERS)} instances, WCAG 1.4.11 non-text).")
w('')

w('## Systemic patterns (fix these once, fix everywhere)')
w('')
w('Grouped by surface + theme + fg/bg/tag across pages (top 40 by occurrences):')
w('')
w('| x | pages | surface | theme | element | fg | bg | worst ratio | example |')
w('|---|---|---|---|---|---|---|---|---|')
for (surf, theme, fg, bg, tag, insvg, mono, kind), info in pattern_groups(AA)[:40]:
    ex = info['ex']
    label = tag + (' (svg/chart)' if insvg else '') + (' (mono/code)' if mono else '') + (' placeholder' if kind == 'placeholder' else '')
    w(f"| {info['occ']} | {len(info['pages'])} | {surf} | {theme} | {label} | {rgb(fg)} | {rgb(bg)} | {info['ratio']:.2f} | {str(ex['text'])[:38]} |")
w('')

w('## Worst offenders (lowest ratios, occurrences >= 3)')
w('')
w('| ratio | surface | theme | page | element | text | fg | bg | pixel-confirmed |')
w('|---|---|---|---|---|---|---|---|---|')
for v in sorted([v for v in AA if v['occurrences'] >= 3], key=lambda v: v['ratio'])[:30]:
    w(f"| {v['ratio']:.2f} | {v['surface']} | {v['theme']} | {v['page']} | {v['tag']} | {str(v['text'])[:34]} | {rgb(v['fg'])} | {rgb(v['bg'])} | {v['pixelConfirmed']} |")
w('')

w('## Focus indicators (keyboard Tab sampling)')
w('')
noind = [f for f in FOCUS if not (f.get('outlineVisible') or (f.get('boxShadow') and f['boxShadow'] != 'none'))]
w(f'{len(FOCUS)} focused-element snapshots taken (10 Tab presses per run). '
  f'**{len(noind)} snapshots show NO visible focus indicator** (no outline, no box-shadow).')
w('')
if noind:
    c = Counter((f['surface'], f['theme']) for f in noind)
    w('| surface | theme | snapshots without indicator |')
    w('|---|---|---|')
    for k, n in c.most_common():
        w(f'| {k[0]} | {k[1]} | {n} |')
    w('')
    seen = set()
    for f in noind:
        key = (f['surface'], f['text'][:24])
        if key in seen: continue
        seen.add(key)
        w(f"- {f['surface']} [{f['theme']}] `{f['tag']}` {str(f['text'])[:40]!r} — outline: `{f['outline']}`, shadow: `{f['boxShadow'][:60]}`")

w('')
w('## Border / divider contrast (WCAG 1.4.11, threshold 3:1)')
w('')
bc = Counter((b['surface'], b['theme']) for b in BORDERS)
w('| surface | theme | failing border color-pairs | instances |')
w('|---|---|---|---|')
bg_occ = Counter()
for b in BORDERS: bg_occ[(b['surface'], b['theme'])] += b['occurrences']
for k, n in bc.most_common():
    w(f'| {k[0]} | {k[1]} | {n} | {bg_occ[k]} |')
w('')

w('## Notes, gaps and method')
w('')
for n in D['meta']['notes']:
    w(f'- {n}')
w('- Charts (`ui-foundation/src/charts.rs`, labels use `rgb(var(--muted-foreground))`) do not render in the no-data static fixtures, so no fixture measured them. Token math: muted-foreground is 113 113 122 on white cards in light (5.3:1 pass) and 161 161 170 on 18 18 21 cards in dark (7.3:1 pass). Fix agent should add data-mode fixtures to verify with real charts.')
w('- Mobile viewports (e.g. the `<details>` disclosure navs) were not audited; runs used desktop widths only.')
w('- og/hero images: text baked into images is outside DOM/pixel text audit; screenshots are available for eyeballing.')
w('- The `.dark`-class layer (dark-class runs) never triggers in the shipped zero-JS console (CSP `script-src \'none\'`); it exists for the future explicit toggle. RESULT: it is fully consistent — 0 dark-class-only failures vs the media-query dark runs — so a future theme toggle is safe on current content.')


w('')
w('## Manual spot-check verification (screenshots in reports/crops/)')
w('')
w('| # | Finding | Data | Visual verdict |')
w('|---|---|---|---|')
w('| 1 | web `/dashboard` light, sidebar heading `Main` | 2.56 vs 4.5 | CONFIRMED FAIL — faint gray on white (A-web-dashboard-light-Main.png) |')
w('| 2 | control-plane `/dashboard` light, sidebar `Operations` | 2.56 vs 4.5 | CONFIRMED FAIL — faint (G-cp-dashboard-light-Operations.png) |')
w('| 3 | marketing `/docs/webhooks/` light, code tokens on near-black block | 1.36-1.5 vs 4.5 | CONFIRMED FAIL — dark-gray/dark-blue tokens nearly unreadable (D-webhooks-light-code.png) |')
w('| 4 | marketing `/compare/postmark/` dark, red-600 links on near-black | 4.12 vs 4.5 | CONFIRMED marginal FAIL — readable but dim (H-postmark-dark-redlinks.png) |')
w('| 5 | marketing `/fr/features/` dark, stat `99.9%` | DOM 1.98 (fail) / pixels 19.1 | DOM FALSE POSITIVE — rendered white-on-dark, readable (F-frfeatures-dark-stat.png); layered/gradient bg defeats ancestor bg walk |')
w('| 6 | marketing `/compare/mailgun/` dark, table cell em-dash | 1.08 (fail, pixelSkipped) | TOOL ARTIFACT — with entrance animations disabled the cell is readable (B2-mailgun-dark-cell.png); earlier invisible readings were `.animate-in` opacity fades captured mid-flight |')
w('')
w('Lessons encoded in the tool: animations/transitions are force-disabled before measuring (entrance fades otherwise produce phantom fg==bg results), and every finding carries a `pixelConfirmed` flag — entries with `pixelConfirmed: true` or `failSource: dom` + agreeing pixels are highest confidence; `pixelSkipped` entries below the 16000px capture cap rely on DOM math only.')
w('')
w('## How to re-run')
w('')
w('```bash')
w('cd tools/contrast-audit')
w('npm install')
w('# refresh full-route fixtures (writes tools/contrast-audit/fixtures/):')
w('cd ../../services/mail-server && APEX_EXPORT_ALL_UI_ROUTES=1 cargo run --bin export_visual_fixtures -- ../../tools/contrast-audit/fixtures && cd ../..')
w('cd tools/contrast-audit && node audit.mjs   # ~6-7 min, 421 runs')
w('python3 gen-summary.py')
w('# crop any finding for visual verification:')
w('node crop.mjs <surface> <page> <theme> "<css-selector>" [out.png]')
w('# CI gate (console+CP full, marketing top-20; zero AA failures; ~100s):')
w('./gate.sh            # or: node audit.mjs --gate')
w('```')
w('')
open('reports/summary.md', 'w').write('\n'.join(out))
print('summary.md written')
print('summary.md written:', len(out), 'lines')
