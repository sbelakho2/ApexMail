# Brief: Marketing CONTENT pages + i18n copy → ARK (agent lane C)

Repo: /Users/sabelakhoua/IdeaProjects/ApexMail (branch main). You own ONLY:
`apps/marketing-zola/content/**/*.md` and `apps/marketing-zola/data/i18n.json`.
DO NOT touch: templates/**, static/**, any .rs file, Dockerfile, anything under packages/
(KiwiCaptcha — separate repo, never edit), or other lanes' files.

## Context
The whole repo is being moved to the ARK design system (authority:
`services/mail-server/crates/ui-foundation/assets/ark.css` — read its header "THE LAW" first).
cssgen (all-Rust) compiles ONLY structural layout utilities (flex/grid/gap/spacing/width/
breakpoints) — every colour/typography/rounded/shadow/ring/gradient/transition/hover: utility in
content pages now renders as NOTHING. The gate `python3 tools/check_ark_law.py` lists every
violation; your lane is every one under `apps/marketing-zola/content/` and `data/i18n.json`.

## Allowed classes (apex-* primitives, all defined in ark.css)
apex-prose, apex-section-head(+apex-section-aside), apex-h2, apex-h3, apex-lead, apex-meta,
apex-label, apex-figure, apex-mono, apex-mono-id, apex-btn(+--primary/--danger/--sm/--link),
apex-field, apex-input, apex-select, apex-textarea, apex-check, apex-help, apex-error,
apex-footnote, apex-notice(+--ok/--warn/--fail), apex-status(+--on/--warn/--fail), apex-table
(+--dense, td.apex-num, .apex-key, .apex-row-actions), apex-pager, apex-kpi(+__n/__l/__d),
apex-panel(+__head), apex-evidence(+__hatch), apex-tabs, apex-empty-state, apex-steps, apex-em,
apex-link, apex-skip-link. Plus structural layout utilities (flex/grid/gap/p/m/w/max-w/md:/lg:/…).

## Work items
1. `python3 tools/check_ark_law.py --fix-list` — every unlawful token whose first site is under
   `apps/marketing-zola/content/` is yours. The content pages embed raw HTML blocks with the old
   design (`text-brand-600`, `font-semibold`, `tracking-widest`, `uppercase`, `bg-surface-50`,
   `focus:ring-…`, `outline-none`, `accent-brand-500`, `text-red-500`, `hover:…`, `bg-surface-900`,
   `btn-primary`, `form-banner(--success/--error)`, `form-privacy-note`, `underline`, middots).
   Map them:
   - form banners → `apex-notice` (+ `apex-notice--ok` / `apex-notice--fail`), with the bold label
     as `<b>Label</b>` at the start (the legend renders itself);
   - `btn-primary` → `apex-btn apex-btn--primary`; secondary CTAs → `apex-btn` (or `apex-link`);
   - inputs/selects/textareas → `apex-input` / `apex-select` / `apex-input apex-textarea`;
     checkbox+label rows → `apex-check` wrapper with a plain `<input type="checkbox">`;
   - small muted text → `apex-meta`; labels → `apex-label`; emphasised values → `apex-em`;
   - privacy notes → `apex-footnote`; help lines → `apex-help`; error lines → `apex-error`;
   - comparison/feature card grids → `apex-table` ledgers or `apex-steps`;
   - code/terminal blocks keep `<pre><code>` (apex-prose styles them);
   - everything else: DELETE the design tokens, keep the text. Where a section's structure was pure
     decoration (icon rows, gradient panels), reduce it to a ruled `apex-panel` or plain prose.
2. Copy law for ALL four locales (en inline + de/fr/es in these files and i18n.json):
   - NO middot separators `·` — use commas or stacked rows (i18n.json lines flagged by the gate;
     also grep the whole file for ` · `);
   - no rhetorical questions ("Ready for calmer sleep?" → state the fact: "Start free. 3,000
     emails a month, no card.");
   - no "Legacy infrastructure vs. Modern engineering"-style slogans → replace with a factual
     sentence of the same length; keep the SAME translation keys and locales — never delete keys;
   - no eyebrow text that repeats its own headline; no brand-coloured highlight phrases;
   - keep technical facts EXACTLY (figures, plan names, legal claims, GDPR/EEA statements) — copy
     only changes register, never substance.
3. Do NOT change keys, structure, or URLs in i18n.json — values only, all four locales treated the
   same way so translations stay parallel.

## Definition of done
`python3 tools/check_ark_law.py` reports ZERO violations under apps/marketing-zola/content/ and
data/i18n.json. Do not run cargo or zola. Report: files changed, mapping counts, any leftovers.
