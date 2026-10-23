# Brief: Marketing TEMPLATES → ARK (agent lane T)

Repo: /Users/sabelakhoua/IdeaProjects/ApexMail (branch main). You own ONLY:
`apps/marketing-zola/templates/**` and `apps/marketing-zola/static/css/input.css`.
DO NOT touch: any .rs file, apps/marketing-zola/content/**, apps/marketing-zola/data/i18n.json,
static/fonts, static/js, Dockerfile, any other lane's files, and NEVER anything under packages/
(KiwiCaptcha — a separate repo we must not edit).

## The system (ARK) — already shipped, do not redesign it
The authority is `services/mail-server/crates/ui-foundation/assets/ark.css` (the marketing mirror
`static/css/ark.css` is byte-identical; regenerate styles.css after template edits with the recipe
at the top of `static/css/input.css`). Vocabulary to use (all defined in ark.css):
apex-wordmark(+__apex/__mail), apex-mkt-nav(+__spacer), apex-mkt-hero(+__title/__sub), apex-factrow
(+__n/__l), apex-mkt-section, apex-section-label, apex-section-head(+apex-section-aside), apex-h2,
apex-h3, apex-lead, apex-meta, apex-label, apex-figure, apex-mono, apex-mono-id, apex-time-cell,
apex-btn(+--primary/--danger/--sm/--link/--busy), apex-field, apex-input, apex-select, apex-select-wrap,
apex-textarea, apex-check, apex-help, apex-error, apex-footnote, apex-notice(+--ok/--warn/--fail),
apex-status(+--on/--warn/--fail), apex-table(+--dense, td.apex-num, .apex-key, tr.is-selected,
.apex-row-actions), apex-pager(+__sentence), apex-kpi(+__n/__l/__d), apex-panel(+__head/__aside),
apex-evidence(+__hatch/__title), apex-tabs(a.is-active), apex-empty-state(+__title), apex-loading
(+__row/__bar), apex-chart-frame/-legend/__key/__sw(--blue/--hatch)/-empty, apex-steps, apex-prose,
apex-auth-doc(+__brand), apex-skip-link, apex-em, apex-link.

## Structural layout utilities are ALLOWED (cssgen compiles them)
flex/grid/gap-*/items-*/justify-*/w-*/max-w-*/p-*/m-*/mx-auto/space-y-*/grid-cols-*/col-span-*/
relative/absolute/hidden/md:*/lg:*/overflow-*/text-left/center/right/whitespace-*/break-words.
Everything else (colours, text sizes/weights, tracking, leading, rounded, shadows, rings, gradients,
blur, transitions, durations, eases, animate, hover:/focus: variants of design utilities, opacity on
decoration) is BANNED — cssgen cannot compile it, so it silently renders as nothing.

## Work items (in order)
1. Read `templates/home.html` + `partials/home/*.html`. Rebuild the home page as the ARK "Swiss
   poster": `apex-mkt-nav` header (wordmark + text links + apex-btn Create account), `apex-mkt-hero`
   with `apex-mkt-hero__title` (a stated FACT, not a slogan) + `__sub` + one `apex-btn--primary` and
   one `apex-link`, then an `apex-factrow` of four facts (use the real figures: 3,000 emails/month
   free; 30,000 launch allowance; EEA storage default; every message carries a signed receipt).
   Delete: `k-arc-label`, `k-meter`, `stats-v`, `card-dna`, hero badges, eyebrow kickers, gradient
   text, stat tiles, anything with a middot separator.
2. `templates/pricing.html` + `partials/pricing/**`: rebuild the pricing as ONE ledger table
   (`apex-table`): columns Plan | Monthly | Annual, per month | Included volume | Overage per 1,000 |
   Dedicated IPs | Users | Support | action (`apex-btn--sm`). Real figures are in
   `data/pricing.json` (read it; do not invent numbers: Free €0/3,000; Developer €20/50,000/€0.80;
   Pro €89/150,000/€0.60; Growth €229/500,000/€0.35/1 IP; Business €699/2,000,000/€0.35/1 IP;
   Enterprise Cloud €1,750/5,000,000/€0.35/3 IPs). No card columns, no "most popular" badges
   (`plan_is_popular`), no `!important` utilities, no calculator card chrome — the calculator
   becomes a plain `apex-panel` with `apex-field` inputs and an `apex-btn--primary`.
3. `templates/partials/header.html`, `footer.html`, `cookie-consent.html`: nav/footer links plain
   (`apex-mkt-nav`), cookie banner buttons → links with `apex-btn--primary apex-btn--sm` styling via
   `apex-link` if links. Keep ALL existing Tera logic, i18n keys, hrefs, data-* attributes, ids
   (tests pin `cookie-consent-banner`, `data-consent-state`, `/consent?choice=...`). No `<button>`
   inside the consent banner action row (a test forbids it).
4. `templates/partials/features/**`, `compare/**`, `compliance/**`, `private-cloud/**`,
   `calculator/**`, `email-logs/**`, `analytics/**`, `forensic/**`, `status/**`, `api-explorer/**`:
   replace the icon+heading+two-line card grids with ruled structures (`apex-table` ledgers,
   `apex-steps`, or `apex-panel` groups). Icons: DELETE every icon SVG (ark is icon-free). Feature
   copy stays (it is factual); only the rendering changes.
5. `templates/*.html` top-level pages: `class="prose"` → `apex-prose`; docs pages
   (`docs-section.html`, `prose.html`, `prose-section.html`, `section.html`, `page.html`):
   restructure to `apex-prose` typography with `apex-section-head` rules, remove
   `[overflow-wrap:anywhere]`-style arbitrary utilities (apex-mono-id wraps identifiers).
6. `static/css/input.css`: this authored file still carries ~1,800 lines of the OLD marketing
   components (k-arc, m-*, form-banner, btn-primary, prose, header/footer styles, cookie banner,
   code-highlight colours, etc.). Rewrite it down to ONLY what the swept templates still need that
   ark.css does not already provide. Almost everything should be DELETABLE — the goal is a file of
   at most ~150 lines. Keep the giallo code-highlight class names only if templates still use them;
   recolour them to ink/limestone (no syntax rainbow).
7. After every batch: regenerate the artifact exactly as the recipe in `static/css/input.css` says
   (from `services/mail-server/`), then run `python3 tools/check_ark_law.py` and eliminate every
   violation in YOUR files (tokens starting `!`, template vars like `slug`/`amount`/`if`/`endif`
   inside class attrs are Tera fragments — restructure so no lawful-token ambiguity remains).
8. Tests that will still fail and you may IGNORE (other lanes own them): anything under
   services/mail-server/crates/**. Do NOT run cargo.

## Copy law (marketing UI)
Middots banned (use commas or stacked rows; "→" only for routes). No rhetorical questions, no
"X vs Y" slogans, no eyebrow repeating its headline, no phrase highlighted in brand colour, one
em-dash per paragraph max. English fallbacks in templates must read as facts. Do NOT touch
data/i18n.json (another lane owns the 4 locales).

## Definition of done
`python3 tools/check_ark_law.py` reports ZERO violations in apps/marketing-zola/templates/** and
static/css/input.css; styles.css regenerated and contains the apex-* rules; `zola build` NOT required.
Report: files changed, classes deleted vs mapped, anything you could not finish and why.
