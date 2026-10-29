# Lane R3 — marketing build: templates (71), styles, data, config, assets

You are an extremely rigorous verifier-fixer. **ZERO SKIPS**: every finding below is adjudicated with
literal command/output evidence. Read `docs/audit/ui-external-review-2026-10-08/review.md` and
`register.md` (rules, ownership, verdict schema) FIRST.

## Your scope

Everything under `apps/marketing-zola/` EXCEPT `content/**` and `i18n.json` (lane R4 owns content):
`templates/**` (all 71 files per review §8), `static/css/{input.css,styles.css,no-js.css,giallo.css}`,
`static/**` (svg/png/txt/xml/yaml/json/assets), `data/{pricing.json,canonical.json}`,
`tailwind.config.js`, `config.toml`, `Dockerfile`, `nginx.conf`, `_headers`, `_redirects`, `.htaccess`,
plus `tools/check_marketing_serving.py`. Findings: §8.1-8.9 (all 71 template rows), §9 (all rows),
§3 P2-2 (calculator slider authority), §3 P2-3 (public claims from shared data), §4.13 (pricing
authority), §4.14 (localization must cover the journey — template-side parts), §4.15 (brand beyond
app: og-image, error pages live under static/ — coordinate: R5 owns only `50x.html` and `404.html`),
and review §1's observed serving defect (versioned stylesheet 404 vs bare path 200).

## Authority to build from (not to duplicate)

- Commercial authority: `apps/marketing-zola/data/pricing.json` + `services/mail-server/crates/platform-catalog/src/lib.rs`
  (Free €0/3,000 per month + one-time 30,000 launch allowance; annual = ten monthly payments ⇒
  ≈16.7% saving, NOT 10%; dedicated-IP entitlements and SDK availability per the catalog/`canonical.json`).
  Every rendered price/quota/savings number on every page/partial must DERIVE from these, not be
  independent prose.
- i18n authority: `apps/marketing-zola/i18n.json` (R4 owns the file; if a template hardcodes a string
  that belongs there, report the key + suggested value for R4 instead of editing i18n.json).
- The zola build: `tools/dev-start.sh` (build_marketing_static_site) shows the CSS build command
  (`apps/marketing-zola/tailwindcss -c apps/marketing-zola/tailwind.config.js -i static/css/input.css -o static/css/styles.css`)
  and the zola build. Use them; never hand-edit `static/css/styles.css` (generated).

## Method per finding

1. For EACH of the 71 templates + each §9 row: locate the current file, adjudicate the finding
   (FIXED-ALREADY with file:line evidence | fix now | stale finding with evidence it no longer
   applies). The review says "Dormant" for some partials — for those, adjudicate as
   retire/explicitly-snapshot per the review's recommendation, or prove they are live and fix.
2. Fixes: data-driven where the review asks for derivation; keep the current red/zinc visual language
   and arch/concentric signatures (review §2). Do not add new decoration.
3. Rebuild the marketing site + CSS after changes; verify rendered output (grep the built HTML in
   `public/` for the changed fragments).
4. Serve/verify live: the marketing host is `-H 'Host: marketing.localhost'` on
   `http://127.0.0.1:8080` (or the built `public/` via the marketing container). Adjudicate the
   versioned-stylesheet finding with a real probe (bare path vs versioned path), fix the handler/nginx
   side if broken, and extend `tools/check_marketing_serving.py` with the versioned-asset case.

## Gates you must run

- `apps/marketing-zola` build (zola + tailwind) must succeed with 0 warnings-as-errors regressions.
- `tools/check_marketing_serving.py` (self-test + real run), `tools/validate_pricing_drift.py`,
  `tools/check_marketing_contrast.py`, and the CTA/tracking + a11y/SEO marketing gates that exist in
  `tools/` — run each; they must pass or you fix what they catch.
- `tools/contrast-audit/gate.sh` and `tools/layout-gate.sh` if they cover marketing pages.

## Constraints

- Do NOT touch `content/**` (R4), Rust console files (R1/R2), transactional emails/PDF/gates (R5).
- KiwiCaptcha: the CAPTCHA assets mirrored under marketing resources/public are EXCLUDED (standing
  owner directive). Record the constraint; do not edit them.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r3-marketing.md`: verdict table covering ALL 71
templates + all §9 rows + the serving defect + P2-2/P2-3 (template-side); zero-skips appendix with
literal commands/outputs; "reported for other lanes" (esp. R4 keys/strings); final orchestrator
paragraph.
