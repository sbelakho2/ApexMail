# Contrast audit residuals — post-fix state

Generated: 2026-08-22 (after the WCAG 2.1 AA fix pass)
Tool: `tools/contrast-audit/audit.mjs` — full run: 421 page-theme runs
(web 33 + control-plane 30 routes × light/dark/dark-class, marketing 116 pages × light/dark)

## Result

**Zero AA text failures remain** (was 2,936 failing instances in 1,072 groups
before the fix pass). Every entry below is either a non-defect artifact of the
measurement method, an enhancement-level (AAA) finding, or explicitly out of
scope for this pass. The CI gate (`tools/contrast-audit/gate.sh`) requires
zero AA failures on its subset and passes.

## Residuals, with reasons

| Residual | Count | Why it is not an AA defect |
|---|---|---|
| `fail-aaa` violation groups (pass AA, miss 7:1 / 4.5:1-large AAA) | 1,306 groups | WCAG 2.1 AAA is an enhancement level, not a conformance requirement ("AA text failures = 0" is the mandate). Dominated by zinc-600 muted text at ~6.6-7:1 on zinc-100 and brand-600 links at 4.8:1 on white — both above the 4.5:1 AA floor by design margins chosen from the existing brand/zinc steps. |
| `pixel-suspect` groups (DOM math passes, rendered-pixel estimate falls >0.75 short) | 100 groups / 215 occurrences | Measurement artifacts of the pixel sampler on wide/sparse cells, not real failures. Examples: `td "2025 / No"` zinc-600 (#52525b) on #fafafa — DOM 7.4:1, "pixels" 1.2:1 (physically impossible for that pair); box-drawing glyphs `│` in code blocks (DOM 18:1, sampled 3.7:1 — 1px-wide glyphs defeat the cluster sampler); thin mono `POST` white-on-brand-600 (DOM 4.8:1, sampled 3.1:1). On solid backgrounds DOM computed-style math is authoritative per the tool's method notes; the crops in `reports/crops/` from the manual spot-check pass confirm DOM accuracy. |
| Low-contrast borders (WCAG 1.4.11 non-text, threshold 3:1) | 2,036 groups / 13,202 instances | Out of scope for this pass (the mandate was AA **text** failures). Hairline decorative dividers (`border-surface-200` on white) dominate; component boundaries that matter visually also carry other cues (fill, shadow, spacing). Follow-up candidate, same tool already records them in `violations.json → borderFindings`. |
| Text baked into og/hero images | n/a | Outside a DOM/pixel text audit (no text nodes to measure). Screenshots under `reports/screenshots/` are available for eyeballing; fixing requires regenerating image assets, not CSS. |
| Mobile viewports (`<details>` disclosure navs etc.) | n/a | Audit runs used desktop widths only (1280x900 console/CP, 1440x900 marketing), same as the pre-fix baseline. The fixed tokens are viewport-independent (same elements/classes render at mobile widths). |
| Charts (`ui-foundation/src/charts.rs`) with live data | n/a | The no-data static fixtures render no chart labels. Token math for the label color `rgb(var(--muted-foreground))`: light zinc-600 #52525b on white cards = 7.0:1; dark zinc-400 #a1a1aa on #18181b cards = 7.3:1 — both pass AA (and now AAA). Adding data-mode fixtures remains a future hardening item. |
| `html.dark`-class layer | 0 dark-class-only failures | Verified fully consistent with the `prefers-color-scheme` runs (0 vs 0), so a future explicit theme toggle is safe on current content. |
| Legacy advisory checker (`deploy/tests/contrast-check.sh`) still prints "critical" items | 126 | That checker regex-scans CSS/HTML and cannot resolve `rgb(var(--token))` values, media-query theming, or inheritance (e.g. it reads the UA-default placeholder gray `#9ca3af` against "bg default" although the shipped rule pins `rgb(var(--surface-600))`). It is advisory (`ci_check_advisory`) in `ci/stages/validate.sh` and is superseded by this pixel-verified audit; the new hard gate is `tools/contrast-audit/gate.sh` in `ci/stages/test.sh`. |
| `dark:` code-token palette (`#93c5fd`/`#fde68a` z-rules) | pre-existing | The dark-mode syntax palette shipped before this pass and passes AA on the near-black code blocks. It was left untouched deliberately: the fix pass only re-maps the **light** theme onto the existing dark-appropriate zinc/brand steps (re-painting the dark code palette to brand hues would be a re-branding change, not a contrast fix). |

## Operational note

Run the audit/gate when no concurrent `export_visual_fixtures` / render-pipeline
write is in flight: a mid-run rewrite of `fixtures/*.html` can transiently
produce phantom dark-class failures (observed once during the fix pass — DOM
fg said zinc-950 while the pixel pass of the very same finding measured 17.9:1;
a clean re-run over identical sources reported 0). The gate script exports
fixtures itself, so it does not race by construction.

## Brand constraint compliance

Every color introduced by the fix pass is an existing step of the brand red
(#dc2626 scale: 400 `#f87171`, 600 `#b91c1c`... — as defined per surface) or
the zinc neutral scale (400 `#a1a1aa`, 500 `#71717a`, 600 `#52525b`, 100
`#f4f4f5`, ...). No new hues; the red/black brand identity and the brand-pin
tests in `ui-foundation/src/lib.rs` are untouched and green.
