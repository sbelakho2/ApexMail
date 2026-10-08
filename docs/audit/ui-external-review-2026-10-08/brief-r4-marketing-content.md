# Lane R4 — marketing content: all 177 files, 54 families, localization

You are an extremely rigorous verifier-fixer. **ZERO SKIPS**: every content family row is adjudicated
with literal evidence. Read `docs/audit/ui-external-review-2026-10-08/review.md` and `register.md`
FIRST.

## Your scope (files)

`apps/marketing-zola/content/**` (all Markdown, 177 files / 54 families per review §10) and
`apps/marketing-zola/i18n.json`. Findings: §3 P1-10 (translated quickstarts — recon: de/es/fr are
370 lines each: VERIFY the bodies are real translations of the EN guide and contain no stubs or
English fallback paragraphs), §3 P1-11 (translated SLAs omit substantive terms — compare section by
section against EN and restore equivalent terms), §3 P2-3 (content-side claims: recurring Free
3,000/month vs launch allowance, annual savings ≈16.7%, dedicated-IP entitlements, SDK availability),
§4.13 (pricing authority: content must derive/repeat only what the catalog says), §4.14 (localization
covering the journey: hardcoded strings, static partials, empty translated bodies, localized pages
linking to English fragments, obsolete pricing in translated strings), §10.1 (all 41 four-language
families), §10.2 (13 English-only families), §13 where the legal/public twin text lives in content.

## Authority

- Catalog (the only commercial truth): `services/mail-server/crates/platform-catalog/src/lib.rs` +
  `apps/marketing-zola/data/pricing.json` (R3 owns data/pricing.json — read it, do not edit; if it
  contradicts the catalog, report to R3). Free = €0 with 3,000 emails/month recurring + one-time
  30,000 launch allowance; annual billing = ten monthly payments ⇒ ≈16.7% saving.
- i18n: `i18n.json` is yours. Keep key parity strong (it already is); route hardcoded template
  strings through it ONLY by reporting the template side to R3 unless the string is content-owned.
- Locale content trees: `content/<family>/index.{md,de.md,es.md,fr.md}`. Metadata lives in
  frontmatter; bodies must be real localized prose.

## Method

1. Build the family inventory from the live tree (do not trust the review's counts blindly): list
   every content file, group by family, and for each family row in §10.1/§10.2 produce a verdict:
   FIXED-ALREADY (with the file + evidence the recommended change already exists) | FIXED-NOW |
   stale (with evidence the finding no longer applies).
2. Priority order: P1-10, P1-11, P2-3 claims, then the family-by-family recommendations.
3. Translations must be REAL localized prose consistent with the glossary/consent terminology —
   never machine-stub text and never English left in place of a translated body. Do not invent
   legal commitments: translated legal pages must mirror the English substance (dates only change
   on substantive revision).
4. After editing content, rebuild/validate: run the zola build used by `tools/dev-start.sh`
   (`zola build` in `apps/marketing-zola`) and the content gates (`tools/validate_pricing_drift.py`,
   docs-lint if it covers marketing content, `tools/check_*` that scan content). Prove the built
   pages exist for the changed files with a real check of the `public/` output.
5. Claims must be scannable: when the review asks to surface a fact (e.g. annual total vs monthly
   equivalent), put it in the content per the page's structure — templates are R3's; report
   template-side needs.

## Constraints

- Do NOT edit templates/static/data/config (R3), Rust (R1/R2), emails/PDF/gates (R5).
- Do NOT touch KiwiCaptcha surfaces or the CAPTCHA mirrors (standing directive).
- Do not update policy dates merely to look fresh.

## Deliverable

`docs/audit/ui-external-review-2026-10-08/lane-r4-content.md`: verdict table covering ALL 54
families (with the four language files each where applicable), P1-10/P1-11/P2-3 explicitly, the
i18n.json changes; zero-skips appendix (literal commands + evidence per family or family group);
"reported for other lanes" (R3 template keys, R1 strings); final orchestrator paragraph.
