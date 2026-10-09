# Lane R4 — marketing content: all 177 files / 54 families, localization

Scope: `apps/marketing-zola/content/**` (177 Markdown files, 54 families) and
`apps/marketing-zola/data/i18n.json` (the file named `i18n.json` in the brief lives at
`data/i18n.json`). Findings: §3 P1-10, §3 P1-11, §3 P2-3 (content side), §4.13, §4.14,
§10.1 (41 four-language families), §10.2 (13 English-only families), §13 (where the
legal/public twin text lives in content), plus the ADDENDUM (42 i18n keys, privacy
`#data-retention` anchors, gate pins). KiwiCaptcha excluded per the standing directive.
No `git commit` was made. No template, static asset, data file (`pricing.json`,
`canonical.json`), Rust source, email/PDF source, or gate file was edited — the whole
change set is 96 `content/**` files + `data/i18n.json` (97 files).

Authority used: `services/mail-server/crates/platform-catalog/src/lib.rs`,
`apps/marketing-zola/data/pricing.json` (read-only for me), and the runtime plan feature
blocks parsed by `tools/validate_pricing_drift.py` (dedicated IP entitlements: Pro =
approved add-on, Growth 1, Business 1, Enterprise Cloud 3; Free = 3,000/month recurring
+ one-time 30,000 launch allowance; annual = ten monthly payments ≈ 16.7%).

## 1. Family inventory (live tree, not the review's counts)

```
$ python3 - <<'EOF'   # groups content/** by family × language
...
files=177 families=54 four-language=41 en-only=13 odd=0
```

Exactly the review's §10.1/§10.2 shape: 41 four-language families (164 files) + 13
English-only families (13 files) = 177.

## 2. P1-10 — translated quickstarts

**Verdict: FIXED-ALREADY (bodies are real translations) + FIXED-NOW (2 small gaps).**

Structural parity of the four guides (same headings, labels, fences, steps):

```
$ python3 <parity>  # h2 / h3 / bold-labels / code-fences / tables / numbered steps
quickstart/index.md    {'h2': 13, 'h3': 3, 'bold_labels': 9,  'code_fences': 11, 'tables': 1, 'steps': 12}
quickstart/index.de.md {'h2': 13, 'h3': 3, 'bold_labels': 9,  'code_fences': 11, 'tables': 1, 'steps': 12}
quickstart/index.es.md {'h2': 13, 'h3': 3, 'bold_labels': 9,  'code_fences': 11, 'tables': 1, 'steps': 12}
quickstart/index.fr.md {'h2': 13, 'h3': 3, 'bold_labels': 103 total (FR "**Label :**"), 'code_fences': 11, 'tables': 1, 'steps': 12}
```

Tree-wide untranslated-prose scan (paragraphs ≥8 words byte-identical to EN, all
four-language families, code fences excluded): **0 prose paragraphs** in de/es/fr — the
only matches were Python code blocks in the quickstart.

Fixes applied now:
- `quickstart/index.{de,es,fr}.md`: added a one-line language handoff notice
  ("Sprachhinweis"/"Aviso de idioma"/"Note linguistique") naming the English-only
  `/docs/` developer documentation and API Explorer.
- `quickstart/index.{de,es,fr}.md`: `[Preise](/pricing/)` → `[Preise](/de/pricing/)`
  etc. — the localized quickstarts were linking the English pricing page.
- EN recurring Free quota re-verified (already correct in the EN body):
  "Free plan: 3,000 emails/month recurring (plus a one-time 30,000-email launch
  allowance)" (`quickstart/index.md:272`) and the Step-12 upgrade bullet with the same
  semantics.

Proof in the built output: `/de/quickstart/` contains `href=/de/pricing/` and
"Sprachhinweis"; `/es/`, `/fr/` equivalents verified.

## 3. P1-11 — translated SLAs omit terms

**Verdict: FIXED-ALREADY (terms present) + FIXED-NOW (revision dates).**

Section-by-section comparison shows the current tree's de/es/fr SLAs carry the full
English substance — scope, uptime table, performance targets, metric definitions,
measurement, the consolidated plan-specific credit matrix, plan notes, exclusions, and
the claims process:

```
$ python3 <parity>  # h2 / h3 / tables
sla/index.md    {'h2': 7, 'h3': 1, 'tables': 3}
sla/index.de.md {'h2': 7, 'h3': 1, 'tables': 3}
sla/index.es.md {'h2': 7, 'h3': 1, 'tables': 3}
sla/index.fr.md {'h2': 7, 'h3': 1, 'tables': 3}
```

The three translations were created in commit `5d634f35` with the 2026-09-09 English
substance but still carried `last_updated = "2026-07-29"`. Because a revision date must
identify the revision actually published, the translated SLAs now mirror the English
date (`2026-09-09`); no other date anywhere in content was refreshed. The credit bands
match the runtime authority (`sla_credit_percentage`): Business graduated to 30%,
Enterprise Cloud capped at 25% — and `templates/legal/sla.md` (R5) pins the same caps
(`pricing drift validation passed`). Public plan names are aligned (`Business`,
`Enterprise Cloud`).

## 4. P2-3 — public claims vs the catalog (content side)

| Claim | Where it was wrong (current tree, before this lane) | Fix |
|---|---|---|
| Dedicated IP entitlements | `enterprise/index.{md,de,es,fr}` said **10 included**; `solutions/high-volume-sending.*` said "1 on Growth, **3 on Business, 10 on Enterprise**"; `solutions/migration.*` table said Scale 3 / Enterprise 10; the 5 compare pages said "1 included on Growth, **3 on Business**"; `architecture.md:106` said "Scale (three included), Enterprise (ten included)" | All now state the authority: approved Pro add-on, **Growth 1, Business 1, Enterprise Cloud 3** (16 files × the 5 compare families, 4 solution pages, enterprise pages, architecture) |
| Obsolete ApexMail Pro price in translated strings | 7 translated compare rows showed **€65** (EN said €89): postmark.fr, sendgrid.fr, amazon-ses.{de,es,fr}, mailgun.{de,es,fr} | All corrected to **€89** (catalog) |
| Overage rate in a dormant i18n string | `pricing.billing_overage_desc` (de/es/fr) claimed a flat **€0.40/1,000** | Rewritten to the catalog ladder: Developer €0.80, Pro €0.60, Growth/Business €0.35; Enterprise Cloud €0.35 contractual |
| Annual savings | i18n already correct in all locales: "10 Monatszahlungen statt 12", "≈ 16,7 %" | Verified, plus the new `pricing_faq.a4` states "≈ 16.7 %" (never 10%) |
| Free recurring vs launch allowance | compare rows, quickstart, enterprise pages all say 3,000/month recurring **+ one-time 30,000 launch** | Verified; new `pricing_faq.a2` states the same |
| SDK availability | `de.features.detail_api_desc` implied available SDKs ("Konsistente SDKs"); EN template string still says "Consistent SDKs" (R3-owned → reported) | de value now says the SDKs are in development with source in the monorepo (matching `home_features.card_6_desc` and `/docs/sdks/`); EN report filed |
| Vague "High" delivery rate | compare/resend + compare/sendgrid, all 4 languages | Replaced with **"Not directly comparable — provider-defined measurement"** (localized), winner "none" |
| Retired internal plan names in customer copy | `Starter`/`Scale` used in EN + translated content (transactional-email tables, migration/high-volume tables, regulated-industries step, de security/terms/secure-email pages) | Public names now: **Developer, Business, Enterprise Cloud** (compare-parity gate: `retired names: ['Scale', 'Starter']`) |
| Pricing description SLA scope | `pricing/_index.*` said "SLA guarantees on Enterprise plans and above" | Corrected to "Business and Enterprise plans" (all 4 languages) |

Built-output sweep after the fixes:

```
$ grep -rl '10 included\|10 on Enterprise\|3 on Business\|€65' apps/marketing-zola/public/
(no output)
```

## 5. §4.13 — one commercial authority

All content pricing statements now repeat only catalog/runtime values (3,000/50,000/
150,000/500,000/2,000,000/5,000,000; €0/29/89/229/699/1,750; overage ladder; ten monthly
payments ≈ 16.7%; launch allowance one-time). The only content-side drift found was the
items in §4 above; `tools/validate_pricing_drift.py` now passes with the content tree
in place, and `tools/check-compare-pricing-parity.py` reports the correct plan
vocabulary and no retired names.

## 6. §4.14 — localization covers the journey

Fixed now:

1. **Hardcoded strings (content-owned):** the new `lang` notice and the localized
   "(English)" markers are real localized strings; the i18n catalog now covers the
   previously English-fallback teapot strings (`home.teaser_*`, `pricing.*`,
   `calculator.*`, `compare.*`, `compliance.cta_*`, `security.not_offered`,
   `private_cloud.svc_*` / `latency_*`, `footer.faq`, `not_found.meta_*`) and the whole
   `pricing_faq` question/answer set — 54 added keys per locale (42 template-referenced
   + 13 FAQ − 1 already-existing `compliance.cta_subtitle`).
2. **Empty translated bodies:** `content/subprocessors/index.{de,es,fr}.md` gained the
   full translated register (10-column vendor table, self-hosted software table,
   notification, objection, change history); `content/contact/_index.{de,es,fr}.md`
   gained the localized channel-selection matrix + Enterprise review block;
   `content/compare/_index.{de,es,fr}.md` gained the localized factual/evidence
   statement, the cited-vs-editorial coverage note and the methodology links.
3. **Localized pages linking to English fragments/paths:** privacy de/es/fr
   `/compliance/#data-retention` → `/de|es|fr/compliance/#data-retention`; solutions/
   enterprise de/es/fr `/contact/sales/` → locale-prefixed; de i18n
   `home.hero_proof_line` `/data-locations/` → `/de|es|fr/data-locations/`. EN-only
   destinations are labelled: about/security "(auf Englisch)/(en inglés)/(en anglais)",
   privacy do-not-sell "(auf Englisch)…", quickstart language notice, and the localized
   footer legal nav now reads "Ihre Datenschutzoptionen (EN)" / "Sus opciones de
   privacidad (EN)" / "Vos choix de confidentialité (EN)".
4. **Obsolete pricing in translated strings:** see §4 (€65, €0.40, IP counts, plan
   names).
5. **Stable language-independent anchors:** `<span id="data-retention"></span>` added
   before the retention heading in all four privacy pages; the compliance partial links
   `{{ lp }}/privacy/#data-retention` now resolve in every locale (fragment proof
   below).
6. **Postmark translated review dates** claimed 2026-07-30 while EN said 2026-08-19;
   translations now state 2026-08-19.

Template-side localization gaps (reported to R3, not faked in content):
`templates/status.html` and `templates/partials/compliance/*.html` contain **zero**
`i18n_data` references, so `/de|es|fr/status/` and `/de|es|fr/compliance/` render English
even though the `status`/`compliance` sections exist in the catalog (the German
compliance hero key is never rendered). Content cannot fix those pages because those
templates do not render `page.content`.

## 7. §13 — legal/public twin text in content

The §13 source templates live in `templates/legal/**` + `templates/compliance/**` and
are R5's per the register (R5's brief claims §13). My scope is the content twin, which I
adjudicated: AUP ↔ anti-spam category rules are now reconciled (see family table),
privacy retention/anchors, DPA scope/subprocessors/retention, SLA matrices, cookies
equivalent outcomes, responsible disclosure, data locations. No policy date was
refreshed except the SLA translations, which had to identify the revision they actually
publish (§3). `tools/validate_pricing_drift.py` also pins
`templates/legal/sla.md` to the runtime credit caps and passes.

## 8. §10.1 / §10.2 — all 54 family verdicts

Legend: **F-ALREADY** = current tree already satisfied the recommendation (evidence);
**F-NOW** = fixed in this lane; **R3** = template-owned half reported to R3.

### 8.1 Four-language families (41)

| # | Family | Verdict | Evidence / change |
|---|---|---|---|
| 1 | Homepage (`_root`) | F-NOW | Teaser/hero strings localized via new keys (`home.teaser_emails_per_month` "E-Mails/Monat"/"emails/mes"/"emails/mois", `teaser_launch_allowance`, `teaser_choices`, `hero_example_label`); 3,000 + 30,000 + 16.7% consistent; built `/de/index.html`, `/es/`, `/fr/` verified |
| 2 | About | F-NOW | Trust block (legal name, registry, VAT, address, governing law, contact table) present in all 4; EN-only `/architecture` link now labelled "(auf Englisch)"/"(en inglés)"/"(en anglais)" |
| 3 | Acceptable use | F-NOW | Decision guide added before the category sections in all 4 (marketing / transactional / mixed→marketing, with honest-classification rule) |
| 4 | Anti-spam | F-NOW | Blanket "all recipients must opt in" / "every email needs unsubscribe" reconciled with the AUP category treatment in all 4 (marketing requires consent+unsubscribe; transactional follows AUP category rules; security/account mail needs no unsubscribe where law does not require it) |
| 5 | Compare index | F-NOW | Localized factual/evidence statement + inline-citation coverage note + methodology links added to de/es/fr bodies (EN already had it) |
| 6 | Amazon SES | F-NOW | IP claim + €65→€89 in de/es/fr; scenario cost assumptions, managed-vs-assembled, methodology note and dated sources verified pre-existing |
| 7 | Mailgun | F-NOW | Region/processing/commercial separation verified; IP claim + €65→€89 fixed; competitor "Scale" plan name kept (it is Mailgun's) |
| 8 | Comparison methodology | F-NOW | Evidence-coverage legend row + literal links to the cited SES/Mailgun pages (and the no-inline-citation pages) added in all 4 |
| 9 | Postmark | F-NOW | IP claim fixed; translated verification dates aligned to EN 2026-08-19; methodology-note plans comparison verified |
| 10 | Resend | F-NOW | Delivery-rate cells → "Not directly comparable …" in all 4; methodology note (plans compared, review date, sourcing) added |
| 11 | SendGrid | F-NOW | Delivery-rate cells fixed; methodology note naming the compared plans (Pro/Essentials, 100K/mo) added; IP claim fixed; SDK row already honest |
| 12 | Compliance | F-NOW (content half) + R3 | Retention fragment destination now resolves everywhere; compliance static sections are hardcoded English in `partials/compliance/*` (0 i18n refs) → reported |
| 13 | Contact index | F-NOW | Channel-selection matrix + Enterprise review block restored in de/es/fr (with locale-prefixed links) |
| 14 | Enterprise contact | F-ALREADY | Scope, preparation guidance and 2-business-day follow-up beside the enquiry action in all 4 |
| 15 | Sales contact | F-ALREADY | Response expectation beside the form + core fields separated from optional procurement context in all 4 |
| 16 | Security contact | F-ALREADY | NDA status field, document-type select, review-scope guidance in all 4 |
| 17 | Cookies | F-ALREADY | Equivalent necessary-only outcomes stated in all 4 ("Gleiche Wirkung"/"Mismo efecto"/"Même effet") |
| 18 | Data locations | F-ALREADY | 12-category table separating deployment/processing/storage/corporate + subprocessor table in all 4 |
| 19 | DPA | F-ALREADY | Template TOC gives scope/definitions/processing/obligations/subprocessors/transfers/security/breach/return-deletion/audit navigation; 1468-fragment check resolves |
| 20 | Enterprise procurement | F-NOW | 10→3 IPs; annual total (€17,500/yr) vs monthly (€1,750) stated in all 4 |
| 21 | Features | F-NOW (i18n) + R3 | Translated recurring quota verified (3,000/month); de SDK language qualified to "in Entwicklung (Quellcode im Monorepo)"; EN template "Consistent SDKs" reported to R3 |
| 22 | Inbox placement | F-ALREADY | Provider telemetry (Postmaster/SNDS) separated from seed-list dashboards in all 4 |
| 23 | Pricing | F-NOW | SLA scope corrected; annual 16.7% + monthly-equivalent semantics in the catalog and template; pricing content is authored by `pricing.html` (R3) |
| 24 | Pricing calculator | F-NOW (i18n) + R3 | Labels localized via new keys ("nur Kontext", "solo contexto", "contexte uniquement", "preisrelevanter Faktor"…); single authoritative input is R3's P2-2 template work |
| 25 | Privacy | F-NOW | Stable `#data-retention` anchors (4 pages), locale-prefixed compliance links, EN-only do-not-sell markers |
| 26 | Private cloud | F-NOW | 14 `private_cloud.svc_*`/`latency_*` keys added; built de/es/fr diagram labels verified ("MTA-Cluster", "Balanceador de carga", "Résolveur DNS"); illustrative-performance qualification verified |
| 27 | Quickstart | F-ALREADY + F-NOW | P1-10; language notice; /pricing/ prefix |
| 28 | Responsible disclosure | F-ALREADY | Scope, report checklist, PGP key and response windows (48h/5 business days) in all 4 |
| 29 | Regulated SaaS | F-NOW | Concise Available/Not offered/Contract-dependent matrix verified; de/es/fr "SAML SSO ab/… Business" name fix |
| 30 | Security | F-NOW (name) | Controls grouped by area/plan; de "Scale"→"Business"; material statements link to documentation/contract |
| 31 | SLA | F-ALREADY + F-NOW | P1-11; date alignment; one plan-specific credit matrix |
| 32 | Solutions index | F-NOW | Goal-based selector (goal → start point → next action) added in all 4 |
| 33 | Enterprise solution | F-NOW | Locale-prefixed sales link; annual commitment total vs effective monthly already stated in all 4 |
| 34 | High-volume sending | F-NOW | Warm-up/qualification/throughput beside onboarding verified; IP bullet + plan table corrected in all 4 |
| 35 | Migration | F-NOW | Gated phases (entry criteria / acceptance / rollback) added in all 4; IP table + plan names corrected |
| 36 | Regulated industries | F-NOW | Procurement checklist added in all 4 (DPA, residency, HIPAA not offered, Private Cloud/BYOIP contract-dependent, questionnaires, SLA) |
| 37 | SaaS platforms | F-ALREADY | Logical-vs-contractual isolation and tenant-boundary responsibility stated (shared cloud logical; contract may add isolation; DPA flow-down is the platform's) |
| 38 | Transactional email | F-NOW | First-send path + diagnostics link added before the narrative in all 4; plan names corrected |
| 39 | Status | F-ALREADY (substance) + R3 | EN template already distinguishes manual viewing/JSON from subscription and avoids health claims; localization blocked by `status.html` (no i18n refs; content not rendered) → reported |
| 40 | Subprocessors | F-NOW | Full registers restored in de/es/fr; EN table cell counts corrected (10/6/3 columns) |
| 41 | Terms | F-NOW (name) | Renewal/cancellation navigation (7.1 auto-renewal + Stripe portal) in all 4; de "Scale"→"Business" |

### 8.2 English-only families (13)

| # | Family | Verdict | Evidence / change |
|---|---|---|---|
| 42 | api-explorer | F-ALREADY | Reserved-recipient (`@example.com`) / isolated-sandbox constraints stated beside the executable actions; response page terminology real |
| 43 | architecture | F-NOW | Responsibility matrix + public-vs-contract-only deployment patterns verified; IP entitlement corrected (Growth/Business 1, Enterprise Cloud 3) |
| 44 | docs (index) | F-ALREADY | "Send your first email / Start the quickstart →" is the first guide card, ahead of discovery cards |
| 45 | docs/alerts | F-ALREADY | Incident severity, maintenance policy, postmortem policy, external regions presented compactly |
| 46 | docs/analytics | F-NOW | Annotated timeline added (API acceptance → MX acceptance → engagement → inbox placement → downstream), with the explicit note that MX acceptance ≠ inbox placement |
| 47 | docs/api | F-ALREADY | Template TOC jump navigation + request/response/follow-up reference structure present |
| 48 | docs/api/grader | F-ALREADY | Public domain check vs authenticated submit unmistakable (endpoint table Auth column + separate sections) |
| 49 | docs/api/openapi | F-NOW | Download bullet now carries version 1.0.0 + publication date + `info.version` note beside `/specs/openapi.yaml` |
| 50 | docs/sdks | F-ALREADY | Preview-source instructions separated from future registry installs; HTTP API alternative foregrounded ("integrate against the HTTP API directly") |
| 51 | docs/webhooks | F-ALREADY | Minimal signature-verification reference + retry schedule + dedup key + replay prevention |
| 52 | email-logs | F-ALREADY (labeling) + R3 | Sample trace labelled "example trace" + "Illustrative actions (not active in this static trace)"; explicit MX-acceptance vs inbox-placement sentence needs the template (page.content not rendered) → reported |
| 53 | performance-methodology | F-ALREADY | Every metric defines units, numerator/denominator, exclusions, measurement period and data source (e.g. §1.1) |
| 54 | privacy/do-not-sell | F-NOW | Rights instructions are an action block (email privacy@apexmail.ee, authorized-agent rule); English-only destination labelled in localized navigation ("(EN)") |

## 9. ADDENDUM items

1. **42 i18n keys** — added per locale **plus** the `pricing_faq.q1..q6/a1..a6` answers the
   island lookups construct at runtime (comment in
   `partials/generated/pricing-faq-island.html` says "keys are reported to R4").
   Key counts: de/fr/es 637 → **691** leaf keys, 21 → 22 sections, full parity.
   Values are real translations (no English prose: the gate's untranslated check and my
   own paragraph scan both clean). The de `compliance.cta_subtitle` empty string was
   filled. Answers use only catalog numbers (3,000/month + 30,000 one-time; per-plan
   overage ladder; ten monthly payments ≈ 16.7%; "not offered" HIPAA; Stripe entitlement
   wording).
2. **Privacy retention anchors** — `<span id="data-retention"></span>` in all four
   privacy pages; every cross-page retention link now resolves (fragment proof below).
3. **Pinned template strings** — I did not fight the gates. `plans.html` name/price
   literals remain R5's pins (`validate_pricing_drift.py` passed untouched);
   template-side needs are listed in §11.

## 10. Zero-skips appendix (literal commands + evidence)

### A. Inventory and structure

```
$ python3 <inventory>          → files=177 families=54 four-language=41 en-only=13 odd=0
$ python3 <parity quickstart>  → h2/h3/fences/tables/steps identical across EN/DE/ES/FR
$ python3 <parity sla>         → 7 h2, 1 h3, 3 tables in all four
$ python3 <untranslated-scan>  → 0 EN prose paragraphs in de/es/fr (only Python code blocks)
```

### B. i18n

```
$ python3 tools/i18n-audit.py    # BEFORE
i18n: 127 finding(s)              (126 = 42 missing keys × 3 locales; 1 = empty de.compliance.cta_subtitle)
$ python3 tools/i18n-audit.py    # AFTER
i18n: 0 finding(s)
```

### C. Build and content gates (after `zola build`)

```
$ cd apps/marketing-zola && zola build
Building site...
-> Creating 151 pages (0 orphan) and 25 sections
Done in 903ms.

$ python3 tools/validate_pricing_drift.py          → pricing drift validation passed
$ python3 tools/check-compare-pricing-parity.py    → compare pricing parity OK
                                                     (plan vocabulary Business/Developer/Enterprise Cloud/Free/Growth/Pro; retired names ['Scale','Starter'])
$ python3 tools/check_marketing_serving.py         → checked 177 built pages ... marketing serving gate passed
$ python3 tools/check_ui_links.py                  → checked 7510 href/action targets, 257 fragment targets — all green
$ python3 tools/check_ui_form_hygiene.py           → 300 POST forms / 309 visible controls — all green
$ python3 tools/check_ui_terminology.py            → terminology: all green
$ python3 tools/check_ui_a11y.py                   → checked 152 documents — accessibility: all green
$ python3 tools/check_capability_claims.py         → capability claims: all green
$ python3 tools/check_marketing_contrast.py        → 34 pair renderings ... all pairs pass
$ sh tools/contrast-audit/layout-gate.sh           # full re-run after the footer-label adjustment
Layout-auditing 272 pages, 1181 page-theme-viewport runs
Done: 0 layout findings across 1181 runs.
LAYOUT_RC=0
```

The first full layout-gate run after my edits flagged 328 `text-spills-box` findings
(246 runs) — every one of them the localized footer column headings ("Unternehmen",
"Producto", "Produit", "Entreprise") spilling at 390px after I lengthened
`footer.your_privacy_choices` with "(Englisch)". A filtered A/B run proved causality on
an otherwise untouched page (`AUDIT_ONLY=de/compliance`: 2 findings with the long label,
0 with the original label), so the final label is the compact "(EN)" form, which keeps
the labelling fix and the gate green. This is recorded for R3 as a footer-grid
fragility note (§11).

### D. Fragment resolution (built pages, all locales)

```
$ python3 <fragment-check>   # every internal href with a fragment, relative + absolute apexmail.ee
fragment links checked: 1468 (absolute apexmail.ee: 810 ) | unresolved: 0
```

### E. Built-page content proofs (selected; all asserted PASS)

`/de/subprocessors/` Hetzner + Widerspruch; `/es/` register heading; `/fr/` register
heading; contact matrix `/de|es|fr/contact/`; compare methodology bodies
`/de/compare/` `/fr/compare/`; AUP guide `/de|es/acceptable-use/`; anti-spam
reconciliation `/de|fr/anti-spam/`; migration phases `/de|es/solutions/migration/`; goal
selector `/de/solutions/`; procurement checklist `/fr/solutions/regulated-industries/`;
first-send path `/de/solutions/transactional-email/`; analytics timeline
`/docs/analytics/`; openapi version `/docs/api/openapi/`; methodology links EN + DE
(`href=/compare/amazon-ses/` … / `href=/de/compare/amazon-ses/` ×5 each); delivery-rate
labels `/compare/resend/`, `/compare/sendgrid/`; IP entitlements
`/compare/sendgrid/` "3 on Enterprise Cloud", `/de/compare/postmark/` "3 ab Enterprise
Cloud", `/enterprise/` "3 included", migration table "Business 1 / Enterprise Cloud 3";
`/architecture/` "Enterprise Cloud (three included)"; privacy anchors `id=data-retention`
in all four locales; i18n rendering (`Häufige Fragen`, `Questions fréquentes`,
`E-Mails/Monat`, `emails/mes`, `allocation de lancement`, `MTA-Cluster`,
`Balanceador de carga`, `Résolveur DNS`, `Bereit für ruhigeren Schlaf?`, `nur Kontext`,
`facteur tarifé`, `solo contexto`, `Trace d'exemple`, `Beispiel-Trace`,
`Traza de ejemplo`).

### F. Stale-claim sweep (built output)

```
$ grep -rl '10 included\|10 on Enterprise\|3 on Business\|€65' apps/marketing-zola/public/
(no output)
$ grep -rn 'Scale |\|Starter |\|Scale-Tarif' public/ | grep -v mailgun
(no output)
```

## 11. Reported for other lanes

**R3 — templates (all with literal evidence):**
1. `templates/status.html` — 0 `i18n_data` references; `/de/status/` renders English
   ("Live incident updates, component health …", "This is a static export …") although
   `status.*` keys exist in all three locales. Wire the existing keys (content cannot:
   the template does not render `page.content`).
2. `templates/partials/compliance/hero.html`, `data-retention.html`, `cta.html` — 0
   `i18n_data` references; `/de/compliance/` renders English ("Compliance workflows
   built into", "How long we keep your data", "Start Free") and the German
   `compliance.hero_title` is never rendered. Wire the existing `compliance.*` keys
   (also consumes the `cta_title`/`cta_subtitle`/`cta_contact` values I added).
3. `partials/features/details.html:17` — EN fallback "Consistent SDKs, comprehensive
   docs …" implies shipped SDKs; /docs/sdks and `home_features` say the SDKs are in
   active development. I qualified the de catalog value; the EN template string needs
   the same qualifier.
4. `partials/generated/pricing-faq-island.html` — EN fallback answer 3 says
   "Enterprise Cloud €0.22–€0.35 contractual" while `data/pricing.json` publishes
   €0.35/1,000; EN fallback also says "roughly a 17% discount" vs the catalog's 16.7%.
   My translated answers use €0.35 and 16.7% — the EN fallback should match.
5. `templates/email-logs.html` — add an explicit "recipient-MX acceptance is not inbox
   placement" sentence (the template does not render `page.content`, so content cannot
   add it; the EN body already carries nothing else).
6. Footer mobile grid fragility (observed while implementing the English-only label):
   lengthening `footer.your_privacy_choices` by 10+ characters made the footer company
   column heading spill by 24–27px at 390px on every locale page (328
   `text-spills-box` findings across 246 runs; 0 when the label is short). I shipped a
   compact "(EN)" label that keeps the gate green; the grid should be made wrap/track
   safe so longer localized labels cannot squeeze sibling columns.
7. Addendum 3: `plans.html` name/price literal pins are R5's and were left untouched.

**R5 — gates:**
1. `tools/i18n-audit.py` `check_links` resolves `exists(f"{loc}{base}")`, so a locale
   page linking an unprefixed path (`/pricing/`, `/compliance/`, `/contact/sales/`)
   passed as green as long as a localized target exists; it also skips absolute
   `apexmail.ee` fragment links (the prose TOC permalinks). The before-run here shows
   127 findings and **0** mixed-language findings while the built pages had exactly the
   defects I fixed; suggest checking the actual target (`/{loc}` prefix required) and
   the absolute-fragment class.
2. Baseline note: `check_ui_a11y.py` and `check_ui_links.py` are green in the current
   tree (R3's stale-baseline items are cleared).

**R1:** no R1-owned (console) strings are reachable from marketing content; nothing
found to report.

## 12. Orchestrator paragraph

Lane R4 adjudicated all 177 marketing-content files in 54 families (41 four-language +
13 English-only), P1-10, P1-11, P2-3, §4.13, §4.14, §13's content twins and both
ADDENDUM items with literal evidence and zero skips, and fixed every open content-side
item: the translated quickstarts were proven to be full translations (identical heading/
step/fence structure, zero English prose paragraphs) and gained a language handoff
notice plus locale-correct pricing links; the translated SLAs were proven to carry the
full English terms (7 sections/1 sub-section/3 tables each) and their revision dates now
match the revision they publish; every dedicated-IP claim was reconciled to the catalog
(Growth 1, Business 1, Enterprise Cloud 3) across 5 compare families, high-volume,
migration, enterprise and architecture; seven obsolete €65 Pro prices and a stale €0.40
overage string were corrected to €89 and the per-plan ladder; "High" delivery-rate rows
became "Not directly comparable" with dated methodology notes in all four languages;
retired internal plan names (Starter/Scale) were removed from customer copy; the empty
subprocessors register, contact matrix and compare-index bodies were written in real
localized prose; the privacy pages gained stable `#data-retention` anchors and
locale-prefixed cross-links, EN-only destinations are now labelled, and 42
template-referenced keys plus the six FAQ answers were added per locale (i18n leaf keys
637 → 691, audit 127 → 0 findings). The site rebuilds to 151 pages/0 orphans;
`validate_pricing_drift`, `check-compare-pricing-parity`, `check_marketing_serving`,
`check_ui_links` (7510 targets / 257 fragments), `check_ui_form_hygiene`,
`check_ui_terminology`, `check_ui_a11y`, `check_capability_claims`, `check_marketing_contrast`
and the 1181-run layout gate (0 findings) are green, and a 1468-fragment resolution check
across the built locales has 0 unresolved targets. Four template-side localization gaps
(status.html, the compliance partials, the features SDK string, the email-logs
MX-vs-placement sentence), two FAQ-fallback drift items plus a footer-grid fragility
note were reported for R3, and one gate weakness for R5, rather than fought with content
edits; no template, static asset, data, Rust, email/PDF or gate file was touched, no
commit was made, and no KiwiCaptcha surface was touched.
