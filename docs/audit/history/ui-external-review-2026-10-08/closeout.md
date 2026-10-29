# External UI/UX review — remediation close-out (2026-10-09)

The external review (`review.md`, 867 lines, sections 1-14) was reconciled against the current tree
by seven rigorous lanes (R1 console+CP Rust, R2 shell/primitives/styles, R3 marketing build, R4
marketing content/localization, R5 emails/PDF/legal/gates, R6 filed-leftover closer, R7 fold
closer). Every finding is adjudicated `FIXED-ALREADY / FIXED-NOW / EXCLUDED` with literal evidence in
the lane reports (`lane-r1-console.md` … `lane-r7-fold.md`); this document is the merged scan.

## P1 register — final verdicts (review §3)

| # | Finding | Verdict | Evidence anchor |
|---|---|---|---|
| P1-1 | Campaign edit could use the create path | FIXED-NOW | Identity-preserving save posts `/web/campaigns/update` + hidden id; round trip pinned by test + golden. Lane also found and fixed the underlying functional bug: the handler never promoted a draft to `scheduled` (the worker only claims scheduled rows), so the scheduling UI's promise was false — now promotes/demotes with a native "Save as draft". |
| P1-2 | Scheduling copy contradicts executable behaviour | FIXED-NOW | Consent copy (§4.11) states timezone + automatic-send consequence; no "manual Start" wording remains; and the handler now makes the copy TRUE (status transition above). |
| P1-3 | Closed mobile navigation blocks content | FIXED-NOW | Chromium probe: closed drawer intercepted **5408** points across documents → **0**; dimensions/background/scrolling now only under `[open]`; invalid `inset-y` fixed; CP drawer mirrored. |
| P1-4 | Populated bulk tables emit nested forms | FIXED-ALREADY + verified | Row forms are siblings wired via `form=`; independent scan over **229 rendered goldens/fixtures: 0 nested forms**; populated-fixture depth scans + the upgraded Python form-hygiene gate keep it pinned. |
| P1-5 | Live settings pages lose action forms | FIXED-NOW | Contacts + CP-audit CSV exports restored through typed `secondary_actions` composed into the live list builder (filters preserved); API-keys/team/webhooks/billing/dedicated-IPs forms verified in place. |
| P1-6 | Domain Verify DNS wrong route | FIXED-NOW | Action target corrected to the mounted handler; rendered-form route test added. |
| P1-7 | Template editing round trip incoherent | FIXED-NOW | Editor loads stored values; blank body keeps stored content with a version bump; redirects target the existing editor route; E2E round trip pinned. |
| P1-8 | Native select options unescaped | FIXED-ALREADY + extended | Primitive escapes value/label/id/name (hostile-name test); the lane also found `render_native_select`'s latent raw interpolations and escaped all six at the helper boundary. |
| P1-9 | Authored vs compiled console styles diverged | FIXED-NOW | Regenerated-from-input diff proved **64 artifact-only selectors + 24 artifact-only comments**; all authored ones moved into `globals.input.css`; regeneration deterministic (single hash) and the served sheet is byte-identical to the artifact. |
| P1-10 | Translated quickstarts empty | FIXED-ALREADY + gaps | de/es/fr bodies verified as genuine full translations (identical structure; 0 English prose paragraphs); language-handoff notice + locale-prefixed links added. |
| P1-11 | Translated SLAs omit terms | FIXED-ALREADY + dates | Full substance verified (7 sections / 3 tables each incl. the credit matrix); revision dates corrected to the revision they publish. |
| P1-12 | Failed-form replay restores wrong controls | FIXED-NOW | Replay scoped to the matching `data-form-id` form, checked/selected state REPLACED not accumulated, stable `aria-describedby` error links; lane also found three handlers never recorded group values (webhooks/API scopes/placement) — fixed with tests. |
| P1-13 | MFA QR masks transposed; shared test decoder | FIXED + independently validated | Spec-orientation masks; new spec-written decoder (`tools/verify_qr_interop.py`, masks 0-7 × versions 1/3/5) plus cross-check against `segno` (0 function-region / 0 format-info differences). |

## P2 register — final verdicts

| # | Finding | Verdict |
|---|---|---|
| P2-1 | Placement detail static waiting view | FIXED-NOW — real results + explicit running/completed/failed lifecycle. |
| P2-2 | Calculator slider not authoritative | FIXED-NOW — single authoritative volume control; priced vs context fields labelled. |
| P2-3 | Public claims vs catalog | FIXED-NOW — dedicated-IP entitlements (Pro add-on / Growth 1 / Business 1 / Enterprise Cloud 3), €89 Pro price, per-plan overage ladder, "High" delivery-rate replaced with dated "not directly comparable", SDK language qualified; annual = ten monthly payments ≈ **16.7%** everywhere, derived from `data/pricing.json`/catalog. |
| P2-4 | PDFs do not use the designed layouts | FIXED-NOW by WIRING — `typst` 0.15.1 pipeline wired (`TypstWorld`, embedded OFL fonts, template/data VFS), hand-rolled data-dump writer removed, all five templates corrected for 0.15 + the review's content rules; `pdf-renderer` 31/31 incl. independent text-extraction/reading-order validation. |

## Section coverage (merged)

- §4.1-4.15 (global recommendations): composition model, copy sweep (implementation-exposing copy
  gone from customer surfaces — remaining occurrences are source comments), state language,
  hierarchy, typography jobs, spacing, selective depth, mobile (drawer + wrapping + focus), native
  controls (inert legacy exports adjudicated per row), form feedback, scheduling consent, preview vs
  fidelity (sanitized-preview disclosure), pricing authority, localization journey, brand beyond
  the app (og-image recomposed + PNG regenerated 1200×630, error pages, emails, PDFs).
- §5.1/§5.2 (shared Rust UI + styles/build): every row adjudicated by R2/R5/R7 (see lane reports).
- §6/§7 (customer console + control plane, every page row): R1 — 23/23 live probes pass.
- §8 (all 71 marketing templates): R3 — 64 FIXED-NOW, several FIXED-ALREADY, four dormant partials
  explicitly snapshotted, `cookie-consent-island.html` retired.
- §9 (marketing styles/data/config/assets): R3 — incl. the versioned-stylesheet serving defect
  (handler 404s for `/giallo.css` + `/specs/openapi.yaml` fixed; serving gate extended with nine
  checks + mutation proofs).
- §10 (177 content files / 54 families): R4 — i18n audit **127 → 0 findings**; 96 content files +
  `i18n.json` (leaf keys 637 → 691/locale); 1468 fragment links resolved, 0 unresolved.
- §11 (CAPTCHA): **EXCLUDED** — standing owner directive: KiwiCaptcha is a separate project/repo, do
  not touch (consume the latest version only). No CAPTCHA surface was edited.
- §12/§13/§14 (emails, error pages, PDF, legal templates, testing/manifests): R5 (+ R7) — every row
  adjudicated; gates strengthened where the review named weaknesses (populated form-hygiene,
  selector-aware class parsing, link integrity incl. fragments/hosts/methods, independent pixel
  baselines, locale pricing drift, missing-tooling failures).

## Defects found beyond the review (all fixed, fail-before/fail-after)

Campaign draft→scheduled never persisted (UI promised auto-send the worker could not honour);
contacts + CP-audit CSV exports missing from live views; templates list lost its editor link
(Actions-column guard ignored `edit_path_prefix`); team invite created dead accounts (now mints
tokens and queues the real invite mail same-transaction); AI-draft approval 500'd on empty
presentation bodies (now rendered through the shared transactional shell); sales dead-letter Replay
and decision Review are real native SSR forms; list members became inspectable (new
`/lists/{id}/members`); dna markers restored; the vendored Tailwind CLI in git was corrupt
(restored to the official v3.4.17 build + `dev-start.sh` host fallback); the golden normalizer
doubled the stylesheet-version token in 73 goldens (fixed, goldens regenerated); the admin
wildcard-scope gate matched one spelling and failed a guarded file (now semantic + mutation-proven);
188 real AA contrast failures during the fold (dark brand logotype token step, one global rule).

## Final battery (frozen tree)

| Battery | Result |
|---|---|
| `cargo nextest run -p ui-foundation` | **529 passed, 0 skipped** |
| `cargo nextest run -p api-server --lib` | **2,119 passed, 0 skipped** |
| `cargo nextest run -p sales-autopilot` | 959 passed, 0 skipped |
| `cargo test -p pdf-renderer` | 31 passed |
| Browser suite (`tests/browser`, live stack) | **220 passed** |
| Python UI/marketing gates (10) | all green |
| Contrast gate | **0 AA failures / 326 runs** |
| Layout gate | **0 findings / 1,196 runs** |
| `dna_verify` | 13/13, exit 0 |
| `cargo fmt --check` (CI-exact) + clippy (ui-foundation, api-server) | clean |
| Independent nested-form scan (229 rendered docs) | 0 nested forms |
| `ci/pipeline.sh run --stages validate` | all gates green |

## Disclosed partials (recorded, not hidden)

- `compliance/data-retention`'s heading remains English: no retention key exists in any locale and
  translating shared policy tables is R4's content authority (reported, not silently skipped).
- Footer grid fragility at some mobile widths (an English-only footer label caused 328 spills; the
  shipped compact "(EN)" label keeps the gate green) — template-side hardening filed.
- One fixture-coverage gap: no exported fixture expresses a plan/permission-RESTRICTED console page
  (loaders' entitlement copy is exercised by api-server tests, not the fixture matrix).

## Standing notes

A single-stage CI run does not bless a sha (full deploy-host line does; no deploy performed).
KiwiCaptcha surfaces untouched throughout. One in-flight agent commit (`927f67c7 "update 128
files"`) swept partial work mid-wave; the fold commit supersedes it with the reconciled tree.
