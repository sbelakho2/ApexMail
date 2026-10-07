# Dogfood — UI/visual: the chatbot + mailbot surfaces (2026-10-06)

Scope: the console assistant `/assistant` and the AI-drafts review queue
`/reviews/ai-drafts`, every state in both themes, at 320 / 768 / 1280 CSS px,
per `brief-bots-ui-visual.md`. Revision under review:
`0557e55df8163be9a90f6ec7c3e03620f3254b20` + working tree (dirty; fixes in
this report). All findings below were re-verified after the fixes.

Method and artifacts:

| Artifact | Path | Result |
|---|---|---|
| WCAG AA contrast gate (fixtures, light/dark/dark-class) | `tools/contrast-audit/reports/gate-report.json` | PASS — 0 AA failures, 99 pages / 278 runs, classifier self-test 12/12 |
| Gate execution record | `tools/contrast-audit/reports/gate-execution.json` | `executed` @ `0557e55d` (dirty) |
| Layout-spill gate (all fixtures + marketing, desktop/mobile, all themes) | `tools/contrast-audit/reports/layout/violations.json` | bot surfaces: 0 findings; 2 pre-existing out-of-slice pages remain RED (see Residuals) |
| ui-foundation suite (gates J/K/L + surface-ladder + goldens + new pins) | `cargo test -p ui-foundation` (lib + bins + integration), `cargo fmt --check` | 470 lib + 12 bin + 1 integration passed, 0 failed; fmt clean |
| Bot-surface state capture (13 states × 2 themes × 3 widths, screenshots + DOM metrics + keyboard walk + copy scan) | `tools/contrast-audit/reports/bots-ui/report.json`, `reports/bots-ui/screenshots/` (78 PNGs) | 0 document overflow, 0 ringless focus stops, 0 focus traps, 0 real clipped text, 0 copy leaks |
| Live capture, rebuilt image, both surfaces × 2 themes × 3 widths | `tools/contrast-audit/reports/bots-ui-live/report.json` (+ screenshots) | 12 runs: 0 ringless focus stops, 0 focus traps, 0 copy leaks; 2 live-only layout defects found (F10/F11) and fixed |
| Live re-capture, FINAL image (`sha256:8977957c8742…`, trio restarted 22:33Z) | `tools/contrast-audit/reports/bots-ui-live-final/report.json` (+ screenshots) | **12/12 runs clean**: F10 (assistant 768 with real identity) and F11 (drafts 320 with long senders) overflow 0, elements-past-viewport 0, 0 ringless, 0 traps |
| Final-image flag/consent probes | `reports/bots-ui-live-final/flag-probe-final-report.json` (+ screenshots) | flag-disabled page names the reason + no form; form restored after the override; consent-gate refusal re-confirmed live |
| Live interaction probes (first/long message, 429, flag-disabled 403, drafts expand/approve/reject) | `reports/bots-ui-live/probe-report.json`, `flag-probe-report.json`, screenshots | all executed; named live refusals verified (429, consent gate, malformed-row guard, disabled capability) |
| New state fixtures (11 states → 13 HTML files, 22 manifest entries) | `tools/contrast-audit/fixtures/{web-assistant-*,control-plane-reviews-ai-drafts-*}.html` | exported by `export_visual_fixtures` (274 manifest entries total) |

Capture tool: `node tools/contrast-audit/bots-ui-dogfood.mjs fixtures`
(writes `reports/bots-ui/`); live mode: `... live --cookies "am_session=…; csrf_token=…"
--cp-cookies "…" --cp-base http://admin.localhost:8080`. Live interaction probes:
`tools/contrast-audit/bots-ui-live-probes.mjs` (first/long message, 429, drafts
expand/approve/reject) and `bots-ui-flag-probe.mjs` (cache-aware flag-disabled
page/POST + restore); session provisioning helpers are described in §4.

---

## 1. What was audited, state by state

The route-level fixture export renders each route's **no-data fallback only** —
on both bot surfaces that is the EMPTY state. Before this pass neither the
contrast gate nor the layout gate had ever seen the populated transcript, the
escalation/unavailable notices, the PRG flash banners, or a single draft row:
an unrepresented state cannot fail a gate. This pass adds the missing states as
first-class fixtures (`fixture_states` module) and wires them into the browser
gates (manifest) **and** the in-crate markup gates (gates J and K scan the same
renders through `gate_support::gate_documents`).

### Console assistant — `/assistant`

| State | Representation | Light | Dark | dark-class |
|---|---|---|---|---|
| empty history | route fixture `web-assistant.html` | pass | pass | pass |
| first message | live: PRG post → transcript (see §4) | pass | pass | pass |
| typing / streaming | **not applicable — zero-JS SSR** (no client script, no streaming surface; each turn is a form POST + redirect). Documented, not a missing test. | n/a | n/a | n/a |
| long conversation (12-turn window) | live §4 + `web-assistant-populated` fixture | pass | pass | pass |
| long single message (2.2 KB, ends in a 120-char unbroken URL) | fixture `web-assistant-populated` | pass | pass | pass |
| grounded answer with citations (`<details>Sources`) | fixture `web-assistant-populated` | pass | pass | pass |
| escalated answer (human-handoff notice) | fixture `web-assistant-populated` | pass | pass | pass |
| history-loading | **not applicable — SSR** (the document arrives rendered; the loader-failure state is the honest alternative) | n/a | n/a | n/a |
| service error | fixture `web-assistant-error-flash` (the exact live copy) | pass | pass | pass |
| rate-limited 429 | fixture `web-assistant-rate-limited-flash` (the exact live copy) + live attempt §4 | pass | pass | pass |
| feature-flag-disabled 403 | fixture `web-assistant-disabled` (honest notice, no form) + live probe §4 — the copy defect found here (F9) was fixed in the working tree by the assistant/ai_chat owner | pass | pass | pass |
| history unavailable | fixture `web-assistant-unavailable` | pass | pass | pass |

### Drafts review — `/reviews/ai-drafts` (control plane; no separate detail route — the row's `<details>Draft reply</details>` is the detail, approve/reject are inline forms)

| State | Representation | Light | Dark | dark-class |
|---|---|---|---|---|
| empty queue | route fixture | pass | pass | pass |
| populated queue (3 rows incl. empty subject, unclassified, objection sub-label, first-response pill, 2.6 KB reply with an unbroken URL) | fixture `control-plane-reviews-ai-drafts-populated` | pass | pass | pass |
| many rows (9 rows, scroll) | fixture `…-many` | pass | pass | pass |
| long subjects/bodies | the populated/many fixtures (longest subject 143 chars) | pass | pass | pass |
| queue unavailable (store read failure) | fixture `…-unavailable` | pass | pass | pass |
| approve feedback | fixture `…-approved-flash` + live §4 | pass | pass | pass |
| reject feedback | fixture `…-rejected-flash` + live §4 | pass | pass | pass |
| already-handled feedback | fixture `…-already-handled-flash` | pass | pass | pass |

### Chat widget / launcher

None exists on any console page: the only chat surface is the `/assistant`
page; there is no launcher, no floating widget, no client-side script (CSP is
`script-src 'none'`; `grep -rn "launcher|widget|typing|stream"` over
`leptos_views.rs` finds only the KiwiCaptcha history note and the sales
decision-stream tables). Nothing to audit beyond the page itself.

---

## 2. Findings and fixes (all fixes in the owned paths: `crates/ui-foundation/**`
shared recipes + the contrast fixtures; every fix has a pinned test)

Severity: P1 = visibly broken / fails the bar; P2 = below the bar, not
blocking; P3 = polish. All P1/P2 below are fixed and re-verified.

### F1 — P1 — the assistant's notices used `amber-*` classes that do not exist in this palette (rendered unstyled)
`web_assistant_page` painted the unavailable state and the escalation notice as
`border-amber-500/40 bg-amber-500/10`. The Tailwind config has no `amber`
scale and `globals.css` defines no amber utilities, so both notices rendered as
plain 1px-grey boxes with **no tint and no warning border** — the classic
"class that renders as nothing" defect. Gate K (class integrity) found it the
moment the unavailable/escalation states joined the gate documents.
Fix: both notices now use the canonical `.apex-callout
apex-callout--warning` recipe (the same recipe the drafts queue's unavailable
state already used). Pin: gate K scans the state renders
(`gate_support::bot_state_documents`), plus the state-content tests in
`fixture_states.rs`.

### F2 — P1 — `.whitespace-pre-wrap` was missing from the committed stylesheet
Three surfaces render pre-formatted multi-line text with it: the assistant
transcript turns, the AI-draft reply bodies, and the demo result blocks. Since
the class was undefined: the transcript `<p>` collapsed every newline (a
multi-paragraph answer rendered as one blob) and the draft `<pre>` kept
`white-space: pre`, so a long reply line painted **outside its box**
(measured 315 px of content in a 206 px box at 320 px viewport). No gate had
seen it because the routes' empty states render no turns/rows.
Fix: `.whitespace-pre-wrap` added to the authored `globals.input.css` and the
built `globals.css`; `break-words` (an already-defined utility) added to the
transcript turn, the draft reply block and the demo result block so unbroken
tokens (long docs URLs) wrap instead of overflowing.
Pins: `lib.rs::bot_surface_wrap_and_hit_target_rules_are_in_both_sheets`;
gate K over the populated states; the layout gate over the new fixtures;
`fixture_states::bot_state_markup_pins_the_wrap_and_action_row_fixes`.

### F3 — P1 — the drafts action row squeezed the note input to 16-30 px
Each approve/reject row was `flex items-end gap-2` inside a `md:grid-cols-2`
cell. The 167 px-wide button wins the flex row, so at 320 px the "Approval
note" input measured **56 px wide**, and at 768 px (two columns in a 448 px
panel) **16 px** — unusable. The empty-state fixture never rendered a row, so
no gate had measured it.
Fix: the two action rows stack below `lg`
(`flex flex-col gap-2 lg:flex-row lg:items-end`); the grid keeps
`md:grid-cols-2` (defined utility). Measured after: field ≥ 191 px at 768 px,
≥ 231 px at 320 px.
Pins: `fixture_states::bot_state_markup_pins_the_wrap_and_action_row_fixes`
(asserts the stacked classes and that the squeezed row cannot come back); the
layout gate over the populated fixture.

### F4 — P2 — disclosure controls were below the 24 px hit target
Every `<summary>` on the bot surfaces ("Draft reply" 20 px, "Sources" 16 px
tall) was below the 24 px CSS bar. Fix: one global base rule for `summary`
(`min-height: 1.5rem; padding-block: 0.25rem;`) in both sheets — every
disclosure on every surface is now ≥ 24 px without changing the type size or
the disclosure marker. Pin:
`lib.rs::bot_surface_wrap_and_hit_target_rules_are_in_both_sheets`; the
capture's hit-target metric re-run shows only the sr-only skip link at its
hidden size (it expands on focus, ring present in the tab walk).

### F5 — P3 — citation links were 15 px tall
The assistant transcript's citation links (`<details>Sources`) measured
108×15 px. Fix: `inline-block leading-6` (both classes already defined) lifts
the link box to 24 px. Pin: covered by the populated-state capture
(`bots-ui-dogfood.mjs` hit-target scan reports zero non-sr-only targets below
24 px after the fix).

### F6 — P1 — dark-mode: brand pill at 2.74:1 (relayed from the live gate run)
`span.apex-pill.apex-pill--brand` ("first response") rendered `--primary`
(light brand-700 red, 185 28 28) on the dark card (24 24 27) = **2.74:1**
(needs 4.5). `.apex-pill--brand` carries its own color rule, so the generic
`.dark .text-primary` remap never reached it.
Fix: dark (and `:root:not(.light)`) step the pill's text **and border** to
brand-400 (248 113 113) in both sheets → ~6.5:1. Pin:
`lib.rs::bot_surface_dark_aa_overrides_are_in_both_sheets` (asserts the rules
in both sheets and computes the AA pairs).

### F7 — P1 — dark-mode: success flash ink at 1.27:1 (relayed from the live gate run)
`div.apex-flash` success banners (and the reveal-once secret banner) pair
`bg-success-50` with `text-success-900`; in dark the wash remaps to 39 39 42
while success-900 stays near-black (9 9 11) = **1.27:1** — the banner text was
effectively invisible.
Fix: dark (and `:root:not(.light)`) step `.text-success-900` to the near-white
success-100 → ~14:1. Checked the other consumers: the flash banner and the
reveal-once secret sit on the remapped dark wash (fixed); `.apex-auth-notice`
is unaffected (its later `.dark .apex-auth-notice` rule sets the foreground).
Pin: the same `bot_surface_dark_aa_overrides_are_in_both_sheets` test + the
contrast gate over the flash fixtures in all three theme modes.

### F8 — P2 — authored/built stylesheets had drifted (7 dark tokens)
The authored `globals.input.css`'s two dark token blocks still carried the
pre-palette-policy values (`--card: 18 18 21`, `--border: 39 39 42`,
`--secondary/--muted: 24 24 27`, `--surface-100: 24 24 27`,
`--surface-200: 39 39 42`, `--input: 39 39 42`) while the served built sheet
has the audited values (`--card: 24 24 27`, `--border: 82 82 91`, …). A future
rebuild from the authored sheet would have silently regressed the dark theme.
Fix: the authored sheet's dark tokens now match the built sheet exactly (both
`.dark` and `:root:not(.light)`); no served output changed. Note: the
`--card: 24 24 27` reconciliation is also what the surface-ladder test pins.

---

## 3. Bar-by-bar verification

1. **WCAG AA (pixel gate + gate suites)** — contrast gate PASS: 0 AA failures
   /99 pages /278 runs incl. the 13 state pages × light/dark/dark-class;
   classifier self-test 12/12; gate report records the revision.
   ui-foundation gates J (theme contrast), K (class integrity), L, the
   surface-ladder and palette-policy pins, full-skeleton goldens: 470 lib + 12
   bin + 1 integration tests green, `cargo fmt --check` clean. **Zero exceptions.**
2. **Layout** — layout-spill gate: 0 findings on both bot surfaces across all
   runs (desktop 1280/1440 + mobile 390/375, three theme modes). The capture
   adds 320/768/1280: 0 document overflow, 0 non-sr-only clips, 0 text spills. Long
   content wraps (F2/F3). Layout shift on a new turn: SSR PRG navigation with
   no client script — see §4 for the live measurement. Buttons/controls:
   `.apex-btn` is 44 px; every `<summary>`/link now ≥ 24 px (F4/F5).
3. **Keyboard** — real Tab walks over all 78 state/theme/width runs: every
   focus stop carries a visible ring (0 ringless), no focus trap, no repeated
   stop; the skip link is the first stop, there is exactly one `h1` per page and
   the heading outline stays h1 → h2 → …; the draft `<details>` and the
   citation `<details>` are native keyboard-operable (no JS).
4. **Copy / honesty** — the capture's copy scan (internal route paths, source
   file names, raw error text, internal id shapes, operator vocabulary on the
   web surface) is clean on all 78 runs. The only hits are "tenant" on the
   control-plane drafts page, which is the operator surface where that
   vocabulary is correct (the page labels the column "Workspace"). Empty,
   unavailable and flash states all state what happened and what to do; the
   rate-limit flash names the reason; the visual disabled/error states render.
   One live copy defect found out of slice — see F9.
5. **No visual regression** — the full-skeleton goldens (including
   `goldens/web/assistant.html` and `goldens/control-plane/reviews_ai-drafts.html`)
   pass unchanged; the fixes only affect populated/notice markup that the
   route goldens do not cover, plus CSS. No golden was regenerated (none needed
   to be).

### F9 — P1 — the 403 feature-flag-disabled state was masked as an outage (found here; fixed in the working tree by the assistant/ai_chat owner)
`POST /web/assistant/message` (`crates/api-server/src/routes/web.rs`, the
`session_turn_inner` match) handled `RateLimitedMessage` and `Validation`
explicitly but let `ApiError::Forbidden` fall into the generic arm →
**"The assistant is temporarily unavailable. Please try again."** A tenant
whose `ai_chat` feature flag was disabled (403 with "the AI assistant is not
enabled for this tenant") was told the service was down instead of that the
capability is switched off for them; the GET `/assistant` page was not
flag-gated either, so it rendered the full form and only failed on submit —
the bar's "disabled-flag state names the reason" was not met live.

Status: the assistant/ai_chat fix owner landed the fix in the working tree
while this pass ran (`AssistantPageData::capability_disabled`, the loader
reads the flag, the page renders the honest notice **and no message form**,
and the POST names the reason). This pass added the matching state fixture so
the browser/in-crate gates cover it: `web-assistant-disabled`, with a test
that asserts the reason is named, the form is absent, and the empty-state
prompt is absent. Live re-verification of the fixed state (flag override →
page) is part of §4.

---

## 4. Live states (rebuilt image) — EXECUTED

Stack/evidence: api-server image `sha256:9fc3894c054ccdf16c149a8f30e696823c4af6adb28eab74110b1b2f19e7c22a`
(started 2026-10-07T21:34:57Z), worker `sha256:8c5c40a008bd9fe4b9efaaf256f9f1ab5ccde669913dbdd42c9c45e2e9948a42`;
`/health/live` ok, `/health/ready` db+redis+schema ok; reviewed revision `0557e55d` with a
202-file dirty working tree (161 modified, 41 untracked — this pass's fixes plus the other
in-flight agents' work). Sessions were provisioned through the product's own flows: a customer
session (signup → Mailpit verification → MFA) and a **MFA-backed control-plane operator**
(signup → SQL promotion to the system tenant → `/web/cp/login` → the product's web MFA
enrollment on `/cp/security` → re-login → `/web/auth/mfa/verify`; the CP gate correctly refuses
non-MFA operators by redirecting them to the security page).

### Console assistant — live states

| State | Live result |
|---|---|
| empty / current history | rendered with the real session identity; form present |
| first message | PRG post → 303 → transcript grew (2 → 4 turns); flash "The assistant answered."; grounded answer with the escalation notice ("I couldn't produce a verified answer… flagged it for the support team") |
| long single message | 3,927-char message posted; turn rendered with `white-space: pre-wrap` + `overflow-wrap: break-word`, transcript/document overflow **0 px** |
| long conversation | 12-turn (session window) transcript rendered after the probes |
| service error | covered by the fixture render (live trigger would require breaking the AI service) |
| rate-limited 429 | **observed live**: after the per-user window, the page renders the honest flash "The assistant is receiving too many questions right now. Please retry in a minute." |
| feature-flag-disabled 403 | **observed live** (after the 30 s flag-cache TTL), on the interim image and re-confirmed on the FINAL image: the page names the reason ("The assistant is not enabled for this workspace" / "switched the AI assistant off"), renders **no message form**, no empty-state prompt; a direct POST stays on the refused page; after removing the override the form returns. Fixture `web-assistant-disabled` pins the same render. |
| history-loading / typing / streaming | not applicable (zero-JS SSR; see §1) |

### Drafts review — live states

| State | Live result |
|---|---|
| populated queue | 100 rows (the loader's cap) of live/legacy test data rendered at 320/768/1280 both themes |
| detail expand | `<details>` opens; the reply `<pre>` computes `pre-wrap` + `break-word`, `scrollWidth == clientWidth`, document overflow 0 |
| approve feedback — malformed row | honest, named refusal: "draft is missing tenant or sender; reject it instead"; row stays pending |
| approve feedback — consent gate | honest, named refusal: "marketing consent required for visual-audit@apexmail.local: no marketing consent on file — recipient must opt in"; row stays pending. Re-confirmed live on the FINAL image. |
| reject feedback | success flash "Draft rejected." (verified against the DB state) |
| empty / unavailable | covered by the fixture renders (live empty would require draining the queue; live unavailable would require breaking the store) |

### Live keyboard / copy

Twelve live runs (2 surfaces × 2 themes × 3 widths), real Tab walks: every focus stop has a
visible ring (0 ringless), no focus trap, exactly one `h1` per page, skip link first. The copy
scan on the live DOM found no internal route paths, source names, raw errors or identifier
shapes (the CP page's operator vocabulary is allowed there by design).

### Browser smoke lane (re-run as instructed)

`BROWSER_TEST_BASE_URL=http://127.0.0.1:8080 tools/run-browser-smoke.sh` → 22 desktop
checks, **5 pass / 17 fail**, and none of the failures is on a bot surface or caused by
this pass's changes:
* every control-plane check fetches its route on `localhost`, which this image maps to the
  **web** surface (`UI_WEB_HOSTS=localhost,127.0.0.1,app.apexmail.ee`;
  `UI_CONTROL_PLANE_HOSTS=admin.localhost,cp.localhost,…`) → `/sales`, `/tenants`, `/jobs`,
  `/alerts`, `/billing/plans` … answer 404 for the lane. The same pages were verified
  manually on `admin.localhost` with the MFA session (drafts queue 100 rows, security page,
  303-to-login after the intended CP idle timeout).
* `web-dashboard` / `login` checks expect an anonymous render or copy the current pages do
  not carry ("Security verification").
* the marketing checks assert the old title `ApexMail - Enterprise Email API for Developers`;
  the live marketing host answers 200 with the current title `Transactional Email API & SMTP
  Infrastructure | ApexMail` (compare passed).
The lane's host mapping/expectations are stale relative to the rebuilt image's env; the fix
belongs to the harness owner (`tools/browser_smoke.py`), not to the shared UI primitives.

### Live-only defects found (fixed in the tree; live re-verification needs the next image build)

### F10 — P1 — the console header overflowed at 768 px with a real session identity
The static fixtures render the shell **without** a session identity, so no gate had ever seen the
header at real width. Live, the plan label + `dogfood-1f42911cc0@dogfood.test` + avatar pushed
`div.flex items-center gap-4` to 787 px in a 768 px viewport (**19 px document overflow**, both
themes). Fix (shared shell): the plan label is secondary and now renders from `lg`
(`hidden lg:flex`), the identity block and both flex ancestors carry `min-w-0`, and the
name/email lines `truncate` — a long address ellipsizes instead of widening the page. Pins: the
state fixtures now carry a realistic session identity (name, long email, plan label) so the
layout/capture gates exercise the real header; `fixture_states::state_fixtures_carry_a_truncating_session_identity`;
the regenerated skeleton goldens record the intended header-class diff (31 files, 1 line each).

### F11 — P1 — a long sender address overflowed the drafts row meta at 320 px
Live rows carry long addresses (`capped-787ff32e256c4c618025bd9495cd19e2@example.com`); "From … ·
Workspace …" is one unbroken token and pushed the document **60 px** at 320 px (the fixture had a
short address, so the empty/short-row renders never showed it). Fix: the row meta line carries
`break-words`; the populated fixture now seeds the real long address and the markup test pins the
class.

**Live re-verification on the final image** (`sha256:8977957c874234615ce37c904b26161cc41a1bf8fcbc00f548ba36aaefbcd3a5`,
started 2026-10-07T22:33:18Z; worker + ai-service also restarted): the 12-run live capture is
clean in both themes and all three widths — assistant 768 px overflow **0** with the real
identity rendered (plan label at `lg`, email ellipsized), drafts 320 px overflow **0** with the
live long-sender rows, every run's only sub-24px target is the sr-only skip link (which expands
on focus), 0 ringless focus stops, 0 traps. F10 and F11 are **live-verified closed**.
(Method note: the capture tool now screenshots the measured state before the keyboard walk; an
intermediate collection had shown a transient sidebar artifact in one dark run — unreproducible
in a direct probe and in the re-run, 12/12 clean.)

## 5. Residuals

| Residual | Status | Why |
|---|---|---|
| Layout gate RED on `control-plane /sales` + `/cp/sales` and `/cp/demos` | **CLOSED (F12/F13, §7)** | Fixed in the shared views/primitives; `layout-gate.sh` re-run: **0 findings across 1116 runs**, contrast gate still PASS 0 AA. |
| F10/F11 live re-verification | **CLOSED** | Re-captured on the final image (`reports/bots-ui-live-final/`): 12/12 runs clean, both defects overflow-0 live. |
| `bg-success-50` dark remap differs between the two authored blocks and the built sheet (authored `9 9 11 / 0.35` vs built `39 39 42 / 0.85`) | observation | Pre-existing; left as-is deliberately — changing the wash would change every success chip surface; the ink fix (F7) makes both values AA-safe. Owners of the success tokens should reconcile. |
| Raw tenant id shown as "Workspace &lt;id&gt;" on the CP drafts row | observation, no change | Operator surface; the identifier is the operator's working key and the labels use the customer word. |
| Browser smoke lane | **CLOSED (F14, §7)** | `tools/browser_smoke.py` updated (env-driven CP/marketing hosts, login-gate + optional authenticated fragment model, shipped copy); 22/22 PASS anonymous and authenticated. `/alerts/rules` answers 501 (honest not-implemented page) — flagged for the CP owner. |
| `pixel-suspect` samples (dark banners, sparse cells) | non-failures | The gate treats them as non-AA (DOM math authoritative on solid backgrounds); the classifier self-test proves the pipeline. |

## 6. Fix inventory (all with tests)

| File | Change | Pin |
|---|---|---|
| `crates/ui-foundation/src/fixture_states.rs` (new) | the 11 bot states, their data, renders and content/honesty tests | 8 tests incl. markup pins |
| `crates/ui-foundation/src/gate_support.rs` | `gate_documents` now includes the bot-state renders (gates J/K scan them) | gates J/K |
| `crates/ui-foundation/src/bin/export_visual_fixtures.rs` | full-route export emits the state fixtures + manifest entries; integration test | `full_route_export_includes_every_bot_state_fixture` |
| `crates/ui-foundation/src/leptos_views.rs` | callout notices (F1), wrap+break (F2), stacked action rows (F3), citation link size (F5) | `fixture_states` pins + gate K + layout gate |
| `crates/ui-foundation/assets/globals.input.css` + `assets/globals.css` | `.whitespace-pre-wrap` (F2), `summary` hit target (F4), dark pill + success ink (F6/F7), authored dark-token sync (F8) | `lib.rs` CSS pins, contrast gate |
| `tools/contrast-audit/fixtures/**` | regenerated from the tree + 13 new state files (22 manifest entries) | contrast + layout gates |
| `tools/contrast-audit/bots-ui-dogfood.mjs` (new) | fixtures/live capture: screenshots, overflow/clip/hit-target metrics, tab walk, copy scan | — (evidence tool) |
| `crates/ui-foundation/src/shell.rs` | F10: plan label `hidden lg:flex`; identity `min-w-0` + `truncate`; header flex chain `min-w-0` | `state_fixtures_carry_a_truncating_session_identity` + capture at 320/768/1280 + goldens |
| `crates/ui-foundation/src/leptos_views.rs` (drafts row) | F11: row meta `break-words` | `bot_state_markup_pins_the_wrap_and_action_row_fixes` + capture at 320 |

---

## 7. Residual sweep — the last two layout-gate pages + the smoke lane (2026-10-07, same slot)

### F12 — P1 (fixed) — the sales JSON-mutation code chips spilled their card at mobile

`control-plane /sales` + `/cp/sales`: the review note
`POST /v1/admin/autopilot/decisions/:id/review` (and the replay / mode / pause /
resume / kill-switch chips) is one unbreakable token; at 375 px it spilled 72 px
out of `#sales-exceptions` (`text-spills-box` + `escapes-card`, both themes).
Fix: all six chips carry `break-words` (an already-defined utility), so the
endpoint wraps inside the chip. Pin:
`lib.rs::sales_code_chips_and_table_wrapper_layout_pins` (renders `/sales` and
asserts the chip class) + the layout gate.

### F13 — P1 (fixed) — the demos sessions table widened the document at mobile

`/cp/demos` at 375 px: `doc-horizontal-overflow` 23 px. Root cause found by
probing the box chain: the `sr-only` label inside the Actions `<th>` is
`position: absolute` with **no positioned ancestor**, so its static position (the
table's right edge, 397 px inside the wrapper's scroll area) is measured against
the document and is NOT clipped by the `.apex-table-wrap` scroll container —
the table itself scrolls correctly (wrapper 311 px, `overflow-x: auto`), but the
abspos label escaped the clip. Fix (shared primitive): `.apex-table-wrap` is now
`position: relative` in **both** sheets, so every table wrapper contains its
absolutely-positioned descendants (the data-list variant already passed
`relative` in markup; the primitive now guarantees it). While there, the
authored rule was reconciled with the built one (it lacked
`overflow-x: auto`/radius — another authored↔built drift). Pin: the same test
(asserts a `.apex-table-wrap` rule with `position: relative` + `overflow-x:
auto` in both sheets) + the layout gate.

**Result**: `tools/contrast-audit/layout-gate.sh` → **0 findings across 1116
runs** (was 10 on these two pages); `gate.sh` → PASS **0 AA / 99 pages / 278
runs**; `cargo test -p ui-foundation` → **472 lib + 12 bin + 1 integration**;
fmt clean; goldens regenerated only for the intended sales/demos diffs.

### F14 — harness — browser smoke lane updated to the current surfaces

`tools/browser_smoke.py` (not the product) was stale in three ways and is now
green on the final stack in **both** modes:
* **CP host**: the lane fetched every control-plane route on `localhost`,
  which this stack maps to the *web* surface (`UI_WEB_HOSTS`), 404ing each.
  The CP host now comes from `BROWSER_TEST_CP_HOST` (default `admin.localhost`,
  matching `UI_CONTROL_PLANE_HOSTS`); the marketing host likewise from
  `BROWSER_TEST_MARKETING_HOST` (default `apexmail.ee`).
* **Gated routes**: `/dashboard` and every CP route are behind the session
  gate (P0 route gating), so an anonymous fetch renders the honest login page.
  The anonymous expectations now assert that gate (web login copy / CP
  "Operator access"); an optional authenticated mode
  (`BROWSER_TEST_WEB_COOKIE` / `BROWSER_TEST_CP_COOKIE`) asserts the real
  console content instead — the lane grew a small `auth_cookie_env` /
  `authed_fragments` / `allowed_statuses` model for this.
* **Stale copy** (product changed, assertions updated to shipped copy):
  login "Security verification" → the password-recovery affordance; dashboard
  KPI fragments → "Overview" / "Monitor your campaign performance"; marketing
  title "ApexMail - Enterprise Email API for Developers" → the current
  "Transactional Email API & SMTP Infrastructure" + current hero/API-console
  headings; CP empty-state fragments → each page's shipped heading/subtitle.
  No copy regression was found — the old assertions predated the current pages.

Run results: `22/22 PASS` anonymous (default) **and** `22/22 PASS`
authenticated (session cookies), exit 0 each.

**Observation (not a lane bug)**: `/alerts/rules` answers **501 "Alert rules
are not implemented"** (honest not-implemented page; not linked from `/alerts`;
the lane asserts the shipped page via `allowed_statuses=(501,)`). Flagged for
the control-plane owner — the docs capability table already lists
alerts-rules as NotYetImplemented, so this is an honest page, not a copy
regression.

### Fix inventory additions

| File | Change | Pin |
|---|---|---|
| `crates/ui-foundation/src/leptos_views.rs` | F12: `break-words` on the six sales JSON-mutation chips | `sales_code_chips_and_table_wrapper_layout_pins` + layout gate |
| `crates/ui-foundation/assets/globals.css` + `globals.input.css` | F13: `.apex-table-wrap` `position: relative` (+ authored rule reconciled with the built one) | same test + layout gate |
| `tools/browser_smoke.py` | F14: env-driven CP/marketing hosts, login-gate/authenticated fragment model, shipped copy | 22/22 PASS in both modes |
