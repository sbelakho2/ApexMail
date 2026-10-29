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

---

## 8. Capability-wave pages (2026-10-08): /alerts/rules, /messages/:id/timeline, /domains/:id/tracking

Three pages postdate every UI fixture; dogfooded live plus new fixtures and
gates. Final-image evidence: api-server
`sha256:e14e12bd9c47ad9fdb3397a484613fadb31be6846f0153a3a077be2dc7f80568`
(started 2026-10-08T03:45:56Z — the rebuild that carries the F15 CSP fix), earlier
capability-wave image `fc35113eb887…` (01:56:07Z) for the state probes, worker
`87c7a488181d…`, ai-service `24d34aefc087…`.

### The headline finding — F15 (P1, fixed in the response layer, LIVE-VERIFIED on the final image): eight HTML pages rendered COMPLETELY UNSTYLED because their responses carried an API CSP with no `style-src`

Every HTML document built by the hand-written `html_page_response` path was
served with the minimal API CSP `default-src 'none'; frame-ancestors 'none'` —
no `style-src` — so the browser **blocked globals.css** and the page rendered as
raw browser-default HTML. Verified live on `/messages/:id/timeline` and
`/campaigns/c_1`: `getComputedStyle(document.body).fontFamily === "Times"`,
`background: transparent`, `document.styleSheets[0].cssRules` throws
SecurityError (CSP-blocked sheet), and the unstyled 5-column table is exactly
why the document overflowed **349 px at 320 px** (it fits at 768/1280, so the
layout gate's mobile width never saw it and the fixtures — which apply the sheet
normally — were clean). Affected handlers (all `html_page_response` callers):
contact edit, domain detail, **domain tracking**, **message timeline**, list
detail, campaign detail, and the SSR/404 fallbacks. Pages served through the
ui-foundation render pipeline (`/events`, `/dashboard`, `/assistant`, the drafts
queue) were unaffected — they set the browser CSP themselves.

Fix (shared response layer, `crates/api-server/src/app.rs` security-headers
middleware): a response with no CSP of its own now gets `browser_csp_header()`
(the same policy every rendered console page carries) when
`Content-Type: text/html`, and the minimal API policy otherwise. Pin:
`app::tests::html_fallback_pages_carry_the_browser_csp` (green; the existing
JSON-CSP pin still passes).

**Live re-verification on the final image** (`sha256:e14e12bd9c47ad9fdb3397a484613fadb31be6846f0153a3a077be2dc7f80568`,
started 2026-10-08T03:45:56Z): `/no-such-page` returns the full browser CSP with
`style-src 'self'`; every previously-unstyled page now computes
`body { font-family: "Inter Variable", system-ui …; background: #f4f4f6 }` with
the stylesheet readable (`cssRules` = 1088, no SecurityError):
`/messages/:id/timeline` (populated) at 1280 **and 320** (document overflow
**0**, was 349 px), the `?at=` past-timestamp state at 320 (0), `/campaigns/c_1`,
`/lists/l_1`, `/contacts/new`, and the 404 fallback. F15 is closed.

### F16 (P1, fixed by the coordinator in the same window): `plans.features` rows predated the capability waves, so both new capabilities were ungrantable by plan

All nine `plans` rows reported `time_travel_debugging=false` and
`custom_tracking_domain=false` while `builtin_plan_seed` and the shipped copy
grant them (Growth+ / Pro+). Entitlement resolution prefers the present-but-
stale DB JSON (`from_plan_features_json` defaults absent keys to false), so a
paying Growth/Pro tenant got the same refusal as Free. Proven live both ways:
free → the honest refusal naming the feature ("plan `free` does not include
`time_travel_debugging`. It ships with Growth and above."); with a per-tenant
`feature_flag_overrides` grant → the populated reconstruction and the tracking
configure flow. The coordinator has since corrected pro/growth/scale/enterprise
to the shipped flags, so the entitled states now render without overrides.

### Page-by-page, state-by-state (live, verified before the plans fix via the documented override escape hatch)

**`/alerts/rules` (CP) — full CRUD verified live**, both themes × 320/768/1280
via the state capture, plus form-level probes: list (existing rules render),
create (`Alert rule "UI visual dogfood rule" created.` + DB row), edit form
(`?edit=<id>` prefilled name/threshold, "fixed — delete and recreate" note for
tenant/metric), toggle (DB `enabled=false`, flash "Alert rule disabled."),
delete (DB row gone, flash). Empty/unavailable renders are covered by the new
fixtures (`No alert rules yet — create one above.` / "The rule list is
unavailable right now — this is a service problem, not an empty list." + the
error callout carrying the correlation reference). The blank-name fallback
("Unnamed rule (Emails sent)") is pinned in `fixture_states` tests.
Observations: the list's tenant cell shows the raw tenant id (operator surface —
consistent with the drafts page's working-key display); the unavailable state
still renders the create form (a create against an unavailable store fails with
its own honest error) — both noted, not changed.

**`/messages/:id/timeline` (console)** — populated reconstruction verified live
(6 transitions from `messages` + `email_queue` + `events`), plan refusal (free
tenant, named feature + "Growth and above"), tenant-scoped not-found ("That
message could not be found in this workspace."), and the past-timestamp
no-entry state. The route was **not data-aware in the shared router** (it always
rendered the static "No message selected" skeleton), so fixtures could never
audit the real page; wired now to render the shared `data_list_page(list,
"entry")` when data is present (identical to the api-server's live composition)
with the skeleton kept as the no-data fallback, and two state fixtures added
(`-populated`, `-insufficient`). **Fixed (F17, P2)**: the description, the "As of" KPI and the "When" cells
rendered the raw RFC 3339 timestamp with nanoseconds
(`2026-10-08T02:46:11.984213272+00:00`). The page-data builder now formats
through the same shared helper the events table uses (`data::relative_time`,
promoted to `pub(crate)`), keeping the raw RFC 3339 value on the wire and in
the cell's `title`/`datetime` slot — the one-timestamp policy. Pin:
`web::tests::timeline_page_data_formats_timestamps_with_the_house_helper`; the
timeline state fixtures were aligned to the house form (relative prose + raw
UTC in the title slot).

**`/domains/:id/tracking` (console)** — all six states reached live through the
product's own flow: parent-not-verified, not-entitled (free plan), configure
form, and configured **pending / verified / failed** (each with the CNAME target
and the Verify/Remove actions; the failed state carries the named reason).
**Coverage gap — CLOSED (F18)**: the panel was hand-rolled inline in
`crates/api-server/src/routes/web.rs`, and the route was absent from
`docs/development/ui-baseline-manifest.json`, so no fixture/golden/gate ever
saw it. Extracted into the shared view layer as
`crates/ui-foundation/src/tracking_domain.rs` (`TrackingDomainPanel`,
`TrackingDomainPanelRow`, `tracking_domain_panel_html`,
`web_domain_tracking_page` — markup moved byte-identical, `pub(crate)` → `pub`);
the ui router serves the route with `RouteData.tracking_domain`, the manifest
gained `/domains/d_1/tracking` (`canonicalPattern /domains/[id]/tracking`; web
38 → 39, total 127 → 128, routing test updated), the link gate registered the
three tracking POST endpoints, and **six state fixtures** (not-verified,
not-entitled, configure, pending, verified, failed) plus a content pin
(`tracking_domain_states_render_their_real_surfaces`) put every state under the
contrast/layout/class-integrity gates and the goldens. The api-server handler
now imports the shared types/renderer (`use ui_foundation::tracking_domain::…`)
and keeps owning the loaders, the entitlement gate and the POSTs — the live
markup is unchanged.

### Verification status at hand-in

* **In-tree + pinned**: F15 (browser CSP for hand-written HTML responses) and
  the timeline route wiring; `cargo test -p api-server -- csp security_headers`
  → 12/12 green (including the new `html_fallback_pages_carry_the_browser_csp`);
  `cargo test -p ui-foundation` → 475 lib + 12 bin + 1 integration green
  (goldens regenerated for the new route only);
  `cargo fmt -p ui-foundation -p api-server --check` clean.
* **Live-verified (pre-CSP-fix image)**: every state and action listed above;
  the pixels of the affected pages were unstyled, which IS the F15 evidence
  (screenshots under `tools/contrast-audit/reports/cap-wave-live/`).
* **Browser smoke lane docs**: the lane's stack usage is now documented —
  `tools/README.md` (both bullets) and the `run-browser-smoke.sh` header state
  `BROWSER_TEST_BASE_URL=http://127.0.0.1:8080` against the compose stack (the
  default `http://127.0.0.1:3000` is the legacy dev port), and the
  `--base-url` help says so. Re-verified with that exact command: **22/22 PASS**.
* **Closed on the final image**: the styled re-capture (both themes ×
  320/768/1280) ran over the three pages after the rebuild landed; F15's 320 px
  overflow is gone with the sheet applied (styled matrix under
  `tools/contrast-audit/reports/cap-wave-matrix/`). The re-capture also caught
  F19 (live tracking h1) — landed and pinned; its live re-check rides the next
  image build.

### Styled re-capture on the final image (post-CSP-fix)

* **F15 live-verified**: `/no-such-page` serves the full browser CSP; on
  `/messages/:id/timeline` (populated and `?at=` past states, 1280 and 320),
  `/campaigns/c_1`, `/lists/l_1`, `/contacts/new` and the 404 fallback the body
  computes `"Inter Variable", system-ui` on `#f4f4f6`, `cssRules` reads 1088
  (no CSP block), and the timeline's **320 px document overflow is 0** (was
  349 px unstyled).
* **Styled state matrix** (`tools/contrast-audit/reports/cap-wave-matrix/`,
  both themes × 320/768/1280): timeline populated + past-timestamp; the six
  tracking states; `/alerts/rules` populated. h1 exactly 1, 0 ringless focus
  stops, 0 focus traps, no copy leaks on any run. The alerts/rules page's
  8-column table extends past the viewport *inside its `.apex-table-wrap`
  scroll container* (doc overflow 0) — the intended wide-table pattern, noted
  so the collector's `elements-past-viewport` count is not misread.
* **F19 (P1 a11y, found by this re-capture, landed, LIVE-VERIFIED)** — the
  live tracking page had **no `h1`**: the api-server handler composed the bare
  panel while the fixture/golden used the shared page wrapper (headings started
  at the shell's `H3`). The handler now renders through
  `ui_foundation::tracking_domain::web_domain_tracking_page`. Pinned by the
  per-state `exactly-one-h1` assertions in
  `tracking_domain_states_render_their_real_surfaces`. **Live re-check on the
  F19 image** (`sha256:d53e1075d3154f34ebc2d528259269e99966b9fd234c9b0484d05a13a0509377`,
  started 2026-10-08T04:27:46Z): all six states (not-verified, not-entitled,
  configure, pending, verified, failed) render exactly one `h1`
  ("Custom tracking domain") and 0 document overflow. Closed.
  Observation (P3, not changed): the tracking page's document `<title>` still
  reads "Domain Detail — ApexMail" because `route_document_title` matches the
  generic `/domains/` arm; the fixture/golden share that title, so there is no
  live/fixture drift — a future polish could add a `/domains/{id}/tracking`
  arm ("Tracking Domain — ApexMail").

### Gates over the new fixtures (all green)

* `tools/contrast-audit/layout-gate.sh` → **0 findings across 1181 runs**
  (re-run on the frozen tree after the styled capture; timeline/alert-rules
  state pages AND the six extracted tracking-domain state pages included; both
  bot surfaces still clean).
* `tools/contrast-audit/gate.sh` → **PASS 0 AA / 112 pages / 317 runs**
  (re-run on the frozen tree).
* `cargo test -p ui-foundation` → **475 lib + 12 bin + 1 integration**, goldens
  included (regenerated only for intended diffs; the new route golden is
  `goldens/web/domains_d_1_tracking.html`).
* `cargo test -p api-server -- csp security_headers timeline_page_data` →
  15/15 green (the browser-CSP pin and the timeline timestamp pin included).
* `cargo fmt -p ui-foundation -p api-server --check` clean.

### Exact tree state handed to the final rebuild (2026-10-08 ~03:25Z)

| Area | State |
|---|---|
| `crates/ui-foundation/src/tracking_domain.rs` (new) | shared panel + page (F18); `lib.rs` registers it |
| `crates/ui-foundation/src/axum_router.rs` | `RouteData.tracking_domain` + `/domains/{id}/tracking` route; timeline route data-aware |
| `crates/ui-foundation/src/fixture_states.rs` | 11 new states (timeline ×2, alert-rules ×3, tracking ×6) + pins |
| `crates/ui-foundation/src/gate_support.rs` | the three tracking POST endpoints registered for gate I |
| `crates/ui-foundation/src/routing.rs` + `docs/development/ui-baseline-manifest.json` | `/domains/d_1/tracking`; web 39, total 128 |
| `crates/api-server/src/app.rs` | F15 browser-CSP dispatch for hand-written HTML responses + pin |
| `crates/api-server/src/routes/web.rs` + `web/data.rs` | F17 timestamp formatting via `data::relative_time`; panel types/renderer imported from ui-foundation |
| `tools/contrast-audit/fixtures/**` | re-exported (300 manifest entries) |
| `crates/ui-foundation/goldens/**` | regenerated (new tracking route golden; no other diffs) |
| Gates | layout 0/1181, contrast PASS 0 AA/112 pages/317 runs, ui-foundation 475+12+1, api-server pins 15/15, fmt clean |

### New fixtures/pins added by this section

| File | Change | Pin |
|---|---|---|
| `fixture_states.rs` | 5 new states: timeline populated/insufficient, alert-rules populated/unavailable/editing | `capability_wave_states_render_their_real_content` (+ existing honesty pins) |
| `axum_router.rs` | timeline route renders the shared data-list page when data is present | the two timeline state fixtures + the route render sweep |
| `app.rs` | HTML responses without their own CSP get the browser policy (F15) | `html_fallback_pages_carry_the_browser_csp` |
| `tools/contrast-audit/cap-wave-probes.mjs` (new) | live CRUD + state driver for the three pages | probe report + screenshots under `reports/cap-wave-live/` |
