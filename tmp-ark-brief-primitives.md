# Brief: primitives.rs → ARK (agent lane P)

Repo: /Users/sabelakhoua/IdeaProjects/ApexMail (branch main). You own ONLY
`services/mail-server/crates/ui-foundation/src/primitives.rs` (its code AND its `#[cfg(test)]`
module). Do not edit any other file. Never touch packages/ (KiwiCaptcha, separate repo).

## Context
The console moved to the ARK design system. Authority: `crates/ui-foundation/assets/ark.css`
(read its header "THE LAW" and the component section). A mechanical sweep already rewrote the
class strings in primitives.rs (raw Tailwind design utilities → apex-* vocabulary or dropped),
so several render functions now emit incoherent markup and their tests fail. Your job: make
every primitive render honest ARK markup, and re-home every test to the ARK contract. NEVER
delete a test to make it pass: when a component's old behaviour is banned by the law, its
test becomes a test that the banned pattern is GONE and the replacement is present.

## The ARK contract per primitive (keep every pub struct/field/fn signature — call sites in
leptos_views.rs depend on them; only render output and docs change)
- Button: `apex-btn` (+`apex-btn--primary` for the primary/default-filled variant,
  `apex-btn--danger` for destructive, `apex-btn--sm` for the small size, `apex-btn--link` for
  link/ghost). `loading` → `aria-busy="true"` + `apex-btn--busy` + disabled; NO spinner SVG.
  `left_icon`/`right_icon`: ARK is icon-free as chrome — do not render icon markup (keep the
  fields; document them as ignored). Keep `data-variant`/`data-size` attributes.
- Input/Textarea/NativeSelect/Select: `apex-input` (textarea adds `apex-textarea`; selects use
  `apex-select`, wrapped in `<span class="apex-select-wrap">` so the ▾ caret renders). Keep
  aria/required/describedby/name/id behaviour exactly. Counter/help lines → `apex-help`.
- Checkbox/NativeCheckbox/RadioGroup: plain native controls inside an `apex-check` row; keep
  the keyboard contracts (they are behavioural facts of native controls).
- Switch: BANNED. Render as a native checkbox in an `apex-check` row (`role="switch"` must not
  appear anywhere). Tests: assert `role="switch"` is absent and the checkbox is present.
- Slider: native `<input type="range">` with `apex-input`; no custom track markup.
- Label: `apex-label`.
- Progress: no bars/meters. Render a ledger sentence `<span class="apex-meta">{value} of 100</span>`
  (with the value), `role="progressbar"` + aria-valuenow kept for assistive tech.
- Badge: a status word — `<span class="apex-status [apex-status--on|--warn|--fail]">label</span>`
  mapped from the variant (success/default → --on; warning → --warn; destructive/error → --fail;
  outline/secondary → no modifier). No icon markup.
- StatusIndicator: same `apex-status` word; map statuses: active/sent/verified/delivered/enabled
  → --on; pending/draft/scheduled/paused → (no modifier); warning/degraded → --warn;
  failed/bounced/error/disabled/suspended → --fail.
- Card: `<section class="apex-panel">` with `<h4 class="apex-panel__head">title</h4>` and a
  `<div class="apex-panel__body">body</div>`; `interactive` adds nothing visual (no hover lift).
- Avatar: `<span class="apex-avatar">INITIALS</span>` (monogram text, no circle, no image chrome).
- EmptyState: `<div class="apex-empty-state"><p class="apex-empty-state__title">…</p><p>…</p>
  [action as apex-btn]</div>`.
- Skeleton (both forms): `apex-loading` with `apex-loading__row` / `apex-loading__bar` children —
  NO `animate-pulse`, no rounded shapes; the dimensioned form sets the bar width via a
  structural `w-*` class or inline `style="width:…"` (width is structural, allowed).
- Dialog / AlertDialog: modals are BANNED (confirmation is a page). Render an inline
  `<section class="apex-notice [apex-notice--fail for destructive]"><b>title</b><p>description</p>
  <div>actions as apex-btn</div></section>` — no overlay, no `role="dialog"`, no `aria-modal`.
  Tests assert absence of role=dialog/aria-modal and presence of the notice.
- Popover / Tooltip: BANNED. Tooltip renders its text as an inline `<span class="apex-help">`
  footnote-style line (visible, no hover dependence). Popover renders its content inline inside an
  `apex-panel` (always visible). Keep the `positioning_contract()` API but make it return the
  inline-contract values documented in its struct; tests pin that no `role="tooltip"` is emitted.
- DropdownMenu: BANNED kebab. Render the items as inline underlined verbs:
  `<nav class="apex-row-actions">` with one `<a>`/`<button class="apex-btn--link">` per item;
  labels and shortcuts render as plain text. No `aria-haspopup`, no `role="menu"`.
- Accordion: native `<details>`/`<summary>` (zero-JS) with `apex-panel` styling; keep the
  keyboard/animation contracts as native-details facts (animation contract: none — document it).
- ScrollArea: `overflow-auto` wrapper, nothing else.
- Toast: BANNED. Render as `<p class="apex-statusline">message</p>` (outcomes land in the page).
- Charts (ApexLineChart/Bar/Area/Pie): keep the SVG; use `apex-chart-frame` + `apex-chart-legend`
  (+`__key`, `__sw`, `__sw--blue`, `__sw--hatch`); strokes `rgb(var(--primary))` / ink; no
  gradient fills (hatched `<pattern>` fills are allowed: the engraved texture is the one texture);
  pie → render as a ledger `apex-table` of label/value/share (no pie slices).
- Table: `<div class="apex-table-wrap"><table class="apex-table">`, `th` plain, numeric cells
  `apex-num`, caption as `<caption class="apex-meta">`.
- PaginationControls: `<nav class="apex-pager"><span class="apex-pager__sentence">Rows a–b of n</span>
  <a>Previous</a><a>Next</a></nav>`.

## Law (enforced by `python3 tools/check_ark_law.py` from the repo root — run it; your file must
show ZERO violations) and by GATE K (`cargo nextest run -p ui-foundation -E 'test(class_integrity)'`):
every class you emit must be apex-* (defined in ark.css) or a structural layout utility
(flex/grid/gap/p/m/w/max-w/relative/absolute/hidden/md:*/overflow-*/text-left/center/right/
whitespace-*). No colour/typography/rounded/shadow/ring/opacity/transition/animate/hover:/
data-[state]:* utilities. No middot `·` in copy. No icons as chrome.

## Done when
`cargo nextest run -p ui-foundation -E 'test(primitives)'` is fully green, `tools/check_ark_law.py`
shows zero violations for primitives.rs, and `cargo clippy -p ui-foundation --all-targets` has no
warnings from primitives.rs. Report: per-primitive change, tests re-homed, anything left.
