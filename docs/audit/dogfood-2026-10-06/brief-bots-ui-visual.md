# Brief — UI/visual dogfood: the chatbot + mailbot surfaces must be PERFECT

You are a rigorous UI/visual dogfooding agent. Repo root:
/Users/sabelakhoua/IdeaProjects/ApexMail. The compose stack serves the tree
under review (api-server being re-imaged; poll
`curl -s http://127.0.0.1:8080/health/live` and retry until it serves the
rebuilt image). Deliverable:
`docs/audit/dogfood-2026-10-06/dogfood-bots-ui.md` with per-surface,
per-state, per-theme evidence (screenshots/metrics) and verdicts.

## Surfaces
- Console assistant: `app.apexmail.ee` / `web.localhost` → `/assistant`
  (empty history, first message, typing/streaming, long conversation, long
  single message, error, feature-flag-disabled 403 state, rate-limited 429
  state, history-loading state).
- Drafts review: the admin/CP ai-drafts list + detail + approve/reject
  actions (`/reviews/ai-drafts` and the CP variants), empty queue, long
  subjects/bodies, many rows, disabled/none states, action feedback.
- Any chat widget/launcher rendered on the console (grep the views).
- The same pages' mobile width (320px), 768px and 1280px.

## Bar (per state, in BOTH light and dark)
1. WCAG AA: run the pixel gate (`tools/contrast-audit/gate.sh` — it must
   stay 0 AA failures and it must INCLUDE these pages; add fixtures if a
   surface is missing there) and the ui-foundation gate suites (J/K/L,
   surface-ladder). Zero tolerated exceptions.
2. Layout: no clipped/truncated/overlapped content, no horizontal overflow,
   long content wraps, no layout shift when a new turn lands, sensible
   scroll behavior, buttons hit >= 24px CSS.
3. Keyboard-only: complete every flow with Tab/Shift-Tab/Enter/Space;
   focus-visible rings on every control; no focus traps; the skip link and
   headings order stay sane.
4. Copy/honesty: no internal ids/paths/secrets/raw errors; empty and error
   states are honest ("what happened, what to do"); disabled-flag state
   names the reason; nothing English-leaks in localized shells beyond the
   documented conventions.
5. No visual regression against the exported baselines beyond intended
   diffs (regenerate goldens ONLY if the change is correct and intended).

## Fixes
Owner directive: fix GLOBALLY through shared primitives/templates
(`crates/ui-foundation/**` primitives, leptos_views, globals.input.css +
the built globals.css — keep authored/built sheets in sync) — never inline
one-off CSS. Every visual fix gets a pinned test where the house pattern
exists (theme_contrast/class_integrity/surface-ladder/goldens). Re-run: the
contrast gate, ui-foundation suite, the browser smoke lane, and the
`/assistant` + drafts pages in both themes. Zero unexplained residuals.

Rules: no deploy; keep every touched gate green; report NOT-VERIFIED with
the reason when a state cannot be reached (e.g. rate-limit windows).
