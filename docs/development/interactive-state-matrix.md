# Interactive State Matrix

Cross-surface state matrix for shared primitives.

## Buttons

- Default: semantic background + readable foreground
- Hover: subtle emphasis increase (not a semantic meaning change)
- Focus-visible: ring token + offset
- Active: slight pressed state (opacity/transform optional)
- Disabled: reduced emphasis + no pointer affordance
- Loading: preserve button width; replace label with spinner+status text

## Inputs

- Default: `input` border token
- Hover: mild border emphasis
- Focus-visible: ring token + stronger border
- Active: same as focused
- Disabled: muted bg + muted text + blocked interaction
- Loading: skeleton/placeholder only when async-bound

## Cards (Interactive)

- Default: border-led hierarchy
- Hover: single elevation step up
- Focus-visible: ring on keyboard focusable cards
- Active: subtle press transform or border emphasis
- Disabled: muted content and no hover affordance
- Loading: fixed-height skeleton preserves layout

## Tables

- Default: clear row/column hierarchy
- Hover row: background tint only
- Focus row/cell: visible focus style
- Active selection: icon + text + color (non-color-only)
- Disabled rows: explicit label and muted visuals
- Loading: deterministic skeleton rows

## Status Badges

- Default semantic variants only (`success`, `warning`, `error`, `info`)
- Hover/active: optional contrast increment only
- Disabled: avoid semantic ambiguity
- Loading: skeleton placeholder where applicable

## Validation & Mutation Messaging

- Pending: `Saving…`
- Success: `Saved`
- Failure: `Retry`

Rules:
- Reserve helper/error text space to reduce layout jitter.
- Place inline validation next to source field and summarize at top when needed.
