# UX QA Checklist

Shared pre-release UX checklist for `web`, `control-plane`, and `marketing` surfaces.

## 1) Async and State
- Use explicit loading, empty, error, and success states for async content.
- Keep card/table dimensions stable while loading to avoid layout shift.
- Provide retry actions on failed fetch/mutation states.
- Show `Last updated` metadata on analytics and operational cards.

## 2) Inputs and Forms
- Add inline field-level validation before submit.
- Add top-level error summary for assistive technologies.
- Ensure all search fields include clear/reset controls.
- Add unsaved-changes guards for long multi-section forms.

## 3) Accessibility
- Ensure visible focus indicators on all interactive elements.
- Ensure keyboard parity for custom controls (`Enter`/`Space`).
- Trap focus in custom dialogs and restore focus on close.
- Ensure icon-only actions have accessible labels.
- Add `aria-live` where status/toast/validation updates are announced.

## 4) Tables and Lists
- Use consistent pagination controls with first/previous/next/last.
- Use consistent sortable-column affordances and `aria-sort` states.
- Enable keyboard-friendly multi-select workflows.
- Add sticky headers on long, scrollable tables.
- Provide no-result guidance with quick filter-reset actions.

## 5) Status and Visual Semantics
- Avoid color-only status communication; always pair with text + icon.
- Validate warning/success/error contrast in both light and dark themes.
- Standardize status-chip taxonomy across pages.
- Include timezone context on schedule/reporting surfaces.

## 6) Evidence and Change Tracking
- Record each completed UX fix in `UI_Fixes.md` with file evidence links.
- Run diagnostics on touched files before checkoff.
- Keep changes minimal and aligned to existing design tokens/components.
