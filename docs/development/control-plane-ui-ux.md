# Control Plane UI/UX Standards

Last updated: 2026-02-27

This document defines the global UI/UX contract for all Control Plane screens in `apps/control-plane`.

## Goals

- Keep all operator pages visually and behaviorally consistent
- Use shared design tokens only (no one-off palettes)
- Ensure responsive and keyboard-accessible workflows
- Reduce per-page UI drift by centralizing layout primitives

## Global Layout Contract

All control-plane pages must use the shared page system from `apps/control-plane/src/app/globals.css`:

- `.cp-page-frame`: shell-level container used by `ControlPlaneShell`
- `.cp-page`: default page width and vertical rhythm (`max-w-7xl` + spacing)
- `.cp-page--narrow`: narrower content mode (`max-w-6xl`)
- `.cp-page--wide`: full-width mode for dense data views
- `.cp-page-header`: standardized title/actions header row
- `.cp-page-title`: page title typography
- `.cp-page-subtitle`: page subtitle typography
- `.cp-section`: default card section treatment

### Required Root Structure

Each page should start with:

1. `div.cp-page` (or `.cp-page.cp-page--narrow` / `.cp-page.cp-page--wide`)
2. Optional `div.cp-page-header`
3. Sections using `.cp-section` for primary content blocks

## Color and Status Rules

Use semantic token classes first:

- Success: `bg-success/10 text-success border-success/20`
- Warning: `bg-warning/10 text-warning border-warning/20`
- Error: `bg-destructive/10 text-destructive border-destructive/20`
- Primary action: `bg-primary text-primary-foreground`

Avoid introducing page-local hardcoded palettes unless explicitly required by data visualization.

## Interaction Standards

- Primary actions use primary button styling and minimum 44px hit area
- Destructive actions use destructive semantic classes and clear wording
- Toasts and dialogs should be dismissible and keyboard-friendly
- Mutating actions should display success/error feedback

## Accessibility Baseline

Every page should meet:

- Keyboard navigation for all interactive rows/items
- `aria-modal`, `role="dialog"`, and Escape handling for dialogs
- Non-color status indicators for critical labels where feasible
- Proper label associations for form controls

## 2026-02-27 UI Sweep Outcome

A global consistency sweep was applied:

- Unified page container classes across control-plane page routes
- Enforced shell-level page frame wrapping in `ControlPlaneShell`
- Added reusable page primitives in `globals.css`
- Normalized sales page accents to semantic design tokens

## Migration Checklist for New Pages

- [ ] Root uses `.cp-page` variant
- [ ] Header uses `.cp-page-header`, `.cp-page-title`, `.cp-page-subtitle`
- [ ] Main sections use `.cp-section`
- [ ] Buttons and badges use semantic token classes
- [ ] Dialogs and overlays follow accessibility baseline
- [ ] No hardcoded one-off color palette for standard UI states
