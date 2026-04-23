# Premium Experience Spec

Canonical implementation contract for premium UX across the Rust-served `web` and `control-plane` surfaces plus `apps/marketing` and `apps/marketing-zola`.

## 1) Spacing Rhythm

- Use `--space-*` tokens only for layout rhythm.
- Standard section rhythm:
  - section-to-section: `--space-12`
  - title-to-subtitle: `--space-3`
  - subtitle-to-actions: `--space-4`
  - card internal vertical rhythm: `--space-2` / `--space-3`

## 2) Elevation Ladder (5 Levels)

- `elevation-0`: flat / border only
- `elevation-1`: subtle resting card shadow
- `elevation-2`: hover/interactive card shadow
- `elevation-3`: overlay surfaces (drawers/popovers)
- `elevation-4`: modal/dialog emphasis

Rules:
- Use tokenized utility classes (`shadow-premium`, `shadow-premium-hover`) or approved component variants.
- Do not add ad-hoc one-off shadow literals in feature components.

## 3) Motion Curves + Timing

Canonical durations:
- `--motion-duration-120`
- `--motion-duration-180`
- `--motion-duration-240`
- `--motion-duration-320`

Canonical easing:
- `--motion-ease-enter`
- `--motion-ease-exit`
- `--motion-ease-feedback`

Rules:
- No `transition-property: all` in shared/global component classes.
- Transition only: `color`, `background-color`, `border-color`, `box-shadow`, `transform`, `opacity`.
- Motion intensity classes must map to canonical durations: `none/subtle/standard/emphasis`.
- Hover transform budget: max `translateY(-2px)` and max `scale(1.01)`.
- Skeleton and shimmer loaders must use the shared `skeleton` / `skeleton-shimmer` pattern and duration tokens.

### 3.1 Route Transition Policy

- Default product routes (`web`, `control-plane`) should not animate layout-level route transitions.
- Only micro-transitions are allowed during route changes (header/action fade at <= `180ms`).
- Marketing routes may use subtle section reveal motion, but must honor reduced-motion and duration tokens.
- Redirect/protected-route transitions should prioritize continuity placeholders over animated scene changes.

## 4) Interaction State Language

Required state set per primitive:
- `default`
- `hover`
- `focus-visible`
- `active`
- `disabled`
- `loading`

All states must:
- be token-driven,
- be readable in light + dark modes,
- avoid color-only meaning for critical status.

## 5) Icon Style Contract

- Source icons only from each app’s `components/ui/icons.tsx` module.
- Keep icon stroke/weight visually consistent per surface.
- Avoid decorative icon variance in dense data UI.

## 6) CTA Hierarchy Rule

- One primary CTA per section/group.
- Optional one secondary CTA.
- Additional actions must be tertiary/ghost, never competing with primary emphasis.

## 7) Enforcement

- Enforced by: `docs/development/style-system.md`, `docs/development/ux-qa-checklist.md`, PR template checklist, and CI visual snapshot step.
