# Apex Style System

Global reference for visual styling across customer console, control-plane, and marketing experiences.

## Style Name

The official visual style name is **Apex**.

Use “Apex style” in documentation, PR descriptions, and design review notes when referring to this system.

## Scope

This guide applies to:

- Rust `web` surface served by `services/mail-server/crates/api-server`
- Rust `control-plane` surface served by `services/mail-server/crates/api-server`
- `apps/marketing-zola` (must follow the same token and interaction contracts)

## Companion Specs

- `docs/development/premium-experience-spec.md`
- `docs/development/interactive-state-matrix.md`
- `docs/development/premium-performance-budgets.md`

## Goals

- **Precise:** predictable token contracts and state behavior.
- **Flexible:** controlled extension points for new product areas.
- **Consistent:** shared premium language across all app surfaces.
- **Accessible:** light/dark parity and clear semantic state signaling.

## Source of Truth

### Canonical Token Source

- `services/mail-server/crates/ui-foundation/assets/globals.css`
- runtime delivery via `services/mail-server/crates/ui-foundation/src/lib.rs` and `services/mail-server/crates/api-server/src/app.rs`

The shared Rust UI stylesheet defines canonical CSS custom properties for color, spacing, radii, and semantic states.

### Marketing Token Mapping

- `apps/marketing-zola/static/css/styles.css`

Rust-served browser surfaces consume the shared stylesheet directly; static marketing CSS should continue to mirror the shared token values where parity matters.

### Token Snapshots

- `web_colors.txt`
- `cp_colors.txt`
- `marketing_colors.txt`

Use snapshots for quick audits and docs, not as canonical definitions.

## Apex Token Contract

### Required Token Families

Every Apex surface should rely on these families:

- Foundation: `background`, `foreground`, `border`, `input`, `ring`
- Surface: `card`, `popover`, `surface-*`
- Brand: `primary`, `brand-*`
- Text hierarchy: `muted`, `muted-foreground`, `accent`, `accent-foreground`
- Semantics: `success`, `warning`, `error`, `danger`, `info`
- Shape/space/type: `--radius-*`, `--space-*`, `--font-*`

### Token Surfaces

The system defines two token surface layers:

- **`default`** — used by the Rust dashboard (`services/mail-server/crates/ui-foundation`). Sources: `globals.css`, `icons.rs`.
- **`marketing`** — used by the Zola marketing site (`apps/marketing-zola`). Sources: `styles.css`, `tailwind.config.js`. Mirrors the indigo brand palette from the dashboard.

Refer to [`docs/development/ui-design-token-baseline.json`](docs/development/ui-design-token-baseline.json) for the canonical token snapshot of both surfaces.

### Contract Rules

1. Product UI must not hard-code new hex/rgb literals for core component styling.
2. New tokens must be defined in the canonical token source before Tailwind exposure.
3. Component APIs should consume semantic tokens, not app-specific one-off color names.
4. New semantic tokens require both light and dark values in the same change.

### Token Anti-Patterns

- `transition-property: all` in shared/global classes.
- Component-local hard-coded semantic colors (`#ef4444`, raw `rgb(...)`) for shared primitives.
- Unmapped one-off spacing/radius values that bypass `--space-*` / `--radius-*`.

### Do-Not-Use Token/Style List

- Unscoped shadow literals in feature code for shared components.
- New ad-hoc semantic aliases not declared in canonical token source.
- Direct third-party icon imports in app source instead of local icon modules.

## Apex Visual Language

### Surfaces and Depth

- Prefer `card`, `popover`, and `surface-*` tokens over ad hoc backgrounds.
- Use restrained depth (`shadow-premium`, `shadow-premium-hover`) rather than heavy blur stacks.
- Keep hierarchy border-led (`border`, `input`) before relying on stronger fills.

### Typography

- Use tokenized families (`--font-sans`, `--font-display`, `--font-mono`).
- Maintain generous readability in dense screens (avoid compressed body copy line height).

### Motion and Interaction

- Favor subtle transitions and state clarity over decorative animation.
- Maintain consistent focus behavior via `ring` token.
- Keep hover/active states token-driven and restrained.

## Component Standards (Precise Defaults)

### Shell (Header + Sidebar + Content)

- High-contrast text against shell surfaces in both themes.
- Consistent spacing rhythm from `--space-*` tokens.
- No isolated color logic outside tokenized class usage.

### Buttons

- Primary actions use brand/primary tokens.
- Secondary/ghost actions rely on border + muted/accent behavior.
- Disabled states reduce emphasis without dropping below readable contrast.

#### Button Size Contract

| Size      | Height | Tailwind Class | Use Case              |
|-----------|--------|----------------|-----------------------|
| `default` | 44px   | `h-11`         | Standard form buttons |
| `lg`      | 48px   | `h-12`         | Primary CTA / hero    |
| `xl`      | 56px   | `h-14`         | Landing page buttons  |

All button sizes maintain a minimum touch target of 44×44px on mobile via `min-h-[44px]` when appropriate.

#### Button ARIA Contract

- `aria-label` on icon-only buttons.
- `aria-pressed` on toggle buttons (theme toggle).
- `aria-disabled` in addition to `disabled` attribute for server-rendered disabled states.

### Cards and Panels

- Default to neutral `card` surfaces with border separation.
- Hover states may increase border emphasis and shadow one step.
- Avoid per-feature bespoke shadow palettes.

### Inputs and Textareas

- Use `input` and `ring` token mappings for all states.
- Placeholder text must remain readable in dark mode.
- Validation styling uses semantic states only.

### Inputs and Textareas — Sizing Contract

All interactive inputs must enforce a minimum touch target:

```css
/* Minimum touch target for all inputs */
input, select, textarea, button {
  min-height: 44px;
}
```

This is applied via `min-h-[44px]` in component classes and ensures WCAG 2.2 target-size compliance.

### Tables and Data UI

- Row/column hierarchy should be clear at default zoom and dark mode.
- Use muted text only for secondary metadata.
- Status chips use semantic tokens and should not encode meaning by color alone.

## Dark Mode Requirements

1. Dark mode is implemented through `.dark` token overrides, not separate hard-coded palettes.
2. `foreground` and `card-foreground` remain readable on `background` and `card`.
3. Semantic states remain distinguishable without oversaturation.
4. Verify shell, cards, buttons, forms, and tables in both themes for every visual change.

### Dark Mode Mechanism

The system uses a dual-selector strategy:

```css
/* Class-based toggle (default) */
.dark { ... }

/* OS-level preference fallback */
@media (prefers-color-scheme: dark) {
  :root { ... }
}
```

The `data-theme-mode` attribute on the root element controls the active mode:

- `data-theme-mode="light"` — forces light mode
- `data-theme-mode="dark"` — forces dark mode
- `data-theme-mode="system"` — defers to `prefers-color-scheme` (default)

## Apex Icons Standard

## Reduced Motion

All animations and transitions must be overridable via the user's system preference:

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
```

This block is defined in [`globals.css`](services/mail-server/crates/ui-foundation/assets/globals.css) and applies globally across all surfaces.

## Spacing Token System

The spacing scale is defined as CSS custom properties in `globals.css`:

| Token       | Value | Typical Use           |
|-------------|-------|-----------------------|
| `--space-1` | 4px   | Micro spacing         |
| `--space-2` | 8px   | Tight gaps            |
| `--space-3` | 12px  | Element spacing       |
| `--space-4` | 16px  | Standard padding      |
| `--space-6` | 24px  | Section padding       |
| `--space-8` | 32px  | Large spacing         |
| `--space-12`| 48px  | Section margins       |
| `--space-16`| 64px  | Page-level padding    |

These map to Tailwind's spacing scale so utility classes like `p-4`, `gap-6`, `px-8` resolve to the correct tokens.

## Cross-System ARIA & Keyboard Patterns

### Shared ARIA Attributes

| Attribute              | Applied To              | Purpose                         |
|------------------------|-------------------------|---------------------------------|
| `aria-hidden="true"`   | Decorative SVGs, overlays| Hide from assistive technology  |
| `aria-label`           | Icon buttons, search     | Provide accessible names        |
| `aria-expanded`        | Menu toggles             | Indicate open/closed state      |
| `aria-pressed`         | Theme toggle buttons     | Indicate toggle state           |
| `aria-current="page"`  | Active nav links         | Indicate current page           |
| `aria-live="polite"`   | Toast, status regions    | Announce dynamic updates        |
| `aria-busy="true"`     | Loading sections         | Indicate async operation        |
| `aria-disabled="true"` | Disabled buttons         | Semantically disable elements   |
| `role="searchbox"`     | Search inputs            | Identify search role            |
| `role="navigation"`    | Sidebar, nav elements    | Identify navigation landmarks   |
| `role="alert"`         | Impersonation banner     | Announce critical banner        |
| `role="region"`        | Toast container          | Identify live region            |

### Keyboard Navigation Patterns

See [`docs/development/interactive-state-matrix.md`](docs/development/interactive-state-matrix.md) for the complete keyboard interaction contract.

## Apex Icons Standard

### Canonical Icon Modules

- `services/mail-server/crates/ui-foundation/src/icons.rs`
- `apps/marketing-zola/templates/partials/` (inline SVG partials and generated fragments)

### Icon Rules

1. Use icons from the owning surface's canonical source only.
2. Keep stable icon names or partial responsibilities aligned with UI usage.
3. Add a glyph to the shared Rust icon module or the relevant Zola partial before using it in feature templates.
4. Do not introduce third-party icon imports into browser-surface code.
5. All decorative SVGs must include `aria-hidden="true"` on the `<svg>` element.
6. Default `stroke-width="2"` for all icon SVGs in the shared icon module.

### Example

```rust
use ui_foundation::icons;
```

## Flexibility Model (How to Extend Apex Safely)

### Allowed Extensions

- New semantic tokens when backed by multi-screen product need.
- New component variants built from existing token families.
- App-specific accents (for example control-plane identity) when tokenized and documented.

### Disallowed Extensions

- Feature-local hard-coded palettes for shared components.
- Introducing a second icon library in app code.
- Diverging dark-mode behavior between equivalent components without product justification.

### Extension Workflow

1. Add or refine tokens in canonical source.
2. Map tokens in relevant Tailwind config(s).
3. Update component variants using tokenized classes.
4. Update this guide and any affected app docs.
5. Validate typecheck + visual coverage for changed surfaces.

## Validation Checklist

When updating Apex style:

1. No new hard-coded color literals for shared UI components.
2. No third-party icon imports in app source.
3. Light and dark readability verified for changed views.
4. Relevant visual tests re-run.
5. Docs updated when tokens, icon exports, or component standards changed.
