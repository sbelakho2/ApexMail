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

---

## Keyboard Interaction Contracts

The following contracts are implemented in [`primitives.rs`](../../services/mail-server/crates/ui-foundation/src/primitives.rs) using roving tabindex and ARIA roles.

### RadioGroup

| Key                | Action                                      |
|--------------------|---------------------------------------------|
| `ArrowUp`          | Move focus to previous radio item (wrap)    |
| `ArrowDown`        | Move focus to next radio item (wrap)        |
| `Home`             | Move focus to first radio item              |
| `End`              | Move focus to last radio item               |
| `Space`            | Select the focused radio item               |

**Pattern:** Roving tabindex — only the selected radio has `tabindex="0"`, all others have `tabindex="-1"`.

**Roles:** `role="radiogroup"` on the container, `role="radio"` on each item, `aria-checked` on the selected item.

### Select (Combobox)

| Key                | Action                                      |
|--------------------|---------------------------------------------|
| `ArrowDown`        | Open the listbox and focus first option     |
| `ArrowUp`          | Open the listbox and focus last option      |
| `Enter` / `Space`  | Toggle the listbox open/closed              |
| `Escape`           | Close the listbox without selecting         |
| `Home`             | Focus the first option when open            |
| `End`              | Focus the last option when open             |
| `Tab`              | Close the listbox and move focus away       |

**Pattern:** The trigger button uses `aria-haspopup="listbox"`, `aria-expanded`, and `aria-controls` pointing to the options list. The listbox uses `role="listbox"` with `role="option"` children and `aria-selected` on the active option.

### DropdownMenu

| Key                | Action                                      |
|--------------------|---------------------------------------------|
| `ArrowDown`        | Move focus to the next menu item (wrap)     |
| `ArrowUp`          | Move focus to the previous menu item (wrap) |
| `Enter`            | Activate the focused menu item              |
| `Escape`           | Close the menu and return focus to trigger  |
| `Tab`              | Close the menu and move focus away          |
| `Home`             | Focus the first menu item                   |
| `End`              | Focus the last menu item                    |

**Pattern:** Roving tabindex on menu items. The menu container has `role="menu"`, each item has `role="menuitem"`. The trigger uses `aria-haspopup="true"` and `aria-expanded`.

### Tabs

| Key                | Action                                      |
|--------------------|---------------------------------------------|
| `ArrowLeft`        | Move focus to the previous tab (wrap)       |
| `ArrowRight`       | Move focus to the next tab (wrap)           |
| `Home`             | Move focus to the first tab                 |
| `End`              | Move focus to the last tab                  |
| `Space` / `Enter`  | Activate the focused tab                    |
| `Tab`              | Move focus into the active tab panel        |

**Pattern:** Roving tabindex on tab elements. The tablist has `role="tablist"`, each tab has `role="tab"` with `aria-selected` and `aria-controls` pointing to the associated panel (`role="tabpanel"`).
