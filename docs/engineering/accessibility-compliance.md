# Accessibility Compliance

> Standard: WCAG 2.2 Level AA
> Last reviewed: 2026-07-29

## Keyboard Accessibility

| Surface | Status | Notes |
|---------|--------|-------|
| Header navigation | Verified | Tab order logical |
| Dropdowns | Verified | Escape closes, arrow keys navigate |
| Mobile menu | Verified | Toggle works with keyboard |
| Pricing toggle (monthly/annual) | Verified | Space/Enter toggles |
| Calculator | Verified | All inputs keyboard-accessible |
| Tabs | Verified | Arrow keys navigate tabs |
| Accordions | Verified | Enter/Space expands |
| Modals | Verified | Escape closes, focus trapped |
| Forms | Verified | Tab order logical, labels associated |
| Code-copy buttons | Verified | Button focusable, announces copied |
| Documentation sidebar | Verified | Skip link available |
| Signup | Verified | All fields accessible |
| Login | Verified | All fields accessible |
| Password reset | Verified | Flow completes with keyboard |
| Cookie controls | Verified | Tab to each control |
| Status subscriptions | Verified | Form accessible |

## Semantic HTML

| Requirement | Status |
|-------------|--------|
| One H1 per page | Verified |
| Logical H2–H6 order | Verified |
| Buttons for actions (`<button>`) | Verified |
| Links for navigation (`<a>`) | Verified |
| Proper form labels | Verified |
| Proper fieldsets for groups | Verified |
| Table headers (`<th>`) | Verified |
| Landmark elements (`<nav>`, `<main>`, `<footer>`) | Verified |
| Accessible navigation labels | Verified |
| Error summary on form validation | Verified |
| Status messages with `aria-live` | Verified |

## Color Contrast (WCAG 2.2 AA)

| Element | Required Ratio | Status |
|---------|---------------|--------|
| Body text | 4.5:1 | Verified |
| Small text (< 18px) | 4.5:1 | Verified |
| Muted/secondary text | 4.5:1 | Verified |
| Links in text | 4.5:1 (3:1 vs surrounding) | Verified |
| Button text | 4.5:1 | Verified |
| Disabled states | Not required (but distinguishable) | Verified |
| Form borders | 3:1 | Verified |
| Placeholder text | 4.5:1 | Verified |
| Error text | 4.5:1 | Verified |
| Warning text | 4.5:1 | Verified |
| Success text | 4.5:1 | Verified |
| Charts | 3:1 between adjacent segments | Verified |
| Code blocks | 4.5:1 | Verified |
| Focus outlines | 3:1 | Verified |
| Footer text | 4.5:1 | Verified |
| Dark mode (if supported) | Same as above | N/A |

## Screen Reader and Media

| Requirement | Status |
|-------------|--------|
| Informative images have alt text | Verified |
| Decorative images have empty alt (`alt=""`) | Verified |
| Architecture diagrams have text descriptions | Verified |
| Icons have accessible labels | Verified |
| Video captions | N/A (no video content) |
| Video transcripts | N/A (no video content) |
| `prefers-reduced-motion` respected | Verified |
| Charts have accessible data tables | Verified |
| Code blocks marked with language | Verified |
| No "click here" as standalone link text | Verified |

## Automated Testing

- axe-core / Lighthouse accessibility audits on CI
- Critical accessibility failures block release
- Known exceptions documented with remediation timeline
- Manual screen reader testing supplements automation (NVDA + VoiceOver)
