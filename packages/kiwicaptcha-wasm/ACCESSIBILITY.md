# KiwiCaptcha accessibility — WCAG 2.2 AA evidence, scope and limitations

Round 29 establishes the accessibility acceptance set for the KiwiCaptcha
widget. This document describes the component's **tested conformance
scope** — what KiwiCaptcha itself provides and verifies, what the
integrating page must provide, and the known limitations. It describes the
software, not organizational structure.

## Positioning

KiwiCaptcha's normal operation does not require a human to pass a
cognitive, visual, audio, memory or dexterity test: the proof-of-work is
computed automatically in the browser. That is a structural accessibility
advantage under WCAG 2.2 **3.3.8 Accessible Authentication (Minimum)** —
no alternative authentication path for users with cognitive
disabilities is needed because the challenge itself is not cognitive.

The defensible product claim is:

> KiwiCaptcha's user-facing widget conforms to WCAG 2.2 Level AA within
> its component scope and is designed to support accessible
> identification and security workflows under Directive (EU) 2019/882
> (European Accessibility Act).

Component conformance is not whole-page conformance: KiwiCaptcha cannot
make an entire e-commerce site EAA-compliant by itself. The consuming
service remains responsible for the page-level requirements (landmarks,
headings, form labels, keyboard flow around the widget, language of the
page, and the WCAG/EAA obligations of its own content).

## Conformance scope

The accessibility acceptance set below is enforced by the automated
browser suite (`tests/browser/specs/a11y.spec.mjs`, run across
Chromium + Firefox + WebKit via `playwright.a11y.config.mjs`) and by the
manual assistive-technology qualification checklist in the release gate.

| Requirement | WCAG 2.2 SC | Kiwi evidence |
| --- | --- | --- |
| Badge text >= 4.5:1 (>= 5:1 headroom) in light and dark themes, all states | 1.4.3 | contrast computed in the a11y suite for solving/done/failed/idle badges; axe `color-contrast` |
| No state conveyed by color alone | 1.4.1 | badge text + `role=status` announcements carry every state |
| Forced-colors / high-contrast mode | 1.4.3 (forced-colors) | `@media (forced-colors: active)` rules; emulated in the suite |
| Progress indicator not exposed as a control/status object | 4.1.2 | `.kiwi-track` is `aria-hidden="true"` (no `role=progressbar`); meaningful states go to the live region |
| Meaningful live region only | 4.1.3 | single polite `role=status` announcer; only Checking/verified/failed/expired/unavailable transitions |
| Keyboard operation: every action keyboard-operable | 2.1.1 / 2.1.2 | the Retry button is a native `<button>`; the passive widget is never focusable; no keyboard trap |
| No pointerdown-only activation | 2.5.2 | reacquisition uses the native button with click activation only |
| Visible focus | 2.4.7 | `:focus-visible` ring on the Retry button |
| Pointer targets >= 24x24 CSS px (32px height) | 2.5.8 | `min-height: 32px; min-width: 24px` on the Retry button; bounding-box asserted |
| No content/function loss at 200% text resize | 1.4.4 | 320 CSS px reflow + text-spacing overrides asserted; long German strings tested |
| Text spacing overrides (1.4.12) | 1.4.12 | letter/word spacing + line-height overrides injected and asserted |
| Reduced motion eliminates decorative motion | 2.3.3 / 2.3.1 | CSS animations + the SVG SMIL wink removed under `prefers-reduced-motion`; asserted |
| Expiry never destroys host-form data or blocks reacquisition | 1.4.10 / 2.1.1 | expiry clears only the token field + fires the expired callback; the Retry button remains |
| Language of the widget subtree programmatically determinable | 3.1.2 | `lang` attribute resolved from `options.lang` / `data-kiwi-lang` / `navigator.language`; `dir=rtl` for RTL packs; untranslated fallback marked `lang="en"` |
| Correct name/role/value for the widget's UI components | 4.1.2 | `role=group` on the widget, native button with a name, hidden decorative SVG |
| Decorative material absent from the accessibility tree | 1.1.1 / 4.1.2 | mascot SVG `aria-hidden` + `focusable=false` |
| No cognitive/visual/audio test as a required fallback | 3.3.8 | the automatic computational challenge is the ONLY path (no puzzle/audio alternatives exist) |
| Automated evidence across engines | — | axe + scenario suite in Chromium, Firefox and WebKit |

## Locale contract

- The widget language resolves in this order: `options.lang` (e.g.
  `grecaptcha.render(el, {lang: 'de'})`), `data-kiwi-lang` on the
  widget/container, then `navigator.language`.
- The resolved language is written to the widget subtree's `lang`
  attribute; RTL packs (Arabic) additionally set `dir="rtl"`.
- Shipped packs: English (fallback, explicitly `lang="en"` when used),
  German, French, Spanish, Italian, Dutch, Polish, Portuguese, Arabic
  (RTL). Unknown locales fall back to English with `lang="en"`.
- Integrators can supply their own strings by patching
  `window.KiwiCaptcha` locale tables (documented in the driver source).

## Manual assistive-technology qualification (release gate)

Automated DOM checks are not sufficient conformance evidence (WCAG
conformance depends on accessibility-supported technology). Before each
release, the maintainers qualify the widget with:

- NVDA + Firefox, NVDA + Chrome (Windows)
- VoiceOver + Safari (macOS)
- TalkBack + Chrome (Android)

The checklist: Tab order reaches the Retry button and the form fields,
Enter/Space activate the button, the live region announces
Checking/verified/failed/expired, and the widget never traps focus.

## Known limitations

- The static template text is English until the driver localizes it
  (the driver runs synchronously at init; `lang` is set at the same
  time, so the English fallback is programmatically marked).
- Page-level WCAG requirements (landmarks, heading structure, form
  labels, page language, focus management around the widget) belong to
  the integrating application.
- Automated contrast assertions cover the widget's own palette;
  integrator overrides of the CSS variables may change ratios and are
  the integrator's responsibility.

## EAA compatibility mapping

Directive (EU) 2019/882 Annex I requires covered services' identification,
security and payment functionality to be perceivable, operable,
understandable and robust. KiwiCaptcha maps its WCAG 2.2 AA evidence to
the EAA POUR requirements and to the applicable standards as they mature:

| EAA Annex I requirement | WCAG 2.2 AA evidence above | Kiwi test | EN 301 549 / M/587 clause |
| --- | --- | --- | --- |
| Perceivable (information and UI presented to all users) | 1.4.3, 1.4.1, 3.1.2, live region | a11y suite: contrast, forced-colors, lang/dir, announcements | EN 301 549 9.1.x (WCAG-mapped); M/587 update in progress |
| Operable (navigation and interaction available to all users) | 2.1.1, 2.5.2, 2.5.8, 2.4.7 | a11y suite: keyboard-only, pointer targets, no pointerdown | EN 301 549 9.2.x; M/587 in progress |
| Understandable (information and operation are clear) | 3.3.8, 3.1.2 | automatic computational challenge; localized strings | EN 301 549 9.3.x; M/587 in progress |
| Robust (compatible with assistive technology) | 4.1.2, 4.1.3 | axe semantics + role=status assertions + manual AT gate | EN 301 549 9.4.x; M/587 in progress |

Note: EN 301 549 v3.2.1 is currently the harmonized standard for the
separate Web Accessibility Directive (it draws heavily from WCAG 2.1);
the EAA standardization work (M/587) is expected to extend through
2026–27. KiwiCaptcha therefore maintains the mapping above against WCAG
2.2 AA now, rather than baking an obsolete standard version into the
architecture.
