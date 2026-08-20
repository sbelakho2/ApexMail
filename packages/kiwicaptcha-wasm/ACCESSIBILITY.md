# KiwiCaptcha accessibility — WCAG 2.2 AA evidence, scope and limitations

This document describes the component's **test scope** for the WCAG 2.2
accessibility acceptance set: computed non-text-contrast evidence (WCAG
1.4.11), the WCAG 2.2 new-criteria dispositions below, and the automated
suite that enforces them — what KiwiCaptcha itself provides and verifies,
what the integrating page must provide, and the known limitations. It
describes the software, not organizational structure.

## Positioning

KiwiCaptcha's normal operation does not require a human to pass a
cognitive, visual, audio, memory or dexterity test: the proof-of-work is
computed automatically in the browser. That is a structural accessibility
advantage under WCAG 2.2 **3.3.8 Accessible Authentication (Minimum)** —
which applies to every step of the complete authentication process.
KiwiCaptcha correctly adds no cognitive-function test of its own, while
the host login flow remains responsible for its own password, passcode
and copy-paste compliance.

The defensible product claim is:

> KiwiCaptcha is engineered and automatically tested against the applicable
> WCAG 2.2 A/AA success criteria within KiwiCaptcha's component test scope,
> and to support accessible identification and security workflows under
> Directive (EU) 2019/882 (European Accessibility Act).

The stronger formulation — "KiwiCaptcha is designed and tested to
satisfy the WCAG 2.2 Level AA success criteria applicable to the
component and to support WCAG 2.2 AA conforming integrations" — is NOT
published for any release until a release-specific manual
assistive-technology (AT) qualification artifact is recorded (see the
release-qualification artifacts below). No completed manual AT
qualification artifact exists for any release yet, and automated
evidence alone is not conformance evidence under WCAG (conformance
depends on accessibility-supported technology).

A component test scope is not whole-page conformance: KiwiCaptcha cannot
make an entire e-commerce site EAA-compliant by itself. The consuming
service remains responsible for the page-level requirements (landmarks,
headings, form labels, keyboard flow around the widget, language of the
page, and the WCAG/EAA obligations of its own content).

## Component test scope

The accessibility acceptance set below is enforced by the automated
browser suite (`tests/browser/specs/a11y.spec.mjs`, run across
Chromium + Firefox + WebKit via `playwright.a11y.config.mjs`) and by the
manual assistive-technology qualification checklist in the release gate.

| Requirement | WCAG 2.2 SC | Kiwi evidence |
| --- | --- | --- |
| Badge text >= 4.5:1 (>= 5:1 headroom) in light and dark themes, all states | 1.4.3 | contrast computed in the a11y suite for solving/done/failed/idle badges; axe `color-contrast` |
| No state conveyed by color alone | 1.4.1 | badge text + `role=status` announcements carry every state |
| Forced-colors / high-contrast mode (accessibility-support evidence, not a WCAG success criterion) | — | `@media (forced-colors: active)` rules keep the widget and Retry discernible with system colors; emulated in the suite |
| Non-text contrast: Retry control boundary and focus indicator >= 3:1 against the widget surface | 1.4.11 | the suite COMPUTES the border/outline colors and the composited button background over the widget surface and applies the WCAG formula — a computed check, not a CSS comment |
| Focus not obscured: the Retry is the only focusable component control | 2.4.11 | asserted structurally in the suite (single focusable control; the widget renders no overlapping content above it) |
| Progress indicator not exposed as a control/status object | 4.1.2 | `.kiwi-track` is `aria-hidden="true"` (no `role=progressbar`); meaningful states go to the live region |
| Meaningful live region only | 4.1.3 | single polite `role=status` announcer; only Checking/verified/failed/expired/unavailable transitions |
| Keyboard operation: every action keyboard-operable | 2.1.1 / 2.1.2 | the Retry button is a native `<button>`; the passive widget is never focusable; no keyboard trap |
| No pointerdown-only activation | 2.5.2 | reacquisition uses the native button with click activation only |
| Visible focus | 2.4.7 | `:focus-visible` ring on the Retry button (its 1.4.11 contrast is computed above) |
| Pointer targets >= 24x24 CSS px (32px height) | 2.5.8 | `min-height: 32px; min-width: 24px` on the Retry button; bounding-box asserted |
| No content/function loss at 2x component font-scale enlargement (a component-level custom-property stress test, not browser/user text zoom; actual 200% browser zoom is part of the manual release-gate qualification — performed at release time for each released artifact with recorded, signed evidence, never implied to have been run on any particular commit) | 1.4.4 | 320 CSS px reflow + text-spacing overrides asserted; long German strings tested |
| Text spacing overrides (1.4.12) | 1.4.12 | letter/word spacing + line-height overrides injected and asserted |
| Reduced motion eliminates decorative motion | 2.3.1 (A); 2.3.3 is Level AAA — the reduced-motion support satisfies 2.3.1 (A) plus above-AA 2.3.3 engineering | CSS animations + the SVG SMIL wink removed under `prefers-reduced-motion`; asserted |
| Expiry never destroys host-form data or blocks reacquisition | 1.4.10 / 2.1.1 | expiry clears only the token field + fires the expired callback; the Retry button remains |
| Language of the widget subtree programmatically determinable | 3.1.2 | `lang` attribute resolved from `options.lang` / `data-kiwi-lang` / `navigator.language`; `dir=rtl` for RTL packs; untranslated fallback marked `lang="en"` |
| Correct name/role/value for the widget's UI components | 4.1.2 | `role=group` on the widget, native button with a name, hidden decorative SVG |
| Decorative material absent from the accessibility tree | 1.1.1 / 4.1.2 | mascot SVG `aria-hidden` + `focusable=false` |
| No cognitive/visual/audio test as a required fallback | 3.3.8 | the automatic computational challenge is the ONLY path (no puzzle/audio alternatives exist) |
| Automated evidence across engines | — | axe + scenario suite in Chromium, Firefox and WebKit |

## WCAG 2.2 new criteria — disposition matrix

WCAG 2.2 added nine success criteria, of which seven are new at Level AA
(2.4.13 Focus Appearance and 3.3.9 Accessible Authentication (Enhanced)
are Level AAA and are not required for AA conformance). The widget's
disposition for every new WCAG 2.2 criterion applicable at Level AA that
touches its component scope:

| WCAG 2.2 SC | Level | Disposition |
| --- | --- | --- |
| 2.4.11 Focus Not Obscured (Minimum) | AA | Supported — the Retry button is the only focusable component control, and the widget renders no overlapping content above it, so the focused control cannot be entirely hidden by author-created content; asserted structurally in the suite |
| 2.4.12 Focus Not Obscured (Enhanced) | AAA | Above-AA engineering — the same structural guarantee (single focusable control, no overlapping author-created content) exceeds the AAA bar by design |
| 2.5.7 Dragging Movements | N/A | No drag interaction exists in the widget; every action is a single click or keyboard activation, so a pointer-drag alternative is not applicable |
| 2.5.8 Target Size Minimum | AA | Supported — the Retry button is >= 24x24 CSS px with a 32px height (an accessibility/security control has no reason to be cramped); bounding box asserted in the suite |
| 3.2.6 Consistent Help | N/A (host-page responsibility) | KiwiCaptcha provides no help mechanism of its own; consistent placement of help is the integrating page's responsibility, not the component's |
| 3.3.7 Redundant Entry | N/A | The widget captures no user-entered data, so nothing is ever re-requested |
| 3.3.8 Accessible Authentication (Minimum) | AA | Strongly satisfied structurally — the automatic computational challenge is the ONLY path, and no cognitive test is ever required. KiwiCaptcha introduces no cognitive-function test. Conformance of the complete authentication process remains the integrating application's responsibility. |

The two new criteria outside the component scope (3.2.6 above is a
host-page responsibility, not a widget capability) have no widget-level
disposition beyond N/A.

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
conformance depends on accessibility-supported technology). The manual
qualification is a RELEASE GATE: for each released artifact, at release
time, the maintainers qualify the widget in a real browser with actual
200% browser/user zoom plus the assistive-technology passes below, and
record signed evidence of the run — the qualification is never implied
to have been run on any particular commit:

- NVDA + Firefox, NVDA + Chrome (Windows)
- VoiceOver + Safari (macOS)
- TalkBack + Chrome (Android)
- at least one speech-recognition or switch-access pass (W3C's own
  explanation of 2.4.11 discusses keyboard-equivalent switch and voice
  input)

The checklist: Tab order reaches the Retry button and the form fields,
Enter/Space activate the button, the live region announces
Checking/verified/failed/expired, and the widget never traps focus.

### Release-qualification artifacts

Each release records a qualification artifact with the template below,
as recorded, signed evidence that the qualification ran at release time
on that release's artifact. The stronger formulation (that KiwiCaptcha
is designed and tested to satisfy the WCAG 2.2 Level AA success
criteria applicable to the component and to support WCAG 2.2 AA
conforming integrations) is published only when the artifact for that
release is complete:

- release tag and commit
- browser versions (Chromium, Firefox, Safari, Android Chrome)
- AT versions: NVDA, VoiceOver, TalkBack, plus the speech-recognition or
  switch-access tool used
- actual 200% browser zoom verification in a real browser
- date and tester (signed)
- pass/fail notes and known exceptions

Only the conservative claim in the Positioning section is published.

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
understandable and robust. The component-scoped EAA statement is:

> KiwiCaptcha is designed to support EAA accessibility requirements for identification and security functionality when integrated into a conforming service.

The phrase "KiwiCaptcha is EAA compliant" is deliberately not used: the
Act regulates the covered service or product, not an embedded component.
Host-page headings, labels, authentication architecture, customer
support, accessibility information, mobile application behavior and
national implementation remain outside the component and are the
integrating service's responsibility.

KiwiCaptcha maps its WCAG 2.2 AA evidence to the EAA POUR requirements
and to the applicable standards as they mature:

| EAA Annex I requirement | WCAG 2.2 AA evidence above | Kiwi test | EN 301 549 / M/587 clause |
| --- | --- | --- | --- |
| Perceivable (information and UI presented to all users) | 1.4.3, 1.4.1, 1.4.11, 3.1.2, live region | a11y suite: contrast, forced-colors, lang/dir, announcements | EN 301 549 9.1.x (WCAG-mapped); v4.1.0 under M/587 — voting closes 2026-08-24, publication planned 2026-08-28, OJ publication projected 2026-11-30; re-checked after publication |
| Operable (navigation and interaction available to all users) | 2.1.1, 2.5.2, 2.5.8, 2.4.7, 2.4.11 | a11y suite: keyboard-only, pointer targets, no pointerdown | EN 301 549 9.2.x; v4.1.0 under M/587 — voting closes 2026-08-24, publication planned 2026-08-28, OJ publication projected 2026-11-30; re-checked after publication |
| Understandable (information and operation are clear) | 3.3.8, 3.1.2 | automatic computational challenge; localized strings | EN 301 549 9.3.x; v4.1.0 under M/587 — voting closes 2026-08-24, publication planned 2026-08-28, OJ publication projected 2026-11-30; re-checked after publication |
| Robust (compatible with assistive technology) | 4.1.2, 4.1.3 | axe semantics + role=status assertions + manual AT gate | EN 301 549 9.4.x; v4.1.0 under M/587 — voting closes 2026-08-24, publication planned 2026-08-28, OJ publication projected 2026-11-30; re-checked after publication |

Note: EN 301 549 v3.2.1 is currently the harmonized standard for the
separate Web Accessibility Directive (it draws heavily from WCAG 2.1).
The EAA standardization work (M/587) has reached its final-deliverable
stage: the v4.1.0 vote is expected to close 2026-08-24, publication is
planned 2026-08-28 and OJ publication is projected 2026-11-30.
KiwiCaptcha therefore maintains the mapping above against WCAG 2.2 AA
now, will re-check the mapping after publication, and does not bake an
obsolete standard version into the architecture.
