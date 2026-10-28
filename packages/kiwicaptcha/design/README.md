# KiwiCaptcha brand and widget

The current widget system is edition 6 (23 October 2026) and lives in
`packages/kiwicaptcha-widget-system/`. Edition 6 governs the widgets:
any older interface, progress track or completion wording is superseded.
Canonical logo geometry and the outlined wordmark masters are unchanged.

`brand-preview.html` is the earlier design reference for the previous
widget skin. It loads the real widget stylesheet and locale packs. The
states are simulated; it does not issue a challenge or a token.

Open it locally, or serve the repository with `python3 -m http.server 8080`
and visit `/packages/kiwicaptcha/design/brand-preview.html`.

The primary mark is `../resources/kiwi-mark.svg`. Keep its two paths,
64×64 viewBox and `currentColor` treatment. The shackle stays still and
reads separately from the lower spiral, including at favicon sizes.
Use the bare mark for favicons and primary branding. The shield is a
secondary security-status emblem. `IDENTITY.md` is the design contract:
the suite masters, the palette, the type system and the voice rules.
The wordmark lettering is fixed artwork recorded in `lettering.json`.

After changing the canonical mark, the lettering or the widget skin, run
from the repo root:

```sh
node packages/kiwicaptcha/tools/sync-brand.mjs
node packages/kiwicaptcha/tools/sync-brand.mjs --check
```

This updates the Rust mark/lockup/stacked/app-icon/shield assets, framework
geometry, Symfony template, compatibility/shim marks, preview specimen, and
packaged CSS/JS mirrors. CI checks their agreement. Rendering remains
self-contained: no brand-asset request, font download or added runtime
dependency is needed.

`logo-proposals.html` and `widget-proposals.html` preserve the earlier
design exploration. Their mockups are historical proposals.
