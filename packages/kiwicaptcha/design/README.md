# KiwiCaptcha brand and widget

`brand-preview.html` is the current design reference. It loads the real
widget stylesheet and locale packs. The states are simulated; it does
not issue a challenge or a token. The controls cover light/dark themes,
240–352 px host containers, English, German, French, Portuguese, Polish
and Arabic, and 100%/200% component text sizes.

Open it locally, or serve the repository with `python3 -m http.server 8080`
and visit `/packages/kiwicaptcha/design/brand-preview.html`.

The primary mark is `../resources/kiwi-mark.svg`. Keep its two paths,
64×64 viewBox and `currentColor` treatment. The shackle stays still and
reads separately from the lower spiral, including at favicon sizes.
Use the bare mark for favicons and primary branding. The shield is a
secondary security-status emblem.

After changing the canonical mark or widget skin, run from the repo root:

```sh
node packages/kiwicaptcha/tools/sync-brand.mjs
node packages/kiwicaptcha/tools/sync-brand.mjs --check
```

This updates the Rust lockup/shield assets, framework geometry,
Symfony template, compatibility/shim marks, preview specimen, and
packaged CSS/JS mirrors. CI checks their agreement. Rendering remains
self-contained: no brand-asset request, font download or added runtime
dependency is needed.

`logo-proposals.html` and `widget-proposals.html` preserve the earlier
design exploration. Their mockups are historical proposals.
