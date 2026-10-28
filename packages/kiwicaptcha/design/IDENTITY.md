# KiwiCaptcha identity

The product identity is the Spiral Lock mark, the fixed humanist wordmark,
the green palette and the quiet widget language. This file is the design
contract for the repository. The packaged SVG masters under `../resources/`
own the artwork; `tools/sync-brand.mjs` keeps every renderer copy in
agreement with them.

## Mark and suite

The primary mark is `../resources/kiwi-mark.svg`: the open coil and the
raised shackle, two strokes on the 64x64 grid, 6.6-unit stroke, round caps
and joins, monochrome through `currentColor`. The shield is the secondary
security-status emblem and does not replace the primary mark.

| Master | File | Use |
| --- | --- | --- |
| Primary horizontal | `kiwi-lockup.svg` | The default signature wherever the full name reads comfortably; keep it at least 192 px wide. |
| Secondary stacked | `kiwi-stacked.svg` | Square-ish placements where the horizontal signature cannot be read. |
| Wordmark | `kiwi-wordmark.svg` | Known-context surfaces; the fixed lettering alone. |
| Bare symbol | `kiwi-mark.svg` | Favicons, widget icon slots and monochrome toolbar or activity-bar contexts; 24 px is the preferred size and a proofed 16 px icon is the smallest. |
| App container | `kiwi-app-icon.svg` | The platform tile with fixed Ink `#08110C` and Teal `#9EDFD4`. A tile is a container, not an extra enclosing shape in the bare mark. |

Every master except the app tile recolors through `currentColor`, so the
Ink, white and accent variants come from the surrounding color.

The wordmark is fixed artwork: lowercase "kiwi captcha" outlined from
Alegreya Sans Bold, kiwi at 100 units and captcha at 82 on the same
baseline, the 12-unit word gap and the pair adjustments recorded in
`lettering.json`. The masters carry no text element and no font reference;
outline edits happen at the source of the lettering, then sync regenerates
the suite.

Keep H/4 clear space on all sides of the visible artwork; empty viewBox
padding does not count as clear space. Preserve the approved
symbol-to-wordmark gap. The masters stay intact: no stretching, rotation,
letter-spacing changes, cropping, outlining, gradients, shadows or added
ornament. On photography, use a quiet solid backing.

## Palette

The palette has clear responsibilities, and brand colors stay distinct
from outcome semantics.

| Name | Hex | Responsibility |
| --- | --- | --- |
| Ink | `#08110C` | Text on Paper; the dark surface. |
| Forest | `#143D2B` | Deep brand green. |
| Paper | `#F3F5EF` | The warm page surface; text on Ink. |
| Sage | `#92AA99` | Muted structure on Ink; 7.69:1. |
| Teal | `#9EDFD4` | The accent on Ink; decorative accent only on Paper (1.37:1). |
| Teal Deep | `#145C52` | The interactive accent and accent text on Paper; 7.13:1. |

Muted text on Paper reads at 5.66:1; the widget tokens use `#5D625F` for
that role on light surfaces. Ink on Paper reaches 17.45:1 and Teal on Ink
12.74:1. The normal-text target is 4.5:1 and essential non-text graphics
need 3:1. State meaning is carried by more than color alone.

## Typography

Alegreya Sans is the reading and display system: 700 and 800 for display
headings, the book weights for reading and controls. IBM Plex Mono carries
technical metadata at 10 to 14 px: IDs, states, source context and code.
The `design/fonts/` folder holds the self-hosted WOFF2 files and the SIL
Open Font License notices for both families.

The production widget inherits the host system stack and takes no
marketing-font payload. Only brand surfaces like the preview page load
these faces, from local files.

## Widget language

Edition 6 (23 October 2026) governs the widget system; the compact status
surface and the factor task form live in
`packages/kiwicaptcha-widget-system/` and its edition-6 guide is
authoritative for the component. The identity rules still apply: the mark
stays static, state meaning is carried by more than color alone, recovery
names a useful next action, and completion describes computation while the
host verification and application policy remain separate.

## Voice

Write what the state actually means, with bounded claims and a recovery
line that names a useful next action. The campaign line is "Let the
browser do the work." Completion copy describes computation; the host
still decides. Privacy copy is mode-specific. There are no fabricated
customers, logos, reviews, performance figures or release availability
claims in brand surfaces.
