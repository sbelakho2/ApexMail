# PDF document design (ARK print)

Every PDF ApexMail produces — invoices, the DPA, compliance reports, QBRs and
analytics exports — is rendered by `pdf-renderer` from a Typst template. The
documents follow the same design law as the web surfaces (ARK): paper/ink/blue,
Spectral + Overpass + Overpass Mono, zero radius, thin rules, the two-tone
wordmark and no green.

## One authority: `templates/ark.typ`

`services/mail-server/crates/pdf-renderer/src/templates/ark.typ` is the only
place design decisions live. It exports:

| Area | Exports |
|---|---|
| Palette | `paper`, `limestone`, `mist`, `ink`, `muted`, `faint`, `rule`, `blue`, `blue-tint`, `red`, `red-tint`, `amber`, `amber-tint`, `wordmark-apex` (#B91C1C), `wordmark-mail` (#09090B) |
| Type | `text-font` (Overpass), `display-font` (Spectral), `mono-font` (Overpass Mono) |
| Page | `page-setup` (A4, fixed margins, running header, one-line footer), `strong-rule`, `thin-rule` |
| Components | `wordmark`, `section`, `eyebrow`, `meta-sep`, `chip`, `notice`, `tone-color`, `tone-fill` |
| Money | `fmt-money`, `currency-symbol` |

Templates import it (`#import "ark.typ": *`), apply
`#show: page-setup.with(…)` and use the components. They contain data parsing
and content only — never a colour, a luma grey, a font family, a page
geometry, a radius or a derived tint.

The module is embedded in the binary next to the templates
(`world::ARK_LIB`), so a hermetic build resolves the import; a
`PDF_TEMPLATES_DIR` deployment must ship `ark.typ` beside its templates.

## Gate: `tools/check_pdf_ark.py`

REQUIRED in `ci/stages/validate.sh` (with `--self-test`). It fails when a
template:

- hardcodes `rgb("#…")`, `#[0-9a-f]{6}`, or `luma(…)`;
- sets its own page geometry (`#set page(`), font (`#set text(font:`), or
  heading style (`#show heading`);
- derives tints/shadows (`.lighten(` / `.darken(`) instead of using tones;
- uses a green success colour (ARK success is blue);
- does not import `ark.typ` or does not use `page-setup`.

The gate also asserts the authority carries the four load-bearing tokens
(wordmark red, wordmark ink, blue, ink).

## Visual acceptance

The five templates are rendered through the real `/v1/pdf/render` endpoint
with production-shaped payloads, rasterised (`pdftoppm`) and reviewed page by
page against the spec: serif display titles, two-tone wordmark (including the
running header), spaced separators, intact header grid, repeated table header
rows across page breaks, non-splitting recommendation boxes, consistent money
and percent formatting, and ≥ 20 px bottom clearance for the one-line footer.
All 13 pages pass.

## Rules for a new document

1. Add `templates/<name>.typ` with the data contract at the top.
2. `#import "ark.typ": *` and `#show: page-setup.with(title: …, …)`.
3. Use `section`, `eyebrow`, `chip`, `tone-*`, `fmt-money` — no inline design.
4. Register the template in `world.rs` (`TEMPLATES`).
5. Run `python3 tools/check_pdf_ark.py` and render + rasterise the new
   template for a visual pass.
