// ARK — the PDF design authority.
//
// Every document template imports this module. Colour, type, rules, spacing
// and the shared components live HERE and nowhere else: a template that
// hardcodes `rgb("#...")`, luma greys, fonts or page geometry is a design
// fork, and `tools/check_pdf_ark.py` fails the build for it.
//
// The tokens mirror `assets/ark.css` (the web authority): paper/ink/blue
// palette, 0 radius, 3/2/1px-equivalent rules, Spectral for display,
// Overpass for text, Overpass Mono for machine data, and the two-tone
// wordmark (#B91C1C Apex / #09090B Mail). Success is BLUE; red means
// destruction/negative; amber is a warning — there is no green.

// ── Palette ────────────────────────────────────────────────────────────────
#let paper = rgb("#FFFFFF")
#let limestone = rgb("#F6F8FA")
#let mist = rgb("#EEF2F6")
#let ink = rgb("#0E141B")
#let muted = rgb("#5B6B7A")
#let faint = rgb("#3D4B59")
#let rule = rgb("#C4CDD5")
#let blue = rgb("#1D4F7C")
#let blue-deep = rgb("#143A5C")
#let blue-tint = rgb("#E8EFF6")
#let red = rgb("#8E2A20")
#let red-tint = rgb("#F7ECEA")
#let amber = rgb("#8A5A10")
#let amber-tint = rgb("#FBF3E4")
// The wordmark's own fixed tones (web `--wordmark-apex` / `--wordmark-mail`).
#let wordmark-apex = rgb("#B91C1C")
#let wordmark-mail = rgb("#09090B")

// ── Type ───────────────────────────────────────────────────────────────────
#let text-font = ("Overpass", "Noto Sans", "DejaVu Sans")
#let display-font = ("Spectral", "Noto Serif", "DejaVu Serif")
#let mono-font = ("Overpass Mono", "DejaVu Sans Mono", "Noto Sans Mono", "monospace")

// ── Measurements ───────────────────────────────────────────────────────────
#let page-margin = (top: 22mm, bottom: 20mm, left: 20mm, right: 20mm)
#let strong-stroke = 2pt + ink
#let rule-stroke = 1pt + rule
#let hairline = 0.5pt + rule

// ── Wordmark ───────────────────────────────────────────────────────────────
// Verbatim two-tone lockup; never restyle it (web law ARK-10).
#let wordmark(size: 18pt) = text(
  size: size,
  weight: "semibold",
  tracking: -0.02em,
)[#text(fill: wordmark-apex)[Apex]#text(fill: wordmark-mail)[Mail]]

// ── Page + document setup ──────────────────────────────────────────────────
// Use as `#show: ark.page.with(title: "…", footer-left: [..], footer-right: [..])`.
// The footer is part of the page design, not of any template.
#let page-setup(
  title: "",
  running-title: none,
  footer-left: [],
  footer-center: [],
  footer-right: [],
  body,
) = {
  set document(title: title, author: "ApexMail")
  set page(
    paper: "a4",
    margin: page-margin,
    header: if running-title == none {
      none
    } else {
      context {
        if counter(page).get().first() > 1 {
          set text(font: text-font, size: 7.5pt, fill: muted)
          grid(
            columns: (1fr, 1fr),
            align(left)[#running-title],
            align(right)[#wordmark(size: 9pt)],
          )
          v(2pt)
          line(length: 100%, stroke: hairline)
        }
      }
    },
    footer: {
      v(6pt)
      line(length: 100%, stroke: hairline)
      v(3pt)
      set text(font: text-font, size: 7pt, fill: muted)
      if footer-center == [] {
        grid(
          columns: (1fr, 1fr),
          align(left)[#footer-left],
          align(right)[#footer-right],
        )
      } else {
        grid(
          columns: (1fr, 1fr, 1fr),
          align(left)[#footer-left],
          align(center)[#footer-center],
          align(right)[#footer-right],
        )
      }
    },
  )
  set text(font: text-font, size: 10pt, fill: ink)
  set par(leading: 1.45em, justify: false, spacing: 1.1em)
  show heading: set text(font: display-font)
  body
}

// ── Rules ──────────────────────────────────────────────────────────────────
#let strong-rule() = line(length: 100%, stroke: strong-stroke)
#let thin-rule() = line(length: 100%, stroke: rule-stroke)

// ── Section + eyebrow ──────────────────────────────────────────────────────
// Section titles are text, not display ornaments: Overpass semibold over a
// hairline, the same hierarchy the web console uses.
#let section(title) = {
  v(6pt)
  text(font: text-font, weight: "semibold", size: 11pt, fill: ink, title)
  v(3pt)
  line(length: 100%, stroke: hairline)
  v(6pt)
}

/// Metadata separator with explicit optical spacing: a bare `·` at 7–8pt
/// reads as if it belonged to the following word.
#let meta-sep = [ #h(0.45em) · #h(0.45em) ]

#let eyebrow(label) = text(
  font: text-font,
  weight: "semibold",
  size: 7.5pt,
  tracking: 0.08em,
  fill: muted,
  upper(label),
)

// ── Tones ──────────────────────────────────────────────────────────────────
// One mapping for every status word in every document. `pos` is BLUE.
#let tone-color(tone) = {
  if tone == "pos" { blue }
  else if tone == "warn" { amber }
  else if tone == "neg" { red }
  else { faint }
}

#let tone-fill(tone) = {
  if tone == "pos" { blue-tint }
  else if tone == "warn" { amber-tint }
  else if tone == "neg" { red-tint }
  else { mist }
}

#let tone-word(word, tone) = text(
  font: text-font,
  weight: "semibold",
  size: 8pt,
  fill: tone-color(tone),
  upper(word),
)

// A bordered status chip: 0 radius, 1pt tone stroke, tinted paper.
#let chip(word, tone: "neutral") = box(
  fill: tone-fill(tone),
  stroke: 0.75pt + tone-color(tone),
  inset: (x: 6pt, y: 2.5pt),
  radius: 0pt,
)[#tone-word(word, tone)]

// A callout: the web `apex-notice` equivalent.
#let notice(body, tone: "neutral") = block(
  width: 100%,
  fill: tone-fill(tone),
  stroke: (left: 2pt + tone-color(tone)),
  inset: (x: 10pt, y: 8pt),
  radius: 0pt,
)[#body]

// ── Tables ─────────────────────────────────────────────────────────────────
// ARK tables carry rules, not zebra stripes or chrome: a limestone header
// row, hairline body rules, numbers in mono. Templates declare
// `stroke: (x: none, y: hairline)` and `fill: (x, y) => if y == 0 { limestone }`.

// ── Money ──────────────────────────────────────────────────────────────────
// Exact minor-unit formatting: the sign leads the symbol, unknown symbols
// fall back to the ISO code + space, and no float ever participates.
#let fmt-money(minor, symbol) = {
  let amount = if type(minor) == int or type(minor) == float { minor } else { 0 }
  let sign = if amount < 0 { "-" } else { "" }
  let abs = calc.abs(amount)
  let major = calc.floor(abs / 100)
  let ct = calc.rem(abs, 100)
  let ct-str = if ct < 10 { "0" + str(ct) } else { str(ct) }
  sign + symbol + str(major) + "." + ct-str
}

#let currency-symbol(code) = {
  let currency = upper(str(code))
  if currency == "EUR" { "€" }
  else if currency == "USD" { "$" }
  else if currency == "GBP" { "£" }
  else if currency in ("CHF", "SEK", "NOK", "DKK", "PLN") { currency + " " }
  else if currency != "" { currency + " " }
  else { "" }
}
