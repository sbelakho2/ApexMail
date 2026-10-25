// ApexMail Invoice Template
// Rendered by pdf-renderer with JSON data from billing-service
//
// Expected data.json structure (produced by
// `billing_service::invoices::generate_invoice_pdf`):
// {
//   "invoice_number": "INV-2025-0042",
//   "status": "paid",                 // InvoiceStatus, lowercased
//   "currency": "EUR",                // ISO-4217 code, authoritative
//   "issued_at": "2025-01-15",
//   "due_at": "2025-02-14",
//   "paid_at": "2025-01-20",          // optional
//   "period_start": "2025-01-01",
//   "period_end": "2025-01-31",
//   "subtotal": 9900,                 // minor units (cents)
//   "vat_total": 2178,
//   "total": 12078,
//   "line_items": [
//     { "description": "Professional Plan", "quantity": 1, "unit_price": 9900, "amount": 9900, "vat_rate": 22, "vat_amount": 2178 }
//   ],
//   "seller": { "name": "Bel Consulting OÜ", "address": "Sakala 7-2, 10141 Tallinn, Estonia", "vat_number": "EE102951727", "registry_code": "16588745" },
//   "bank": { "name": "Wise", "iban": "EE...", "bic": "..." },   // optional; rendered only when present
//   "bill_to": {
//     "company": "Acme Corp",
//     "name": "Jane Doe",
//     "address": "123 Main St",
//     "city": "Tallinn",
//     "country": "EE",
//     "vat_number": "EE123456789"
//   }
// }

#import "ark.typ": *

#let data = json("data.json")

// Seller identity is passed in by billing-service; these are only fallbacks so a
// misconfigured build still renders a self-consistent (if incomplete) document.
#let seller = if "seller" in data { data.seller } else { (name: "Bel Consulting OÜ",) }
#let seller-vat = if "vat_number" in seller { seller.vat_number } else { "EE102951727" }
#let seller-reg = if "registry_code" in seller { seller.registry_code } else { "16588745" }
#let seller-address = if "address" in seller { seller.address } else { "Sakala 7-2, 10141 Tallinn, Estonia" }

// The authoritative currency is the ISO-4217 code the invoice was issued in.
// Symbols are presentation only; an unknown code always renders as the code
// itself, never as a guessed symbol.
#let currency = if "currency" in data and data.currency != none { upper(str(data.currency)) } else { "" }
// Defensive bindings: a payload missing an optional field renders an
// explicit placeholder instead of failing the whole document.
#let invoice-number = str(data.at("invoice_number", default: "Not recorded"))
#let status-value = lower(str(data.at("status", default: "unknown")))
#let issued-at = str(data.at("issued_at", default: "—"))
#let due-at = str(data.at("due_at", default: "—"))
#let period-start = str(data.at("period_start", default: "—"))
#let period-end = str(data.at("period_end", default: "—"))
#let line-items = data.at("line_items", default: ())
#let subtotal = data.at("subtotal", default: 0)
#let vat-total = data.at("vat_total", default: 0)
// US state sales tax (billing-service `us_tax`), when the invoice carries it.
#let us-sales-tax = data.at("us_sales_tax", default: none)
#let total = data.at("total", default: 0)
#let currency-symbol = currency-symbol(currency)

#show: page-setup.with(
  title: "Invoice " + invoice-number,
  footer-left: [#seller.name#meta-sep Reg. #seller-reg#meta-sep VAT #seller-vat],
  footer-right: [
    support\@apexmail.ee#meta-sep apexmail.ee#meta-sep Page #context { counter(page).display() } of #context { counter(page).final().first() }
  ],
)

// ---------------------------------------------------------------------------
// Helpers: authoritative money and date handling
// ---------------------------------------------------------------------------

/// Format minor units with the invoice's own currency symbol (the authority
/// owns the arithmetic; this binds it to this document's currency).
#let money(minor) = fmt-money(minor, currency-symbol)

/// Parse an ISO `YYYY-MM-DD` date; `none` for anything else (never throws).
#let parse-date(s) = {
  if type(s) != str { return none }
  let parts = s.split("-")
  if parts.len() != 3 { return none }
  let (y, m, d) = (int(parts.at(0)), int(parts.at(1)), int(parts.at(2)))
  datetime(year: y, month: m, day: d)
}

/// Payment term in days, derived from the authoritative issue/due dates
/// (`due_at - issued_at`). `none` when either date is unavailable.
#let term-days = {
  let issued = parse-date(issued-at)
  let due = parse-date(due-at)
  if issued == none or due == none { none } else { (due - issued).days() }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#grid(
  columns: (1fr, 1fr),
  // Company info (left)
  [
    #wordmark(size: 19pt)
    #v(4pt)
    #text(size: 8pt, fill: muted)[
      #seller.name \
      #seller-address \
      VAT: #seller-vat \
      Reg: #seller-reg
    ]
  ],
  // Invoice info (right)
  align(right)[
    #text(font: display-font, weight: "semibold", size: 22pt, fill: ink)[INVOICE]
    #v(6pt)
    #table(
      columns: (auto, auto),
      stroke: none,
      align: (left, right),
      [*Invoice \#:*], [#invoice-number],
      [*Status:*], [#upper(status-value)],
      [*Issued:*], [#issued-at],
      [*Due:*], [#due-at],
      [*Period:*], [#period-start — #period-end],
    )
  ],
)

#v(12pt)
#strong-rule()

#if status-value == "paid" [
  #v(10pt)
  #align(right)[
    #block(
      fill: tone-fill("pos"),
      stroke: 1pt + tone-color("pos"),
      inset: (x: 12pt, y: 6pt),
      radius: 0pt,
    )[
      #text(weight: "semibold", size: 10pt, fill: tone-color("pos"), tracking: 0.06em)[
        PAID
        #if "paid_at" in data and data.paid_at != none [ — #data.at("paid_at", default: "—") ]
      ]
    ]
  ]
]

#v(6pt)

// ---------------------------------------------------------------------------
// Bill To
// ---------------------------------------------------------------------------

#text(weight: "bold", size: 11pt)[Bill To:]
#v(4pt)
#block(
  fill: limestone,
  stroke: (left: 2pt + rule),
  inset: 10pt,
  radius: 0pt,
  width: 50%,
)[
  #if "bill_to" in data and data.bill_to != none [
    #if "company" in data.bill_to [#text(weight: "bold")[#data.bill_to.company] \
    ]
    #if "name" in data.bill_to [#data.bill_to.name \
    ]
    #if "address" in data.bill_to [#data.bill_to.address \
    ]
    #if "city" in data.bill_to and "country" in data.bill_to [#data.bill_to.city, #data.bill_to.country \
    ] else if "country" in data.bill_to [#data.bill_to.country \
    ]
    #if "vat_number" in data.bill_to and data.bill_to.vat_number != none and data.bill_to.vat_number != "" [
      VAT: #data.bill_to.vat_number
    ]
  ] else [
    _Customer details not available_
  ]
]

#v(16pt)

// ---------------------------------------------------------------------------
// Line Items Table
// ---------------------------------------------------------------------------

#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: (x: none, y: hairline),
  fill: (x, y) => if y == 0 { limestone } else { none },
  inset: 8pt,
  align: (left, center, right, right, right),
  // Header row
  [*Description*], [*Qty*], [*Unit Price*], [*VAT*], [*Amount*],
  // Data rows
  ..for item in line-items {(
    [#item.description],
    [#item.quantity],
    [#money(item.unit_price)],
    [#item.vat_rate%],
    [#money(item.amount)],
  )}
)

#v(12pt)

// ---------------------------------------------------------------------------
// Totals
// ---------------------------------------------------------------------------

#align(right)[
  #block(width: 45%)[
    #table(
      columns: (1fr, auto),
      stroke: none,
      inset: 6pt,
      align: (left, right),
      [Subtotal], [#money(subtotal)],
      [VAT (#{ let seen = (); for item in line-items { let rate = str(item.vat_rate) + "%"; if not seen.contains(rate) { seen.push(rate) } }; seen.join(", ") })],
      [#money(vat-total)],
      // US state sales tax (billing-service `us_tax`, plan WP C2): rendered
      // only when the invoice carries it, so subtotal + VAT + US tax = total.
      // An exempt sale (customer certificate) says so — a silent $0.00 row
      // would not tell the reader why no tax was charged.
      ..if us-sales-tax == none { () } else if us-sales-tax.at("exempt", default: false) { (
        [US sales tax (#us-sales-tax.state) — exempt#{
          let cert = us-sales-tax.at("certificate_id", default: none)
          if cert == none { "" } else { " (certificate " + cert + ")" }
        }],
        [#money(0)],
      ) } else { (
        [US sales tax (#us-sales-tax.state)],
        [#money(us-sales-tax.amount_cents)],
      ) },
    )
    #strong-rule()
    #table(
      columns: (1fr, auto),
      stroke: none,
      inset: 8pt,
      align: (left, right),
      [*Total (#currency)*], [*#money(total)*],
    )
  ]
]

#v(24pt)

// ---------------------------------------------------------------------------
// Payment Information
// Bank details come from billing configuration (Wise by default); the whole
// transfer block is omitted when no account details are configured.
// Payment terms are derived from the invoice's own issue and due dates.
// ---------------------------------------------------------------------------

#if "bank" in data and data.bank != none [
  #text(weight: "bold", size: 11pt)[Payment Information]
  #v(4pt)
  #block(
    fill: limestone,
    stroke: (left: 2pt + rule),
    inset: 12pt,
    radius: 0pt,
    width: 100%,
  )[
    #grid(
      columns: (1fr, 1fr),
      [
        *Bank Transfer:* \
        Bank: #if "name" in data.bank { data.bank.name } else { [Wise] } \
        #if "iban" in data.bank and data.bank.iban != none and data.bank.iban != "" [IBAN: #data.bank.iban \
        ]
        #if "bic" in data.bank and data.bank.bic != none and data.bank.bic != "" [BIC/SWIFT: #data.bank.bic]
      ],
      [
        *Payment Terms:* \
        Payment due by #due-at#if term-days != none [ (Net #term-days days from the invoice date)].

        *Reference:* #invoice-number
      ],
    )
  ]
] else [
  #text(weight: "bold", size: 11pt)[Payment Information]
  #v(4pt)
  #block(
    fill: limestone,
    stroke: (left: 2pt + rule),
    inset: 12pt,
    radius: 0pt,
    width: 100%,
  )[
    Payments are collected automatically via the configured payment provider. \
    Payment due by #due-at#if term-days != none [ (Net #term-days days from the invoice date)].

    *Reference:* #invoice-number
  ]
]

