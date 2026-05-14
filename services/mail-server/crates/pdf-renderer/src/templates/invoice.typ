// ApexMail Invoice Template
// Rendered by pdf-renderer with JSON data from billing-service
//
// Expected data.json structure:
// {
//   "invoice_number": "INV-2025-0042",
//   "status": "paid",
//   "currency": "EUR",
//   "issued_at": "2025-01-15",
//   "due_at": "2025-02-14",
//   "paid_at": "2025-01-20",
//   "period_start": "2025-01-01",
//   "period_end": "2025-01-31",
//   "subtotal": 9900,       // cents
//   "vat_total": 2178,      // cents
//   "total": 12078,         // cents
//   "line_items": [
//     { "description": "Professional Plan", "quantity": 1, "unit_price": 9900, "amount": 9900, "vat_rate": 22, "vat_amount": 2178 }
//   ],
//   "bill_to": {
//     "company": "Acme Corp",
//     "name": "Jane Doe",
//     "address": "123 Main St",
//     "city": "Tallinn",
//     "country": "EE",
//     "vat_number": "EE123456789"
//   }
// }

#let data = json("data.json")

#set document(
  title: "Invoice " + data.invoice_number,
  author: "ApexMail OÜ",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  footer: [
    #line(length: 100%, stroke: 0.5pt + luma(180))
    #v(4pt)
    #set text(size: 7pt, fill: luma(120))
    #grid(
      columns: (1fr, 1fr),
      align(left)[
        ApexMail OÜ · Reg. 16789012 · VAT EE102345678 \
        Tornimäe 5, 10145 Tallinn, Estonia
      ],
      align(right)[
        support\@apexmail.ee · apexmail.ee \
        Page #counter(page).display() of #locate(loc => counter(page).final(loc).first())
      ],
    )
  ],
)

#set text(font: "Inter", "DejaVu Sans", sans-serif, size: 10pt)

// ---------------------------------------------------------------------------
// Helper: format cents to currency string
// ---------------------------------------------------------------------------

#let fmt-money(cents) = {
  let eur = calc.floor(cents / 100)
  let ct = calc.rem(cents, 100)
  let ct-str = if ct < 10 { "0" + str(ct) } else { str(ct) }
  "€" + str(eur) + "." + ct-str
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#grid(
  columns: (1fr, 1fr),
  // Company info (left)
  [
    #text(weight: "bold", size: 18pt, fill: rgb("#dc2626"))[ApexMail]
    #v(4pt)
    #text(size: 8pt, fill: luma(100))[
      ApexMail OÜ \
      Tornimäe 5, 10145 Tallinn \
      Estonia \
      VAT: EE102345678 \
      Reg: 16789012
    ]
  ],
  // Invoice info (right)
  align(right)[
    #text(weight: "bold", size: 22pt)[INVOICE]
    #v(6pt)
    #table(
      columns: (auto, auto),
      stroke: none,
      align: (left, right),
      [*Invoice \#:*], [#data.invoice_number],
      [*Status:*], [#upper(data.status)],
      [*Issued:*], [#data.issued_at],
      [*Due:*], [#data.due_at],
      [*Period:*], [#data.period_start — #data.period_end],
    )
  ],
)

#v(12pt)
#line(length: 100%, stroke: 1pt + rgb("#000000"))
#v(12pt)

// ---------------------------------------------------------------------------
// Bill To
// ---------------------------------------------------------------------------

#text(weight: "bold", size: 11pt)[Bill To:]
#v(4pt)
#block(
  fill: luma(248),
  inset: 10pt,
  radius: 0pt,
  width: 50%,
)[
  #if "bill_to" in data [
    #text(weight: "bold")[#data.bill_to.company] \
    #data.bill_to.name \
    #data.bill_to.address \
    #data.bill_to.city, #data.bill_to.country \
    #if "vat_number" in data.bill_to [
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
  stroke: (x: none, y: 0.5pt + luma(200)),
  fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else if calc.rem(y, 2) == 0 { luma(250) } else { none },
  inset: 8pt,
  align: (left, center, right, right, right),
  // Header row
  [*Description*], [*Qty*], [*Unit Price*], [*VAT*], [*Amount*],
  // Data rows
  ..for item in data.line_items {(
    [#item.description],
    [#item.quantity],
    [#fmt-money(item.unit_price)],
    [#item.vat_rate%],
    [#fmt-money(item.amount)],
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
      [Subtotal], [#fmt-money(data.subtotal)],
      [VAT (#{ let rates = data.line_items.map(i => str(i.vat_rate) + "%"); rates.dedup(); rates.join(", ") })],
      [#fmt-money(data.vat_total)],
    )
    #line(length: 100%, stroke: 1.5pt + rgb("#000000"))
    #table(
      columns: (1fr, auto),
      stroke: none,
      inset: 8pt,
      align: (left, right),
      [*Total (#data.currency)*], [*#fmt-money(data.total)*],
    )
  ]
]

#v(24pt)

// ---------------------------------------------------------------------------
// Payment Information
// ---------------------------------------------------------------------------

#text(weight: "bold", size: 11pt)[Payment Information]
#v(4pt)
#block(
  fill: luma(248),
  inset: 12pt,
  radius: 0pt,
  width: 100%,
)[
  #grid(
    columns: (1fr, 1fr),
    [
      *Bank Transfer:* \
      Bank: LHV Pank \
      IBAN: EE867700771002345678 \
      BIC/SWIFT: LHVBEE22
    ],
    [
      *Payment Terms:* \
      Net 30 days from invoice date \
      Late payment interest: 0.05% per day \
      \
      *Reference:* #data.invoice_number
    ],
  )
]

#if data.status == "paid" [
  #v(16pt)
  #align(center)[
    #block(
      fill: rgb("#16a34a").lighten(80%),
      stroke: 1pt + rgb("#16a34a"),
      inset: 12pt,
      radius: 0pt,
    )[
      #text(weight: "bold", size: 14pt, fill: rgb("#16a34a"))[
        ✓ PAID
        #if "paid_at" in data [ — #data.paid_at ]
      ]
    ]
  ]
]
