// ApexMail Analytics Export Template
//
// Expected data.json structure:
// {
//   "tenant_name": "Acme Corp",
//   "date_range": { "from": "2024-12-01", "to": "2024-12-31" },
//   "generated_at": "2025-01-15T10:30:00Z",
//   "summary": {
//     "total_sent": 145230,
//     "total_delivered": 141890,
//     "total_bounced": 2340,
//     "total_opened": 58756,
//     "total_clicked": 12340,
//     "total_unsubscribed": 456,
//     "total_complaints": 12,
//     "delivery_rate": 97.7,
//     "open_rate": 41.4,
//     "click_rate": 8.7,
//     "bounce_rate": 1.6,
//     "complaint_rate": 0.008
//   },
//   "daily_stats": [
//     { "date": "2024-12-01", "sent": 4820, "delivered": 4710, "opened": 1950, "clicked": 410, "bounced": 80 },
//     { "date": "2024-12-02", "sent": 5100, "delivered": 4980, "opened": 2050, "clicked": 430, "bounced": 90 }
//   ],
//   "top_campaigns": [
//     { "name": "Holiday Sale", "sent": 25000, "open_rate": 48.2, "click_rate": 12.1 },
//     { "name": "Newsletter #12", "sent": 18000, "open_rate": 35.6, "click_rate": 6.4 }
//   ],
//   "domain_breakdown": [
//     { "domain": "gmail.com", "sent": 52000, "delivery_rate": 98.1, "open_rate": 42.3 },
//     { "domain": "outlook.com", "sent": 31000, "delivery_rate": 97.5, "open_rate": 38.7 }
//   ]
// }

#let data = json("data.json")

#set document(
  title: "Analytics Export — " + data.tenant_name,
  author: "ApexMail OÜ",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr),
      [ApexMail Analytics Export · #data.date_range.from — #data.date_range.to],
      align(right)[Page #counter(page).display()],
    )
  ],
)

#set text(font: "Helvetica", size: 10pt)
#set par(justify: true)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#let fmt-num(n) = {
  let s = str(n)
  let parts = ()
  let i = s.len()
  while i > 3 {
    parts.push(s.slice(i - 3, i))
    i -= 3
  }
  parts.push(s.slice(0, i))
  parts.rev().join(",")
}

#let rate-color(rate, good-threshold: 90, warn-threshold: 70) = {
  if rate >= good-threshold { rgb("#22c55e") }
  else if rate >= warn-threshold { rgb("#f59e0b") }
  else { rgb("#ef4444") }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#text(weight: "bold", size: 22pt, fill: rgb("#2563eb"))[Analytics Export]
#v(2pt)
#text(size: 12pt)[#data.tenant_name]
#v(2pt)
#text(size: 9pt, fill: luma(120))[
  Period: #data.date_range.from — #data.date_range.to
  #h(16pt) Generated: #data.generated_at
]

#v(6pt)
#line(length: 100%, stroke: 1pt + rgb("#2563eb"))
#v(12pt)

// ---------------------------------------------------------------------------
// Summary Statistics (KPI Cards)
// ---------------------------------------------------------------------------

== Summary Statistics

#let s = data.summary

#grid(
  columns: (1fr, 1fr, 1fr),
  column-gutter: 12pt,
  row-gutter: 12pt,
  // Row 1
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[TOTAL SENT]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-num(s.total_sent)]
  ],
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[DELIVERED]
    #v(2pt)
    #text(weight: "bold", size: 20pt, fill: rate-color(s.delivery_rate))[#fmt-num(s.total_delivered)]
    #text(size: 9pt, fill: luma(120))[ (#s.delivery_rate%)]
  ],
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[BOUNCED]
    #v(2pt)
    #text(weight: "bold", size: 20pt, fill: rate-color(100 - s.bounce_rate))[#fmt-num(s.total_bounced)]
    #text(size: 9pt, fill: luma(120))[ (#s.bounce_rate%)]
  ],
  // Row 2
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[OPENED]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-num(s.total_opened)]
    #text(size: 9pt, fill: luma(120))[ (#s.open_rate%)]
  ],
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[CLICKED]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-num(s.total_clicked)]
    #text(size: 9pt, fill: luma(120))[ (#s.click_rate%)]
  ],
  block(fill: luma(248), inset: 12pt, radius: 4pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[COMPLAINTS]
    #v(2pt)
    #text(weight: "bold", size: 20pt, fill: rate-color(100 - s.complaint_rate * 1000, good-threshold: 99, warn-threshold: 95))[#s.total_complaints]
    #text(size: 9pt, fill: luma(120))[ (#s.complaint_rate%)]
  ],
)

#v(16pt)

// ---------------------------------------------------------------------------
// Daily Sending Volume
// ---------------------------------------------------------------------------

== Daily Sending Volume

#table(
  columns: (auto, auto, auto, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else if calc.rem(y, 2) == 0 { luma(250) } else { none },
  inset: 6pt,
  align: (left, right, right, right, right, right),
  [*Date*], [*Sent*], [*Delivered*], [*Opened*], [*Clicked*], [*Bounced*],
  ..for day in data.daily_stats {(
    [#day.date],
    [#fmt-num(day.sent)],
    [#fmt-num(day.delivered)],
    [#fmt-num(day.opened)],
    [#fmt-num(day.clicked)],
    [#fmt-num(day.bounced)],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// Top Campaigns
// ---------------------------------------------------------------------------

== Top Campaigns

#table(
  columns: (1fr, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, right, right, right),
  [*Campaign*], [*Sent*], [*Open Rate*], [*Click Rate*],
  ..for c in data.top_campaigns {(
    [#c.name],
    [#fmt-num(c.sent)],
    [#c.open_rate%],
    [#c.click_rate%],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// Domain Breakdown
// ---------------------------------------------------------------------------

== Delivery by Domain

#table(
  columns: (1fr, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, right, right, right),
  [*Domain*], [*Volume*], [*Delivery Rate*], [*Open Rate*],
  ..for d in data.domain_breakdown {(
    text(font: "Courier")[#d.domain],
    [#fmt-num(d.sent)],
    [
      #text(fill: rate-color(d.delivery_rate))[#d.delivery_rate%]
    ],
    [#d.open_rate%],
  )}
)
