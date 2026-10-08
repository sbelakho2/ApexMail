// ApexMail Analytics Export Template
//
// Expected data.json structure (produced by
// `api_server::routes::analytics::export_pdf`):
// {
//   "tenant_name": "…",                       // the tenant identifier
//   "date_range": { "from": "2024-12-01", "to": "2024-12-31" },
//   "generated_at": "2025-01-15T10:30:00Z",
//   "summary": {
//     "total_sent": 145230, "total_delivered": 141890, "total_bounced": 2340,
//     "total_opened": 58756, "total_clicked": 12340,
//     "total_unsubscribed": 0, "total_complaints": 0,
//     "delivery_rate": 97.7, "open_rate": 41.4, "click_rate": 8.7,
//     "bounce_rate": 1.6, "complaint_rate": 0.0
//   },
//   "daily_stats": [],                        // optional sections
//   "top_campaigns": [],
//   "domain_breakdown": []
// }
//
// Units: every `*_rate` and `*_percent` value is a PERCENTAGE (0–100),
// computed by the producer over the sent volume for the period. Counts are
// raw message counts. Sections the producer did not record are rendered as
// "Not recorded for this period" — never as a zero or an empty table.

#let data = json("data.json")

#let tenant = if "tenant_name" in data and data.tenant_name != none { str(data.tenant_name) } else { "Not recorded" }
#let generated = if "generated_at" in data { str(data.generated_at) } else { "Not recorded" }
#let range = if "date_range" in data { data.date_range } else { (from: "—", to: "—") }
#let s = if "summary" in data { data.summary } else { (:) }

#set document(
  title: "Analytics Export — " + tenant,
  author: "Bel Consulting OÜ (trading as ApexMail)",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr),
      [ApexMail Analytics Export · #range.from — #range.to],
      align(right)[Page #context { counter(page).display() } of #context { counter(page).final().first() }],
    )
  ],
)

#set text(font: ("Noto Sans", "DejaVu Sans"), size: 10pt, hyphenate: false)
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

// A rate the producer did not record is not a zero.
#let fmt-rate(key) = {
  if key in s and s.at(key) != none { str(s.at(key)) + "%" } else { [Not recorded] }
}

#let fmt-count(key) = {
  if key in s and s.at(key) != none { fmt-num(s.at(key)) } else { [Not recorded] }
}

// Complaints are only ever reported when the platform recorded a non-zero
// value; a placeholder zero must not read as "no complaints occurred".
#let complaint-available = {
  if "total_complaints" not in s or s.total_complaints == none { false }
  else { s.total_complaints > 0 or (("complaint_rate" in s) and s.complaint_rate > 0) }
}

#let rate-color(rate, good-threshold: 90, warn-threshold: 70) = {
  if rate >= good-threshold { rgb("#16a34a") }
  else if rate >= warn-threshold { rgb("#f59e0b") }
  else { rgb("#ef4444") }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#text(weight: "bold", size: 22pt, fill: rgb("#dc2626"))[Analytics Export]
#v(2pt)
#text(size: 12pt)[Tenant: #tenant]
#v(2pt)
#text(size: 9pt, fill: luma(120))[
  Period: #range.from — #range.to
  #h(16pt) Generated: #generated
]

#v(6pt)
#line(length: 100%, stroke: 1pt + rgb("#000000"))
#v(12pt)

// ---------------------------------------------------------------------------
// Summary Statistics (KPI Cards)
// ---------------------------------------------------------------------------

== Summary Statistics

Rates are percentages of sent volume for the period; counts are message
counts recorded by the platform.

#grid(
  columns: (1fr, 1fr, 1fr),
  column-gutter: 12pt,
  row-gutter: 12pt,
  // Row 1
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[TOTAL SENT]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-count("total_sent")]
  ],
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[DELIVERED]
    #v(2pt)
    #text(weight: "bold", size: 20pt, fill: if "delivery_rate" in s { rate-color(s.delivery_rate) } else { luma(90) })[#fmt-count("total_delivered")]
    #text(size: 9pt, fill: luma(120))[ (#fmt-rate("delivery_rate"))]
  ],
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[BOUNCED]
    #v(2pt)
    #text(weight: "bold", size: 20pt, fill: if "bounce_rate" in s { rate-color(100 - s.bounce_rate) } else { luma(90) })[#fmt-count("total_bounced")]
    #text(size: 9pt, fill: luma(120))[ (#fmt-rate("bounce_rate"))]
  ],
  // Row 2
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[OPENED]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-count("total_opened")]
    #text(size: 9pt, fill: luma(120))[ (#fmt-rate("open_rate"))]
  ],
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[CLICKED]
    #v(2pt)
    #text(weight: "bold", size: 20pt)[#fmt-count("total_clicked")]
    #text(size: 9pt, fill: luma(120))[ (#fmt-rate("click_rate"))]
  ],
  block(fill: luma(248), inset: 12pt, radius: 0pt, width: 100%)[
    #text(size: 8pt, fill: luma(120))[COMPLAINTS]
    #v(2pt)
    #if complaint-available [
      #text(weight: "bold", size: 20pt)[#fmt-num(s.total_complaints)]
      #text(size: 9pt, fill: luma(120))[ (#fmt-rate("complaint_rate"))]
    ] else [
      #text(weight: "bold", size: 14pt, fill: luma(120))[Not reported]
    ]
  ],
)

#v(16pt)

// ---------------------------------------------------------------------------
// Daily Sending Volume
// ---------------------------------------------------------------------------

== Daily Sending Volume

#if "daily_stats" in data and data.daily_stats.len() > 0 [
  #table(
    columns: (auto, auto, auto, auto, auto, auto),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else if calc.rem(y, 2) == 0 { luma(250) } else { none },
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
] else [
  No daily breakdown was recorded for this period.
]

#v(16pt)

// ---------------------------------------------------------------------------
// Top Campaigns
// ---------------------------------------------------------------------------

== Top Campaigns

#if "top_campaigns" in data and data.top_campaigns.len() > 0 [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
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
] else [
  No campaign breakdown was recorded for this period.
]

#v(16pt)

// ---------------------------------------------------------------------------
// Domain Breakdown
// ---------------------------------------------------------------------------

== Delivery by Domain

#if "domain_breakdown" in data and data.domain_breakdown.len() > 0 [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
    inset: 8pt,
    align: (left, right, right, right),
    [*Domain*], [*Volume*], [*Delivery Rate*], [*Open Rate*],
    ..for d in data.domain_breakdown {(
      [#d.domain],
      [#fmt-num(d.sent)],
      [
        #text(fill: rate-color(d.delivery_rate))[#d.delivery_rate%]
      ],
      [#d.open_rate%],
    )}
  )
] else [
  No recipient-domain breakdown was recorded for this period.
]

#v(16pt)
#line(length: 100%, stroke: 0.5pt + luma(200))
#v(8pt)
#align(center)[
  #text(size: 8pt, fill: luma(120))[
    Prepared by Bel Consulting OÜ (trading as ApexMail) · support\@apexmail.ee
  ]
]
