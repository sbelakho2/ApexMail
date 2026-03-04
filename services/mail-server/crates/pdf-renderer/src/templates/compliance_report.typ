// ApexMail Compliance Report Template
//
// Expected data.json structure:
// {
//   "tenant_name": "Acme Corp",
//   "report_date": "2025-01-15",
//   "date_range": { "from": "2024-12-01", "to": "2024-12-31" },
//   "overall_score": 94,
//   "scores": {
//     "data_protection": 96,
//     "access_control": 92,
//     "encryption": 100,
//     "audit_logging": 88,
//     "retention_policy": 95,
//     "breach_readiness": 90
//   },
//   "checks": [
//     { "name": "TLS 1.3 enforced", "status": "pass", "details": "All endpoints use TLS 1.3" },
//     { "name": "AES-256 at rest", "status": "pass", "details": "All data encrypted" },
//     { "name": "MFA enabled", "status": "warn", "details": "2 of 5 operators lack MFA" },
//     { "name": "Log retention >90d", "status": "pass", "details": "365 day retention" }
//   ],
//   "audit_entries": [
//     { "timestamp": "2024-12-30T14:22:00Z", "actor": "admin@acme.com", "action": "domain.verify", "resource": "acme.com", "ip": "1.2.3.4" },
//     { "timestamp": "2024-12-29T09:15:00Z", "actor": "system", "action": "key.rotate", "resource": "dkim-key-1", "ip": "internal" }
//   ]
// }

#let data = json("data.json")

#set document(
  title: "Compliance Report — " + data.tenant_name,
  author: "ApexMail OÜ",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr),
      [ApexMail Compliance Report · Generated #data.report_date],
      align(right)[Page #counter(page).display()],
    )
  ],
)

#set text(font: "Helvetica", size: 10pt)
#set par(justify: true)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#let status-badge(status) = {
  let (color, label) = if status == "pass" {
    (rgb("#22c55e"), "PASS")
  } else if status == "warn" {
    (rgb("#f59e0b"), "WARN")
  } else {
    (rgb("#ef4444"), "FAIL")
  }
  box(
    fill: color.lighten(80%),
    stroke: 0.5pt + color,
    inset: (x: 6pt, y: 2pt),
    radius: 3pt,
    text(weight: "bold", size: 8pt, fill: color.darken(20%))[#label]
  )
}

#let score-color(score) = {
  if score >= 90 { rgb("#22c55e") }
  else if score >= 70 { rgb("#f59e0b") }
  else { rgb("#ef4444") }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#grid(
  columns: (1fr, auto),
  [
    #text(weight: "bold", size: 20pt, fill: rgb("#2563eb"))[Compliance Report]
    #v(4pt)
    #text(size: 12pt)[#data.tenant_name]
    #v(2pt)
    #text(size: 9pt, fill: luma(120))[
      Period: #data.date_range.from — #data.date_range.to \
      Generated: #data.report_date
    ]
  ],
  align(right + horizon)[
    #block(
      fill: score-color(data.overall_score).lighten(85%),
      stroke: 1.5pt + score-color(data.overall_score),
      inset: 16pt,
      radius: 8pt,
    )[
      #text(size: 9pt, fill: luma(100))[Overall Score]
      #v(2pt)
      #text(weight: "bold", size: 32pt, fill: score-color(data.overall_score))[
        #data.overall_score%
      ]
    ]
  ],
)

#v(8pt)
#line(length: 100%, stroke: 1pt + rgb("#2563eb"))
#v(12pt)

// ---------------------------------------------------------------------------
// Score Breakdown
// ---------------------------------------------------------------------------

== Score Breakdown

#table(
  columns: (1fr, auto, 1fr),
  stroke: none,
  inset: 8pt,
  ..for (name, score) in data.scores.pairs() {(
    [#name.replace("_", " ").split(" ").map(w => upper(w.first()) + w.slice(1)).join(" ")],
    align(right)[
      #text(weight: "bold", fill: score-color(score))[#score%]
    ],
    [
      #box(
        width: 100%,
        height: 8pt,
        fill: luma(230),
        radius: 4pt,
      )[
        #box(
          width: score * 1%,
          height: 8pt,
          fill: score-color(score),
          radius: 4pt,
        )
      ]
    ],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// Configuration Checks
// ---------------------------------------------------------------------------

== Configuration Status Checks

#table(
  columns: (auto, 1fr, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, left, center),
  [*Check*], [*Details*], [*Status*],
  ..for check in data.checks {(
    [#check.name],
    [#check.details],
    [#status-badge(check.status)],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// Audit Log Entries
// ---------------------------------------------------------------------------

== Audit Log (Recent Entries)

#table(
  columns: (auto, auto, auto, 1fr, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else if calc.rem(y, 2) == 0 { luma(250) } else { none },
  inset: 6pt,
  align: (left, left, left, left, left),
  [*Timestamp*], [*Actor*], [*Action*], [*Resource*], [*IP*],
  ..for entry in data.audit_entries {(
    text(size: 8pt)[#entry.timestamp],
    text(size: 8pt)[#entry.actor],
    [#entry.action],
    [#entry.resource],
    text(size: 8pt, font: "Courier")[#entry.ip],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// Recommendations
// ---------------------------------------------------------------------------

== Recommendations

#let warnings = data.checks.filter(c => c.status != "pass")
#if warnings.len() > 0 [
  The following items require attention:

  #for (i, w) in warnings.enumerate() [
    #numbering("1.", i + 1) *#w.name* — #w.details \
  ]
] else [
  #block(
    fill: rgb("#22c55e").lighten(85%),
    stroke: 1pt + rgb("#22c55e"),
    inset: 12pt,
    radius: 4pt,
    width: 100%,
  )[
    #text(fill: rgb("#15803d"))[
      ✓ All configuration checks passed. No immediate action required.
    ]
  ]
]
