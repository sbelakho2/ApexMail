// ApexMail Quarterly Business Review (QBR) Template
//
// Expected data.json structure:
// {
//   "tenant_name": "Acme Corp",
//   "quarter": "Q4 2024",
//   "date_range": { "from": "2024-10-01", "to": "2024-12-31" },
//   "generated_at": "2025-01-10",
//   "account_manager": "Sarah Johnson",
//   "executive_summary": "Strong quarter with 15% growth in sending volume...",
//   "metrics": {
//     "sending_volume": { "current": 450000, "previous": 390000, "change_pct": 15.4 },
//     "delivery_rate": { "current": 98.2, "previous": 97.8, "change_pct": 0.4 },
//     "bounce_rate": { "current": 1.3, "previous": 1.8, "change_pct": -27.8 },
//     "open_rate": { "current": 42.1, "previous": 39.5, "change_pct": 6.6 },
//     "click_rate": { "current": 8.9, "previous": 7.2, "change_pct": 23.6 },
//     "complaint_rate": { "current": 0.005, "previous": 0.008, "change_pct": -37.5 },
//     "avg_latency_ms": { "current": 245, "previous": 310, "change_pct": -21.0 }
//   },
//   "monthly_breakdown": [
//     { "month": "October", "sent": 140000, "delivery_rate": 98.0, "open_rate": 41.2, "click_rate": 8.5 },
//     { "month": "November", "sent": 155000, "delivery_rate": 98.3, "open_rate": 42.8, "click_rate": 9.1 },
//     { "month": "December", "sent": 155000, "delivery_rate": 98.4, "open_rate": 42.3, "click_rate": 9.0 }
//   ],
//   "top_performing_campaigns": [
//     { "name": "Black Friday", "sent": 45000, "open_rate": 52.3, "click_rate": 15.2, "revenue": "$12,400" },
//     { "name": "Holiday Gift Guide", "sent": 38000, "open_rate": 48.1, "click_rate": 11.8, "revenue": "$9,200" }
//   ],
//   "incidents": [
//     { "date": "2024-11-15", "type": "Degraded delivery", "duration": "45 min", "impact": "~2000 emails delayed", "resolution": "Upstream provider issue resolved" }
//   ],
//   "recommendations": [
//     { "priority": "high", "title": "Implement list hygiene automation", "description": "Auto-remove contacts with >5 consecutive bounces to maintain sender reputation." },
//     { "priority": "medium", "title": "A/B test subject lines", "description": "Running A/B tests on top 5 campaigns could increase open rates by 5-10%." },
//     { "priority": "low", "title": "Enable send-time optimization", "description": "ML-based send time optimization is available on your plan and could improve engagement." }
//   ],
//   "next_quarter_goals": [
//     "Achieve 99% delivery rate",
//     "Reduce bounce rate below 1%",
//     "Launch automated welcome series"
//   ]
// }

#let data = json("data.json")

#set document(
  title: "QBR " + data.quarter + " — " + data.tenant_name,
  author: "ApexMail OÜ",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 8pt, fill: luma(140))
      #grid(
        columns: (1fr, 1fr),
        [ApexMail QBR · #data.quarter],
        align(right)[#data.tenant_name],
      )
      #line(length: 100%, stroke: 0.3pt + luma(200))
    ]
  },
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr, 1fr),
      [Confidential],
      align(center)[Page #counter(page).display() of #locate(loc => counter(page).final(loc).first())],
      align(right)[#data.generated_at],
    )
  ],
)

#set text(font: "Helvetica", size: 10pt)
#set par(justify: true)
#set heading(numbering: "1.")

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

#let change-indicator(pct) = {
  let color = if pct > 0 { rgb("#22c55e") } else if pct < 0 { rgb("#ef4444") } else { luma(120) }
  let arrow = if pct > 0 { "↑" } else if pct < 0 { "↓" } else { "→" }
  text(weight: "bold", fill: color)[#arrow #calc.abs(pct)%]
}

#let priority-badge(p) = {
  let color = if p == "high" { rgb("#ef4444") } else if p == "medium" { rgb("#f59e0b") } else { rgb("#3b82f6") }
  box(
    fill: color.lighten(80%),
    stroke: 0.5pt + color,
    inset: (x: 6pt, y: 2pt),
    radius: 3pt,
    text(weight: "bold", size: 7pt, fill: color.darken(20%))[#upper(p)]
  )
}

// ---------------------------------------------------------------------------
// Title Page
// ---------------------------------------------------------------------------

#v(20mm)

#align(center)[
  #text(weight: "bold", size: 14pt, fill: rgb("#2563eb"))[ApexMail]
  #v(8pt)
  #text(weight: "bold", size: 28pt)[Quarterly Business Review]
  #v(4pt)
  #text(size: 16pt, fill: luma(80))[#data.quarter]
  #v(20pt)
  #line(length: 50%, stroke: 1.5pt + rgb("#2563eb"))
  #v(20pt)
  #text(size: 14pt)[Prepared for *#data.tenant_name*]
  #v(8pt)
  #text(size: 11pt, fill: luma(120))[
    Account Manager: #data.account_manager \
    Generated: #data.generated_at
  ]
]

#pagebreak()

// ---------------------------------------------------------------------------
// 1. Executive Summary
// ---------------------------------------------------------------------------

= Executive Summary

#data.executive_summary

#v(16pt)

// ---------------------------------------------------------------------------
// 2. Key Performance Metrics
// ---------------------------------------------------------------------------

= Key Performance Metrics

#let m = data.metrics

#table(
  columns: (1fr, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else { none },
  inset: 10pt,
  align: (left, right, right, center),
  [*Metric*], [*This Quarter*], [*Last Quarter*], [*Change*],
  [Sending Volume], [#fmt-num(m.sending_volume.current)], [#fmt-num(m.sending_volume.previous)], [#change-indicator(m.sending_volume.change_pct)],
  [Delivery Rate], [#m.delivery_rate.current%], [#m.delivery_rate.previous%], [#change-indicator(m.delivery_rate.change_pct)],
  [Bounce Rate], [#m.bounce_rate.current%], [#m.bounce_rate.previous%], [#change-indicator(m.bounce_rate.change_pct)],
  [Open Rate], [#m.open_rate.current%], [#m.open_rate.previous%], [#change-indicator(m.open_rate.change_pct)],
  [Click Rate], [#m.click_rate.current%], [#m.click_rate.previous%], [#change-indicator(m.click_rate.change_pct)],
  [Complaint Rate], [#m.complaint_rate.current%], [#m.complaint_rate.previous%], [#change-indicator(m.complaint_rate.change_pct)],
  [Avg Latency], [#m.avg_latency_ms.current ms], [#m.avg_latency_ms.previous ms], [#change-indicator(m.avg_latency_ms.change_pct)],
)

#v(16pt)

// ---------------------------------------------------------------------------
// 3. Monthly Breakdown
// ---------------------------------------------------------------------------

= Monthly Breakdown

#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else if calc.rem(y, 2) == 0 { luma(250) } else { none },
  inset: 8pt,
  align: (left, right, right, right, right),
  [*Month*], [*Sent*], [*Delivery*], [*Opens*], [*Clicks*],
  ..for mo in data.monthly_breakdown {(
    [#mo.month],
    [#fmt-num(mo.sent)],
    [#mo.delivery_rate%],
    [#mo.open_rate%],
    [#mo.click_rate%],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// 4. Top Performing Campaigns
// ---------------------------------------------------------------------------

= Top Performing Campaigns

#table(
  columns: (1fr, auto, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#2563eb").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, right, right, right, right),
  [*Campaign*], [*Sent*], [*Open Rate*], [*Click Rate*], [*Revenue*],
  ..for c in data.top_performing_campaigns {(
    [#c.name],
    [#fmt-num(c.sent)],
    [#c.open_rate%],
    [#c.click_rate%],
    [#c.revenue],
  )}
)

#v(16pt)

// ---------------------------------------------------------------------------
// 5. Incidents
// ---------------------------------------------------------------------------

= Service Incidents

#if data.incidents.len() == 0 [
  #block(
    fill: rgb("#22c55e").lighten(85%),
    inset: 12pt,
    radius: 4pt,
    width: 100%,
  )[✓ No service incidents during this quarter.]
] else [
  #table(
    columns: (auto, auto, auto, 1fr, 1fr),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#fef3c7") } else { none },
    inset: 6pt,
    [*Date*], [*Type*], [*Duration*], [*Impact*], [*Resolution*],
    ..for inc in data.incidents {(
      [#inc.date],
      [#inc.type],
      [#inc.duration],
      text(size: 9pt)[#inc.impact],
      text(size: 9pt)[#inc.resolution],
    )}
  )
]

#v(16pt)

// ---------------------------------------------------------------------------
// 6. Recommendations
// ---------------------------------------------------------------------------

= Recommendations

#for rec in data.recommendations [
  #block(
    fill: luma(248),
    inset: 12pt,
    radius: 4pt,
    width: 100%,
    below: 8pt,
  )[
    #priority-badge(rec.priority)
    #h(8pt)
    #text(weight: "bold")[#rec.title]
    #v(4pt)
    #text(size: 9pt)[#rec.description]
  ]
]

#v(16pt)

// ---------------------------------------------------------------------------
// 7. Next Quarter Goals
// ---------------------------------------------------------------------------

= Next Quarter Goals

#for (i, goal) in data.next_quarter_goals.enumerate() [
  #numbering("1.", i + 1) #goal \
]

#v(24pt)
#line(length: 100%, stroke: 0.5pt + luma(200))
#v(8pt)
#align(center)[
  #text(size: 9pt, fill: luma(120))[
    This report was prepared by ApexMail for #data.tenant_name. \
    For questions, contact your account manager: #data.account_manager.
  ]
]
