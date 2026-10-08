// ApexMail Quarterly Business Review (QBR) Template
//
// Expected data.json structure (produced by
// `enterprise::routes::qbr_generate_pdf` from the stored
// QuarterlyBusinessReview record):
// {
//   "id": "…", "tenant_id": "…",
//   "quarter": 4, "year": 2025,
//   "status": "completed",
//   "scheduled_date": "2025-12-15", "delivered_date": "2025-12-16T10:00:00Z",
//   "created_at": "2025-12-16T09:00:00Z",
//   "metrics": {
//     "sent": 450000, "delivered": 441900, "bounced": 5850,
//     "opened": 186000, "clicked": 39500,
//     "delivery_rate": 98.2, "bounce_rate": 1.3,
//     "open_rate": 42.1, "click_rate": 8.9
//   },
//   "insights": [ { "category": "deliverability", "severity": "info", "message": "…" } ],
//   "recommendations": [ { "priority": "high", "title": "…", "description": "…" } ],
//   "highlights": [], "concerns": [],
//   "goals": [ { "title": "…", "status": "in_progress", "progress_percent": 60.0,
//                "unit": "%", "target_value": 99.0, "current_value": 98.2 } ],
//   "quarter_over_quarter_change": { "sent": { "previous": 390000, "current": 450000 }, … }
// }
//
// Units: rates are PERCENTAGES. Delivery and bounce rates are computed over
// sent volume; open and click rates over delivered volume. Rate deltas are
// shown in percentage points (pp).
//
// Improvement direction is metric-specific: a rise in sent/delivered/opened/
// clicked/delivery/open/click is an improvement; a rise in bounced/bounce
// rate/complaints/latency is a regression. The two lists below decide the
// colour and the wording, never the sign of the change alone.

#let data = json("data.json")

// ── Identity ────────────────────────────────────────────────────────────
#let tenant = if "tenant_id" in data { str(data.tenant_id) } else { "Not recorded" }
#let quarter = if "quarter" in data { str(data.quarter) } else { "—" }
#let year = if "year" in data { str(data.year) } else { "—" }
#let status = if "status" in data { str(data.status) } else { "unknown" }
#let generated = if "created_at" in data and data.created_at != none { str(data.created_at) } else if "delivered_date" in data and data.delivered_date != none { str(data.delivered_date) } else { "Not recorded" }
#let metrics = if "metrics" in data and type(data.metrics) == dictionary { data.metrics } else { (:) }
#let comparison = if "quarter_over_quarter_change" in data and type(data.quarter_over_quarter_change) == dictionary { data.quarter_over_quarter_change } else { (:) }

#set document(
  title: "QBR Q" + quarter + " " + year + " — " + tenant,
  author: "Bel Consulting OÜ (trading as ApexMail)",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 8pt, fill: luma(140))
      #grid(
        columns: (1fr, 1fr),
        [ApexMail QBR · Q#quarter #year],
        align(right)[Tenant: #tenant],
      )
      #line(length: 100%, stroke: 0.3pt + luma(200))
    ]
  },
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr, 1fr),
      [Confidential],
      align(center)[Page #context { counter(page).display() } of #context { counter(page).final().first() }],
      align(right)[Generated #generated],
    )
  ],
)

#set text(font: ("Noto Sans", "DejaVu Sans"), size: 10pt, hyphenate: false)
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

#let value-or-unknown(value) = {
  if value == none { [Not recorded] } else { [#value] }
}

// Metrics where a HIGHER value is an improvement.
#let good-when-up = ("sent", "delivered", "opened", "clicked", "delivery_rate", "open_rate", "click_rate", "volume", "throughput")
// Metrics where a LOWER value is an improvement.
#let good-when-down = ("bounced", "bounce_rate", "complaints", "complaint_rate", "unsubscribed", "unsubscribe_rate", "avg_latency_ms", "latency_ms", "latency", "failed", "failure_rate", "deferred")

#let direction-for(metric) = {
  if metric in good-when-down { "lower-is-better" }
  else if metric in good-when-up { "higher-is-better" }
  else { "unknown" }
}

#let is-rate(metric) = metric.ends-with("_rate") or metric == "rate"

/// One decimal, always with a decimal part ("98" → "98.0").
#let fmt-dec1(v) = {
  let s = str(calc.round(v, digits: 1))
  if "." in s { s } else { s + ".0" }
}

// A change annotation whose colour/wording follows the metric's own
// improvement direction; an unrecognized metric is reported neutrally and
// never claims an improvement it cannot justify.
#let change-indicator(metric, previous, current, format-fn: fmt-num) = {
  let p = if type(previous) == float or type(previous) == int { previous } else { none }
  let c = if type(current) == float or type(current) == int { current } else { none }
  if p == none or c == none {
    text(fill: luma(120))[—]
  } else {
    let delta = c - p
    let direction = direction-for(metric)
    let improved = if direction == "lower-is-better" { delta < 0 }
      else if direction == "higher-is-better" { delta > 0 }
      else { none }
    let color = if improved == none { luma(120) }
      else if improved { rgb("#16a34a") }
      else if delta == 0 { luma(120) }
      else { rgb("#dc2626") }
    let arrow = if delta > 0 { "↑" } else if delta < 0 { "↓" } else { "→" }
    let unit = if is-rate(metric) { "pp" } else { "" }
    let direction-word = if improved == none { "" }
      else if delta == 0 { " (unchanged)" }
      else if improved { " (improvement)" }
      else { " (regression)" }
    text(weight: "bold", fill: color)[#arrow #format-fn(calc.round(delta * 10) / 10)#unit#direction-word]
  }
}

#let metric-row(metric, label, format-fn: fmt-num, suffix: "") = {
  let current = if metric in metrics { metrics.at(metric) } else { none }
  let change = if metric in comparison and type(comparison.at(metric)) == dictionary { comparison.at(metric) } else { none }
  let previous = if change != none { change.at("previous", default: none) } else { none }
  let current-for-change = if change != none { change.at("current", default: current) } else { current }
  (
    [#label],
    [#if current != none { format-fn(current) + suffix } else { [Not recorded] }],
    [#if previous != none { format-fn(previous) + suffix } else { [Not recorded] }],
    [#change-indicator(metric, previous, current-for-change, format-fn: format-fn)],
  )
}

#let severity-badge(severity) = {
  let s = if severity == none { "unknown" } else { lower(str(severity)) }
  let (color, label) = if s == "info" or s == "informational" { (rgb("#2563eb"), "INFO") }
    else if s == "warning" or s == "warn" { (rgb("#f59e0b"), "WARNING") }
    else if s == "critical" or s == "error" { (rgb("#dc2626"), "CRITICAL") }
    else { (rgb("#f59e0b"), "UNKNOWN") }
  box(
    fill: color.lighten(85%),
    stroke: 0.5pt + color,
    inset: (x: 6pt, y: 2pt),
    radius: 0pt,
    text(weight: "bold", size: 7pt, fill: color.darken(20%))[#label]
  )
}

#let goal-badge(status) = {
  let s = if status == none { "unknown" } else { lower(str(status)) }
  let (color, label) = if s == "completed" { (rgb("#16a34a"), "COMPLETED") }
    else if s == "in_progress" { (rgb("#2563eb"), "IN PROGRESS") }
    else if s == "at_risk" { (rgb("#f59e0b"), "AT RISK") }
    else if s == "not_started" { (luma(120), "NOT STARTED") }
    else if s == "cancelled" { (luma(120), "CANCELLED") }
    else { (rgb("#f59e0b"), "UNKNOWN") }
  box(
    fill: color.lighten(85%),
    stroke: 0.5pt + color,
    inset: (x: 6pt, y: 2pt),
    radius: 0pt,
    text(weight: "bold", size: 7pt, fill: color.darken(20%))[#label]
  )
}

#let priority-badge(priority) = {
  let p = if priority == none { "unknown" } else { lower(str(priority)) }
  let color = if p == "high" or p == "critical" { rgb("#dc2626") }
    else if p == "medium" { rgb("#f59e0b") }
    else { luma(120) }
  box(
    fill: color.lighten(80%),
    stroke: 0.5pt + color,
    inset: (x: 6pt, y: 2pt),
    radius: 0pt,
    text(weight: "bold", size: 7pt, fill: color.darken(20%))[#upper(p)]
  )
}

// ---------------------------------------------------------------------------
// Title Page
// ---------------------------------------------------------------------------

#v(20mm)

#align(center)[
  #text(weight: "bold", size: 14pt, fill: rgb("#dc2626"))[ApexMail]
  #v(8pt)
  #text(weight: "bold", size: 28pt)[Quarterly Business Review]
  #v(4pt)
  #text(size: 16pt, fill: luma(80))[Q#quarter #year]
  #v(20pt)
  #line(length: 50%, stroke: 1.5pt + rgb("#000000"))
  #v(20pt)
  #text(size: 14pt)[Prepared for *#tenant*]
  #v(8pt)
  #text(size: 11pt, fill: luma(120))[
    Status: #upper(status) \
    Generated: #generated
  ]
]

#pagebreak()

// ---------------------------------------------------------------------------
// 1. Key Performance Metrics
// ---------------------------------------------------------------------------

= Key Performance Metrics

Rates are percentages: delivery and bounce rates over sent volume, open and
click rates over delivered volume. Changes are shown against the recorded
quarter-over-quarter comparison, coloured by the metric's own improvement
direction (for example, a rising bounce rate is a regression).

#table(
  columns: (1fr, auto, auto, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
  inset: 10pt,
  align: (left, right, right, center),
  [*Metric*], [*This Quarter*], [*Previous*], [*Change*],
  ..metric-row("sent", "Sending Volume"),
  ..metric-row("delivered", "Delivered"),
  ..metric-row("bounced", "Bounced"),
  ..metric-row("opened", "Opened"),
  ..metric-row("clicked", "Clicked"),
  ..metric-row("delivery_rate", "Delivery Rate", format-fn: fmt-dec1, suffix: "%"),
  ..metric-row("bounce_rate", "Bounce Rate", format-fn: fmt-dec1, suffix: "%"),
  ..metric-row("open_rate", "Open Rate", format-fn: fmt-dec1, suffix: "%"),
  ..metric-row("click_rate", "Click Rate", format-fn: fmt-dec1, suffix: "%"),
)

#if comparison.len() == 0 [
  #v(6pt)
  #text(size: 9pt, fill: luma(120))[No quarter-over-quarter comparison was recorded for this report.]
]

#v(16pt)

// ---------------------------------------------------------------------------
// 2. Insights
// ---------------------------------------------------------------------------

= Insights

#if "insights" in data and type(data.insights) == array and data.insights.len() > 0 [
  #table(
    columns: (auto, auto, 1fr),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
    inset: 8pt,
    align: (left, left, left),
    [*Severity*], [*Category*], [*Finding*],
    ..for insight in data.insights {(
      [#if type(insight) == dictionary { severity-badge(insight.at("severity", default: none)) } else { severity-badge(none) }],
      [#if type(insight) == dictionary { insight.at("category", default: "—") } else { [—] }],
      [#if type(insight) == dictionary {
        insight.at("message", default: "—")
        if "metric_name" in insight and insight.metric_name != none [
          [ (#insight.metric_name: ]
          #value-or-unknown(if "metric_value" in insight { insight.metric_value } else { none })
          #if "threshold" in insight and insight.threshold != none [, threshold #insight.threshold]
          [)]
        ]
      } else { [#insight] }],
    )}
  )
] else [
  No insights were recorded for this report.
]

#v(16pt)

// ---------------------------------------------------------------------------
// 3. Highlights and Concerns
// ---------------------------------------------------------------------------

= Highlights and Concerns

#if "highlights" in data and type(data.highlights) == array and data.highlights.len() > 0 [
  *Highlights*
  #for item in data.highlights [
    - #if type(item) == dictionary { item.at("title", default: item.at("message", default: "—")) } else { item }
  ]
  #v(8pt)
]

#if "concerns" in data and type(data.concerns) == array and data.concerns.len() > 0 [
  *Concerns*
  #for item in data.concerns [
    - #if type(item) == dictionary { item.at("title", default: item.at("message", default: "—")) } else { item }
  ]
]

#if ("highlights" not in data or type(data.highlights) != array or data.highlights.len() == 0) and ("concerns" not in data or type(data.concerns) != array or data.concerns.len() == 0) [
  No highlights or concerns were recorded for this report.
]

#v(16pt)

// ---------------------------------------------------------------------------
// 4. Recommendations
// ---------------------------------------------------------------------------

= Recommendations

#if "recommendations" in data and type(data.recommendations) == array and data.recommendations.len() > 0 [
  #for rec in data.recommendations [
    #block(
      fill: luma(248),
      inset: 12pt,
      radius: 0pt,
      width: 100%,
      below: 8pt,
    )[
      #if type(rec) == dictionary [
        #priority-badge(rec.at("priority", default: none))
        #h(8pt)
        #text(weight: "bold")[#rec.at("title", default: "Recommendation")]
        #v(4pt)
        #text(size: 9pt)[#rec.at("description", default: rec.at("message", default: "—"))]
      ] else [
        #text(size: 9pt)[#rec]
      ]
    ]
  ]
] else [
  No recommendations were recorded for this report.
]

#v(16pt)

// ---------------------------------------------------------------------------
// 5. Goals
// ---------------------------------------------------------------------------

= Goals

#if "goals" in data and type(data.goals) == array and data.goals.len() > 0 [
  #table(
    columns: (1fr, auto, auto, auto),
    stroke: 0.5pt + luma(220),
    fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
    inset: 8pt,
    align: (left, left, right, right),
    [*Goal*], [*Status*], [*Progress*], [*Target*],
    ..for goal in data.goals {(
      [#if type(goal) == dictionary { goal.at("title", default: "—") } else { [#goal] }],
      [#if type(goal) == dictionary { goal-badge(goal.at("status", default: none)) } else { goal-badge(none) }],
      [#if type(goal) == dictionary and "progress_percent" in goal and goal.progress_percent != none { str(goal.progress_percent) + "%" } else { [Not recorded] }],
      [#if type(goal) == dictionary and "target_value" in goal and goal.target_value != none {
        str(goal.target_value)
        if "unit" in goal and goal.unit != none { " " + str(goal.unit) }
      } else { [Not recorded] }],
    )}
  )
] else [
  No goals were recorded for this report.
]

#v(24pt)
#line(length: 100%, stroke: 0.5pt + luma(200))
#v(8pt)
#align(center)[
  #text(size: 9pt, fill: luma(120))[
    Prepared by Bel Consulting OÜ (trading as ApexMail) for tenant #tenant. \
    For questions, contact support\@apexmail.ee.
  ]
]
