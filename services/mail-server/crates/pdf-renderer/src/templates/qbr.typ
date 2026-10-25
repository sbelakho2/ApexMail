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

#import "ark.typ": *

// ── Identity ────────────────────────────────────────────────────────────
#let tenant = if "tenant_id" in data { str(data.tenant_id) } else { "Not recorded" }
#let quarter = if "quarter" in data { str(data.quarter) } else { "—" }
#let year = if "year" in data { str(data.year) } else { "—" }
#let status = if "status" in data { str(data.status) } else { "unknown" }
#let generated = if "created_at" in data and data.created_at != none { str(data.created_at) } else if "delivered_date" in data and data.delivered_date != none { str(data.delivered_date) } else { "Not recorded" }
#let metrics = if "metrics" in data and type(data.metrics) == dictionary { data.metrics } else { (:) }
#let comparison = if "quarter_over_quarter_change" in data and type(data.quarter_over_quarter_change) == dictionary { data.quarter_over_quarter_change } else { (:) }

#show: page-setup.with(
  title: "QBR Q" + quarter + " " + year + " — " + tenant,
  running-title: [QBR#meta-sep Q#quarter #year],
  footer-left: [Confidential],
  footer-center: [Page #context { counter(page).display() } of #context { counter(page).final().first() }],
  footer-right: [Generated #generated],
)

#set par(justify: true)
#set heading(numbering: "1.")

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Thousands-grouped decimal that survives a sign and a fractional part:
// "-100.0" must read "-100.0", never "-,100.0" (the naive end-slicing loop
// grouped the fraction and stranded the sign).
#let fmt-num(n) = {
  let raw = str(n)
  let sign = if raw.starts-with("-") or raw.starts-with("−") { "-" } else { "" }
  // U+2212 (the typographic minus Typst prints) is THREE UTF-8 bytes; slicing
  // it at 1 splits the character and Typst fails the render.
  let unsigned = if raw.starts-with("-") {
    raw.slice(1)
  } else if raw.starts-with("−") {
    raw.slice(3)
  } else {
    raw
  }
  let pieces = unsigned.split(".")
  let whole = pieces.at(0)
  let fraction = if pieces.len() > 1 { "." + pieces.at(1) } else { "" }
  let parts = ()
  let i = whole.len()
  while i > 3 {
    parts.push(whole.slice(i - 3, i))
    i -= 3
  }
  parts.push(whole.slice(0, i))
  sign + parts.rev().join(",") + fraction
}

// A change value: integral deltas drop the ".0" (a count moved 100, not
// 100.0); fractional deltas keep one decimal.
#let fmt-delta(v) = {
  let rounded = calc.round(v * 10) / 10
  if calc.fract(rounded) == 0 { fmt-num(int(rounded)) } else { fmt-num(rounded) }
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
    text(fill: muted)[—]
  } else {
    let delta = c - p
    let direction = direction-for(metric)
    let improved = if direction == "lower-is-better" { delta < 0 }
      else if direction == "higher-is-better" { delta > 0 }
      else { none }
    let color = if improved == none { muted }
      else if improved { tone-color("pos") }
      else if delta == 0 { muted }
      else { tone-color("neg") }
    let arrow = if delta > 0 { "↑" } else if delta < 0 { "↓" } else { "→" }
    let unit = if is-rate(metric) { "pp" } else { "" }
    let direction-word = if improved == none { "" }
      else if delta == 0 { " (unchanged)" }
      else if improved { " (improvement)" }
      else { " (regression)" }
    text(weight: "bold", fill: color)[#arrow #fmt-delta(delta)#unit#direction-word]
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
  let (tone, label) = if s == "info" or s == "informational" { ("neutral", "INFO") }
    else if s == "warning" or s == "warn" { ("warn", "WARNING") }
    else if s == "critical" or s == "error" { ("neg", "CRITICAL") }
    else { ("warn", "UNKNOWN") }
  chip(label, tone: tone)
}

#let goal-badge(status) = {
  let s = if status == none { "unknown" } else { lower(str(status)) }
  let (tone, label) = if s == "completed" { ("pos", "COMPLETED") }
    else if s == "in_progress" { ("neutral", "IN PROGRESS") }
    else if s == "at_risk" { ("warn", "AT RISK") }
    else if s == "not_started" { ("neutral", "NOT STARTED") }
    else if s == "cancelled" { ("neutral", "CANCELLED") }
    else { ("warn", "UNKNOWN") }
  chip(label, tone: tone)
}

#let priority-badge(priority) = {
  let p = if priority == none { "unknown" } else { lower(str(priority)) }
  let tone = if p == "high" or p == "critical" { "neg" }
    else if p == "medium" { "warn" }
    else { "neutral" }
  chip(p, tone: tone)
}

// ---------------------------------------------------------------------------
// Title Page
// ---------------------------------------------------------------------------

#v(20mm)

#align(center)[
  #wordmark(size: 15pt)
  #v(8pt)
  #text(font: display-font, weight: "semibold", size: 28pt, fill: ink)[Quarterly Business Review]
  #v(4pt)
  #text(size: 16pt, fill: faint)[Q#quarter #year]
  #v(20pt)
  #line(length: 50%, stroke: strong-stroke)
  #v(20pt)
  #text(size: 14pt)[Prepared for *#tenant*]
  #v(8pt)
  #text(size: 11pt, fill: muted)[
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
  stroke: (x: none, y: hairline),
  fill: (x, y) => if y == 0 { limestone } else { none },
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
  #text(size: 9pt, fill: muted)[No quarter-over-quarter comparison was recorded for this report.]
]

#v(16pt)

// ---------------------------------------------------------------------------
// 2. Insights
// ---------------------------------------------------------------------------

= Insights

#if "insights" in data and type(data.insights) == array and data.insights.len() > 0 [
  #table(
    columns: (auto, auto, 1fr),
    stroke: hairline,
    fill: (x, y) => if y == 0 { limestone } else { none },
    inset: 8pt,
    align: (left, left, left),
    [*Severity*], [*Category*], [*Finding*],
    ..for insight in data.insights {(
      [#if type(insight) == dictionary { severity-badge(insight.at("severity", default: none)) } else { severity-badge(none) }],
      [#if type(insight) == dictionary { insight.at("category", default: "—") } else { [—] }],
      [#if type(insight) == dictionary {
        let message = str(insight.at("message", default: "—"))
        if "metric_name" in insight and insight.metric_name != none {
          let value = if "metric_value" in insight and insight.metric_value != none {
            str(insight.metric_value)
          } else {
            "not recorded"
          }
          let threshold = if "threshold" in insight and insight.threshold != none {
            ", threshold " + str(insight.threshold)
          } else {
            ""
          }
          message + " (" + str(insight.metric_name) + ": " + value + threshold + ")"
        } else {
          message
        }
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
      fill: limestone,
      stroke: (left: 2pt + rule),
      inset: 12pt,
      radius: 0pt,
      width: 100%,
      below: 8pt,
      breakable: false,
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
    stroke: hairline,
    fill: (x, y) => if y == 0 { limestone } else { none },
    inset: 8pt,
    align: (left, left, right, right),
    [*Goal*], [*Status*], [*Progress*], [*Target*],
    ..for goal in data.goals {(
      [#if type(goal) == dictionary { goal.at("title", default: "—") } else { [#goal] }],
      [#if type(goal) == dictionary { goal-badge(goal.at("status", default: none)) } else { goal-badge(none) }],
      [#if type(goal) == dictionary and "progress_percent" in goal and goal.progress_percent != none { str(goal.progress_percent) + "%" } else { [Not recorded] }],
      [#if type(goal) == dictionary and "target_value" in goal and goal.target_value != none {
        let unit = if "unit" in goal and goal.unit != none { str(goal.unit) } else { "" }
        str(goal.target_value) + if unit == "%" { "%" } else if unit == "" { "" } else { " " + unit }
      } else { [Not recorded] }],
    )}
  )
] else [
  No goals were recorded for this report.
]

#v(24pt)
#line(length: 100%, stroke: hairline)
#v(8pt)
#align(center)[
  #text(size: 9pt, fill: muted)[
    Prepared by Bel Consulting OÜ (trading as ApexMail) for tenant #tenant. \
    For questions, contact support\@apexmail.ee.
  ]
]
