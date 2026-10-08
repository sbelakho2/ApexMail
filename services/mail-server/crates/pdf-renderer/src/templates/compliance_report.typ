// ApexMail Compliance Report Template
//
// Expected data.json structure (produced by
// `enterprise::compliance::ComplianceService::generate_report`):
// {
//   "tenant_id": "…",
//   "generated_at": "2026-01-15T10:00:00Z",
//   "enabled_frameworks": ["gdpr", "soc2"],
//   "status": "active",                     // recorded configuration status
//   "baa_signed": true,
//   "baa_signed_at": "2026-01-02T00:00:00Z",
//   "dpa_signed": true,
//   "zero_retention_mode": false,
//   "encryption_at_rest": true,
//   "encryption_in_transit": true,
//   "audit_log_entries": 128,               // count in the audit log
//   "data_access_requests": 3,              // count of recorded requests
//   "audit_retention_days": 365
// }
//
// Evidence scope: this report reproduces the tenant's RECORDED compliance
// configuration at the generation time. It is not an independent audit
// attestation and does not assert anything the recorded configuration does
// not contain — unknown or absent values are rendered as "Unknown"/"Not
// recorded", never as a failure.

#let data = json("data.json")

#set document(
  title: "Compliance Report — " + data.tenant_id,
  author: "Bel Consulting OÜ (trading as ApexMail)",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 20mm, right: 20mm),
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr),
      [ApexMail Compliance Report · Generated #data.generated_at],
      align(right)[Page #context { counter(page).display() }],
    )
  ],
)

#set text(font: ("Noto Sans", "DejaVu Sans"), size: 10pt, hyphenate: false)
#set par(justify: true)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Tri-state badge: a recorded boolean is Signed/Not signed or Enabled/
// Disabled; a value the report cannot interpret is Unknown — never Fail.
#let tri-badge(value, positive: "Yes", negative: "No") = {
  if value == true {
    box(fill: rgb("#16a34a").lighten(85%), stroke: 0.5pt + rgb("#16a34a"), inset: (x: 6pt, y: 2pt), radius: 0pt,
        text(weight: "bold", size: 8pt, fill: rgb("#16a34a").darken(20%))[#positive])
  } else if value == false {
    box(fill: luma(240), stroke: 0.5pt + luma(180), inset: (x: 6pt, y: 2pt), radius: 0pt,
        text(weight: "bold", size: 8pt, fill: luma(110))[#negative])
  } else {
    box(fill: rgb("#f59e0b").lighten(85%), stroke: 0.5pt + rgb("#f59e0b"), inset: (x: 6pt, y: 2pt), radius: 0pt,
        text(weight: "bold", size: 8pt, fill: rgb("#b45309"))[UNKNOWN])
  }
}

// Configuration status: recognized values get a label; anything else is
// explicitly Unknown (an unrecognized status is not a failure).
#let status-label(value) = {
  if value == none { "Unknown (not recorded)" }
  else {
    let s = lower(str(value))
    if s == "active" or s == "enabled" or s == "compliant" { upper(str(value)) + " (recorded)" }
    else if s == "inactive" or s == "disabled" or s == "not_configured" { upper(str(value)) + " (recorded)" }
    else { "Unknown (unrecognized status: " + str(value) + ")" }
  }
}

#let value-or-unknown(value) = {
  if value == none { [Unknown (not recorded)] } else { [#value] }
}

#let frameworks = if "enabled_frameworks" in data and data.enabled_frameworks != none and data.enabled_frameworks.len() > 0 {
  data.enabled_frameworks.map(f => upper(str(f))).join(", ")
} else { [None recorded] }

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

#grid(
  columns: (1fr, auto),
  [
    #text(weight: "bold", size: 20pt, fill: rgb("#dc2626"))[Compliance Report]
    #v(4pt)
    #text(size: 12pt)[Tenant: #data.tenant_id]
    #v(2pt)
    #text(size: 9pt, fill: luma(120))[
      Generated: #data.generated_at
    ]
  ],
  align(right + horizon)[
    #block(
      fill: luma(245),
      stroke: 1pt + luma(200),
      inset: 14pt,
      radius: 0pt,
      width: 100%,
    )[
      #text(size: 8pt, fill: luma(100))[CONFIGURATION STATUS]
      #v(4pt)
      #text(weight: "bold", size: 13pt)[#status-label(if "status" in data { data.status } else { none })]
    ]
  ],
)

#v(8pt)
#line(length: 100%, stroke: 1pt + rgb("#000000"))
#v(12pt)

// ---------------------------------------------------------------------------
// Recorded Configuration
// ---------------------------------------------------------------------------

== Recorded Configuration

This section reproduces the values recorded for the tenant at the generation
time above. A recorded "No" states that the corresponding control is not in
effect; "Unknown" states that the report's data does not contain a
recognizable value for it.

#table(
  columns: (1fr, auto, 1fr),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, center, left),
  [*Control*], [*Recorded*], [*Notes*],

  [Data Processing Agreement (DPA)],
  [#tri-badge(if "dpa_signed" in data { data.dpa_signed } else { none }, positive: "SIGNED", negative: "NOT SIGNED")],
  [Signed with the customer under the platform's standard DPA.],

  [Business Associate Agreement (BAA)],
  [#tri-badge(if "baa_signed" in data { data.baa_signed } else { none }, positive: "SIGNED", negative: "NOT SIGNED")],
  [#if "baa_signed_at" in data and data.baa_signed_at != none [Signed at #data.baa_signed_at.] else [No signing date recorded.]],

  [Encryption at rest],
  [#tri-badge(if "encryption_at_rest" in data { data.encryption_at_rest } else { none }, positive: "ENABLED", negative: "DISABLED")],
  [Storage-level encryption for persisted message and account data.],

  [Encryption in transit],
  [#tri-badge(if "encryption_in_transit" in data { data.encryption_in_transit } else { none }, positive: "ENABLED", negative: "DISABLED")],
  [TLS on every client and internal connection.],

  [Zero-retention mode],
  [#tri-badge(if "zero_retention_mode" in data { data.zero_retention_mode } else { none }, positive: "ON", negative: "OFF")],
  [When on, message content is not retained after delivery.],

  [Enabled frameworks],
  [—],
  [#frameworks],

  [Audit log retention],
  [#value-or-unknown(if "audit_retention_days" in data { data.audit_retention_days } else { none })],
  [Days the tenant's audit log entries are retained.],
)

#v(16pt)

// ---------------------------------------------------------------------------
// Recorded Activity
// ---------------------------------------------------------------------------

== Recorded Activity

#table(
  columns: (1fr, auto),
  stroke: 0.5pt + luma(220),
  fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, right),
  [*Measure*], [*Count*],
  [Audit log entries], [#value-or-unknown(if "audit_log_entries" in data { data.audit_log_entries } else { none })],
  [Data access requests], [#value-or-unknown(if "data_access_requests" in data { data.data_access_requests } else { none })],
)

#v(16pt)

// ---------------------------------------------------------------------------
// Evidence Scope
// ---------------------------------------------------------------------------

== Evidence Scope

- This report reflects the configuration *recorded in the ApexMail platform*
  for tenant #data.tenant_id at the generation time; it is not an independent
  audit attestation.
- Counts are the platform's own recorded counts (#value-or-unknown(if "audit_log_entries" in data { data.audit_log_entries } else { none }) audit
  entries, #value-or-unknown(if "data_access_requests" in data { data.data_access_requests } else { none }) data access requests) and cover the
  platform's records only.
- Framework selections state which frameworks the tenant has enabled in the
  platform; they do not by themselves certify conformance.
- Values shown as "Unknown" were not present or not recognized in the
  report's data; they are not assertions of failure, and no control has been
  inferred from an absent value.

#v(16pt)
#line(length: 100%, stroke: 0.5pt + luma(200))
#v(8pt)
#align(center)[
  #text(size: 8pt, fill: luma(120))[
    Prepared by Bel Consulting OÜ (trading as ApexMail) · support\@apexmail.ee
  ]
]
