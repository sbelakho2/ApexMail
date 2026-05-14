// ApexMail Data Processing Agreement (DPA) Template
// GDPR-compliant DPA per Articles 28, 32, 33
//
// Expected data.json structure:
// {
//   "effective_date": "2025-01-15",
//   "controller": {
//     "company": "Acme Corp",
//     "address": "123 Main St, Tallinn, EE",
//     "contact": "Jane Doe",
//     "email": "jane@acme.com"
//   },
//   "data_categories": ["Email addresses", "First/last names", "IP addresses", "Engagement data"],
//   "processing_purposes": ["Email delivery", "Analytics", "Bounce processing", "Compliance monitoring"],
//   "sub_processors": [
//     { "name": "Hetzner Online GmbH", "purpose": "Infrastructure hosting", "location": "Germany" },
//     { "name": "Cloudflare, Inc.", "purpose": "CDN and DDoS protection", "location": "USA (EU data region)" },
//     { "name": "LHV Pank", "purpose": "Payment processing", "location": "Estonia" }
//   ],
//   "data_retention_days": 365,
//   "dpa_version": "2.1"
// }

#let data = json("data.json")

#set document(
  title: "Data Processing Agreement — " + data.controller.company,
  author: "ApexMail OÜ",
)

#set page(
  paper: "a4",
  margin: (top: 25mm, bottom: 25mm, left: 25mm, right: 25mm),
  header: context {
    if counter(page).get().first() > 1 [
      #set text(size: 8pt, fill: luma(140))
      #grid(
        columns: (1fr, 1fr),
        [Data Processing Agreement — v#data.dpa_version],
        align(right)[ApexMail OÜ & #data.controller.company],
      )
      #line(length: 100%, stroke: 0.3pt + luma(200))
    ]
  },
  footer: [
    #set text(size: 7pt, fill: luma(140))
    #grid(
      columns: (1fr, 1fr, 1fr),
      [DPA v#data.dpa_version],
      align(center)[Page #counter(page).display() of #locate(loc => counter(page).final(loc).first())],
      align(right)[Confidential],
    )
  ],
)

#set text(font: "Inter", "DejaVu Sans", sans-serif, size: 10pt)
#set par(justify: true)
#set heading(numbering: "1.1")

// ---------------------------------------------------------------------------
// Title Page
// ---------------------------------------------------------------------------

#v(30mm)

#align(center)[
  #text(weight: "bold", size: 28pt, fill: rgb("#dc2626"))[
    Data Processing Agreement
  ]
  #v(8pt)
  #text(size: 12pt, fill: luma(100))[
    pursuant to Article 28 of the General Data Protection Regulation (GDPR)
  ]
  #v(24pt)
  #line(length: 60%, stroke: 1pt + rgb("#000000"))
  #v(24pt)
  #text(size: 14pt)[
    Between
  ]
  #v(8pt)
  #text(weight: "bold", size: 16pt)[
    #data.controller.company
  ]
  #text(size: 11pt)[(the "Controller")]
  #v(12pt)
  #text(size: 14pt)[and]
  #v(12pt)
  #text(weight: "bold", size: 16pt)[ApexMail OÜ]
  #text(size: 11pt)[(the "Processor")]
  #v(24pt)
  #text(size: 11pt)[
    Effective Date: *#data.effective_date* \
    Version: *#data.dpa_version*
  ]
]

#pagebreak()

// ---------------------------------------------------------------------------
// 1. Definitions & Scope
// ---------------------------------------------------------------------------

= Definitions and Scope

This Data Processing Agreement ("DPA") is entered into between *#data.controller.company* ("Controller") and *ApexMail OÜ*, a company incorporated under the laws of Estonia (registry code 16789012), with its registered office at Tornimäe 5, 10145 Tallinn, Estonia ("Processor").

This DPA supplements the Terms of Service and governs the processing of personal data by the Processor on behalf of the Controller in connection with the ApexMail email delivery platform.

== Key Definitions

- *Personal Data:* Any information relating to an identified or identifiable natural person, as defined in Article 4(1) GDPR.
- *Processing:* Any operation performed on Personal Data, as defined in Article 4(2) GDPR.
- *Data Subject:* The identified or identifiable natural person to whom Personal Data relates.
- *Sub-processor:* Any third party engaged by the Processor to process Personal Data on behalf of the Controller.

// ---------------------------------------------------------------------------
// 2. Categories of Data Processed
// ---------------------------------------------------------------------------

= Categories of Personal Data

The following categories of personal data are processed under this Agreement:

#block(
  fill: luma(248),
  inset: 12pt,
  radius: 0pt,
  width: 100%,
)[
  #for (i, cat) in data.data_categories.enumerate() [
    #numbering("1.", i + 1) #cat \
  ]
]

== Purposes of Processing

The Processor shall process the above categories of Personal Data solely for the following purposes:

#for purpose in data.processing_purposes [
  - #purpose
]

== Data Retention

Personal Data shall be retained for a maximum of *#data.data_retention_days days* from the date of collection, unless a longer retention period is required by applicable law.

// ---------------------------------------------------------------------------
// 3. Obligations of the Processor (Art. 28)
// ---------------------------------------------------------------------------

= Obligations of the Processor

== General Obligations (Article 28 GDPR)

The Processor shall:

+ Process Personal Data only on documented instructions from the Controller, including with regard to transfers to a third country, unless required to do so by EU or Member State law.
+ Ensure that persons authorised to process Personal Data have committed themselves to confidentiality or are under an appropriate statutory obligation of confidentiality.
+ Take all measures required pursuant to Article 32 GDPR (security of processing).
+ Respect the conditions for engaging another processor (sub-processing) as set out in Section 5.
+ Assist the Controller in responding to requests for exercising data subjects' rights under Chapter III GDPR.
+ Assist the Controller in ensuring compliance with obligations under Articles 32–36 GDPR, taking into account the nature of processing and information available to the Processor.
+ At the choice of the Controller, delete or return all Personal Data after the end of the provision of services, and delete existing copies unless EU or Member State law requires storage.
+ Make available to the Controller all information necessary to demonstrate compliance with Article 28 GDPR and allow for and contribute to audits, including inspections, conducted by the Controller or another auditor mandated by the Controller.

// ---------------------------------------------------------------------------
// 4. Security Measures (Art. 32)
// ---------------------------------------------------------------------------

= Technical and Organisational Measures (Article 32 GDPR)

The Processor implements the following security measures:

== Encryption
- All data in transit is encrypted using TLS 1.3.
- All data at rest is encrypted using AES-256-GCM.
- DKIM signing keys are generated and stored using RSA-2048 or Ed25519.

== Access Control
- Role-based access control (RBAC) with principle of least privilege.
- Multi-factor authentication (MFA) required for all operator access.
- API keys are hashed with Argon2id before storage.
- Session tokens expire after 24 hours of inactivity.

== Infrastructure Security
- Dedicated IP isolation per enterprise tenant.
- DDoS protection with adaptive rate limiting.
- Web Application Firewall (WAF) with OWASP Top 10 rulesets.
- Intrusion Detection System (IDS) with real-time alerting.

== Monitoring and Logging
- Comprehensive audit logging of all data access operations.
- Real-time monitoring with Prometheus + Grafana.
- Log retention: 90 days for operational logs, 365 days for audit logs.

== Business Continuity
- Automated daily backups with point-in-time recovery.
- Multi-region failover capability.
- Recovery Time Objective (RTO): 4 hours.
- Recovery Point Objective (RPO): 1 hour.

// ---------------------------------------------------------------------------
// 5. Sub-processors
// ---------------------------------------------------------------------------

= Sub-processors

The Controller hereby provides general written authorisation for the Processor to engage the following sub-processors:

#table(
  columns: (1fr, 1fr, auto),
  stroke: 0.5pt + luma(200),
  fill: (x, y) => if y == 0 { rgb("#dc2626").lighten(90%) } else { none },
  inset: 8pt,
  align: (left, left, left),
  [*Sub-processor*], [*Purpose*], [*Location*],
  ..for sp in data.sub_processors {(
    [#sp.name],
    [#sp.purpose],
    [#sp.location],
  )}
)

#v(8pt)

The Processor shall inform the Controller of any intended changes concerning the addition or replacement of sub-processors, giving the Controller the opportunity to object to such changes.

// ---------------------------------------------------------------------------
// 6. Breach Notification (Art. 33)
// ---------------------------------------------------------------------------

= Personal Data Breach Notification (Article 33 GDPR)

The Processor shall notify the Controller without undue delay, and in any event within *24 hours*, after becoming aware of a personal data breach. The notification shall include:

+ The nature of the personal data breach, including where possible the categories and approximate number of data subjects and records concerned.
+ The name and contact details of the Processor's data protection officer or other contact point.
+ The likely consequences of the breach.
+ The measures taken or proposed to address the breach, including measures to mitigate its possible adverse effects.

// ---------------------------------------------------------------------------
// 7. Data Subject Rights
// ---------------------------------------------------------------------------

= Assistance with Data Subject Requests

The Processor shall provide reasonable assistance to the Controller in responding to requests from data subjects exercising their rights under GDPR Chapter III, including:

- Right of access (Art. 15)
- Right to rectification (Art. 16)
- Right to erasure / "right to be forgotten" (Art. 17)
- Right to restriction of processing (Art. 18)
- Right to data portability (Art. 20)
- Right to object (Art. 21)

The Processor shall respond to Controller requests for assistance within *5 business days*.

// ---------------------------------------------------------------------------
// 8. Governing Law
// ---------------------------------------------------------------------------

= Governing Law and Jurisdiction

This DPA shall be governed by and construed in accordance with the laws of the Republic of Estonia, without regard to its conflict of laws provisions. Any dispute arising under this DPA shall be submitted to the exclusive jurisdiction of the courts of Tallinn, Estonia.

// ---------------------------------------------------------------------------
// 9. Signatures
// ---------------------------------------------------------------------------

#pagebreak()

= Signatures

This DPA has been executed in two copies, one for each party.

#v(24pt)

#grid(
  columns: (1fr, 1fr),
  column-gutter: 24pt,
  [
    *For the Controller:*
    #v(8pt)
    #data.controller.company
    #v(40pt)
    #line(length: 90%, stroke: 0.5pt)
    #v(4pt)
    Name: #data.controller.contact \
    Title: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ \
    Date: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
  ],
  [
    *For the Processor:*
    #v(8pt)
    ApexMail OÜ
    #v(40pt)
    #line(length: 90%, stroke: 0.5pt)
    #v(4pt)
    Name: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ \
    Title: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ \
    Date: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_
  ],
)
