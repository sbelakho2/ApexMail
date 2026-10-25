+++
title = "ApexMail vs Resend | Feature Comparison"
description = "See how ApexMail compares to Resend on deliverability, compliance, pricing, and developer experience."
template = "compare.html"

[extra]
noindex = true
competitor = "Resend"
competitor_slug = "resend"
competitor_name = "Resend"
competitor_description = "Resend is a modern email API for developers with component-based email authoring."
pricing_as_of = "2026-10-04"
og_image = "/images/og-image.png"
# Feature comparison counts are not displayed (review 2026-09-08 §19)
verdict_title = "How ApexMail differs from Resend"
verdict_points = [
  "Core email data (content, delivery events, sender and recipient data) stored in the EEA by default, not just sent from an EU region",
  "Private deployment paths (Dedicated Tenant, BYOC) alongside the shared cloud",
  "Delivery forensics: per-attempt timelines, deferral diagnostics, and the Email Deliverability Grader",
  "Honest capability disclosure: SDK availability, certification status, and data locations documented as they are, not as aspirational",
]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans and any inline markup. Winner is one of: apexmail | competitor | tie | none.
comparison_sections = [
  { title = "DELIVERABILITY", rows = [
    { feature = "Delivery Rate", apex = '<span>Not directly comparable, provider-defined measurement</span>', comp = '<span class="">Not directly comparable, provider-defined measurement</span>', winner = "none" },
    { feature = "Dedicated IP", apex = '<span>Approved add-on on Pro; 1 included on Growth and Business; 3 on Enterprise Cloud</span>', comp = '<span class="">See provider pricing</span>', winner = "none" },
    { feature = "IP Warming", apex = '<span>Automatic geometric</span>', comp = '<span class="">Automatic (managed)</span>', winner = "tie" },
    { feature = "BIMI Support", apex = '<span class="">✗</span>', comp = '<span class="">✗</span>', winner = "none" },
    { feature = "ARC Signing", apex = '<span class="">✗</span>', comp = '<span class="">✗</span>', winner = "none" },
    { feature = "Reputation Circuit Breaker", apex = '<span class="">✓</span>', comp = '<span class="">✗</span>', winner = "apexmail" }
  ]},
  { title = "COMPLIANCE", rows = [
    { feature = "GDPR Automation", apex = '<span>DSR workflows</span>', comp = '<span class="">Standard controls</span>', winner = "apexmail" },
    { feature = "HIPAA availability", apex = '<span>Not currently offered</span>', comp = '<span class="">Not evaluated in this comparison</span>', winner = "none" },
    { feature = "Consent Management", apex = '<span>Built-in</span>', comp = '<span class="">✗</span>', winner = "apexmail" },
    { feature = "Audit Logs", apex = '<span>Operator + API audit trail</span>', comp = '<span class="">Activity logs only</span>', winner = "apexmail" },
    { feature = "Idempotency Keys", apex = '<span class="">✓</span>', comp = '<span class="">✓</span>', winner = "tie" }
  ]}
]

# Trailing methodology paragraph (rendered by partials/compare/table.html).
methodology_note = """\
<strong>Methodology:</strong> Feature rows summarize publicly documented Resend behavior. Plans compared: ApexMail self-service tiers and Resend published plans; where a comparable published measurement does not exist (for example delivery rate), the row states that it is not directly comparable. Reviewed: 2026-10-04. See our <a href="/compare/methodology/">comparison methodology</a> for sourcing standards. <strong>Migrating from Resend?</strong> The base-URL swap and the exactly mapped subset of its API are documented in the <a href="/migrate/resend/">Resend migration guide</a>.
"""
+++

<!-- Comparison rows are rendered from the [extra].comparison_sections array
     by partials/compare/table.html. This body is intentionally empty. -->
