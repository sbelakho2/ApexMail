+++
title = "ApexMail vs Postmark | Feature Comparison"
description = "See how ApexMail compares to Postmark on deliverability, compliance, pricing, and developer experience."
template = "compare.html"

[extra]
noindex = true
competitor = "Postmark"
competitor_slug = "postmark"
competitor_name = "Postmark"
competitor_description = "Postmark by ActiveCampaign focuses on fast, reliable transactional email delivery."
pricing_as_of = "2026-10-04"
currency_note = "Prices are shown in EUR. Where a provider publishes only USD, the EUR figure is converted at 1 USD = €0.92 (reference rate, 2026-08-19) and the provider's published USD price is shown in parentheses. Exclude applicable taxes."
og_image = "/images/og-image.png"

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans and any inline markup. Winner is one of: apexmail | competitor | tie | none.
# Postmark rows editorially avoid declaring a winner; the one exception is
# MTA-STS (competitor supports it; ApexMail does not enforce it in delivery
#, see docs/deployment-facts.json mta_sts_enforcement).
comparison_sections = [
  { title = "DELIVERABILITY", rows = [
    { feature = "Delivery Rate", apex = '<span>High</span>', comp = '<span class="">High</span>', winner = "none" },
    { feature = "P95 acceptance to first attempt", apex = '<span>&le;30s (P95) &mdash; internal engineering target, not an independently verified figure</span>', comp = '<span class="">Not publicly documented</span>', winner = "none" },
    { feature = "Dedicated IP", apex = '<span>Approved add-on on Pro; 1 included on Growth and Business; 3 on Enterprise Cloud</span>', comp = '<span class="">See provider pricing</span>', winner = "none" },
    { feature = "Automatic IP Warming", apex = '<span class="">✓</span>', comp = '<span class="">Automatic (Postmark-managed)</span>', winner = "none" },
    { feature = "BIMI Support", apex = '<span class="">✗</span>', comp = '<span class="">✗</span>', winner = "none" },
    { feature = "MTA-STS Support", apex = '<span class="">✗</span>', comp = '<span class="">✓</span>', winner = "competitor" }
  ]},
  { title = "COMPLIANCE", rows = [
    { feature = "GDPR Automation", apex = '<span>Full DSR handling</span>', comp = '<span class="">Self-managed</span>', winner = "none" },
    { feature = "HIPAA availability", apex = '<span>Not currently offered</span>', comp = '<span class="">See provider documentation</span>', winner = "none" },
    { feature = "Audit Logs", apex = '<span>Operator + API audit trail</span>', comp = '<span class="">Event logs only</span>', winner = "none" },
    { feature = "Consent Management", apex = '<span>Built-in</span>', comp = '<span class="">✗</span>', winner = "none" }
  ]},
  { title = "FEATURES", rows = [
    { feature = "Transactional Email", apex = '<span class="">✓</span>', comp = '<span class="">✓</span>', winner = "none" },
    { feature = "Marketing Email", apex = '<span>Yes (unified API)</span>', comp = '<span class="">Separate product</span>', winner = "none" },
    { feature = "Inbound Processing", apex = '<span>Business and Enterprise plans</span>', comp = '<span class="">✓</span>', winner = "none" },
    { feature = "Templates", apex = '<span>Stored templates</span>', comp = '<span class="">Proprietary</span>', winner = "none" },
    { feature = "Scheduled Sending", apex = '<span class="">✓</span>', comp = '<span class="">✗</span>', winner = "none" }
  ]},
  { title = "ENTERPRISE", rows = [
    { feature = "SSO/SAML", apex = '<span>Business and Enterprise</span>', comp = '<span class="">Available on request</span>', winner = "none" },
    { feature = "Custom Deployment Review", apex = '<span>Enterprise review</span>', comp = '<span class="">✗</span>', winner = "none" },
    { feature = "Dedicated Deployment Options", apex = '<span>Custom review</span>', comp = '<span class="">✗</span>', winner = "none" }
  ]},
  { title = "PRICING", rows = [
    { feature = "Free Tier", apex = '<span>3,000/mo + one-time 30,000 launch allowance</span>', comp = '<span class="">100/mo</span>', winner = "none" },
    { feature = "100K emails/mo", apex = '<span>€89 (Pro: 150K)</span>', comp = '<span class="">€122.82 (US$133.50), Pro: €15.18 (US$16.50)/mo + 90K overage @ €1.20 (US$1.30)/1K</span>', winner = "none" },
    { feature = "Unlimited team members", apex = '<span>Enterprise plan</span>', comp = '<span class="">✗</span>', winner = "none" },
    { feature = "Custom enterprise terms", apex = '<span>Annual contracts</span>', comp = '<span class="">✗</span>', winner = "none" }
  ]}
]

# Trailing methodology paragraph (rendered via macros::methodology_note).
# Raw HTML, the inner <p> content with the methodology link. Uses a TOML
# multi-line basic string (""" """) because the text contains both a single
# quote ("provider's") and double-quoted HTML attributes; the leading \ trims
# the opening newline and literal newlines collapse to spaces per TOML spec.
methodology_note = """\
<strong>Methodology:</strong> Feature comparisons are based on publicly available documentation, pricing pages, and official sources. Plans compared: ApexMail self-service tiers and Postmark standard plans. Pricing and plan details last reviewed: 2026-08-19. Data may change; verify with each provider's current documentation. See our <a href="/compare/methodology/">comparison methodology</a> for sourcing details. <strong>Migrating from Postmark?</strong> The base-URL swap and the exactly mapped subset of its API are documented in the <a href="/migrate/postmark/">Postmark migration guide</a>.
"""
+++

<!-- Comparison rows are rendered from the [extra].comparison_sections array
     by partials/compare/table.html. This body is intentionally empty. -->
