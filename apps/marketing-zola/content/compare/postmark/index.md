+++
title = "ApexMail vs Postmark | Feature Comparison"
description = "See how ApexMail compares to Postmark on deliverability, compliance, pricing, and developer experience."
template = "compare.html"

[extra]
competitor = "Postmark"
competitor_slug = "postmark"
competitor_name = "Postmark"
competitor_description = "Postmark by ActiveCampaign focuses on fast, reliable transactional email delivery."
pricing_as_of = "2026-08-19"
currency_note = "Prices are shown in EUR. Where a provider publishes only USD, the EUR figure is converted at 1 USD = €0.92 (reference rate, 2026-08-19) and the provider's published USD price is shown in parentheses. Exclude applicable taxes."
og_image = "/images/og-image.svg"
apexmail_wins = 0
competitor_wins = 0

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans and any inline markup. Winner is one of: apexmail | competitor | tie | none.
# Postmark never declares a winner — every row uses winner = "none".
comparison_sections = [
  { title = "DELIVERABILITY", rows = [
    { feature = "Delivery Rate", apex = '<span class="text-brand-600 font-semibold">High</span>', comp = '<span class="text-surface-600">High</span>', winner = "none" },
    { feature = "P95 acceptance to first attempt", apex = '<span class="text-brand-600 font-semibold">&le;30s (P95)</span>', comp = '<span class="text-surface-600">Not publicly documented</span>', winner = "none" },
    { feature = "Dedicated IP", apex = '<span class="text-brand-600 font-semibold">Approved add-on on Pro; 1 included on Growth, 3 on Scale</span>', comp = '<span class="text-surface-600">See provider pricing</span>', winner = "none" },
    { feature = "Automatic IP Warming", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-600">Automatic (Postmark-managed)</span>', winner = "none" },
    { feature = "BIMI Support", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "MTA-STS Support", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" }
  ]},
  { title = "COMPLIANCE", rows = [
    { feature = "GDPR Automation", apex = '<span class="text-brand-600 font-semibold">Full DSR handling</span>', comp = '<span class="text-surface-600">Self-managed</span>', winner = "none" },
    { feature = "HIPAA availability", apex = '<span class="text-surface-600 font-semibold">Not currently offered</span>', comp = '<span class="text-surface-600">See provider documentation</span>', winner = "none" },
    { feature = "SOC 2 certification", apex = '<span class="text-surface-600 font-semibold">Not currently offered</span>', comp = '<span class="text-surface-600">See provider documentation</span>', winner = "none" },
    { feature = "Audit Logs", apex = '<span class="text-brand-600 font-semibold">Growth plan & above</span>', comp = '<span class="text-surface-600">Event logs only</span>', winner = "none" },
    { feature = "Consent Management", apex = '<span class="text-brand-600 font-semibold">Built-in</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "FEATURES", rows = [
    { feature = "Transactional Email", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" },
    { feature = "Marketing Email", apex = '<span class="text-brand-600 font-semibold">Yes (unified API)</span>', comp = '<span class="text-surface-600">Separate product</span>', winner = "none" },
    { feature = "Inbound Processing", apex = '<span class="text-brand-600 font-semibold">Scale and Enterprise plans</span>', comp = '<span class="text-brand-600">✓</span>', winner = "none" },
    { feature = "Templates", apex = '<span class="text-brand-600 font-semibold">Stored templates</span>', comp = '<span class="text-surface-600">Proprietary</span>', winner = "none" },
    { feature = "Scheduled Sending", apex = '<span class="text-brand-600">✓</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "ENTERPRISE", rows = [
    { feature = "SSO/SAML", apex = '<span class="text-brand-600 font-semibold">Scale and Enterprise</span>', comp = '<span class="text-surface-600">Available on request</span>', winner = "none" },
    { feature = "Custom Deployment Review", apex = '<span class="text-brand-600 font-semibold">Enterprise review</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "Dedicated Deployment Options", apex = '<span class="text-brand-600 font-semibold">Custom review</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]},
  { title = "PRICING", rows = [
    { feature = "Free Tier", apex = '<span class="text-brand-600 font-semibold">30,000/mo</span>', comp = '<span class="text-surface-600">100/mo</span>', winner = "none" },
    { feature = "100K emails/mo", apex = '<span class="text-brand-600 font-semibold">€65 (Pro: 150K)</span>', comp = '<span class="text-surface-600">€122.82 (US$133.50) — Pro: €15.18 (US$16.50)/mo + 90K overage @ €1.20 (US$1.30)/1K</span>', winner = "none" },
    { feature = "Unlimited team members", apex = '<span class="text-brand-600 font-semibold">Enterprise plan</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" },
    { feature = "Custom enterprise terms", apex = '<span class="text-brand-600 font-semibold">Annual contracts</span>', comp = '<span class="text-surface-400">✗</span>', winner = "none" }
  ]}
]

# Trailing methodology paragraph (rendered via macros::methodology_note).
# Raw HTML — the inner <p> content with the methodology link. Uses a TOML
# multi-line basic string (""" """) because the text contains both a single
# quote ("provider's") and double-quoted HTML attributes; the leading \ trims
# the opening newline and literal newlines collapse to spaces per TOML spec.
methodology_note = """\
<strong>Methodology:</strong> Feature comparisons are based on publicly available documentation, pricing pages, and official sources. Plans compared: ApexMail self-service tiers and Postmark standard plans. Pricing snapshot date: 2026-05-09. Last verified: 2026-07-30. Data may change; verify with each provider's current documentation. See our <a href="/compare/methodology/" class="text-brand-600 hover:text-brand-700 underline">comparison methodology</a> for sourcing details."""
+++

<!-- Comparison rows are rendered from the [extra].comparison_sections array
     by partials/compare/table.html. This body is intentionally empty. -->
