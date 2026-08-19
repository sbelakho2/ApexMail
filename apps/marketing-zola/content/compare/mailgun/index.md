+++
title = "ApexMail vs Mailgun | Capability Comparison"
description = "Factual comparison of transactional email capabilities: ApexMail vs Mailgun. EU hosting, API, deliverability, compliance, and deployment models."
template = "compare.html"

[extra]
competitor = "Mailgun"
competitor_slug = "mailgun"
competitor_name = "Mailgun"
competitor_description = "Mailgun by Sinch is an email delivery platform with APIs for sending, receiving, and tracking email."
last_verified = "2026-07-29"
methodology = "Public Mailgun documentation at mailgun.com/docs reviewed on the verification date. Pricing compared at Foundation 100K plan. Monthly billing. Features, limits, and pricing may change."
volume_assumption = "100,000 emails/month"
billing_period = "monthly"
currency_note = "USD for ApexMail and Mailgun. Prices exclude applicable taxes."
# Feature comparison counts — update when capabilities change
apexmail_wins = 8
competitor_wins = 2
verdict_title = "How ApexMail differs from Mailgun"
verdict_points = ["EU/EEA-oriented deployment configuration", "Current public catalog in USD", "Scale and Enterprise access controls", "Audit logs on Growth and above", "Architecture and contract review for non-standard deployments"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-mgN"> citations. Winner is one
# of: apexmail | competitor | tie | none.
comparison_sections = [
  { title = "EEA DATA PROCESSING", rows = [
    { feature = "Primary hosting region", apex = 'EU/EEA-oriented default configuration; confirm active deployment', comp = 'US (EU region available on Foundation 50K+ and higher plans)<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "EEA data processing default", apex = 'EU/EEA-oriented default configuration; active locations are agreement-specific', comp = 'No — US-based by default; EU region configured per sending domain<sup><a href="#src-mg1">1</a></sup>', winner = "none" },
    { feature = "DPA availability", apex = 'Available under the applicable ApexMail agreement', comp = 'Available — Sinch DPA covers Mailgun services<sup><a href="#src-mg2">2</a></sup>', winner = "none" }
  ]},
  { title = "SENDING CAPABILITIES", rows = [
    { feature = "REST API", apex = 'Yes — <code>POST /v1/messages</code>', comp = 'Yes — <code>POST /v3/{domain}/messages</code><sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "SMTP relay", apex = 'Yes — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Yes — smtp.mailgun.org:587 (STARTTLS)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Batch sending", apex = 'Available where enabled for the subscribed plan', comp = 'Yes — batch sending via <code>recipient-variables</code> with up to 1,000 recipients<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Idempotency keys", apex = 'Yes (all plans) — <code>Idempotency-Key</code> header', comp = 'Not supported — applications must implement deduplication logic<sup><a href="#src-mg3">3</a></sup>', winner = "apexmail" },
    { feature = "Scheduled sending", apex = 'Available where enabled for the subscribed plan', comp = 'Yes — <code>o:deliverytime</code> parameter (RFC 2822 format, up to 3 days)<sup><a href="#src-mg3">3</a></sup>', winner = "none" },
    { feature = "Inbound email", apex = 'Scale and Enterprise plans', comp = 'Yes — inbound routes with forwarding, storage, and webhook actions<sup><a href="#src-mg4">4</a></sup>', winner = "none" }
  ]},
  { title = "DEPLOYMENT MODELS", rows = [
    { feature = "Shared cloud", apex = 'Yes (all plans) — multi-tenant on Hetzner', comp = 'Yes (all plans)<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Dedicated IP", apex = 'Approved add-on on Pro; 1 included on Growth, 3 on Scale', comp = 'Available as add-on on Foundation plan and above<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "Dedicated tenancy", apex = 'Subject to architecture and contract review', comp = 'See provider documentation<sup><a href="#src-mg5">5</a></sup>', winner = "none" },
    { feature = "BYOC / private deployment", apex = 'Subject to architecture and contract review', comp = 'See provider documentation<sup><a href="#src-mg5">5</a></sup>', winner = "none" }
  ]},
  { title = "ENTERPRISE CONTROLS", rows = [
    { feature = "SAML SSO", apex = 'Scale and Enterprise plans', comp = 'Foundation 100K and higher plans<sup><a href="#src-mg6">6</a></sup>', winner = "none" },
    { feature = "SCIM", apex = 'Enterprise plan', comp = 'Not documented as of verification date — user provisioning through Mailgun API<sup><a href="#src-mg6">6</a></sup>', winner = "apexmail" },
    { feature = "Audit logs", apex = 'Growth plan and above — account activity, API key usage, configuration changes; searchable, exportable', comp = 'Event logs accessible via Events API; retention varies by plan; no consolidated account-level audit trail<sup><a href="#src-mg7">7</a></sup>', winner = "apexmail" }
  ]},
  { title = "PRICING AT 100K/MO (verified 2026-07-29)", rows = [
    { feature = "Plan compared", apex = 'Pro: $65/mo (150,000 emails included)', comp = 'Foundation 100K: $75/mo (100,000 emails included)<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Usage terms", apex = 'See the current public catalog and checkout for applicable usage terms', comp = '$1.00/1,000 for Foundation; varies by volume tier; Flex pricing available<sup><a href="#src-mg8">8</a></sup>', winner = "none" },
    { feature = "Free tier", apex = '30,000 emails/month', comp = '100 emails/day (Flex trial — no credit card)<sup><a href="#src-mg8">8</a></sup>', winner = "apexmail" }
  ]},
  { title = "AREAS WHERE MAILGUN IS STRONGER", rows = [
    { feature = "Email validation", apex = 'Email Grader API (DNS/SPF/DKIM/DMARC/content/reputation)', comp = 'Dedicated Email Validation API with real-time and bulk validation<sup><a href="#src-mg9">9</a></sup>', winner = "competitor" },
    { feature = "Inbound email processing", apex = 'Inbound email on Scale and Enterprise plans', comp = 'Inbound routing with forwarding, HTTP webhook, and storage actions; included on all plans<sup><a href="#src-mg4">4</a></sup>', winner = "competitor" },
    { feature = "Email testing sandbox", apex = 'Sandbox environment with sandbox domains and rate limits', comp = 'Sandbox domain for testing on all plans with separate test credentials<sup><a href="#src-mg3">3</a></sup>', winner = "none" }
  ]}
]

# Sources block (rendered by macros::sources_block via partials/compare/table.html).
# Each entry: { ref = anchor suffix (e.g. "mg1"), n = display number, label, url }.
sources = [
  { ref = "mg1", n = 1, label = "Mailgun EU Data Center documentation", url = "https://www.mailgun.com/eu-data-center/" },
  { ref = "mg2", n = 2, label = "Mailgun Data Processing Agreement", url = "https://www.mailgun.com/legal/dpa/" },
  { ref = "mg3", n = 3, label = "Mailgun Sending API reference", url = "https://documentation.mailgun.com/en/latest/api-sending.html" },
  { ref = "mg4", n = 4, label = "Mailgun Inbound Email documentation", url = "https://documentation.mailgun.com/en/latest/user_manual.html#receiving-forwarding-and-storing-messages" },
  { ref = "mg5", n = 5, label = "Mailgun Products page", url = "https://www.mailgun.com/products/" },
  { ref = "mg6", n = 6, label = "Mailgun SSO documentation", url = "https://www.mailgun.com/products/sso/" },
  { ref = "mg7", n = 7, label = "Mailgun Events API reference", url = "https://documentation.mailgun.com/en/latest/api-events.html" },
  { ref = "mg8", n = 8, label = "Mailgun Pricing page", url = "https://www.mailgun.com/pricing/" },
  { ref = "mg9", n = 9, label = "Mailgun Email Validation", url = "https://www.mailgun.com/email-validation/" }
]
sources_disclaimer = "Last verified: 2026-07-29. Volume assumption: 100,000 emails/month, monthly billing. Prices are shown in USD and exclude applicable taxes. Reviewed by: ApexMail marketing engineering."
+++

<!-- Comparison rows and sources block are rendered from the
     [extra].comparison_sections and [extra].sources arrays by
     partials/compare/table.html. This body is intentionally empty. -->
