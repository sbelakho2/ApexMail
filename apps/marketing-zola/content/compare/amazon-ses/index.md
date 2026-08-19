+++
title = "ApexMail vs Amazon SES | Capability Comparison"
description = "Factual comparison of transactional email capabilities: ApexMail vs Amazon SES. EU hosting, API, deliverability, compliance, and deployment models."
template = "compare.html"

[extra]
competitor = "Amazon SES"
competitor_slug = "amazon-ses"
competitor_name = "Amazon SES"
competitor_description = "Amazon Simple Email Service (SES) is a cloud-based email sending service built on AWS infrastructure, priced as pay-as-you-go capacity."
last_verified = "2026-07-29"
methodology = "Public AWS SES documentation at docs.aws.amazon.com/ses reviewed on the verification date. Pricing compared at pay-as-you-go for 100,000 emails/month. Monthly billing. ApexMail is managed infrastructure; SES is raw capacity. Features, limits, and pricing may change."
volume_assumption = "100,000 emails/month"
billing_period = "monthly"
currency_note = "Prices are shown in EUR. Where a provider publishes only USD, the EUR figure is converted at 1 USD = €0.92 (reference rate, 2026-08-19) and the provider's published USD price is shown in parentheses. Exclude applicable taxes."
# Feature comparison counts — update when capabilities change.
apexmail_wins = 2
competitor_wins = 4
verdict_title = "How ApexMail differs from Amazon SES"
verdict_points = ["Managed email infrastructure with API, events, and support included vs raw capacity billing", "Per-message delivery diagnostics dashboard vs self-assembled CloudWatch + SNS", "Idempotency keys on all plans vs not natively supported", "EU/EEA-oriented deployment configuration with active regions confirmed per deployment", "Dedicated tenancy managed service vs self-managed on AWS"]

# Comparison data (audit 3.3): rendered by partials/compare/table.html via a
# single loop, so design changes to the row/winner markup happen in ONE place.
# Cell values are raw HTML (rendered with | safe) to preserve color-emphasis
# spans, inline <code>, and <sup><a href="#src-sesN"> citations. Winner is one
# of: apexmail | competitor | tie | none. Bare "—" winner cells normalize to
# "none" (the winner_badge macro renders them as a spanned em-dash).
comparison_sections = [
  { title = "EEA DATA PROCESSING", rows = [
    { feature = "Primary hosting region", apex = 'EU/EEA-oriented default configuration; confirm active deployment', comp = 'Multiple regions including EU (Ireland eu-west-1, Frankfurt eu-central-1, etc.)<sup><a href="#src-ses1">1</a></sup>', winner = "none" },
    { feature = "EEA data processing default", apex = 'EU/EEA-oriented default configuration; active locations are agreement-specific', comp = 'Available — must be explicitly configured; region selection required per sending domain<sup><a href="#src-ses1">1</a></sup>', winner = "none" },
    { feature = "DPA availability", apex = 'Available under the applicable ApexMail agreement', comp = 'Available — AWS DPA (Artifact) with SCCs<sup><a href="#src-ses2">2</a></sup>', winner = "none" }
  ]},
  { title = "SENDING CAPABILITIES", rows = [
    { feature = "REST API", apex = 'Yes — native <code>POST /v1/messages</code> (ApexMail API)', comp = 'Yes — AWS SDK (multiple languages) via <code>SendEmail</code>, <code>SendBulkEmail</code><sup><a href="#src-ses3">3</a></sup>', winner = "none" },
    { feature = "SMTP relay", apex = 'Yes — smtp.apexmail.ee:587 (STARTTLS)', comp = 'Yes — email-smtp.{region}.amazonaws.com:587 (STARTTLS)<sup><a href="#src-ses3">3</a></sup>', winner = "none" },
    { feature = "Idempotency keys", apex = 'Yes (all plans) — <code>Idempotency-Key</code> header', comp = 'Not natively supported — AWS recommends application-level message deduplication<sup><a href="#src-ses3">3</a></sup>', winner = "apexmail" },
    { feature = "Message event tracking", apex = 'Per-message delivery diagnostics dashboard with 7-step timeline', comp = 'CloudWatch metrics (send, bounce, complaint, delivery) + SNS notifications for events — self-assembly required<sup><a href="#src-ses4">4</a></sup>', winner = "apexmail" },
    { feature = "Inbound email", apex = 'Scale and Enterprise plans', comp = 'Yes — SES receipt rules with S3, Lambda, SNS, SQS actions<sup><a href="#src-ses5">5</a></sup>', winner = "none" }
  ]},
  { title = "DEPLOYMENT MODELS", rows = [
    { feature = "Shared cloud", apex = 'Yes (all plans) — managed multi-tenant on Hetzner', comp = 'Yes (all accounts) — shared IP pool by default<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Dedicated IP", apex = 'Approved add-on on Pro; 1 included on Growth, 3 on Scale', comp = 'Yes — €22.95 (US$24.95)/mo per dedicated IP; IP pool management available<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Dedicated tenancy", apex = 'Subject to architecture and contract review', comp = 'Self-managed — customer architects dedicated tenancy on AWS using SES as a service component<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "BYOC / private deployment", apex = 'Subject to architecture and contract review', comp = 'Inherent — customer runs on own AWS account; SES is an AWS service<sup><a href="#src-ses6">6</a></sup>', winner = "none" }
  ]},
  { title = "ENTERPRISE CONTROLS", rows = [
    { feature = "SAML SSO", apex = 'Scale and Enterprise plans', comp = 'Via AWS IAM Identity Center — requires AWS Organization setup and IAM configuration<sup><a href="#src-ses7">7</a></sup>', winner = "none" },
    { feature = "Subaccounts / isolation", apex = 'Scale (10) and Enterprise (100) — managed, hierarchical', comp = 'Via AWS Organizations with separate account per environment — self-managed<sup><a href="#src-ses7">7</a></sup>', winner = "none" },
    { feature = "Managed support", apex = 'Plan-specific support terms', comp = 'AWS Support plans (Developer, Business, Enterprise) — separate purchase from SES usage<sup><a href="#src-ses8">8</a></sup>', winner = "none" },
    { feature = "HIPAA availability", apex = 'Not currently offered', comp = 'Yes — AWS BAA available; SES is an eligible HIPAA service<sup><a href="#src-ses9">9</a></sup>', winner = "competitor" }
  ]},
  { title = "PRICING AT 100K/MO (verified 2026-07-29)", rows = [
    { feature = "Plan compared", apex = 'Pro: €65/mo (150,000 emails included, managed infrastructure)', comp = 'Pay-as-you-go: ~€9.20 (US$10)/100K emails (raw sending, no management included)<sup><a href="#src-ses10">10</a></sup>', winner = "none" },
    { feature = "Pricing model distinction", apex = 'Managed email infrastructure: API, event storage, webhook delivery, support, analytics included', comp = 'Raw capacity billing: IaaS — pay per send, plus additional AWS costs (EC2, S3, CloudWatch, SNS, support)<sup><a href="#src-ses10">10</a></sup>', winner = "none" },
    { feature = "Free tier", apex = '30,000 emails/month (no credit card, no time limit)', comp = '62,000 emails/month when sending from EC2 (first 12 months); 3,000/month otherwise<sup><a href="#src-ses10">10</a></sup>', winner = "none" }
  ]},
  { title = "AREAS WHERE AMAZON SES IS STRONGER", rows = [
    { feature = "Raw cost per email", apex = 'See the current public catalog and checkout for applicable usage terms', comp = '€0.09 (US$0.10)/1,000 emails — lowest per-message cost among major providers<sup><a href="#src-ses10">10</a></sup>', winner = "competitor" },
    { feature = "AWS ecosystem integration", apex = 'Standalone platform with API integration', comp = 'Deep integration with AWS services: Lambda, S3, CloudWatch, SNS, SQS, IAM, KMS, Organizations<sup><a href="#src-ses3">3</a></sup>', winner = "competitor" },
    { feature = "Maximum sending volume", apex = 'Scale supports up to 2 million emails/month; Enterprise terms are contract-scoped', comp = 'Virtually unlimited — constrained by account sending limits which auto-scale with reputation<sup><a href="#src-ses6">6</a></sup>', winner = "none" },
    { feature = "Global regions", apex = 'Germany &amp; Finland (EEA focus)', comp = '22+ AWS regions globally including US, EU, APAC, South America<sup><a href="#src-ses1">1</a></sup>', winner = "competitor" }
  ]}
]

# Trailing footnote sources (rendered via macros::sources_block). Each source
# {ref, n, label, url} maps a <sup id="src-sesN"> definition. ref is the anchor
# suffix so the macro emits id="src-{{ref}}", matching the inline #src-sesN refs.
sources = [
  { ref = "ses1", n = 1, label = "AWS SES Regional Endpoints", url = "https://docs.aws.amazon.com/general/latest/gr/ses.html" },
  { ref = "ses2", n = 2, label = "AWS GDPR Center and DPA", url = "https://aws.amazon.com/compliance/gdpr-center/" },
  { ref = "ses3", n = 3, label = "AWS SES v2 SendEmail API reference", url = "https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html" },
  { ref = "ses4", n = 4, label = "AWS SES Monitoring documentation", url = "https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html" },
  { ref = "ses5", n = 5, label = "AWS SES Receiving Email documentation", url = "https://docs.aws.amazon.com/ses/latest/dg/receiving-email.html" },
  { ref = "ses6", n = 6, label = "AWS SES Dedicated IPs documentation", url = "https://docs.aws.amazon.com/ses/latest/dg/dedicated-ip.html" },
  { ref = "ses7", n = 7, label = "AWS IAM Identity Center (SSO) documentation", url = "https://docs.aws.amazon.com/singlesignon/latest/userguide/" },
  { ref = "ses8", n = 8, label = "AWS Support Plans", url = "https://aws.amazon.com/premiumsupport/plans/" },
  { ref = "ses9", n = 9, label = "AWS HIPAA Compliance and BAA information", url = "https://aws.amazon.com/compliance/hipaa-compliance/" },
  { ref = "ses10", n = 10, label = "AWS SES Pricing page", url = "https://aws.amazon.com/ses/pricing/" }
]
sources_disclaimer = "Last verified: 2026-08-19. Volume assumption: 100,000 emails/month, monthly billing. Prices are shown in EUR. Where a provider publishes only USD, the EUR figure is converted at 1 USD = €0.92 (reference rate, 2026-08-19) and the provider's published USD price is shown in parentheses. Exclude applicable taxes. ApexMail is priced as managed email infrastructure; Amazon SES is priced as raw email sending capacity. Reviewed by: ApexMail marketing engineering."
+++

<!-- Comparison rows and footnote sources are rendered from the
     [extra].comparison_sections, [extra].sources, and
     [extra].sources_disclaimer fields by partials/compare/table.html
     (which calls macros::sources_block). This body is intentionally empty. -->
