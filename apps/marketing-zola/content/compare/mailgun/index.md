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
currency_note = "EUR for ApexMail; USD for Mailgun (Mailgun prices in USD). Prices exclude VAT."
verdict_title = "How ApexMail differs from Mailgun"
verdict_points = ["EEA data processing by default vs US-based with EU option on request", "Idempotency keys on all plans vs not supported", "SCIM on Enterprise plan vs not documented", "Dedicated tenancy from €4,000/mo vs not available", "Audit logs from Growth plan — searchable and exportable vs event logs only"]

+++

<tbody>
  <tr class="section-row"><td colspan="4">EEA DATA PROCESSING</td></tr>
  <tr>
    <td>Primary hosting region</td>
    <td class="text-center">EU (Hetzner, Germany &amp; Finland)</td>
    <td class="text-center">US (EU region available on Foundation 50K+ and higher plans)<sup><a href="#src-mg1">1</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
  <tr>
    <td>EEA data processing default</td>
    <td class="text-center">Yes — all customer data processed and stored in Germany/Finland</td>
    <td class="text-center">No — US-based by default; EU region configured per sending domain<sup><a href="#src-mg1">1</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
  <tr>
    <td>DPA availability</td>
    <td class="text-center">Business plan and above — incorporates Subprocessor Register by reference</td>
    <td class="text-center">Available — Sinch DPA covers Mailgun services<sup><a href="#src-mg2">2</a></sup></td>
    <td class="text-center">—</td>
  </tr>
</tbody>
<tbody>
  <tr class="section-row"><td colspan="4">SENDING CAPABILITIES</td></tr>
  <tr>
    <td>REST API</td>
    <td class="text-center">Yes — <code>POST /v1/messages</code></td>
    <td class="text-center">Yes — <code>POST /v3/{domain}/messages</code><sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>SMTP relay</td>
    <td class="text-center">Yes — smtp.apexmail.ee:587 (STARTTLS)</td>
    <td class="text-center">Yes — smtp.mailgun.org:587 (STARTTLS)<sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Batch sending</td>
    <td class="text-center">Yes (Developer+) — single API call with recipient array</td>
    <td class="text-center">Yes — batch sending via <code>recipient-variables</code> with up to 1,000 recipients<sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Idempotency keys</td>
    <td class="text-center">Yes (all plans) — <code>Idempotency-Key</code> header</td>
    <td class="text-center">Not supported — applications must implement deduplication logic<sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
  <tr>
    <td>Scheduled sending</td>
    <td class="text-center">Yes (Developer+) — <code>send_at</code>, up to 72 hours</td>
    <td class="text-center">Yes — <code>o:deliverytime</code> parameter (RFC 2822 format, up to 3 days)<sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Inbound email</td>
    <td class="text-center">Pro plan and above</td>
    <td class="text-center">Yes — inbound routes with forwarding, storage, and webhook actions<sup><a href="#src-mg4">4</a></sup></td>
    <td class="text-center">—</td>
  </tr>
</tbody>
<tbody>
  <tr class="section-row"><td colspan="4">DEPLOYMENT MODELS</td></tr>
  <tr>
    <td>Shared cloud</td>
    <td class="text-center">Yes (all plans) — multi-tenant on Hetzner</td>
    <td class="text-center">Yes (all plans)<sup><a href="#src-mg5">5</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Dedicated IP</td>
    <td class="text-center">€30/mo add-on (Pro tier); included on Growth+</td>
    <td class="text-center">Available as add-on on Foundation plan and above<sup><a href="#src-mg5">5</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Dedicated tenancy</td>
    <td class="text-center">Yes — Dedicated Tenant from €4,000/mo (12-month minimum)</td>
    <td class="text-center">Not available<sup><a href="#src-mg5">5</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
  <tr>
    <td>BYOC / private deployment</td>
    <td class="text-center">Yes — BYOC from €6,500/mo (12–24 month minimum)</td>
    <td class="text-center">Not available<sup><a href="#src-mg5">5</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
</tbody>
<tbody>
  <tr class="section-row"><td colspan="4">ENTERPRISE CONTROLS</td></tr>
  <tr>
    <td>SAML SSO</td>
    <td class="text-center">Business plan and above</td>
    <td class="text-center">Foundation 100K and higher plans<sup><a href="#src-mg6">6</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>SCIM</td>
    <td class="text-center">Enterprise plan</td>
    <td class="text-center">Not documented as of verification date — user provisioning through Mailgun API<sup><a href="#src-mg6">6</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
  <tr>
    <td>Audit logs</td>
    <td class="text-center">Growth plan and above — account activity, API key usage, configuration changes; searchable, exportable</td>
    <td class="text-center">Event logs accessible via Events API; retention varies by plan; no consolidated account-level audit trail<sup><a href="#src-mg7">7</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
</tbody>
<tbody>
  <tr class="section-row"><td colspan="4">PRICING AT 100K/MO (verified 2026-07-29)</td></tr>
  <tr>
    <td>Plan compared</td>
    <td class="text-center">Pro: €89/mo (150,000 emails included)</td>
    <td class="text-center">Foundation 100K: $75/mo (100,000 emails included)<sup><a href="#src-mg8">8</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Overage rate</td>
    <td class="text-center">€0.60 per 1,000 emails</td>
    <td class="text-center">$1.00/1,000 for Foundation; varies by volume tier; Flex pricing available<sup><a href="#src-mg8">8</a></sup></td>
    <td class="text-center">—</td>
  </tr>
  <tr>
    <td>Free tier</td>
    <td class="text-center">30,000 emails/month</td>
    <td class="text-center">100 emails/day (Flex trial — no credit card)<sup><a href="#src-mg8">8</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">ApexMail</span></td>
  </tr>
</tbody>
<tbody>
  <tr class="section-row"><td colspan="4">AREAS WHERE MAILGUN IS STRONGER</td></tr>
  <tr>
    <td>Email validation</td>
    <td class="text-center">Email Grader API (DNS/SPF/DKIM/DMARC/content/reputation)</td>
    <td class="text-center">Dedicated Email Validation API with real-time and bulk validation<sup><a href="#src-mg9">9</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">Mailgun</span></td>
  </tr>
  <tr>
    <td>Inbound email processing</td>
    <td class="text-center">Inbound email on Pro plan and above</td>
    <td class="text-center">Inbound routing with forwarding, HTTP webhook, and storage actions; included on all plans<sup><a href="#src-mg4">4</a></sup></td>
    <td class="text-center"><span class="text-brand-600 font-semibold">Mailgun</span></td>
  </tr>
  <tr>
    <td>Email testing sandbox</td>
    <td class="text-center">Sandbox environment with sandbox domains and rate limits</td>
    <td class="text-center">Sandbox domain for testing on all plans with separate test credentials<sup><a href="#src-mg3">3</a></sup></td>
    <td class="text-center">—</td>
  </tr>
</tbody>

<p class="text-xs text-surface-400 mt-10 pt-4 border-t border-surface-200">
  <strong>Sources (all accessed 2026-07-29):</strong><br>
  <sup id="src-mg1">1</sup> <a href="https://www.mailgun.com/eu-data-center/" class="text-brand-500 underline">Mailgun EU Data Center documentation</a><br>
  <sup id="src-mg2">2</sup> <a href="https://www.mailgun.com/legal/dpa/" class="text-brand-500 underline">Mailgun Data Processing Agreement</a><br>
  <sup id="src-mg3">3</sup> <a href="https://documentation.mailgun.com/en/latest/api-sending.html" class="text-brand-500 underline">Mailgun Sending API reference</a><br>
  <sup id="src-mg4">4</sup> <a href="https://documentation.mailgun.com/en/latest/user_manual.html#receiving-forwarding-and-storing-messages" class="text-brand-500 underline">Mailgun Inbound Email documentation</a><br>
  <sup id="src-mg5">5</sup> <a href="https://www.mailgun.com/products/" class="text-brand-500 underline">Mailgun Products page</a><br>
  <sup id="src-mg6">6</sup> <a href="https://www.mailgun.com/products/sso/" class="text-brand-500 underline">Mailgun SSO documentation</a><br>
  <sup id="src-mg7">7</sup> <a href="https://documentation.mailgun.com/en/latest/api-events.html" class="text-brand-500 underline">Mailgun Events API reference</a><br>
  <sup id="src-mg8">8</sup> <a href="https://www.mailgun.com/pricing/" class="text-brand-500 underline">Mailgun Pricing page</a><br>
  <sup id="src-mg9">9</sup> <a href="https://www.mailgun.com/email-validation/" class="text-brand-500 underline">Mailgun Email Validation</a><br>
  <br>
  Last verified: 2026-07-29. Volume assumption: 100,000 emails/month, monthly billing. EUR for ApexMail; USD for Mailgun. Prices exclude VAT. Reviewed by: ApexMail marketing engineering.
</p>
