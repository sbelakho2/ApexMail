# ApexMail Pricing — Canonical Reference (February 2026)

> **This is the single source of truth for all pricing.**
> Every document, marketing page, AI training file, support playbook, and backend
> constant MUST agree with this file. When in doubt, this file wins.

---

## Competitive Context

ApexMail competes directly with **Resend** (and indirectly with SendGrid, Postmark,
Mailgun, Amazon SES). Our pricing is designed to be **competitive on per-email
cost** while justifying a moderate premium through **features Resend does not
offer**: contact management, A/B testing, send-time optimisation, long data
retention, SSO/HIPAA/SOC2 compliance, and white-label.

### Resend pricing (Feb 2026)

| Plan       | Price  | Emails/mo | Overage   | Retention | Domains | Teams | Dedicated IPs   |
|------------|--------|-----------|-----------|-----------|---------|-------|-----------------|
| Free       | $0     | 3,000     | —         | 1 day     | 1       | 1     | —               |
| Pro        | $20    | 50,000    | $0.90/1K  | 3 days    | 10      | 5     | —               |
| Scale      | $90    | 100,000   | $0.90/1K  | 7 days    | 1,000   | 100   | Add-on ($30)    |
| Enterprise | Custom | Custom    | Custom    | Flexible  | Flex    | Flex  | Add-on ($30)    |

### Where ApexMail wins

| Advantage                  | ApexMail          | Resend           |
|----------------------------|-------------------|------------------|
| Data retention (Free)      | **7 days**        | 1 day            |
| Data retention (paid)      | **30–730 days**   | 3–7 days         |
| Contact management         | **Built-in**      | Basic "Audiences" |
| A/B testing                | **Yes (Pro+)**    | No               |
| Send-time optimisation     | **AI-powered**    | No               |
| SSO / SAML                 | **Scale+**        | No               |
| HIPAA / SOC2               | **Enterprise**    | SOC2 only        |
| White-label                | **Enterprise**    | No               |
| SDKs                       | **6 languages**   | 4 languages      |
| Dedicated IPs              | **From Pro ($30)**| Scale only ($30) |
| Overage cost               | **$0.40/1K**      | $0.90/1K         |

---

## New ApexMail Pricing (effective March 2026)

### Subscription Plans

| Plan       | Price/mo | Annual  | Emails/mo   | API calls/mo | Team | Domains | Contacts    | Retention |
|------------|----------|---------|-------------|--------------|------|---------|-------------|-----------|
| Free       | $0       | $0      | 3,000       | 50,000       | 1    | 1       | 500         | 7 days    |
| Starter    | $25      | $250/yr | 50,000      | 500,000      | 5    | 5       | 10,000      | 30 days   |
| Pro        | $65      | $650/yr | 150,000     | 2,000,000    | 10   | 25      | 50,000      | 60 days   |
| Growth     | $150     | $1,500/yr | 500,000   | 5,000,000    | 25   | 100     | 200,000     | 90 days   |
| Scale      | $350     | $3,500/yr | 2,000,000 | 20,000,000   | 50   | Unlimited | 500,000   | 365 days  |
| Enterprise | $800     | $8,000/yr | 5,000,000 | Unlimited    | Unlimited | Unlimited | Unlimited | 730 days |

Annual billing = 10 months (2 months free; ~17% discount).

### Pay-As-You-Go (PAYG)

| Volume tier | Price per email |
|-------------|----------------|
| 0–10,000    | $0.001         |
| 10,001–100K | $0.0008        |
| 100K–1M     | $0.0005        |
| 1M+         | $0.0003        |

No monthly commitment. API calls: first 100K free, then $0.10/1K.

### Overages (subscription plans)

| Item             | Rate             |
|------------------|------------------|
| Extra emails     | $0.40 per 1,000  |
| Extra API calls  | $0.10 per 1,000 (first 100K free on all plans) |

### Dedicated IPs

| Item                    | Price    |
|-------------------------|----------|
| Dedicated IP add-on     | $30/mo   |
| Growth plan             | 1 included |
| Scale plan              | 3 included |
| Enterprise plan         | 10 included |

Available from **Pro** plan and above. Requires average sending volume > 500 emails/day.
Warmup, monitoring, and autoscaling included.

---

## Feature Matrix

| Feature                        | Free | Starter | Pro       | Growth    | Scale       | Enterprise  |
|--------------------------------|------|---------|-----------|-----------|-------------|-------------|
| REST API + SMTP relay          | ✓    | ✓       | ✓         | ✓         | ✓           | ✓           |
| SDKs (Node, Python, Go, Ruby, PHP, Java) | ✓ | ✓  | ✓         | ✓         | ✓           | ✓           |
| Basic analytics                | ✓    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Webhooks                       | —    | ✓ (5)   | ✓ (10)    | ✓ (25)    | ✓ (Unlim)   | ✓ (Unlim)   |
| Custom templates               | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Data export                    | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Custom tracking domain         | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Advanced analytics             | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| A/B testing                    | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Send-time optimisation (AI)    | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Audit logs                     | —    | —       | —         | ✓         | ✓           | ✓           |
| Dedicated IP                   | —    | —       | Add-on    | 1 included| 3 included  | 10 included |
| SSO / SAML                     | —    | —       | —         | —         | ✓           | ✓           |
| Subaccounts                    | —    | —       | —         | —         | ✓ (10)      | ✓ (100)     |
| Inbound email receiving        | —    | —       | —         | —         | ✓           | ✓           |
| SLA guarantee                  | —    | —       | —         | —         | 99.9% (10%) | 99.9% (25%) |
| HIPAA compliance               | —    | —       | —         | —         | —           | ✓           |
| SOC2 compliance                | —    | —       | —         | —         | —           | ✓           |
| White-label                    | —    | —       | —         | —         | —           | ✓           |
| BYOIP                          | —    | —       | —         | —         | —           | ✓           |
| Dedicated CSM                  | —    | —       | —         | —         | ✓           | ✓           |
| Priority onboarding            | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Support level                  | Community | Email | Email   | Priority  | Phone       | Dedicated   |

### Key feature gates (for AI training):

- **A/B testing**: Pro ($65) and above. NOT on Free or Starter.
- **Send-time optimisation**: Pro ($65) and above.
- **Custom tracking domain**: Pro ($65) and above.
- **Audit logs**: Growth ($150) and above.
- **Dedicated IPs**: Pro ($65) as add-on ($30/mo). Growth (1 free), Scale (3 free), Enterprise (10 free).
- **SSO/SAML**: Scale ($350) and above.
- **Inbound email**: Scale ($350) and above.
- **SLA credits**: Scale 10%, Enterprise 25%.
- **HIPAA/SOC2**: Enterprise ($800) only.
- **White-label / BYOIP**: Enterprise ($800) only.

---

## Margin Analysis (internal only — NEVER disclose)

Infrastructure provider: AWS SES ($0.10 per 1,000 emails).
Dedicated IP cost: $24.95/mo per IP (AWS SES standard dedicated IP).

| Plan       | Revenue | SES COGS (max) | Gross Margin |
|------------|---------|----------------|--------------|
| Free       | $0      | $0.30          | N/A (lead gen) |
| Starter    | $25     | $5.00          | 80%          |
| Pro        | $65     | $15.00         | 77%          |
| Growth     | $150    | $50.00 + $24.95 (1 IP) | 50%  |
| Scale      | $350    | $200 + $74.85 (3 IPs) | 21%  |
| Enterprise | $800    | $500 + $249.50 (10 IPs) | 6%  |

Scale and Enterprise margins improve significantly when customers use
less than their email allocation (typical utilisation: 40–60%).

---

## Migration from Old Pricing

| Plan       | Old Price | New Price | Old Emails | New Emails | Change       |
|------------|-----------|-----------|------------|------------|--------------|
| Free       | $0/1K     | $0/3K     | 1,000      | 3,000      | 3× volume    |
| Starter    | $29/25K   | $25/50K   | 25,000     | 50,000     | −$4, 2× vol  |
| Pro        | $59/50K   | $65/150K  | 50,000     | 150,000    | +$6, 3× vol  |
| Growth     | $129/100K | $150/500K | 100,000    | 500,000    | +$21, 5× vol |
| Scale      | $399/500K | $350/2M   | 500,000    | 2,000,000  | −$49, 4× vol |
| Enterprise | $1,299/2M | $800/5M   | 2,000,000  | 5,000,000  | −$499, 2.5× vol |

Every tier delivers **significantly more emails per dollar** than before.
Existing customers on old plans are grandfathered for 6 months, then auto-
migrated to the nearest equivalent new tier (always to their benefit).

---

## Contact Limits by Plan

| Plan       | Contacts  |
|------------|-----------|
| Free       | 500       |
| Starter    | 10,000    |
| Pro        | 50,000    |
| Growth     | 200,000   |
| Scale      | 500,000   |
| Enterprise | Unlimited |

---

## API Rate Limits

All plans: **1,000 requests/min** (sliding window).
Enterprise may negotiate higher limits.

---

## SLA Details

| Plan       | Uptime SLA | Credit Cap |
|------------|------------|------------|
| Scale      | 99.9%      | 10%        |
| Enterprise | 99.9%      | 25%        |

Other plans: best-effort, no SLA.

---

## Annual Billing

Annual plans are billed at 10× monthly price (2 months free):

| Plan       | Monthly | Annual   | Effective/mo |
|------------|---------|----------|--------------|
| Starter    | $25     | $250     | $20.83       |
| Pro        | $65     | $650     | $54.17       |
| Growth     | $150    | $1,500   | $125.00      |
| Scale      | $350    | $3,500   | $291.67      |
| Enterprise | $800    | $8,000   | $666.67      |
