# ApexMail Pricing — Canonical Reference (April 2026)

> **This is the single source of truth for all pricing.**
> Every document, marketing page, AI training file, support playbook, and backend
> constant MUST agree with this file. When in doubt, this file wins.

## Honest Framing

ApexMail's path to $100k MRR is enterprise-led. We win when a regulated SaaS
company needs deliverability isolation, audit logs, GDPR workflows, HIPAA BAA
lifecycle support, SOC 2 control evidence workflows, SIG/CAIQ/HECVAT answer-pack
automation, and high-touch account ownership as part of the email platform. The
Free, Starter, and Pro tiers exist to make adoption frictionless during the
trial; the value capture lives in Growth, Scale, and Enterprise.

We charge less per message than Resend at every paid tier; we charge
**more** at Enterprise because annual contracts fund dedicated onboarding,
CSM coverage, SLA commitments, compliance review, and custom architecture work.

---

## Competitive Context

ApexMail competes directly with **Resend** (and indirectly with SendGrid, Postmark,
Mailgun, Amazon SES). Our pricing is designed to be **competitive on per-email
cost** while justifying a premium through **features Resend does not offer**:
contact management, long data retention, SSO, SCIM, send-time optimization,
A/B testing, HIPAA BAA lifecycle tooling, SOC 2 control evidence workflows,
generated security questionnaires, audit logs, and white-label.

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
| SSO / SAML                 | **Scale+**        | No               |
| HIPAA / SOC2 workflows     | **Enterprise**    | SOC2 only        |
| White-label                | **Enterprise**    | No               |
| SDKs                       | **5 languages**   | 4 languages      |
| Dedicated IPs              | **From Pro ($30)**| Scale only ($30) |
| Overage cost               | **$0.40/1K**      | $0.90/1K         |

---

## New ApexMail Pricing (effective March 2026)

### Subscription Plans

| Plan       | Price/mo | Annual  | Emails/mo   | API calls/mo | Team | Domains | Retention |
|------------|----------|---------|-------------|--------------|------|---------|-----------|
| Free       | $0       | $0      | 30,000      | 300,000      | 1    | 1       | 7 days    |
| Starter    | $25      | $250/yr | 50,000      | 500,000      | 5    | 5       | 30 days   |
| Pro        | $65      | $650/yr | 150,000     | 2,000,000    | 10   | 25      | 60 days   |
| Growth     | $150     | $1,500/yr | 500,000   | 5,000,000    | 25   | 100     | 90 days   |
| Scale      | $350     | $3,500/yr | 2,000,000 | 20,000,000   | 50   | Unlimited | 365 days |
| Enterprise | $3,000   | $30,000/yr | 5,000,000 | Unlimited    | Unlimited | Unlimited | 730 days |

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

The current billing-service plan contract does not define a separate subscription-plan API-call overage price. PAYG API-call billing remains `first 100K free, then $0.10 / 1K`.

### Dedicated IPs

| Item                    | Price    |
|-------------------------|----------|
| Dedicated IP add-on     | $30/mo   |
| Growth plan             | 1 included |
| Scale plan              | 3 included |
| Enterprise plan         | 10 included |

Available from **Pro** plan and above. Requires average sending volume > 500 emails/day.
Warmup, monitoring, and autoscaling included.

> **Transport note:** Dedicated IPs are provisioned via Hetzner Cloud floating IPs (~€4/mo per IP). Shared-pool sending uses AWS SES. Routing is automatic based on tenant dedicated IP ownership.

---

## Feature Matrix

| Feature                        | Free | Starter | Pro       | Growth    | Scale       | Enterprise  |
|--------------------------------|------|---------|-----------|-----------|-------------|-------------|
| REST API + SMTP relay          | ✓    | ✓       | ✓         | ✓         | ✓           | ✓           |
| SDKs (Python, Go, Ruby, PHP, Java) | ✓ | ✓  | ✓         | ✓         | ✓           | ✓           |
| Basic analytics                | ✓    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Webhooks                       | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Custom templates               | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Data export                    | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Custom tracking domain         | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Advanced analytics             | —    | ✓       | ✓         | ✓         | ✓           | ✓           |
| Send-time optimization         | —    | —       | ✓         | ✓         | ✓           | ✓           |
| A/B testing                    | —    | —       | —         | ✓         | ✓           | ✓           |
| Audit logs                     | —    | —       | —         | ✓         | ✓           | ✓           |
| Dedicated IP                   | —    | —       | Add-on    | 1 included| 3 included  | 10 included |
| SSO / SAML                     | —    | —       | —         | —         | ✓           | ✓           |
| Subaccounts                    | —    | —       | —         | —         | ✓ (10)      | ✓ (100)     |
| Inbound email receiving        | —    | —       | —         | —         | ✓           | ✓           |
| SLA guarantee                  | —    | —       | —         | —         | 99.9% (10%) | 99.9% (25%) |
| HIPAA BAA workflow             | —    | —       | —         | —         | —           | ✓           |
| SOC 2 control evidence         | —    | —       | —         | —         | —           | ✓           |
| SIG / CAIQ / HECVAT answer packs | —  | —       | —         | —         | —           | ✓           |
| Security-review report export  | —    | —       | —         | —         | —           | ✓           |
| White-label                    | —    | —       | —         | —         | —           | ✓           |
| Private deployment lifecycle   | —    | —       | —         | —         | —           | ✓           |
| BYOIP registration + verification | — | —       | —         | —         | —           | ✓           |
| Dedicated CSM                  | —    | —       | —         | —         | ✓           | ✓           |
| Priority onboarding            | —    | —       | ✓         | ✓         | ✓           | ✓           |
| Support level                  | Community | Email | Email   | Email     | Priority    | Dedicated   |

### Key feature gates (for AI training):

- **Custom tracking domain**: Pro ($65) and above.
- **Send-time optimization**: Pro ($65) and above.
- **A/B testing**: Growth ($150) and above.
- **Audit logs**: Growth ($150) and above.
- **Dedicated IPs**: Pro ($65) as add-on ($30/mo). Growth (1 free), Scale (3 free), Enterprise (10 free).
- **SSO/SAML**: Scale ($350) and above.
- **Inbound email**: Scale ($350) and above.
- **SLA credits**: Scale 10%, Enterprise 25%.
- **HIPAA BAA + SOC 2 evidence workflows + SIG/CAIQ/HECVAT packs**: Enterprise ($3,000) only.
- **White-label**: Enterprise ($3,000) only.
- **Private deployment + BYOIP lifecycle**: Enterprise ($3,000) only; includes private deployment tracking, health checks, dedicated IP lifecycle, and BYOIP CIDR verification workflows.

---

Internal margin modelling is maintained outside this public pricing reference.

---

## Migration from Old Pricing

| Plan       | Old Price | New Price | Old Emails | New Emails | Change       |
|------------|-----------|-----------|------------|------------|--------------|
| Free       | $0/1K     | $0/30K    | 1,000      | 30,000     | 30× volume   |
| Starter    | $29/25K   | $25/50K   | 25,000     | 50,000     | −$4, 2× vol  |
| Pro        | $59/50K   | $65/150K  | 50,000     | 150,000    | +$6, 3× vol  |
| Growth     | $129/100K | $150/500K | 100,000    | 500,000    | +$21, 5× vol |
| Scale      | $399/500K | $350/2M   | 500,000    | 2,000,000  | −$49, 4× vol |
| Enterprise | $1,299/2M | $3,000/5M | 2,000,000  | 5,000,000  | Annual contract, 2.5× volume |

Self-serve tiers deliver **significantly more emails per dollar** than before;
Enterprise is deliberately repriced as a higher-touch annual contract.
Existing customers on old plans are grandfathered for 6 months, then auto-
migrated to the nearest equivalent new tier (always to their benefit).

---

## API Rate Limits

The current billing-service quota model maps plans to request-rate tiers:

| Plan tier | Throughput |
|-----------|------------|
| Free | 10 requests / second |
| Starter / Pro / PAYG | 100 requests / second |
| Growth / Scale | 500 requests / second |
| Enterprise | 5,000 requests / second |

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
| Enterprise | $3,000  | $30,000  | $2,500.00    |
