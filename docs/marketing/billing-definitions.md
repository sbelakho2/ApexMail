# Billing Definitions

> Last updated: 2026-07-29

## Core Concepts

| Term | Definition |
|------|-----------|
| **Included emails** | Emails sent within the monthly allowance of your plan at no additional charge. Counted per accepted recipient, not per API call. |
| **Billable email** | Each accepted recipient delivery that counts toward your plan usage. A single API call with 100 recipients counts as 100 billable emails. |
| **Attempted email** | Any email submitted through the API or SMTP, regardless of whether it was accepted for delivery. |
| **Accepted email** | An attempted email that passed validation, sender authorization, domain verification, and was queued for delivery. Accepted emails are billable. |
| **Rejected email** | An attempted email that failed validation (invalid sender, unverified domain, suppressed recipient, attachment too large, etc.). Rejected emails are not billable. |
| **Retried email** | An email submission that was retried using the same idempotency key. If the original request succeeded, the retry is not a new billable email. If the original request failed, the retry is a new billable email only if accepted. |
| **Duplicate request** | A request submitted with an idempotency key that matches a previously accepted request within the 24-hour key lifetime. Duplicates receive the original response and are not billable. |
| **Test email** | Emails sent to addresses in your verified sending domains during development and testing. Test emails are metered like any other send (upgrade your plan or use a suppressed test alias for un-metered local testing). |
| **Overage** | Email volume beyond a plan's included monthly amount. Paid plans may send into an overage allowance (default +100% of the included volume); the excess is invoiced at the plan's catalog rate (Developer €0.80, Pro €0.60, Growth/Business €0.35, Enterprise Cloud contractual) per 1,000 emails when the billing period ends. Free plans are hard-capped. |
| **Pay-as-you-go** | Billing model where you are charged only for accepted emails above your included volume. No upfront commitment. |
| **Dynamic Allocation** | ApexMail's approach to plan boundaries: usage alerts warn before the limit is reached, the dashboard recommends an upgrade as usage approaches it, and upgrading takes effect immediately after verified checkout. Beyond the included volume, paid plans continue into a metered overage allowance instead of stopping — no surprise, since the rate is published and the sweep invoices at period end. |
| **Monthly commitment** | Billing on a month-to-month basis. Cancel anytime. |
| **Annual commitment** | 12-month billing at 10 times the monthly price — two months free, a 16.7% saving versus twelve monthly payments. |
| **Dedicated IP fee** | Monthly fee for one or more dedicated sending IP addresses. EUR 49 for the first IP and EUR 69 for each additional IP per month on Pro and above (one included on Growth; one on Business, a second where traffic justifies it; up to three on Enterprise Cloud based on architecture). |
| **Private Cloud fee** | Monthly fee for dedicated tenant or BYOC deployment. Dedicated Tenant from EUR 4,000/mo (12-month minimum). BYOC from EUR 6,500/mo. |
| **Setup fee** | One-time onboarding fee for Private Cloud deployments. Dedicated Tenant: EUR 10,000–40,000. BYOC: EUR 20,000–60,000. |
| **Compliance line** | Annual-contract line at EUR 990/mo: 1M emails, EU-only routing, dedicated IP, DORA/NIS2 evidence pack, GDPR processor pack, signed routing receipts, 1-year audit log and SSO. |
| **Platform line** | Annual-contract line: EUR 990/mo base, EUR 0.30 per 1,000 emails above 1M, and EUR 1 per active subaccount above 100. |
| **Mailbox seat** | EUR 6 per seat/month, 10-seat minimum; archive and journaling adds EUR 2 per seat. |
| **Inbox placement monitoring** | EUR 99/mo add-on on any paid plan. |
| **EU-only routing** | EUR 149/mo add-on on Pro and above; sending through ApexMail's own EU MTAs with no third-party transport. |
| **Support fee** | Monthly fee for enhanced support tiers. Included in plan price for Growth and above. Enterprise includes dedicated CSM. |
| **Tax** | Value Added Tax (VAT) is applied where required by law. EU customers with valid VAT IDs may use reverse charge. All displayed prices exclude VAT unless noted. |
| **Credit** | Account credit applied toward future invoices. May be issued for service disruptions, promotional offers, or prepayment. |
| **Refund** | Return of payment for services not rendered. Subject to the refund policy in the Terms of Service. |

## What generates a charge

- Each accepted recipient email above your plan's included volume
- Dedicated IP addresses (flat monthly fee per IP)
- Private Cloud deployment (flat monthly fee plus setup fee)
- Compliance, Platform and Mailbox-seat lines on their annual contract
- Inbox placement monitoring and EU-only routing add-ons
- Enhanced support tiers (if not included in your plan)
- Extended data retention beyond plan default
- Annual commitment bills at 10 times the monthly price (two months free, 16.7% saving)

## What does NOT generate a charge

- Rejected emails (validation failures, unverified domains, suppressed recipients)
- Duplicate idempotent requests within 24-hour key lifetime
- Webhook delivery attempts
- API calls that do not result in accepted emails
- Account management and dashboard access
- Documentation and community support

## Dynamic Allocation vs Overage

Paid plans are not hard-blocked at the included volume. As usage approaches
the limit:

1. Usage alerts fire at your configured thresholds
2. The dashboard recommends an upgrade
3. Beyond the included volume, sending continues into the overage allowance
   (default +100% of the plan volume) metered at the plan's catalog rate
   (Developer €0.80, Pro €0.60, Growth/Business €0.35 per 1,000 emails),
   invoiced automatically at period end
4. When the allowance itself is exhausted, sends return `403 email quota
   exceeded` until an upgrade or the next period
5. You may switch plans at any time; proration applies for mid-cycle changes

Enterprise plans may negotiate custom volume commitments and ceilings.
