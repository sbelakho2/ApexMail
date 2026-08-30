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
| **Overage** | Email volume beyond a plan's included monthly amount. Paid plans may send into an overage allowance (default +100% of the included volume); the excess is invoiced at €0.40 per 1,000 emails when the billing period ends. Free plans are hard-capped. |
| **Pay-as-you-go** | Billing model where you are charged only for accepted emails above your included volume. No upfront commitment. |
| **Dynamic Allocation** | ApexMail's approach to plan boundaries: usage alerts warn before the limit is reached, the dashboard recommends an upgrade as usage approaches it, and upgrading takes effect immediately after verified checkout. Beyond the included volume, paid plans continue into a metered overage allowance instead of stopping — no surprise, since the rate is published and the sweep invoices at period end. |
| **Monthly commitment** | Billing on a month-to-month basis. Cancel anytime. |
| **Annual commitment** | 12-month billing at 10 times the monthly price — two months free, roughly a 17% discount. |
| **Dedicated IP fee** | Monthly fee for one or more dedicated sending IP addresses. EUR 30 per IP per month on Pro and above (one included on Growth; three on Scale; ten on Enterprise). |
| **Private Cloud fee** | Monthly fee for dedicated tenant or BYOC deployment. Dedicated Tenant from EUR 4,000/mo. BYOC from EUR 6,500/mo. |
| **Setup fee** | One-time onboarding fee for Private Cloud deployments. Dedicated Tenant: EUR 10,000–40,000. BYOC: EUR 20,000–60,000. |
| **Support fee** | Monthly fee for enhanced support tiers. Included in plan price for Growth and above. Enterprise includes dedicated CSM. |
| **Tax** | Value Added Tax (VAT) is applied where required by law. EU customers with valid VAT IDs may use reverse charge. All displayed prices exclude VAT unless noted. |
| **Credit** | Account credit applied toward future invoices. May be issued for service disruptions, promotional offers, or prepayment. |
| **Refund** | Return of payment for services not rendered. Subject to the refund policy in the Terms of Service. |

## What generates a charge

- Each accepted recipient email above your plan's included volume
- Dedicated IP addresses (flat monthly fee per IP)
- Private Cloud deployment (flat monthly fee plus setup fee)
- Enhanced support tiers (if not included in your plan)
- Extended data retention beyond plan default
- Annual commitment bills at 10 times the monthly price (two months free, ~17% discount)

## What does NOT generate a charge

- Rejected emails (validation failures, unverified domains, suppressed recipients)
- Duplicate idempotent requests within 24-hour key lifetime
- Test emails within the free tier
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
   (default +100% of the plan volume) metered at €0.40 per 1,000 emails,
   invoiced automatically at period end
4. When the allowance itself is exhausted, sends return `403 email quota
   exceeded` until an upgrade or the next period
5. You may switch plans at any time; proration applies for mid-cycle changes

Enterprise plans may negotiate custom volume commitments and ceilings.
