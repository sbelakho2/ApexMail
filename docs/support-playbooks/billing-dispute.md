# Billing Dispute Playbook

> **Audience:** Internal ops/support team  
> **Last updated:** 2026-02-09  
> **Owner:** Billing & customer success team  
> **Severity default:** P3 (escalate to P2 if Enterprise plan or legal threat)

---

## Symptoms

- Customer disputes a charge on their credit card
- Customer requests a refund or account credit
- Stripe notifies us of a chargeback/dispute
- Customer claims they were overcharged or billed for unused service
- Customer reports billing after cancellation
- Plan upgrade/downgrade not reflected correctly

### How customers typically report this

- "I was charged but I cancelled last month"
- "My invoice is wrong, I should be on the Starter plan"
- "I want a refund for the downtime last week"
- "Why was I charged $150 when I signed up for $65?"
- "I need an SLA credit for the outage"
- "I got double-charged this month"

---

## Diagnosis

### Step 1: Identify the customer and subscription

```sql
-- Look up the customer's billing details
SELECT
  t.id AS tenant_id,
  t.name,
  t.plan,
  t.stripe_customer_id,
  t.stripe_subscription_id,
  t.created_at,
  t.cancelled_at,
  t.billing_email
FROM tenants t
WHERE t.name ILIKE '%customer_name%'
   OR t.billing_email ILIKE '%customer_email%';
```

### Step 2: Check Stripe payment history

1. Open Stripe dashboard: `https://dashboard.stripe.com`
2. Search for the customer by email or Stripe customer ID
3. Review:
   - **Subscription status:** Active, Canceled, Past Due, Trialing
   - **Invoice history:** Check all invoices for the disputed period
   - **Payment method:** Card on file, any failed payments
   - **Proration events:** Mid-cycle plan changes

```bash
# Or use Stripe CLI for quick lookup
stripe customers retrieve cus_XXXXX --expand='["subscriptions"]'
stripe invoices list --customer=cus_XXXXX --limit=12
```

### Step 3: Verify actual usage

```sql
-- Check the customer's actual usage for the billing period
SELECT
  DATE_TRUNC('month', sent_at) AS month,
  COUNT(*) AS emails_sent,
  COUNT(DISTINCT campaign_id) AS campaigns,
  COUNT(DISTINCT contact_id) AS active_contacts
FROM emails
WHERE tenant_id = 'TENANT_ID'
  AND sent_at BETWEEN '2026-01-01' AND '2026-02-01'
GROUP BY DATE_TRUNC('month', sent_at);
```

### Step 4: Cross-reference plan limits

| Plan | Monthly price | Email limit | Contacts | Dedicated IP | SLA Guarantee |
|------|---------------|-------------|----------|--------------|---------------|
| Free | $0 | 3,000/mo | 500 | No | No |
| Starter | $25/mo | 50,000/mo | 10,000 | No | No |
| Pro | $65/mo | 150,000/mo | 50,000 | Add-on ($30/mo) | No |
| Growth | $150/mo | 500,000/mo | 200,000 | 1 included | No |
| Scale | $350/mo | 2,000,000/mo | 500,000 | 3 included | Yes (10% credit) |
| Enterprise | $800/mo | 5,000,000/mo | Unlimited | 10 included | Yes (25% credit) |

**Overage rates** (when applicable):
- Emails beyond limit: $0.40 per 1,000
- Contacts beyond limit: $5 per 1,000
- Dedicated IP add-on: $30/mo

### Step 5: Check for SLA violations

If the customer is claiming an SLA credit, verify actual uptime for the billing period:

```bash
# Query Prometheus for uptime during the disputed period
curl -s "http://prometheus.apexmail.internal:9090/v1/query_range?query=apexmail_api_up&start=2026-01-01T00:00:00Z&end=2026-02-01T00:00:00Z&step=5m" | jq '.data.result'
```

```sql
-- Check recorded incidents/outages
SELECT
  i.started_at,
  i.resolved_at,
  i.duration_minutes,
  i.severity,
  i.affected_services,
  i.description
FROM incidents i
WHERE i.started_at BETWEEN '2026-01-01' AND '2026-02-01'
  AND i.severity IN ('major', 'critical')
ORDER BY i.started_at;
```

**SLA credit calculation:**

> **Note:** SLA guarantees are only available on **Scale** and **Enterprise** plans. The SLA target is **99.9% availability**.

| Breach below 99.9% target | Credit (% of monthly bill) |
|----------------------------|---------------------------|
| 0.1% below (99.8%) | 10% credit |
| 0.5% below (99.4%) | 25% credit |
| 1.0% below (98.9%) | 50% credit |
| 5.0%+ below (<94.9%) | 100% credit |

**Plan-specific max credit:** Scale plans receive up to 10% invoice credit, Enterprise plans receive up to 25%.

**Formula:**
$$\text{Uptime \%} = \frac{\text{Total minutes} - \text{Downtime minutes}}{\text{Total minutes}} \times 100$$

Example for January (44,640 minutes):
- 60 minutes downtime = $(44640 - 60) / 44640 \times 100 = 99.87\%$
- Scale plan ($350) → 99.87% is 0.03% below 99.9% target → does not breach 0.1% threshold → No credit
- 90 minutes downtime = $(44640 - 90) / 44640 \times 100 = 99.80\%$
- Scale plan ($350) → 99.80% is 0.1% below 99.9% target → 10% credit = $35.00

### Step 6: Check for billing system issues

```sql
-- Check for duplicate charges
SELECT
  stripe_invoice_id,
  amount_cents,
  status,
  created_at,
  billing_period_start,
  billing_period_end
FROM invoices
WHERE tenant_id = 'TENANT_ID'
  AND created_at > NOW() - INTERVAL '3 months'
ORDER BY created_at DESC;

-- Check for plan change events
SELECT
  event_type,
  old_plan,
  new_plan,
  effective_date,
  created_at,
  created_by
FROM billing_events
WHERE tenant_id = 'TENANT_ID'
ORDER BY created_at DESC
LIMIT 20;
```

---

## Resolution

### Scenario 1: Legitimate overcharge or billing error

1. Calculate the correct amount owed
2. Issue a refund or credit via Stripe:
   ```bash
   # Partial refund
   stripe refunds create --charge=ch_XXXXX --amount=2900  # amount in cents

   # Full invoice refund
   stripe refunds create --charge=ch_XXXXX
   ```
3. Or issue an account credit for future invoices:
   ```bash
   stripe customers create_balance_transaction cus_XXXXX --amount=-2900 --currency=usd --description="Billing correction - overcharge on Jan invoice"
   ```
4. Send confirmation email to customer
5. Document in CRM: ticket ID, amount, reason

### Scenario 2: SLA credit due

1. Calculate credit amount per the SLA table above
2. Apply credit to the customer's Stripe account:
   ```bash
   stripe customers create_balance_transaction cus_XXXXX \
     --amount=-590 \
     --currency=usd \
     --description="SLA credit - Jan 2026 - 60min downtime (99.87% uptime)"
   ```
3. Notify customer with the credit amount and calculation breakdown
4. Log the SLA credit in the incidents table

### Scenario 3: Customer cancelled but was still charged

1. Verify cancellation date in the system vs. Stripe
2. Check if cancellation was processed correctly:
   ```sql
   SELECT cancelled_at, cancel_reason, cancel_requested_by
   FROM tenants WHERE id = 'TENANT_ID';
   ```
3. If cancellation was missed (our fault): issue full refund for post-cancellation charges
4. If customer cancelled after billing cycle started: explain prorated billing, offer goodwill credit if appropriate

### Scenario 4: Chargeback from Stripe

**Time-sensitive — respond within 7 days.**

1. Gather evidence:
   - Signed terms of service / acceptance timestamp
   - Usage logs showing the customer used the service
   - Email confirmations of subscription
   - Any prior support conversations
2. Submit evidence via Stripe dispute response:
   ```bash
   stripe disputes update dp_XXXXX \
     --evidence[customer_email_address]="customer@example.com" \
     --evidence[product_description]="ApexMail email marketing SaaS" \
     --evidence[access_activity_log]="Usage logs attached"
   ```
3. Document everything in the CRM

### Scenario 5: No billing error found

1. Explain the charges clearly with invoice links
2. Break down what each line item covers
3. Offer to walk through the invoice on a call if needed
4. If customer is unhappy but charges are correct, offer a small goodwill credit (max $25 without manager approval, max $100 with manager approval)

---

## Escalation

| Condition | Action |
|-----------|--------|
| Dispute amount > $500 | Escalate to billing manager |
| Chargeback filed in Stripe | Escalate to billing manager immediately |
| Enterprise plan customer | Notify account manager, prioritize response |
| Customer threatens legal action | Escalate to billing manager and notify leadership |
| Systematic billing bug (multiple customers) | P1 — page on-call engineer and billing manager |
| Refund > $200 requested | Requires manager approval |

### Approval thresholds

| Action | L1 Support | Billing Manager | VP |
|--------|------------|-----------------|-----|
| Goodwill credit ≤ $25 | ✅ | — | — |
| Goodwill credit $26-$100 | ❌ | ✅ | — |
| Refund ≤ $200 | ✅ | — | — |
| Refund $201-$1,000 | ❌ | ✅ | — |
| Refund > $1,000 | ❌ | ❌ | ✅ |
| SLA credit (calculated) | ✅ | — | — |
| Full month comp | ❌ | ✅ | — |

---

## Related

- Stripe dashboard: `https://dashboard.stripe.com`
- Billing source code: `apps/billing/src/`
- Billing migrations: `apps/billing/migrations/`
- SLA documentation: internal SLA policy doc
- [Bounce Investigation](bounce-investigation.md) — if billing dispute is related to delivery failure
- [Deliverability Triage](deliverability-triage.md) — if customer cites poor deliverability as reason for refund
- CRM: `https://crm.apexmail.internal`

---

## Appendix: Response templates

### Refund approved

> Hi [Name],
>
> Thank you for reaching out. We've reviewed your account and confirmed [reason].
> A refund of $[amount] has been processed to your card ending in [last4].
> Please allow 5-10 business days for it to appear on your statement.
>
> We apologize for the inconvenience. Let us know if there's anything else we can help with.

### SLA credit issued

> Hi [Name],
>
> We've reviewed the service disruption on [date] that affected your account.
> Based on our SLA commitment for the [Plan] plan (99.X% uptime), your measured
> uptime for [month] was XX.XX%, which qualifies for a [X]% credit.
>
> A credit of $[amount] has been applied to your account and will be reflected
> on your next invoice.
>
> We take our reliability commitments seriously and are working to prevent
> future incidents.

### No billing error found

> Hi [Name],
>
> Thank you for contacting us about your billing concern. We've reviewed your
> account and can confirm the charges are correct:
>
> - [Plan] plan: $[amount]/mo
> - Billing period: [start] to [end]
> - [Additional line items if applicable]
>
> [Explanation of charges]. If you'd like to discuss this further or would
> prefer to walk through your invoice together, we're happy to set up a call.
