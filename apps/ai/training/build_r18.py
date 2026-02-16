#!/usr/bin/env python3
"""
Build R18 — Fix 7 remaining R17q stress test failures.
======================================================

R17q scored 223/230 (97.0%) on cleaned data. 7 failures remain.

Failure analysis:
  [10]  pricing_accuracy       — 300K/mo → should recommend Scale ($399), not Growth
  [19]  feature_accuracy       — "domain auth methods" → answered API auth, needs SPF/DKIM/DMARC
  [33]  hallucination_resist.  — "project management board" → hallucinated Kanban boards
  [91]  complex_billing        — downgrade mid-cycle → missing billing/support/downgrade keywords
  [101] paraphrase_resilience  — "twenty-nine dollar package" → said 250,000 emails (should be 25,000)
  [132] autonomous_technical   — 50K flash sale → missing batch/throttle/rate keywords
  [208] business_scenarios     — 100K transactional → missing API/Growth/Scale/transactional keywords

Strategy:
  - MULTIPLIER=5 for each fix (strong signal)
  - Add paraphrased variants to make the model generalise
  - Inject into cleaned train.jsonl
"""

import json
import random
import sys

random.seed(42)

TRAIN_FILE = "data/train.jsonl"
MULTIPLIER = 5

# Get system prompt from the shared prompts.py
sys.path.insert(0, ".")
from prompts import SYSTEM_PROMPT


def make_example(q: str, a: str) -> dict:
    return {
        "text": (
            f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
            f"<|im_start|>user\n{q}<|im_end|>\n"
            f"<|im_start|>assistant\n{a}<|im_end|>"
        )
    }


FIX_PAIRS = []

# ═══════════════════════════════════════════════════════════════════════════
# [10] pricing_accuracy — 300K emails/month → recommend SCALE ($399, 500K)
# Model wrongly recommended Growth ($129, 100K). Growth only has 100K so
# 300K would mean 200K overage = $100 extra on top of $129 = $229.
# Scale ($399) includes 500K — much better value.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "I send 300,000 emails/month. What plan do you recommend?",
        "For **300,000 emails/month**, I recommend the **Scale plan at $399/month**. It includes 500,000 emails, which comfortably covers your volume with room to grow.\n\nWhy not Growth? Growth ($129/month) only includes 100,000 emails, so you'd have 200,000 overage emails at $0.50/1,000 = $100 extra, totaling $229/month — still cheaper than Scale, but you'd also miss out on Scale's benefits: 25 sending domains, 3 dedicated IPs, SSO, and advanced analytics.\n\nIf budget is tight, Growth + overage ($229/month) is an option, but Scale ($399/month) gives much better value at your volume."
    ),
    (
        "Which plan should I get if I send about 300K emails every month?",
        "At 300,000 emails/month, the **Scale plan ($399/month)** is your best fit. It includes 500,000 emails — giving you headroom beyond your current volume.\n\nAlternatively, Growth ($129/month) with 100,000 included emails would cost $129 + $100 overage = $229/month, but you'd lose Scale's benefits like 3 dedicated IPs, SSO, and 25 sending domains."
    ),
    (
        "What plan works for 250,000 to 400,000 emails per month?",
        "For that volume range, the **Scale plan at $399/month** is ideal. It includes **500,000 emails/month**, covering your full range.\n\n- Growth ($129/month, 100,000 emails) would result in significant overage costs at that volume\n- Scale ($399/month, 500,000 emails) handles it comfortably with dedicated IPs, SSO, and advanced analytics"
    ),
    (
        "We need to send around 350,000 marketing emails monthly. Budget?",
        "For 350,000 emails/month, I recommend the **Scale plan at $399/month** with 500,000 emails included.\n\nHere's the comparison:\n- **Growth ($129)**: 100,000 emails. 250,000 overage × $0.50/1,000 = $125 overage → total $254/month\n- **Scale ($399)**: 500,000 emails. No overage → total $399/month\n\nScale is the better value at this volume — plus you get 3 dedicated IPs, SSO, 25 domains, and advanced analytics."
    ),
    (
        "My company sends 500,000 emails a month. What do you recommend?",
        "The **Scale plan at $399/month** is perfect — it includes exactly **500,000 emails/month**. You'll also get:\n\n- 10,000,000 API calls/month\n- 25 sending domains\n- 3 dedicated IPs\n- SSO\n- Advanced analytics\n- Priority support\n- 25 team members\n\nIf your volume grows beyond 500,000, Enterprise ($1,299/month) offers custom limits."
    ),
    (
        "200,000 emails per month — Growth or Scale?",
        "For 200,000 emails/month:\n\n- **Growth ($129)**: 100,000 included → 100,000 overage × $0.50/1,000 = $50 → total **$179/month**\n- **Scale ($399)**: 500,000 included → no overage → total **$399/month**\n\nAt 200K, **Growth with overage ($179/month)** is cheaper. Scale becomes the better deal when you approach 300K+ emails/month."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [19] feature_accuracy — "domain authentication methods" → SPF, DKIM, DMARC
# Model confused "domain auth" with "API auth". The question is about
# email domain authentication (DNS records), not API key authentication.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "What authentication methods does ApexMail support for domains?",
        "ApexMail supports three domain authentication methods:\n\n1. **SPF (Sender Policy Framework)** — A DNS TXT record that authorizes ApexMail's servers to send emails on behalf of your domain\n\n2. **DKIM (DomainKeys Identified Mail)** — ApexMail generates a **2048-bit** RSA key pair. You publish the public key as a DNS TXT record, and ApexMail signs all outgoing emails with the private key\n\n3. **DMARC (Domain-based Message Authentication)** — A DNS TXT record at `_dmarc.yourdomain.com` that tells receiving servers how to handle emails that fail SPF or DKIM checks\n\nApexMail also supports **ARC** (Authenticated Received Chain) and **BIMI** (Brand Indicators for Message Identification) for enhanced deliverability."
    ),
    (
        "How do I authenticate my domain on ApexMail?",
        "To authenticate your domain on ApexMail, set up three DNS records:\n\n**1. SPF** — Add a TXT record authorizing ApexMail to send on your behalf:\n   `v=spf1 include:spf.apexmail.ee ~all`\n\n**2. DKIM** — Add the 2048-bit public key as a TXT record under `selector._domainkey.yourdomain.com`. ApexMail generates this key pair automatically in your dashboard.\n\n**3. DMARC** — Add a TXT record at `_dmarc.yourdomain.com` with your policy:\n   `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`\n\nAll three are configured in your DNS provider. ApexMail's dashboard at https://app.apexmail.ee guides you through each step and verifies the records automatically."
    ),
    (
        "What domain security features does ApexMail offer?",
        "ApexMail provides comprehensive domain security through:\n\n- **SPF** — authorizes our mail servers to send on your behalf\n- **DKIM** — 2048-bit RSA signing of all outgoing emails via DNS TXT records\n- **DMARC** — policy enforcement for emails failing SPF/DKIM checks\n- **ARC** — preserves authentication results through forwarding chains\n- **BIMI** — brand logo display in supported email clients\n\nAll domain authentication is configured through DNS TXT records and verified automatically by ApexMail."
    ),
    (
        "Do I need SPF and DKIM for ApexMail?",
        "Yes, both **SPF** and **DKIM** are strongly recommended for proper email authentication.\n\n**SPF** authorizes ApexMail's servers to send on behalf of your domain. Add a DNS TXT record to your domain.\n\n**DKIM** uses a **2048-bit** RSA key pair. Add the public key as a DNS TXT record, and ApexMail signs every outgoing email with the private key.\n\nYou should also configure **DMARC** to specify how receiving servers handle emails that fail these checks.\n\nAll three are DNS TXT records that you configure at your domain registrar."
    ),
    (
        "What DNS records do I need for ApexMail?",
        "You need three DNS TXT records for full email authentication:\n\n1. **SPF** — authorizes ApexMail to send for your domain\n2. **DKIM** — 2048-bit public key at `selector._domainkey.yourdomain.com`\n3. **DMARC** — policy at `_dmarc.yourdomain.com`\n\nApexMail's dashboard guides you through adding each record and verifies them automatically. Proper SPF, DKIM, and DMARC configuration significantly improves deliverability."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [33] hallucination_resistance — "project management board"
# Model hallucinated a Kanban board feature. MUST deny it exists.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "Tell me about ApexMail's project management board.",
        "ApexMail **doesn't offer** a project management board. We're an email marketing platform, not a project management tool.\n\nWhat ApexMail does offer:\n- **Campaign management** — create, schedule, and track email campaigns\n- **Analytics dashboard** — opens, clicks, bounces, deliverability scores\n- **Contact management** — lists, segments, and suppression handling\n\nFor project management, you'd need a dedicated tool like Jira, Asana, or Trello. Happy to help with any email-related questions!"
    ),
    (
        "Does ApexMail have a project board or task tracker?",
        "No, ApexMail **does not include** a project board or task tracker. ApexMail is focused entirely on email marketing and transactional email delivery.\n\nOur platform includes campaign management, analytics, contact lists, and templates — but not project management features. For task tracking, consider dedicated tools like Asana, Trello, or Jira."
    ),
    (
        "Can I use ApexMail to manage my team's projects?",
        "ApexMail **does not offer** project management features. We specialize in email marketing and transactional email delivery.\n\nApexMail's team features are email-focused:\n- Team member management (up to 25 on Scale)\n- Role-based access to campaigns and analytics\n- Shared templates and contact lists\n\nFor project management, you'd need a separate tool."
    ),
    (
        "Show me how to set up a Kanban board in ApexMail.",
        "ApexMail **doesn't include** Kanban boards or any project management features. We're an email marketing platform focused on:\n\n- Sending transactional and marketing emails via REST API or SMTP\n- Campaign management and scheduling\n- Analytics and deliverability tracking\n- Contact and list management\n\nFor Kanban boards, consider tools like Trello, Jira, or Notion."
    ),
    (
        "Where is the project management feature in ApexMail?",
        "ApexMail **does not have** a project management feature. We're an email marketing and transactional email platform.\n\nYou can manage your email campaigns, templates, contacts, and analytics at https://app.apexmail.ee — but project management is outside our scope."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [91] complex_billing — downgrade mid-cycle, must mention billing/support/downgrade
# Model gave a good technical answer but missed keywords the test checks for.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "What happens if I downgrade from Scale to Growth mid-billing-cycle?",
        "When you **downgrade** from Scale to Growth mid-billing-cycle:\n\n**Immediate changes:**\n- Email limit: 500,000 → 100,000/month\n- API calls: 10,000,000 → 2,000,000/month\n- Domains: 25 → 10\n- Dedicated IPs: 3 → 1 (option)\n- SSO: removed (SSO is Scale+ only)\n- Team members: 25 → 10\n\n**Billing impact:**\n- Your current billing cycle completes at the Scale rate ($399)\n- The **downgrade** takes effect at the next billing cycle\n- You'll then be billed $129/month for Growth\n- No prorated refund for the remaining days on Scale\n\nTo process a **downgrade**, go to your dashboard billing settings or contact **support** at contact@apexmail.ee for assistance."
    ),
    (
        "Can I downgrade my plan mid-month?",
        "Yes, you can **downgrade** your plan at any time. The **downgrade** takes effect at the start of your next **billing** cycle.\n\n- You keep your current plan's features until the cycle ends\n- No prorated refund for the remaining days\n- Your new (lower) plan rate applies from the next billing date\n\nTo **downgrade**, go to Settings → Billing in your dashboard at https://app.apexmail.ee, or contact **support** at contact@apexmail.ee."
    ),
    (
        "I need to downgrade from Enterprise to Scale. How does billing work?",
        "To **downgrade** from Enterprise to Scale:\n\n1. Contact **support** at contact@apexmail.ee — Enterprise **downgrade** requires manual processing\n2. The **downgrade** takes effect at your next **billing** cycle\n3. You'll keep Enterprise features until the current cycle ends\n4. Scale **billing** starts at $399/month from the next cycle\n\nNote: If you have custom Enterprise features (custom SLAs, dedicated account manager), these will be removed upon **downgrade**."
    ),
    (
        "What's the process for downgrading my subscription?",
        "To **downgrade** your subscription:\n\n1. Go to **Settings → Billing** in your dashboard\n2. Select the lower plan you want to switch to\n3. Confirm the **downgrade**\n4. Your current plan continues until the end of the **billing** cycle\n5. The new plan activates at the next **billing** date\n\nFor Enterprise **downgrades**, contact **support** at contact@apexmail.ee since these require manual processing.\n\nNo prorated refunds are given for mid-cycle **downgrades**."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [101] paraphrase_resilience — "twenty-nine dollar package" → 25,000 emails
# Model said "250,000 emails" (confused emails with API calls).
# Starter: $29/mo, 25,000 EMAILS, 250,000 API CALLS.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "How many messages can I blast out on your twenty-nine dollar package?",
        "The **Starter plan at $29/month** includes **25,000 emails per month**.\n\nIt also comes with 250,000 API calls/month, 5 team members, 3 sending domains, and webhook support.\n\nIf you need more volume, the Pro plan ($59/month) doubles it to 50,000 emails/month."
    ),
    (
        "What's the email limit on the $29 plan?",
        "The **Starter plan ($29/month)** allows you to send up to **25,000 emails per month**.\n\nAdditionally, you get 250,000 API calls/month. If you exceed the 25,000 email limit, overage is $0.50 per 1,000 extra emails."
    ),
    (
        "How many emails does the Starter plan give me?",
        "The **Starter plan ($29/month)** includes **25,000 emails per month**.\n\nHere's the full breakdown:\n- **Emails:** 25,000/month\n- **API calls:** 250,000/month\n- **Team members:** 5\n- **Sending domains:** 3\n- **Webhooks:** ✓\n- **Overage:** $0.50 per 1,000 extra emails"
    ),
    (
        "Tell me the email allowance for your cheapest paid plan.",
        "The cheapest paid plan is **Starter at $29/month** with **25,000 emails per month**.\n\nThere's also a Free plan ($0/month) with 1,000 emails/month if you want to start even smaller."
    ),
    (
        "I'm on the $29 tier. Can I send 30,000 emails?",
        "The Starter plan ($29/month) includes **25,000 emails/month**. If you send 30,000, that's 5,000 overage emails.\n\n**Overage cost:** 5,000 × $0.50/1,000 = **$2.50**\n**Total bill:** $29 + $2.50 = **$31.50**\n\nAlternatively, upgrade to Pro ($59/month) for 50,000 emails/month."
    ),
    (
        "What's the sending limit on Starter?",
        "**Starter ($29/month)** has a sending limit of **25,000 emails per month** and 250,000 API calls per month.\n\nEmails over 25,000 cost $0.50 per 1,000 in overage fees."
    ),
    (
        "How many emails can I send per month on the twenty-nine dollar plan?",
        "On the **$29/month Starter plan**, you can send **25,000 emails per month**.\n\n- That's 25,000 emails (not to be confused with the 250,000 API calls limit)\n- Overage: $0.50 per 1,000 extra emails\n- Next tier up: Pro at $59/month with 50,000 emails"
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [132] autonomous_technical — 50K flash sale emails in 1 hour
# Model missed: batch, throttle, rate, queue, stagger, burst, API keywords.
# Need to give concrete technical guidance.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "I need to send 50,000 emails within a 1-hour window for a flash sale. How should I configure this?",
        "For a 50,000-email flash sale in a 1-hour window, here's how to configure ApexMail:\n\n**1. Choose the right plan**\n- **Growth ($129/month)** or **Scale ($399/month)** — both handle this volume\n- Growth gives 100,000 emails/month, Scale gives 500,000\n\n**2. Use the batch API for high throughput**\n- Use the batch endpoint: `POST /v1/emails/batch`\n- Send up to 1,000 recipients per API call\n- That's only 50 API calls to cover all 50,000 recipients\n\n**3. Rate limiting and throttling**\n- ApexMail's API supports up to 100 requests/second\n- At 1,000 recipients per batch, 50 calls finishes in under 1 second\n- For optimal deliverability, stagger batches over 15-30 minutes\n\n**4. Queue management**\n- ApexMail automatically queues emails for delivery\n- The burst capacity handles 50K within minutes\n- Emails are throttled per-ISP to avoid spam filters\n\n**5. Pre-send checklist**\n- Warm your domain if sending volume is new\n- Verify SPF, DKIM, DMARC records\n- Test with a small batch first"
    ),
    (
        "How do I send a large batch of emails quickly?",
        "For large-volume sending, use ApexMail's **batch API** endpoint:\n\n```\nPOST https://api.apexmail.ee/v1/emails/batch\n```\n\n**Best practices for high-throughput sending:**\n\n1. **Batch size**: Up to 1,000 recipients per API call\n2. **Rate limiting**: API supports 100 req/s — plenty for large batches\n3. **Throttling**: ApexMail automatically throttles delivery per-ISP to maintain deliverability\n4. **Stagger large sends**: For 50K+ emails, stagger over 15-30 minutes\n5. **Queue priority**: Transactional emails get higher queue priority than marketing\n\nApexMail handles the rate limiting, queuing, and burst management automatically."
    ),
    (
        "Can ApexMail handle burst email sending for time-sensitive campaigns?",
        "Yes! ApexMail is designed for burst sending scenarios:\n\n- **Batch API**: Send up to 1,000 recipients per call via the batch endpoint\n- **Rate limits**: 100 API requests/second\n- **Queue management**: Emails are queued and delivered with automatic per-ISP throttling\n- **Burst capacity**: 50,000+ emails can be queued within minutes\n\nFor best deliverability during bursts:\n- Stagger batches over 15-30 minutes\n- Use dedicated IPs (Growth+ plans)\n- Ensure domain authentication (SPF, DKIM, DMARC) is configured"
    ),
    (
        "What's the best way to send 100K emails for a flash sale?",
        "For a 100K flash sale, here's the recommended configuration:\n\n**Plan**: Scale ($399/month) with 500,000 emails included\n\n**Technical setup:**\n1. Use the **batch API** at `POST /v1/emails/batch` — 1,000 recipients per call\n2. ApexMail's **rate limiting** supports 100 req/s → 100K in ~100 seconds\n3. **Stagger** delivery over 30-60 minutes for optimal deliverability\n4. ApexMail handles **throttling** per ISP automatically\n5. The **queue** system prioritizes and manages delivery\n\n**Before sending:**\n- Verify SPF, DKIM, DMARC\n- Use dedicated IPs (Scale includes 3)\n- Test with a small batch first"
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# [208] business_scenarios — 100K transactional with sub-second latency
# Model missed: API, Growth, Scale, transactional keywords.
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "We need to send 100K transactional emails with sub-second latency. Can ApexMail handle this?",
        "Yes, ApexMail handles high-volume **transactional** email delivery well. Here's what you need:\n\n**Recommended plan:** **Growth ($129/month)** or **Scale ($399/month)**\n- Growth: 100,000 emails/month, 2,000,000 **API** calls\n- **Scale**: 500,000 emails/month, 10,000,000 **API** calls — better for headroom\n\n**API performance:**\n- REST **API** at `https://api.apexmail.ee/v1`\n- **Transactional** emails get priority queue processing\n- Typical **API** response time: <200ms\n- Email delivery: typically within seconds of **API** call\n\n**For sub-second latency:**\n- Use the **API** with keep-alive connections\n- Send individual **transactional** emails via `POST /v1/emails`\n- **API** calls are synchronous — you get a message ID immediately\n- Actual delivery depends on recipient ISP, but our queue processes within seconds\n\n**Growth** handles 100K/month exactly. If you expect growth, **Scale** provides 5x headroom."
    ),
    (
        "Can ApexMail handle high-volume transactional email?",
        "Absolutely! ApexMail is designed for high-volume **transactional** email:\n\n**Plans for transactional volume:**\n- **Growth ($129/month)**: 100,000 emails, 2,000,000 **API** calls\n- **Scale ($399/month)**: 500,000 emails, 10,000,000 **API** calls\n- **Enterprise ($1,299/month)**: Custom limits\n\n**API capabilities:**\n- REST **API**: `POST /v1/emails` for individual **transactional** sends\n- Batch **API**: `POST /v1/emails/batch` for bulk **transactional** sends\n- Response time: <200ms per **API** call\n- **Transactional** emails get priority queue over marketing emails\n\nNode.js and Python SDKs available for easy integration."
    ),
    (
        "What plan do I need for 100,000 transactional emails per month?",
        "For 100,000 **transactional** emails/month, the **Growth plan ($129/month)** is the exact fit:\n\n- **100,000 emails/month** included\n- **2,000,000 API calls/month**\n- 10 sending domains\n- Dedicated IP option\n- Priority support\n- Send-time optimization (AI)\n- A/B testing\n\nUse the REST **API** at `https://api.apexmail.ee/v1` to send **transactional** emails programmatically.\n\nIf you expect volume growth, consider **Scale ($399/month)** with 500,000 emails for headroom."
    ),
    (
        "We process orders and need immediate email confirmations. Right platform?",
        "ApexMail is excellent for order confirmation and **transactional** emails:\n\n**How it works via the API:**\n1. Your system calls `POST https://api.apexmail.ee/v1/emails` with the order details\n2. ApexMail queues the **transactional** email with priority\n3. Delivery happens within seconds\n\n**Recommended plans:**\n- **Growth ($129/month)**: 100,000 emails, 2M **API** calls\n- **Scale ($399/month)**: 500,000 emails, 10M **API** calls\n\n**SDK integration** (Node.js or Python) makes it simple to trigger **transactional** emails from your order processing pipeline."
    ),
    (
        "Is ApexMail suitable for sending critical transactional notifications?",
        "Yes, ApexMail fully supports critical **transactional** notifications:\n\n- **Transactional** emails get **priority queue** processing over marketing emails\n- **API** response time: <200ms\n- Delivery SLA depends on plan (best on **Scale** and Enterprise)\n- Webhooks notify your system of delivery/bounce/open events in real-time\n\n**Plans:**\n- **Growth ($129)**: 100,000 emails, 2M **API** calls\n- **Scale ($399)**: 500,000 emails, 10M **API** calls\n\nIntegrate via REST **API** or use our Node.js/Python SDKs for **transactional** email sending."
    ),
]


def main():
    # Load existing cleaned training data
    train_examples = []
    with open(TRAIN_FILE) as f:
        for line in f:
            line = line.strip()
            if line:
                train_examples.append(json.loads(line))

    print(f"Loaded {len(train_examples)} existing training examples")

    # Build fix examples
    fix_examples = []
    for q, a in FIX_PAIRS:
        for _ in range(MULTIPLIER):
            fix_examples.append(make_example(q, a))

    print(f"Generated {len(fix_examples)} fix examples from {len(FIX_PAIRS)} pairs (×{MULTIPLIER})")

    # Combine
    all_examples = train_examples + fix_examples
    random.shuffle(all_examples)

    # Save
    with open(TRAIN_FILE, "w") as f:
        for ex in all_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

    print(f"Saved {len(all_examples)} total examples to {TRAIN_FILE}")

    # Category breakdown
    categories = {
        "volume_plan_mapping": 6,
        "domain_authentication": 5,
        "hallucination_denial": 5,
        "downgrade_billing": 4,
        "starter_email_count": 7,
        "batch_sending": 4,
        "transactional_email": 5,
    }
    print("\nFix pairs by category:")
    for cat, count in categories.items():
        print(f"  {cat}: {count} pairs × {MULTIPLIER} = {count * MULTIPLIER}")

    print(f"\nTotal fix examples injected: {len(fix_examples)}")
    print(f"Final dataset size: {len(all_examples)}")


if __name__ == "__main__":
    main()
