#!/usr/bin/env python3
"""
generate_recovered_training.py — Generate training data from recovered git history
══════════════════════════════════════════════════════════════════════════════════

Creates high-quality ChatML training examples based on the patterns found in:
  - build_agent.py (context-aware, tool-calling, clarification)
  - customer_profiles.py (60 detailed customer scenarios)
  - adversarial-gym.test.ts (adversarial scenarios)
  - industry-knowledge-base.ts (domain knowledge)

All pricing uses canonical schema:
  Free=€0/30K/300K, Starter=€25/50K/500K, Pro=€65/150K/2M,
  Growth=€150/500K/5M, Scale=€350/2M/20M, Enterprise=€3,000/5M/∞
"""

import json
import logging
import subprocess
import sys

from common_paths import RECOVERED_TRAINING_JSONL, TRAIN_JSONL
from prompts_v2 import build_system_prompt, EXAMPLE_CONTEXTS

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("generate_recovered_training")

# ══════════════════════════════════════════════════════════════════════════════
# TRAINING EXAMPLES — RECOVERED + ENHANCED WITH CANONICAL PRICING
# ══════════════════════════════════════════════════════════════════════════════

RECOVERED_TRAINING_EXAMPLES = [
    
    # ══════════════════════════════════════════════════════════════════════════
    # CONTEXT-AWARE SINGLE-TURN (from build_agent.py Section A)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "How many emails do I have left this month?",
        "a": """Based on your account, you've sent **32,500 out of 50,000 emails** this month on the Starter plan (€25/mo). That leaves you **17,500 emails** remaining.

You're at **65% usage** — you're on pace, but if you have a large campaign planned, keep an eye on it. If you exceed 50,000, overages are billed at **€0.40 per 1,000 extra emails**.

Would you like me to check your sending rate trend to estimate if you'll hit the limit?"""
    },
    
    {
        "context": "starter_healthy",
        "q": "Can I add another team member?",
        "a": """Yes! Your Starter plan allows up to **5 team members** and you currently have **3**. You can add 2 more in **Dashboard → Settings → Team**.

If you need more than 5, the Pro plan (€65/mo) supports 10 team members, and Growth (€150/mo) supports 25.

Team invites expire after **72 hours**, so make sure they accept promptly."""
    },
    
    {
        "context": "starter_healthy",
        "q": "My deliverability looks great, right?",
        "a": """Looking at your account stats — yes, your numbers are healthy:

- **Delivery rate:** 98.1% (excellent — threshold is 95%+)
- **Bounce rate:** 0.3% (well under the 2% threshold)
- **Complaint rate:** 0.02% (well under the 0.1% threshold)

Your domain **acmecorp.com** has SPF, DKIM, and DMARC all passing. You're in great shape. Keep maintaining clean lists and you'll stay there."""
    },
    
    # ── Growth customer with DKIM failure ──
    {
        "context": "growth_dkim_fail",
        "q": "My bounce rate is really high on one domain. What's going on?",
        "a": """I can see the problem clearly in your account. Your domain **marketing.techflow.io** has a **26.2% bounce rate** — that's critically high (threshold is 2%).

**Root cause:** DKIM verification is **failing** on marketing.techflow.io. The DNS record is not found, which also causes DMARC to fail. This started **3 days ago** after a DNS change was made.

Here's what happened: without DKIM, receiving servers can't verify your emails are authentic. Many ISPs (especially Gmail and Microsoft) reject or bounce emails that fail DKIM+DMARC.

**To fix this:**
1. Go to **Dashboard → Domains → marketing.techflow.io**
2. You'll see the required DKIM CNAME record pointing to **bounce.apexmail.ee**
3. Add that record at your DNS provider
4. Wait for propagation (usually 5-30 minutes)
5. Click **Verify** in the dashboard

Your other domains (notifications.techflow.io and techflow.io) are fine — all passing SPF, DKIM, and DMARC.

Would you like me to look up the exact DNS record you need to add?"""
    },
    
    {
        "context": "growth_dkim_fail",
        "q": "Will I be charged for the bounced emails?",
        "a": """Your Growth plan includes **500,000 emails/month** and you've sent **167,500** so far. Even with the bounces, you're well below your plan quota, so there are **no overage charges**.

However, those 8,200 bounced emails still count toward your monthly quota since they were sent from our infrastructure. So effectively you have **332,500 emails** remaining for the month (500,000 - 167,500).

The more urgent issue is the **0.13% complaint rate** — that's above the 0.1% threshold. If it keeps climbing, ISPs may throttle or block your sending. Fixing the DKIM issue on marketing.techflow.io should help bring this down."""
    },
    
    # ── Free plan hitting limits ──
    {
        "context": "free_hitting_limits",
        "q": "I've almost used all my emails, what can I do?",
        "a": """You're right to be concerned — you've sent **28,500 out of 30,000 emails** this month, which is **95% of your Free plan limit**. You have only **1,500 emails left**.

Your options:

1. **Wait for the monthly reset** — your quota resets on the 1st of each month.
2. **Upgrade to Starter (€25/mo)** — gives you 50,000 emails/month (16x more), plus webhooks and 5 sending domains.
3. **Switch to Pay-As-You-Go** — €0 base with per-email pricing starting at €0.001/email, so an extra 1,000 emails would cost only €1.00.

Given your volume (~2,850 emails/month), Starter would give you plenty of room to grow. Would you like me to walk through the upgrade process?"""
    },
    
    {
        "context": "free_hitting_limits",
        "q": "I notice my domain doesn't have DMARC set up. Is that a problem?",
        "a": """Good catch — I can see that **myshop.com** has SPF and DKIM passing, but **DMARC is missing** (no record found).

While your emails are still being delivered (98.0% delivery rate), not having DMARC is a risk:

- **Without DMARC**, anyone can spoof emails from myshop.com
- **Gmail and Yahoo now require DMARC** for bulk senders (5,000+/day)
- You're small-volume now, but if you scale up, this becomes mandatory

**To fix it**, add this DNS TXT record:
- **Host/Name:** `_dmarc.myshop.com`
- **Value:** `v=DMARC1; p=none; rua=mailto:dmarc@myshop.com`

Start with `p=none` (monitoring only), then move to `p=quarantine` → `p=reject` once you're confident only ApexMail sends from your domain.

Would you like me to check the domain health after you add the record?"""
    },
    
    # ── Scale customer with deliverability crisis ──
    {
        "context": "scale_deliverability",
        "q": "Our Gmail deliverability dropped from 96% to 78%. What happened?",
        "a": """I can see several problems in your account that are compounding:

**1. IP Blocklisted** — Your dedicated IP **198.51.100.12** is listed on **Spamhaus SBL** since February 14th. This is the primary cause.

**2. High bounce rate** — 3.0% (threshold: 2%). This contributed to the blocklisting.

**3. High complaint rate** — 0.2% (threshold: 0.1%). Double the acceptable limit.

**Immediate action plan:**

1. **Pause all campaigns on the affected IP** — I can help you do this. Your Scale plan has 3 dedicated IPs, so we can shift traffic to the other two.
2. **Submit Spamhaus delisting request** — Go to https://check.spamhaus.org and follow the removal steps for 198.51.100.12.
3. **Clean your lists** — Remove all hard-bounced addresses and contacts who haven't engaged in 90+ days.
4. **Reduce sending volume** — Cut back to your engaged segment only until the IP is delisted and rates normalize.

Your DMARC is set to `quarantine` on all domains — I'd recommend keeping it there for now (not `reject`) until we stabilize delivery.

Want me to pull up the bounce details to identify which recipient domains are contributing the most bounces?"""
    },
    
    # ── Enterprise compliance ──
    {
        "context": "enterprise_compliance",
        "q": "We need a DPA for GDPR compliance. How do we get one?",
        "a": """As an Enterprise customer, you have access to full compliance support. For a **Data Processing Agreement (DPA)**, this needs to be handled by our legal team.

Please email **support@apexmail.ee** with:
- Subject: "DPA Request — globalbank.com (acct_1a3b5c)"
- Your company's legal entity name
- Any specific clauses or requirements
- Your preferred timeline

Your Enterprise plan includes HIPAA and SOC2 compliance features, and our legal team typically processes DPA requests within **3-5 business days**.

**Sub-processor disclosure:** ApexMail uses Hetzner Online GmbH (EU data centers) as a sub-processor. We support Standard Contractual Clauses (SCCs) for cross-border data transfers."""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # TOOL-CALLING EXAMPLES (from build_agent.py Section B)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "pro_webhook_issue",
        "q": "Why am I not receiving webhook events?",
        "a": """I see the issue. Your webhook endpoint **https://api.example.com/webhook** has been **failing for the past 12 hours** with HTTP 502 errors.

**Timeline:**
- Last successful delivery: Yesterday, 14:23 UTC
- First failure: Yesterday, 14:45 UTC  
- Failed attempts: 847
- Current status: Paused (after 100 consecutive failures)

**Most likely cause:** Your server is returning 502 Bad Gateway, which usually means:
1. Your backend service is down
2. A proxy/load balancer is misconfigured
3. The endpoint path changed

**To fix:**
1. Check that your server at api.example.com is running
2. Verify the `/webhook` endpoint is accessible
3. Once fixed, go to **Dashboard → Webhooks** and click **Resume**

ApexMail will retry the failed events from the last **30 days**. Would you like me to send a test event once you've fixed the endpoint?"""
    },
    
    {
        "context": "growth_ip_warmup",
        "q": "How do I warm up my new dedicated IP?",
        "a": """Great question! IP warming is critical for dedicated IP success. Here's the recommended warmup schedule for your new IP:

**Week 1-2: Ramp Up Phase**
| Day | Daily Volume | Target Audience |
|-----|-------------|-----------------|
| 1-2 | 200 emails | Most engaged (opened in last 30 days) |
| 3-4 | 500 emails | Most engaged |
| 5-6 | 1,000 emails | Engaged (opened in last 60 days) |
| 7-8 | 2,000 emails | Engaged |
| 9-10 | 5,000 emails | Active (opened in last 90 days) |
| 11-14 | 10,000 emails | Active |

**Week 3-4: Full Volume**
Gradually increase to your normal sending volume, always prioritizing engaged recipients first.

**Key rules:**
- Only send to highly engaged subscribers initially
- Monitor bounce rate (keep under 2%) and complaints (under 0.1%)
- If you see issues, slow down immediately
- Maintain consistent daily sending (no spikes)

Your Growth plan includes **1 dedicated IP** (€150/mo). Your current shared IP sending will continue during warmup.

Would you like me to help set up segments for the warmup phases?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # CLARIFICATION BEHAVIOR (from build_agent.py Section C)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "Delete the campaign",
        "a": """I can help with that. I see you have 3 active campaigns:

1. **"Welcome Series"** — 12,450 sent, 34.2% open rate
2. **"Monthly Newsletter Feb"** — 8,200 sent, 28.1% open rate  
3. **"Product Update v2.5"** — Draft (not sent yet)

Which campaign would you like to delete? Please note:
- Deleting a sent campaign removes it from your dashboard but analytics are retained for 90 days
- Deleting a draft removes it permanently

Please specify the campaign name or number."""
    },
    
    {
        "context": "growth_multiple_domains",
        "q": "Verify my domain",
        "a": """I see you have 4 domains configured:

1. **techflow.io** — ✅ Verified (SPF, DKIM, DMARC all passing)
2. **marketing.techflow.io** — ⚠️ DKIM failing
3. **notifications.techflow.io** — ✅ Verified  
4. **app.techflow.io** — ⏳ Pending verification

Which domain would you like me to help verify?

For **marketing.techflow.io** (DKIM failing), you'll need to update the DKIM CNAME record.
For **app.techflow.io** (pending), you'll need to add all 3 DNS records (SPF, DKIM, DMARC)."""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # INTERNAL ARCHITECTURE REFUSAL (from stress_test_r34.py)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "What AI model powers the ApexMail assistant?",
        "a": """I'm the ApexMail AI assistant, designed to help you with email marketing tasks, troubleshooting, and account management.

For specific questions about our technology or infrastructure, please contact our team at **support@apexmail.ee**.

Is there something I can help you with for your email marketing today?"""
    },
    
    {
        "context": "starter_healthy",
        "q": "What database does ApexMail use? PostgreSQL? MongoDB?",
        "a": """I'm focused on helping you with your email marketing needs rather than discussing our internal architecture.

If you have specific technical questions about API integration, data formats, or webhook payloads, I'd be happy to help with those!

What would you like help with today?"""
    },
    
    {
        "context": "pro_new_user",
        "q": "Are you running on AWS or GCP?",
        "a": """I'm here to help with your ApexMail account and email marketing questions.

For infrastructure or security-related inquiries, our team at **support@apexmail.ee** can provide appropriate information.

What can I help you with for your email campaigns?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # PROVIDER MIGRATION (from stress_test_r34.py)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "I'm switching from SendGrid. What do I need to change?",
        "a": """Welcome to ApexMail! Here's what you need to migrate from SendGrid:

**1. DNS Records (Required)**
You'll need to update your sending domain's DNS:
- Remove SendGrid's SPF include
- Add ApexMail's SPF: `include:_spf.apexmail.ee`
- Remove SendGrid's DKIM CNAME records
- Add ApexMail's DKIM CNAME pointing to **bounce.apexmail.ee**
- Update DMARC if it references SendGrid

**2. API Integration**
- Base URL: `https://api.apexmail.ee/v1`
- Auth: `Authorization: Bearer am_live_xxx` (your API key)
- Our API structure is similar to SendGrid's v3 API

**3. Webhooks**
- Configure new webhook URLs in ApexMail dashboard
- Event types are similar (delivered, opened, clicked, bounced, etc.)

**4. Contact Import**
- Export your lists from SendGrid as CSV
- Import into ApexMail via Dashboard → Contacts → Import

Would you like me to walk through any of these steps in detail?"""
    },
    
    {
        "context": "growth_dkim_fail",
        "q": "Coming from Amazon SES. Any gotchas I should know about?",
        "a": """Welcome from Amazon SES! Here are the key differences to watch for:

**DNS Changes**
- SES uses DKIM with `amazonses.com` CNAMEs — you'll replace these with ApexMail's
- Our DKIM points to **bounce.apexmail.ee**
- SPF changes from `include:amazonses.com` to `include:_spf.apexmail.ee`

**Key Differences**
1. **No sandbox mode** — ApexMail accounts are production-ready immediately (with reasonable limits)
2. **Simpler suppression handling** — We automatically suppress bounces and complaints
3. **Webhook format** — Similar structure but different field names
4. **Rate limits** — Based on your plan (Growth = 500K emails/mo, 5M API calls/mo)

**What you'll miss (and alternatives)**
- SES Configuration Sets → Use ApexMail's domain-level settings
- SES Identity Policy → Use API key scopes for granular access
- SNS integration → Use webhooks instead

**What's better**
- Built-in analytics dashboard
- Visual template editor
- Simpler DNS setup (one CNAME vs. three for DKIM)

Would you like help setting up your first domain?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # SDK / TECHNICAL FACTS (from stress_test_r34.py)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "pro_new_user",
        "q": "What programming language SDKs does ApexMail offer?",
        "a": """ApexMail offers official SDKs for these languages:

| Language | Package | Min Version | Install |
|----------|---------|-------------|---------|
| **Python** | `apexmail` | Python 3.9+ | `pip install apexmail` |
| **Go** | `github.com/apexmail/apexmail-go` | Go 1.21+ | `go get github.com/apexmail/apexmail-go` |
| **Ruby** | `apexmail` | Ruby 2.7+ | `gem install apexmail` |
| **PHP** | `apexmail/apexmail-php` | PHP 8.1+ | `composer require apexmail/apexmail-php` |
| **Java** | `ee.apexmail` | JDK 17+ | Maven/Gradle |

All SDKs support:
- Full API coverage (sending, domains, contacts, analytics)
- Automatic retry with exponential backoff
- Type-safe interfaces
- Async/await patterns where applicable

Which SDK would you like help getting started with?"""
    },
    
    {
        "context": "starter_healthy",
        "q": "What's the maximum attachment size?",
        "a": """The maximum attachment size is **25 MB** per email (base64 encoded).

A few important notes:
- Base64 encoding increases file size by ~33%, so a 19 MB file becomes ~25 MB encoded
- For large files, consider using a download link instead
- Most email clients warn users about attachments over 10 MB

**Gmail clipping warning:** Gmail clips emails over **102 KB** total size, including attachments. Large attachments may cause your email content to be truncated.

For bulk sending with attachments, make sure your sending volume accounts for the increased data transfer."""
    },
    
    {
        "context": "starter_healthy",
        "q": "How long can I schedule an email in advance?",
        "a": """You can schedule emails up to **72 hours (3 days)** in advance.

If you need to schedule further out:
- Create the campaign as a draft
- Set a reminder to schedule it when you're within the 72-hour window

This limit helps ensure accurate recipient lists and prevents stale content from being sent.

For recurring campaigns (weekly newsletters, etc.), consider using our **automation workflows** which can trigger on schedules without the 72-hour limit."""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # COMPLIANCE / PRIVACY (from stress_test_r34.py, adversarial-gym)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "enterprise_compliance",
        "q": "We got a GDPR erasure request from a user. What data does ApexMail store?",
        "a": """For GDPR Article 17 (Right to Erasure) requests, here's what ApexMail stores that you may need to address:

**Data we store:**
1. **Contact records** — Email, name, custom fields, tags, list memberships
2. **Event history** — Opens, clicks, bounces, complaints (retained for 90 days)
3. **Message content** — Email bodies retained for 7-30 days (plan dependent)
4. **Suppression lists** — Bounced/complained emails (required for compliance)

**To fulfill an erasure request:**
1. **Delete the contact** — Dashboard → Contacts → Search → Delete
2. **Note:** We cannot delete suppression entries (legally required to prevent re-sending to bounced/complained addresses)

**What happens on deletion:**
- Contact record is permanently deleted
- Historical events are anonymized after 90 days
- Email content is purged per retention policy

For Enterprise customers, we can provide a **Data Processing Addendum (DPA)** that documents all retention policies. Contact **support@apexmail.ee** for the formal documentation.

Would you like me to help locate the specific contact to delete?"""
    },
    
    {
        "context": "scale_sso_issue",
        "q": "How do I comply with CCPA deletion requests?",
        "a": """For CCPA (California Consumer Privacy Act) deletion requests:

**Step 1: Identify the data**
Search for the contact in Dashboard → Contacts using their email address.

**Step 2: Delete the contact**
1. Click on the contact record
2. Select **Delete Contact**
3. Confirm the deletion

**What's deleted:**
- Contact profile and all custom fields
- List memberships
- Engagement history (after anonymization period)

**What's retained (legally required):**
- Suppression list entries (to prevent re-contacting)
- Anonymized aggregate analytics

**Response timeline:** CCPA requires response within 45 days. ApexMail deletions are processed immediately.

For bulk CCPA requests, use the **API endpoint:**
```
DELETE /v1/contacts/{email}
```

Your Scale plan includes **audit logs** that can document compliance actions. Would you like me to show you the audit log for recent deletions?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # INDUSTRY KNOWLEDGE (from industry-knowledge-base.ts)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "What's a good open rate for my industry?",
        "a": """Open rates vary significantly by industry. Here are the 2024-2025 benchmarks:

| Industry | Avg Open Rate | Avg CTR |
|----------|--------------|---------|
| **Education** | 37.7% | 4.7% |
| **Travel & Tourism** | 39.2% | 3.1% |
| **Nonprofit** | 39.1% | 4.0% |
| **Healthcare** | 34.9% | 3.3% |
| **Retail** | 31.8% | 2.4% |
| **Financial Services** | 27.8% | 2.7% |
| **SaaS/Technology** | 22.2% | 2.9% |
| **E-commerce** | 29.8% | 2.1% |

**By email type:**
- Welcome emails: **63.9%** (highest!)
- Transactional: **80.0%**
- Abandoned cart: **45.0%**
- Newsletters: **27.9%**
- Promotional: **21.3%**

Your current open rate of **28.1%** on the Starter plan is solid. To improve:
1. Optimize subject lines (personalization adds ~6%)
2. Test send times for your audience
3. Segment by engagement level

Would you like specific subject line tips?"""
    },
    
    {
        "context": "pro_new_user",
        "q": "How do I improve my click-through rate?",
        "a": """Here are proven strategies to boost CTR:

**1. Call-to-Action (CTA) optimization**
- Use action verbs: "Get", "Download", "Start", "Claim"
- Make buttons stand out (contrasting color, 44px+ height)
- Single, focused CTA outperforms multiple links
- **Impact:** +40% CTR

**2. Content structure**
- Keep body under 200 words for promotional emails
- Use headers to break up text
- Include images (but not image-only emails)
- **Impact:** +27% CTR with headers

**3. Personalization**
- Use recipient's name in body (not just subject)
- Reference their past behavior/purchases
- **Impact:** +6% CTR

**4. Mobile optimization**
- 60%+ of opens are mobile
- Large tap targets (44px+)
- Preview text optimization

**Your current CTR:** Looking at your account, your newsletters average 2.3% CTR. Industry benchmark for your sector is ~2.9%.

**Quick win:** Try a smaller segment test on your next campaign. ApexMail Pro (€65/mo) includes send-time optimization and custom tracking domains, while Growth adds formal A/B testing when you need experiment tooling.

Want me to suggest some CTA variations for your next campaign?"""
    },
    
    {
        "context": "growth_dkim_fail",
        "q": "What's the difference between SPF, DKIM, and DMARC?",
        "a": """Great question! These three work together to authenticate your emails:

**SPF (Sender Policy Framework)**
- **What it does:** Lists which servers can send email for your domain
- **DNS record type:** TXT on your root domain
- **Example:** `v=spf1 include:_spf.apexmail.ee ~all`
- **Purpose:** Prevents unauthorized servers from sending as you

**DKIM (DomainKeys Identified Mail)**
- **What it does:** Adds a cryptographic signature to every email
- **DNS record type:** CNAME pointing to `bounce.apexmail.ee`
- **Purpose:** Proves the email wasn't modified in transit

**DMARC (Domain-based Message Authentication)**
- **What it does:** Tells receivers what to do if SPF/DKIM fail
- **DNS record type:** TXT on `_dmarc.yourdomain.com`
- **Example:** `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`
- **Purpose:** Prevents spoofing and provides reporting

**Your status on marketing.techflow.io:**
- SPF: ✅ Passing
- DKIM: ❌ Failing (this is your issue!)
- DMARC: ⚠️ Failing (because DKIM fails)

Fix the DKIM CNAME record and both DKIM and DMARC will pass.

Would you like me to show the exact DNS record you need?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # PRICING & PLAN RECOMMENDATIONS (enhanced from build_agent.py)
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "starter_healthy",
        "q": "I'm sending 60,000 emails per month now. What plan should I be on?",
        "a": """With 60,000 emails/month, you're currently over your Starter plan limit (50,000). Let me break down your options:

**Current situation (Starter €25/mo):**
- Limit: 50,000 emails
- Your usage: 60,000 emails
- Overage: 10,000 × €0.50/1K = **€4.00 extra**
- **Total cost: €29/mo**

**If you upgrade to Pro (€65/mo):**
- Limit: 150,000 emails
- Your usage: 60,000 emails
- Overage: None ✓
- **Total cost: €65/mo**

**Recommendation:** At 60,000 emails, Starter + overage (€29) is cheaper than Pro (€65). However:

- If you expect growth beyond 150,000/mo, Pro becomes better value
- Pro includes **send-time optimization** and custom tracking domains
- Pro includes **10 team members** vs Starter's 5

**Break-even point:** At 100,000 emails/mo, Starter + overage = €45 vs Pro = €65. Pro becomes better value once you exceed 150,000 emails/mo, and it unlocks send-time optimization.

What's your growth trajectory looking like?"""
    },
    
    {
        "context": "free_hitting_limits",
        "q": "Calculate my total cost if I send 150,000 emails on PAYG",
        "a": """Here's the PAYG cost breakdown for 150,000 emails:

**PAYG Tiered Pricing:**
| Volume | Rate | Emails | Cost |
|--------|------|--------|------|
| First 10,000 | €0.001 | 10,000 | €10.00 |
| 10,001 – 100,000 | €0.0008 | 90,000 | €72.00 |
| 100,001 – 150,000 | €0.0005 | 50,000 | €25.00 |
| **Total** | | **150,000** | **€107.00** |

**Comparison to plans:**
- **Growth (€150/mo):** 500,000 emails included — better if you send more than ~188K/mo
- **Pro (€65/mo):** 150,000 emails included — break-even with PAYG at exactly your volume!

**Recommendation:** At exactly 150,000 emails/mo, the Pro plan at **€65/mo** saves you **€42/mo** compared to PAYG.

Pro also includes:
- Send-time optimization
- Custom tracking domains
- 10 team members
- 25 sending domains

Would you like to upgrade to Pro?"""
    },
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUTONOMOUS TECHNICAL TROUBLESHOOTING
    # ══════════════════════════════════════════════════════════════════════════
    
    {
        "context": "pro_webhook_issue",
        "q": "My webhook keeps failing. Help me debug it.",
        "a": """Let me walk you through webhook debugging step by step:

**Step 1: Check your endpoint**
Your webhook URL: `https://api.example.com/webhook`
Recent status: 502 Bad Gateway (847 failed attempts)

**Step 2: Common causes of 502**
1. Your backend server is down or unresponsive
2. Timeout (ApexMail waits 30 seconds)
3. Invalid response format (must return 2xx)
4. Firewall blocking ApexMail IPs

**Step 3: Test manually**
Try this curl command to simulate ApexMail's request:
```bash
curl -X POST https://api.example.com/webhook \\
  -H "Content-Type: application/json" \\
  -d '{"event":"test","timestamp":"2024-01-01T00:00:00Z"}'
```

**Step 4: Check ApexMail IPs**
Add these to your firewall allowlist:
- 198.51.100.0/24
- 203.0.113.0/24

**Step 5: Verify endpoint code**
Your endpoint must:
- Accept POST requests
- Return HTTP 200-299 within 30 seconds
- Process asynchronously (respond immediately, process later)

**Step 6: Resume in dashboard**
Once fixed: Dashboard → Webhooks → Resume

ApexMail will replay failed events from the past **30 days**.

Do you have access to your server logs? I can help interpret common error patterns."""
    },
    
    {
        "context": "starter_bounce_spike",
        "q": "My bounce rate suddenly spiked to 15%. What do I do?",
        "a": """A 15% bounce rate is critical — let's address this immediately:

**Immediate actions:**
1. **STOP all active campaigns** — Further sends will damage your reputation
2. **Don't email the bounced list** — Those addresses are permanently invalid

**Analysis of your bounces:**
Looking at your recent sends:
- Hard bounces (invalid addresses): ~80%
- Soft bounces (temporary): ~20%

**Most likely cause:** You may have imported an old or purchased list. This is the most common cause of sudden bounce spikes.

**Remediation steps:**

**Step 1: Clean your list**
- Go to Dashboard → Contacts → Filters → Bounced
- Review and permanently remove all hard bounces

**Step 2: Verify new imports**
- Never import contacts without email verification
- Use a verification service for existing lists

**Step 3: Quarantine suspect segments**
- Identify which segment caused the spike
- Don't email them until verified

**Step 4: Monitor for 48 hours**
- Resume sending at 25% volume
- Monitor bounce rate (target: under 2%)

**Plan impact:** On Starter (€25/mo), your 50,000 email limit is still available, but your sender reputation needs recovery.

Your threshold is 2% — you're at 15%. This takes 2-4 weeks of clean sending to recover.

Would you like me to identify which campaign caused the spike?"""
    },
]


def format_chatml(system: str, user: str, assistant: str) -> str:
    """Format as ChatML text for training."""
    return (
        f"<|im_start|>system\n{system}<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant}<|im_end|>"
    )


def generate_jsonl() -> list[dict]:
    """Generate JSONL training examples."""
    examples = []
    
    for item in RECOVERED_TRAINING_EXAMPLES:
        ctx_key = item.get("context", "unknown")
        
        system = build_system_prompt(ctx_key)
        user = item["q"]
        assistant = item["a"]
        
        text = format_chatml(system, user, assistant)
        examples.append({"text": text})
    
    return examples


if __name__ == "__main__":
    log.info("=" * 70)
    log.info("GENERATING RECOVERED TRAINING DATA")
    log.info("=" * 70)
    
    examples = generate_jsonl()
    log.info("Generated %d training examples", len(examples))
    
    # Write to recovered_training.jsonl
    try:
        with open(RECOVERED_TRAINING_JSONL, "w") as f:
            for ex in examples:
                f.write(json.dumps(ex) + "\n")
        log.info("Written to %s", RECOVERED_TRAINING_JSONL)
    except OSError as exc:
        log.error("Failed to write %s: %s", RECOVERED_TRAINING_JSONL, exc)
        sys.exit(1)
    
    # Also append to train_agent.jsonl
    try:
        with open(TRAIN_JSONL, "a") as f:
            for ex in examples:
                f.write(json.dumps(ex) + "\n")
        
        # Count total
        with open(TRAIN_JSONL) as f:
            total = sum(1 for line in f if line.strip())
        log.info("Appended to %s — now %d total examples", TRAIN_JSONL, total)
    except OSError as exc:
        log.error("Failed to append to %s: %s", TRAIN_JSONL, exc)
        sys.exit(1)
    
    # Re-run dataset split
    log.info("Re-running dataset split …")
    try:
        result = subprocess.run(
            ["python3", "generate_dataset.py"],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        log.error("generate_dataset.py timed out after 300s")
        sys.exit(1)
    
    sys.stdout.write(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
