#!/usr/bin/env python3
from __future__ import annotations

import logging
import sys

from common_paths import TRAIN_JSONL

# ONE canon, one import: every price/limit below is checked against
# validate_pricing.CANONICAL_PRICING before anything is written.
from validate_pricing import validate_pricing_in_text

# A SECOND canon (audit-6 #9): tool authority, compliance status (HIPAA /
# SOC 2 / ISO 27001) and the marketing pricing surface are DERIVED from the
# canonical registries — chat.rs CHAT_READ_ONLY_TOOLS (the tools the runtime
# actually executes), docs/development/capability-registry.json and
# apps/marketing-zola/data/pricing.json — never hand-coded here. A stale
# example fails _enforce_canonical() before anything is written.
import canonical_truth

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("generate_gap_training")
"""
generate_gap_training.py — Generate training examples for coverage gaps.

Adds examples for: cancellation/retention, automation workflows,
inbound email, rate limits, SLA/uptime, trial management, payment methods,
incident handling, white-label, enterprise compliance, send-time optimization,
contact limits, feature requests, migration, multi-language/encoding.

All prompt-building uses the canonical build_system_prompt() from prompts_v2.py
to avoid duplication of pricing/feature data across training scripts.
"""

import json
import os

from prompts_v2 import EXAMPLE_CONTEXTS, _fmt, build_system_prompt

# Chat template helper
def chatml(system: str, user: str, assistant: str) -> str:
    """Build ChatML formatted training text."""
    return (
        f"<|im_start|>system\n{system}<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant}<|im_end|>"
    )


# ═══════════════════════════════════════════════════════════════════════════════
# TRAINING EXAMPLES — organized by gap area
# ═══════════════════════════════════════════════════════════════════════════════

EXAMPLES: list[dict] = []

# ---------------------------------------------------------------------------
# 1. CANCELLATION & RETENTION (gap: only 2 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel01\n- Plan: Pro (€89/mo)\n- Email usage: 89,000/150,000\n- Account created: 2023-06-15\n- Billing cycle: Renews 15th"),
            "I want to cancel my account.",
            "I understand you'd like to cancel your ApexMail account. Before I proceed, let me share a few things:\n\n**What happens when you cancel:**\n- Your account will remain active until the end of your current billing cycle (the 15th).\n- After that, sending will stop and all data will enter a 30-day grace period.\n- After the grace period, your data (templates, contacts, analytics history) will be permanently deleted.\n- Any remaining email volume for this cycle is non-refundable.\n\nYou're currently using 89,000 of your 150,000 monthly emails, so your account is well-utilized.\n\n**Before you go, may I ask what prompted this decision?** Depending on your situation, I may be able to help — for example:\n- If it's a **cost concern**, we have lower-tier plans starting at €20/mo (Developer) or even a Free plan (3,000 emails/mo)\n- If it's a **feature gap**, I'd love to hear what's missing\n- If it's **deliverability issues**, I can run diagnostics right now\n\nIf you're sure you want to cancel, I'll need you to confirm explicitly, and I'll walk you through the process."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel02\n- Plan: Growth (€229/mo)\n- Email usage: 12,000/500,000\n- Account created: 2024-09-01\n- Billing cycle: Renews 1st"),
            "Cancel my subscription right now. I don't want to talk about it.",
            "I respect your decision. Let me walk you through the cancellation.\n\n**⚠️ Important — this is irreversible after the grace period:**\n- Your Growth plan will stay active through the end of this billing cycle (the 1st of next month)\n- After that, you'll have a 30-day grace period to reactivate\n- Once the grace period ends, all data (contacts, templates, campaigns, analytics) is permanently deleted\n\nTo confirm you want to proceed: you can cancel yourself in **Dashboard → Billing → Cancel subscription** — it takes effect at the end of the billing cycle, and the same 30-day grace period applies.\n\nOne thing to be transparent about: I can't execute subscription changes from this chat — my tools are read-only, and billing actions are either self-service in the Dashboard or handled by our team at **support@apexmail.ee**.\n\nIf you ever want to return, you can sign up again at any time — though your previous data won't be recoverable after deletion."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel03\n- Plan: Developer (€20/mo)\n- Email usage: 48,200/50,000\n- Account created: 2024-02-20\n- Billing cycle: Renews 20th\n- Contacts: 9,800"),
            "I'm switching to Mailchimp. How do I export all my data before I leave?",
            "I'm sorry to see you go! Here's how to export everything before cancellation:\n\n### Exporting your data\n\n1. **Contacts**: Go to **Dashboard → Contacts → Export**. You'll get a CSV with all 9,800 contacts, tags, and metadata. The Contacts page shows the live count, so you can verify all 9,800 made it into the export.\n\n2. **Templates**: Go to **Dashboard → Templates** → click each template → **Export HTML**. You can also use the API: `GET /v1/templates/{template_id}` to programmatically download all of them.\n\n3. **Campaign history & analytics**: Go to **Dashboard → Campaigns → Export Report** for each campaign. Your Developer plan has 30-day data retention, so make sure to export before your final billing date (the 20th).\n\n4. **Suppression lists**: Go to **Dashboard → Suppressions → Export** to get your bounce and complaint lists. This is important for maintaining good sender reputation on your new platform.\n\n5. **API keys**: If any external systems reference your ApexMail API keys, update them before cancellation.\n\nWould you like me to help with any of these exports, or are you ready to proceed with cancellation?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel04\n- Plan: Business (€699/mo)\n- Email usage: 1,800,000/2,000,000\n- Account created: 2023-01-05\n- Billing cycle: Renews 5th\n- Contacts: 450,000\n- Team members: 35/50"),
            "We need to downgrade to save costs. What's the cheapest plan that can handle our volume?",
            "Let's find the right fit for your volume. You're currently sending ~1.8M emails/month with 450K contacts and 35 team members. Here's the analysis:\n\n| Requirement | Your usage | Growth (€229) | Business (€699) |\n|------------|-----------|---------------|---------------|\n| Emails/mo | 1,800,000 | 500,000 ❌ | 2,000,000 ✅ |\n| Contacts | 450,000 | 200,000 ❌ | 500,000 ✅ |\n| Team | 35 | 25 ❌ | 50 ✅ |\n| API calls | — | 5,000,000 | 20,000,000 |\n\n**Unfortunately, Business (€699/mo) is the lowest plan that fits your needs.** The Growth plan (€229/mo) can't handle your email volume (500K vs 1.8M needed), contact count (200K vs 450K), or team size (25 vs 35).\n\n**Options to reduce costs on Business:**\n1. **Reduce team members** — remove inactive accounts (you have 35 of 50 slots)\n2. **Audit email volume** — are all 1.8M emails necessary? Segmenting better could reduce sends\n3. **Review subaccounts** — if not using all 10, no savings here, but worth auditing\n\nAlternatively, if you can reduce volume below 500K and contacts below 200K, the Growth plan at €229/mo saves you €470/mo.\n\nWould you like me to help analyze your sending patterns to find optimization opportunities?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel05\n- Plan: Free (€0/mo)\n- Email usage: 21/3,000\n- Account created: 2025-01-10"),
            "How do I delete my account entirely? I want all my data removed.",
            "I understand you want a full account deletion. Here's what you need to know:\n\n**⚠️ Account deletion is permanent and irreversible.** This will:\n- Delete all your contacts, templates, and campaign history\n- Remove all sending domains and DNS configurations\n- Revoke all API keys immediately\n- Purge all analytics and event data\n- Remove your login credentials\n\nSince you're on the Free plan, there are no billing implications.\n\nTo be transparent about how this works: I can't delete your account from this chat — my tools are read-only, and account deletion is a self-service action you control.\n\n**To delete your account yourself:**\n1. Go to **Dashboard → Account Settings → Danger Zone → Delete Account**\n2. Confirm with your password\n3. Deletion is queued and permanent — once confirmed, this cannot be undone, and there is no recovery option\n\nIf the dashboard option gives you any trouble, email **support@apexmail.ee** from your account's address and our team will process it after verifying you're the account owner.\n\nIf you have any data you want to export first (contacts, templates), I recommend doing that before deletion."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cancel06\n- Plan: Pro (€89/mo)\n- Email usage: 20,000/150,000\n- Account created: 2024-11-01\n- Billing cycle: Renews 1st"),
            "I'm barely using my Pro plan. Is there something cheaper?",
            "You're right — at 20,000 emails out of 150,000, you're only using about 13% of your Pro plan capacity. Let's look at your options:\n\n**Developer plan — €20/mo** (save €69/mo)\n- 50,000 emails/mo — plenty for your current 20K usage\n- 500,000 API calls/mo\n- 5 team members, 5 domains\n- **Trade-offs**: No send-time optimization, no custom tracking domain, no dedicated IP option\n- 10,000 contacts max (vs 50,000 on Pro)\n\n**Free plan — €0/mo** (save €89/mo)\n- 3,000 emails/mo — covers your 20K usage, but keeps Free limits (1 domain, 1 team member, no webhooks, no send-time optimization)\n\n**My recommendation**: The **Developer plan at €20/mo** fits your volume well and saves you €69/month (€828/year). You'd lose send-time optimization, custom tracking domains, and the dedicated IP add-on, but if you're not actively using those features, it's a great fit.\n\nWould you like me to downgrade you to Developer? I'll need you to confirm, and the change will take effect at your next billing cycle (the 1st)."
        )
    },
])


# ---------------------------------------------------------------------------
# 2. AUTOMATION WORKFLOWS (gap: only 6 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto01\n- Plan: Pro (€89/mo)\n- Email usage: 45,000/150,000\n- Account created: 2024-04-01\n- Contacts: 12,000"),
            "How do I set up a welcome email that sends automatically when someone signs up?",
            "Great question! Here's how to set up a welcome automation on your Pro plan:\n\n### Setting up a welcome email automation\n\n1. **Create your welcome template first** (if you haven't already):\n   - Go to **Dashboard → Templates → New Template**\n   - Design your welcome email with personalization variables like `{{first_name}}`\n\n2. **Create the automation**:\n   - Go to **Dashboard → Automations → Create New**\n   - **Trigger**: Select \"Contact added\" or \"Tag added\" (e.g., when tagged with `new-subscriber`)\n   - **Action**: Send email → select your welcome template\n   - **Delay**: Optional — you can set it to send immediately (0 delay) or after a short delay (e.g., 5 minutes)\n\n3. **Enable it**: Toggle the automation to active\n\nOr I can create it for you right now! I'll need:\n- The template to use (or I can create a basic one)\n- The trigger condition (contact added? specific tag?)\n- Any delay before sending?\n\nWould you like me to set this up?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto02\n- Plan: Growth (€229/mo)\n- Email usage: 210,000/500,000\n- Account created: 2023-08-15\n- Contacts: 85,000"),
            "I want to build a drip campaign: welcome email on day 0, product tips on day 3, and a discount offer on day 7. Can you help?",
            "Absolutely! Let me set up a 3-step drip sequence for you. Here's the plan:\n\n### Drip campaign: Welcome → Tips → Offer\n\n**Step 1 — Welcome email (Day 0)**\n- Trigger: Contact added / tagged with your chosen trigger\n- Send immediately\n\n**Step 2 — Product tips (Day 3)**\n- Delay: 3 days after Step 1\n- Only send if contact is still subscribed\n\n**Step 3 — Discount offer (Day 7)**\n- Delay: 4 days after Step 2 (7 days total from signup)\n- Only send if contact hasn't unsubscribed\n\nTo set this up, I'll need:\n1. **Templates** — Do you have templates ready for each email, or should I create basic ones?\n2. **Trigger** — What event starts the sequence? (e.g., \"tagged with `new-customer`\", or \"added to list X\")\n3. **Sender details** — Which sending domain/from address?\n\nOnce you have those three pieces, you can build the sequence yourself in **Dashboard → Automations → Create New** — the three steps above map 1:1 to the automation builder. I can't create automations from this chat (my tools are read-only), but I can review your trigger logic or answer questions while you build.\n\nOn your Growth plan, you have full automation capabilities with audit logs to track performance. Would you like to proceed?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto03\n- Plan: Developer (€20/mo)\n- Email usage: 30,000/50,000"),
            "Can I set up an automation that re-engages inactive subscribers after 30 days?",
            "Yes! Developer plan supports automations. Here's how to set up a re-engagement flow:\n\n### Re-engagement automation\n\n**Trigger**: Contact hasn't opened/clicked in 30 days\n- You can set this up by tagging contacts as `inactive-30d` using a segment rule, then triggering the automation on that tag\n\n**Sequence**:\n1. **Day 0**: Send a \"We miss you!\" email with a compelling subject line\n2. **Day 7** (optional): If no open, send a final \"Last chance\" email with an incentive\n3. **Day 14**: If still no engagement, automatically add to a suppression segment to protect your sender reputation\n\n**Best practices**:\n- Keep the subject line personal: \"We haven't heard from you, {{first_name}}\"\n- Offer value — exclusive content, discount, or product update\n- Include a clear unsubscribe option\n- Remove truly inactive contacts after the sequence to maintain list hygiene\n\nWant me to create this automation for you? I'll need your preferred sending domain and any template preferences."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto04\n- Plan: Pro (€89/mo)\n- Automations: [auto_welcome (active), auto_abandoned_cart (paused)]"),
            "My abandoned cart automation stopped working. It shows as paused but I didn't pause it.",
            "Let me investigate your paused abandoned cart automation. You can see its current state and pause reason in **Dashboard → Automations → auto_abandoned_cart** — the details panel shows the exact trigger that paused it.\n\nWhile you check, here are the common reasons an automation can auto-pause:\n\n1. **Error threshold**: If too many emails in the automation bounce or generate complaints, the system may auto-pause it as a safety measure\n2. **Template deleted**: If the email template referenced by the automation was deleted or modified\n3. **Domain verification lost**: If the sending domain lost its verification status\n4. **Contact limit hit**: If your plan's contact limit was reached\n\nIf the pause reason is benign (e.g., a fixed template issue), you can resume it yourself with the **Resume** button on the automation's page. I can't re-enable it from this chat — my tools are read-only — but I can help you interpret the pause reason if you paste it here.\n\nIn the meantime — do you recall when it stopped? And have you made any changes to your templates or domains recently?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto05\n- Plan: Business (€699/mo)\n- Email usage: 1,200,000/2,000,000\n- Contacts: 380,000"),
            "Can I trigger automations via the API instead of through the dashboard?",
            "Absolutely! On Business, you have full API access for automation management. Here's how:\n\n### API-triggered automations\n\n**Option 1: Tag-based triggers**\nCreate an automation in the dashboard triggered by a specific tag, then use the API to add that tag:\n```\nPOST /v1/contacts/{email}/tags\n{\"tags\": [\"trigger-welcome-flow\"]}\n```\nThis fires the automation for that contact.\n\n**Option 2: Direct automation API**\nManage automations programmatically:\n```\n# List automations\nGET /v1/automations\n\n# Create automation\nPOST /v1/automations\n{\"name\": \"API Welcome\", \"trigger\": \"tag_added\", \"trigger_value\": \"new-signup\", \"actions\": [{\"type\": \"send_email\", \"template_id\": \"tmpl_xxx\", \"delay\": 0}]}\n\n# Enable/disable\nPOST /v1/automations/{id}/enable\nPOST /v1/automations/{id}/disable\n```\n\n**Option 3: Webhook + automation**\nSet up an inbound webhook that adds a tag or creates a contact, which then triggers the automation.\n\nOn your Business plan, you have 20M API calls/month (currently using ~3.2M of your allocation), so there's plenty of headroom for API-driven automation triggers.\n\nWant me to help set up a specific API-triggered automation?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_auto06\n- Plan: Growth (€229/mo)\n- Contacts: 120,000"),
            "What's the difference between a campaign and an automation in ApexMail?",
            "Great question! Here's the key difference:\n\n### Campaigns vs. Automations\n\n| Feature | Campaign | Automation |\n|---------|----------|------------|\n| **Type** | One-time or scheduled | Ongoing, event-driven |\n| **Trigger** | You manually send or schedule | Triggered automatically by events |\n| **Audience** | Fixed list/segment at send time | Dynamic — each contact enters individually |\n| **Use case** | Newsletters, announcements, promotions | Welcome series, drip sequences, re-engagement |\n| **Reporting** | Aggregate campaign stats | Per-contact journey tracking |\n\n**Examples:**\n- 📧 **Campaign**: \"Black Friday Sale\" email sent to all subscribers on Nov 29\n- ⚡ **Automation**: Welcome email sent to each new subscriber the moment they sign up\n\n**On your Growth plan**, you have access to both:\n- Unlimited campaigns\n- Full automation builder with multi-step sequences\n- Audit logs to track both campaign and automation activity\n\nWould you like help creating either a campaign or an automation?"
        )
    },
])


# ---------------------------------------------------------------------------
# 3. INBOUND EMAIL (gap: only 2 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inb01\n- Plan: Business (€699/mo)\n- Domains: [mail.bigshop.com (verified), replies.bigshop.com (verified)]"),
            "How does inbound email parsing work? I want to receive customer replies.",
            "Inbound email receiving is available on your Business plan. Here's how it works:\n\n### Setting up inbound email\n\n**1. Configure your inbound domain**\nSet up an MX record for the domain you want to receive on:\n```\nreplies.bigshop.com  MX  10  inbound.apexmail.ee\n```\n\n**2. Create an inbound webhook**\nWhen ApexMail receives an email at your inbound domain, it parses the message and forwards the structured data to your webhook URL:\n```\nPOST /v1/webhooks\n{\n  \"url\": \"https://api.bigshop.com/inbound\",\n  \"events\": [\"inbound\"]\n}\n```\n\n**3. Webhook payload**\nYour webhook receives a JSON payload with:\n- `from`: Sender email and name\n- `to`: Recipient address (e.g., support@replies.bigshop.com)\n- `subject`: Email subject\n- `text`: Plain text body\n- `html`: HTML body (if present)\n- `attachments`: Array of attachment metadata with download URLs\n- `headers`: Full email headers\n\n**4. Use cases**:\n- Process customer replies to campaigns\n- Build a support inbox\n- Auto-extract unsubscribe requests\n- Parse order confirmations\n\nWant me to help set up the MX record and webhook for `replies.bigshop.com`?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inb02\n- Plan: Pro (€89/mo)"),
            "Can I use ApexMail to receive incoming emails from my customers?",
            "Inbound email receiving is available on the **Business plan (€699/mo) and above**. Your current Pro plan (€89/mo) doesn't include this feature.\n\nHere's the plan comparison for inbound:\n\n| Plan | Inbound receiving |\n|------|------------------|\n| Free, Developer, Pro, Growth | ❌ Not available |\n| Business (€699/mo) | ✅ Included |\n| Enterprise Cloud (€1,750/mo) | ✅ Included |\n\n**What inbound email gives you:**\n- Receive emails at your domain (e.g., replies@yourdomain.com)\n- Automatic parsing of sender, subject, body, and attachments\n- Webhook forwarding of parsed email data to your application\n- Great for processing reply-to campaign emails, support inboxes, etc.\n\n**Alternatives on your Pro plan:**\n- Use a separate inbound email service and connect it to ApexMail via API\n- Set up reply tracking via webhooks — you can capture bounce-backs and complaints (though not full inbound parsing)\n\nWould you like to learn more about upgrading to Business, or explore the webhook-based alternatives?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inb03\n- Plan: Business (€699/mo)\n- Inbound domain: replies.shopfast.io (MX configured)"),
            "My inbound webhook is receiving emails but some attachments are missing. What's going on?",
            "Let me help troubleshoot your inbound attachment issue. A few things to check:\n\n### Common inbound attachment issues\n\n**1. Attachment size limits**\n- ApexMail processes attachments up to **25 MB per message** and **10 MB per individual attachment**\n- Attachments exceeding these limits are stripped but the email text is still delivered\n- Check if the missing attachments were large files (PDFs, images, etc.)\n\n**2. Attachment types**\n- Some potentially dangerous attachment types (.exe, .bat, .cmd, .scr) are stripped for security\n- Standard types (PDF, images, Office docs, CSV) are always included\n\n**3. Webhook timeout**\n- If your webhook endpoint takes too long to respond (>30 seconds), the request may time out before all attachment data is transmitted\n- Ensure your endpoint responds with 200 within 5 seconds, then process attachments asynchronously\n\n**4. Encoding issues**\n- Some email clients send attachments with unusual MIME encodings\n- Check the `attachments[].content_type` field in the webhook payload\n\nNext, check the delivery history for that endpoint: **Dashboard → Webhooks → wh_inbound_shopfast → Deliveries** shows each attempt with status and response time, so you can spot error patterns (timeouts, retries) yourself.\n\nCan you share a specific message ID where attachments were missing? That will help me pinpoint the issue."
        )
    },
])


# ---------------------------------------------------------------------------
# 4. RATE LIMITS (gap: only 3 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_rate01\n- Plan: Pro (€89/mo)\n- API calls this month: 1,850,000/2,000,000"),
            "I'm getting 429 errors from the API. What are my rate limits?",
            "You're hitting API rate limits. Here's a breakdown of your Pro plan limits:\n\n### API rate limits — Pro plan\n\n**Monthly quota**: 2,000,000 API calls/month\n- You've used **1,850,000** (92.5%) — only 150,000 remaining this month\n\n**Per-second rate limits**:\n- **Sending endpoints** (`POST /v1/messages`): 100 requests/second\n- **Read endpoints** (GET requests): 200 requests/second\n- **Bulk operations**: 10 requests/second\n\n**When you hit a 429 error:**\n- The response includes a `Retry-After` header (in seconds)\n- Implement exponential backoff: wait 1s → 2s → 4s → 8s on consecutive 429s\n- Check the `X-RateLimit-Remaining` header to proactively slow down before hitting limits\n\n**Immediate actions:**\n1. Check if you have any scripts making unnecessary API calls\n2. Use webhooks instead of polling for event data\n3. Batch operations where possible (e.g., bulk contact imports vs individual adds)\n\n**If you need more capacity:**\n- **Growth plan (€229/mo)**: 5,000,000 API calls/month\n- **Business plan (€699/mo)**: 20,000,000 API calls/month\n\nWant me to check your API usage pattern to identify what's consuming the most calls?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_rate02\n- Plan: Developer (€20/mo)\n- API calls this month: 490,000/500,000"),
            "I'm about to hit my API limit. What happens if I go over?",
            "You're at 490,000 of your 500,000 monthly API calls — only 10,000 left. Here's what happens if you exceed it:\n\n### API overage policy\n\n**When you hit your monthly API limit:**\n- API calls beyond your 500,000 limit are **billed as overages**\n- First 30,000 API calls over your limit: **free** (grace buffer)\n- After that: **€0.10 per 1,000 extra API calls**\n\n**Example for your situation:**\n- If you make 650,000 total API calls this month:\n  - 500,000 included in Developer\n  - 150,000 overage → first 30,000 free → 120,000 billable\n  - Extra charge: 120 × €0.10 = **€12.00**\n\n**Your API calls are NOT cut off** — they just incur overage charges.\n\n**To avoid overages:**\n1. Use webhooks instead of polling (biggest API saver)\n2. Cache responses that don't change frequently\n3. Use batch endpoints for bulk operations\n4. Consider upgrading: **Pro plan (€89/mo)** gives you 2,000,000 API calls\n\nWould you like me to check your API usage breakdown to see where calls are going?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_rate03\n- Plan: Business (€699/mo)\n- API calls this month: 18,500,000/20,000,000"),
            "We need to send a bulk import of 2 million contacts via the API. Will we hit any limits?",
            "Good timing on checking! With 18.5M of your 20M monthly API calls used, a 2M contact import could push you over. Let's plan this carefully:\n\n### Bulk import approach\n\n**Option 1: CSV import (recommended)**\nUse the bulk contacts-import API endpoint with a CSV file:\n```\nPOST /v1/contacts/import\n{\"csv_url\": \"https://your-server.com/contacts.csv\"}\n```\nThis counts as **1 API call** regardless of contact count. Much more efficient!\n\n**Option 2: Individual API calls**\nIf you use `POST /v1/contacts` for each contact:\n- 2,000,000 API calls needed\n- You only have 1,500,000 remaining → you'd go 500,000 over\n- Overage cost: (500,000 - 30,000 free) × €0.10/1,000 = **€47.00**\n- Plus rate limits: at 200 req/sec, this takes ~2.8 hours\n\n**My recommendation**: Use the CSV bulk import endpoint. It's:\n- ✅ 1 API call instead of 2,000,000\n- ✅ Handles deduplication automatically\n- ✅ Supports field mapping\n- ✅ Much faster (server-side processing)\n\nWant me to help set up the CSV import? I'll need the URL where your CSV file is hosted."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_rate04\n- Plan: Free (€0/mo)\n- API calls this month: 28,000/30,000"),
            "How do I check my remaining API calls?",
            "You can check your remaining API calls in several ways:\n\n### 1. Dashboard\nGo to **Dashboard → Usage** — shows your current API usage vs limit in real-time.\n\n### 2. API response headers\nEvery API response includes rate limit headers:\n```\nX-RateLimit-Limit: 50000          (your monthly limit)\nX-RateLimit-Remaining: 2000        (calls remaining)\nX-RateLimit-Reset: 2025-03-01T00:00:00Z  (when limit resets)\n```\n\n### 3. Usage API endpoint\n```\nGET /v1/account/usage\n```\nReturns your current usage breakdown.\n\n### 4. Your current status\nFrom your account context: you've used **28,000 of 30,000** API calls this month (93%). Only 2,000 remaining on your Free plan — and the Dashboard → Usage view updates in real time if you want to watch it.\n\n**Tip**: Consider upgrading to **Developer (€20/mo)** for 500,000 API calls — over 16× your current limit. Would you like to explore that?"
        )
    },
])


# ---------------------------------------------------------------------------
# 5. INCIDENT HANDLING (gap: only 7 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inc01\n- Plan: Business (€699/mo)\n- SLA: 99.9% uptime"),
            "Is there an outage right now? My emails aren't going out.",
            "I understand the urgency. Let's triage this right now — I'll be straight with you about what I can and can't see: my tools are read-only guidance tools, so I can't pull your live account data from this chat, but the diagnostics below pinpoint most causes in minutes.\n\n### Immediate diagnostics\n1. **System status**: Check our status page at **status.apexmail.ee** for any reported incidents\n2. **Your account**: Open **Dashboard → Usage** — if you've hit a sending limit, it shows immediately, and **Dashboard → Campaigns** shows whether sends are queued or failing\n3. **Domain health**: Any recent DNS changes on your sending domains?\n\n### If there IS a platform issue:\n- Your Business plan includes a **99.9% SLA** with 10% credit for qualifying downtime\n- We'll post updates on the status page and send a post-incident report within 24 hours\n\n### If it's account-specific:\n- Could be a domain verification issue, IP blocklisting, or sending limit reached\n- **Dashboard → Analytics** shows bounce and complaint spikes, and each failed message carries a machine-readable reason\n\nCan you share a specific message ID that failed to send? That will help me trace the exact failure point."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inc02\n- Plan: Enterprise Cloud (€1,750/mo)\n- SLA: 99.9% uptime (25% credit)"),
            "We've had 2 hours of downtime today. How do I claim my SLA credit?",
            "I'm sorry about the downtime. Here's how the SLA credit process works for your Enterprise Cloud plan:\n\n### SLA credit claim process\n\n**Your Enterprise Cloud SLA terms:**\n- Guaranteed uptime: **99.9%** per calendar month\n- Credit amount: **25% of monthly fee** (€750.00) for qualifying downtime\n- Monthly downtime budget: 99.9% = max 43.8 minutes/month before SLA breach\n\n**2 hours of downtime = 120 minutes** → This exceeds the 43.8-minute threshold, so you likely qualify for a credit.\n\n**To claim your SLA credit:**\nThis needs to be handled by our billing team. Please email **support@apexmail.ee** with:\n\n**Subject**: SLA Credit Claim — acct_inc02\n\n**Include**:\n1. Date/time of the downtime incident (with timezone)\n2. Duration observed (2 hours)\n3. Services affected (sending, API, dashboard, etc.)\n4. Impact description (number of emails delayed/failed)\n5. Any error messages or status codes observed\n\nOur team will cross-reference with our internal monitoring data and process the credit within 5 business days if the claim is validated.\n\n**Note**: Scheduled maintenance windows (announced 72 hours in advance) and force majeure events are excluded from SLA calculations.\n\nWould you like me to help draft the email?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inc03\n- Plan: Growth (€229/mo)\n- Recent events: API response times elevated (avg 2.3s vs normal 200ms)"),
            "The API has been really slow today. Is something wrong on your end?",
            "Let me investigate the elevated API response times you're experiencing.\n\n### What your context shows:\n- Your API response times are currently averaging **2.3 seconds** vs the normal ~200ms\n- That's a **10x degradation** which is definitely abnormal\n\n(I can't pull live API analytics from this chat — my tools are read-only — but **Dashboard → Analytics → API** shows the same latency breakdown per endpoint.)\n\n### Possible causes:\n1. **Platform-wide issue**: Check **status.apexmail.ee** for any posted incidents\n2. **Regional routing**: If you're in a specific region, there may be network-level issues\n3. **Rate limiting**: Are you near your API limit? Throttled requests can appear slower\n4. **Endpoint-specific**: Some endpoints (bulk operations, analytics) are naturally slower\n\n### What you can do right now:\n- **Add timeouts and retries** to your API calls with exponential backoff\n- **Check which endpoints are slow**: Is it all endpoints or specific ones?\n- **Reduce non-critical calls** temporarily until performance normalizes\n\nIf this is a confirmed platform issue, your Growth plan doesn't include an SLA, but we take performance seriously. The Business plan (€699/mo) includes a 99.9% SLA with credit guarantees if you need formal uptime commitments.\n\nCan you share which API endpoints are affected?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_inc04\n- Plan: Pro (€89/mo)"),
            "I can't log in to the dashboard. Is it down?",
            "I'm sorry you're having trouble logging in. Let me help you diagnose this:\n\n### Immediate checks:\n\n1. **System status**: Visit **status.apexmail.ee** — if there's a platform outage, it will be posted there\n\n2. **Common login issues** (not related to an outage):\n   - **Wrong credentials**: Try the \"Forgot Password\" flow to reset\n   - **Browser cache**: Clear your browser cache and cookies, or try an incognito/private window\n   - **2FA issues**: If you have two-factor authentication enabled and lost your device, you'll need a recovery code\n   - **Account locked**: After 5 failed login attempts, your account may be temporarily locked (30-minute cooldown)\n   - **Browser compatibility**: Use a modern browser (Chrome, Firefox, Safari, Edge)\n\n3. **What error do you see?** The error message will help me narrow it down:\n   - \"Invalid credentials\" → password issue\n   - \"Account locked\" → too many failed attempts\n   - Blank page / timeout → possible platform issue\n   - 500 error → server-side issue\n\nCould you tell me what exactly happens when you try to log in? Any specific error message?"
        )
    },
])


# ---------------------------------------------------------------------------
# 6. WHITE LABEL (gap: only 2 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_wl01\n- Plan: Enterprise Cloud (€1,750/mo)"),
            "We want to white-label ApexMail for our agency clients. How does that work?",
            "White-labeling is included in your Enterprise Cloud plan! Here's how it works:\n\n### White-label features on Enterprise Cloud\n\n**1. Custom branding**\n- Replace all ApexMail branding with your own logo, colors, and company name\n- Custom login page at your domain (e.g., `mail.youragency.com`)\n- Branded transactional emails (password resets, notifications)\n\n**2. Custom domain for the dashboard**\n- Set up a CNAME record to serve the dashboard from your domain:\n  ```\n  mail.youragency.com  CNAME  dashboard.apexmail.ee\n  ```\n- SSL certificate is automatically provisioned\n\n**3. Subaccounts**\n- Create separate subaccounts for each of your agency clients\n- Each client gets their own contacts, templates, campaigns, and analytics\n- You maintain admin access across all subaccounts\n- Enterprise Cloud plan: unlimited subaccounts (Business: 10)\n\n**4. What gets white-labeled:**\n- ✅ Dashboard UI\n- ✅ Login page\n- ✅ Email notifications\n- ✅ API responses (X-Powered-By header)\n- ❌ DNS records still point to ApexMail infrastructure (but your clients won't see this)\n\n**To get started**, please reach out to your **dedicated Customer Success Manager** or email **support@apexmail.ee** — they'll walk you through the branding configuration and provide the setup guide.\n\nShall I help you with anything else related to white-label setup?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_wl02\n- Plan: Business (€699/mo)"),
            "Does the Business plan include white-labeling?",
            "No, **white-labeling is only available on the Enterprise Cloud plan (€1,750/mo)**. Here's the comparison:\n\n| Feature | Business (€699) | Enterprise Cloud (€1,750) |\n|---------|-------------|-------------------|\n| White-label branding | ❌ | ✅ |\n| Custom dashboard domain | ❌ | ✅ |\n| Subaccounts | 10 | Unlimited |\n| Dedicated CSM | ❌ | ✅ |\n| BYOIP | ❌ | ✅ |\n\nYour Business plan includes powerful features like SSO/SAML, 1 dedicated IP included (more as add-ons), priority async support, shared Slack hub, and 10 subaccounts — but the branding remains ApexMail throughout the interface.\n\nOne thing I want to be precise about, since agencies often ask: **HIPAA and SOC 2 are not currently offered on any plan** — including Enterprise Cloud. Enterprise adds branding, infrastructure and support commitments, not compliance certifications.\n\n**If white-labeling is important for your business** (e.g., agency reselling), the Enterprise Cloud upgrade at €1,750/mo gives you full branding control, unlimited subaccounts, and a dedicated Customer Success Manager to help with setup.\n\nWould you like to discuss upgrading to Enterprise?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_wl03\n- Plan: Enterprise Cloud (€1,750/mo)\n- White-label: enabled\n- Custom domain: mail.acmemail.com"),
            "One of my agency clients is asking about your pricing. They want to see the ApexMail pricing page. How do we handle this?",
            "Since you're using white-label on Enterprise Cloud, your clients see **your branding**, not ApexMail's. Here's how to handle this:\n\n### Pricing for white-label agency clients\n\n**Your clients don't interact with ApexMail directly.** From their perspective, they're using your product (\"AcmeMail\" via mail.acmemail.com). You set your own pricing for your clients.\n\n**Best practices for agency white-label:**\n\n1. **Set your own pricing tiers** — You can markup ApexMail's cost however you want. Common approaches:\n   - Per-client flat fee\n   - Per-email volume pricing\n   - Feature-based tiers\n\n2. **Use subaccounts** to isolate each client's data, templates, contacts, and sending domains\n\n3. **Don't share ApexMail pricing** with your clients — this is the point of white-labeling. They're your customers, not ours.\n\n4. **Billing**: You pay ApexMail the Enterprise Cloud fee (€1,750/mo). You bill your clients separately through your own billing system.\n\n5. **Support**: Your clients contact your team for support. You can then escalate to us via **support@apexmail.ee** if needed, and we'll keep your white-label confidential.\n\nWould you like help setting up a new subaccount for this client?"
        )
    },
])


# ---------------------------------------------------------------------------
# 7. ENTERPRISE COMPLIANCE — HIPAA / SOC2 (gap: only 4 examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_comp01\n- Plan: Growth (€229/mo)\n- Industry: Healthcare"),
            "We're a healthcare company. Do you support HIPAA compliance?",
            "I have to give you a direct answer here, because it matters for a healthcare company: **HIPAA compliance is not currently offered on any ApexMail plan** — including Enterprise Cloud. There is no BAA and no HIPAA-specific processing on the platform today.\n\n### What that means for you\n\n**Do NOT send Protected Health Information (PHI) through ApexMail.** If your emails would contain patient names, health conditions, treatment details, or other PHI, ApexMail is not the right tool under HIPAA — sending PHI without a BAA in place is a regulatory violation on your side.\n\n**If your emails are non-PHI** (e.g., generic appointment reminders with no health details, staff newsletters, billing notices without diagnosis information), many healthcare organizations use us for exactly that — but run it past your compliance team first.\n\n### What we DO offer (on every plan)\n- GDPR: EU/EEA processing, and a Data Processing Agreement is available\n- Encryption: TLS 1.2+ in transit, AES-256 at rest\n- Published data locations and subprocessor register on apexmail.ee\n\nIf regulated-workload requirements are on your roadmap, email **support@apexmail.ee** with subject \"Regulated-workload requirements — Healthcare Account\" — HIPAA is not offered today, so those requirements go on record with the team that plans the roadmap, and we'll be straight with you about what is and isn't possible.\n\nWould you like help scoping what non-PHI sending could look like for you?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_comp02\n- Plan: Enterprise Cloud (€1,750/mo)"),
            "We need a copy of your SOC 2 Type II report for our vendor review.",
            "I have to be straight with you, because a vendor review needs accurate evidence: **ApexMail is not SOC 2 certified, and no SOC 2 report exists** — on any plan, including Enterprise Cloud. If I pointed you to a report request process, I'd be sending your security team after a document that doesn't exist, and that's worse for both of us.\n\n### What I can give you instead (all verifiable)\n- **GDPR posture**: EU/EEA processing, a Data Processing Agreement is available, data locations and the subprocessor register are published on apexmail.ee\n- **Encryption**: TLS 1.2+ in transit, AES-256 at rest\n- **Audit logging**: signed audit logs; 730-day retention on your Enterprise Cloud plan\n- **Status and incidents**: status.apexmail.ee\n\n### For the vendor review\nEmail **support@apexmail.ee** with:\n- **Subject**: Vendor Review — Security Documentation — acct_comp02\n- **Include**: what your security questionnaire requires (encryption standards, data residency, subprocessors, breach notification)\n\nOur team will answer in writing with the documentation that DOES exist. If your approval process hard-requires a SOC 2 report we cannot provide, we'll say so plainly rather than stall your review — no one benefits from a surprise at signing.\n\nIs there anything else your security team needs? I'd rather answer hard questions accurately than easily."
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_comp03\n- Plan: Business (€699/mo)"),
            "Does ApexMail have SOC 2 certification? Our security team requires it for vendor approval.",
            "No — **ApexMail is not SOC 2 certified on any plan**, and I won't pretend a higher tier unlocks it. We are not certified, so there is no report, bridge letter, or certification to send your security team.\n\n### What your security team CAN verify today\n\n| Control area | What we actually have |\n|--------------|----------------------|\n| Data protection | TLS 1.2+ in transit, AES-256 at rest |\n| Data residency | EU/EEA processing; locations published on apexmail.ee |\n| GDPR | DPA available; subprocessor register published |\n| Audit logging | Signed audit logs (365-day retention on your Business plan, 730-day on Enterprise Cloud) |\n| Availability | 99.9% SLA on Business and Enterprise Cloud; status page at status.apexmail.ee |\n| Access control | MFA/TOTP, RBAC-scoped API keys, SSO/SAML on Business+ |\n\n### For the vendor questionnaire\nEmail **support@apexmail.ee** with:\n- **Subject**: Vendor Review — Security Documentation — acct_comp03\n- Include the questionnaire or the specific controls your approval requires\n\nOur team answers in writing with evidence for everything in the table above. If a SOC 2 report — which we cannot provide — is a hard requirement for approval, we'd rather tell you now than have it surface during an audit.\n\nAnything else your security team needs? I'm happy to go deeper on any control in the table."
        )
    },
])


# ---------------------------------------------------------------------------
# 8. SLA & UPTIME (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sla01\n- Plan: Business (€699/mo)"),
            "What's your uptime guarantee?",
            "Your Business plan includes a **99.9% uptime SLA**. Here's the breakdown:\n\n### SLA details — Business plan\n\n| Metric | Value |\n|--------|-------|\n| Uptime guarantee | 99.9% per calendar month |\n| Max allowed downtime | ~43.8 minutes/month |\n| Credit for breach | **10% of monthly fee** (€35.00) |\n| Monitoring | 24/7 automated + manual monitoring |\n| Status page | status.apexmail.ee |\n\n### SLA comparison across plans\n\n| Plan | SLA | Credit |\n|------|-----|--------|\n| Free, Developer, Pro | No SLA | — |\n| Growth (€229) | No formal SLA | — |\n| Business (€699) | 99.9% | 10% credit (€35) |\n| Enterprise Cloud (€1,750) | 99.9% | 25% credit (€750) |\n\n### What's covered:\n- Email sending API availability\n- Dashboard/console availability\n- Webhook delivery processing\n- Inbound email receiving\n\n### What's excluded:\n- Scheduled maintenance (72-hour advance notice)\n- DNS propagation delays (your side)\n- Third-party service outages\n- Force majeure events\n\nYou can monitor real-time status at **status.apexmail.ee**. Would you like more details about the SLA claim process?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sla02\n- Plan: Pro (€89/mo)"),
            "Do you offer an SLA? We need uptime guarantees for our business.",
            "Your current **Pro plan (€89/mo) does not include a formal SLA**. Here's the comparison:\n\n| Plan | SLA | Credit on breach |\n|------|-----|------------------|\n| Free / Developer / Pro | No formal SLA | — |\n| Growth (€229) | No formal SLA | — |\n| **Business (€699)** | **99.9% uptime** | 10% credit (€69.90/mo) |\n| **Enterprise Cloud (€1,750)** | **99.9% uptime** | 25% credit (€437.50/mo) |\n\n**While we don't guarantee uptime on Pro**, we maintain the same infrastructure for all plans and target 99.9%+ uptime across the board. Our historical uptime has consistently exceeded 99.95%.\n\n**If you need formal guarantees:**\n- **Business (€699/mo)**: 99.9% SLA with 10% credit on breach, plus priority async support, shared Slack hub, SSO/SAML, and 3 dedicated IPs\n- **Enterprise Cloud (€1,750/mo)**: Same 99.9% SLA but with 25% credit, dedicated CSM, and priority incident response\n\nThe SLA covers API availability, dashboard access, email sending, and webhook processing.\n\nWould you like to discuss upgrading to a plan with SLA guarantees?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sla03\n- Plan: Enterprise Cloud (€1,750/mo)\n- SLA: 99.9%"),
            "We had maintenance downtime last night that wasn't announced. Does that count against the SLA?",
            "That's a valid concern. Let me clarify the SLA maintenance policy:\n\n### Maintenance and SLA policy\n\n**Scheduled maintenance requirements:**\n- Must be announced **at least 72 hours in advance** via email and status page\n- Typically scheduled during low-traffic windows (weekends, early morning UTC)\n- Excluded from SLA calculations **only if properly announced**\n\n**If the downtime was NOT announced 72 hours in advance:**\n- ✅ It **does count** against your SLA\n- You may be eligible for a **25% credit** (€750) if total unplanned downtime this month exceeds 43.8 minutes\n\n**To verify and file a claim:**\nPlease email **support@apexmail.ee** with:\n- **Subject**: SLA Inquiry — Unannounced Maintenance — acct_sla03\n- **Include**: Date/time of the downtime, duration observed, and whether you received any advance notification\n\nOur operations team will cross-reference their maintenance logs and monitoring data. If the downtime was indeed unannounced, your SLA credit will be processed.\n\n**Your dedicated CSM** can also investigate this directly and expedite the resolution.\n\nWould you like me to help draft the email?"
        )
    },
])


# ---------------------------------------------------------------------------
# 9. TRIAL MANAGEMENT (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_trial01\n- Plan: Free (€0/mo)\n- Email usage: 12/3,000\n- Account created: 2025-02-15"),
            "Is there a free trial for the paid plans? I want to try Pro before committing.",
            "Great question! Here's how our plans work:\n\n### Free plan vs. trial\n\nApexMail doesn't offer a traditional time-limited free trial. Instead, we provide a **permanent Free plan** that you can use indefinitely:\n\n| Feature | Free (current) | Pro (€89/mo) |\n|---------|---------------|---------------|\n| Emails/mo | 3,000 | 150,000 |\n| API calls | 30,000 | 2,000,000 |\n| Domains | 1 | 25 |\n| Team | 1 | 10 |\n| A/B testing | ❌ | ❌ |\n| Send-time optimization | ❌ | ✅ |\n| Dedicated IP add-on | ❌ | ✅ (€49/mo) |\n| Retention | 7 days | 60 days |\n\n**The Free plan IS your trial** — you can test all core sending features, API integration, and deliverability at a small scale before upgrading.\n\n**When you're ready to upgrade:**\n- Upgrading is instant — no data migration needed\n- Your contacts, templates, and domains carry over\n- Billing starts immediately on a monthly cycle\n- You can downgrade or cancel anytime\n\nYou've used 1,200 of your 3,000 free emails this month. If you're hitting the limit, that's a good sign it's time to upgrade!\n\nWould you like to upgrade to Pro?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_trial02\n- Plan: Free (€0/mo)\n- Account created: 2025-03-01"),
            "Can I get a trial of the Enterprise Cloud plan? We need to test HIPAA compliance before buying.",
            "I need to stop you at the second half of that question, because testing HIPAA compliance is not something a trial can do here: **HIPAA is not currently offered on any ApexMail plan** — there is no BAA and no HIPAA mode to evaluate, at any price. An Enterprise trial would let you test infrastructure, not compliance features that don't exist.\n\n### What an Enterprise evaluation CAN cover\n\nWe don't offer self-service trials of Enterprise Cloud, but you can arrange a guided evaluation:\n\nEmail **support@apexmail.ee** with:\n- **Subject**: Enterprise Evaluation Request — Healthcare\n- **Include**: company size, expected email volume, and your actual requirements\n\nThe evaluation typically covers:\n1. Technical architecture walkthrough (dedicated IPs, BYOIP, isolation model)\n2. GDPR documentation (DPA, subprocessor register, data residency)\n3. Proof-of-concept setup\n4. Migration planning\n\n### If PHI is in scope for your sending\n- **Do NOT send PHI through ApexMail** — without a BAA that's a HIPAA violation on your side, and no ApexMail plan changes that today\n- If your volume is non-PHI (appointment reminders without health details, staff communications), the Free plan lets you test the core flow right now\n- If regulated workloads are a hard requirement, say so in the evaluation email — the team will tell you honestly whether ApexMail can ever fit, rather than discovering it post-signature\n\nShall I help you draft the evaluation request email?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_trial03\n- Plan: Free (€0/mo)\n- Email usage: 29/3,000\n- Account created: 2025-01-10"),
            "I've almost hit my free limit. What happens when I reach 3,000 emails?",
            "You're at 2,900 of your 3,000 free emails — only 100 left! Here's what happens:\n\n### When you hit the Free plan limit\n\n**Emails beyond 3,000 will be queued but not sent.** They'll remain in a pending state until:\n1. Your limit resets on the 10th of next month (your billing cycle), OR\n2. You upgrade to a paid plan\n\n**Your API calls also have a limit** (30,000/mo) — check that you're not close there too.\n\n### Your upgrade options\n\n| Plan | Price | Emails/mo | Best for |\n|------|-------|-----------|----------|\n| **Developer** | €20/mo | 50,000 | Small businesses, newsletters |\n| **Pro** | €89/mo | 150,000 | Growing businesses, send-time optimization |\n| **Growth** | €229/mo | 500,000 | High-volume senders |\n\n**Upgrading is instant:**\n- No data loss — everything carries over\n- Your remaining 100 free emails + new plan's allocation become immediately available\n- Billing starts today and recurs monthly\n\nBased on your usage (hitting 3K within a month), the **Developer plan at €20/mo** gives you 50,000 emails — plenty of room to grow.\n\nWould you like me to upgrade you to Developer?"
        )
    },
])


# ---------------------------------------------------------------------------
# 10. PAYMENT METHODS (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_pay01\n- Plan: Pro (€89/mo)\n- Billing cycle: Renews 15th"),
            "How do I update my credit card on file?",
            "You can update your payment method directly in the dashboard:\n\n### Updating your credit card\n\n1. Go to **Dashboard → Billing → Payment Methods**\n2. Click **\"Update Payment Method\"**\n3. Enter your new card details\n4. Click **\"Save\"**\n\nThe new card will be used for your next billing cycle (the 15th).\n\n**Accepted payment methods:**\n- Visa, Mastercard, American Express\n- Debit cards with Visa/MC network\n\n**If you're having trouble updating in the dashboard**, email **support@apexmail.ee** with:\n- **Subject**: Payment Method Update — acct_pay01\n- Our billing team can assist directly (never send full card numbers via email)\n\nIs there anything specific about the payment update you need help with?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_pay02\n- Plan: Growth (€229/mo)\n- Payment status: Failed — card declined on last renewal"),
            "My payment failed and I got an email about it. Will my account be suspended?",
            "I can see your last payment was declined. Here's what happens and how to fix it:\n\n### Failed payment process\n\n**Timeline:**\n1. **Day 0 (now)**: Payment failed — you received a notification email\n2. **Day 3**: First automatic retry attempt\n3. **Day 7**: Second retry attempt\n4. **Day 14**: Final retry + warning email\n5. **Day 21**: Account downgraded to Free plan if still unpaid\n\n**Your account is NOT suspended yet.** You have full access to all Growth plan features during the retry period. Email sending continues normally.\n\n### How to fix it\n\n**Option 1 (quickest)**: Update your payment method now\n1. Go to **Dashboard → Billing → Payment Methods**\n2. Add a new card or update the existing one\n3. Click **\"Retry Payment\"** to process immediately\n\n**Option 2**: Wait for the automatic retry on Day 3\n\n**If the card was declined due to:**\n- **Insufficient funds**: Ensure the card has at least €229 available\n- **Expired card**: Update with your new card details\n- **Bank block**: Some banks flag recurring international charges (we're based in Estonia) — call your bank to authorize it\n\nWould you like to update your payment method now?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_pay03\n- Plan: Developer (€20/mo)"),
            "Do you accept PayPal or wire transfers?",
            "Currently, ApexMail accepts the following payment methods:\n\n### Accepted payment methods\n- ✅ **Credit cards**: Visa, Mastercard, American Express\n- ✅ **Debit cards** with Visa/Mastercard network\n- ❌ **PayPal**: Not currently supported\n- ❌ **Wire transfers**: Not available for standard plans\n\n### For Enterprise Cloud customers (€1,750/mo)\nEnterprise accounts can arrange:\n- Annual invoicing with wire transfer/bank transfer\n- Purchase orders (PO)\n- Custom billing terms\n\nIf PayPal or wire transfer is a requirement for your organization, the Enterprise Cloud plan offers flexible billing. Otherwise, any major credit or debit card works for your Developer plan.\n\n**To discuss alternative payment arrangements**, email **support@apexmail.ee** with your requirements.\n\nWould you like help with anything else related to billing?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_pay04\n- Plan: Business (€699/mo)\n- Billing cycle: Renews 1st"),
            "Can I switch to annual billing? Is there a discount?",
            "Great question! Here's our billing options:\n\n### Annual vs. monthly billing\n\nApexMail offers annual billing at **10 months of the monthly price** — roughly a 17% discount.\n\n**However, for Enterprise Cloud accounts (€1,750/mo):**\n- Annual contract price starts at **€17,500/year**\n- The order form can include custom architecture terms for private cloud, BYOIP, or very high volume\n\n**For your Business plan (€699/mo):**\n- Monthly billing: €699/month\n- Annual billing: **€6,990/year** instead of €8,388/year\n- Savings: **€1,398/year**\n\nYou can switch eligible self-serve plans to annual billing from Dashboard → Billing. Enterprise annual contracts follow the signed order form.\n\nWould you like me to help with anything else?"
        )
    },
])


# ---------------------------------------------------------------------------
# 11. SEND-TIME OPTIMIZATION (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sto01\n- Plan: Pro (€89/mo)\n- Contacts: 35,000"),
            "How does send-time optimization work? I see it in my dashboard.",
            "Send-time optimization (STO) is an AI-powered feature on your Pro plan. Here's how it works:\n\n### How send-time optimization works\n\n**What it does:**\nInstead of sending your campaign to all contacts at the same time, STO delivers each email at the time that specific contact is most likely to open it.\n\n**How it learns:**\n1. ApexMail analyzes each contact's historical engagement patterns (opens, clicks)\n2. It identifies their optimal engagement window (e.g., \"Tuesdays 9-10 AM in their timezone\")\n3. For new contacts with no history, it uses aggregate patterns from similar profiles\n\n**How to use it:**\n1. Create your campaign as normal\n2. On the scheduling step, select **\"Optimize send time\"** instead of choosing a specific time\n3. Set a **delivery window** (e.g., \"Send within 24 hours\")\n4. ApexMail distributes sends across that window based on each contact's optimal time\n\n**Requirements:**\n- You need at least **some engagement history** for best results (ideally 3+ months)\n- Available on **Pro plan and above** (not on Free or Developer)\n- Works with timezone detection — contacts are grouped by their detected timezone\n\n**Best practices:**\n- Use a 24-hour window for best optimization\n- Don't use STO for time-sensitive emails (use immediate send instead)\n- Review the campaign report to see the actual send time distribution\n\nWith 35,000 contacts, you'll likely see a meaningful improvement in open rates. Want to try it on your next campaign?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sto02\n- Plan: Developer (€20/mo)"),
            "Is send-time optimization available on my plan?",
            "Send-time optimization is **not available on the Developer plan**. Here's the comparison:\n\n| Plan | Send-time optimization |\n|------|----------------------|\n| Free | ❌ |\n| Developer (€20) | ❌ |\n| **Pro (€89)** | ✅ |\n| Growth (€229) | ✅ |\n| Business (€699) | ✅ |\n| Enterprise Cloud (€1,750) | ✅ |\n\nSend-time optimization uses AI to deliver each email at the time a specific contact is most likely to engage, based on their historical open/click patterns.\n\n**On your Developer plan, you can still optimize manually:**\n- **Best general send times**: Tuesday–Thursday, 9-11 AM in your audience's primary timezone\n- Use your **campaign analytics** to identify when your audience opens most\n- Schedule campaigns based on those insights\n\n**To get STO**, the **Pro plan (€89/mo)** is the most affordable option — it also includes custom tracking domains, which pair well with send-time optimization.\n\nWould you like to upgrade to Pro?"
        )
    },
])


# ---------------------------------------------------------------------------
# 12. CONTACT LIMITS (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cl01\n- Plan: Pro (€89/mo)\n- Contacts: 48,500/50,000"),
            "I'm almost at my contact limit. What happens when I hit 50,000?",
            "You're at 48,500 of your 50,000 contact limit — getting close! Here's what happens:\n\n### When you hit your contact limit\n\n**New contacts will be rejected.** Specifically:\n- API calls to add contacts will return an error\n- CSV imports will partially fail (first contacts succeed, rest rejected)\n- Automation-added contacts (e.g., from forms) will fail silently\n\n**Existing contacts are NOT affected** — you can still send to all 48,500+ contacts.\n\n### Your options\n\n**1. Clean up your list** (free, immediate)\n- Remove inactive contacts who haven't engaged in 60+ days\n- Remove bounced/invalid emails\n- **Dashboard → Contacts → Segments** has a built-in \"inactive 60+ days\" segment, so you can review and delete candidates in a couple of clicks (I can't modify contacts from this chat — my tools are read-only)\n\n**2. Upgrade to Growth (€229/mo)**\n- 200,000 contacts (4× your current limit)\n- Plus: 500,000 emails/mo, 25 team members, 1 dedicated IP, audit logs\n\n### Contact limit comparison\n| Plan | Contact limit |\n|------|---------------|\n| Developer (€20) | 10,000 |\n| **Pro (€89)** | **50,000** ← you are here |\n| Growth (€229) | 200,000 |\n| Business (€699) | 500,000 |\n| Enterprise Cloud (€1,750) | Unlimited |\n\nWould you like me to help identify inactive contacts for cleanup, or discuss the Growth upgrade?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_cl02\n- Plan: Growth (€229/mo)\n- Contacts: 195,000/200,000"),
            "I have 195K contacts and growing. Will my list get cut off at 200K?",
            "Your list won't be cut — existing contacts stay, but new additions will be blocked at 200,000. Here's the detail:\n\n### Contact limit enforcement\n\n**At 200,000 contacts (your Growth limit):**\n- ❌ Cannot add new contacts (API errors, import rejection)\n- ✅ Can still email all existing contacts\n- ✅ Can still update existing contact data\n- ✅ Can remove contacts to make room\n\n**You have ~5,000 slots remaining.** At your growth rate, you may hit this within days.\n\n### Recommendations\n\n**Immediate: List hygiene**\n- Remove contacts that haven't opened in 90+ days\n- Purge bounced/invalid addresses\n- This can free up thousands of slots\n\n**If you need more capacity:**\n\n| Plan | Contacts | Price |\n|------|----------|-------|\n| Growth (current) | 200,000 | €229/mo |\n| **Business** | **500,000** | **€699/mo** |\n| Enterprise Cloud | Unlimited | €1,750/mo |\n\nThe **Business plan (€699/mo)** gives you 500K contacts, plus SSO/SAML, 3 dedicated IPs, priority async support, shared Slack hub, and subaccounts.\n\nWant me to analyze your contact list for cleanup opportunities?"
        )
    },
])


# ---------------------------------------------------------------------------
# 13. FEATURE REQUESTS (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_fr01\n- Plan: Pro (€89/mo)"),
            "Will ApexMail ever support SMS sending? I'd love that feature.",
            "Thanks for the suggestion! I appreciate you sharing what you'd like to see.\n\n**Currently, ApexMail focuses exclusively on email** — we don't offer SMS sending at this time, and I don't have information about future product roadmap items.\n\n**What I can suggest:**\n1. **Submit a feature request**: Email **support@apexmail.ee** with:\n   - **Subject**: Feature Request — SMS Sending\n   - Describe your use case and how you'd use SMS alongside email\n   - Feature requests are reviewed by our product team\n\n2. **In the meantime**, you can integrate an SMS service alongside ApexMail:\n   - Use webhooks to trigger SMS sends in an external service when email events occur\n   - Use the API to coordinate email + SMS campaigns from your own application\n\nI can't promise any specific features or timelines, but customer feedback directly shapes our roadmap. Is there anything else I can help with?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_fr02\n- Plan: Growth (€229/mo)"),
            "I wish the template editor had drag-and-drop blocks. Any plans for that?",
            "Thank you for the feedback! I don't have access to our product roadmap, so I can't confirm or deny specific upcoming features.\n\n**Current template options:**\n- **HTML editor**: Full control with raw HTML and CSS\n- **Dynamic variables**: Use `{{variable_name}}` for personalization\n- **Preview**: Test across email clients before sending\n- **API-based**: Create and update templates programmatically\n\n**To submit your feature request:**\nEmail **support@apexmail.ee** with:\n- **Subject**: Feature Request — Drag-and-Drop Template Builder\n- Describe your ideal workflow and any examples from other tools you've liked\n\nCustomer feedback is taken seriously and directly influences product priorities.\n\n**In the meantime**, if you need more visual template editing:\n- Design in a visual editor like MJML (free, open-source) and paste the compiled HTML into ApexMail\n- Use our template API to programmatically manage reusable components\n\nCan I help with anything else related to templates?"
        )
    },
])


# ---------------------------------------------------------------------------
# 14. MIGRATION FROM COMPETITORS (gap: minimal)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_mig01\n- Plan: Free (€0/mo)\n- Account created: 2025-03-10"),
            "I'm currently with Mailchimp and want to switch to ApexMail. What's the migration process?",
            "Welcome! Here's a step-by-step migration guide from Mailchimp to ApexMail:\n\n### Migration checklist\n\n**1. Export data from Mailchimp** (do this first)\n- **Contacts**: Audience → All Contacts → Export Audience → CSV\n- **Templates**: Campaigns → Email Templates → Export HTML for each\n- **Campaign history**: Download reports/analytics you want to keep\n- **Suppression lists**: Account → Compliance → Export bounces and complaints\n\n**2. Set up your ApexMail account**\n- Verify your sending domain(s): Dashboard → Domains → Add Domain\n- Set up SPF, DKIM, and DMARC DNS records (I can guide you through each)\n- Wait for DNS propagation (usually 15-60 minutes)\n\n**3. Import to ApexMail**\n- **Contacts**: Dashboard → Contacts → Import CSV (or use the API: `POST /v1/contacts/import`)\n- **Suppression lists**: Import bounces and complaints to maintain sender reputation\n- **Templates**: Recreate or paste HTML into new templates\n\n**4. Update DNS (important!)**\n- Point MX/sending records to ApexMail\n- Remove Mailchimp DNS records to avoid conflicts\n- Update any application code using the Mailchimp API to use the ApexMail API\n\n**5. Warm up (if using dedicated IP)**\n- Start with low volume and gradually increase over 2-4 weeks\n- ApexMail provides IP warmup guidance on Growth+ plans\n\n**Timeline**: Most migrations complete in 1-3 days for the technical setup, plus 2-4 weeks for IP warmup if applicable.\n\nWant me to help you get started with step 2 (domain verification)?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_mig02\n- Plan: Business (€699/mo)\n- Account created: 2025-02-01\n- Dedicated IPs: 3"),
            "We just migrated from SendGrid. Our deliverability is terrible — way worse than before. Help!",
            "Post-migration deliverability issues are common, especially with new IPs. Let me diagnose this with you.\n\n### Most likely causes after migration\n\n**1. IP warmup not complete**\nYou have 3 dedicated IPs that are likely new. ISPs don't trust new IPs:\n- **Days 1-7**: Send 5,000-10,000/day max, gradually increasing\n- **Weeks 2-3**: Scale to 50,000-100,000/day\n- **Week 4+**: Full volume\n- Are you sending at full volume immediately? That's the #1 post-migration mistake.\n\n**2. DNS configuration issues**\nCheck each domain's health in **Dashboard → Domains** (I can't pull your live DNS state from this chat — my tools are read-only):\n- SPF record must include ApexMail AND exclude old SendGrid entries\n- DKIM must be signed with ApexMail keys\n- DMARC policy should start at `p=none` during transition\n\n**3. Suppression list not imported**\n- Did you import your SendGrid bounce and complaint lists?\n- Sending to previously-bounced addresses destroys IP reputation\n- This is the most common migration oversight\n\n**4. Shared vs. dedicated IP change**\n- If you were on SendGrid's shared IPs (with good reputation) and now on new dedicated IPs, you start with zero reputation\n\n### Immediate action plan\n1. Share your sending domains — I'll check DNS and reputation\n2. Reduce daily volume immediately until warmup is complete\n3. Import any bounce/complaint lists from SendGrid\n4. Let's check your ISP-specific delivery rates\n\nWhat's your current daily send volume, and did you import suppression lists from SendGrid?"
        )
    },
])


# ---------------------------------------------------------------------------
# 15. MULTI-LANGUAGE / ENCODING (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_ml01\n- Plan: Growth (€229/mo)\n- Contacts: 95,000"),
            "I need to send emails in Japanese. Are there any encoding issues I should worry about?",
            "ApexMail fully supports international content including Japanese. Here's what you need to know:\n\n### Multi-language email support\n\n**Encoding:**\n- All emails are sent as **UTF-8** by default\n- UTF-8 supports all Japanese character sets: hiragana, katakana, kanji, and full-width characters\n- No special configuration needed — just include Japanese text in your template\n\n**Subject lines:**\n- Japanese characters in subject lines are fully supported\n- They're automatically encoded per RFC 2047 for email client compatibility\n- Keep subject lines concise — some email clients truncate earlier with CJK characters\n\n**Template tips for Japanese:**\n- Use `lang=\"ja\"` attribute in your HTML for proper font rendering\n- Specify Japanese-friendly fonts: `font-family: 'Hiragino Sans', 'Yu Gothic', 'Meiryo', sans-serif`\n- Avoid mixing half-width and full-width numbers/punctuation inconsistently\n\n**Personalization variables:**\n- `{{first_name}}`, `{{last_name}}` etc. work with Japanese names (stored as UTF-8)\n- Test with actual Japanese data to verify rendering\n\n**RTL support:**\n- Japanese is LTR so no special layout adjustments needed\n- If you also need Arabic/Hebrew (RTL), use `dir=\"rtl\"` in your HTML\n\nWould you like me to help set up a test email to verify Japanese rendering?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_ml02\n- Plan: Pro (€89/mo)"),
            "We send emails in Arabic. The text shows up reversed in some email clients. How do I fix this?",
            "Arabic text rendering issues are usually caused by missing RTL (right-to-left) directives. Here's how to fix it:\n\n### Fixing Arabic/RTL email rendering\n\n**1. Set the direction in your HTML template:**\n```html\n<html dir=\"rtl\" lang=\"ar\">\n<head>\n  <meta charset=\"utf-8\">\n  <style>\n    body {\n      direction: rtl;\n      text-align: right;\n      font-family: 'Tahoma', 'Arial', sans-serif;\n    }\n  </style>\n</head>\n<body>\n  <p>مرحباً {{first_name}}</p>\n</body>\n</html>\n```\n\n**2. Key elements:**\n- `dir=\"rtl\"` on the `<html>` tag for document-level direction\n- `direction: rtl` in CSS for consistent rendering\n- `text-align: right` to align text properly\n- `lang=\"ar\"` for proper font selection and hyphenation\n\n**3. Common pitfalls:**\n- **Mixed content**: If mixing Arabic and English, use `<bdo dir=\"ltr\">` for English sections\n- **Numbers**: Arabic numerals in LTR context can cause reordering — wrap in `<span dir=\"ltr\">`\n- **Tables**: Add `dir=\"rtl\"` to `<table>` elements separately\n- **Outlook**: Outlook desktop may need inline `direction:rtl` on each `<td>` element\n\n**4. Testing:**\nSend yourself a test from **Dashboard → Templates → your template → Send test** and open it in the clients your audience uses (Gmail web, Outlook desktop, Apple Mail) — rendering differs the most there. I can't send test emails from this chat (my tools are read-only).\n\nWould you like me to review your current template for RTL issues?"
        )
    },
])


# ---------------------------------------------------------------------------
# 16. REVENUE ATTRIBUTION / E-COMMERCE (gap: zero examples)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_rev01\n- Plan: Growth (€229/mo)\n- Email usage: 300,000/500,000"),
            "Can I track revenue from my email campaigns? Like seeing which emails drove purchases?",
            "Yes! ApexMail supports click tracking which you can use for revenue attribution. Here's how:\n\n### Setting up revenue tracking\n\n**1. Click tracking (built-in)**\n- ApexMail automatically tracks clicks in your emails\n- Use UTM parameters in your links:\n  ```\n  https://yourstore.com/product?utm_source=apexmail&utm_medium=email&utm_campaign=summer-sale\n  ```\n- View click reports in **Dashboard → Campaigns → [Campaign Name] → Click Map**\n\n**2. Conversion tracking via webhooks**\nSet up a webhook to receive real-time events:\n```\nPOST /v1/webhooks\n{\"url\": \"https://api.yourstore.com/email-events\", \"events\": [\"clicked\", \"opened\"]}\n```\nThen correlate clicks with purchases in your analytics system.\n\n**3. Integration with Google Analytics**\n- Add UTM parameters to all campaign links\n- In GA4: Acquisition → Traffic Acquisition → filter by `apexmail`\n- Track conversions, revenue, and ROI per campaign\n\n**4. Custom tracking domain** (available on your Growth plan)\n- Set up a branded tracking domain (e.g., `track.yourstore.com`)\n- Improves click-through rates and brand trust\n- Go to **Dashboard → Domains → Add Tracking Domain**\n\n**What ApexMail provides directly:**\n- ✅ Open tracking (pixel)\n- ✅ Click tracking (link wrapping)\n- ✅ Conversion webhooks\n- ❌ Built-in revenue dashboards (use GA4 or your analytics platform)\n\nWant me to help set up UTM parameters or a tracking webhook?"
        )
    },
])


# ---------------------------------------------------------------------------
# 17. GDPR / DATA PRIVACY (supplementing existing compliance coverage)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_gdpr01\n- Plan: Business (€699/mo)\n- Contacts: 380,000\n- Regions: EU, US, UK"),
            "One of our EU contacts submitted a GDPR data deletion request. How do we handle this?",
            "GDPR data deletion requests (\"right to erasure\") must be handled carefully. Here's the process:\n\n### Handling a GDPR deletion request\n\n**⚠️ Important**: Data deletion requests have legal obligations. You must respond within **30 days** under GDPR.\n\n**What you can do in the dashboard (I can't modify contacts from this chat — my tools are read-only):**\n1. **Remove the contact** from your ApexMail account: **Dashboard → Contacts → search the address → Delete**\n2. **Add them to the suppression list** so they're never contacted again: **Dashboard → Suppressions → Add**, reason \"GDPR deletion request\"\n\n**What you need to do:**\n1. Delete the contact's data from ALL your other systems too (CRM, analytics, backups)\n2. Confirm deletion to the requestor in writing within 30 days\n3. Document the request and your response for compliance records\n\n**For the formal legal process:**\nPlease also email **support@apexmail.ee** with:\n- **Subject**: GDPR Data Deletion Request — acct_gdpr01\n- Include the contact's email address\n- Our compliance team will ensure data is purged from all ApexMail systems (including backups within the next backup rotation cycle)\n\n**On your Business plan**, data is retained for 365 days in audit logs. The compliance team will handle log purging as part of the deletion process.\n\nWhat's the email address of the contact requesting deletion?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_gdpr02\n- Plan: Enterprise Cloud (€1,750/mo)"),
            "We need a Data Processing Agreement (DPA) for GDPR. Do you have one?",
            "Yes, ApexMail provides a Data Processing Agreement. Here's how to obtain it:\n\n### Data Processing Agreement (DPA)\n\n**For Enterprise Cloud customers:**\nYour dedicated CSM can provide the DPA directly. You can also email **support@apexmail.ee** with:\n- **Subject**: DPA Request — Enterprise Cloud — acct_gdpr02\n- Include your company's legal entity name and registered address\n\n**What our DPA covers:**\n- Data processing purposes and scope\n- Sub-processor list and notification obligations\n- Data security measures (encryption at rest and in transit)\n- Data breach notification procedures (within 72 hours per GDPR)\n- Data subject rights facilitation\n- Data return and deletion on termination\n- Cross-border transfer mechanisms (Standard Contractual Clauses)\n\n**Compliance features relevant to GDPR (same posture on every plan):**\n- ✅ DPA available\n- ✅ Data encryption (AES-256 at rest, TLS 1.2+ in transit)\n- ✅ Signed audit logs (730-day retention on your Enterprise Cloud plan)\n- ✅ EU/EEA data processing\n\n**Equally important — what we are NOT:** ApexMail is not SOC 2 certified and HIPAA is not currently offered on any plan. If your vendor registry asks about either, that's the answer to record; the DPA and the subprocessor register are the compliance artifacts that do exist.\n\n**Data residency note:**\nApexMail processes data within the EU/EEA.\n\nWould you like me to help with anything else related to GDPR compliance?"
        )
    },
])


# ---------------------------------------------------------------------------
# 18. ADDITIONAL BILLING (supplement complex_billing in stress_test)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_bill01\n- Plan: Pro (€89/mo)\n- Email usage: 165,000/150,000 (over limit)\n- Billing cycle: Renews 20th"),
            "I went over my email limit. How much extra will I be charged?",
            "You've sent 165,000 emails against your Pro plan limit of 150,000. Here's the overage calculation:\n\n### Overage breakdown\n\n| Item | Amount |\n|------|--------|\n| Pro plan base | €89.00 |\n| Emails over limit | 165,000 - 150,000 = **15,000 extra** |\n| Overage rate | €0.60 per 1,000 emails |\n| Overage charge | 15,000 × €0.0006 = **€9.00** |\n| **Total bill** | **€98.00** |\n\n**How overages work:**\n- Your plan includes 150,000 emails/month\n- Any emails beyond that are charged at **€0.80 (Developer) / €0.60 (Pro) / €0.35 (Growth+) per 1,000**\n- Overages are billed at the end of your billing cycle (the 20th)\n- Overage is billed per email (e.g., 15,001 extra = €9.01)\n\n**To avoid future overages:**\n1. **Monitor usage** in Dashboard → Usage\n2. **Set up alerts** to notify you at 80% and 90% of your limit\n3. **Consider upgrading**: Growth plan (€229/mo) includes 500,000 emails — more than enough headroom\n\nOn Growth, your 165K emails would have no overage and you'd save vs. paying overages every month.\n\nWould you like to discuss upgrading?"
        )
    },
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_bill02\n- Plan: Growth (€229/mo)\n- Email usage: 620,000/500,000\n- API calls: 5,200,000/5,000,000\n- Billing cycle: Renews 5th"),
            "I'm over my limits on both emails and API calls. What's my total bill going to be?",
            "Let me calculate your total bill with both overages:\n\n### Bill breakdown\n\n**Email overage:**\n| Item | Amount |\n|------|--------|\n| Growth plan base | €229.00 |\n| Emails over limit | 620,000 - 500,000 = 120,000 extra |\n| Email overage | 120,000 × €0.00035 = **€42.00** |\n\n**API overage:**\n| Item | Amount |\n|------|--------|\n| API calls over limit | 5,200,000 - 5,000,000 = 200,000 extra |\n| First 30,000 | **Free** (grace buffer) |\n| Remaining 170,000 | 170 × €0.10 = **€17.00** |\n\n**Total:**\n| Component | Cost |\n|-----------|------|\n| Growth base | €229.00 |\n| Email overage | €42.00 |\n| API overage | €17.00 |\n| **Total** | **€288.00** |\n\n**Comparison with Business plan (€699/mo):**\n- 2,000,000 emails/mo (vs your 620K used)\n- 20,000,000 API calls/mo (vs your 5.2M used)\n- Zero overages = €699 flat\n\nAt €288 on Growth, you're still cheaper than Business. Business becomes the better deal once your Growth overages regularly push the total above €699/mo.\n\nWant me to help you analyze your volume trend?"
        )
    },
])


# ---------------------------------------------------------------------------
# 19. ADDITIONAL SECURITY (supplement existing security_awareness)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_sec01\n- Plan: Business (€699/mo)\n- API keys: 5 active"),
            "I think one of our API keys was compromised. What should I do?",
            "**This is urgent — let's act immediately.** Here's the response plan:\n\n### Compromised API key response\n\n**Step 1: Identify and revoke the key immediately**\nGo to **Dashboard → API Keys** (you have 5 active keys listed there). Find the suspected key by name or prefix and click **Revoke**. I can't revoke keys from this chat — my tools are read-only — and honestly, that's the right design for a destructive security action: it should be your hands on the button.\n**⚠️ Warning**: Revoking is permanent. Any applications using this key will immediately lose access.\n\n**Step 2: Generate a replacement**\nStill in **Dashboard → API Keys → Create key** — scope it to only what the application needs instead of reusing broad scopes.\n\n**Step 3: Audit recent activity**\nReview **Dashboard → Analytics** for the last 7 days for send spikes or unusual API patterns.\n\n**Step 4: Broader security review**\n- Rotate ALL API keys as a precaution\n- Check webhook endpoints for any unauthorized additions\n- Review team member list for any unauthorized accounts\n- Enable 2FA if not already active\n\n**Step 5: Escalate to security team**\nPlease also email **support@apexmail.ee** with:\n- **Subject**: URGENT — Possible API Key Compromise — acct_sec01\n- Include: when you noticed, what suspicious activity you saw, which key\n\nOur security team will investigate server-side logs for unauthorized access.\n\n**Which key looked compromised? I can help you interpret its recent activity while you revoke it.**"
        )
    },
])


# ---------------------------------------------------------------------------
# 20. ONBOARDING (supplement existing)
# ---------------------------------------------------------------------------

EXAMPLES.extend([
    {
        "text": chatml(
            build_system_prompt(inline_context="## Customer context\n### Account\n- Account ID: acct_onb01\n- Plan: Developer (€20/mo)\n- Account created: Today\n- Email usage: 0/50,000\n- Domains: 0 verified"),
            "I just signed up. What should I do first?",
            "Welcome to ApexMail! Here's your step-by-step onboarding checklist:\n\n### Getting started — first 30 minutes\n\n**Step 1: Verify your sending domain** (5 min)\nThis is the most important step — you can't send emails without a verified domain.\n1. Go to **Dashboard → Domains → Add Domain**\n2. Enter your domain (e.g., `mail.yourcompany.com`)\n3. Add the DNS records ApexMail provides:\n   - **SPF**: TXT record for sender authorization\n   - **DKIM**: TXT record for email signing\n   - **DMARC**: TXT record for policy (recommended: start with `p=none`)\n4. Wait for verification (usually 15-60 minutes)\n\nThe **Domains page also shows the exact DNS records to publish** (or you can fetch them from the `POST /v1/domains/dns-records` API endpoint) — I can't look up live DNS state from this chat, but once verification finishes the page flips to green.\n\n**Step 2: Import your contacts** (10 min)\n- Go to **Dashboard → Contacts → Import**\n- Upload a CSV with at minimum: email, first_name, last_name\n- Your Developer plan supports up to 10,000 contacts\n\n**Step 3: Create your first template** (10 min)\n- Go to **Dashboard → Templates → Create**\n- Write your HTML or use our basic editor\n- Add personalization: `{{first_name}}`, `{{company_name}}`\n\n**Step 4: Send a test email** (2 min)\n- Before sending to your list, send a test to yourself\n- Verify formatting, links, and deliverability\n\n**Step 5: Create and send your first campaign** (5 min)\n- Go to **Dashboard → Campaigns → Create**\n- Select your template, audience, and schedule\n\n**Your Developer plan includes:** 50,000 emails/mo, 5 webhooks, 5 domains, 5 team members, email support.\n\nWhat's your sending domain? Let me help you set it up!"
        )
    },
])


# ═══════════════════════════════════════════════════════════════════════════════
# WRITE TO JSONL
# ═══════════════════════════════════════════════════════════════════════════════

def _enforce_canonical() -> None:
    """Fail closed if any generated example carries non-canonical truth.

    Three gates, all derived from registries (audit-6 #9):
      1. pricing — validate_pricing_in_text against CANONICAL_PRICING;
      2. product/compliance truth — canonical_truth.truth_problems_in_text
         (tools outside the REAL chat registry; HIPAA/BAA/SOC 2/ISO 27001
         availability the capability registry does not back), checked over
         each example's system+assistant text AND every shared
         EXAMPLE_CONTEXTS profile so no prompt surface reintroduces it;
      3. pricing-registry parity — the marketing pricing.json must agree
         with the canonical catalog, or regeneration stops.
    """
    problems = []
    for index, ex in enumerate(EXAMPLES, 1):
        text = ex.get("text", "")
        for finding in validate_pricing_in_text(text, source=f"example {index}"):
            problems.append(f"{finding['source']}: {finding['message']}")
        # The CUSTOMER turn may ask for anything; only the system prompt and
        # the assistant turn assert product truth.
        assertable = canonical_truth.assertable_text(text)
        for finding in canonical_truth.truth_problems_in_text(
            assertable, source=f"example {index}"
        ):
            problems.append(f"{finding['source']}: {finding['message']}")
    for key in sorted(EXAMPLE_CONTEXTS):
        for finding in canonical_truth.truth_problems_in_text(
            _fmt(EXAMPLE_CONTEXTS[key]), source=f"profile {key}"
        ):
            problems.append(f"{finding['source']}: {finding['message']}")
    for finding in canonical_truth.pricing_drift_problems():
        problems.append(f"{finding['source']}: {finding['message']}")
    if problems:
        for problem in problems[:10]:
            log.error("canonical truth violation: %s", problem)
        sys.exit(1)


def main() -> None:
    _enforce_canonical()
    output_path = TRAIN_JSONL
    
    # Read existing
    try:
        with open(output_path) as f:
            existing = [json.loads(line) for line in f if line.strip()]
    except FileNotFoundError:
        log.warning("%s not found — starting with empty dataset", output_path)
        existing = []
    except json.JSONDecodeError as exc:
        log.error("Failed to parse %s: %s", output_path, exc)
        sys.exit(1)
    
    # Build dedup set from existing records' text fields
    existing_texts: set[str] = set()
    for rec in existing:
        if "text" in rec:
            existing_texts.add(rec["text"])
    
    log.info("Existing training examples: %d", len(existing))
    log.info("New examples to add: %d", len(EXAMPLES))
    
    # Filter new examples against existing (dedup by text field)
    deduped_new: list[dict] = []
    skipped = 0
    for ex in EXAMPLES:
        if "text" in ex and ex["text"] in existing_texts:
            skipped += 1
            continue
        deduped_new.append(ex)
        if "text" in ex:
            existing_texts.add(ex["text"])
    
    all_examples = existing + deduped_new
    
    # Write back
    try:
        with open(output_path, "w") as f:
            for ex in all_examples:
                f.write(json.dumps(ex) + "\n")
    except OSError as exc:
        log.error("Failed to write %s: %s", output_path, exc)
        sys.exit(1)
    
    log.info("Total training examples: %d", len(all_examples))
    log.info("  (skipped %d duplicates already in dataset)", skipped)
    log.info("Written to %s", output_path)


if __name__ == "__main__":
    main()
