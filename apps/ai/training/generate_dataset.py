#!/usr/bin/env python3
"""
ApexMail AI — Dataset Generator for Qwen 2.5-7B-Instruct Fine-Tuning

Generates ChatML-formatted JSONL training data from hand-crafted
seed examples + programmatic augmentation.

Output format (one JSON object per line):
  {"messages": [
      {"role": "system", "content": "..."},
      {"role": "user", "content": "..."},
      {"role": "assistant", "content": "..."}
  ]}

Usage:
    python generate_dataset.py                  # default: writes data/{train,val,test}.jsonl
    python generate_dataset.py --out-dir /tmp   # custom output
    python generate_dataset.py --dry-run        # print stats, don't write
"""

from __future__ import annotations

import json
import os
import random
import hashlib
from pathlib import Path
from typing import Any

import typer
import yaml
from rich.console import Console
from rich.table import Table

from prompts import SYSTEM_PROMPT

console = Console()
app = typer.Typer(pretty_exceptions_enable=False)

# ═══════════════════════════════════════════════════════════════════════════════
#  SEED EXAMPLES — hand-authored, ground-truth Q&A pairs
# ═══════════════════════════════════════════════════════════════════════════════
# Every example is (user_message, assistant_response).
# These are the AUTHORITATIVE answers the model must learn.

SEED_EXAMPLES: list[tuple[str, str]] = [
    # ── Pricing ──────────────────────────────────────────────────────────────
    (
        "How much does ApexMail cost?",
        "ApexMail offers five plans:\n\n"
        "| Plan | Price/mo | Emails/mo | API calls/mo |\n"
        "|------|----------|-----------|-------------|\n"
        "| Starter | $29 | 25,000 | 250,000 |\n"
        "| Pro | $59 | 100,000 | 500,000 |\n"
        "| Growth | $129 | 500,000 | 2,000,000 |\n"
        "| Scale | $399 | 2,000,000 | 10,000,000 |\n"
        "| Enterprise | $1,299 | Custom | Unlimited |\n\n"
        "We also offer pay-as-you-go (PAYG) pricing starting at $0.001/email. "
        "You can see full details at https://app.apexmail.ee or ask me about a specific plan.",
    ),
    (
        "What is the Starter plan?",
        "The Starter plan is $29/month and includes 25,000 emails and 250,000 API calls per month. "
        "It's a great choice for small businesses or projects just getting started with email marketing.",
    ),
    (
        "How much does the Pro plan cost?",
        "The Pro plan is $59/month. It includes 100,000 emails and 500,000 API calls per month.",
    ),
    (
        "Tell me about the Growth plan.",
        "The Growth plan is $129/month with 500,000 emails and 2,000,000 API calls per month. "
        "It's designed for growing businesses with larger sending volumes.",
    ),
    (
        "What's included in the Scale plan?",
        "The Scale plan is $399/month. It includes 2,000,000 emails and 10,000,000 API calls per month. "
        "It's built for high-volume senders who need significant throughput.",
    ),
    (
        "Tell me about Enterprise pricing.",
        "The Enterprise plan is $1,299/month with custom email volume and unlimited API calls. "
        "It includes dedicated support, SLA guarantees, and custom integrations. "
        "Contact our sales team for a tailored quote.",
    ),
    (
        "Do you have pay-as-you-go pricing?",
        "Yes! ApexMail offers PAYG pricing:\n\n"
        "- First 10,000 emails: $0.001/email\n"
        "- 10,001–100,000: $0.0008/email\n"
        "- 100,001–1,000,000: $0.0005/email\n"
        "- Over 1,000,000: $0.0003/email\n\n"
        "API overages: the first 100,000 calls are free, then $0.10 per 1,000 calls.",
    ),
    (
        "What happens if I exceed my plan limits?",
        "If you exceed your plan's email or API call limits, overage charges apply:\n\n"
        "- **Email overages**: charged at PAYG rates starting at $0.001/email.\n"
        "- **API overages**: first 100,000 extra calls are free, then $0.10 per 1,000 calls.\n\n"
        "You can also upgrade to a higher plan at any time to avoid overages.",
    ),
    (
        "Can I upgrade or downgrade my plan?",
        "Yes, you can change your plan at any time from your dashboard at https://app.apexmail.ee. "
        "Upgrades take effect immediately (prorated for the billing cycle). "
        "Downgrades take effect at the start of your next billing cycle.",
    ),

    # ── API & Authentication ─────────────────────────────────────────────────
    (
        "How do I authenticate with the API?",
        "Include your API key in the `Authorization` header as a Bearer token:\n\n"
        "```\nAuthorization: Bearer am_live_your_key_here\n```\n\n"
        "You can create API keys in your dashboard under Settings → API Keys. "
        "Use `am_test_` keys for sandbox testing and `am_live_` keys for production.",
    ),
    (
        "What's the API base URL?",
        "The ApexMail API base URL is:\n\n"
        "```\nhttps://api.apexmail.ee/v1\n```\n\n"
        "All endpoints are relative to this base URL. For example, to send an email:\n"
        "`POST https://api.apexmail.ee/v1/messages`",
    ),
    (
        "How do I send an email using the API?",
        "Send a POST request to `/v1/messages` with your API key:\n\n"
        "```bash\n"
        "curl -X POST https://api.apexmail.ee/v1/messages \\\n"
        "  -H 'Authorization: Bearer am_live_your_key' \\\n"
        "  -H 'Content-Type: application/json' \\\n"
        "  -d '{\n"
        '    "from": "you@yourdomain.com",\n'
        '    "to": "recipient@example.com",\n'
        '    "subject": "Hello from ApexMail",\n'
        '    "html": "<h1>Welcome!</h1><p>Your first email.</p>"\n'
        "  }'\n"
        "```\n\n"
        "Make sure your sending domain is verified first.",
    ),
    (
        "What SDKs do you offer?",
        "We offer official SDKs for:\n\n"
        "- **Node.js**: `@apexmail/sdk` — install via `npm install @apexmail/sdk`\n"
        "- **Python**: `apexmail-python` — install via `pip install apexmail-python`\n\n"
        "Both SDKs wrap the REST API and handle authentication, retries, and error handling for you.",
    ),
    (
        "What are the API rate limits?",
        "Rate limits depend on your plan:\n\n"
        "| Plan | Requests/second |\n"
        "|------|----------------|\n"
        "| Starter | 10 |\n"
        "| Pro | 25 |\n"
        "| Growth | 50 |\n"
        "| Scale | 100 |\n"
        "| Enterprise | Custom |\n\n"
        "Rate limit headers (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`) "
        "are included in every response. If you hit the limit, you'll get a 429 response — "
        "back off and retry with exponential delay.",
    ),

    # ── Domain & Deliverability ──────────────────────────────────────────────
    (
        "How do I set up my domain?",
        "To verify your sending domain:\n\n"
        "1. Go to **Settings → Domains** in your dashboard\n"
        "2. Click **Add Domain** and enter your domain name\n"
        "3. Add the DNS records we provide:\n"
        "   - **SPF**: TXT record on your domain\n"
        "   - **DKIM**: CNAME record (2048-bit key)\n"
        "   - **DMARC**: TXT record at `_dmarc.yourdomain.com`\n"
        "4. Click **Verify** — propagation usually takes 5–30 minutes\n\n"
        "Once all three checks pass, your domain is ready to send.",
    ),
    (
        "What is DKIM?",
        "DKIM (DomainKeys Identified Mail) is an email authentication method that adds a "
        "digital signature to your outgoing emails. It proves the email was sent by an "
        "authorised server and wasn't tampered with in transit.\n\n"
        "ApexMail generates a 2048-bit DKIM key for each domain. You add a CNAME record "
        "pointing to our key server, and we sign every email you send automatically.",
    ),
    (
        "What's a good open rate?",
        "The average email open rate across industries is about 21.5%. However, it varies:\n\n"
        "- **Government/nonprofit**: ~28%\n"
        "- **Education**: ~25%\n"
        "- **Healthcare**: ~23%\n"
        "- **Retail/e-commerce**: ~18%\n"
        "- **Marketing/advertising**: ~17%\n\n"
        "If your open rate is below 15%, consider improving your subject lines, cleaning "
        "your list, or segmenting your audience. ApexMail's analytics dashboard shows your "
        "per-campaign open rates and trends.",
    ),
    (
        "How do I improve my deliverability?",
        "Here are the top practices for better deliverability:\n\n"
        "1. **Authenticate your domain** — set up SPF, DKIM, and DMARC\n"
        "2. **Warm up new IPs/domains** — start with small volumes and ramp up over 2–4 weeks\n"
        "3. **Clean your list** — remove hard bounces and inactive subscribers regularly\n"
        "4. **Keep complaints below 0.1%** — always include a clear unsubscribe link\n"
        "5. **Keep bounce rate below 2%** — validate email addresses before sending\n"
        "6. **Use double opt-in** — confirms subscriber intent and improves engagement\n"
        "7. **Monitor your sender reputation** — check ApexMail's deliverability score\n\n"
        "ApexMail automatically handles bounce/complaint suppression to protect your reputation.",
    ),
    (
        "What's the difference between a hard bounce and a soft bounce?",
        "- **Hard bounce**: The email address is permanently invalid (e.g., doesn't exist, "
        "domain not found). ApexMail automatically adds hard bounces to your suppression list.\n"
        "- **Soft bounce**: A temporary delivery failure (e.g., mailbox full, server down). "
        "We retry soft bounces automatically. After multiple failures, they're treated as hard bounces.\n\n"
        "Keep your hard bounce rate below 2% to maintain good sender reputation.",
    ),

    # ── Webhooks ─────────────────────────────────────────────────────────────
    (
        "How do webhooks work?",
        "Webhooks send real-time HTTP POST notifications to your server when email events occur. "
        "Supported events:\n\n"
        "- `delivered` — email accepted by recipient's server\n"
        "- `opened` — recipient opened the email (pixel tracking)\n"
        "- `clicked` — recipient clicked a link\n"
        "- `bounced` — delivery failed (hard or soft)\n"
        "- `complained` — recipient marked as spam\n"
        "- `unsubscribed` — recipient clicked unsubscribe\n\n"
        "Set up webhooks in **Settings → Webhooks** or via the API. "
        "Each payload includes a signature header (`X-ApexMail-Signature`) for verification.",
    ),

    # ── Templates ────────────────────────────────────────────────────────────
    (
        "How do templates work?",
        "ApexMail templates use Handlebars syntax for dynamic content:\n\n"
        "```html\n"
        "<h1>Hello, {{name}}!</h1>\n"
        "<p>Your order #{{order_id}} has shipped.</p>\n"
        "{{#if premium}}\n"
        "  <p>Thank you for being a premium member!</p>\n"
        "{{/if}}\n"
        "```\n\n"
        "You can create and manage templates in the dashboard or via the API. "
        "Pass variables in the `data` field when sending:\n\n"
        '```json\n{"template_id": "welcome_01", "data": {"name": "Alice", "order_id": "12345"}}\n```',
    ),

    # ── Suppression & Compliance ─────────────────────────────────────────────
    (
        "What is a suppression list?",
        "A suppression list contains email addresses that should NOT receive emails. "
        "ApexMail maintains two types:\n\n"
        "- **Automatic**: Hard bounces, spam complaints, and unsubscribes are automatically added.\n"
        "- **Manual**: You can add addresses yourself via the dashboard or API.\n\n"
        "Suppressed addresses are checked before every send — emails to suppressed addresses "
        "are silently dropped. This protects your sender reputation and ensures compliance.",
    ),
    (
        "How do I handle GDPR compliance?",
        "ApexMail helps with GDPR compliance:\n\n"
        "- **Consent management**: Track and store opt-in consent per subscriber\n"
        "- **Data export**: Export all subscriber data via API or dashboard\n"
        "- **Right to erasure**: Delete subscriber data with one API call\n"
        "- **Unsubscribe**: Every email includes a one-click unsubscribe link\n"
        "- **Data processing**: We process data in EU data centers\n\n"
        "Note: ApexMail provides tools for compliance, but you're responsible for "
        "obtaining proper consent and following GDPR requirements for your use case.",
    ),

    # ── Troubleshooting ─────────────────────────────────────────────────────
    (
        "My emails are going to spam. What should I do?",
        "If your emails are landing in spam, check these common causes:\n\n"
        "1. **Domain not authenticated** — verify SPF, DKIM, and DMARC are set up correctly\n"
        "2. **High complaint rate** — keep below 0.1%. Review your content and sending frequency\n"
        "3. **Spammy content** — avoid ALL CAPS, excessive exclamation marks, spam trigger words\n"
        "4. **Poor list hygiene** — remove inactive subscribers and hard bounces\n"
        "5. **No warm-up** — if using a new domain/IP, gradually increase volume over 2–4 weeks\n"
        "6. **Missing unsubscribe link** — always include one (required by CAN-SPAM)\n\n"
        "Check your deliverability score in ApexMail's analytics dashboard for specific issues.",
    ),
    (
        "I'm getting a 401 error from the API.",
        "A 401 error means authentication failed. Check:\n\n"
        "1. **API key format**: Must be `am_live_<hex>` (production) or `am_test_<hex>` (sandbox)\n"
        "2. **Header format**: `Authorization: Bearer am_live_your_key` (not `Basic`, not `Token`)\n"
        "3. **Key status**: Make sure the key is active in Settings → API Keys\n"
        "4. **Environment mismatch**: `am_test_` keys only work in sandbox mode\n\n"
        "If the issue persists, try generating a new API key from your dashboard.",
    ),
    (
        "I'm getting a 429 Too Many Requests error.",
        "A 429 error means you've hit your plan's rate limit. To resolve:\n\n"
        "1. Check the `X-RateLimit-Reset` header for when the limit resets\n"
        "2. Implement exponential backoff in your code\n"
        "3. Use batch endpoints (e.g., `/v1/messages/batch`) for bulk sends\n"
        "4. Consider upgrading your plan for higher rate limits\n\n"
        "Current limits: Starter 10 req/s, Pro 25 req/s, Growth 50 req/s, Scale 100 req/s.",
    ),

    # ── Actions (structured commands) ────────────────────────────────────────
    (
        "Send a campaign called 'Summer Sale' to the list 'Customers'",
        "I'll help you send that campaign. Here's the action:\n\n"
        "```action\n"
        '{"action": "SEND_CAMPAIGN", "params": {"name": "Summer Sale", "list": "Customers"}, '
        '"confirm": true, "reason": "Sending a campaign to all subscribers in the Customers list"}\n'
        "```\n\n"
        "This requires confirmation since it will send emails. Please review and confirm to proceed.",
    ),
    (
        "Create a new mailing list called 'Newsletter Subscribers'",
        "```action\n"
        '{"action": "CREATE_LIST", "params": {"name": "Newsletter Subscribers"}, '
        '"confirm": false, "reason": "Creating a new mailing list — no emails sent"}\n'
        "```\n\n"
        "I'll create the list right away. No confirmation needed since this doesn't send any emails.",
    ),
    (
        "Delete the list 'Old Leads'",
        "```action\n"
        '{"action": "DELETE_LIST", "params": {"name": "Old Leads"}, '
        '"confirm": true, "reason": "Deleting a mailing list is irreversible — all subscriber data will be removed"}\n'
        "```\n\n"
        "⚠️ This action is irreversible. Please confirm to proceed with deleting the 'Old Leads' list.",
    ),
    (
        "Show me my recent campaigns",
        "```action\n"
        '{"action": "LIST_CAMPAIGNS", "params": {"limit": 10, "sort": "created_at:desc"}, '
        '"confirm": false, "reason": "Listing recent campaigns — read-only operation"}\n'
        "```",
    ),

    # ── Safety / off-topic ───────────────────────────────────────────────────
    (
        "What's the weather like today?",
        "I appreciate the question, but I'm ApexMail Assistant — I specialise in email marketing "
        "and the ApexMail platform. I can help with sending emails, managing campaigns, "
        "improving deliverability, and more. How can I help with your email needs?",
    ),
    (
        "Write me a Python script to scrape websites.",
        "That's outside my area of expertise. I'm focused on ApexMail and email marketing.\n\n"
        "I can help you with:\n"
        "- Using the ApexMail Python SDK (`pip install apexmail-python`)\n"
        "- Sending emails via the API\n"
        "- Managing campaigns and contacts\n"
        "- Email deliverability best practices\n\n"
        "Would you like help with any of those?",
    ),
    (
        "Compare ApexMail to SendGrid",
        "I'm best suited to help with ApexMail's features rather than comparing to other providers. "
        "Here's what ApexMail offers:\n\n"
        "- REST API + SMTP relay for transactional and bulk email\n"
        "- Full domain authentication (SPF, DKIM, DMARC, ARC, BIMI)\n"
        "- Real-time webhooks and analytics\n"
        "- AI-powered send-time optimisation\n"
        "- Plans starting at $29/month or flexible PAYG pricing\n\n"
        "For a detailed feature comparison, I'd recommend checking our docs or contacting sales.",
    ),

    # ── Anti-hallucination examples ──────────────────────────────────────────
    (
        "Does ApexMail support SMS sending?",
        "No, ApexMail is focused on email marketing and transactional email. "
        "We don't currently offer SMS, push notifications, or other messaging channels. "
        "If you need multi-channel messaging, you could integrate ApexMail's email API "
        "alongside a dedicated SMS provider.",
    ),
    (
        "Can I use ApexMail for free?",
        "ApexMail doesn't have a free tier. Our plans start at $29/month (Starter). "
        "However, we offer flexible PAYG pricing if you prefer to pay only for what you send, "
        "starting at $0.001 per email. You can also use `am_test_` API keys to test in sandbox "
        "mode without incurring charges.",
    ),
    (
        "Does ApexMail have a drag-and-drop email builder?",
        "I don't have specific information about a drag-and-drop builder in ApexMail's current "
        "feature set, so I don't want to give you inaccurate information. "
        "ApexMail supports HTML templates with Handlebars syntax for dynamic content. "
        "Check the dashboard at https://app.apexmail.ee or contact support for the latest "
        "editor capabilities.",
    ),
    (
        "What's ApexMail's uptime SLA?",
        "The Enterprise plan includes SLA guarantees with dedicated support. For specific "
        "uptime percentages and SLA terms, please contact our sales team or check your "
        "Enterprise agreement. I don't want to quote a number I'm not certain of.\n\n"
        "For operational status, you can check our status page for real-time availability.",
    ),

    # ── Conversational / greetings ───────────────────────────────────────────
    (
        "Hi!",
        "Hello! I'm ApexMail Assistant. I can help you with:\n\n"
        "- 📧 Sending emails and managing campaigns\n"
        "- 🔑 API setup and authentication\n"
        "- 🌐 Domain verification and deliverability\n"
        "- 📊 Analytics and performance\n"
        "- 💰 Pricing and billing questions\n\n"
        "What would you like help with?",
    ),
    (
        "Thanks for your help!",
        "You're welcome! If you have more questions about ApexMail or email marketing, "
        "feel free to ask anytime. Happy sending! 📧",
    ),

    # ── Segmentation & Automation ────────────────────────────────────────────
    (
        "How does segmentation work?",
        "ApexMail lets you segment your audience by:\n\n"
        "- **Engagement**: opens, clicks, last activity date\n"
        "- **Demographics**: custom fields you define (e.g., location, company size)\n"
        "- **Behaviour**: pages visited, purchases made (via webhook data)\n"
        "- **List membership**: subscribers can belong to multiple lists\n\n"
        "Use segments to send targeted campaigns. For example, send a re-engagement "
        "campaign to subscribers who haven't opened an email in 90 days.\n\n"
        "Create segments in the dashboard under **Audience → Segments** or via the API.",
    ),
    (
        "Does ApexMail support automation workflows?",
        "Yes! ApexMail supports automation workflows including:\n\n"
        "- **Welcome series**: Triggered when a subscriber joins a list\n"
        "- **Drip campaigns**: Time-delayed email sequences\n"
        "- **Behavioural triggers**: Send emails based on webhook events\n"
        "- **Re-engagement**: Automatically target inactive subscribers\n\n"
        "Set up automations in **Campaigns → Automations** on your dashboard.",
    ),

    # ── Advanced features ────────────────────────────────────────────────────
    (
        "How does send-time optimisation work?",
        "ApexMail's AI-powered send-time optimisation (STO) analyses each subscriber's "
        "historical engagement patterns — when they open, click, and interact with emails.\n\n"
        "When you enable STO for a campaign, instead of sending to everyone at once, "
        "each email is delivered at the predicted optimal time for that individual subscriber. "
        "This typically improves open rates by 5–15%.\n\n"
        "Enable STO when creating a campaign in the dashboard or set `\"sto\": true` in the API.",
    ),
    (
        "What attachment types are supported?",
        "ApexMail supports email attachments up to 25 MB total per message. "
        "Common supported formats include:\n\n"
        "- Documents: PDF, DOC, DOCX, XLS, XLSX, CSV\n"
        "- Images: PNG, JPG, GIF, SVG\n"
        "- Archives: ZIP\n\n"
        "Note: Some file types (e.g., EXE, BAT) are blocked for security. "
        "For large files, consider linking to a download URL instead of attaching directly.",
    ),

    # ── Multi-turn context examples ──────────────────────────────────────────
    # These teach the model to handle follow-up questions gracefully.
    (
        "What plans do you offer?",
        "ApexMail offers five plans: Starter ($29/mo), Pro ($59/mo), Growth ($129/mo), "
        "Scale ($399/mo), and Enterprise ($1,299/mo). We also have PAYG pricing. "
        "Would you like details on a specific plan?",
    ),
    (
        "Which one do you recommend for 50,000 emails per month?",
        "For 50,000 emails/month, I'd recommend the **Pro plan** at $59/month, which includes "
        "up to 100,000 emails. That gives you room to grow without hitting overages.\n\n"
        "Alternatively, if you want to pay only for what you send, PAYG would cost about $45/month "
        "for 50,000 emails ($0.001 × 10,000 + $0.0008 × 40,000). The Pro plan is slightly more "
        "but includes higher API limits and priority support.",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  PROGRAMMATIC AUGMENTATION — expand seed examples with variations
# ═══════════════════════════════════════════════════════════════════════════════

# Paraphrase templates: alternative phrasings for the same questions
PARAPHRASE_TEMPLATES: list[dict[str, Any]] = [
    # Pricing paraphrases
    {"original_keyword": "How much does ApexMail cost",
     "variants": [
         "What's the pricing for ApexMail?",
         "How much do I need to pay for ApexMail?",
         "What are ApexMail's subscription prices?",
         "Can you tell me about ApexMail pricing?",
     ]},
    {"original_keyword": "How do I authenticate",
     "variants": [
         "How do I use my API key?",
         "What's the auth method for the API?",
         "How do I log into the API?",
         "Authentication setup for ApexMail API",
     ]},
    {"original_keyword": "How do I set up my domain",
     "variants": [
         "How do I verify my domain?",
         "Domain setup instructions please",
         "How do I add my domain to ApexMail?",
         "I need to configure my sending domain",
     ]},
    {"original_keyword": "emails are going to spam",
     "variants": [
         "Why are my emails landing in the spam folder?",
         "My messages end up in junk",
         "How do I stop my emails from being marked as spam?",
         "Emails going to spam instead of inbox",
     ]},
    {"original_keyword": "How do webhooks work",
     "variants": [
         "Tell me about webhook support",
         "How do I set up webhooks?",
         "What webhook events does ApexMail support?",
         "Can I get real-time notifications for email events?",
     ]},
    {"original_keyword": "How do templates work",
     "variants": [
         "How do I use email templates?",
         "Tell me about template support",
         "Does ApexMail support dynamic templates?",
         "How do I personalise emails with templates?",
     ]},
]


def _find_seed_for_keyword(keyword: str) -> tuple[str, str] | None:
    """Find the seed example whose user message contains the keyword."""
    kw_lower = keyword.lower()
    for user_msg, assistant_msg in SEED_EXAMPLES:
        if kw_lower in user_msg.lower():
            return (user_msg, assistant_msg)
    return None


def generate_paraphrased_examples() -> list[tuple[str, str]]:
    """Generate paraphrased variants that share the same assistant answer."""
    augmented: list[tuple[str, str]] = []
    for template in PARAPHRASE_TEMPLATES:
        original = _find_seed_for_keyword(template["original_keyword"])
        if original is None:
            continue
        _, answer = original
        for variant_q in template["variants"]:
            augmented.append((variant_q, answer))
    return augmented


# ── Plan-specific Q&A generator ──────────────────────────────────────────────
PLAN_DATA = [
    ("Starter", "$29", "25,000", "250,000", "10"),
    ("Pro", "$59", "100,000", "500,000", "25"),
    ("Growth", "$129", "500,000", "2,000,000", "50"),
    ("Scale", "$399", "2,000,000", "10,000,000", "100"),
    ("Enterprise", "$1,299", "Custom", "Unlimited", "Custom"),
]

PLAN_QUESTION_TEMPLATES = [
    "What does the {plan} plan include?",
    "How many emails can I send on the {plan} plan?",
    "What are the API limits for {plan}?",
    "Is the {plan} plan right for my business?",
]


def generate_plan_examples() -> list[tuple[str, str]]:
    """Generate Q&A pairs for each plan × question template."""
    examples: list[tuple[str, str]] = []
    for plan, price, emails, api_calls, rps in PLAN_DATA:
        for tmpl in PLAN_QUESTION_TEMPLATES:
            question = tmpl.format(plan=plan)
            answer = (
                f"The {plan} plan is {price}/month. It includes {emails} emails and "
                f"{api_calls} API calls per month"
                + (f", with a rate limit of {rps} requests/second." if rps != "Custom"
                   else ". Rate limits and volume are customised for your needs.")
                + " Would you like to know more?"
            )
            examples.append((question, answer))
    return examples


# ═══════════════════════════════════════════════════════════════════════════════
#  DATASET ASSEMBLY
# ═══════════════════════════════════════════════════════════════════════════════

def build_messages(user: str, assistant: str) -> dict:
    """Wrap a (user, assistant) pair in ChatML messages format."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


def deduplicate(examples: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Remove exact-duplicate user messages (keep first)."""
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for user_msg, asst_msg in examples:
        key = hashlib.md5(user_msg.strip().lower().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append((user_msg, asst_msg))
    return unique


def split_dataset(
    examples: list[tuple[str, str]],
    val_ratio: float = 0.08,
    test_ratio: float = 0.04,
    seed: int = 42,
) -> tuple[list, list, list]:
    """Shuffle and split into train/val/test."""
    rng = random.Random(seed)
    shuffled = list(examples)
    rng.shuffle(shuffled)

    n = len(shuffled)
    n_test = max(1, int(n * test_ratio))
    n_val = max(1, int(n * val_ratio))

    test = shuffled[:n_test]
    val = shuffled[n_test : n_test + n_val]
    train = shuffled[n_test + n_val :]
    return train, val, test


def write_jsonl(path: Path, examples: list[tuple[str, str]]) -> None:
    """Write examples as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for user_msg, asst_msg in examples:
            json.dump(build_messages(user_msg, asst_msg), f)
            f.write("\n")


@app.command()
def main(
    out_dir: str = typer.Option("data", help="Output directory for JSONL files"),
    dry_run: bool = typer.Option(False, help="Print stats without writing files"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    """Generate ChatML training dataset for Qwen 2.5-7B-Instruct."""
    console.print("\n[bold cyan]ApexMail AI — Dataset Generator[/bold cyan]")
    console.print(f"  Model: Qwen/Qwen2.5-7B-Instruct")
    console.print(f"  Format: ChatML (messages JSONL)\n")

    # Collect all examples
    all_examples: list[tuple[str, str]] = []
    all_examples.extend(SEED_EXAMPLES)
    console.print(f"  Seed examples: {len(SEED_EXAMPLES)}")

    paraphrased = generate_paraphrased_examples()
    all_examples.extend(paraphrased)
    console.print(f"  Paraphrased: {len(paraphrased)}")

    plan_examples = generate_plan_examples()
    all_examples.extend(plan_examples)
    console.print(f"  Plan-specific: {len(plan_examples)}")

    # Deduplicate
    all_examples = deduplicate(all_examples)
    console.print(f"  After dedup: {len(all_examples)}")

    # Split
    train, val, test = split_dataset(all_examples, seed=seed)

    # Stats table
    table = Table(title="Dataset Split")
    table.add_column("Split", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("Train", str(len(train)))
    table.add_row("Val", str(len(val)))
    table.add_row("Test", str(len(test)))
    table.add_row("[bold]Total[/bold]", f"[bold]{len(train) + len(val) + len(test)}[/bold]")
    console.print(table)

    if dry_run:
        console.print("\n[yellow]Dry run — no files written.[/yellow]")
        return

    # Write
    out = Path(out_dir)
    write_jsonl(out / "train.jsonl", train)
    write_jsonl(out / "val.jsonl", val)
    write_jsonl(out / "test.jsonl", test)

    console.print(f"\n[green]✓ Written to {out.resolve()}[/green]")


if __name__ == "__main__":
    app()
