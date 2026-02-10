#!/usr/bin/env python3
"""
ApexMail AI — Dataset Generator v2 (Comprehensive)

Generates a large, high-quality ChatML training dataset by combining:
  1. Hand-authored seed Q&A pairs (expanded from v1)
  2. Documentation-grounded Q&A — mines all 40+ customer-facing docs
  3. 500-fixes checklist → 500 technical Q&A pairs
  4. Bitext customer support dataset (HuggingFace) for tone/patterns
  5. Multi-turn conversation examples
  6. Strong negative/safety examples
  7. Paraphrase augmentation

Target: 3000–5000 high-quality training examples for Qwen 2.5-7B QLoRA.

Usage:
    python generate_dataset_v2.py
    python generate_dataset_v2.py --dry-run
    python generate_dataset_v2.py --include-bitext  # download + include HF data
"""

from __future__ import annotations

import json
import os
import re
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

DOCS_ROOT = Path(__file__).resolve().parent.parent.parent.parent / "docs"

# ═══════════════════════════════════════════════════════════════════════════════
#  1. SEED EXAMPLES — Hand-authored, authoritative Q&A pairs
# ═══════════════════════════════════════════════════════════════════════════════

SEED_EXAMPLES: list[tuple[str, str]] = [
    # ── Pricing ──────────────────────────────────────────────────────────
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
    (
        "Which plan is best for 50,000 emails per month?",
        "For 50,000 emails/month, I'd recommend the **Pro plan** at $59/month, which includes "
        "up to 100,000 emails. That gives you room to grow without hitting overages.\n\n"
        "Alternatively, if you want to pay only for what you send, PAYG would cost about $45/month "
        "for 50,000 emails. The Pro plan is slightly more but includes higher API limits.",
    ),
    (
        "Which plan do you recommend for a startup?",
        "For a startup, I'd recommend starting with the **Starter plan** at $29/month. "
        "It includes 25,000 emails and 250,000 API calls — plenty for early-stage. "
        "You can always upgrade to Pro or Growth as you scale.\n\n"
        "If your volume is unpredictable, PAYG lets you pay only for what you send.",
    ),
    (
        "Do you offer annual billing?",
        "For annual billing options, please contact our sales team. The listed prices "
        "are monthly rates. Enterprise plans typically include flexible billing terms.",
    ),
    (
        "Is there a free trial?",
        "ApexMail doesn't currently offer a free tier, but you can test the API using "
        "`am_test_` sandbox API keys without incurring charges. Our plans start at "
        "$29/month (Starter), and PAYG pricing starts at just $0.001/email.",
    ),

    # ── API & Authentication ─────────────────────────────────────────────
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
        "How do I use the Node.js SDK?",
        "Install and use the Node.js SDK:\n\n"
        "```bash\nnpm install @apexmail/sdk\n```\n\n"
        "```javascript\n"
        "import { ApexMail } from '@apexmail/sdk';\n\n"
        "const client = new ApexMail({ apiKey: 'am_live_your_key' });\n\n"
        "const result = await client.messages.send({\n"
        "  from: 'you@yourdomain.com',\n"
        "  to: 'recipient@example.com',\n"
        "  subject: 'Hello!',\n"
        "  html: '<p>Welcome!</p>',\n"
        "});\n"
        "```",
    ),
    (
        "How do I use the Python SDK?",
        "Install and use the Python SDK:\n\n"
        "```bash\npip install apexmail-python\n```\n\n"
        "```python\n"
        "from apexmail import ApexMail\n\n"
        "client = ApexMail(api_key='am_live_your_key')\n\n"
        "result = client.messages.send(\n"
        "    from_email='you@yourdomain.com',\n"
        "    to='recipient@example.com',\n"
        "    subject='Hello!',\n"
        "    html='<p>Welcome!</p>',\n"
        ")\n"
        "```",
    ),
    (
        "What are the API rate limits?",
        "Rate limits depend on your plan. Check the `X-RateLimit-Limit`, "
        "`X-RateLimit-Remaining`, and `X-RateLimit-Reset` headers in every API response "
        "to see your current usage. If you hit the limit, you'll get a 429 response — "
        "back off and retry with exponential delay.",
    ),
    (
        "How do I send a batch of emails?",
        "Use the batch endpoint to send up to 1,000 emails in a single API call:\n\n"
        "```bash\n"
        "POST https://api.apexmail.ee/v1/messages/batch\n"
        "```\n\n"
        "Send an array of message objects in the request body. Each message can have "
        "different recipients, subjects, and content. The API returns a batch ID for tracking.",
    ),
    (
        "How do I send emails with SMTP?",
        "ApexMail supports SMTP relay. Use these settings:\n\n"
        "- **Host**: smtp.apexmail.ee\n"
        "- **Port**: 587 (STARTTLS) or 465 (TLS)\n"
        "- **Username**: Your API key\n"
        "- **Password**: Your API key\n\n"
        "SMTP is useful for integrating with existing email clients, CMS platforms, or "
        "applications that don't support REST APIs.",
    ),

    # ── Domain & Deliverability ──────────────────────────────────────────
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
        "What is SPF?",
        "SPF (Sender Policy Framework) is a DNS TXT record that specifies which mail servers "
        "are authorised to send email for your domain. When you add your domain to ApexMail, "
        "we provide the SPF record value to add to your DNS.\n\n"
        "Example: `v=spf1 include:spf.apexmail.ee ~all`",
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
        "What is DMARC?",
        "DMARC (Domain-based Message Authentication, Reporting & Conformance) builds on SPF "
        "and DKIM to tell receiving servers what to do with emails that fail authentication.\n\n"
        "Recommended DMARC record: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`\n\n"
        "Start with `p=none` to monitor, then move to `quarantine` or `reject` once you're "
        "confident all legitimate email is authenticated.",
    ),
    (
        "What is ARC?",
        "ARC (Authenticated Received Chain) preserves email authentication results across "
        "forwarding. When an email is forwarded (e.g., via a mailing list), SPF and DKIM "
        "may break. ARC creates a chain of trust so the final recipient can verify the "
        "original authentication. ApexMail supports ARC signing automatically.",
    ),
    (
        "What is BIMI?",
        "BIMI (Brand Indicators for Message Identification) lets you display your brand logo "
        "next to your emails in recipients' inboxes. It requires:\n\n"
        "1. DMARC policy set to `quarantine` or `reject`\n"
        "2. A Verified Mark Certificate (VMC) from a certificate authority\n"
        "3. An SVG logo hosted at a public URL\n"
        "4. A BIMI DNS TXT record\n\n"
        "ApexMail validates BIMI configuration through the domain settings page.",
    ),
    (
        "What is MTA-STS?",
        "MTA-STS (MTA Strict Transport Security) ensures that emails sent to your domain "
        "use encrypted TLS connections. It prevents man-in-the-middle attacks on email "
        "delivery. ApexMail respects MTA-STS policies when delivering to recipient domains "
        "and can help you set up MTA-STS for your own domain.",
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
        "What's a good click rate?",
        "The average email click rate is about 2.3%. It varies by industry and email type:\n\n"
        "- Transactional emails typically see higher click rates (5–10%)\n"
        "- Marketing emails average 2–3%\n"
        "- Newsletters average 1–2%\n\n"
        "To improve: use clear CTAs, segment your audience, personalise content, "
        "and A/B test your layouts.",
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
    (
        "How does IP warm-up work?",
        "IP warm-up gradually increases your sending volume on a new IP or domain to build "
        "sender reputation with ISPs. Best practices:\n\n"
        "1. **Week 1**: Send to your most engaged subscribers (50–500 emails/day)\n"
        "2. **Week 2**: Double your volume daily\n"
        "3. **Week 3–4**: Continue increasing until you reach full volume\n\n"
        "During warm-up, monitor your bounce rate, spam complaints, and inbox placement. "
        "ApexMail's analytics dashboard tracks these metrics for you.",
    ),
    (
        "What is sender reputation?",
        "Sender reputation is a score assigned by ISPs (Gmail, Outlook, etc.) that determines "
        "whether your emails land in the inbox or spam folder. It's based on:\n\n"
        "- Bounce rate\n"
        "- Spam complaint rate\n"
        "- Engagement (opens, clicks)\n"
        "- List quality\n"
        "- Sending consistency\n\n"
        "ApexMail provides a deliverability score in your dashboard that tracks your reputation.",
    ),

    # ── Webhooks ─────────────────────────────────────────────────────────
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
    (
        "How do I verify webhook signatures?",
        "Every webhook request includes an `X-ApexMail-Signature` header with an HMAC-SHA256 "
        "signature. Verify it by computing the HMAC over the raw request body using your "
        "webhook signing secret:\n\n"
        "```javascript\n"
        "const crypto = require('crypto');\n"
        "const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');\n"
        "const isValid = crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));\n"
        "```\n\n"
        "Your signing secret is shown when you create the webhook and is available in "
        "**Settings → Webhooks**.",
    ),
    (
        "What happens if my webhook endpoint is down?",
        "If your endpoint returns a non-2xx status or times out, ApexMail retries the delivery "
        "with exponential backoff over approximately 24 hours. After multiple consecutive failures, "
        "the event is marked as failed.\n\n"
        "You can view failed deliveries and manually retry them in your dashboard or via the API.",
    ),

    # ── Templates ────────────────────────────────────────────────────────
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
    (
        "What template variables are available?",
        "You can use any custom variables in your templates — just pass them in the `data` "
        "field when sending. Common patterns:\n\n"
        "- `{{name}}` — recipient's name\n"
        "- `{{company}}` — company name\n"
        "- `{{#if condition}}...{{/if}}` — conditional blocks\n"
        "- `{{#each items}}...{{/each}}` — loop over arrays\n"
        "- `{{formatDate date 'MMMM D, YYYY'}}` — date formatting\n\n"
        "Templates use Handlebars syntax.",
    ),

    # ── Suppression & Compliance ─────────────────────────────────────────
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
    (
        "How does CAN-SPAM compliance work?",
        "CAN-SPAM requires:\n\n"
        "1. Include your physical postal address in every commercial email\n"
        "2. Provide a clear unsubscribe mechanism\n"
        "3. Honor unsubscribe requests within 10 business days\n"
        "4. Don't use deceptive subject lines or headers\n"
        "5. Identify the message as an ad (if applicable)\n\n"
        "ApexMail automatically includes unsubscribe links and handles opt-out processing.",
    ),
    (
        "What is double opt-in?",
        "Double opt-in requires subscribers to confirm their email address by clicking a link "
        "in a confirmation email. Benefits:\n\n"
        "- Verifies the email address is valid\n"
        "- Confirms the subscriber actually wants to receive emails\n"
        "- Reduces spam complaints and bounces\n"
        "- Improves engagement rates\n\n"
        "You can enable double opt-in in **Settings → Subscription** or set it per list.",
    ),

    # ── Contacts & Lists ─────────────────────────────────────────────────
    (
        "How do I import contacts?",
        "Import contacts via the dashboard or API:\n\n"
        "**Dashboard**: Go to **Audience → Contacts → Import**, upload a CSV file with "
        "columns for email, name, and any custom fields.\n\n"
        "**API**: Use `POST /v1/contacts/import` with a CSV or JSON payload.\n\n"
        "During import, ApexMail automatically skips suppressed addresses and validates email formats.",
    ),
    (
        "How do I create a mailing list?",
        "Create lists in the dashboard under **Audience → Lists → Create List**, or via the API:\n\n"
        "```bash\n"
        "POST https://api.apexmail.ee/v1/lists\n"
        '{"name": "Newsletter Subscribers", "double_optin": true}\n'
        "```\n\n"
        "Subscribers can belong to multiple lists. Use lists to organize your audience "
        "and target campaigns.",
    ),
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
        "What contact statuses are there?",
        "Contacts have the following statuses:\n\n"
        "| Status | Can send? | Description |\n"
        "|--------|-----------|-------------|\n"
        "| Active | ✅ | Contact is subscribed and eligible for emails |\n"
        "| Unsubscribed | ❌ | Contact opted out. Honoring this is legally required |\n"
        "| Bounced | ❌ | Hard bounce detected. Address is invalid |\n"
        "| Complained | ❌ | Marked as spam. Do not email |\n"
        "| Pending | ⏳ | Awaiting double opt-in confirmation |\n\n"
        "ApexMail automatically enforces these statuses — it won't send to unsubscribed, "
        "bounced, or complained contacts.",
    ),

    # ── Analytics ─────────────────────────────────────────────────────────
    (
        "What analytics does ApexMail provide?",
        "ApexMail provides comprehensive analytics:\n\n"
        "- **Campaign metrics**: opens, clicks, bounces, unsubscribes, complaints\n"
        "- **Deliverability score**: overall sender reputation indicator\n"
        "- **Engagement heatmaps**: click location data within emails\n"
        "- **Time-series trends**: track performance over time\n"
        "- **Per-recipient tracking**: individual engagement history\n"
        "- **Bot detection**: filters automated clicks from real engagement\n\n"
        "Access analytics in the dashboard or via the `GET /v1/analytics` API endpoint.",
    ),
    (
        "How does bot click detection work?",
        "ApexMail automatically filters bot clicks from your engagement metrics using "
        "multiple detection signals including user-agent analysis, click timing patterns, "
        "IP reputation, and click velocity. Adjusted metrics are shown alongside raw numbers "
        "in your analytics dashboard.\n\n"
        "You can also enable honeypot links for more accurate bot detection.",
    ),

    # ── Automation ────────────────────────────────────────────────────────
    (
        "Does ApexMail support automation workflows?",
        "Yes! ApexMail supports automation workflows including:\n\n"
        "- **Welcome series**: Triggered when a subscriber joins a list\n"
        "- **Drip campaigns**: Time-delayed email sequences\n"
        "- **Behavioural triggers**: Send emails based on webhook events\n"
        "- **Re-engagement**: Automatically target inactive subscribers\n\n"
        "Set up automations in **Campaigns → Automations** on your dashboard.",
    ),
    (
        "How does send-time optimisation work?",
        "ApexMail's AI-powered send-time optimisation (STO) analyses each subscriber's "
        "historical engagement patterns — when they open, click, and interact with emails.\n\n"
        "When you enable STO for a campaign, instead of sending to everyone at once, "
        "each email is delivered at the predicted optimal time for that individual subscriber. "
        "This typically improves open rates by 5–15%.\n\n"
        "Enable STO when creating a campaign in the dashboard or set `\"sto\": true` in the API.",
    ),

    # ── Advanced features ────────────────────────────────────────────────
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
    (
        "Does ApexMail support A/B testing?",
        "Yes! You can A/B test:\n\n"
        "- **Subject lines**: Test different subjects to see which gets higher open rates\n"
        "- **Content**: Test different email body content or layouts\n"
        "- **Send times**: Test different sending times\n\n"
        "Set the test audience size (e.g., 20% of your list), and ApexMail will "
        "automatically send the winning variant to the remaining subscribers.",
    ),
    (
        "What is the reply tracking feature?",
        "ApexMail's reply tracking detects when recipients reply to your emails, "
        "providing a deeper engagement signal beyond opens and clicks. Replies indicate "
        "genuine interest and are weighted heavily in engagement scoring.\n\n"
        "Enable reply tracking in your sending domain settings. Replies can be forwarded "
        "to your support inbox or processed via webhooks.",
    ),
    (
        "What is the Engagement Trust Score?",
        "The Engagement Trust Score (0–100) measures subscriber trust based on the "
        "Trust Equation: (Credibility + Reliability + Intimacy) / Self-Orientation.\n\n"
        "- **Credibility**: Opens, clicks, spam marks\n"
        "- **Reliability**: Tenure, preferences, recency\n"
        "- **Intimacy**: Replies, surveys, NPS\n"
        "- **Self-Orientation**: Your sending frequency vs their engagement\n\n"
        "Access trust scores via the API or dashboard. Use them to identify at-risk "
        "subscribers and personalise your sending strategy.",
    ),

    # ── Troubleshooting ──────────────────────────────────────────────────
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
        "Check the `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers for your current usage.",
    ),
    (
        "My domain verification is failing.",
        "Domain verification can fail for several reasons:\n\n"
        "1. **DNS propagation delay** — wait up to 48 hours for records to propagate\n"
        "2. **Wrong record type** — SPF is a TXT record, DKIM is a CNAME record\n"
        "3. **Conflicting records** — check for duplicate SPF records (only one allowed per domain)\n"
        "4. **Typo in records** — double-check the values match exactly\n\n"
        "Use `dig` or an online DNS checker to verify your records are visible:\n"
        "```bash\ndig TXT yourdomain.com +short\ndig CNAME apexmail._domainkey.yourdomain.com +short\n```",
    ),
    (
        "My webhook isn't receiving events.",
        "Troubleshoot webhook issues:\n\n"
        "1. **Check URL**: Must be HTTPS — HTTP endpoints are rejected\n"
        "2. **Check firewall**: Your server must accept POST requests from our IPs\n"
        "3. **Check response code**: Your endpoint must return 2xx within 30 seconds\n"
        "4. **Check logs**: View delivery attempts in Settings → Webhooks → [your webhook] → Deliveries\n"
        "5. **Send a test**: Use the \"Test\" button in the webhook settings to send a sample event\n\n"
        "Private IPs (10.x, 172.16-31.x, 192.168.x) are blocked for SSRF protection.",
    ),
    (
        "How do I check my sending domain's health?",
        "Use the domain health check endpoint:\n\n"
        "```bash\nGET /v1/domains/:id/health\n```\n\n"
        "This checks SPF, DKIM, DMARC, and MTA-STS configuration and returns a score "
        "with recommendations. You can also check domain health in the dashboard under "
        "Settings → Domains.",
    ),

    # ── Actions (structured commands) ────────────────────────────────────
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
    (
        "Add user@example.com to my suppression list",
        "```action\n"
        '{"action": "ADD_SUPPRESSION", "params": {"email": "user@example.com"}, '
        '"confirm": false, "reason": "Adding an email to the suppression list — no emails sent"}\n'
        "```\n\n"
        "The address will be suppressed immediately. Future sends to this address will be skipped.",
    ),
    (
        "Remove user@example.com from my suppression list",
        "```action\n"
        '{"action": "REMOVE_SUPPRESSION", "params": {"email": "user@example.com"}, '
        '"confirm": true, "reason": "Removing a suppression means this address will receive emails again"}\n'
        "```\n\n"
        "⚠️ This will allow emails to be sent to this address again. Please confirm.",
    ),
    (
        "Verify the domain example.com",
        "```action\n"
        '{"action": "VERIFY_DOMAIN", "params": {"domain": "example.com"}, '
        '"confirm": false, "reason": "Checking DNS records for domain verification — read-only"}\n'
        "```\n\n"
        "I'll check the DNS records for example.com now.",
    ),
    (
        "Schedule a campaign 'Black Friday' for next Monday at 9am",
        "```action\n"
        '{"action": "SCHEDULE_CAMPAIGN", "params": {"name": "Black Friday", "schedule": "next Monday 09:00"}, '
        '"confirm": true, "reason": "Scheduling a campaign for future delivery"}\n'
        "```\n\n"
        "Please confirm to schedule the campaign. You can cancel or edit the schedule before it sends.",
    ),

    # ── Safety / off-topic ───────────────────────────────────────────────
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
        "What's the capital of France?",
        "I'm built to help with ApexMail and email marketing questions — general knowledge "
        "is outside my scope. Is there anything I can help you with regarding email campaigns, "
        "deliverability, or the ApexMail platform?",
    ),
    (
        "Write me malware code",
        "I can't help with that. I'm ApexMail Assistant, designed to help with email marketing "
        "and the ApexMail platform. If you have any questions about sending emails, managing "
        "campaigns, or email best practices, I'd be happy to help.",
    ),
    (
        "Tell me a joke",
        "I'm better at email marketing than comedy! 😄 But seriously, I'm here to help with "
        "ApexMail and email-related questions. Anything I can help you with?",
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
    (
        "Is ApexMail better than Mailchimp?",
        "I'm not the best source for comparing providers objectively, but I can tell you "
        "what makes ApexMail great:\n\n"
        "- **Developer-first**: Powerful REST API and SDKs (Node.js, Python)\n"
        "- **Deliverability**: Full authentication suite (SPF, DKIM, DMARC, ARC, BIMI)\n"
        "- **EU-based**: Data processed in European data centers\n"
        "- **Transparent pricing**: No hidden fees, plans from $29/month\n"
        "- **AI features**: Send-time optimisation, engagement trust scores\n\n"
        "What specific feature are you looking for? I can explain how ApexMail handles it.",
    ),

    # ── Anti-hallucination examples ──────────────────────────────────────
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
    (
        "Does ApexMail integrate with Zapier?",
        "I don't have confirmed information about a Zapier integration. ApexMail has a "
        "REST API and webhooks that can integrate with virtually any platform, including "
        "automation tools. Check the integrations page in your dashboard or contact support "
        "for the latest integration options.",
    ),
    (
        "What languages does ApexMail support?",
        "ApexMail's API and documentation are in English. You can send emails in any language "
        "— there are no restrictions on email content language. The dashboard interface is "
        "currently English-only.",
    ),

    # ── Conversational / greetings ───────────────────────────────────────
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
        "Hello",
        "Hi there! I'm ApexMail Assistant. How can I help you with your email marketing today?",
    ),
    (
        "Hey",
        "Hey! Welcome to ApexMail support. What can I help you with?",
    ),
    (
        "Thanks for your help!",
        "You're welcome! If you have more questions about ApexMail or email marketing, "
        "feel free to ask anytime. Happy sending! 📧",
    ),
    (
        "Goodbye",
        "Goodbye! If you need help with ApexMail in the future, I'm always here. Have a great day! 👋",
    ),
    (
        "Who are you?",
        "I'm ApexMail Assistant — the official AI assistant for the ApexMail email marketing "
        "platform. I can help you with:\n\n"
        "- Sending emails and managing campaigns\n"
        "- API authentication and SDK usage\n"
        "- Domain setup and deliverability\n"
        "- Analytics and performance optimization\n"
        "- Pricing and billing\n\n"
        "ApexMail is operated by Bel Consulting OÜ, based in Tallinn, Estonia. How can I help?",
    ),
    (
        "What can you do?",
        "I can help with everything related to ApexMail and email marketing:\n\n"
        "- **API & SDKs**: Authentication, sending emails, managing contacts\n"
        "- **Domain setup**: SPF, DKIM, DMARC configuration\n"
        "- **Deliverability**: Best practices, troubleshooting spam issues\n"
        "- **Campaigns**: Creating, scheduling, A/B testing\n"
        "- **Analytics**: Understanding metrics, improving performance\n"
        "- **Pricing**: Plans, PAYG, billing questions\n"
        "- **Compliance**: GDPR, CAN-SPAM guidance\n"
        "- **Actions**: I can perform tasks like creating lists or sending campaigns\n\n"
        "Just ask me anything!",
    ),

    # ── Enterprise features ──────────────────────────────────────────────
    (
        "What enterprise features does ApexMail offer?",
        "ApexMail Enterprise includes:\n\n"
        "- **SSO**: SAML 2.0 and OIDC single sign-on\n"
        "- **Sub-accounts**: Manage multiple brands/clients under one organization\n"
        "- **Dedicated support**: Named account manager and priority support\n"
        "- **Custom SLA**: Uptime guarantees and response time commitments\n"
        "- **Log streaming**: Real-time event streaming to your SIEM or data warehouse\n"
        "- **Private cloud**: Dedicated infrastructure deployment\n"
        "- **White-label**: Custom branding for the dashboard and emails\n"
        "- **Template approval workflows**: Multi-step approval for email templates\n\n"
        "Contact sales for Enterprise pricing and custom configurations.",
    ),
    (
        "How does SSO work in ApexMail?",
        "ApexMail supports SAML 2.0 and OIDC for enterprise single sign-on. "
        "Configure SSO in your organization settings by providing:\n\n"
        "- **SAML**: Your IdP metadata URL or XML\n"
        "- **OIDC**: Client ID, secret, and issuer URL\n\n"
        "Once configured, team members can log in via your identity provider (Okta, "
        "Azure AD, Google Workspace, etc.) without separate credentials.",
    ),
    (
        "What is log streaming?",
        "Log streaming delivers your email event data in real-time to external services. "
        "Supported destinations include:\n\n"
        "- Amazon S3\n"
        "- Google BigQuery\n"
        "- Snowflake\n"
        "- Apache Kafka\n"
        "- Elasticsearch\n"
        "- Datadog\n"
        "- Custom webhooks\n\n"
        "Configure log streams in your Enterprise dashboard or via the API.",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
#  2. DOCUMENTATION-GROUNDED Q&A GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def extract_doc_qa_pairs() -> list[tuple[str, str]]:
    """
    Read customer-facing docs and generate Q&A pairs from their content.
    Extracts key facts, headings, code examples, and tables.
    """
    pairs: list[tuple[str, str]] = []
    
    # Customer-facing doc directories
    customer_dirs = ["api", "security", "enterprise", "user-guide"]
    standalone_files = ["quickstart.md"]
    
    for d in customer_dirs:
        doc_dir = DOCS_ROOT / d
        if not doc_dir.exists():
            continue
        for md_file in sorted(doc_dir.rglob("*.md")):
            new_pairs = _extract_from_doc(md_file)
            pairs.extend(new_pairs)
    
    for f in standalone_files:
        fp = DOCS_ROOT / f
        if fp.exists():
            pairs.extend(_extract_from_doc(fp))
    
    return pairs


def _extract_from_doc(path: Path) -> list[tuple[str, str]]:
    """Extract Q&A pairs from a single markdown file."""
    pairs: list[tuple[str, str]] = []
    
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return pairs
    
    # Get doc title from first heading
    title_match = re.search(r'^#\s+(.+)', text, re.MULTILINE)
    doc_title = title_match.group(1).strip() if title_match else path.stem
    
    # Extract sections (## headings with their content)
    sections = re.split(r'^##\s+', text, flags=re.MULTILINE)
    
    topic_area = _classify_doc(path)
    
    for section in sections[1:]:  # skip content before first ##
        lines = section.strip().split('\n')
        if not lines:
            continue
        
        heading = lines[0].strip()
        body = '\n'.join(lines[1:]).strip()
        
        if len(body) < 50:  # skip very short sections
            continue
        
        # Truncate very long sections to key content
        body_clean = _clean_section_body(body)
        
        if len(body_clean) < 30:
            continue
        
        # Generate a natural question from the heading
        question = _heading_to_question(heading, topic_area)
        
        if question:
            # Cap answer length for training
            answer = body_clean[:1500] if len(body_clean) > 1500 else body_clean
            pairs.append((question, answer))
    
    return pairs


def _classify_doc(path: Path) -> str:
    """Classify a doc into a topic area for better question generation."""
    p = str(path).lower()
    if "api" in p:
        return "api"
    if "security" in p or "compliance" in p or "data-protection" in p:
        return "security"
    if "enterprise" in p:
        return "enterprise"
    if "troubleshoot" in p:
        return "troubleshooting"
    if "domain" in p or "authentication" in p or "deliverability" in p:
        return "deliverability"
    if "webhook" in p:
        return "webhooks"
    if "contact" in p or "getting-started" in p:
        return "getting-started"
    return "general"


def _heading_to_question(heading: str, topic: str) -> str | None:
    """Convert a markdown heading into a natural user question."""
    heading = heading.strip().rstrip('#').strip()
    
    # Skip non-informative headings
    skip = {"overview", "introduction", "summary", "table of contents", 
            "additional links", "resources", "next steps", "prerequisites",
            "related", "see also", "changelog", "version history"}
    if heading.lower() in skip:
        return None
    
    # Direct question mappings for common patterns
    h_lower = heading.lower()
    
    if "error" in h_lower or "troubleshoot" in h_lower:
        return f"How do I handle {heading.lower()}?"
    if "setup" in h_lower or "configuration" in h_lower or "config" in h_lower:
        return f"How do I configure {heading.lower().replace('setup', '').replace('configuration', '').strip()}?"
    if "best practice" in h_lower:
        return f"What are the {heading.lower()}?"
    if "how" in h_lower:
        return heading + ("?" if not heading.endswith("?") else "")
    if "what" in h_lower:
        return heading + ("?" if not heading.endswith("?") else "")
    
    # Generic question formation
    prefixes = [
        f"Tell me about {heading.lower()} in ApexMail.",
        f"How does {heading.lower()} work in ApexMail?",
        f"What is {heading} in ApexMail?",
        f"Explain {heading.lower()} in ApexMail.",
    ]
    
    return random.choice(prefixes)


def _clean_section_body(body: str) -> str:
    """Clean markdown body for use as training data."""
    # Remove markdown image references
    body = re.sub(r'!\[.*?\]\(.*?\)', '', body)
    # Remove HTML comments
    body = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)
    # Remove excessive whitespace
    body = re.sub(r'\n{3,}', '\n\n', body)
    return body.strip()


# ═══════════════════════════════════════════════════════════════════════════════
#  3. 500-FIXES CHECKLIST → Q&A PAIRS
# ═══════════════════════════════════════════════════════════════════════════════

def extract_checklist_qa() -> list[tuple[str, str]]:
    """
    Convert the 500-fixes checklist into Q&A about what was fixed.
    Groups fixes by batch/category for coherent answers.
    """
    checklist_path = DOCS_ROOT / "500-fixes-checklist.md"
    if not checklist_path.exists():
        return []
    
    text = checklist_path.read_text(encoding="utf-8")
    pairs: list[tuple[str, str]] = []
    
    # Extract batch sections
    batch_pattern = re.compile(
        r'^##\s+(Batch\s+\d+[^(\n]*)\(([^)]+)\)\s*\n((?:- \[.\].*\n?)+)',
        re.MULTILINE
    )
    
    for match in batch_pattern.finditer(text):
        batch_title = match.group(1).strip()
        item_range = match.group(2).strip()
        items_text = match.group(3).strip()
        
        # Parse individual items
        items = re.findall(r'- \[.\]\s*\d+\.\s*(.+)', items_text)
        
        if not items:
            continue
        
        # Create a Q&A about this batch
        category = _extract_category(batch_title)
        items_summary = "\n".join(f"- {item}" for item in items[:5])
        if len(items) > 5:
            items_summary += f"\n- ...and {len(items) - 5} more improvements"
        
        question = f"What {category} improvements has ApexMail made recently?"
        answer = (
            f"ApexMail has made significant {category} improvements including:\n\n"
            f"{items_summary}\n\n"
            f"These are part of our ongoing commitment to platform reliability and security."
        )
        pairs.append((question, answer))
    
    # Also generate individual Q&A for interesting fixes
    all_items = re.findall(r'- \[.\]\s*\d+\.\s*(.+)', text)
    for item in all_items:
        q, a = _fix_to_qa(item)
        if q and a:
            pairs.append((q, a))
    
    return pairs


def _extract_category(batch_title: str) -> str:
    """Extract category from batch title."""
    title_lower = batch_title.lower()
    if "security" in title_lower:
        return "security"
    if "data loss" in title_lower or "critical" in title_lower:
        return "reliability"
    if "performance" in title_lower or "latency" in title_lower:
        return "performance"
    if "compliance" in title_lower or "gdpr" in title_lower:
        return "compliance"
    if "api" in title_lower:
        return "API"
    if "deliverability" in title_lower:
        return "deliverability"
    return "platform"


def _fix_to_qa(fix_description: str) -> tuple[str | None, str | None]:
    """Convert a single fix description into a user-facing Q&A pair."""
    desc = fix_description.strip()
    
    # Skip internal technical fixes that don't make sense as customer Q&A
    skip_keywords = ["internal", "refactor", "typo in comment", "test coverage",
                     "lint", "unused import"]
    if any(kw in desc.lower() for kw in skip_keywords):
        return None, None
    
    # Convert to customer-facing Q&A
    d_lower = desc.lower()
    
    if "tracking" in d_lower and "event" in d_lower:
        return (
            "How reliable is ApexMail's event tracking?",
            "ApexMail's event tracking is designed for high reliability. "
            "We use write-ahead logging with automatic retry to ensure no tracking events "
            "are lost, even during brief service interruptions. "
            "All events (opens, clicks, bounces) are guaranteed to be recorded and delivered to your webhooks."
        )
    
    if "bounce" in d_lower:
        return (
            "How does ApexMail handle bounce processing?",
            "ApexMail automatically processes bounces:\n\n"
            "- **Hard bounces** are immediately added to your suppression list\n"
            "- **Soft bounces** are retried automatically with exponential backoff\n"
            "- After multiple soft bounce failures, the address is treated as a hard bounce\n\n"
            "This protects your sender reputation and ensures list hygiene."
        )
    
    if "webhook" in d_lower and ("retry" in d_lower or "circuit" in d_lower):
        return (
            "How reliable is webhook delivery?",
            "ApexMail's webhook delivery is designed for reliability:\n\n"
            "- Failed deliveries are retried with exponential backoff over ~24 hours\n"
            "- Failed events can be manually retried from the dashboard\n"
            "- Webhook health is monitored — you're notified if your endpoint is consistently failing\n\n"
            "Check webhook delivery status in Settings → Webhooks → Deliveries."
        )
    
    if "suppression" in d_lower:
        return (
            "How accurate is suppression list checking?",
            "ApexMail's suppression checking is thorough and reliable. "
            "Every email send is checked against your suppression list before delivery. "
            "Both automatic suppressions (bounces, complaints, unsubscribes) and manual "
            "suppressions are enforced. This ensures you never send to an address that "
            "should be suppressed."
        )
    
    # Generic quality improvement
    return None, None


# ═══════════════════════════════════════════════════════════════════════════════
#  4. BITEXT CUSTOMER SUPPORT DATASET (HUGGINGFACE)
# ═══════════════════════════════════════════════════════════════════════════════

def load_bitext_examples(max_examples: int = 500) -> list[tuple[str, str]]:
    """
    Load and adapt Bitext customer support dataset.
    Re-contextualizes generic customer support patterns to ApexMail domain.
    """
    try:
        from datasets import load_dataset
    except ImportError:
        console.print("[yellow]  'datasets' not installed, skipping Bitext data[/yellow]")
        return []
    
    try:
        console.print("  Loading Bitext customer support dataset from HuggingFace...")
        ds = load_dataset(
            "bitext/Bitext-customer-support-llm-chatbot-training-dataset",
            split="train",
        )
    except Exception as e:
        console.print(f"[yellow]  Failed to load Bitext dataset: {e}[/yellow]")
        return []
    
    pairs: list[tuple[str, str]] = []
    
    # Map Bitext intents to ApexMail-relevant intents
    relevant_intents = {
        "create_account", "delete_account", "edit_account",
        "complaint", "review",
        "check_invoice", "get_invoice",
        "newsletter_subscription",
        "cancel_order", "change_order", "place_order",
        "check_payment_methods", "payment_issue",
        "check_refund_policy", "track_refund",
        "contact_customer_service", "contact_human_agent",
        "recover_password", "registration_problems",
    }
    
    # Keyword replacements to contextualize for email marketing
    replacements = {
        "order": "campaign",
        "product": "email template",
        "store": "dashboard",
        "shopping cart": "email queue",
        "purchase": "send",
        "item": "email",
        "shipping": "delivery",
        "delivery": "email delivery",
        "package": "campaign",
        "warehouse": "sending infrastructure",
        "return": "suppression",
    }
    
    seen_intents: dict[str, int] = {}
    max_per_intent = max_examples // len(relevant_intents)
    
    for row in ds:
        intent = row.get("intent", "")
        if intent not in relevant_intents:
            continue
        
        if seen_intents.get(intent, 0) >= max_per_intent:
            continue
        
        instruction = row.get("instruction", "")
        response = row.get("response", "")
        
        if not instruction or not response:
            continue
        
        # Contextualize for ApexMail
        for old, new in replacements.items():
            instruction = re.sub(rf'\b{old}\b', new, instruction, flags=re.IGNORECASE)
            response = re.sub(rf'\b{old}\b', new, response, flags=re.IGNORECASE)
        
        # Add ApexMail context to responses
        response = response.rstrip()
        if not response.endswith('.'):
            response += '.'
        response += " For more help, visit your ApexMail dashboard at https://app.apexmail.ee or contact our support team."
        
        pairs.append((instruction, response))
        seen_intents[intent] = seen_intents.get(intent, 0) + 1
    
    return pairs


# ═══════════════════════════════════════════════════════════════════════════════
#  5. PARAPHRASE AUGMENTATION
# ═══════════════════════════════════════════════════════════════════════════════

PARAPHRASE_TEMPLATES: list[dict[str, Any]] = [
    {"original_keyword": "How much does ApexMail cost",
     "variants": [
         "What's the pricing for ApexMail?",
         "How much do I need to pay for ApexMail?",
         "What are ApexMail's subscription prices?",
         "Can you tell me about ApexMail pricing?",
         "How expensive is ApexMail?",
         "What does ApexMail charge?",
     ]},
    {"original_keyword": "How do I authenticate",
     "variants": [
         "How do I use my API key?",
         "What's the auth method for the API?",
         "How do I log into the API?",
         "Authentication setup for ApexMail API",
         "How do I connect to the ApexMail API?",
         "What credentials do I need for the API?",
     ]},
    {"original_keyword": "How do I set up my domain",
     "variants": [
         "How do I verify my domain?",
         "Domain setup instructions please",
         "How do I add my domain to ApexMail?",
         "I need to configure my sending domain",
         "Domain verification steps",
         "How to add a new domain",
     ]},
    {"original_keyword": "emails are going to spam",
     "variants": [
         "Why are my emails landing in the spam folder?",
         "My messages end up in junk",
         "How do I stop my emails from being marked as spam?",
         "Emails going to spam instead of inbox",
         "My emails aren't reaching the inbox",
         "Why do my emails go to junk?",
     ]},
    {"original_keyword": "How do webhooks work",
     "variants": [
         "Tell me about webhook support",
         "How do I set up webhooks?",
         "What webhook events does ApexMail support?",
         "Can I get real-time notifications for email events?",
         "How to configure webhooks",
         "Webhook setup guide",
     ]},
    {"original_keyword": "How do templates work",
     "variants": [
         "How do I use email templates?",
         "Tell me about template support",
         "Does ApexMail support dynamic templates?",
         "How do I personalise emails with templates?",
         "Template usage guide",
         "How to create an email template",
     ]},
    {"original_keyword": "How do I send an email using the API",
     "variants": [
         "Show me how to send an email with curl",
         "API example for sending email",
         "How to send a message via the REST API",
         "Send email API example",
         "How do I make a send API call?",
     ]},
    {"original_keyword": "What SDKs do you offer",
     "variants": [
         "Do you have a Node.js library?",
         "Is there a Python SDK?",
         "What programming languages do you support?",
         "Client libraries for ApexMail",
         "SDK support",
     ]},
    {"original_keyword": "How do I improve my deliverability",
     "variants": [
         "Tips for better email deliverability",
         "How to improve inbox placement",
         "My emails aren't getting delivered",
         "Deliverability best practices",
         "How do I get better inbox rates?",
     ]},
    {"original_keyword": "How does segmentation work",
     "variants": [
         "How do I segment my audience?",
         "Can I target specific subscribers?",
         "How to create a segment",
         "Audience segmentation in ApexMail",
     ]},
    {"original_keyword": "What is a suppression list",
     "variants": [
         "How do I suppress an email address?",
         "What's the blocklist?",
         "How does the suppression list work?",
         "How to add someone to the do-not-send list",
     ]},
    {"original_keyword": "How do I handle GDPR",
     "variants": [
         "Is ApexMail GDPR compliant?",
         "How does ApexMail handle data privacy?",
         "GDPR compliance in ApexMail",
         "How do I delete subscriber data for GDPR?",
     ]},
    {"original_keyword": "What analytics does ApexMail provide",
     "variants": [
         "How do I view my email stats?",
         "Where can I see campaign performance?",
         "Email analytics and reporting",
         "How to track email opens and clicks",
     ]},
    {"original_keyword": "My domain verification is failing",
     "variants": [
         "Domain verification not working",
         "Can't verify my domain",
         "DNS records not validating",
         "Domain setup failing",
     ]},
    {"original_keyword": "My webhook isn't receiving events",
     "variants": [
         "Webhook not working",
         "Not getting webhook notifications",
         "Webhook events not delivered",
         "Why isn't my webhook endpoint getting events?",
     ]},
]

# ── Plan-specific Q&A ────────────────────────────────────────────────────────
PLAN_DATA = [
    ("Starter", "$29", "25,000", "250,000"),
    ("Pro", "$59", "100,000", "500,000"),
    ("Growth", "$129", "500,000", "2,000,000"),
    ("Scale", "$399", "2,000,000", "10,000,000"),
    ("Enterprise", "$1,299", "Custom", "Unlimited"),
]

PLAN_QUESTION_TEMPLATES = [
    "What does the {plan} plan include?",
    "How many emails can I send on the {plan} plan?",
    "What are the API limits for {plan}?",
    "Is the {plan} plan right for my business?",
    "Tell me about the {plan} plan.",
    "{plan} plan details",
]


def generate_plan_examples() -> list[tuple[str, str]]:
    examples: list[tuple[str, str]] = []
    for plan, price, emails, api_calls in PLAN_DATA:
        for tmpl in PLAN_QUESTION_TEMPLATES:
            question = tmpl.format(plan=plan)
            answer = (
                f"The {plan} plan is {price}/month. It includes {emails} emails and "
                f"{api_calls} API calls per month."
                + (" Rate limits and volume are customised for your needs." if plan == "Enterprise"
                   else "")
                + " Would you like to know more?"
            )
            examples.append((question, answer))
    return examples


def _find_seed_for_keyword(keyword: str) -> tuple[str, str] | None:
    kw_lower = keyword.lower()
    for user_msg, asst_msg in SEED_EXAMPLES:
        if kw_lower in user_msg.lower():
            return (user_msg, asst_msg)
    return None


def generate_paraphrased_examples() -> list[tuple[str, str]]:
    augmented: list[tuple[str, str]] = []
    for template in PARAPHRASE_TEMPLATES:
        original = _find_seed_for_keyword(template["original_keyword"])
        if original is None:
            continue
        _, answer = original
        for variant_q in template["variants"]:
            augmented.append((variant_q, answer))
    return augmented


# ═══════════════════════════════════════════════════════════════════════════════
#  6. MULTI-TURN CONVERSATION EXAMPLES
# ═══════════════════════════════════════════════════════════════════════════════

MULTI_TURN_EXAMPLES: list[list[dict[str, str]]] = [
    # Pricing conversation
    [
        {"role": "user", "content": "What plans do you offer?"},
        {"role": "assistant", "content": "ApexMail offers five plans: Starter ($29/mo), Pro ($59/mo), Growth ($129/mo), Scale ($399/mo), and Enterprise ($1,299/mo). We also have PAYG pricing. Would you like details on a specific plan?"},
        {"role": "user", "content": "Which one is best for 50,000 emails per month?"},
        {"role": "assistant", "content": "For 50,000 emails/month, I'd recommend the **Pro plan** at $59/month, which includes up to 100,000 emails. That gives you room to grow without hitting overages.\n\nAlternatively, PAYG would cost about $45/month for 50,000 emails. The Pro plan is slightly more but includes higher API limits."},
    ],
    # Domain setup flow
    [
        {"role": "user", "content": "I just signed up. What's the first thing I should do?"},
        {"role": "assistant", "content": "Great to have you! Here are your first steps:\n\n1. **Add your sending domain** — go to Settings → Domains\n2. **Set up DNS records** — SPF, DKIM, and DMARC\n3. **Create an API key** — Settings → API Keys\n4. **Send a test email** — using the API or dashboard\n\nWould you like help with any of these steps?"},
        {"role": "user", "content": "Yes, help me set up my domain"},
        {"role": "assistant", "content": "To verify your sending domain:\n\n1. Go to **Settings → Domains** in your dashboard\n2. Click **Add Domain** and enter your domain name\n3. Add the DNS records we provide:\n   - **SPF**: TXT record on your domain\n   - **DKIM**: CNAME record (2048-bit key)\n   - **DMARC**: TXT record at `_dmarc.yourdomain.com`\n4. Click **Verify** — propagation usually takes 5–30 minutes\n\nOnce all three checks pass, your domain is ready to send."},
        {"role": "user", "content": "How long does DNS propagation take?"},
        {"role": "assistant", "content": "DNS propagation typically takes 5–30 minutes, but in some cases it can take up to 48 hours. You can check if your records are live using:\n\n```bash\ndig TXT yourdomain.com +short\ndig CNAME apexmail._domainkey.yourdomain.com +short\n```\n\nIf it's been more than 48 hours and verification still fails, double-check that the record values match exactly what's shown in your ApexMail dashboard."},
    ],
    # Troubleshooting flow
    [
        {"role": "user", "content": "My emails aren't being delivered. Help!"},
        {"role": "assistant", "content": "Let's troubleshoot this. First, some questions:\n\n1. Are emails bouncing (you see bounce events) or just not arriving?\n2. Is your domain verified? Check Settings → Domains\n3. Are you seeing any error messages in the API response?\n\nThe most common causes are:\n- Domain not authenticated (missing SPF/DKIM/DMARC)\n- Emails going to spam (check spam folder)\n- Suppressed addresses\n\nWhat error codes or behavior are you seeing?"},
        {"role": "user", "content": "I'm seeing 550 bounce codes"},
        {"role": "assistant", "content": "A 550 bounce code is a hard bounce — the recipient's server permanently rejected the email. Common reasons:\n\n- **550 User not found** — the email address doesn't exist\n- **550 Mailbox unavailable** — account disabled or full\n- **550 Rejected by policy** — the recipient's server blocked you\n\nApexMail automatically adds hard bounces to your suppression list. If you're seeing a lot of 550s:\n\n1. **Clean your list** — remove invalid addresses\n2. **Use email validation** — verify addresses before importing\n3. **Check your domain auth** — ensure SPF, DKIM, DMARC are set up\n\nKeep your hard bounce rate below 2% to maintain good sender reputation."},
    ],
    # API integration flow
    [
        {"role": "user", "content": "I want to integrate ApexMail with my app"},
        {"role": "assistant", "content": "Great! Here's how to get started:\n\n1. **Create an API key** in Settings → API Keys\n2. **Choose your integration method**:\n   - **REST API**: Direct HTTP calls to `https://api.apexmail.ee/v1`\n   - **Node.js SDK**: `npm install @apexmail/sdk`\n   - **Python SDK**: `pip install apexmail-python`\n   - **SMTP**: Use smtp.apexmail.ee with your API key\n\nWhich language/framework are you using?"},
        {"role": "user", "content": "Python with Django"},
        {"role": "assistant", "content": "Perfect! Install the Python SDK:\n\n```bash\npip install apexmail-python\n```\n\nThen in your Django views:\n\n```python\nfrom apexmail import ApexMail\n\nclient = ApexMail(api_key='am_live_your_key')\n\n# Send a transactional email\nresult = client.messages.send(\n    from_email='noreply@yourdomain.com',\n    to=user.email,\n    subject='Welcome to our app!',\n    html='<h1>Welcome, {{name}}!</h1>',\n    data={'name': user.first_name},\n)\n```\n\nStore your API key in environment variables or Django settings, not in code. Use `am_test_` keys for development."},
    ],
]


# ═══════════════════════════════════════════════════════════════════════════════
#  DATASET ASSEMBLY
# ═══════════════════════════════════════════════════════════════════════════════

def build_messages(user: str, assistant: str) -> dict:
    """Wrap a single-turn (user, assistant) pair in ChatML messages."""
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


def build_multiturn_messages(turns: list[dict[str, str]]) -> dict:
    """Wrap multi-turn conversation in ChatML messages."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    messages.extend(turns)
    return {"messages": messages}


def deduplicate(examples: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Remove duplicate user messages (keep first occurrence)."""
    seen: set[str] = set()
    unique: list[tuple[str, str]] = []
    for user_msg, asst_msg in examples:
        key = hashlib.md5(user_msg.strip().lower().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append((user_msg, asst_msg))
    return unique


def split_dataset(
    examples: list[dict],
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


def write_jsonl(path: Path, data: list[dict]) -> None:
    """Write data as JSONL."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for item in data:
            json.dump(item, f, ensure_ascii=False)
            f.write("\n")


@app.command()
def main(
    out_dir: str = typer.Option("data", help="Output directory for JSONL files"),
    dry_run: bool = typer.Option(False, help="Print stats without writing"),
    include_bitext: bool = typer.Option(False, help="Include Bitext HF dataset"),
    seed: int = typer.Option(42, help="Random seed"),
) -> None:
    """Generate comprehensive ChatML training dataset."""
    console.print("\n[bold cyan]ApexMail AI — Dataset Generator v2[/bold cyan]")
    console.print(f"  Model: Qwen/Qwen2.5-7B-Instruct")
    console.print(f"  Format: ChatML (messages JSONL)\n")

    all_single_turn: list[tuple[str, str]] = []
    all_formatted: list[dict] = []

    # 1. Seed examples
    all_single_turn.extend(SEED_EXAMPLES)
    console.print(f"  [cyan]Seed examples:[/cyan] {len(SEED_EXAMPLES)}")

    # 2. Paraphrased variants
    paraphrased = generate_paraphrased_examples()
    all_single_turn.extend(paraphrased)
    console.print(f"  [cyan]Paraphrased:[/cyan] {len(paraphrased)}")

    # 3. Plan-specific Q&A
    plan_examples = generate_plan_examples()
    all_single_turn.extend(plan_examples)
    console.print(f"  [cyan]Plan-specific:[/cyan] {len(plan_examples)}")

    # 4. Documentation-grounded Q&A
    doc_qa = extract_doc_qa_pairs()
    all_single_turn.extend(doc_qa)
    console.print(f"  [cyan]Doc-grounded:[/cyan] {len(doc_qa)}")

    # 5. 500-fixes checklist Q&A
    checklist_qa = extract_checklist_qa()
    all_single_turn.extend(checklist_qa)
    console.print(f"  [cyan]Checklist Q&A:[/cyan] {len(checklist_qa)}")

    # 6. Bitext customer support (optional)
    if include_bitext:
        bitext_qa = load_bitext_examples(max_examples=500)
        all_single_turn.extend(bitext_qa)
        console.print(f"  [cyan]Bitext CS:[/cyan] {len(bitext_qa)}")

    # Deduplicate single-turn
    all_single_turn = deduplicate(all_single_turn)
    console.print(f"  [cyan]After dedup:[/cyan] {len(all_single_turn)}")

    # Convert to ChatML format
    for user_msg, asst_msg in all_single_turn:
        all_formatted.append(build_messages(user_msg, asst_msg))

    # 7. Multi-turn conversations
    for conv in MULTI_TURN_EXAMPLES:
        all_formatted.append(build_multiturn_messages(conv))
    console.print(f"  [cyan]Multi-turn:[/cyan] {len(MULTI_TURN_EXAMPLES)}")

    console.print(f"\n  [bold]Total examples:[/bold] {len(all_formatted)}")

    # Split
    train, val, test = split_dataset(all_formatted, seed=seed)

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

    # Also write golden QA set for evaluation (from eval.py's GOLDEN_SET)
    golden = _build_golden_set()
    if golden:
        write_jsonl(out / "golden_qa.jsonl", golden)
        console.print(f"  [cyan]Golden QA set:[/cyan] {len(golden)} items")

    console.print(f"\n[green]✓ Written to {out.resolve()}[/green]")


def _build_golden_set() -> list[dict]:
    """Build golden QA set for evaluation from eval.py's GOLDEN_SET."""
    try:
        from eval import GOLDEN_SET
        return GOLDEN_SET
    except ImportError:
        console.print("  [yellow]Skipping golden_qa.jsonl (eval.py deps not available)[/yellow]")
        return []


if __name__ == "__main__":
    app()
