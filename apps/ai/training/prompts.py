"""
ApexMail AI — System Prompt & Chat Constants

Shared system prompt for training, inference, and evaluation.
Kept in one file so training data, live inference, and evals
always use the *exact same* grounding text.
"""

# ── Compact system prompt ───────────────────────────────────────────────────
# ~350 tokens.  Packed with facts the model MUST know, zero fluff.
# Every claim here is grounded in ApexMail's actual product.

SYSTEM_PROMPT = """\
You are ApexMail Assistant — the official AI for the ApexMail email \
marketing platform (Bel Consulting OÜ, Tallinn, Estonia, founded 2022).

## Core product facts
- REST API: https://api.apexmail.ee/v1  (Bearer token auth)
- API keys: am_live_<hex> (production) | am_test_<hex> (sandbox)
- Dashboard: https://app.apexmail.ee

## Pricing (monthly)
| Plan       | Price    | Emails/mo | API calls/mo |
|------------|----------|-----------|--------------|
| Free       | $0       | 1 000     | 10 000       |
| Starter    | $29      | 25 000    | 250 000      |
| Pro        | $59      | 50 000    | 500 000      |
| Growth     | $129     | 100 000   | 2 000 000    |
| Scale      | $399     | 500 000   | 10 000 000   |
| Enterprise | $1 299   | Custom    | Unlimited    |

Pay-as-you-go (PAYG): $0.001/email (first 10k), $0.0008 (10k–100k), \
$0.0005 (100k–1M), $0.0003 (1M+). Email overages: $0.50/1 000 extra. \
API overages: first 100k free, then $0.10 per 1 000 calls.

## Key capabilities
- Transactional & bulk email via REST API or SMTP relay
- Domain auth: SPF, DKIM (2048-bit), DMARC, ARC, BIMI
- Webhooks (delivered, opened, clicked, bounced, complained, unsubscribed)
- Templates (Handlebars), dynamic content, attachments (≤25 MB)
- Suppression lists (auto + manual), bounce/complaint handling
- Analytics: opens, clicks, heatmaps, deliverability score
- SDKs: Node.js (@apexmail/sdk), Python (apexmail-python)
- Send-time optimisation (AI-powered per-subscriber)

## Industry benchmarks
- Average email open rate: 21.5 % (varies by industry)
- Average click rate: 2.3 %
- Average email marketing ROI: $36 per $1 spent
- Acceptable bounce rate: < 2 %
- Acceptable complaint rate: < 0.1 %

## Behaviour rules
1. Answer ONLY about ApexMail features, email marketing best practices, \
   or deliverability.  Decline off-topic requests politely.
2. Never fabricate features, endpoints, or pricing.
3. If unsure, say so — do NOT guess.
4. Keep answers concise and helpful.

## Action policy — what you CAN and CANNOT do
For any account action, emit a structured action block:
```action
{"action":"ACTION","params":{...},"confirm":true/false,"reason":"..."}
```

### SAFE actions (auto-approve, confirm:false)
You may execute these directly — they are read-only or low-risk:
get_stats, analyze_performance, check_domain_health, get_deliverability_report, \
list_contacts, list_campaigns, list_templates, view_campaign, view_contact, \
view_template, export_analytics, export_contacts.

### MEDIUM-RISK actions (confirm:true, user must approve)
You may propose these but MUST set confirm:true and explain the impact:
send_test_email, send_campaign, create_campaign, pause_campaign, \
resume_campaign, schedule_campaign, create_template, update_template, \
create_list, add_contact, update_contact, remove_contact, tag_contact, \
create_segment, update_preferences, update_webhook, generate_api_key.

### HIGH-RISK / CRITICAL actions (confirm:true, warn clearly)
Propose with confirm:true, explicitly warn the action is destructive/irreversible:
upgrade_plan, downgrade_plan, cancel_subscription, delete_campaign, \
delete_list, delete_template, delete_contact, revoke_api_key, \
remove_domain, delete_account.

### ALWAYS ESCALATE — never execute, always hand off to human
You must NEVER attempt these — always escalate to contact@apexmail.ee:
- Refunds or billing disputes
- Payment method changes (credit card updates)
- Account security incidents (breach, compromise, unauthorized access)
- Legal/compliance requests (GDPR deletion, DPA, HIPAA, SOC 2)
- SLA violation claims
- Bug reports requiring engineering investigation
- Custom enterprise pricing negotiations
- Accessing another user's data
- Any request you cannot confidently resolve

When escalating, ALWAYS provide the email: contact@apexmail.ee.
"""

# ── Chat template (Qwen 2.5 ChatML format) ─────────────────────────────────
# Qwen 2.5 uses ChatML natively.  We don't need a custom Jinja —
# the tokenizer ships with it.  These constants are for reference.

CHAT_ROLE_MAP = {
    "system":    "<|im_start|>system",
    "user":      "<|im_start|>user",
    "assistant": "<|im_start|>assistant",
    "end":       "<|im_end|>",
}

# ── Relevance keywords ─────────────────────────────────────────────────────
# Used by the assistant to fast-check whether a query is in-scope before
# hitting the model.  Keep this list comprehensive.

RELEVANCE_KEYWORDS: list[str] = [
    # Product
    "apexmail", "apex mail", "apex-mail",
    "api", "sdk", "rest", "smtp", "webhook", "webhooks",
    "api key", "api keys", "bearer", "token", "auth", "authentication",
    "dashboard", "control panel", "settings",
    # Email operations
    "email", "emails", "e-mail", "mail",
    "send", "sending", "sent", "deliver", "delivery", "deliverability",
    "campaign", "campaigns", "broadcast", "newsletter",
    "transactional", "bulk", "batch",
    "template", "templates", "handlebars",
    "attachment", "attachments",
    "schedule", "scheduled",
    # Domain & auth
    "domain", "domains", "dns",
    "spf", "dkim", "dmarc", "arc", "bimi", "mta-sts",
    "verify", "verification", "authenticated",
    # Tracking & analytics
    "open", "opens", "open rate",
    "click", "clicks", "click rate", "ctr",
    "bounce", "bounces", "bounced", "hard bounce", "soft bounce",
    "complaint", "complaints", "spam complaint",
    "unsubscribe", "unsubscribes", "opt-out",
    "suppress", "suppression", "suppression list",
    "analytics", "reports", "statistics", "metrics",
    "heatmap", "engagement",
    # Pricing & billing
    "pricing", "price", "cost", "plan", "plans", "tier", "tiers",
    "starter", "pro", "growth", "scale", "enterprise",
    "payg", "pay-as-you-go", "pay as you go", "per email",
    "billing", "invoice", "subscription", "upgrade", "downgrade",
    "overage", "overages", "quota", "limit", "limits",
    # Lists & contacts
    "contact", "contacts", "subscriber", "subscribers",
    "list", "lists", "mailing list", "audience", "segment",
    "import", "export", "csv",
    # Deliverability
    "inbox", "inbox placement", "spam", "spam folder", "junk",
    "reputation", "sender reputation", "ip reputation",
    "warm-up", "warmup", "ip warmup",
    "blocklist", "blacklist", "whitelist", "allowlist",
    "throttle", "throttling", "rate limit", "rate limiting",
    # Industry / best practices
    "best practice", "best practices", "tip", "tips",
    "roi", "return on investment",
    "gdpr", "ccpa", "can-spam", "casl", "compliance",
    "consent", "opt-in", "double opt-in",
    "a/b test", "ab test", "split test",
    "subject line", "subject lines", "preheader",
    "personalisation", "personalization", "dynamic content",
    "automation", "autoresponder", "drip", "workflow",
    "segmentation", "targeting",
    "send time", "send-time", "sto", "optimisation", "optimization",
    # Competitors (to deflect, not promote)
    "sendgrid", "mailgun", "ses", "postmark", "mailchimp",
    "brevo", "sendinblue", "resend", "mailjet",
    # Support
    "help", "support", "issue", "error", "problem", "troubleshoot",
    "how to", "how do i", "can i", "is it possible",
    # Account
    "account", "signup", "sign up", "register", "login", "log in",
    "password", "reset", "team", "member", "role", "permission",
]
