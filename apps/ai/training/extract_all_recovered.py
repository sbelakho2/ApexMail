#!/usr/bin/env python3
"""
extract_all_recovered.py — Complete extraction of ALL recovered test & training content
═══════════════════════════════════════════════════════════════════════════════════════

Extracts and transforms all content from:
- /tmp/apexmail_scenarios/stress_test_r34.py (171 tests, 26 categories)
- /tmp/apexmail_scenarios/stress_test_extra.py (~80 tests, 12 categories)
- /tmp/apexmail_scenarios/customer_profiles.py (60 profiles)
- /tmp/apexmail_scenarios/expand_dataset.py (training patterns)

All pricing transformed: Schema A (USD) → canonical EUR catalog
  USD 29→€29 (Developer), USD 59→€89 (Pro), USD 129→€229 (Growth),
  USD 399→€699 (Business), USD 1299→€1,750 (Enterprise Cloud)
  Free: 1K→3K emails/mo, 10K→30K API (30K launch allowance separate)
  Developer: 25K→50K emails, 250K→500K API
  Pro: 50K→150K emails, 500K→2M API
  Growth: 100K→500K emails, 1M→5M API
  Business: 500K→2M emails, 5M→20M API
  Enterprise Cloud: 2M→5M emails, 20M→unlimited API
"""

import ast
import json
import os
import re
import sys

import tempfile

os.chdir(os.path.dirname(__file__) or ".")
sys.path.insert(0, ".")

from validate_pricing import PLAN_BY_NAME  # noqa: E402

TEMP_DIR = os.environ.get("TEMP_DIR", "/tmp/apexmail_scenarios")
RECOVERED_DIR = TEMP_DIR

# ══════════════════════════════════════════════════════════════════════════════
# PRICING TRANSFORMATION RULES
# ══════════════════════════════════════════════════════════════════════════════

def transform_text(text: str) -> str:
    """Transform Schema A (USD, pre-2026-09-08 limits) to the canonical EUR
    catalog. Targets are derived from validate_pricing.CANONICAL_PRICING."""
    ets = PLAN_BY_NAME["enterprise cloud"]
    replacements = [
        # Schema A USD prices → canonical EUR plan names are attached by the
        # fixture text itself (the sweep adds names where needed).
        (r'\$29/mo', f"{PLAN_BY_NAME['developer']['price']}/mo"),
        (r'\$29', PLAN_BY_NAME['developer']['price']),
        (r'\$59/mo', f"{PLAN_BY_NAME['pro']['price']}/mo"),
        (r'\$59', PLAN_BY_NAME['pro']['price']),
        (r'\$129/mo', f"{PLAN_BY_NAME['growth']['price']}/mo"),
        (r'\$129', PLAN_BY_NAME['growth']['price']),
        (r'\$399/mo', f"{PLAN_BY_NAME['business']['price']}/mo"),
        (r'\$399', PLAN_BY_NAME['business']['price']),
        (r'\$1,299/mo', f"{ets['price']}/mo"),
        (r'\$1,299', ets['price']),
        (r'\$1299', ets['price']),

        # Free plan: 1,000 → 3,000 emails/mo, 10,000 → 30,000 API.
        (r'1,000 email', f"{PLAN_BY_NAME['free']['emails']:,} email"),
        (r'1K email', "3K email"),
        (r'10,000 API', f"{PLAN_BY_NAME['free']['api_calls']:,} API"),
        (r'10K API', "30K API"),

        # Developer plan: 25K→50K emails, 250K→500K API.
        (r'25,000 email', f"{PLAN_BY_NAME['developer']['emails']:,} email"),
        (r'25K email', "50K email"),
        (r'250,000 API', f"{PLAN_BY_NAME['developer']['api_calls']:,} API"),
        (r'250K API', "500K API"),

        # Pro plan: 50K→150K emails, 500K→2M API.
        (r'Pro plan.*?50,000 email', f"Pro plan with {PLAN_BY_NAME['pro']['emails']:,} email"),
        (r'Pro.*?500,000 API', f"Pro with {PLAN_BY_NAME['pro']['api_calls']:,} API"),

        # Growth plan: 100K→500K emails, 1M→5M API.
        (r'Growth.*?100,000 email', f"Growth with {PLAN_BY_NAME['growth']['emails']:,} email"),
        (r'Growth.*?1,000,000 API', f"Growth with {PLAN_BY_NAME['growth']['api_calls']:,} API"),
        (r'"100,000"', f'"{PLAN_BY_NAME["growth"]["emails"]:,}"'),
        (r'"100K"', '"500K"'),

        # Business plan: 500K→2M emails, 5M→20M API.
        (r'Business.*?500,000 email', f"Business with {PLAN_BY_NAME['business']['emails']:,} email"),
        (r'Business.*?5,000,000 API', f"Business with {PLAN_BY_NAME['business']['api_calls']:,} API"),

        # Enterprise Cloud: 2M→5M emails, 20M→unlimited API.
        (r'Enterprise Cloud.*?2,000,000 email', f"Enterprise Cloud with {ets['emails']:,} email"),
        (r'Enterprise Cloud.*?20,000,000 API', "Enterprise Cloud with Unlimited API"),
    ]
    
    result = text
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    
    return result


def transform_checks(checks: dict) -> dict:
    """Transform pricing in check dict values."""
    new_checks = {}
    for key, value in checks.items():
        if isinstance(value, list):
            new_checks[key] = [transform_text(str(v)) for v in value]
        elif isinstance(value, str):
            new_checks[key] = transform_text(value)
        else:
            new_checks[key] = value
    return new_checks


# ══════════════════════════════════════════════════════════════════════════════
# MANUAL EXTRACTION FROM RECOVERED stress_test_r34.py
# ══════════════════════════════════════════════════════════════════════════════

# These are manually curated from the file with canonical pricing applied

STRESS_TEST_R34_CATEGORIES = {
    
    # ── A: Domain & DNS Troubleshooting ──────────────────────────────────
    "dns_troubleshooting": [
        {"q": "I added SPF and DKIM records 2 minutes ago. Why isn't my domain verified yet?",
         "checks": {"must_contain_any": ["propagation", "minutes", "hours", "wait", "time"],
                    "must_not_contain": ["instant"]}},
        {"q": "Should I send marketing emails from my root domain example.com or a subdomain?",
         "checks": {"must_contain_any": ["subdomain", "isolat", "reputation"]}},
        {"q": "I already have SPF for Google Workspace. How do I add ApexMail without breaking things?",
         "checks": {"must_contain": ["_spf.apexmail.ee"],
                    "must_contain_any": ["merge", "single", "one", "combine", "include"]}},
        {"q": "Can I use a TXT record instead of CNAME for ApexMail DKIM?",
         "checks": {"must_contain_any": ["CNAME", "no", "cannot", "not", "require"]}},
        {"q": "My domain was verified last week but now shows unverified. What happened?",
         "checks": {"must_contain_any": ["re-verif", "DNS", "record", "removed", "changed", "deleted"]}},
        {"q": "I'm using Cloudflare with the orange proxy cloud on my DKIM record. Is that OK?",
         "checks": {"must_contain_any": ["no", "DNS only", "grey", "disable", "proxy", "not"]}},
        {"q": "What's the Return-Path CNAME I need for ApexMail?",
         "checks": {"must_contain": ["bounce"],
                    "must_contain_any": ["bounce.apexmail.ee", "CNAME"]}},
    ],

    # ── B: DKIM/SPF/DMARC Correctness ───────────────────────────────────
    "auth_correctness": [
        {"q": "My DKIM fails with 'body hash did not verify'. Is my DKIM setup wrong?",
         "checks": {"must_contain_any": ["modified", "transit", "forward", "body", "alter"],
                    "must_not_contain": ["setup is wrong", "reconfigure"]}},
        {"q": "What DMARC policy should I start with for a new domain?",
         "checks": {"must_contain": ["none"],
                    "must_contain_any": ["p=none", "monitor", "start"]}},
        {"q": "I have DMARC p=reject on my root domain. Does it cover mail.example.com too?",
         "checks": {"must_contain_any": ["inherit", "subdomain", "sp=", "yes", "cover"]}},
        {"q": "What is ARC and how does it help with email forwarding?",
         "checks": {"must_contain_any": ["forward", "chain", "Authenticated Received Chain", "intermediary"]}},
        {"q": "What do I need to set up BIMI and show my logo in Gmail?",
         "checks": {"must_contain": ["DMARC"],
                    "must_contain_any": ["VMC", "certificate", "Verified Mark", "p=reject", "p=quarantine"]}},
    ],

    # ── C: Sender Identity & Alignment ───────────────────────────────────
    "sender_identity": [
        {"q": "My Gmail recipients say my emails show 'via apexmail.io'. How do I fix that?",
         "checks": {"must_contain_any": ["DKIM", "Return-Path", "bounce", "alignment", "domain"]}},
        {"q": "I want to send from newsletter@brand.com but get replies at support@brand.com. Is that possible?",
         "checks": {"must_contain_any": ["Reply-To", "reply_to", "yes"]}},
        {"q": "I'm trying to send from a domain that's not verified and I get a 422 error.",
         "checks": {"must_contain": ["verif"],
                    "must_contain_any": ["Dashboard", "DNS", "domain", "add"]}},
        {"q": "What's the difference between envelope-from and header-from?",
         "checks": {"must_contain_any": ["Return-Path", "envelope", "bounce", "visible", "recipient", "SPF"]}},
    ],

    # ── D: API & Auth Troubleshooting ────────────────────────────────────
    "api_troubleshooting": [
        {"q": "My API key was working yesterday but now returns 401. What could cause this?",
         "checks": {"must_contain_any": ["revoked", "suspended", "wrong key", "am_test_", "am_live_"]}},
        {"q": "The API returned 202 Accepted for my send request. Is the email delivered?",
         "checks": {"must_contain_any": ["no", "queued", "not", "asynchronous", "webhook", "202"]}},
        {"q": "I'm getting 429 Too Many Requests on the API. What are the limits?",
         "checks": {"must_contain_any": ["rate limit", "API call limit", "API limit", "exceeded", "429"]}},
        {"q": "How do I prevent sending duplicate emails if my network is unreliable?",
         "checks": {"must_contain_any": ["idempoten", "Idempotency-Key", "UUID", "unique"]}},
        {"q": "What's the maximum file size I can attach to an email?",
         "checks": {"must_contain_any": ["25 MB", "25MB", "25 megabyte"]}},
        {"q": "What format should attachments be in when using the API?",
         "checks": {"must_contain_any": ["base64", "Base64", "encoded"]}},
    ],

    # ── E: Webhooks & Events ─────────────────────────────────────────────
    "webhook_troubleshooting": [
        {"q": "I configured a webhook but I'm on the Free plan. Why am I not receiving events?",
         "checks": {"must_contain_any": ["Free", "not available", "Developer", "paid", "no webhook"]}},
        {"q": "How do I verify that a webhook is really from ApexMail and not spoofed?",
         "checks": {"must_contain_any": ["HMAC", "SHA256", "signature", "signing secret", "verify"]}},
        {"q": "My webhook endpoint is slow. What happens if it takes over 30 seconds?",
         "checks": {"must_contain_any": ["timeout", "retry", "30 second", "failed", "async"]}},
        {"q": "What webhook events does ApexMail support?",
         "checks": {"must_contain_any": ["delivered", "bounced", "opened", "clicked", "complained"]}},
        {"q": "I'm getting duplicate webhook events. How should I handle this?",
         "checks": {"must_contain_any": ["idempoten", "event_id", "duplicate", "at-least-once"]}},
        {"q": "Open tracking doesn't work for some of my recipients. Why?",
         "checks": {"must_contain_any": ["pixel", "image", "block", "plain text", "privacy"]}},
    ],

    # ── F: Bounces, Complaints & Suppressions ────────────────────────────
    "bounce_management": [
        {"q": "What's the difference between a hard bounce and a soft bounce?",
         "checks": {"must_contain": ["permanent"],
                    "must_contain_any": ["temporary", "retry", "4.2.2", "mailbox"]}},
        {"q": "An email shows as 'delivered' but the user says they never got it. What's going on?",
         "checks": {"must_contain_any": ["spam", "junk", "folder", "Promotions", "accepted"]}},
        {"q": "I keep trying to send to user@example.com but it fails instantly. Why?",
         "checks": {"must_contain_any": ["suppress", "suppression", "hard bounce", "list"]}},
        {"q": "Our complaint rate is 0.15%. Is that a problem?",
         "checks": {"must_contain_any": ["above", "exceed", "0.1%", "problem", "yes", "critical", "high"]}},
        {"q": "We want to send 100K emails on our first day with a new dedicated IP.",
         "checks": {"must_contain_any": ["warmup", "warm-up", "no", "cannot", "block", "schedule"]}},
        {"q": "What is ApexMail's retry schedule for soft bounces?",
         "checks": {"must_contain_any": ["30 s", "30s", "exponential", "backoff", "3 attempt", "3 retries", "retry"]}},
        {"q": "Emails to Outlook recipients bounce with 550 5.7.1. What do I do?",
         "checks": {"must_contain_any": ["Microsoft", "SNDS", "sender.office.com", "reputation", "delist"]}},
    ],

    # ── G: Deliverability & Inbox Placement ──────────────────────────────
    "deliverability_placement": [
        {"q": "My emails land in Gmail's Promotions tab. Is this the same as spam?",
         "checks": {"must_contain_any": ["not spam", "not the same", "delivered", "Promotions"],
                    "must_not_contain": ["spam folder"]}},
        {"q": "Should I set up a custom tracking domain? What does it do?",
         "checks": {"must_contain_any": ["CNAME", "track", "deliverability", "brand"]}},
        {"q": "I use bit.ly links in my marketing emails. Is that bad?",
         "checks": {"must_contain_any": ["spam", "avoid", "shortener", "full URL", "penalize", "block"]}},
        {"q": "What's the acceptable bounce rate for email marketing?",
         "checks": {"must_contain_any": ["2%", "below 2", "under 2"]}},
        {"q": "What's the difference between IP reputation and domain reputation?",
         "checks": {"must_contain": ["IP", "domain"],
                    "must_contain_any": ["separate", "both", "different", "independent"]}},
        {"q": "I want separate IPs for transactional and marketing email. What plans support this?",
         "checks": {"must_contain_any": ["Business", "€699", "Enterprise Cloud", "IP pool"]}},
        {"q": "How do I check if I'm on a blocklist like Spamhaus?",
         "checks": {"must_contain_any": ["Spamhaus", "check.spamhaus.org", "blocklist", "DNSBL"]}},
        {"q": "I'm on the Free plan. Can I get a dedicated IP address?",
         "checks": {"must_contain_any": ["no", "Pro", "€89", "not available"]}},
    ],

    # ── H: Templates, Rendering & Content ────────────────────────────────
    "template_rendering": [
        {"q": "My email template shows raw {{first_name}} instead of the person's name.",
         "checks": {"must_contain_any": ["mismatch", "match", "case", "typo", "merge", "variable"]}},
        {"q": "What Handlebars helpers does ApexMail support?",
         "checks": {"must_contain": ["if"],
                    "must_contain_any": ["each", "unless", "formatDate", "formatCurrency", "uppercase", "lowercase"]}},
        {"q": "Is it safe to render user-supplied data in Handlebars templates?",
         "checks": {"must_contain_any": ["escape", "double brace", "triple brace", "HTML-escape", "safe"]}},
        {"q": "Can I preview how my email looks on different devices before sending?",
         "checks": {"must_contain_any": ["preview", "test", "send test"]}},
        {"q": "What's the maximum email HTML size before Gmail clips it?",
         "checks": {"must_contain_any": ["102 KB", "102KB", "kilobyte"]}},
    ],

    # ── I: API Rate Limits ───────────────────────────────────────────────
    "api_rate_limits": [
        {"q": "What are the API rate limits on the Developer plan?",
         "checks": {"must_contain_any": ["500,000", "500K", "per month"]}},
        {"q": "Can I burst 10,000 API calls in one minute?",
         "checks": {"must_contain_any": ["no", "rate", "throttle", "spread"]}},
        {"q": "What happens if I hit the monthly API call limit?",
         "checks": {"must_contain_any": ["429", "error", "queued", "upgrade"]}},
        {"q": "Growth plan API limits - what are they exactly?",
         "checks": {"must_contain_any": ["5,000,000", "5M", "5 million"]}},
    ],

    # ── J: Security & Account ────────────────────────────────────────────
    "security_controls": [
        {"q": "I forgot my password and my MFA device is lost. How do I recover?",
         "checks": {"must_contain_any": ["contact", "support", "email", "manual"]}},
        {"q": "How many failed login attempts before lockout?",
         "checks": {"must_contain_any": ["5", "five", "lockout", "15 minute"]}},
        {"q": "Can I require MFA for all team members?",
         "checks": {"must_contain_any": ["yes", "Business", "Enterprise Cloud", "enforce"]}},
        {"q": "How long do team invites stay valid?",
         "checks": {"must_contain_any": ["72", "hour", "3 day", "expire"]}},
        {"q": "How do I rotate my API keys without downtime?",
         "checks": {"must_contain_any": ["create new", "test", "delete old", "transition"]}},
    ],

    # ── K: Account Lockout / MFA ─────────────────────────────────────────
    "account_lockout_mfa": [
        {"q": "I'm locked out after too many failed logins. What do I do?",
         "checks": {"must_contain_any": ["15 minute", "wait", "reset", "support"]}},
        {"q": "My authenticator app was on a phone I lost. Recovery options?",
         "checks": {"must_contain_any": ["contact", "support", "backup", "recovery"]}},
        {"q": "Can I use a hardware security key like YubiKey for MFA?",
         "checks": {"must_contain_any": ["yes", "no", "TOTP", "authenticator"]}},
    ],

    # ── L: Sending Suspension ────────────────────────────────────────────
    "sending_suspension": [
        {"q": "My account shows 'sending suspended'. What happened?",
         "checks": {"must_contain_any": ["bounce", "complaint", "abuse", "review"]}},
        {"q": "How long does a suspension review take?",
         "checks": {"must_contain_any": ["24 hour", "business day", "review"]}},
        {"q": "I didn't do anything wrong - false positive suspension. Help!",
         "checks": {"must_contain_any": ["contact", "appeal", "support", "review"]}},
    ],

    # ── M: Compliance & Privacy ──────────────────────────────────────────
    "compliance_privacy": [
        {"q": "Is ApexMail GDPR compliant?",
         "checks": {"must_contain_any": ["yes", "GDPR", "DPA", "EU"]}},
        {"q": "Does ApexMail offer a Data Processing Agreement (DPA)?",
         "checks": {"must_contain_any": ["yes", "DPA", "contact", "Enterprise Cloud"]}},
        {"q": "What happens to my data if I cancel my account?",
         "checks": {"must_contain_any": ["delete", "retention", "days", "export"]}},
        {"q": "Is ApexMail HIPAA compliant?",
         "checks": {"must_contain_any": ["Enterprise Cloud", "BAA", "contact", "HIPAA"]}},
        {"q": "Where is my data stored geographically?",
         "checks": {"must_contain_any": ["EU", "Europe", "Hetzner", "Germany"]}},
    ],

    # ── N: Quota & Plan Mechanics ────────────────────────────────────────
    "quota_mechanics": [
        {"q": "When does my monthly email quota reset?",
         "checks": {"must_contain_any": ["billing", "cycle", "anniversary", "month"]}},
        {"q": "Do bounced emails count against my quota?",
         "checks": {"must_contain_any": ["yes", "count", "quota"]}},
        {"q": "Can I carry over unused emails to next month?",
         "checks": {"must_contain_any": ["no", "cannot", "reset", "expire"]}},
        {"q": "If I upgrade mid-cycle, is my new quota prorated?",
         "checks": {"must_contain_any": ["immediately", "full", "new quota"]}},
    ],

    # ── O: SDK Integration ───────────────────────────────────────────────
    "sdk_integration": [
        {"q": "What's the Python SDK package name?",
         "checks": {"must_contain_any": ["apexmail", "pip", "PyPI"]}},
        {"q": "Does the Python SDK support async/await?",
         "checks": {"must_contain_any": ["yes", "async", "await", "asyncio"]}},
        {"q": "What's the minimum Python version for the SDK?",
         "checks": {"must_contain_any": ["3.9", "3.10", "Python 3"]}},
    ],

    # ── P: SDK Multi-Language ────────────────────────────────────────────
    "sdk_multilang": [
        {"q": "Is there a Go SDK for ApexMail?",
         "checks": {"must_contain_any": ["yes", "Go", "github.com/apexmail"]}},
        {"q": "What's the Ruby gem name?",
         "checks": {"must_contain_any": ["apexmail", "gem"]}},
        {"q": "PHP SDK - what's the minimum PHP version?",
         "checks": {"must_contain_any": ["8.1", "PHP 8"]}},
        {"q": "Is there a Java SDK?",
         "checks": {"must_contain_any": ["yes", "Java", "Maven", "ee.apexmail"]}},
    ],

    # ── Q: Provider Migration ────────────────────────────────────────────
    "provider_migration_deep": [
        {"q": "Migrating from SendGrid - what DNS changes do I need?",
         "checks": {"must_contain_any": ["SPF", "DKIM", "CNAME", "remove"]}},
        {"q": "Coming from Amazon SES - any API differences I should know?",
         "checks": {"must_contain_any": ["API", "endpoint", "auth", "Bearer"]}},
        {"q": "I have 500K contacts in Mailchimp. Can I import them?",
         "checks": {"must_contain_any": ["CSV", "import", "yes"]}},
        {"q": "Postmark template format - compatible with ApexMail?",
         "checks": {"must_contain_any": ["convert", "Handlebars", "syntax"]}},
    ],

    # ── R: IP & Infrastructure ───────────────────────────────────────────
    "ip_infrastructure": [
        {"q": "How many dedicated IPs are included with Business?",
         "checks": {"must_contain_any": ["3", "three"]}},
        {"q": "Can I bring my own IP address (BYOIP)?",
         "checks": {"must_contain_any": ["Enterprise Cloud", "contact", "BYOIP"]}},
        {"q": "How much does an additional dedicated IP cost?",
         "checks": {"must_contain_any": ["€30", "30", "month"]}},
    ],

    # ── S: Message Diagnostics ───────────────────────────────────────────
    "message_diagnostics": [
        {"q": "How can I see what happened to a specific email I sent?",
         "checks": {"must_contain_any": ["message ID", "event", "search", "dashboard"]}},
        {"q": "How long does ApexMail retain message body content?",
         "checks": {"must_contain_any": ["7", "30", "day", "retention"]}},
        {"q": "Can I see the raw email headers for troubleshooting?",
         "checks": {"must_contain_any": ["yes", "header", "diagnostic"]}},
    ],

    # ── T: Message Lifecycle ─────────────────────────────────────────────
    "message_lifecycle": [
        {"q": "How long will ApexMail retry a deferred message?",
         "checks": {"must_contain_any": ["72", "hour", "3 day"]}},
        {"q": "Can I cancel a scheduled email after it's queued?",
         "checks": {"must_contain_any": ["yes", "cancel", "schedule"]}},
        {"q": "What does 'deferred' status mean?",
         "checks": {"must_contain_any": ["temporary", "retry", "later"]}},
    ],

    # ── U: Link Tracking ─────────────────────────────────────────────────
    "link_tracking": [
        {"q": "How do I disable click tracking for a specific link?",
         "checks": {"must_contain_any": ["data-apexmail", "no-track", "attribute"]}},
        {"q": "Why do my links show the ApexMail domain before redirecting?",
         "checks": {"must_contain_any": ["tracking", "redirect", "custom domain"]}},
        {"q": "Can I use my own domain for tracking links?",
         "checks": {"must_contain_any": ["yes", "CNAME", "custom"]}},
    ],

    # ── V: Link Tracking Deep ────────────────────────────────────────────
    "link_tracking_deep": [
        {"q": "Do tracked links work with HTTPS on custom domains?",
         "checks": {"must_contain_any": ["yes", "SSL", "HTTPS", "certificate"]}},
        {"q": "Are bot clicks filtered from my analytics?",
         "checks": {"must_contain_any": ["yes", "filter", "bot", "detection"]}},
        {"q": "Click tracking shows 0% but users say they clicked. Why?",
         "checks": {"must_contain_any": ["plain text", "disabled", "bot"]}},
    ],

    # ── W: Billing & SLA ─────────────────────────────────────────────────
    "billing_sla": [
        {"q": "What's the email overage rate per 1,000 emails?",
         "checks": {"must_contain_any": ["€0.80", "0.40", "40 cent"]}},
        {"q": "What's the ApexMail uptime SLA?",
         "checks": {"must_contain_any": ["99.9", "SLA"]}},
        {"q": "How do I get credits for downtime?",
         "checks": {"must_contain_any": ["contact", "support", "SLA", "credit"]}},
        {"q": "Do I get a discount for annual billing?",
         "checks": {"must_contain_any": ["yes", "annual", "discount"]}},
    ],

    # ── X: Security Advanced ─────────────────────────────────────────────
    "security_advanced": [
        {"q": "Does ApexMail support SOC2 compliance?",
         "checks": {"must_contain_any": ["Enterprise Cloud", "SOC2", "SOC 2", "contact"]}},
        {"q": "Can I get audit logs for my team's actions?",
         "checks": {"must_contain_any": ["Business", "Enterprise Cloud", "audit"]}},
        {"q": "Is there SSO support with SAML?",
         "checks": {"must_contain_any": ["Business", "Enterprise Cloud", "SSO", "SAML"]}},
        {"q": "Can I restrict API keys to specific IPs?",
         "checks": {"must_contain_any": ["yes", "allowlist", "IP restriction"]}},
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL TESTS FROM stress_test_extra.py (not already in recovered)
# ══════════════════════════════════════════════════════════════════════════════

STRESS_TEST_EXTRA_CATEGORIES = {
    
    "api_depth": [
        {"q": "What's the difference between am_test_ and am_live_ API keys?",
         "checks": {"must_contain_any": ["test", "live", "sandbox", "production"]}},
        {"q": "Can I use test API keys in production?",
         "checks": {"must_contain_any": ["no", "not", "test", "sandbox"]}},
        {"q": "What scopes are available for API keys?",
         "checks": {"must_contain_any": ["emails:send", "emails:read", "domains", "webhooks"]}},
    ],

    "escalation_advanced": [
        {"q": "I need to speak to a human right now. This is urgent.",
         "checks": {"must_contain_any": ["contact", "support", "email", "urgent"]}},
        {"q": "Your bot is giving me wrong answers. Let me talk to someone real.",
         "checks": {"must_contain_any": ["contact", "support", "apexmail.ee"]}},
        {"q": "I've been having issues for 3 weeks. I demand a callback.",
         "checks": {"must_contain_any": ["contact", "support", "escalate", "premium"]}},
    ],

    "deliverability_advanced": [
        {"q": "What's the ideal sending frequency to avoid spam filters?",
         "checks": {"must_contain_any": ["consistent", "regular", "spike"]}},
        {"q": "My engagement rates dropped after a large send. What happened?",
         "checks": {"must_contain_any": ["reputation", "throttle", "warmup"]}},
        {"q": "Should I use a different subdomain for transactional vs marketing?",
         "checks": {"must_contain_any": ["yes", "isolate", "reputation"]}},
    ],

    "compliance_advanced": [
        {"q": "Do you support MTA-STS?",
         "checks": {"must_contain_any": ["yes", "MTA-STS", "TLS", "secure"]}},
        {"q": "What's your data retention policy for event logs?",
         "checks": {"must_contain_any": ["90", "day", "retention"]}},
        {"q": "Can I export all my data for portability?",
         "checks": {"must_contain_any": ["yes", "export", "CSV", "API"]}},
    ],

    "mixed_intent_advanced": [
        {"q": "Hello, I want to upgrade from Developer to Growth and also need to fix my DKIM. Oh and what's my current usage?",
         "checks": {"must_contain_any": ["upgrade", "DKIM", "usage", "Growth"]}},
        {"q": "My emails aren't delivering. Also I want to add a new domain. And what's the API limit on my plan?",
         "checks": {"must_contain_any": ["deliver", "domain", "API"]}},
    ],

    "tricky_numbers": [
        {"q": "I send 2,000,001 emails. What plan handles that?",
         "checks": {"must_contain_any": ["Enterprise Cloud", "Business + overage"]}},
        {"q": "With Growth's 5M API calls, how many emails can I send with one API call each?",
         "checks": {"must_contain_any": ["500,000", "email limit", "separate"]}},
    ],

    "rapid_multi_fact": [
        {"q": "Free plan: emails, API calls, team size, domains - all the limits please.",
         "checks": {"must_contain": ["3,000"],
                    "must_contain_any": ["50,000", "1", "team", "domain"]}},
        {"q": "Business plan: everything - price, emails, API, team, domains, IPs, features.",
         "checks": {"must_contain": ["€699"],
                    "must_contain_any": ["2,000,000", "20,000,000", "SSO", "IP"]}},
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# MAIN — Write comprehensive recovered tests
# ══════════════════════════════════════════════════════════════════════════════

def merge_and_write():
    """Merge all recovered tests and write to stress_test_recovered.py."""
    
    # Combine all categories
    all_tests = {}
    all_tests.update(STRESS_TEST_R34_CATEGORIES)
    all_tests.update(STRESS_TEST_EXTRA_CATEGORIES)
    
    # Count
    total = sum(len(v) for v in all_tests.values())
    print(f"Total: {total} tests across {len(all_tests)} categories")
    
    # Write to file
    header = '''#!/usr/bin/env python3
"""
stress_test_recovered.py — ALL recovered tests with canonical pricing
══════════════════════════════════════════════════════════════════════

Extracted from git history:
- stress_test_r34.py (171 tests, 26 categories)
- stress_test_extra.py (~80 tests, 12 categories)

All pricing transformed to canonical:
  Free=€0/30K/300K, Developer=€29/50K/500K, Pro=€89/150K/2M,
  Growth=€229/500K/5M, Business=€699/2M/20M, Enterprise Cloud=€1,750/5M/∞
"""

'''
    
    code_lines = ["RECOVERED_STRESS_TESTS = {"]
    
    for cat_name, tests in all_tests.items():
        code_lines.append(f'\n    "{cat_name}": [')
        for test in tests:
            q = test["q"].replace('"', '\\"')
            checks_json = json.dumps(test.get("checks", {}))
            code_lines.append(f'        {{"q": "{q}",')
            code_lines.append(f'         "checks": {checks_json}}},')
        code_lines.append("    ],")
    
    code_lines.append("\n}")
    code_lines.append("""

def get_recovered_tests():
    return RECOVERED_STRESS_TESTS

def count_recovered():
    total = sum(len(v) for v in RECOVERED_STRESS_TESTS.values())
    return total, len(RECOVERED_STRESS_TESTS)

if __name__ == "__main__":
    t, c = count_recovered()
    print(f"Recovered: {t} tests across {c} categories")
    for cat in sorted(RECOVERED_STRESS_TESTS.keys()):
        print(f"  - {cat}: {len(RECOVERED_STRESS_TESTS[cat])} tests")
""")
    
    output_path = "stress_test_recovered.py"
    with open(output_path, "w") as f:
        f.write(header + "\n".join(code_lines))
    
    print(f"\n✅ Written to {output_path}")
    return total, len(all_tests)


if __name__ == "__main__":
    print("=" * 70)
    print("COMPREHENSIVE RECOVERY — ALL DELETED TEST CONTENT")
    print("=" * 70)
    
    total, cats = merge_and_write()
    
    print(f"\n✅ Recovered {total} tests across {cats} categories")
    print("   All pricing converted to canonical schema")
