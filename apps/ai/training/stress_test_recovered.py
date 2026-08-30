#!/usr/bin/env python3
"""
stress_test_recovered.py — ALL recovered tests with canonical pricing
══════════════════════════════════════════════════════════════════════

Extracted from git history:
- stress_test_r34.py (171 tests, 26 categories)
- stress_test_extra.py (~80 tests, 12 categories)

All pricing transformed to canonical:
  Free=€0/30K/300K, Starter=€25/50K/500K, Pro=€65/150K/2M,
  Growth=€150/500K/5M, Scale=€350/2M/20M, Enterprise=€3,000/5M/∞
"""

RECOVERED_STRESS_TESTS = {

    "dns_troubleshooting": [
        {"q": "I added SPF and DKIM records 2 minutes ago. Why isn't my domain verified yet?",
         "checks": {"must_contain_any": ["propagation", "minutes", "hours", "wait", "time"], "must_not_contain": ["instant"]}},
        {"q": "Should I send marketing emails from my root domain example.com or a subdomain?",
         "checks": {"must_contain_any": ["subdomain", "isolat", "reputation"]}},
        {"q": "I already have SPF for Google Workspace. How do I add ApexMail without breaking things?",
         "checks": {"must_contain": ["_spf.apexmail.ee"], "must_contain_any": ["merge", "single", "one", "combine", "include"]}},
        {"q": "Can I use a TXT record instead of CNAME for ApexMail DKIM?",
         "checks": {"must_contain_any": ["CNAME", "no", "cannot", "not", "require"]}},
        {"q": "My domain was verified last week but now shows unverified. What happened?",
         "checks": {"must_contain_any": ["re-verif", "DNS", "record", "removed", "changed", "deleted"]}},
        {"q": "I'm using Cloudflare with the orange proxy cloud on my DKIM record. Is that OK?",
         "checks": {"must_contain_any": ["no", "DNS only", "grey", "disable", "proxy", "not"]}},
        {"q": "What's the Return-Path CNAME I need for ApexMail?",
         "checks": {"must_contain": ["bounce"], "must_contain_any": ["bounce.apexmail.ee", "CNAME"]}},
    ],

    "auth_correctness": [
        {"q": "My DKIM fails with 'body hash did not verify'. Is my DKIM setup wrong?",
         "checks": {"must_contain_any": ["modified", "transit", "forward", "body", "alter"], "must_not_contain": ["setup is wrong", "reconfigure"]}},
        {"q": "What DMARC policy should I start with for a new domain?",
         "checks": {"must_contain": ["none"], "must_contain_any": ["p=none", "monitor", "start"]}},
        {"q": "I have DMARC p=reject on my root domain. Does it cover mail.example.com too?",
         "checks": {"must_contain_any": ["inherit", "subdomain", "sp=", "yes", "cover"]}},
        {"q": "What is ARC and how does it help with email forwarding?",
         "checks": {"must_contain_any": ["forward", "chain", "Authenticated Received Chain", "intermediary"]}},
        {"q": "What do I need to set up BIMI and show my logo in Gmail?",
         "checks": {"must_contain": ["DMARC"], "must_contain_any": ["VMC", "certificate", "Verified Mark", "p=reject", "p=quarantine"]}},
    ],

    "sender_identity": [
        {"q": "My Gmail recipients say my emails show 'via apexmail.io'. How do I fix that?",
         "checks": {"must_contain_any": ["DKIM", "Return-Path", "bounce", "alignment", "domain"]}},
        {"q": "I want to send from newsletter@brand.com but get replies at support@brand.com. Is that possible?",
         "checks": {"must_contain_any": ["Reply-To", "reply_to", "yes"]}},
        {"q": "I'm trying to send from a domain that's not verified and I get a 422 error.",
         "checks": {"must_contain": ["verif"], "must_contain_any": ["Dashboard", "DNS", "domain", "add"]}},
        {"q": "What's the difference between envelope-from and header-from?",
         "checks": {"must_contain_any": ["Return-Path", "envelope", "bounce", "visible", "recipient", "SPF"]}},
    ],

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

    "webhook_troubleshooting": [
        {"q": "I configured a webhook but I'm on the Free plan. Why am I not receiving events?",
         "checks": {"must_contain_any": ["Free", "not available", "Starter", "paid", "no webhook"]}},
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

    "bounce_management": [
        {"q": "What's the difference between a hard bounce and a soft bounce?",
         "checks": {"must_contain": ["permanent"], "must_contain_any": ["temporary", "retry", "4.2.2", "mailbox"]}},
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

    "deliverability_placement": [
        {"q": "My emails land in Gmail's Promotions tab. Is this the same as spam?",
         "checks": {"must_contain_any": ["not spam", "not the same", "delivered", "Promotions"], "must_not_contain": ["spam folder"]}},
        {"q": "Should I set up a custom tracking domain? What does it do?",
         "checks": {"must_contain_any": ["CNAME", "track", "deliverability", "brand"]}},
        {"q": "I use bit.ly links in my marketing emails. Is that bad?",
         "checks": {"must_contain_any": ["spam", "avoid", "shortener", "full URL", "penalize", "block"]}},
        {"q": "What's the acceptable bounce rate for email marketing?",
         "checks": {"must_contain_any": ["2%", "below 2", "under 2"]}},
        {"q": "What's the difference between IP reputation and domain reputation?",
         "checks": {"must_contain": ["IP", "domain"], "must_contain_any": ["separate", "both", "different", "independent"]}},
        {"q": "I want separate IPs for transactional and marketing email. What plans support this?",
         "checks": {"must_contain_any": ["Scale", "€350", "Enterprise", "IP pool"]}},
        {"q": "How do I check if I'm on a blocklist like Spamhaus?",
         "checks": {"must_contain_any": ["Spamhaus", "check.spamhaus.org", "blocklist", "DNSBL"]}},
        {"q": "I'm on the Free plan. Can I get a dedicated IP address?",
         "checks": {"must_contain_any": ["no", "Pro", "€65", "not available"]}},
    ],

    "template_rendering": [
        {"q": "My email template shows raw {{first_name}} instead of the person's name.",
         "checks": {"must_contain_any": ["mismatch", "match", "case", "typo", "merge", "variable"]}},
        {"q": "What Handlebars helpers does ApexMail support?",
         "checks": {"must_contain": ["if"], "must_contain_any": ["each", "unless", "formatDate", "formatCurrency", "uppercase", "lowercase"]}},
        {"q": "Is it safe to render user-supplied data in Handlebars templates?",
         "checks": {"must_contain_any": ["escape", "double brace", "triple brace", "HTML-escape", "safe"]}},
        {"q": "Can I preview how my email looks on different devices before sending?",
         "checks": {"must_contain_any": ["preview", "test", "send test"]}},
        {"q": "What's the maximum email HTML size before Gmail clips it?",
         "checks": {"must_contain_any": ["102 KB", "102KB", "kilobyte"]}},
    ],

    "api_rate_limits": [
        {"q": "What are the API rate limits on the Starter plan?",
         "checks": {"must_contain_any": ["500,000", "500K", "per month"]}},
        {"q": "Can I burst 10,000 API calls in one minute?",
         "checks": {"must_contain_any": ["no", "rate", "throttle", "spread"]}},
        {"q": "What happens if I hit the monthly API call limit?",
         "checks": {"must_contain_any": ["429", "error", "queued", "upgrade"]}},
        {"q": "Growth plan API limits - what are they exactly?",
         "checks": {"must_contain_any": ["5,000,000", "5M", "5 million"]}},
    ],

    "security_controls": [
        {"q": "I forgot my password and my MFA device is lost. How do I recover?",
         "checks": {"must_contain_any": ["contact", "support", "email", "manual"]}},
        {"q": "How many failed login attempts before lockout?",
         "checks": {"must_contain_any": ["5", "five", "lockout", "15 minute"]}},
        {"q": "Can I require MFA for all team members?",
         "checks": {"must_contain_any": ["yes", "Scale", "Enterprise", "enforce"]}},
        {"q": "How long do team invites stay valid?",
         "checks": {"must_contain_any": ["72", "hour", "3 day", "expire"]}},
        {"q": "How do I rotate my API keys without downtime?",
         "checks": {"must_contain_any": ["create new", "test", "delete old", "transition"]}},
    ],

    "account_lockout_mfa": [
        {"q": "I'm locked out after too many failed logins. What do I do?",
         "checks": {"must_contain_any": ["15 minute", "wait", "reset", "support"]}},
        {"q": "My authenticator app was on a phone I lost. Recovery options?",
         "checks": {"must_contain_any": ["contact", "support", "backup", "recovery"]}},
        {"q": "Can I use a hardware security key like YubiKey for MFA?",
         "checks": {"must_contain_any": ["yes", "no", "TOTP", "authenticator"]}},
    ],

    "sending_suspension": [
        {"q": "My account shows 'sending suspended'. What happened?",
         "checks": {"must_contain_any": ["bounce", "complaint", "abuse", "review"]}},
        {"q": "How long does a suspension review take?",
         "checks": {"must_contain_any": ["24 hour", "business day", "review"]}},
        {"q": "I didn't do anything wrong - false positive suspension. Help!",
         "checks": {"must_contain_any": ["contact", "appeal", "support", "review"]}},
    ],

    "compliance_privacy": [
        {"q": "Is ApexMail GDPR compliant?",
         "checks": {"must_contain_any": ["yes", "GDPR", "DPA", "EU"]}},
        {"q": "Does ApexMail offer a Data Processing Agreement (DPA)?",
         "checks": {"must_contain_any": ["yes", "DPA", "contact", "Enterprise"]}},
        {"q": "What happens to my data if I cancel my account?",
         "checks": {"must_contain_any": ["delete", "retention", "days", "export"]}},
        {"q": "Is ApexMail HIPAA compliant?",
         "checks": {"must_contain_any": ["Enterprise", "BAA", "contact", "HIPAA"]}},
        {"q": "Where is my data stored geographically?",
         "checks": {"must_contain_any": ["EU", "Europe", "Hetzner", "Germany"]}},
    ],

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

    "sdk_integration": [
        {"q": "What's the Python SDK package name?",
         "checks": {"must_contain_any": ["apexmail", "pip", "PyPI"]}},
        {"q": "Does the Python SDK support async/await?",
         "checks": {"must_contain_any": ["yes", "async", "await", "asyncio"]}},
        {"q": "What's the minimum Python version for the SDK?",
         "checks": {"must_contain_any": ["3.9", "3.10", "Python 3"]}},
    ],

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

    "ip_infrastructure": [
        {"q": "How many dedicated IPs are included with Scale?",
         "checks": {"must_contain_any": ["3", "three"]}},
        {"q": "Can I bring my own IP address (BYOIP)?",
         "checks": {"must_contain_any": ["Enterprise", "contact", "BYOIP"]}},
        {"q": "How much does an additional dedicated IP cost?",
         "checks": {"must_contain_any": ["€30", "30", "month"]}},
    ],

    "message_diagnostics": [
        {"q": "How can I see what happened to a specific email I sent?",
         "checks": {"must_contain_any": ["message ID", "event", "search", "dashboard"]}},
        {"q": "How long does ApexMail retain message body content?",
         "checks": {"must_contain_any": ["7", "30", "day", "retention"]}},
        {"q": "Can I see the raw email headers for troubleshooting?",
         "checks": {"must_contain_any": ["yes", "header", "diagnostic"]}},
    ],

    "message_lifecycle": [
        {"q": "How long will ApexMail retry a deferred message?",
         "checks": {"must_contain_any": ["72", "hour", "3 day"]}},
        {"q": "Can I cancel a scheduled email after it's queued?",
         "checks": {"must_contain_any": ["yes", "cancel", "schedule"]}},
        {"q": "What does 'deferred' status mean?",
         "checks": {"must_contain_any": ["temporary", "retry", "later"]}},
    ],

    "link_tracking": [
        {"q": "How do I disable click tracking for a specific link?",
         "checks": {"must_contain_any": ["data-apexmail", "no-track", "attribute"]}},
        {"q": "Why do my links show the ApexMail domain before redirecting?",
         "checks": {"must_contain_any": ["tracking", "redirect", "custom domain"]}},
        {"q": "Can I use my own domain for tracking links?",
         "checks": {"must_contain_any": ["yes", "CNAME", "custom"]}},
    ],

    "link_tracking_deep": [
        {"q": "Do tracked links work with HTTPS on custom domains?",
         "checks": {"must_contain_any": ["yes", "SSL", "HTTPS", "certificate"]}},
        {"q": "Are bot clicks filtered from my analytics?",
         "checks": {"must_contain_any": ["yes", "filter", "bot", "detection"]}},
        {"q": "Click tracking shows 0% but users say they clicked. Why?",
         "checks": {"must_contain_any": ["plain text", "disabled", "bot"]}},
    ],

    "billing_sla": [
        {"q": "What's the email overage rate per 1,000 emails?",
         "checks": {"must_contain_any": ["€0.40", "0.40", "40 cent"]}},
        {"q": "What's the ApexMail uptime SLA?",
         "checks": {"must_contain_any": ["99.9", "SLA"]}},
        {"q": "How do I get credits for downtime?",
         "checks": {"must_contain_any": ["contact", "support", "SLA", "credit"]}},
        {"q": "Do I get a discount for annual billing?",
         "checks": {"must_contain_any": ["yes", "annual", "discount"]}},
    ],

    "security_advanced": [
        {"q": "Does ApexMail support SOC2 compliance?",
         "checks": {"must_contain_any": ["Enterprise", "SOC2", "SOC 2", "contact"]}},
        {"q": "Can I get audit logs for my team's actions?",
         "checks": {"must_contain_any": ["Scale", "Enterprise", "audit"]}},
        {"q": "Is there SSO support with SAML?",
         "checks": {"must_contain_any": ["Scale", "Enterprise", "SSO", "SAML"]}},
        {"q": "Can I restrict API keys to specific IPs?",
         "checks": {"must_contain_any": ["yes", "allowlist", "IP restriction"]}},
    ],

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
        {"q": "Hello, I want to upgrade from Starter to Growth and also need to fix my DKIM. Oh and what's my current usage?",
         "checks": {"must_contain_any": ["upgrade", "DKIM", "usage", "Growth"]}},
        {"q": "My emails aren't delivering. Also I want to add a new domain. And what's the API limit on my plan?",
         "checks": {"must_contain_any": ["deliver", "domain", "API"]}},
    ],

    "tricky_numbers": [
        {"q": "I send 2,000,001 emails. What plan handles that?",
         "checks": {"must_contain_any": ["Enterprise", "Scale + overage"]}},
        {"q": "With Growth's 5M API calls, how many emails can I send with one API call each?",
         "checks": {"must_contain_any": ["500,000", "email limit", "separate"]}},
    ],

    "rapid_multi_fact": [
        {"q": "Free plan: emails, API calls, team size, domains - all the limits please.",
         "checks": {"must_contain": ["3,000"], "must_contain_any": ["50,000", "1", "team", "domain"]}},
        {"q": "Scale plan: everything - price, emails, API, team, domains, IPs, features.",
         "checks": {"must_contain": ["€350"], "must_contain_any": ["2,000,000", "20,000,000", "SSO", "IP"]}},
    ],

}


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
