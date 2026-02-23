"""
stress_test_r34.py — New stress tests for R34 support playbook training
═══════════════════════════════════════════════════════════════════════
~60 new tests across 8 sections (A-H) testing knowledge from the
comprehensive support playbook documentation.

These tests validate that the model correctly learned:
  - DNS/domain troubleshooting (SPF, DKIM, DMARC setup)
  - Authentication best practices
  - Sender identity and alignment
  - API usage patterns
  - Webhook event handling
  - Bounce/complaint/suppression management
  - Deliverability optimization
  - Template and rendering guidance
"""

R34_TESTS = {

    # ── A: Domain & DNS Troubleshooting ──────────────────────────────────
    "dns_troubleshooting": [
        {"q": "I added SPF and DKIM records 2 minutes ago. Why isn't my domain verified yet?",
         "checks": {"must_contain_any": ["propagation", "minutes", "hours", "wait", "time"],
                    "must_not_contain": ["instant"]}},

        {"q": "Should I send marketing emails from my root domain example.com or a subdomain?",
         "checks": {"must_contain_any": ["subdomain", "isolat", "reputation"],
                    "must_not_contain": []}},

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
         "checks": {"must_contain_any": ["rate limit", "API call limit", "API limit", "exceeded", "429"],
                    "must_not_contain": []}},

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
         "checks": {"must_contain_any": ["Scale", "$399", "Enterprise", "IP pool"]}},

        {"q": "How do I check if I'm on a blocklist like Spamhaus?",
         "checks": {"must_contain_any": ["Spamhaus", "check.spamhaus.org", "blocklist", "DNSBL"]}},

        {"q": "I'm on the Free plan. Can I get a dedicated IP address?",
         "checks": {"must_contain_any": ["no", "Growth", "$129", "not available"]}},
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

        {"q": "My email looks perfect in Gmail but broken in Outlook desktop. Why?",
         "checks": {"must_contain_any": ["Word", "rendering", "table", "inline", "CSS"]}},

        {"q": "What's the max attachment size for emails sent through ApexMail?",
         "checks": {"must_contain_any": ["25 MB", "25MB", "25 megabyte"]}},

        {"q": "How do I add preview text (preheader) to my emails?",
         "checks": {"must_contain_any": ["preheader", "preview", "hidden", "div"]}},

        {"q": "My email subject line shows garbled characters like Ã©. How do I fix it?",
         "checks": {"must_contain_any": ["UTF-8", "encoding", "charset"]}},
    ],

    # ── I: Security, SDK, & Advanced Topics ──────────────────────────────
    "security_advanced": [
        {"q": "I'm getting a 403 ip_not_allowed error on API calls. What's wrong?",
         "checks": {"must_contain_any": ["allowlist", "IP", "address", "whitelist", "Dashboard"]}},

        {"q": "Can I create an API key that can only send emails and nothing else?",
         "checks": {"must_contain_any": ["scope", "emails:send", "restrict", "granular"]}},

        {"q": "What team member roles does ApexMail support?",
         "checks": {"must_contain_any": ["Owner", "Admin", "Developer", "Analyst", "Billing"]}},

        {"q": "I'm locked out after entering the wrong password too many times.",
         "checks": {"must_contain_any": ["5", "locked", "15 minute", "15-minute", "wait", "reset"]}},

        {"q": "My account says 'sending suspended'. How do I get it reinstated?",
         "checks": {"must_contain_any": ["complaint", "bounce", "contact", "compliance", "review"]}},

        {"q": "What Node.js version do I need for the ApexMail SDK?",
         "checks": {"must_contain_any": ["18", "Node.js 18", "fetch"]}},

        {"q": "How do I verify webhook signatures in my Express.js app?",
         "checks": {"must_contain_any": ["raw", "HMAC", "SHA256", "express.raw", "body"]}},

        {"q": "How do I disable click tracking for a specific email?",
         "checks": {"must_contain_any": ["tracking", "false", "clicks", "disable"]}},

        {"q": "How many times does ApexMail retry failed webhook deliveries?",
         "checks": {"must_contain_any": ["3", "retry", "retries", "5", "exponential"]}},

        {"q": "What are the SLA uptime guarantees for each ApexMail plan?",
         "checks": {"must_contain_any": ["99.5", "99.9", "99.95", "99.99", "uptime"]}},

        {"q": "How many recipients can I include in one batch API call?",
         "checks": {"must_contain_any": ["1,000", "1000", "batch"]}},

        {"q": "How long does ApexMail retain message body content?",
         "checks": {"must_contain_any": ["7 day", "30 day", "3 day", "14 day", "retention"]}},

        {"q": "How does ApexMail detect bot clicks in tracking?",
         "checks": {"must_contain_any": ["bot", "User-Agent", "timing", "is_bot"]}},

        {"q": "Under what conditions does ApexMail automatically stop sending for an account?",
         "checks": {"must_contain_any": ["complaint", "bounce", "spike", "phishing", "0.1%", "10%"]}},

        {"q": "How much does a dedicated IP add-on cost?",
         "checks": {"must_contain_any": ["$49", "$50", "49", "50", "add-on", "dedicated"]}},
    ],

    # ── J: Compliance, Privacy & GDPR ────────────────────────────────────
    "compliance_privacy": [
        {"q": "How long does a GDPR deletion request take to process?",
         "checks": {"must_contain_any": ["30 day", "72 hour", "erasure", "GDPR"]}},

        {"q": "What CAN-SPAM requirements must my emails meet?",
         "checks": {"must_contain_any": ["physical address", "unsubscribe", "10 business day", "opt-out"]}},

        {"q": "Is ApexMail a data processor or data controller under GDPR?",
         "checks": {"must_contain_any": ["processor", "Article 28", "controller"]}},

        {"q": "What encryption does ApexMail use at rest and in transit?",
         "checks": {"must_contain_any": ["AES-256", "TLS 1.2", "AES", "TLS"]}},

        {"q": "Can ApexMail store all my data in the EU only?",
         "checks": {"must_contain_any": ["Enterprise", "EU", "Hetzner", "Frankfurt", "data residency"]}},

        {"q": "Is ApexMail SOC 2 certified?",
         "checks": {"must_contain_any": ["SOC 2", "Type II", "NDA", "audit"]}},

        {"q": "Does ApexMail offer a HIPAA BAA?",
         "checks": {"must_contain_any": ["Enterprise", "HIPAA", "BAA"]}},

        {"q": "Does ApexMail provide a Data Processing Agreement?",
         "checks": {"must_contain_any": ["DPA", "Data Processing", "contact@apexmail.ee", "GDPR"]}},
    ],

    # ── K: SDK Runtime & Integration ─────────────────────────────────────
    "sdk_integration": [
        {"q": "What is the npm package name for the ApexMail SDK?",
         "checks": {"must_contain": ["@apexmail/node"],
                    "must_not_contain": ["@apexmail/sdk"]}},

        {"q": "How do I verify webhook signatures in a Next.js App Router route?",
         "checks": {"must_contain_any": ["text()", "raw body", "rawBody", "request.text"]}},

        {"q": "How do I verify webhook signatures in FastAPI?",
         "checks": {"must_contain_any": ["request.body()", "raw", "bytes", "FastAPI"]}},

        {"q": "Can the ApexMail SDK run in Cloudflare Workers?",
         "checks": {"must_contain_any": ["Edge", "Cloudflare", "fetch", "compatible", "yes"]}},

        {"q": "What happens when the SDK gets a 5xx error?",
         "checks": {"must_contain_any": ["retry", "3 retries", "retried", "exponential", "backoff"]}},

        {"q": "How do I schedule an email to be sent in the future?",
         "checks": {"must_contain_any": ["send_at", "72 hour", "ISO 8601", "schedule"]}},

        {"q": "How many tags can I attach to a single email?",
         "checks": {"must_contain_any": ["5 tag", "5", "metadata"]}},

        {"q": "Are SDK 4xx errors automatically retried?",
         "checks": {"must_contain_any": ["not retried", "NOT retried", "no", "client error", "4xx"]}},
    ],

    # ── L: Link Tracking & Branding ──────────────────────────────────────
    "link_tracking": [
        {"q": "My custom tracking domain links return 404. What's wrong?",
         "checks": {"must_contain_any": ["CNAME", "DNS", "SSL", "t.apexmail.ee", "verified"]}},

        {"q": "How do I implement Gmail's one-click unsubscribe requirement?",
         "checks": {"must_contain_any": ["RFC 8058", "List-Unsubscribe", "one-click", "Post"]}},

        {"q": "Apple Mail Privacy Protection is inflating my open rates. What can I do?",
         "checks": {"must_contain_any": ["prefetch", "is_bot", "click rate", "Privacy Protection"]}},

        {"q": "How do I prevent link tracking from breaking my signed URLs?",
         "checks": {"must_contain_any": ["data-tracking", "false", "exclude", "signed"]}},
    ],

    # ── M: Quotas & Rate Limits ──────────────────────────────────────────
    "quota_mechanics": [
        {"q": "When does my email quota reset each day?",
         "checks": {"must_contain_any": ["00:00 UTC", "midnight UTC", "UTC", "daily"]}},

        {"q": "If I send one API call with 5 recipients, does it count as 1 send or 5?",
         "checks": {"must_contain_any": ["5 send", "each recipient", "5", "per recipient"]}},

        {"q": "Do emails to suppressed addresses count against my quota?",
         "checks": {"must_contain_any": ["no", "not count", "suppressed", "don't count", "do not count"]}},

        {"q": "What happens to my dedicated IPs if I downgrade from Growth to Pro?",
         "checks": {"must_contain_any": ["disabled", "removed", "lose", "Growth", "requires"]}},

        {"q": "I'm getting 409 Conflict from the ApexMail API. Why?",
         "checks": {"must_contain_any": ["idempotency", "key", "reuse", "conflict", "payload"]}},
    ],

    # ── N: IP Infrastructure & SMTP ──────────────────────────────────────
    "ip_infrastructure": [
        {"q": "What SMTP ports does ApexMail support?",
         "checks": {"must_contain_any": ["587", "465", "25", "2525"]}},

        {"q": "Does ApexMail support DANE for SMTP delivery?",
         "checks": {"must_contain_any": ["DANE", "TLSA", "DNSSEC", "RFC 6698"]}},

        {"q": "Can ApexMail receive inbound emails?",
         "checks": {"must_contain_any": ["inbound", "MX", "receiving", "webhook"]}},
    ],

    # ── O: Message Diagnostics & Tracing ─────────────────────────────────
    "message_diagnostics": [
        {"q": "How do I find out why a specific email wasn't delivered?",
         "checks": {"must_contain_any": ["message_id", "GET /v1/messages", "events", "trace", "timeline"]}},

        {"q": "Gmail clips my email and shows 'View entire message'. How do I fix it?",
         "checks": {"must_contain_any": ["102", "KB", "size", "clip", "reduce"]}},
    ],

    # ── P: Security Controls ─────────────────────────────────────────────
    "security_controls": [
        {"q": "I'm locked out after enabling IP allowlist. How do I fix it?",
         "checks": {"must_contain_any": ["Dashboard", "session", "login", "remove", "allowlist"]}},

        {"q": "How do I rotate my API key without downtime?",
         "checks": {"must_contain_any": ["create new", "revoke old", "both active", "parallel", "new key"]}},

        {"q": "Does ApexMail support SAML single sign-on?",
         "checks": {"must_contain_any": ["SAML", "SSO", "Scale", "Enterprise"]}},

        {"q": "How do I report a security vulnerability to ApexMail?",
         "checks": {"must_contain_any": ["security@apexmail.ee", "vulnerability", "disclosure"]}},

        {"q": "I lost my MFA device and can't log in. What do I do?",
         "checks": {"must_contain_any": ["recovery code", "contact@apexmail.ee", "verify", "identity"]}},
    ],

    # ── Q: API Rate Limits & Payload ─────────────────────────────────────
    "api_rate_limits": [
        {"q": "What's the per-minute API rate limit on the Growth plan?",
         "checks": {"must_contain_any": ["1,000", "1000", "req/min", "requests per minute"]}},

        {"q": "What rate limit headers does the ApexMail API return?",
         "checks": {"must_contain_any": ["X-RateLimit", "Retry-After"]}},

        {"q": "What's the maximum request body size for the batch send endpoint?",
         "checks": {"must_contain_any": ["10 MB", "10MB", "payload"]}},

        {"q": "I'm getting 422 when sending a marketing email. What could cause that?",
         "checks": {"must_contain_any": ["unsubscribe", "domain", "template", "validation"]}},
    ],
}
