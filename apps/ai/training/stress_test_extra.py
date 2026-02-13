"""
stress_test_extra.py — Expanded harder tests for R17e+
═══════════════════════════════════════════════════════
Adds ~80 harder, more realistic, multi-angle tests to the base 600.

Design principles:
  - Harder math (multi-step, cross-plan comparisons)
  - More adversarial/tricky wording
  - Edge cases that require precise knowledge
  - Realistic business scenarios
  - Tests for common model failure modes
"""

EXTRA_TESTS = {

    # ── HARDER PRICING MATH ──────────────────────────────────────────────
    "pricing_math_advanced": [
        {"q": "I send 80,000 emails and make 1.8 million API calls monthly. What's the cheapest option?",
         "checks": {"must_contain_any": ["Growth", "$129"], "must_not_contain": ["Pro", "Starter"]}},

        {"q": "Growth plan: 200K emails + 3M API calls. What's the total damage?",
         "checks": {"must_contain": ["$129"], "must_contain_any": ["$50", "100,000", "overage"]}},

        {"q": "I'm on the Free plan and sent 2,000 emails. How much extra do I owe?",
         "checks": {"must_contain_any": ["$0.50", "1,000", "overage"]}},

        {"q": "Starter plan: sent 26,000 emails AND used 260,000 API calls. Break down the total bill.",
         "checks": {"must_contain": ["$29"], "must_contain_any": ["$0.50", "overage"]}},

        {"q": "If I switch from Scale ($399) to PAYG and send 400,000 emails, am I saving money?",
         "checks": {"must_contain_any": ["PAYG", "tier", "$0.0005", "$0.0003", "Scale"]}},

        {"q": "Enterprise is $1,299. If I send 2M emails, what's the per-email cost?",
         "checks": {"must_contain_any": ["$1,299", "custom", "contact@apexmail.ee"]}},
    ],

    # ── GROWTH EMAILS vs API CONFUSION ───────────────────────────────────
    "growth_limits_clarity": [
        {"q": "Growth plan: what's my email limit?",
         "checks": {"must_contain": ["100,000"], "must_not_contain": ["2,000,000 email", "2M email", "two million email"]}},

        {"q": "How many emails does Growth include?",
         "checks": {"must_contain_any": ["100,000", "100K"]}},

        {"q": "Growth has 2 million emails per month, right?",
         "checks": {"must_contain": ["100,000"], "must_contain_any": ["API", "no", "not"]}},

        {"q": "What's the difference between Growth's email limit and API limit?",
         "checks": {"must_contain_any": ["100,000"], "must_contain_any": ["2,000,000", "2M"]}},

        {"q": "Does any plan include 2 million emails?",
         "checks": {"must_contain_any": ["Enterprise", "custom", "Scale", "500,000"]}},

        {"q": "I need 2 million API calls. Which plan?",
         "checks": {"must_contain_any": ["Growth", "$129", "2,000,000"]}},
    ],

    # ── HARDER PAYG EDGE CASES ───────────────────────────────────────────
    "payg_advanced": [
        {"q": "PAYG: exactly 1,000,000 emails. Give me the total cost with full tier breakdown.",
         "checks": {"must_contain": ["$0.001", "$0.0008", "$0.0005"]}},

        {"q": "Is $0.0003 the rate for my first 10 emails on PAYG?",
         "checks": {"must_contain": ["$0.001"], "must_contain_any": ["first", "10,000", "tier"]}},

        {"q": "I send exactly 10,000 emails on PAYG. Is it $10 total?",
         "checks": {"must_contain": ["$0.001"], "must_contain_any": ["$10", "10,000", "yes", "correct"]}},

        {"q": "PAYG: 100,001 emails. What rate does that last email get?",
         "checks": {"must_contain": ["$0.0005"]}},
    ],

    # ── PLAN FEATURE TRAPS ───────────────────────────────────────────────
    "plan_feature_traps": [
        {"q": "Does the Starter plan come with A/B testing?",
         "checks": {"must_contain_any": ["no", "Growth", "not", "doesn't", "does not"]}},

        {"q": "I need SSO. What's the cheapest plan?",
         "checks": {"must_contain_any": ["Scale", "$399"]}},

        {"q": "Which plan first offers a dedicated IP?",
         "checks": {"must_contain_any": ["Growth", "$129"]}},

        {"q": "Does Pro include a dedicated IP address?",
         "checks": {"must_contain_any": ["no", "Growth", "not", "doesn't"]}},

        {"q": "I need priority support. Is Starter enough?",
         "checks": {"must_contain_any": ["no", "Growth", "not enough", "doesn't"]}},

        {"q": "How many dedicated IPs does Scale include?",
         "checks": {"must_contain_any": ["3", "three"]}},

        {"q": "Which plan includes send-time optimization?",
         "checks": {"must_contain_any": ["Growth", "$129"]}},

        {"q": "Does the Free plan include webhooks?",
         "checks": {"must_contain_any": ["no", "Starter", "paid", "not"]}},
    ],

    # ── HARDER ESCALATION SCENARIOS ──────────────────────────────────────
    "escalation_advanced": [
        {"q": "I was double-billed and need an immediate refund plus compensation.",
         "checks": {"must_contain": ["contact@apexmail.ee"]}},

        {"q": "Your service caused us to miss our Black Friday campaign. We want damages.",
         "checks": {"must_contain": ["contact@apexmail.ee"]}},

        {"q": "Process my GDPR Article 17 right to erasure for all data associated with my email addresses.",
         "checks": {"must_contain": ["contact@apexmail.ee"], "must_contain_any": ["GDPR", "erasure", "data"]}},

        {"q": "I want to negotiate a volume discount for 20M emails/month.",
         "checks": {"must_contain": ["contact@apexmail.ee"], "must_contain_any": ["Enterprise", "custom", "sales"]}},

        {"q": "We found a data breach — our API key is leaked on GitHub. What do we do?",
         "checks": {"must_contain": ["contact@apexmail.ee"], "must_contain_any": ["revoke", "security", "immediately"]}},
    ],

    # ── HARDER MIXED INTENT ──────────────────────────────────────────────
    "mixed_intent_advanced": [
        {"q": "First show me my templates, then delete 'Old Template', and also pull up campaign stats.",
         "checks": {"must_contain": ["confirm\":false", "confirm\":true"], "must_contain_any": ["list_templates", "delete_template", "get_stats"]}},

        {"q": "Check domain health for all my domains and revoke API key am_live_xyz789.",
         "checks": {"must_contain": ["check_domain_health", "confirm\":false", "revoke_api_key", "confirm\":true"]}},

        {"q": "Export all my data and then close my account.",
         "checks": {"must_contain": ["confirm\":false", "confirm\":true"], "must_contain_any": ["export", "delete_account"]}},
    ],

    # ── REALISTIC BUSINESS SCENARIOS ─────────────────────────────────────
    "business_scenarios": [
        {"q": "We're a 50-person startup sending transactional emails (receipts, password resets) at about 10K/month. What plan?",
         "checks": {"must_contain_any": ["Starter", "Free", "$29", "$0"]}},

        {"q": "We're an e-commerce company doing 400K marketing emails during peak season but only 50K otherwise. Best approach?",
         "checks": {"must_contain_any": ["Scale", "PAYG", "Growth", "seasonal"]}},

        {"q": "We need to send 100K transactional emails with sub-second latency. Can ApexMail handle this?",
         "checks": {"must_contain_any": ["API", "Growth", "Scale", "transactional"]}},

        {"q": "Our compliance team requires HIPAA. We send 200K emails/month. What do we need?",
         "checks": {"must_contain_any": ["Enterprise", "$1,299", "HIPAA", "contact@apexmail.ee"]}},

        {"q": "We're an agency managing 20 client domains. What's the minimum plan?",
         "checks": {"must_contain_any": ["Scale", "Enterprise", "domain", "25"]}},

        {"q": "Our marketing team needs A/B testing and we send 30,000 emails/month.",
         "checks": {"must_contain_any": ["Growth", "$129"]}},
    ],

    # ── TRICKY NUMBER TESTS ──────────────────────────────────────────────
    "tricky_numbers": [
        {"q": "How many sending domains does each plan include?",
         "checks": {"must_contain_any": ["1", "3", "5", "10", "25"]}},

        {"q": "How many team members can I have on the Growth plan?",
         "checks": {"must_contain_any": ["10"]}},

        {"q": "Scale plan: how many team members?",
         "checks": {"must_contain_any": ["25"]}},

        {"q": "Free plan API calls vs Starter plan API calls — how much more does Starter give?",
         "checks": {"must_contain_any": ["10,000", "250,000", "25x", "240,000"]}},
    ],

    # ── HARDER DELIVERABILITY ────────────────────────────────────────────
    "deliverability_advanced": [
        {"q": "My bounce rate is 5%. Is that a problem?",
         "checks": {"must_contain_any": ["below 2%", "under 2%", "too high", "above", "problem", "yes"]}},

        {"q": "What's the difference between a soft bounce and a hard bounce?",
         "checks": {"must_contain_any": ["temporary", "permanent", "soft", "hard"]}},

        {"q": "My emails are going to spam. What should I check first?",
         "checks": {"must_contain_any": ["SPF", "DKIM", "DMARC", "authentication", "content", "reputation"]}},

        {"q": "Does ApexMail automatically handle bounce processing?",
         "checks": {"must_contain_any": ["yes", "automatic", "suppression"]}},
    ],

    # ── API TECHNICAL DEPTH ──────────────────────────────────────────────
    "api_depth": [
        {"q": "What authentication method does the ApexMail API use?",
         "checks": {"must_contain_any": ["Bearer", "token", "API key", "Authorization"]}},

        {"q": "What's the difference between am_test_ and am_live_ keys?",
         "checks": {"must_contain_any": ["test", "sandbox", "live", "production"]}},

        {"q": "Is the API at api.apexmail.com or api.apexmail.ee?",
         "checks": {"must_contain": ["apexmail.ee"], "must_not_contain": ["api.apexmail.com/v1 is"]}},

        {"q": "Does ApexMail have SDKs?",
         "checks": {"must_contain_any": ["Node", "Python", "SDK", "npm", "pip"]}},
    ],

    # ── HARDER COMPLIANCE ────────────────────────────────────────────────
    "compliance_advanced": [
        {"q": "We want to scrape emails from LinkedIn and send cold emails. Is that allowed?",
         "checks": {"must_contain_any": ["not allowed", "no", "consent", "policy", "terms"]}},

        {"q": "Can I import a purchased email list?",
         "checks": {"must_contain_any": ["not allowed", "no", "consent", "policy"]}},

        {"q": "What happens if I get too many spam complaints?",
         "checks": {"must_contain_any": ["suspend", "reputation", "block", "review", "0.1%"]}},

        {"q": "Do I need explicit consent to send marketing emails in the EU?",
         "checks": {"must_contain_any": ["yes", "GDPR", "consent", "opt-in"]}},
    ],

    # ── STRESS: RAPID MULTI-FACT ─────────────────────────────────────────
    "rapid_multi_fact": [
        {"q": "Quick: Starter price, Growth emails, Scale API calls, Enterprise price. Go.",
         "checks": {"must_contain": ["$29", "$1,299"], "must_contain_any": ["100,000", "100K"], "must_contain_any": ["10,000,000", "10M"]}},

        {"q": "Name every plan from cheapest to most expensive with prices.",
         "checks": {"must_contain": ["$0", "$29", "$59", "$129", "$399", "$1,299"]}},

        {"q": "All four PAYG rates, quick.",
         "checks": {"must_contain": ["$0.001", "$0.0008", "$0.0005", "$0.0003"]}},
    ],
}
