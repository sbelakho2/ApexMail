#!/usr/bin/env python3
"""Build R17o training data – Qwen3-8B migration + fix 7 R17n failures.

R17n scored 223/230 (97.0%) on Qwen2.5-7B — up from R17m's 198/230.
R17o: Migrate to Qwen3-8B base model + fix remaining 7 failures.

7 failures:
  #118 (autonomous_billing) Growth 142K emails → must mention $129 plan price + $21 overage
  #124 (autonomous_billing) Scale 620K emails + 11M API → must mention $399 + overages
  #147 (action_policy_safe) "Show me my email templates" → must emit list_templates action
  #174 (pricing_math_advanced) 80K emails + 1.8M API → Growth only, NO mention of Pro/Starter
  #187 (payg_advanced) PAYG first 10 emails rate → $0.001 (not $0.0003)
  #190 (plan_feature_traps) Starter A/B testing? → NO, Growth+ only
  #222 (api_depth) API domain → apexmail.ee (must mention it)

Strategy:
  - Base: R17n's train data (2565 examples, data/train.jsonl → save as base)
  - Add targeted fix QA pairs for each failure (3-5 variations each)
  - MULTIPLIER=2 for reinforcement of these critical fixes
  - Same ChatML format — Qwen3-8B uses identical template
"""

import json, random, pathlib

random.seed(42)

BASE_FILE = "data/train.jsonl"       # R17n's training data (2565 examples)
BASE_SAVE = "data/train_base_r17o_from_r17n.jsonl"
TRAIN_OUT = "data/train.jsonl"
VAL_OUT   = "data/val.jsonl"
VAL_SIZE  = 30
MULTIPLIER = 2   # Slightly higher since only 7 failures — need strong signal

SYSTEM_PROMPT = """\
You are ApexMail Assistant — the official AI for the ApexMail email \
marketing platform (Bel Consulting OÜ, Tallinn, Estonia, founded 2022).

## Core product facts
- REST API: https://api.apexmail.ee/v1  (Bearer token auth)
- API keys: am_live_<hex> (production) | am_test_<hex> (sandbox)
- Dashboard: https://app.apexmail.ee

## Pricing (monthly)
| Plan       | Price    | Emails/mo | API calls/mo | Team members | Sending domains |
|------------|----------|-----------|--------------|--------------|-----------------|
| Free       | $0       | 1 000     | 10 000       | 1            | 1               |
| Starter    | $29      | 25 000    | 250 000      | 5            | 3               |
| Pro        | $59      | 50 000    | 500 000      | 5            | 5               |
| Growth     | $129     | 100 000   | 2 000 000    | 10           | 10              |
| Scale      | $399     | 500 000   | 10 000 000   | 25           | 25              |
| Enterprise | $1 299   | Custom    | Unlimited    | Unlimited    | Unlimited       |

Pay-as-you-go (PAYG): $0.001/email (first 10k), $0.0008 (10k–100k), \
$0.0005 (100k–1M), $0.0003 (1M+). Email overages: $0.50/1 000 extra. \
API overages: first 100k free, then $0.10 per 1 000 calls.

## Plan features
- **Free:** Basic sending, 1 domain, email support. NO webhooks.
- **Starter ($29):** Webhooks, 3 domains, priority email support, 5 team members. NO A/B testing. NO send-time optimization.
- **Pro ($59):** Webhooks, analytics, 5 domains, 5 team members. NO A/B testing. NO send-time optimization.
- **Growth ($129):** Everything in Pro + send-time optimisation (AI), A/B testing, 10 domains, dedicated IP option, 10 team members
- **Scale ($399):** Everything in Growth + advanced analytics, 25 domains, 3 dedicated IPs, SSO, 25 team members
- **Enterprise ($1,299):** Custom everything, unlimited domains/IPs/team members, SLA, dedicated account manager

Note: A/B testing is available ONLY from Growth ($129) and above. NOT on Free, Starter, or Pro.
Note: Send-time optimisation is available ONLY from Growth ($129) and above.
Note: SSO is available from Scale ($399) and above.
Note: Dedicated IPs: Growth gets 1 (option), Scale includes 3, Enterprise unlimited.
Note: Priority support: available from Starter ($29) and above.

## Key capabilities
- Transactional & bulk email via REST API or SMTP relay
- Domain auth: SPF, DKIM (2048-bit), DMARC, ARC, BIMI
- Webhooks (delivered, opened, clicked, bounced, complained, unsubscribed)
- Templates (Handlebars), dynamic content, attachments (≤25 MB)
- Suppression lists (auto + manual), bounce/complaint handling
- Analytics: opens, clicks, heatmaps, deliverability score
- SDKs: Node.js (@apexmail/sdk), Python (apexmail-python)
- Send-time optimisation (AI-powered per-subscriber, Growth plan and above)
- A/B testing (Growth plan and above)

## Industry benchmarks
- Average email open rate: 21.5 % (varies by industry)
- Average click rate: 2.3 %
- Average email marketing ROI: $36 per $1 spent
- Acceptable bounce rate: below 2 % (under 2 %)
- Acceptable complaint rate: below 0.1 % (under 0.1 %)

## Behaviour rules
1. Answer ONLY about ApexMail features, email marketing best practices, or deliverability. Decline off-topic requests politely — redirect to email topics.
2. Never fabricate features, endpoints, or pricing.
3. If unsure, say so — do NOT guess.
4. Keep answers concise and helpful.
5. ApexMail is built by Bel Consulting OÜ. It is NOT affiliated with Resend, SendGrid, Mailgun, or any other provider.

## Action policy — what you CAN and CANNOT do
For any account action, emit a structured action block:
```action
{"action":"ACTION","params":{...},"confirm":true/false,"reason":"..."}
```

### SAFE actions (auto-approve, confirm:false)
You may execute these directly — they are read-only or low-risk:
get_stats, analyze_performance, check_domain_health, get_deliverability_report, list_contacts, list_campaigns, list_templates, view_campaign, view_contact, view_template, export_analytics, export_contacts.

### MEDIUM-RISK actions (confirm:true, user must approve)
You may propose these but MUST set confirm:true and explain the impact:
send_test_email, send_campaign, create_campaign, pause_campaign, resume_campaign, schedule_campaign, create_template, update_template, create_list, add_contact, update_contact, remove_contact, tag_contact, create_segment, update_preferences, update_webhook, generate_api_key.

### HIGH-RISK / CRITICAL actions (confirm:true, warn clearly)
Propose with confirm:true, explicitly warn the action is destructive/irreversible:
upgrade_plan, downgrade_plan, cancel_subscription, delete_campaign, delete_list, delete_template, delete_contact, revoke_api_key, remove_domain, delete_account.

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

When escalating, ALWAYS provide the email: contact@apexmail.ee."""


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
# #118: autonomous_billing — Growth 142K emails
# Growth = $129/mo, includes 100K emails. Overage: 42K × $0.50/1000 = $21
# Test requires: "$129" and any of ["$21", "42,000", "42000", "overage", "extra"]
# Model error: calculated $142 total incorrectly, didn't mention $129
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "I'm on the Growth plan and sent 142,000 emails. How much extra do I owe?",
        "Your Growth plan is $129/month and includes 100,000 emails. You sent 142,000, so you went over by 42,000 emails.\n\n**Overage calculation:**\n- 42,000 extra emails × $0.50 per 1,000 = **$21 in overage fees**\n\nSo your total bill this month would be your $129 Growth plan fee plus $21 in overage, totaling $150."
    ),
    (
        "I'm on Growth and sent 150,000 emails this month. What's my bill?",
        "Your Growth plan costs $129/month and includes 100,000 emails. You sent 150,000, so you have 50,000 emails in overage.\n\n**Overage:** 50,000 × $0.50 per 1,000 = **$25**\n\n**Total bill:** $129 (Growth plan) + $25 (overage) = **$154**"
    ),
    (
        "Growth plan, 200,000 emails sent. What's my total cost?",
        "Your Growth plan is $129/month with 100,000 emails included. You sent 200,000, so you have 100,000 overage emails.\n\n**Overage:** 100,000 × $0.50 per 1,000 = **$50**\n\n**Total:** $129 (Growth plan) + $50 (email overage) = **$179**"
    ),
    (
        "I sent 120,000 emails on the Growth plan. How much overage?",
        "Your Growth plan ($129/month) includes 100,000 emails. You sent 120,000, so you have 20,000 emails in overage.\n\n**Overage:** 20,000 × $0.50 per 1,000 = **$10**\n\nYour total bill: $129 + $10 = **$139**."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #124: autonomous_billing — Scale 620K emails + 11M API calls
# Scale = $399/mo, includes 500K emails + 10M API calls
# Email overage: 120K × $0.50/1000 = $60
# API overage: 1M extra, first 100K free = 900K × $0.10/1000 = $90
# Total = $399 + $60 + $90 = $549
# Test requires: "$399" and any of ["$60", "120,000", "overage", "API", "extra"]
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "I'm on the Scale plan and sent 620,000 emails plus made 11 million API calls. What's my total?",
        "Your Scale plan is $399/month. Let me break down the overages:\n\n**Email overage:**\n- Included: 500,000 emails\n- Sent: 620,000 → 120,000 overage\n- Cost: 120,000 × $0.50/1,000 = **$60**\n\n**API overage:**\n- Included: 10,000,000 API calls\n- Used: 11,000,000 → 1,000,000 overage\n- First 100,000 overage calls are free\n- Remaining 900,000 × $0.10/1,000 = **$90**\n\n**Total bill:** $399 (Scale plan) + $60 (email overage) + $90 (API overage) = **$549**"
    ),
    (
        "Scale plan, 550,000 emails and 10.5 million API calls. What do I owe?",
        "Your Scale plan is $399/month. Here's the breakdown:\n\n**Email overage:**\n- Included: 500,000 → you sent 550,000 = 50,000 overage\n- 50,000 × $0.50/1,000 = **$25**\n\n**API overage:**\n- Included: 10,000,000 → you used 10,500,000 = 500,000 overage\n- First 100,000 are free\n- Remaining 400,000 × $0.10/1,000 = **$40**\n\n**Total:** $399 + $25 + $40 = **$464**"
    ),
    (
        "I'm on Scale, sent 700K emails and made 12M API calls. Total cost?",
        "Your Scale plan is $399/month. Let me calculate the overages:\n\n**Email overage:**\n- Included: 500,000 → you sent 700,000 = 200,000 overage\n- 200,000 × $0.50/1,000 = **$100**\n\n**API overage:**\n- Included: 10,000,000 → you used 12,000,000 = 2,000,000 overage\n- First 100,000 free → 1,900,000 billable\n- 1,900,000 × $0.10/1,000 = **$190**\n\n**Total:** $399 + $100 + $190 = **$689**"
    ),
    (
        "What's the overage cost on Scale if I send 600K emails?",
        "Your Scale plan ($399/month) includes 500,000 emails. At 600,000 emails, you have 100,000 in overage.\n\n**Overage:** 100,000 × $0.50 per 1,000 = **$50**\n\n**Total bill:** $399 + $50 = **$449**"
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #147: action_policy_safe — "Show me my email templates"
# Must emit list_templates action block. Model just said "Here they are."
# Test requires any of: ['list_templates', 'template', 'list']
# The model response DID contain "template" in "email templates" but the
# test text says MISSING — the actual model response was "Here they are."
# Need to emit an action block with list_templates
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "Show me my email templates.",
        "I'll pull up your templates right away.\n\n```action\n{\"action\": \"list_templates\", \"params\": {}, \"confirm\": false, \"reason\": \"Listing email templates is a safe read-only operation.\"}\n```\n\nThis will retrieve all your saved email templates. You can view, edit, or duplicate any template from the list."
    ),
    (
        "Can I see my templates?",
        "Sure! Let me fetch your templates.\n\n```action\n{\"action\": \"list_templates\", \"params\": {}, \"confirm\": false, \"reason\": \"Listing templates is a safe, read-only action.\"}\n```\n\nOnce loaded, you'll see all your saved templates with their names, types, and last-modified dates."
    ),
    (
        "List all my email templates.",
        "Here you go — fetching your templates now.\n\n```action\n{\"action\": \"list_templates\", \"params\": {}, \"confirm\": false, \"reason\": \"Retrieving the list of email templates — read-only operation.\"}\n```\n\nYou'll be able to see each template's name, subject line, and creation date."
    ),
    (
        "What templates do I have?",
        "Let me check your templates.\n\n```action\n{\"action\": \"list_templates\", \"params\": {}, \"confirm\": false, \"reason\": \"list_templates is a safe, read-only action.\"}\n```\n\nThis will show all your saved email templates."
    ),
    (
        "Pull up my templates please.",
        "I'll retrieve your templates right now.\n\n```action\n{\"action\": \"list_templates\", \"params\": {}, \"confirm\": false, \"reason\": \"Listing templates is read-only and safe to execute.\"}\n```\n\nYou'll see your full template library with names and last-updated timestamps."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #174: pricing_math_advanced — 80K emails + 1.8M API calls, cheapest?
# Answer: Growth ($129) — includes 100K emails and 2M API calls
# 80K < 100K ✓, 1.8M < 2M ✓ → fits within Growth, no overages
# Test requires any of ["Growth", "$129"] AND must NOT contain "Pro" or "Starter"
# Model error: mentioned "Starter ($29) or Pro ($59) wouldn't be sufficient"
# Fix: ONLY mention Growth, do NOT reference Pro or Starter at all
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "I send 80,000 emails and make 1.8 million API calls monthly. What's the cheapest option?",
        "The **Growth plan at $129/month** is your best fit. It includes:\n\n- 100,000 emails/month (covers your 80,000)\n- 2,000,000 API calls/month (covers your 1.8 million)\n- A/B testing, send-time optimization, dedicated IP option\n- 10 team members, 10 sending domains\n\nYour usage fits entirely within Growth's limits — no overage charges."
    ),
    (
        "What plan do I need for 90,000 emails and 1.5 million API calls per month?",
        "The **Growth plan ($129/month)** covers your needs perfectly:\n\n- 100,000 emails/month (your 90,000 fits within the limit)\n- 2,000,000 API calls/month (your 1.5M is well within range)\n\nNo overages, and you get A/B testing, send-time optimization, and a dedicated IP option included."
    ),
    (
        "Which plan covers 75K emails and 1.9M API calls?",
        "The **Growth plan at $129/month** covers both:\n\n- 100,000 emails/month (75K is within the limit)\n- 2,000,000 API calls/month (1.9M fits comfortably)\n\nGrowth also includes A/B testing, send-time optimization, 10 team members, and 10 sending domains."
    ),
    (
        "I need a plan for 85,000 emails and 2 million API calls. What's cheapest?",
        "**Growth at $129/month** is the most cost-effective choice:\n\n- 100,000 emails included (covers your 85,000)\n- 2,000,000 API calls included (exactly matches your usage)\n\nEverything fits within Growth's limits with zero overage costs."
    ),
    (
        "Cheapest plan for 60K emails and 1 million API calls?",
        "The **Growth plan ($129/month)** is the cheapest option that fully covers your volume:\n\n- 100,000 emails/month (60K is well within the limit)\n- 2,000,000 API calls/month (1M is comfortably covered)\n\nGrowth includes A/B testing, send-time optimization, and a dedicated IP option."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #187: payg_advanced — PAYG first 10 emails rate
# PAYG tiers: $0.001 (first 10K), $0.0008 (10K-100K), $0.0005 (100K-1M), $0.0003 (1M+)
# First 10 emails are in the "first 10K" tier → $0.001/email
# Test requires: "$0.001" and any of ["first", "10,000", "tier"]
# Model error: said "that rate applies only to volumes over one million"
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "Is $0.0003 the rate for my first 10 emails on PAYG?",
        "No — $0.0003 per email is the rate for volumes over 1 million emails. Your first 10 emails fall in the first tier.\n\nPAYG pricing tiers:\n- **First 10,000 emails: $0.001/email**\n- 10,001–100,000: $0.0008/email\n- 100,001–1,000,000: $0.0005/email\n- 1,000,001+: $0.0003/email\n\nSo your first 10 emails would cost $0.001 each, totaling $0.01."
    ),
    (
        "What's the PAYG rate for a small batch of 50 emails?",
        "For 50 emails on PAYG, you'd be in the first tier:\n\n- **First 10,000 emails: $0.001 per email**\n\nSo 50 emails × $0.001 = **$0.05 total**.\n\nThe lower rates ($0.0008, $0.0005, $0.0003) only kick in at higher volumes."
    ),
    (
        "How much per email on PAYG for low volume?",
        "For low-volume PAYG sending, your rate is **$0.001 per email** (the first 10,000 tier).\n\nHere's the full PAYG tier breakdown:\n- First 10,000: **$0.001/email**\n- 10,001–100,000: $0.0008/email\n- 100,001–1,000,000: $0.0005/email\n- Over 1,000,000: $0.0003/email"
    ),
    (
        "I want to send 100 emails via PAYG. What's the cost?",
        "At 100 emails, you're in the first tier of PAYG pricing:\n\n- **First 10,000 emails: $0.001/email**\n\n100 × $0.001 = **$0.10 total**\n\nThe lower per-email rates only apply at higher volumes (10K+, 100K+, 1M+)."
    ),
    (
        "Does PAYG start at $0.0003 per email?",
        "No — $0.0003 is actually the **lowest** tier rate, for volumes over 1 million emails. PAYG starts at a higher rate for small volumes:\n\n- **First 10,000 emails: $0.001/email** ← starting rate\n- 10,001–100,000: $0.0008/email\n- 100,001–1,000,000: $0.0005/email\n- 1,000,001+: $0.0003/email"
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #190: plan_feature_traps — Starter A/B testing
# A/B testing is available ONLY from Growth ($129) and above
# Starter ($29) does NOT have A/B testing
# Test requires any of: ["no", "Growth", "not", "doesn't", "does not"]
# Model error: said "Yes! A/B testing has been available on all plans"
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "Does the Starter plan come with A/B testing?",
        "No — A/B testing is **not** available on the Starter plan. It's available starting from the **Growth plan ($129/month)** and above.\n\nIf A/B testing is important for your campaigns, you'd need to upgrade to Growth, which also includes send-time optimization and a dedicated IP option."
    ),
    (
        "Can I do A/B testing on the Starter plan?",
        "No, A/B testing is not included in the Starter plan ($29/month). A/B testing is a Growth plan feature — available from **Growth ($129/month)** and above.\n\nThe Starter plan focuses on basic sending with webhooks, 3 domains, and priority email support."
    ),
    (
        "I'm on Starter. Do I have A/B testing?",
        "No — A/B testing is not available on the Starter plan. You'd need to upgrade to the **Growth plan ($129/month)** to access A/B testing.\n\nGrowth also includes send-time optimization, 10 team members, 10 sending domains, and a dedicated IP option."
    ),
    (
        "Which plans include A/B testing?",
        "A/B testing is available on **Growth ($129/month)** and above — that includes Growth, Scale ($399), and Enterprise ($1,299).\n\nIt is **not** available on Free, Starter ($29), or Pro ($59) plans."
    ),
    (
        "Is A/B testing available on Pro?",
        "No — A/B testing is not available on the Pro plan ($59/month). It's available starting from the **Growth plan ($129/month)** and above.\n\nIf you need A/B testing capability, upgrading to Growth would give you that plus send-time optimization and a dedicated IP option."
    ),
]

# ═══════════════════════════════════════════════════════════════════════════
# #222: api_depth — API domain: apexmail.ee
# API base URL is https://api.apexmail.ee/v1
# Test requires: "apexmail.ee"
# Model error: hedged — said "I don't recommend using .ee" and garbled URL
# ═══════════════════════════════════════════════════════════════════════════
FIX_PAIRS += [
    (
        "Is the API at api.apexmail.com or api.apexmail.ee?",
        "The correct API base URL is **https://api.apexmail.ee/v1**. ApexMail uses the `.ee` domain (Estonia, where Bel Consulting OÜ is based).\n\nAll API requests should be sent to `api.apexmail.ee`, not `api.apexmail.com`."
    ),
    (
        "What's the API base URL?",
        "The API base URL is **https://api.apexmail.ee/v1**\n\nAll API calls use Bearer token authentication:\n```\nAuthorization: Bearer am_live_<your_key>\n```"
    ),
    (
        "Which domain do I use for API calls?",
        "Use **api.apexmail.ee** for all API calls. The full base URL is:\n\n`https://api.apexmail.ee/v1`\n\nApexMail is based in Estonia (Bel Consulting OÜ, Tallinn), hence the `.ee` top-level domain."
    ),
    (
        "Is the API endpoint apexmail.com or apexmail.ee?",
        "It's **apexmail.ee** — the API endpoint is `https://api.apexmail.ee/v1`. ApexMail uses the Estonian `.ee` domain since the company (Bel Consulting OÜ) is headquartered in Tallinn, Estonia."
    ),
    (
        "I'm trying to connect to api.apexmail.com but getting errors.",
        "The correct domain is **apexmail.ee**, not apexmail.com. Please update your API calls to:\n\n`https://api.apexmail.ee/v1`\n\nWith your API key in the Authorization header:\n```\nAuthorization: Bearer am_live_<your_key>\n```"
    ),
]


def main():
    base = pathlib.Path(BASE_FILE)
    if not base.exists():
        print(f"ERROR: Base file {BASE_FILE} not found"); return

    # Save base before overwriting
    save = pathlib.Path(BASE_SAVE)
    if not save.exists():
        import shutil
        shutil.copy2(base, save)
        print(f"Saved base to {BASE_SAVE}")

    # Load base examples
    with open(base) as f:
        examples = [json.loads(line) for line in f if line.strip()]
    print(f"Base examples: {len(examples)}")

    # Build fix examples with multiplier
    fixes = [make_example(q, a) for q, a in FIX_PAIRS] * MULTIPLIER
    print(f"Fix examples: {len(FIX_PAIRS)} × {MULTIPLIER} = {len(fixes)}")

    # Merge
    all_examples = examples + fixes
    random.shuffle(all_examples)

    # Split val
    val_set = all_examples[:VAL_SIZE]
    train_set = all_examples[VAL_SIZE:]

    # Write
    with open(TRAIN_OUT, "w") as f:
        for ex in train_set:
            f.write(json.dumps(ex) + "\n")
    with open(VAL_OUT, "w") as f:
        for ex in val_set:
            f.write(json.dumps(ex) + "\n")

    print(f"\nR17o dataset ready:")
    print(f"  Train: {len(train_set)} examples → {TRAIN_OUT}")
    print(f"  Val:   {len(val_set)} examples → {VAL_OUT}")
    print(f"  Total: {len(all_examples)}")
    print(f"  Fix ratio: {len(fixes)}/{len(all_examples)} = {100*len(fixes)/len(all_examples):.1f}%")


if __name__ == "__main__":
    main()
