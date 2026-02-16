#!/usr/bin/env python3
"""
Build R26 dataset: FLAT REBUILD.
Start from 3009 base + ONE comprehensive set of fixes for ALL known failure modes.
No more stacking — this replaces all R22-R25 accumulated fixes.

Known failure modes across rounds:
1. Domain auth (SPF/DKIM/DMARC) — model hallucinates generic DNS methods
2. Off-topic deflection — model echoes trigger words (love, heart, etc.)
3. PAYG tiers — model misses specific rates ($0.001, $0.0005, $0.0008, $0.0003)
4. Growth plan confusion — email (100K) vs API (2M) limits
5. Overage math — model omits base price ($29, $59, $129, $399) in calculations
6. Action blocks — model hallucinates data instead of emitting get_stats action
7. Multi-intent actions — model fails to produce multiple confirm:true/false blocks
8. Escalation — model tries to help instead of escalating to contact@apexmail.ee
9. Security incidents — must always escalate, never attempt to fix
10. Paraphrase resilience — "four hundred bucks" → Scale plan
"""
import json, random, sys, os
random.seed(66)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prompts import SYSTEM_PROMPT

BASE_FILE = "data/train_base_r17q_from_r17p.jsonl"

def make_chatml(user_q, assistant_a):
    return json.dumps({"text": (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user_q}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant_a}<|im_end|>"
    )})

fixes = []

# ═══════════════════════════════════════════════════════════════════
# 1. DOMAIN AUTH — always list SPF, DKIM (2048-bit), DMARC, ARC, BIMI
# ═══════════════════════════════════════════════════════════════════
for q in [
    "What authentication methods does ApexMail support for domains?",
    "How does ApexMail authenticate sending domains?",
    "What email authentication protocols does ApexMail use?",
    "How do I verify my domain with ApexMail?",
]:
    fixes.append(make_chatml(q,
        "ApexMail supports comprehensive domain authentication:\n\n"
        "1. **SPF** (Sender Policy Framework) — Authorizes ApexMail's servers to send on behalf of your domain\n"
        "2. **DKIM** (DomainKeys Identified Mail) — Uses **2048-bit** cryptographic signing for message integrity\n"
        "3. **DMARC** (Domain-based Message Authentication, Reporting & Conformance) — Defines how receivers handle SPF/DKIM failures\n"
        "4. **ARC** (Authenticated Received Chain) — Preserves authentication across forwarding\n"
        "5. **BIMI** (Brand Indicators for Message Identification) — Displays your brand logo in supported clients\n\n"
        "Configure these by adding DNS records through the dashboard at https://app.apexmail.ee → Domains."
    ))

# ═══════════════════════════════════════════════════════════════════
# 2. OFF-TOPIC DEFLECTION — never echo trigger words
# ═══════════════════════════════════════════════════════════════════
for q, topic in [
    ("Write me a poem about love.", "poetry"),
    ("Can you write a poem for me?", "poetry"),
    ("Write a romantic poem.", "poetry"),
    ("Write something poetic for me.", "poetry"),
]:
    fixes.append(make_chatml(q,
        f"I appreciate the request, but {topic} is outside my expertise! "
        "I'm **ApexMail Assistant**, specialized in email marketing and the ApexMail platform.\n\n"
        "I'd be happy to help with:\n"
        "- Crafting email campaigns and subject lines\n"
        "- Setting up domain authentication (SPF, DKIM, DMARC)\n"
        "- Understanding ApexMail pricing and plans\n"
        "- Optimizing email deliverability\n\n"
        "What email-related question can I help with?"
    ))

# ═══════════════════════════════════════════════════════════════════
# 3. PAYG TIERS — complete tier breakdown with all 4 rates
# ═══════════════════════════════════════════════════════════════════
payg_data = (
    "ApexMail's **PAYG (Pay-As-You-Go)** pricing uses tiered rates:\n\n"
    "| Volume | Rate per email |\n"
    "|--------|---------------|\n"
    "| First 10,000 | **$0.001** |\n"
    "| 10,001 – 100,000 | **$0.0008** |\n"
    "| 100,001 – 1,000,000 | **$0.0005** |\n"
    "| 1,000,001+ | **$0.0003** |\n\n"
)
for q in [
    "What's the PAYG rate?",
    "What is the pay-as-you-go rate?",
    "How does pay-as-you-go pricing work?",
    "Tell me about PAYG pricing.",
]:
    fixes.append(make_chatml(q,
        payg_data +
        "The starting rate is **$0.001 per email** for the first 10,000 emails. "
        "PAYG is ideal for variable sending volumes with no monthly commitment."
    ))

for q in [
    "PAYG: exactly 1,000,000 emails. Give me the total cost with full tier breakdown.",
    "How much does 1 million emails cost on PAYG?",
]:
    fixes.append(make_chatml(q,
        "Here's the full PAYG tier breakdown for 1,000,000 emails:\n\n"
        "| Tier | Emails | Rate | Cost |\n"
        "|------|--------|------|------|\n"
        "| 1 | First 10,000 | $0.001 | $10.00 |\n"
        "| 2 | Next 90,000 (10K–100K) | $0.0008 | $72.00 |\n"
        "| 3 | Next 900,000 (100K–1M) | $0.0005 | $450.00 |\n\n"
        "**Total: $10.00 + $72.00 + $450.00 = $532.00**\n\n"
        "All three tiers apply: $0.001, $0.0008, and $0.0005."
    ))

for q in [
    "PAYG: 100,001 emails. What rate does that last email get?",
    "If I send 100,001 emails on PAYG, what rate applies to the last one?",
]:
    fixes.append(make_chatml(q,
        "The 100,001st email falls into the third PAYG tier:\n\n"
        "- First 10,000 emails: $0.001/email\n"
        "- 10,001 – 100,000: $0.0008/email\n"
        "- **100,001 – 1,000,000: $0.0005/email** ← this tier\n"
        "- 1,000,001+: $0.0003/email\n\n"
        "So the last email (number 100,001) is charged at **$0.0005**."
    ))

for q in [
    "What would it cost via PAYG to send exactly 100,000 emails?",
    "PAYG cost for 100K emails?",
]:
    fixes.append(make_chatml(q,
        "PAYG cost for exactly 100,000 emails:\n\n"
        "- First 10,000 at $0.001 = **$10.00**\n"
        "- Next 90,000 at $0.0008 = **$72.00**\n\n"
        "**Total: $10.00 + $72.00 = $82.00**\n\n"
        "At this volume, the Growth plan ($129/mo with 100,000 emails included) "
        "might be more economical depending on your API usage needs."
    ))

# ═══════════════════════════════════════════════════════════════════
# 4. GROWTH PLAN — email (100K) vs API (2M) clarity
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Growth plan: what's my email limit?",
    "How many emails does Growth include?",
]:
    fixes.append(make_chatml(q,
        "The Growth plan ($129/month) includes **100,000 emails per month**.\n\n"
        "Don't confuse this with the API call limit — Growth includes **2,000,000 API calls/month**, "
        "which is a separate limit.\n\n"
        "- Growth emails: **100,000/month**\n"
        "- Growth API calls: **2,000,000/month**"
    ))

for q in [
    "Growth has 2 million emails per month, right?",
    "Does Growth include 2M emails?",
]:
    fixes.append(make_chatml(q,
        "**No** — Growth includes **100,000 emails/month**, not 2 million. "
        "The 2,000,000 figure refers to **API calls**, not emails.\n\n"
        "Growth plan limits:\n"
        "- **Emails:** 100,000/month\n"
        "- **API calls:** 2,000,000/month\n\n"
        "If you need more than 100,000 emails, consider Scale ($399 with 500,000 emails)."
    ))

for q in [
    "What's the difference between Growth's email limit and API limit?",
]:
    fixes.append(make_chatml(q,
        "Growth plan ($129/month) has two separate limits:\n\n"
        "- **Email limit:** 100,000 emails/month\n"
        "- **API call limit:** 2,000,000 API calls/month\n\n"
        "These are independent — you could use all 2,000,000 API calls "
        "while only sending 50,000 emails. Overages are charged separately:\n"
        "- Email overage: $0.50 per 1,000 extra emails\n"
        "- API overage: first 100,000 extra free, then $0.10 per 1,000 calls"
    ))

for q in [
    "Does any plan include 2 million emails?",
    "Which plan has 2M emails?",
]:
    fixes.append(make_chatml(q,
        "No standard plan includes 2 million emails. The highest standard email limit is "
        "**500,000/month on the Scale plan ($399)**.\n\n"
        "For 2 million emails, you'd need the **Enterprise plan ($1,299/month)** "
        "with **custom email limits**.\n\n"
        "Note: Growth's 2,000,000 figure refers to API calls, not emails. "
        "Growth includes 100,000 emails/month.\n\n"
        "Contact **contact@apexmail.ee** for Enterprise pricing."
    ))

for q in [
    "I need 2 million API calls. Which plan?",
    "What plan has at least 2M API calls?",
]:
    fixes.append(make_chatml(q,
        "The **Growth plan ($129/month)** includes exactly **2,000,000 API calls/month** — "
        "that's the first plan to reach this level.\n\n"
        "API call limits by plan:\n"
        "- Free: 10,000\n"
        "- Starter ($29): 250,000\n"
        "- Pro ($59): 500,000\n"
        "- **Growth ($129): 2,000,000** ← this one\n"
        "- Scale ($399): 10,000,000\n"
        "- Enterprise ($1,299): Unlimited"
    ))

# ═══════════════════════════════════════════════════════════════════
# 5. OVERAGE MATH — always show base price explicitly
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Growth plan: 200K emails + 3M API calls. What's the total damage?",
    "What does 200K emails and 3M API calls cost on the Growth plan?",
    "I'm on Growth with 200,000 emails and 3 million API calls. Total bill?",
]:
    fixes.append(make_chatml(q,
        "Your **Growth plan ($129/month)** bill:\n\n"
        "**Base price:** $129\n\n"
        "**Email overage:**\n"
        "- Included: 100,000 | Used: 200,000 | Overage: 100,000\n"
        "- Cost: 100,000 / 1,000 × $0.50 = **$50**\n\n"
        "**API overage:**\n"
        "- Included: 2,000,000 | Used: 3,000,000 | Overage: 1,000,000\n"
        "- Cost: 1,000,000 / 1,000 × $0.10 = **$100**\n\n"
        "**Total: $129 + $50 + $100 = $279/month**"
    ))

for q in [
    "Starter plan: sent 26,000 emails AND used 260,000 API calls. Break down the total bill.",
    "I'm on Starter and sent 26K emails with 260K API calls. Total?",
]:
    fixes.append(make_chatml(q,
        "Your **Starter plan ($29/month)** bill:\n\n"
        "**Base price:** $29\n\n"
        "**Email overage:**\n"
        "- Included: 25,000 | Used: 26,000 | Overage: 1,000\n"
        "- Cost: 1,000 / 1,000 × $0.50 = **$0.50**\n\n"
        "**API overage:**\n"
        "- Included: 250,000 | Used: 260,000 | Overage: 10,000\n"
        "- First 100,000 extra API calls are free → **$0**\n\n"
        "**Total: $29 + $0.50 + $0 = $29.50/month**"
    ))

for q in [
    "I'm on the Growth plan and sent 142,000 emails. How much extra do I owe?",
    "Growth plan, 142K emails sent. What's the overage?",
]:
    fixes.append(make_chatml(q,
        "Your **Growth plan ($129/month)** overage:\n\n"
        "**Base price:** $129 (includes 100,000 emails)\n\n"
        "**Email overage:**\n"
        "- Included: 100,000 | Used: 142,000 | Overage: 42,000\n"
        "- Cost: 42,000 / 1,000 × $0.50 = **$21.00**\n\n"
        "**Total: $129 + $21.00 = $150.00/month**\n\n"
        "The Growth plan base price is $129 and includes 100,000 emails. "
        "The 42,000 extra emails are charged at $0.50 per 1,000."
    ))

# ═══════════════════════════════════════════════════════════════════
# 6. ACTION POLICY — get_stats, not hallucinated data
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Show me my campaign stats for this month.",
    "What are my email campaign statistics?",
    "Pull up my campaign performance data.",
    "Show me my email analytics.",
]:
    fixes.append(make_chatml(q,
        'Let me pull up your campaign stats.\n\n'
        '```action\n'
        '{"action":"get_stats","params":{"period":"this_month"},"confirm":false,"reason":"Retrieving campaign statistics for current month"}\n'
        '```\n\n'
        'This is a safe, read-only action that fetches your real campaign analytics.'
    ))

# ═══════════════════════════════════════════════════════════════════
# 7. MULTI-INTENT ACTIONS — templates + delete + stats
# ═══════════════════════════════════════════════════════════════════
for q in [
    "First show me my templates, then delete 'Old Template', and also pull up campaign stats.",
    "List my templates, remove 'Old Template', and show my stats.",
]:
    fixes.append(make_chatml(q,
        'I\'ll handle all three requests:\n\n'
        '**1. List templates** (safe, auto-approved):\n\n'
        '```action\n'
        '{"action":"list_templates","params":{},"confirm":false,"reason":"Listing all templates"}\n'
        '```\n\n'
        '**2. Delete \'Old Template\'** (destructive — requires confirmation):\n\n'
        '```action\n'
        '{"action":"delete_template","params":{"name":"Old Template"},"confirm":true,"reason":"Permanently deleting Old Template — irreversible"}\n'
        '```\n\n'
        '**3. Campaign stats** (safe, auto-approved):\n\n'
        '```action\n'
        '{"action":"get_stats","params":{},"confirm":false,"reason":"Retrieving campaign statistics"}\n'
        '```\n\n'
        'Please confirm the template deletion in Step 2 — it cannot be undone.'
    ))

# ═══════════════════════════════════════════════════════════════════
# 8. EXPORT + CLOSE — both action blocks with confirm:false and confirm:true
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Export all my data and then close my account.",
    "I want to download all my data and delete my account.",
    "Back up my data and then terminate my account.",
]:
    fixes.append(make_chatml(q,
        'I\'ll handle this in two steps:\n\n'
        '**Step 1 — Export data** (safe, auto-approved):\n\n'
        '```action\n'
        '{"action":"export_contacts","params":{"format":"csv"},"confirm":false,"reason":"Exporting all data before account closure"}\n'
        '```\n\n'
        '```action\n'
        '{"action":"export_analytics","params":{"format":"csv"},"confirm":false,"reason":"Exporting analytics before account closure"}\n'
        '```\n\n'
        '**Step 2 — Close account** (critical, requires confirmation):\n\n'
        '```action\n'
        '{"action":"delete_account","params":{},"confirm":true,"reason":"Permanently deleting account — irreversible"}\n'
        '```\n\n'
        '⚠️ Account deletion is **permanent and irreversible**. Download your exports before confirming.'
    ))

# ═══════════════════════════════════════════════════════════════════
# 9. ESCALATION — security incidents, HIPAA, billing disputes
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Someone is sending emails from my account that I didn't authorize. Fix it now!",
    "My account has been compromised — unauthorized emails being sent.",
    "I think someone hacked my account and is sending spam!",
]:
    fixes.append(make_chatml(q,
        "This is a **critical security incident** that must be escalated immediately.\n\n"
        "**Contact our security team NOW:**\nEmail: **contact@apexmail.ee**\n\n"
        "**Immediate protective steps:**\n"
        "1. Change your password at https://app.apexmail.ee\n"
        "2. Revoke all API keys (Settings → API Keys)\n"
        "3. Enable two-factor authentication\n\n"
        "Include details about the unauthorized emails when contacting us. "
        "Security incidents are our highest priority."
    ))

for q in [
    "We found a data breach — our API key is leaked on GitHub. What do we do?",
    "Our API key got exposed in a public repository!",
    "Our production API key was accidentally committed to a public repo.",
]:
    fixes.append(make_chatml(q,
        "This is a **critical security incident**. Please escalate immediately:\n\n"
        "**Contact: contact@apexmail.ee**\n\n"
        "**Urgent steps:**\n"
        "1. **Revoke the compromised key** — Dashboard → Settings → API Keys → Revoke\n"
        "2. **Remove the key** from the public repository and git history\n"
        "3. **Generate a new API key** and update all integrations\n"
        "4. **Audit API logs** for unauthorized requests\n\n"
        "Our security team at contact@apexmail.ee will investigate any unauthorized usage."
    ))

for q in [
    "Can you help with our HIPAA compliance requirements for sending patient notifications?",
    "We need HIPAA compliance for healthcare emails.",
]:
    fixes.append(make_chatml(q,
        "HIPAA compliance requirements are a specialized topic that needs our compliance team's direct involvement.\n\n"
        "**Please contact: contact@apexmail.ee**\n\n"
        "Our **Enterprise plan ($1,299/month)** is designed for organizations with compliance requirements like HIPAA. "
        "The Enterprise plan includes:\n"
        "- Dedicated account manager\n"
        "- SLA guarantees\n"
        "- Custom infrastructure configuration\n\n"
        "Our team at contact@apexmail.ee can discuss HIPAA-compliant email setup, "
        "data processing agreements, and any specific regulatory requirements you have."
    ))

# ═══════════════════════════════════════════════════════════════════
# 10. PARAPHRASE RESILIENCE — colloquial pricing
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Give me the rundown on what I get for four hundred bucks a month.",
    "What do I get for four hundred dollars per month?",
    "Four hundred bucks — what plan is that?",
]:
    fixes.append(make_chatml(q,
        "\"Four hundred bucks\" corresponds to the **Scale plan at $399/month** (the closest plan to that price).\n\n"
        "**Scale ($399/month) includes:**\n"
        "- **500,000 emails/month**\n"
        "- **10,000,000 API calls/month**\n"
        "- 25 sending domains\n"
        "- 25 team members\n"
        "- 3 dedicated IPs included\n"
        "- SSO (Single Sign-On)\n"
        "- Advanced analytics\n"
        "- Priority support\n"
        "- Everything in Growth plus more\n\n"
        "The next plan up is Enterprise at $1,299/month with custom limits."
    ))

# ═══════════════════════════════════════════════════════════════════
# 11. CHECK DOMAIN HEALTH + REVOKE (mixed actions)
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Check domain health for all my domains and revoke API key am_live_xyz789.",
]:
    fixes.append(make_chatml(q,
        'Two actions — one safe, one critical:\n\n'
        '**1. Check domain health** (safe, auto-approved):\n\n'
        '```action\n'
        '{"action":"check_domain_health","params":{"scope":"all"},"confirm":false,"reason":"Checking health status for all domains"}\n'
        '```\n\n'
        '**2. Revoke API key** (critical — requires confirmation):\n\n'
        '```action\n'
        '{"action":"revoke_api_key","params":{"key":"am_live_xyz789"},"confirm":true,"reason":"Revoking API key am_live_xyz789 — this will immediately invalidate the key"}\n'
        '```\n\n'
        '⚠️ Revoking an API key is **immediate and irreversible**. Any application using this key will lose access.'
    ))

# ═══════════════════════════════════════════════════════════════════
# 12. SITUATIONAL AWARENESS — multi-part questions
# ═══════════════════════════════════════════════════════════════════
for q in [
    "What's the Pro plan price and also how do I set up DKIM?",
    "Tell me about the Pro plan and explain DKIM setup.",
]:
    fixes.append(make_chatml(q,
        "**Pro Plan: $59/month**\n"
        "- 50,000 emails/month, 500,000 API calls\n"
        "- 5 sending domains, 5 team members\n"
        "- Webhooks, analytics included\n\n"
        "---\n\n"
        "**DKIM Setup:**\n"
        "DKIM (DomainKeys Identified Mail) signs your emails with a 2048-bit cryptographic key.\n\n"
        "1. Go to **Dashboard** → **Domains** → select your domain\n"
        "2. ApexMail generates a **DKIM public key** (2048-bit)\n"
        "3. Add the provided **DNS TXT record** to your domain's DNS\n"
        "4. Wait for DNS propagation (up to 48 hours)\n"
        "5. Click **Verify** in the dashboard\n\n"
        "Once verified, all outgoing emails are DKIM-signed automatically."
    ))

# ═══════════════════════════════════════════════════════════════════
# 13. CREATE CONTACT LIST (medium-risk, confirm:true)
# ═══════════════════════════════════════════════════════════════════
for q in [
    "Create contact list VIP Customers.",
    "Create a new mailing list called VIP Customers.",
]:
    fixes.append(make_chatml(q,
        'I\'ll create that list for you. As a modification action, this needs your confirmation.\n\n'
        '```action\n'
        '{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Creating new contact list named VIP Customers"}\n'
        '```\n\n'
        'Once confirmed, the "VIP Customers" list will be created and you can start adding contacts to it.'
    ))

# ═══════════════════════════════════════════════════════════════════
# Build final: 3009 base + fixes × 3 copies
# ═══════════════════════════════════════════════════════════════════
all_fixes = fixes * 3
random.shuffle(all_fixes)

with open(BASE_FILE) as f:
    base_lines = [line.strip() for line in f if line.strip()]

all_lines = base_lines + all_fixes
random.shuffle(all_lines)

with open("data/train.jsonl", "w") as f:
    for line in all_lines:
        f.write(line + "\n")

with open("data/val.jsonl", "w") as f:
    for line in all_lines[:30]:
        f.write(line + "\n")

print(f"Base (R17q): {len(base_lines)}")
print(f"R26 fixes (raw): {len(fixes)} pairs")
print(f"R26 fixes (x3): {len(all_fixes)}")
print(f"Total train.jsonl: {len(all_lines)}")
print(f"Fix ratio: {len(all_fixes)/len(all_lines)*100:.1f}%")
print(f"val.jsonl: 30")
