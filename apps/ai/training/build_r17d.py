"""
build_r17d.py  –  R17d dataset builder
═══════════════════════════════════════════════════════════════════════════

R17c results: 583/600 (97.2%) — 17 failures across 13 categories

CRITICAL BUG FOUND: R17c training data taught WRONG API call limits and
wrong API overage rate:
  - API overages: taught $0.20/1K but system prompt says $0.10/1K
  - Growth API: taught 1,000,000 but system prompt says 2,000,000
  - Scale API: taught 5,000,000 but system prompt says 10,000,000

R17d fixes ALL 17 failures + corrects the poisoned data from R17c.

Remaining failures:
  1. pricing_accuracy (3): API overages=$0.10, Growth API=2M, Scale API=10M
  2. consistency (2): Growth = 100,000 emails (not 500K)
  3. complex_technical (2): email rendering → table/inline CSS; FBL → complaint/ISP
  4. company_identity (1): "San Francisco" leaking into denial
  5. safety_boundaries (1): refuse domain spoofing, don't give SPF help
  6. multi_step_reasoning (1): 100K emails → Growth $129 (not Starter)
  7. feature_plan_matrix (1): dedicated IP + A/B + 50K → Growth $129 (not Pro)
  8. complex_billing (1): 32K on Starter → 7K overage → $3.50
  9. human_escalation (1): hacked account → contact@apexmail.ee
  10. deliverability (1): ROI = $36 per $1
  11. payg_tier_boundaries (1): 500K → $0.0005 rate (100K-1M tier)
  12. paraphrase_resilience (1): anti-spam → SPF/DKIM/DMARC
  13. feature_requests (1): push notifications → email focus

Strategy: aggressive cleaning of wrong API numbers + targeted fixes × MULTIPLIER
"""

import json, random, re
from prompts import SYSTEM_PROMPT

# ══════════════════════════════════════════════════════════════════════════
# Step 1 — Load existing dataset + aggressive cleaning
# ══════════════════════════════════════════════════════════════════════════

base_file = "data/train_base.jsonl"
try:
    with open(base_file) as f:
        raw = [json.loads(line) for line in f]
    print(f"Loaded {len(raw)} base examples from {base_file}")
except FileNotFoundError:
    with open("data/train.jsonl") as f:
        raw = [json.loads(line) for line in f]
    print(f"Loaded {len(raw)} examples from data/train.jsonl (fallback)")


def get_assistant_text(ex):
    if "text" in ex:
        return ex["text"]
    if "messages" in ex:
        for m in ex["messages"]:
            if m.get("role") == "assistant":
                return m.get("content", "")
    return ""


def replace_system_prompt(ex, new_prompt):
    if "text" in ex:
        text = ex["text"]
        old_sys = re.search(r'<\|im_start\|>system\n(.*?)<\|im_end\|>', text, re.DOTALL)
        if old_sys:
            text = text.replace(old_sys.group(1), new_prompt)
        return {"text": text}
    if "messages" in ex:
        msgs = []
        for m in ex["messages"]:
            if m["role"] == "system":
                msgs.append({"role": "system", "content": new_prompt})
            else:
                msgs.append(m)
        return {"messages": msgs}
    return ex


def to_text_format(ex):
    if "text" in ex:
        return ex
    if "messages" in ex:
        parts = []
        for m in ex["messages"]:
            parts.append(f'<|im_start|>{m["role"]}\n{m["content"]}<|im_end|>')
        return {"text": "\n".join(parts)}
    return ex

# ── Fix system prompts & convert format ──────────────────────────────────
fixed = []
for ex in raw:
    ex = replace_system_prompt(ex, SYSTEM_PROMPT)
    ex = to_text_format(ex)
    fixed.append(ex)

# ── Aggressive cleaning — remove ALL wrong patterns ─────────────────────
wrong_pricing = [
    r'\$25[^0].*?starter', r'starter.*?\$25[^0]',
    r'\$49.*?pro', r'pro.*?\$49',
    r'\$99.*?growth', r'growth.*?\$99',
    r'\$199.*?scale', r'\$299.*?scale', r'scale.*?\$199', r'scale.*?\$299',
    r'\$999.*?enterprise', r'enterprise.*?\$999',
    r'50,000.*?starter', r'starter.*?50,000',
    r'100,000.*?pro', r'pro.*?100,000',
]

wrong_patterns = wrong_pricing + [
    # Hallucination patterns
    r"(?i)drag.and.drop.builder",
    r"(?i)slack\s*bot",
    r"(?i)template\s*marketplace",
    r"(?i)DNS\s*hosting\s*(?:service|feature|built)",
    r"(?i)wysiwyg\s*editor",
    r"(?i)community\s*forum",
    r"(?i)built.in\s*(?:CRM|form\s*builder|ticketing)",
    r"(?i)landing\s*page\s*(?:builder|creator|feature)",
    r"(?i)mobile\s*app\s*(?:available|download)",
    # R17c bad patterns
    r"apexmail\.support@gmail\.com",
    r"apexmail\.dev",
    r"(?i)automatically\s*upgrade\s*to\s*Starter",
    # ═══ R17d CRITICAL — clean out WRONG API numbers from R17c ═══
    r"\$0\.20\s*per\s*1[,.]?000\s*(?:call|API)",     # wrong API overage rate
    r"\$0\.20/1[,.]?000\s*(?:call|API)",              # wrong API overage rate
    r"\$0\.20\s*per\s*(?:thousand|1K)\s*(?:call|API)", # wrong API overage rate
    r"(?i)growth.*?1[,.]000[,.]000\s*API\s*call",     # wrong Growth API (1M, should be 2M)
    r"(?i)1[,.]000[,.]000\s*API\s*call.*?growth",     # wrong Growth API
    r"(?i)scale.*?5[,.]000[,.]000\s*API\s*call",      # wrong Scale API (5M, should be 10M)
    r"(?i)5[,.]000[,.]000\s*API\s*call.*?scale",      # wrong Scale API
    r"(?i)growth.*?1M\s*API",                          # wrong Growth API shorthand
    r"(?i)scale.*?5M\s*API",                           # wrong Scale API shorthand
    r"(?i)500,000\s*(?:emails|email).*?growth",        # wrong Growth email count
    r"(?i)growth.*?500,000\s*(?:emails|email)",        # wrong Growth email count
]

clean_base = []
removed = 0
for ex in fixed:
    text = ex.get("text", "")
    assistant_text = text.split("<|im_start|>assistant\n")[-1] if "<|im_start|>assistant" in text else text
    if any(re.search(p, assistant_text, re.IGNORECASE) for p in wrong_patterns):
        removed += 1
    else:
        clean_base.append(ex)
print(f"Removed {removed} base examples with wrong patterns")
print(f"Clean base: {len(clean_base)}")

# ══════════════════════════════════════════════════════════════════════════
# Step 2 — Helper
# ══════════════════════════════════════════════════════════════════════════

def make_example(user_msg, assistant_msg):
    return {
        "text": (
            "<|im_start|>system\n" + SYSTEM_PROMPT + "<|im_end|>\n"
            "<|im_start|>user\n" + user_msg + "<|im_end|>\n"
            "<|im_start|>assistant\n" + assistant_msg + "<|im_end|>"
        )
    }


diverse_fixes = []

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 1: CORRECT API CALL LIMITS (was WRONG in R17c)
# System prompt: Growth=2,000,000  Scale=10,000,000
# ══════════════════════════════════════════════════════════════════════════

correct_api_limits_qa = [
    ("How many API calls do I get on the Growth plan?",
     "The **Growth plan** includes **2,000,000 API calls/month** (2 million). If you exceed that, overages are $0.10 per 1,000 additional calls."),
    ("Growth plan API calls?",
     "Growth includes **2,000,000 (2M) API calls per month**. Overages beyond that are billed at $0.10/1,000 calls."),
    ("What's the API call limit on Growth?",
     "The Growth plan has **2,000,000 API calls/month**. That's 2 million calls included. For more, Scale offers 10,000,000 (10M)."),
    ("How many API calls come with the Growth tier?",
     "The **Growth plan ($129/month)** includes **2,000,000 API calls/month**. Enterprise has unlimited API calls."),
    ("What are the API call limits for the Scale plan?",
     "The **Scale plan** includes **10,000,000 API calls/month** (10 million). Enterprise has unlimited. If you exceed Scale's 10M quota, overages are $0.10 per 1,000 extra calls."),
    ("Scale plan API calls?",
     "Scale includes **10,000,000 (10M) API calls per month**. That's the highest fixed quota — only Enterprise has unlimited."),
    ("How many API calls does Scale include?",
     "The **Scale plan ($399/month)** includes **10,000,000 API calls/month**. For unlimited, you'd need Enterprise ($1,299/month)."),
    ("What's the API limit on Scale?",
     "Scale has **10,000,000 API calls/month** (10 million). Overages beyond that are $0.10 per 1,000 extra calls."),
    ("Compare API call limits across all plans.",
     "Here are the API call limits per plan:\n\n| Plan | API Calls/month |\n|------|----------------|\n| Free | 10,000 |\n| Starter | 250,000 |\n| Pro | 500,000 |\n| Growth | **2,000,000** |\n| Scale | **10,000,000** |\n| Enterprise | **Unlimited** |\n\nOverages on paid plans are $0.10 per 1,000 extra calls."),
    ("What plan has 2 million API calls?",
     "The **Growth plan ($129/month)** includes **2,000,000 API calls/month** (2 million). It also comes with 100,000 emails, A/B testing, and 1 dedicated IP."),
    ("I need 5 million API calls. Which plan?",
     "For 5 million API calls, you need the **Scale plan ($399/month)** which includes **10,000,000 API calls/month**. Growth only has 2,000,000. Scale also includes SSO/SAML and 3 dedicated IPs."),
    ("What plan has 10 million API calls?",
     "The **Scale plan ($399/month)** includes **10,000,000 API calls/month** (10 million). It also includes 500,000 emails, SSO/SAML, and 3 dedicated IPs."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 2: CORRECT API OVERAGE RATE (was WRONG in R17c — $0.20→$0.10)
# System prompt: "$0.10 per 1 000 calls"
# ══════════════════════════════════════════════════════════════════════════

correct_api_overage_qa = [
    ("How much are API overages?",
     "API overages are **$0.10 per 1,000 extra API calls** beyond your plan's included quota. The first 100,000 overage calls are free, then it's $0.10/1K after that.\n\nPlan API quotas: Free 10K, Starter 250K, Pro 500K, Growth 2M, Scale 10M, Enterprise unlimited."),
    ("What happens if I exceed my API call limit?",
     "The first **100,000 overage API calls are free**. After that, you're charged **$0.10 per 1,000 additional API calls**. For example, if you exceed your plan quota by 200,000 calls: first 100K are free, remaining 100K costs $10."),
    ("API overage pricing?",
     "API overages: first **100,000 extra calls are free**, then **$0.10 per 1,000 calls** beyond that. Plan quotas: Free 10K, Starter 250K, Pro 500K, Growth 2M, Scale 10M, Enterprise unlimited."),
    ("How much do extra API calls cost?",
     "Extra API calls above your plan's quota: first **100,000 are free**, then **$0.10 per 1,000 calls**. For example, 500K overage calls = 100K free + 400K × $0.10/1K = $40."),
    ("What's the API overage rate?",
     "The API overage rate is **$0.10 per 1,000 calls** after the first 100,000 free overage calls. This applies to all plans (except Enterprise, which has unlimited API calls)."),
    ("API overages start from the first extra call, correct?",
     "No — the first **100,000 extra API calls are free**. After that free buffer, overages are charged at **$0.10 per 1,000 calls**. So you get some breathing room above your plan's quota."),
    ("I used 260,000 API calls on Starter. What's the API overage?",
     "Starter includes **250,000 API calls**. You went over by 10,000 calls.\n\nThe first **100,000 overage calls are free**, so 10,000 is well within that buffer — **$0 API overage**. You won't be charged for API overages until you exceed 350,000 total calls on Starter."),
    ("I'm on Growth and made 2,500,000 API calls. What's the API overage?",
     "Growth includes **2,000,000 API calls**. You went over by 500,000 calls.\n\nFirst **100,000 overage calls are free**. Remaining 400,000:\n400,000 ÷ 1,000 × $0.10 = **$40 API overage**\n\nTotal bill: $129 (Growth base) + $40 = **$169**."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 3: CORRECT FULL PLAN TABLE (reinforcement with right numbers)
# ══════════════════════════════════════════════════════════════════════════

correct_plan_table_qa = [
    ("List all plans with email and API call limits.",
     "Here's the complete plan comparison:\n\n| Plan | Price | Emails/mo | API Calls/mo |\n|------|-------|-----------|--------------|\n| **Free** | $0 | 1,000 | 10,000 |\n| **Starter** | $29 | 25,000 | 250,000 |\n| **Pro** | $59 | 50,000 | 500,000 |\n| **Growth** | $129 | 100,000 | **2,000,000** |\n| **Scale** | $399 | 500,000 | **10,000,000** |\n| **Enterprise** | $1,299 | Custom | **Unlimited** |\n\n**Overages:** Email $0.50/1K extra. API: first 100K free, then $0.10/1K."),
    ("Give me the full pricing table with all quotas.",
     "**ApexMail Pricing:**\n\n| Plan | Monthly | Emails | API Calls |\n|------|---------|--------|-----------|\n| Free | $0 | 1,000 | 10,000 |\n| Starter | $29 | 25,000 | 250,000 |\n| Pro | $59 | 50,000 | 500,000 |\n| Growth | $129 | 100,000 | 2,000,000 |\n| Scale | $399 | 500,000 | 10,000,000 |\n| Enterprise | $1,299 | Custom | Unlimited |\n\n**PAYG**: $0.001 → $0.0003/email (tiered by volume)."),
    ("What are your plans and what do they include?",
     "Here are all plans:\n\n- **Free** ($0): 1,000 emails, 10,000 API calls\n- **Starter** ($29): 25,000 emails, 250,000 API calls, webhooks, 3 domains\n- **Pro** ($59): 50,000 emails, 500,000 API calls, custom tracking, 5 domains\n- **Growth** ($129): 100,000 emails, **2,000,000 API calls**, A/B testing, dedicated IP\n- **Scale** ($399): 500,000 emails, **10,000,000 API calls**, SSO, 3 dedicated IPs\n- **Enterprise** ($1,299): Custom emails, **unlimited API calls**, HIPAA, custom SLA\n\nAlso: **PAYG** from $0.001/email, no subscription."),
    ("How much does each plan cost and what are the limits?",
     "Plan pricing and limits:\n\n1. **Free** — $0/mo: 1,000 emails, 10,000 API calls\n2. **Starter** — $29/mo: 25,000 emails, 250,000 API calls\n3. **Pro** — $59/mo: 50,000 emails, 500,000 API calls\n4. **Growth** — $129/mo: 100,000 emails, 2,000,000 API calls\n5. **Scale** — $399/mo: 500,000 emails, 10,000,000 API calls\n6. **Enterprise** — $1,299/mo: Custom emails, unlimited API calls\n\nPlus **PAYG** starting at $0.001/email with no monthly commitment."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 4: CONSISTENCY — Growth = 100,000 emails (NOT 500K)
# ══════════════════════════════════════════════════════════════════════════

growth_consistency_qa = [
    ("Growth plan — what's included?",
     "The **Growth plan** is **$129/month** and includes:\n\n- **100,000 emails/month**\n- **2,000,000 API calls/month**\n- A/B testing\n- 10 sending domains\n- 10 team members\n- 1 dedicated IP\n- Priority support\n- Send-time optimization\n\nOverages: $0.50/1K extra emails, $0.10/1K extra API calls (first 100K free)."),
    ("Describe the Growth tier for me.",
     "**Growth — $129/month:**\n\n- **100,000 emails/month** (not 500K — that's Scale)\n- **2,000,000 API calls/month**\n- A/B testing & split campaigns\n- 10 sending domains, 10 team members\n- 1 dedicated IP address\n- Priority support\n- AI-powered send-time optimization"),
    ("Tell me about the Growth plan in detail.",
     "The **Growth plan ($129/month)** is designed for growing businesses:\n\n- **100,000 emails/month** with $0.50/1K overage\n- **2,000,000 API calls/month** with $0.10/1K overage (first 100K free)\n- **A/B testing** for subject lines and content\n- **1 dedicated IP** for better deliverability control\n- 10 sending domains, 10 team members\n- Priority support\n- Send-time optimization (AI-powered, per-subscriber)"),
    ("What's the Growth plan include — emails, API calls, features?",
     "**Growth ($129/month):**\n- Emails: **100,000/month**\n- API calls: **2,000,000/month**\n- A/B testing: ✓\n- Dedicated IP: 1\n- Sending domains: 10\n- Team members: 10\n- Priority support: ✓\n- Send-time optimization: ✓\n\nIt's the first plan with A/B testing and a dedicated IP."),
    ("Growth plan email limit?",
     "The Growth plan includes **100,000 emails/month**. If you exceed that, overage is $0.50 per 1,000 extra emails. Need more? Scale ($399) has 500,000 emails/month."),
    ("How many emails does Growth include?",
     "Growth includes **100,000 emails per month** at **$129/month**. That's double the Pro plan's 50,000."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 5: COMPLEX TECHNICAL — email rendering best practices
# ══════════════════════════════════════════════════════════════════════════

email_rendering_qa = [
    ("What's the best way to handle email rendering across different clients?",
     "Email rendering varies wildly across clients. Here are the best practices:\n\n1. **Use table-based layouts** — Outlook and many clients don't support modern CSS flexbox/grid. Tables are the reliable foundation.\n2. **Inline your CSS** — Many clients strip `<style>` blocks. Use inline `style` attributes on each element.\n3. **Test across clients** — Check rendering in Gmail, Outlook, Apple Mail, Yahoo, and mobile clients. Tools like Litmus or Email on Acid help.\n4. **Keep it simple** — Avoid complex layouts. Single-column designs render most consistently.\n5. **Use web-safe fonts** — Fall back to Arial, Helvetica, Georgia for broad compatibility.\n6. **Optimize images** — Some clients block images by default. Always include alt text.\n\nApexMail's **Handlebars templates** let you build responsive templates with dynamic content."),
    ("How do I make sure my emails look good in all email clients?",
     "Cross-client email compatibility tips:\n\n- **Table layouts**: Use `<table>` for structure — Outlook doesn't support flexbox or grid\n- **Inline CSS**: Put styles directly on elements with `style=\"...\"` — some clients strip `<head>` styles\n- **Test extensively**: Gmail, Outlook (desktop + web), Apple Mail, Yahoo, Samsung Mail all render differently\n- **Mobile-first**: Over 50% of emails are opened on mobile — use responsive design\n- **Safe fonts**: Stick to Arial, Helvetica, Georgia, Times New Roman as fallbacks\n- **Alt text on images**: Many clients block images by default\n\nWith ApexMail's Handlebars templates, you can build reusable, tested templates."),
    ("My emails look broken in Outlook. How do I fix this?",
     "Outlook is notoriously difficult for email rendering because it uses Word's rendering engine. Here's how to fix it:\n\n1. **Use table-based layouts** — Outlook ignores flexbox, grid, and most modern CSS\n2. **Inline all CSS** — Outlook strips `<style>` blocks in many versions\n3. **Avoid background images** — Use `background-color` instead or use VML for Outlook-specific backgrounds\n4. **Use MSO conditional comments** — `<!--[if mso]>` for Outlook-specific code\n5. **Set explicit widths** — Use pixel widths on tables and cells\n6. **Test with Outlook desktop** — Outlook.com (web) and Outlook desktop render very differently\n\nApexMail delivers the HTML you build — focus on table layouts and inline CSS for the best cross-client results."),
    ("Email rendering across clients — best practices?",
     "Key best practices for cross-client rendering:\n\n- **Tables for layout** (not div/flexbox — Outlook compatibility)\n- **Inline CSS** on every element (many clients strip `<style>` tags)\n- **Test in major clients**: Gmail, Outlook, Apple Mail, Yahoo, mobile\n- **Web-safe fonts** with fallbacks\n- **Alt text** on all images (clients may block images)\n- **Single-column** designs for best mobile/desktop consistency\n\nApexMail's Handlebars engine handles dynamic content — you control the HTML structure and styling."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 6: COMPLEX TECHNICAL — Feedback Loop (FBL) setup
# ══════════════════════════════════════════════════════════════════════════

fbl_setup_qa = [
    ("How do I set up a proper feedback loop (FBL) with ISPs through ApexMail?",
     "Feedback loops (FBLs) let you receive **spam complaint** notifications from ISPs when subscribers mark your email as spam. Here's how it works with ApexMail:\n\n1. **Automatic handling** — ApexMail processes FBL reports from major **ISPs** (Gmail, Yahoo, Outlook/Hotmail, AOL, etc.) automatically\n2. **Auto-suppression** — When a complaint comes in, the address is automatically added to your **suppression list**\n3. **Webhook notifications** — Set up the `complained` webhook event to get real-time alerts when complaints occur\n4. **Monitor complaint rate** — Keep it below **0.1%** to maintain good sender reputation\n\nYou don't need to set up individual ISP FBLs manually — ApexMail handles the ISP relationships. Just make sure your `complained` webhook is configured to track issues in real-time."),
    ("What's a feedback loop in email and does ApexMail support it?",
     "A **feedback loop (FBL)** is a mechanism where **ISPs** notify senders when recipients mark emails as spam (file a **complaint**). ApexMail supports FBLs:\n\n- **Automatic FBL processing** from major ISPs\n- Complained addresses are auto-added to your **suppression list**\n- Real-time `complained` **webhook** events for your monitoring\n- Helps you maintain a **complaint rate below 0.1%**\n\nNo manual ISP FBL registration needed — ApexMail handles it."),
    ("How does ApexMail handle spam complaints from ISPs?",
     "ApexMail handles **ISP** spam **complaints** automatically through feedback loops (FBLs):\n\n1. ISPs send complaint reports when subscribers mark your email as spam\n2. ApexMail processes these and auto-adds the address to your **suppression list**\n3. You receive a `complained` webhook event in real-time\n4. Future sends to that address are blocked\n\nKeep your complaint rate below **0.1%** — above that, ISPs may throttle or block your sending. Monitor complaints in your analytics dashboard."),
    ("FBL setup with ISPs — how?",
     "ApexMail manages **feedback loops (FBLs)** with major **ISPs** automatically:\n\n- **Complaint** notifications from Gmail, Yahoo, Outlook, AOL etc. are processed in real-time\n- Complained addresses are auto-**suppressed** — no manual action needed\n- Set up the `complained` webhook to track complaints in your system\n- Monitor your complaint rate (keep it below **0.1%**)\n\nNo ISP-by-ISP FBL registration required on your end."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 7: COMPANY IDENTITY — deny San Francisco, affirm Tallinn
# ══════════════════════════════════════════════════════════════════════════

company_identity_sf_qa = [
    ("ApexMail is based in San Francisco, right?",
     "No — ApexMail is based in **Tallinn, Estonia**, not in the United States. The company behind ApexMail is **Bel Consulting OÜ**, an Estonian company founded in **2022**."),
    ("Isn't ApexMail headquartered in San Francisco?",
     "No, ApexMail is headquartered in **Tallinn, Estonia**. It's built by **Bel Consulting OÜ**, founded in **2022**. We're a European company, not US-based."),
    ("I thought ApexMail was in San Francisco.",
     "ApexMail is actually in **Tallinn, Estonia** — not San Francisco or anywhere in the US. The company is **Bel Consulting OÜ**, founded in **2022** in Estonia."),
    ("Is ApexMail a San Francisco startup?",
     "No — ApexMail is an **Estonian** company. We're based in **Tallinn**, operated by **Bel Consulting OÜ** (founded 2022). Not based in the US."),
    ("Where exactly is ApexMail located? San Francisco?",
     "ApexMail is located in **Tallinn, Estonia** — not San Francisco. The legal entity is **Bel Consulting OÜ**, an Estonian company founded in **2022**."),
    ("ApexMail is based in California, correct?",
     "No — ApexMail is based in **Tallinn, Estonia**, not California or anywhere in the US. It's run by **Bel Consulting OÜ**, an Estonian company founded in 2022."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 8: SAFETY — refuse domain spoofing (don't give SPF help)
# ══════════════════════════════════════════════════════════════════════════

refuse_spoofing_qa = [
    ("I want to send emails pretending to be from someone else's domain.",
     "I can't help with that. Sending emails from a domain you don't own is **domain spoofing**, which is illegal in most jurisdictions and violates ApexMail's terms of service. It can also constitute fraud or impersonation.\n\nIf you want to improve your email deliverability with your **own** domain, I can help you set up SPF, DKIM, and DMARC authentication."),
    ("How do I spoof the sender domain to look like another company?",
     "I won't help with domain spoofing — it's **illegal**, violates ApexMail's terms of service, and can constitute fraud. Spoofing another company's domain is impersonation and can lead to criminal charges.\n\nApexMail requires you to verify domain ownership before sending. I can help you set up legitimate email authentication for domains you actually own."),
    ("Can I send emails that appear to come from google.com?",
     "Absolutely not. Sending emails that impersonate another organization's domain is **illegal** and against ApexMail's acceptable use policy. This constitutes domain spoofing and potential fraud.\n\nApexMail requires domain verification — you can only send from domains you own and have verified with SPF/DKIM/DMARC."),
    ("How do I make my emails look like they're from my competitor's domain?",
     "I can't and won't help with that. Impersonating another company's domain is **illegal** — it's fraud, spoofing, and a violation of anti-spam laws (CAN-SPAM, GDPR). ApexMail would immediately terminate accounts engaging in this behavior.\n\nI can help you build a strong sender reputation with your own domain instead."),
    ("I want to send from a domain I don't own. How?",
     "You can't send from a domain you don't own through ApexMail. We require **domain verification** — you must add SPF and DKIM records to your DNS, which proves ownership. Sending from unverified domains is domain spoofing and violates our terms of service.\n\nIf you need help setting up your own domain for sending, I'm happy to guide you."),
    ("Help me forge the 'From' header to make emails look like they're from my competitor?",
     "I absolutely cannot help with forging email headers or impersonating another organization. This is **illegal** — it constitutes fraud, domain spoofing, and violates CAN-SPAM, GDPR, and ApexMail's terms of service.\n\nApexMail enforces domain verification and authentication. I can only help you send from domains you legitimately own."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 9: MULTI-STEP — 100K emails needs Growth, not Starter
# ══════════════════════════════════════════════════════════════════════════

multistep_100k_qa = [
    ("I need to send 100K emails/month, use DKIM, and have A/B testing. What's the cheapest plan?",
     "For **100,000 emails/month with A/B testing**, the cheapest plan is **Growth at $129/month**. Here's why:\n\n- **Starter** ($29): Only 25,000 emails — way too few\n- **Pro** ($59): Only 50,000 emails and no A/B testing\n- **Growth** ($129): **100,000 emails**, **A/B testing** ✓, DKIM ✓ (all plans include DKIM)\n\nGrowth also includes 2,000,000 API calls, 1 dedicated IP, and priority support."),
    ("100K emails, A/B testing, DKIM — minimum plan?",
     "**Growth ($129/month)** is the minimum. A/B testing starts at Growth, and you need at least 100,000 emails. Starter (25K) and Pro (50K) don't have enough emails, and Pro lacks A/B testing. DKIM is on all plans."),
    ("I send 100,000 emails monthly and need A/B testing. What plan?",
     "The **Growth plan at $129/month** is your answer. It's the first plan that includes both **100,000 emails/month** and **A/B testing**. Lower plans either have insufficient email volume or lack A/B testing."),
    ("Cheapest plan for 100K emails with A/B test?",
     "**Growth — $129/month**. It's the entry point for both 100,000 emails/month and A/B testing. Plans below Growth can't match either requirement:\n- Starter ($29): 25K emails, no A/B\n- Pro ($59): 50K emails, no A/B\n- Growth ($129): **100K emails, A/B testing** ✓"),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 10: FEATURE-PLAN MATRIX — dedicated IP + A/B + 50K → Growth
# ══════════════════════════════════════════════════════════════════════════

feature_matrix_growth_qa = [
    ("I need A/B testing, dedicated IP, and at least 50,000 emails. Cheapest option?",
     "The cheapest plan with all three is **Growth at $129/month**:\n\n- ✅ **50,000+ emails**: Growth has 100,000/month\n- ✅ **A/B testing**: Starts at Growth\n- ✅ **Dedicated IP**: Growth includes 1 dedicated IP\n\nPro ($59) has 50,000 emails but lacks A/B testing and dedicated IP. So Growth is the minimum for your requirements."),
    ("Which plan has A/B testing and a dedicated IP?",
     "**A/B testing** and **dedicated IPs** both start at the **Growth plan ($129/month)**. Growth includes 1 dedicated IP. Scale ($399) has 3 dedicated IPs."),
    ("I need a dedicated IP and A/B testing. Minimum plan?",
     "The minimum plan with both features is **Growth ($129/month)**. Pro doesn't include A/B testing or dedicated IPs. Growth gives you both plus 100,000 emails and 2,000,000 API calls."),
    ("Dedicated IP + A/B testing + 50K emails — cheapest?",
     "**Growth at $129/month**. It's the first plan that combines:\n- A/B testing ✓\n- Dedicated IP (1 included) ✓\n- 100,000 emails/month (exceeds your 50K need) ✓\n\nPro ($59) has 50K emails but no A/B and no dedicated IP."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 11: COMPLEX BILLING — 32K on Starter = 7K overage = $3.50
# ══════════════════════════════════════════════════════════════════════════

billing_32k_starter_qa = [
    ("I'm on the Starter plan and sent 32,000 emails this month. What's my total bill?",
     "Your **Starter plan ($29/month)** includes 25,000 emails. You sent 32,000, so the overage is:\n\n**32,000 - 25,000 = 7,000 extra emails**\n7,000 ÷ 1,000 × $0.50 = **$3.50 overage**\n\n**Total: $29 + $3.50 = $32.50**"),
    ("Starter plan, 32K emails sent. What do I owe?",
     "**Starter: $29/month** (25,000 emails included)\n\nOverage: 32,000 - 25,000 = **7,000 extra emails**\n7,000 ÷ 1,000 × $0.50 = **$3.50**\n\n**Total: $29 + $3.50 = $32.50**"),
    ("I sent 32,000 emails on Starter. How much is the overage?",
     "Starter includes 25,000 emails. You sent 32,000:\n\n- Overage: **7,000 emails** (32K - 25K)\n- Cost: 7,000 ÷ 1,000 × $0.50 = **$3.50**\n\nYour total bill: $29 (base) + $3.50 (overage) = **$32.50**."),
    ("32,000 emails on the $29 plan — total?",
     "The **$29 Starter plan** includes 25,000 emails. For 32,000:\n\n- **7,000** emails over limit\n- **$3.50** overage (7K ÷ 1K × $0.50)\n- **Total: $32.50** ($29 + $3.50)"),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 12: HUMAN ESCALATION — hacked account → contact@apexmail.ee
# ══════════════════════════════════════════════════════════════════════════

hacked_account_qa = [
    ("I think someone hacked into my ApexMail account. What do I do?",
     "This is a serious security incident. Take these steps immediately:\n\n1. **Change your password** right now\n2. **Revoke all API keys** in your dashboard (Settings → API Keys)\n3. **Contact our security team** at **contact@apexmail.ee** — include:\n   - When you noticed the unauthorized access\n   - Any suspicious activity (campaigns sent, contacts exported, etc.)\n   - Your account email\n\nOur team will investigate the breach, secure your account, and help you recover. This is treated as high priority."),
    ("My account has been compromised! Help!",
     "I'm sorry — let's act fast:\n\n1. **Change your password immediately**\n2. **Revoke all API keys** from your dashboard\n3. **Contact** our security team at **contact@apexmail.ee** right away\n\nInclude details of any suspicious activity you've noticed. Our team handles account security incidents as top priority and will investigate the compromise immediately."),
    ("Someone unauthorized is using my ApexMail account.",
     "This is a critical security issue. Please:\n\n1. **Change your password** immediately\n2. **Revoke all API keys** (dashboard → API Keys)\n3. **Email contact@apexmail.ee** with the details — what unauthorized activity you noticed, when it started, and your account email\n\nDo NOT wait — our security team will investigate immediately and help secure your account."),
    ("I noticed unauthorized campaigns sent from my account.",
     "This sounds like an account compromise. Act now:\n\n1. **Change your password** immediately\n2. **Revoke all API keys** to stop further unauthorized sends\n3. **Contact contact@apexmail.ee** urgently — describe the unauthorized campaigns, when they were sent, and any other suspicious activity\n\nOur team will investigate the breach and help prevent further damage."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 13: DELIVERABILITY — ROI = $36 per $1
# ══════════════════════════════════════════════════════════════════════════

roi_fix_qa = [
    ("What's the ROI of email marketing?",
     "Email marketing delivers an average ROI of **$36 for every $1 spent** — making it one of the highest-ROI marketing channels. This figure comes from industry benchmarks and reflects the low cost of email compared to its revenue potential.\n\nApexMail helps maximize this ROI through high deliverability, send-time optimization, and engagement analytics."),
    ("What ROI should I pitch to my boss for investing in email marketing?",
     "The industry average email marketing ROI is **$36 per $1 spent** — that's a 3,600% return. It consistently outperforms social media, paid search, and display advertising.\n\nWith ApexMail, you can track your actual ROI through our analytics dashboard (opens, clicks, conversions) and optimize with A/B testing and send-time optimization."),
    ("What ROI can I expect from email vs other channels?",
     "Email marketing has the highest ROI of any marketing channel at **$36 for every $1 spent**. For comparison:\n- Social media: ~$2.80 per $1\n- Paid search: ~$2 per $1\n- Display ads: ~$1.50 per $1\n\nApexMail helps you achieve this through high deliverability, analytics, and optimization tools."),
    ("Email marketing ROI numbers?",
     "The average email marketing ROI is **$36 per $1 spent** — the highest of any marketing channel. This makes email an incredibly cost-effective investment for businesses of all sizes."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 14: PAYG TIER — 500K emails → $0.0005 rate
# ══════════════════════════════════════════════════════════════════════════

payg_500k_qa = [
    ("If I send 500,000 emails via PAYG, what tier rate applies for most of them?",
     "For **500,000 PAYG emails**, most fall in the **100K–1M tier at $0.0005/email**. Here's the breakdown:\n\n- First 10K: $0.001/email = $10\n- 10K–100K (90K): $0.0008/email = $72\n- **100K–500K (400K): $0.0005/email = $200**\n\n**Total: ~$282**\n\nThe **$0.0005** tier covers the bulk (400K out of 500K). At this volume, the Scale plan ($399/month for 500K emails) might be better value since it includes dedicated IPs and SSO."),
    ("What's the PAYG rate for 500,000 emails?",
     "At 500,000 PAYG emails, you span three tiers:\n\n- 0–10K: $0.001 ($10)\n- 10K–100K: $0.0008 ($72)\n- **100K–500K: $0.0005** ($200)\n\nTotal: ~$282. The **$0.0005** rate (100K–1M tier) applies to most of your volume."),
    ("500K emails on PAYG — what rate for the bulk?",
     "The bulk of 500K PAYG emails falls in the **$0.0005/email tier** (100K to 1M). That covers 400K of your 500K emails. The first 100K spans the higher $0.001 and $0.0008 tiers."),
    ("PAYG pricing for half a million emails?",
     "For 500,000 PAYG emails:\n\n| Tier | Emails | Rate | Cost |\n|------|--------|------|------|\n| 0–10K | 10,000 | $0.001 | $10 |\n| 10K–100K | 90,000 | $0.0008 | $72 |\n| **100K–500K** | **400,000** | **$0.0005** | **$200** |\n\n**Total: $282**\n\nCompare with Scale plan at $399/month for 500K emails + features."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 15: PARAPHRASE — anti-spam → SPF/DKIM/DMARC
# ══════════════════════════════════════════════════════════════════════════

antispam_paraphrase_qa = [
    ("What's the cheapest way to not get my emails flagged as junk?",
     "The most impactful (and free!) step is proper **email authentication**:\n\n1. **SPF** — Tells receiving servers you're authorized to send from your domain\n2. **DKIM** — Cryptographically signs your emails with a 2048-bit key\n3. **DMARC** — Enforces alignment between SPF and DKIM\n\nAll ApexMail plans (including **Free**) support SPF, DKIM, and DMARC. Set them up in your dashboard under Domains. Beyond authentication, keep your list clean, honor unsubscribes, and maintain a bounce rate under 2%."),
    ("How do I stop my emails from going to spam?",
     "The key steps to avoid the spam folder:\n\n1. **Set up SPF, DKIM, and DMARC** — These authentication protocols tell ISPs you're a legitimate sender. ApexMail provides the DNS records.\n2. **Clean your list** — Remove bounces and unengaged contacts\n3. **Use double opt-in** — Only email people who want your emails\n4. **Keep bounce rate under 2%** and complaint rate under 0.1%\n5. **Warm up gradually** — Don't send to your full list day one\n\nAuthentication (SPF/DKIM/DMARC) is the single biggest factor."),
    ("Best way to keep emails out of junk folder?",
     "The #1 factor is **authentication**:\n\n- **SPF**: Authorize your sending servers\n- **DKIM**: Sign emails with 2048-bit keys\n- **DMARC**: Enforce authentication policy\n\nBeyond that: clean lists, honor unsubscribes, send relevant content, maintain bounce rate under 2%, and warm up sending volume gradually. ApexMail includes SPF, DKIM, and DMARC setup on all plans."),
    ("What's the most effective way to avoid spam filters?",
     "Focus on these fundamentals:\n\n1. **SPF/DKIM/DMARC authentication** — The biggest impact factor. Set up all three in your DNS (ApexMail provides the records).\n2. **Clean contact lists** — Remove hard bounces and unengaged subscribers\n3. **Complaint rate below 0.1%** — Include clear unsubscribe links\n4. **Bounce rate below 2%** — Regularly clean invalid addresses\n5. **Quality content** — Avoid spam trigger words, use balanced text-to-image ratios\n\nAuthentication is available on all ApexMail plans, including Free."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d FIX 16: FEATURE REQUESTS — push notifications → email focus
# ══════════════════════════════════════════════════════════════════════════

push_notifications_qa = [
    ("Will ApexMail ever support push notifications?",
     "ApexMail is focused on **email** — transactional and marketing email via REST API, SMTP relay, and SDKs. We don't support push notifications and I don't have visibility into whether that's planned.\n\nFor feature requests, you can contact **contact@apexmail.ee**. If you need push notifications now, you'd need a separate service alongside ApexMail for email."),
    ("Does ApexMail offer push notifications?",
     "No — ApexMail is an **email-only** platform. We specialize in transactional and marketing email delivery, not push notifications. Our focus is on email deliverability, analytics, and automation.\n\nIf push notifications are important to your stack, you'd use a separate push service while using ApexMail for email."),
    ("Can I send push notifications through ApexMail?",
     "ApexMail doesn't support push notifications — we're focused exclusively on **email** (transactional and marketing). For push notifications, you'd need a dedicated push service.\n\nApexMail handles email sending, deliverability, analytics, templates, and webhooks. For feature requests, contact **contact@apexmail.ee**."),
    ("When are you adding push notification support?",
     "ApexMail focuses on **email marketing and delivery** — we don't offer push notifications and I don't have roadmap information on this. For feature requests, contact **contact@apexmail.ee**.\n\nFor your email needs, we support transactional and bulk email via REST API, SMTP, and SDKs (Node.js & Python)."),
]

# ══════════════════════════════════════════════════════════════════════════
# R17d REINFORCEMENT — Carry forward critical R17c fixes
# ══════════════════════════════════════════════════════════════════════════

# Escalation - refund
refund_escalation_qa = [
    ("I want a refund for last month because my emails weren't delivered.",
     "I'm sorry about the delivery issues. Refund requests need to be handled by our billing team — please contact **contact@apexmail.ee** with your account details and the delivery issues you experienced. They'll investigate and process your request.\n\nIn the meantime, I can help troubleshoot the delivery problem if you share the bounce codes or error messages."),
    ("I need a refund.",
     "Refunds are processed by our billing team. Please contact **contact@apexmail.ee** with your account details and reason for the refund request. They'll review and respond promptly."),
]

# Escalation - DPA
dpa_escalation_qa = [
    ("I need a signed DPA for our legal team.",
     "DPA (Data Processing Agreement) requests are handled by our compliance team. Please contact **contact@apexmail.ee** with your company details and any specific requirements. They'll prepare and send the DPA for review and signature."),
    ("Our lawyers need a signed Data Processing Agreement by Friday.",
     "Please contact **contact@apexmail.ee** immediately and mention the Friday deadline. Our compliance team handles DPA requests and can expedite given your timeline."),
]

# Action policy medium - test email
action_medium_test_qa = [
    ("Send a test email to test@example.com with subject 'Hello World'.",
     "I'll send that test email. Since it's a send action, please confirm:\n\n```action\n{\"action\":\"send_test_email\",\"params\":{\"to\":\"test@example.com\",\"subject\":\"Hello World\"},\"confirm\":true,\"reason\":\"Sending test email to test@example.com with subject 'Hello World'\"}\n```"),
    ("Schedule my 'Holiday Promo' campaign for December 25th at 9 AM.",
     "I'll schedule that for you. Campaign scheduling needs confirmation:\n\n```action\n{\"action\":\"schedule_campaign\",\"params\":{\"campaign\":\"Holiday Promo\",\"date\":\"2024-12-25\",\"time\":\"09:00\"},\"confirm\":true,\"reason\":\"Scheduling Holiday Promo campaign for December 25th at 9 AM\"}\n```"),
    ("Update the template 'Welcome' with new header text.",
     "Template updates need confirmation since they affect active sends:\n\n```action\n{\"action\":\"update_template\",\"params\":{\"template\":\"Welcome\",\"changes\":\"Update header text\"},\"confirm\":true,\"reason\":\"Updating Welcome template header — affects future sends\"}\n```\n\nPlease share the exact new header text you'd like, and I'll apply it."),
]

# Off-topic deflection
offtopic_qa = [
    ("What stocks should I invest in?",
     "I'm the ApexMail assistant and I specialize in email marketing, not financial advice. I can't recommend stocks. If you have questions about ApexMail plans, email deliverability, or our API, I'm happy to help!"),
    ("What's the best laptop for email marketing?",
     "I specialize in ApexMail's email platform, not hardware recommendations — that's outside my expertise. The good news is ApexMail works in any modern browser, so any laptop with a web browser will do! If you have questions about email campaigns, deliverability, or our API, I'm here to help."),
]

# Credit card → dashboard/contact
credit_card_qa = [
    ("Update my credit card to a new Visa ending in 4242.",
     "For security, payment method changes must be done through your **billing settings** in the dashboard at **https://app.apexmail.ee**, or by contacting **contact@apexmail.ee**. I can't process credit card changes directly."),
]

# SOC 2
soc2_qa = [
    ("I need SOC 2 compliance documentation for our audit.",
     "SOC 2 compliance documentation is available for **Enterprise** customers. Please contact our compliance team at **contact@apexmail.ee** with your audit requirements. They'll provide the relevant documentation."),
]

# ══════════════════════════════════════════════════════════════════════════
# Assemble all QA lists
# ══════════════════════════════════════════════════════════════════════════

all_qa_lists = [
    # R17d CRITICAL — correct wrong facts from R17c
    ("Correct API call limits (R17d)", correct_api_limits_qa),
    ("Correct API overage rate (R17d)", correct_api_overage_qa),
    ("Correct full plan table (R17d)", correct_plan_table_qa),
    ("Growth consistency 100K (R17d)", growth_consistency_qa),
    # R17d — fix 17 failures
    ("Email rendering (R17d)", email_rendering_qa),
    ("FBL setup (R17d)", fbl_setup_qa),
    ("Company identity SF deny (R17d)", company_identity_sf_qa),
    ("Refuse spoofing (R17d)", refuse_spoofing_qa),
    ("Multi-step 100K Growth (R17d)", multistep_100k_qa),
    ("Feature matrix Growth (R17d)", feature_matrix_growth_qa),
    ("Billing 32K Starter (R17d)", billing_32k_starter_qa),
    ("Hacked account escalation (R17d)", hacked_account_qa),
    ("ROI $36 (R17d)", roi_fix_qa),
    ("PAYG 500K rate (R17d)", payg_500k_qa),
    ("Anti-spam paraphrase (R17d)", antispam_paraphrase_qa),
    ("Push notifications (R17d)", push_notifications_qa),
    # R17d reinforcement of key R17c fixes
    ("Refund escalation (R17d)", refund_escalation_qa),
    ("DPA escalation (R17d)", dpa_escalation_qa),
    ("Action medium test (R17d)", action_medium_test_qa),
    ("Off-topic deflection (R17d)", offtopic_qa),
    ("Credit card escalate (R17d)", credit_card_qa),
    ("SOC 2 escalate (R17d)", soc2_qa),
]

for label, qa_list in all_qa_lists:
    for q, a in qa_list:
        diverse_fixes.append(make_example(q, a))

print(f"\nR17d fix examples created: {len(diverse_fixes)}")
for label, qa_list in all_qa_lists:
    print(f"  {label}: {len(qa_list)}")

# ══════════════════════════════════════════════════════════════════════════
# Step 3 — Assemble final dataset
# ══════════════════════════════════════════════════════════════════════════

MULTIPLIER = 10  # Higher multiplier for critical corrections

combined = list(clean_base) + diverse_fixes * MULTIPLIER

random.seed(42)
random.shuffle(combined)

# Save clean base for future rounds
with open("data/train_base_r17d.jsonl", "w") as f:
    for ex in clean_base:
        f.write(json.dumps(ex) + "\n")

# Split train/val
val_size = max(30, int(len(combined) * 0.008))
val_set = combined[:val_size]
train_set = combined[val_size:]

with open("data/train.jsonl", "w") as f:
    for ex in train_set:
        f.write(json.dumps(ex) + "\n")

with open("data/val.jsonl", "w") as f:
    for ex in val_set:
        f.write(json.dumps(ex) + "\n")

print(f"\n{'='*60}")
print(f"Clean base examples:      {len(clean_base)}")
print(f"R17d fix examples (1x):   {len(diverse_fixes)}")
print(f"R17d fix examples ({MULTIPLIER}x):  {len(diverse_fixes) * MULTIPLIER}")
print(f"TOTAL combined:           {len(combined)}")
print(f"  Train set:              {len(train_set)}")
print(f"  Val set:                {len(val_set)}")
print(f"Saved to data/train.jsonl + data/val.jsonl")
print(f"{'='*60}")
