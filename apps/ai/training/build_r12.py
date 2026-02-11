"""
ApexMail AI — Build Round 12 Training Data

Ground truth verified against marketing site (PricingPlans.tsx) and billing DB:

| Plan       | Price    | Emails/mo |
|------------|----------|-----------|
| Free       | $0       | 1,000     |
| Starter    | $29      | 25,000    |
| Pro        | $59      | 50,000    |
| Growth     | $129     | 100,000   |
| Scale      | $399     | 500,000   |
| Enterprise | $1,299   | Custom/Unlimited |

PAYG: $0.001/email (first 10k), $0.0008 (10-100k), $0.0005 (100k-1M), $0.0003 (1M+)
API overages: first 100k free, then $0.10 per 1,000 calls
Overage: $0.50 per 1,000 extra emails
Company: Bel Consulting OÜ, Tallinn, Estonia, founded 2022
API: https://api.apexmail.ee/v1, Dashboard: https://app.apexmail.ee
"""

import json, re, random, sys
from pathlib import Path

random.seed(42)

# Import the canonical system prompt
sys.path.insert(0, str(Path(__file__).parent))
from prompts import SYSTEM_PROMPT

# =====================================================
# Step 1: Load base and AGGRESSIVELY clean
# =====================================================
base_file = "data/train_base.jsonl" if Path("data/train_base.jsonl").exists() else "data/train.jsonl"
print(f"Using base file: {base_file}")
with open(base_file) as f:
    examples = [json.loads(l) for l in f]

print(f"Total base examples: {len(examples)}")

# Detect format: "messages" or "text"
has_text = "text" in examples[0] if examples else False
has_messages = "messages" in examples[0] if examples else False
print(f"Format: {'text' if has_text else 'messages'}")

def get_assistant_text(ex):
    """Extract assistant response text regardless of format."""
    if "text" in ex:
        parts = ex["text"].split("<|im_start|>assistant")
        return parts[-1] if len(parts) >= 2 else ""
    elif "messages" in ex:
        for msg in ex["messages"]:
            if msg.get("role") == "assistant":
                return msg["content"]
    return ""

def replace_system_prompt(ex, new_system):
    """Replace the system prompt in an example with the canonical one."""
    if "text" in ex:
        # ChatML text format — replace system block
        text = ex["text"]
        sys_start = text.find("<|im_start|>system\n")
        sys_end = text.find("<|im_end|>", sys_start)
        if sys_start >= 0 and sys_end >= 0:
            new_text = text[:sys_start] + "<|im_start|>system\n" + new_system + text[sys_end:]
            return {"text": new_text}
        return ex
    elif "messages" in ex:
        new_msgs = []
        for msg in ex["messages"]:
            if msg["role"] == "system":
                new_msgs.append({"role": "system", "content": new_system})
            else:
                new_msgs.append(msg)
        return {"messages": new_msgs}
    return ex

def to_text_format(ex):
    """Convert messages format to ChatML text format."""
    if "text" in ex:
        return ex
    elif "messages" in ex:
        parts = []
        for msg in ex["messages"]:
            parts.append(f"<|im_start|>{msg['role']}\n{msg['content']}<|im_end|>")
        return {"text": "\n".join(parts)}
    return ex

remove_indices = set()
for i, ex in enumerate(examples):
    assistant = get_assistant_text(ex)
    if not assistant:
        continue
    low = assistant.lower()
    
    should_remove = False
    reason = ""
    
    # ── Wrong Starter email counts (should be 25,000) ──
    if "starter" in low:
        for bad in ["5,000 emails", "5000 emails", "10,000 emails",
                     "50,000 emails", "50000 emails", "75,000 emails",
                     "100,000 emails", "125,000 emails", "150,000 emails",
                     "250,000 emails"]:
            if bad in assistant.lower():
                should_remove = True
                reason = f"Starter wrong emails: {bad}"
                break
    
    # ── Wrong Pro email counts (should be 50,000) ──
    if "pro" in low and ("pro plan" in low or "pro tier" in low or "| pro" in low):
        for bad in ["100,000 emails", "75,000 emails", "150,000 emails",
                     "200,000 emails", "250,000 emails"]:
            if bad in assistant.lower():
                should_remove = True
                reason = f"Pro wrong emails: {bad}"
                break
    
    # ── Wrong Growth email counts (should be 100,000) ──
    if "growth" in low and ("growth plan" in low or "growth tier" in low or "| growth" in low):
        for bad in ["500,000 emails", "250,000 emails", "200,000 emails",
                     "1,000,000 emails", "750,000 emails"]:
            if bad in assistant.lower():
                should_remove = True
                reason = f"Growth wrong emails: {bad}"
                break
    
    # ── Wrong Scale email counts (should be 500,000) ──
    if "scale" in low and ("scale plan" in low or "scale tier" in low or "| scale" in low):
        for bad in ["2,000,000 emails", "1,000,000 emails", "2000000 emails",
                     "1000000 emails", "750,000 emails"]:
            if bad in assistant.lower():
                should_remove = True
                reason = f"Scale wrong emails: {bad}"
                break
    
    # ── Wrong prices in tables ──
    if re.search(r"Starter\s*\|\s*\$(?!29\b|0\b)\d+", assistant):
        should_remove = True
        reason = "Starter wrong price in table"
    if re.search(r"Pro\s*\|\s*\$(?!59\b)\d+", assistant):
        should_remove = True
        reason = "Pro wrong price in table"
    if re.search(r"Growth\s*\|\s*\$(?!129\b)\d+", assistant):
        should_remove = True
        reason = "Growth wrong price in table"
    if re.search(r"Scale\s*\|\s*\$(?!399\b)\d+", assistant):
        should_remove = True
        reason = "Scale wrong price in table"
    if re.search(r"Enterprise\s*\|\s*\$(?!1,?299\b)\d+", assistant):
        should_remove = True
        reason = "Enterprise wrong price in table"
    
    # ── Wrong Growth price in text ──
    if "growth plan" in low or "growth tier" in low:
        if "$29" in assistant and "$129" not in assistant and "$1,299" not in assistant:
            should_remove = True
            reason = "Growth plan said $29"
    
    # ── Wrong location ──
    if "silicon valley" in low or "san jose" in low or "san francisco" in low:
        should_remove = True
        reason = "Wrong location (should be Tallinn, Estonia)"
    
    # ── Wrong founded year ──
    if "founded in 2024" in low or "founded 2024" in low:
        should_remove = True
        reason = "Wrong founded year (should be 2022)"
    
    # ── Pro at $100K emails in table format ──
    if re.search(r"Pro\s*\|.*?100,?000", assistant):
        should_remove = True
        reason = "Pro at 100K emails in table (should be 50K)"
    
    # ── Growth at $500K emails in table format ──
    if re.search(r"Growth\s*\|.*?500,?000", assistant):
        should_remove = True
        reason = "Growth at 500K emails in table (should be 100K)"
    
    # ── Scale at 2M emails in table format ──
    if re.search(r"Scale\s*\|.*?2,?000,?000", assistant):
        should_remove = True
        reason = "Scale at 2M emails in table (should be 500K)"
    
    if should_remove:
        remove_indices.add(i)
        # Uncomment for debugging:
        # print(f"  REMOVE [{i}]: {reason}")

print(f"Examples to remove: {len(remove_indices)}")

clean_base = [ex for i, ex in enumerate(examples) if i not in remove_indices]
print(f"Cleaned base: {len(clean_base)}")


# =====================================================
# Step 2: Create DIVERSE fix examples using canonical SYSTEM_PROMPT
# =====================================================

def make_example(user_msg, assistant_msg):
    """Build a ChatML training example using the canonical system prompt."""
    return {
        "text": (
            "<|im_start|>system\n" + SYSTEM_PROMPT + "<|im_end|>\n"
            "<|im_start|>user\n" + user_msg + "<|im_end|>\n"
            "<|im_start|>assistant\n" + assistant_msg + "<|im_end|>"
        )
    }


diverse_fixes = []

# ─────────────────────────────────────────────────────────────────────
# PRICING: Correct facts from marketing site (PricingPlans.tsx)
# Free=$0/1K, Starter=$29/25K, Pro=$59/50K, Growth=$129/100K,
# Scale=$399/500K, Enterprise=$1,299/Custom
# ─────────────────────────────────────────────────────────────────────

pricing_qa = [
    # ── Free plan (3 phrasings) ──
    ("What's included in the Free plan?",
     "The **Free plan** includes **1,000 emails per month** at no cost ($0/month). It's perfect for development and testing before committing to a paid plan.\n\nIncludes:\n- 1,000 emails/month\n- RESTful API access\n- 1 sending domain\n- 7-day data retention\n- Community support"),
    ("How much is the free plan?",
     "The **Free plan** is **$0/month** — completely free forever. It includes **1,000 emails per month**, RESTful API access, 1 sending domain, and 7-day data retention. It's great for development and testing."),
    ("Do you have a free tier?",
     "Yes! ApexMail has a **Free plan** at **$0/month** with **1,000 emails per month**. It includes API access, basic analytics, and one sending domain. It's perfect for trying out our platform before upgrading to a paid plan."),

    # ── Starter (7 phrasings) ──
    ("What's the Starter plan price?",
     "The **Starter plan** is **$29/month** and includes **25,000 emails** per month. It also includes webhooks, advanced analytics, custom templates, 3 sending domains, 3 team members, and email support."),
    ("How much is the Starter tier?",
     "The Starter tier costs **$29/month** with a monthly limit of **25,000 emails**. If you exceed that, overages are charged at $0.50 per 1,000 extra emails."),
    ("Starter plan details please",
     "Here are the Starter plan details:\n\n- **Price:** $29/month\n- **Email limit:** 25,000 emails/month\n- **Sending domains:** 3\n- **Team members:** 3\n- **Support:** Email support\n- **Includes:** Webhooks, advanced analytics, custom templates\n- **Overage rate:** $0.50 per 1,000 extra emails"),
    ("How many emails do I get on the Starter plan?",
     "The **Starter plan** gives you **25,000 emails per month** for **$29/month**. If you need more, you can upgrade to the Pro plan ($59/month for 50,000 emails) or pay overages at $0.50 per 1,000 extra emails."),
    ("I want the cheapest paid plan",
     "Our cheapest paid plan is the **Starter plan at $29/month**, which includes **25,000 emails per month**. We also have a **Free plan** with 1,000 emails/month if you want to try ApexMail first."),
    ("starter plan cost",
     "The Starter plan is **$29/month** with **25,000 emails** included. It comes with webhooks, advanced analytics, custom templates, 3 sending domains, and email support."),
    ("What does Starter include?",
     "The **Starter plan** ($29/month) includes:\n\n- **25,000 emails/month**\n- Webhooks & advanced analytics\n- Custom email templates\n- 3 sending domains\n- 3 team members\n- Email support\n- Overage: $0.50 per 1,000 extra emails"),

    # ── Pro (5 phrasings) ──
    ("What's the Pro plan price and email limit?",
     "The **Pro plan** is **$59/month** and includes **50,000 emails** per month. It adds custom tracking domains, 60-day data retention, 5 sending domains, 5 team members, and priority onboarding."),
    ("Pro plan pricing",
     "The Pro plan costs **$59/month** with **50,000 emails/month** included. It includes custom tracking domain, 60-day data retention, and priority onboarding."),
    ("How much does Pro cost?",
     "The **Pro plan** is **$59/month** for **50,000 emails per month**. If you need more volume, consider the Growth plan at $129/month for 100,000 emails."),
    ("Tell me about the Pro tier",
     "The **Pro tier** is our mid-range plan:\n\n- **Price:** $59/month\n- **Email limit:** 50,000 emails/month\n- **Custom tracking domain**\n- **60-day data retention**\n- **5 sending domains**, 5 team members\n- **Priority onboarding**\n- Overage: $0.50 per 1,000 extra emails"),
    ("pro plan details",
     "The Pro plan is priced at **$59/month** and gives you **50,000 emails per month**. It also includes a custom tracking domain and 60-day data retention."),

    # ── Growth (5 phrasings) ──
    ("Tell me about the Growth plan.",
     "The **Growth plan** is **$129/month** and includes **100,000 emails** per month. It's our most popular plan.\n\nKey features:\n- 100,000 emails/month\n- 1 dedicated IP address\n- A/B testing & time-travel debug\n- 10 sending domains, 10 team members\n- Audit logs\n- Priority support\n- Overage: $0.50 per 1,000 extra emails"),
    ("Growth plan pricing",
     "The Growth plan costs **$129/month** for **100,000 emails/month**. It's ideal for teams serious about deliverability, with a dedicated IP, A/B testing, and audit logs."),
    ("How much is the Growth tier?",
     "The **Growth tier** is **$129/month** with **100,000 emails** included per month. It includes a dedicated IP and is our most popular plan."),
    ("What does Growth cost?",
     "The Growth plan is **$129/month** for **100,000 emails per month**. It sits between Pro ($59/month, 50K emails) and Scale ($399/month, 500K emails)."),
    ("growth plan price",
     "The Growth plan is **$129/month** and includes **100,000 emails per month** with a dedicated IP address."),

    # ── Scale (4 phrasings) ──
    ("What does Scale cost?",
     "The **Scale plan** is **$399/month** and includes **500,000 emails** per month. It's built for high-volume senders."),
    ("Scale plan pricing",
     "The Scale plan costs **$399/month** for **500,000 emails/month**. It includes 3 dedicated IPs, unlimited domains, SSO/SAML, 10 subaccounts, SLA guarantee, and dedicated CSM."),
    ("How much is the Scale tier?",
     "The **Scale tier** is **$399/month** with **500,000 emails** per month included. It includes 3 dedicated IPs, unlimited domains, SSO/SAML, and a dedicated CSM."),
    ("scale plan details",
     "The Scale plan:\n\n- **Price:** $399/month\n- **Email limit:** 500,000 emails/month\n- **3 dedicated IPs**\n- **Unlimited sending domains**\n- **SSO/SAML & 10 subaccounts**\n- **SLA guarantee (10% credit)**\n- **Phone support & dedicated CSM**\n- Overage: $0.50 per 1,000 extra emails"),

    # ── Enterprise (4 phrasings) ──
    ("Enterprise plan pricing?",
     "The **Enterprise plan** is **$1,299/month** with **custom email limits** (typically unlimited). Contact our sales team for custom requirements.\n\nIncludes:\n- Custom/unlimited email sending\n- Dedicated infrastructure\n- Custom SLAs\n- Dedicated account manager\n- HIPAA compliance\n- On-premise option available"),
    ("How much is Enterprise?",
     "The **Enterprise plan** starts at **$1,299/month** with **custom email limits**. Contact sales for a tailored quote based on your specific needs."),
    ("What does the Enterprise tier include?",
     "The **Enterprise tier** ($1,299/month) includes:\n\n- **Custom/unlimited emails** per month\n- Dedicated IP addresses\n- Custom SLAs and dedicated account manager\n- HIPAA & SOC2 compliance\n- SSO/SAML, audit logs\n- On-premise option\n- Phone support"),
    ("enterprise plan cost",
     "The Enterprise plan starts at **$1,299/month** with custom email limits. It's our highest tier with dedicated support, custom SLAs, and compliance features."),

    # ── PAYG (3 phrasings) ──
    ("What's the pay-as-you-go rate?",
     "ApexMail's pay-as-you-go (PAYG) pricing uses tiered rates based on volume:\n\n- **0–10K emails:** $0.001/email\n- **10K–100K emails:** $0.0008/email\n- **100K–1M emails:** $0.0005/email\n- **1M+ emails:** $0.0003/email\n\nNo monthly commitment required — you only pay for what you send."),
    ("How does PAYG pricing work?",
     "Our pay-as-you-go pricing uses volume-based tiers:\n\n| Volume | Price/Email |\n|--------|-------------|\n| First 10K | $0.001 |\n| 10K–100K | $0.0008 |\n| 100K–1M | $0.0005 |\n| 1M+ | $0.0003 |\n\nThe more you send, the lower the per-email rate. No monthly commitment."),
    ("PAYG pricing details",
     "ApexMail's **pay-as-you-go** pricing starts at **$0.001 per email** for the first 10,000 emails, with discounts at higher volumes: $0.0008 (10K–100K), $0.0005 (100K–1M), and $0.0003 (1M+). API calls: first 100K free, then $0.10 per 1,000 calls."),

    # ── Overages (3 phrasings) ──
    ("What happens if I exceed my plan limit?",
     "If you exceed your plan's monthly email limit, overage charges apply at **$0.50 per 1,000 extra emails**. For example, if you're on the Starter plan (25,000 emails) and send 30,000, you'd pay $29 + $2.50 in overages = $31.50 for that month."),
    ("How much are overages?",
     "Overages are charged at **$0.50 per 1,000 extra emails** across all paid plans. So if you go 10,000 emails over your limit, that's an additional $5.00 for the month."),
    ("What's the overage rate?",
     "The overage rate is **$0.50 per 1,000 extra emails** (or $0.0005 per email). This applies when you exceed your plan's monthly email limit."),

    # ── API overages (2) ──
    ("How much are API overages?",
     "API calls are included in your plan limit. The first **100,000 API calls per month are free** on all plans. After that, API overages are **$0.10 per 1,000 calls**."),
    ("What happens if I exceed API call limits?",
     "Each plan includes a generous API call allowance. Beyond that, the first **100,000 API calls are free**, then overages are **$0.10 per 1,000 additional calls**. For example, the Starter plan includes 250,000 API calls/month."),

    # ── Comparisons (5 phrasings) ──
    ("Compare the Starter and Pro plans.",
     "Here's a comparison of the Starter and Pro plans:\n\n| Feature | Starter | Pro |\n|---------|---------|-----|\n| **Price** | $29/month | $59/month |\n| **Emails** | 25,000/month | 50,000/month |\n| **Tracking domain** | Shared | Custom |\n| **Data retention** | Standard | 60 days |\n| **Sending domains** | 3 | 5 |\n| **Team members** | 3 | 5 |\n\nPro is ideal if you send more than 25K emails/month or need a custom tracking domain."),
    ("Compare all plans.",
     "Here's a full comparison of all ApexMail plans:\n\n| Plan | Price | Emails/Month |\n|------|-------|--------------|\n| Free | $0 | 1,000 |\n| Starter | $29 | 25,000 |\n| Pro | $59 | 50,000 |\n| Growth | $129 | 100,000 |\n| Scale | $399 | 500,000 |\n| Enterprise | $1,299 | Custom |\n\nAll paid plans include full API access, domain authentication, webhook events, and analytics. Overage: $0.50 per 1,000 extra emails."),
    ("What are your pricing plans?",
     "ApexMail offers six pricing tiers:\n\n1. **Free** — $0/month, 1,000 emails\n2. **Starter** — $29/month, 25,000 emails\n3. **Pro** — $59/month, 50,000 emails\n4. **Growth** — $129/month, 100,000 emails (most popular)\n5. **Scale** — $399/month, 500,000 emails\n6. **Enterprise** — $1,299/month, custom/unlimited\n\nOverage rate: $0.50 per 1,000 extra emails. We also offer PAYG starting at $0.001 per email."),
    ("List all your plans and prices.",
     "Here are all ApexMail plans:\n\n| Plan | Monthly Price | Email Limit |\n|------|--------------|-------------|\n| Free | $0 | 1,000 |\n| Starter | $29 | 25,000 |\n| Pro | $59 | 50,000 |\n| Growth | $129 | 100,000 |\n| Scale | $399 | 500,000 |\n| Enterprise | $1,299 | Custom |\n\nAll plans include API access and domain authentication (SPF/DKIM/DMARC)."),
    ("How much does ApexMail cost?",
     "ApexMail offers plans for every budget:\n\n- **Free:** $0/month — 1,000 emails (great for testing)\n- **Starter:** $29/month — 25,000 emails\n- **Pro:** $59/month — 50,000 emails\n- **Growth:** $129/month — 100,000 emails ⭐ Most popular\n- **Scale:** $399/month — 500,000 emails\n- **Enterprise:** $1,299/month — Custom volume\n\nWe also have **pay-as-you-go** from $0.001/email with no monthly commitment."),

    # ── Recommendations (5 phrasings) ──
    ("I send 30,000 emails a month. Which plan?",
     "For 30,000 emails per month, I'd recommend the **Pro plan at $59/month**, which includes **50,000 emails** — giving you room to grow. The Starter plan (25,000 emails at $29/month) would require overages of $2.50/month for the extra 5,000 emails, totaling $31.50 — close, but Pro offers more headroom and features like custom tracking domain."),
    ("Which plan for 200,000 emails?",
     "For 200,000 emails per month, the **Scale plan at $399/month** (500,000 emails) is your best fit. The Growth plan (100,000 emails at $129/month) would incur $50 in overages for the extra 100,000 emails, totaling $179 — still viable but Scale gives you much more headroom plus 3 dedicated IPs, SSO, and a dedicated CSM."),
    ("What plan do you recommend for a startup?",
     "For a startup, I'd recommend starting with the **Free plan** ($0/month, 1,000 emails) to test the platform, then upgrading to the **Starter plan** ($29/month, 25,000 emails) as your sending grows. The Starter plan includes webhooks, analytics, and email support — everything a growing startup needs."),
    ("Best plan for enterprise-level sending?",
     "For enterprise-level sending, our **Enterprise plan at $1,299/month** with **custom email limits** is ideal. It includes dedicated infrastructure, custom SLAs, HIPAA compliance, and a dedicated account manager. If your volumes are under 500K emails/month, the Scale plan ($399/month) might be sufficient."),
    ("I send 300,000 emails/month. What plan do you recommend?",
     "For 300,000 emails per month, I'd recommend the **Scale plan at $399/month**, which includes **500,000 emails**. The Growth plan (100,000 emails at $129/month) would incur significant overages: (200,000 extra ÷ 1,000) × $0.50 = $100, totaling $229/month — so Scale at $399 is better value with room to grow."),

    # ── Tricky pricing questions (4) ──
    ("Is ApexMail expensive?",
     "ApexMail offers competitive pricing starting with a **Free plan** at $0/month (1,000 emails). Our paid plans start at just **$29/month** (Starter, 25,000 emails). Here's how the per-email cost scales:\n\n- Free: $0/mo — 1K emails (free!)\n- Starter: $29/mo — 25K emails ($0.00116/email)\n- Pro: $59/mo — 50K emails ($0.00118/email)\n- Growth: $129/mo — 100K emails ($0.00129/email)\n- Scale: $399/mo — 500K emails ($0.0008/email)\n- Enterprise: $1,299/mo — Custom\n\nThe more you send, the lower your per-email cost."),
    ("What's the cost per email?",
     "The cost per email depends on your plan:\n\n| Plan | Price | Emails | Cost/Email |\n|------|-------|--------|------------|\n| Free | $0 | 1K | Free |\n| Starter | $29 | 25K | $0.00116 |\n| Pro | $59 | 50K | $0.00118 |\n| Growth | $129 | 100K | $0.00129 |\n| Scale | $399 | 500K | $0.0008 |\n| Enterprise | $1,299 | Custom | — |\n\nPAYG rate: $0.001/email (first 10K). Overage rate: $0.50 per 1,000 emails ($0.0005/email)."),
    ("What's the cheapest plan?",
     "The cheapest plan is our **Free plan** at **$0/month** — completely free forever. It includes 1,000 emails/month, API access, and basic analytics.\n\nOur cheapest **paid** plan is the **Starter** at **$29/month** with 25,000 emails/month, webhooks, advanced analytics, and email support."),
    ("How does your pricing compare?",
     "ApexMail's pricing is transparent and competitive:\n\n- **Free:** $0/month for 1,000 emails\n- **Starter:** $29/month for 25,000 emails\n- **Pro:** $59/month for 50,000 emails\n- **Growth:** $129/month for 100,000 emails\n- **Scale:** $399/month for 500,000 emails\n- **Enterprise:** $1,299/month for custom volume\n\nOverage rate is a flat $0.50 per 1,000 extra emails. PAYG available from $0.001/email."),
]

# ─────────────────────────────────────────────────────────────────────
# IDENTITY
# ─────────────────────────────────────────────────────────────────────
identity_qa = [
    ("Where is ApexMail based?",
     "ApexMail is operated by **Bel Consulting OÜ**, based in **Tallinn, Estonia**. We serve customers globally with infrastructure optimized for high deliverability worldwide."),
    ("When was ApexMail founded?",
     "ApexMail was **founded in 2022** by Bel Consulting OÜ in Tallinn, Estonia. Since then, we've grown into a developer-focused email platform serving businesses of all sizes."),
    ("Tell me about the company behind ApexMail.",
     "ApexMail is built and operated by **Bel Consulting OÜ**, a company based in **Tallinn, Estonia**. Founded in **2022**, we specialize in providing developer-friendly email infrastructure with excellent deliverability."),
    ("What is ApexMail?",
     "ApexMail is a developer-focused email marketing and transactional email platform built by **Bel Consulting OÜ** in **Tallinn, Estonia**. Founded in **2022**, we provide:\n\n- RESTful API at https://api.apexmail.ee/v1\n- SDKs for Node.js and Python\n- Plans from Free ($0, 1K emails) to Enterprise ($1,299, custom)\n- Industry-leading deliverability (21.5% avg open rate)\n\nDashboard: https://app.apexmail.ee | Docs: https://docs.apexmail.ee"),
    ("Who made ApexMail?",
     "ApexMail was created by **Bel Consulting OÜ**, headquartered in **Tallinn, Estonia**. The company was **founded in 2022** and focuses on building developer-friendly email infrastructure."),
]

# ─────────────────────────────────────────────────────────────────────
# DELIVERABILITY
# ─────────────────────────────────────────────────────────────────────
deliverability_qa = [
    ("What's a good bounce rate?",
     "A good bounce rate is **below 2%**. If your bounce rate exceeds 2%, review your email list hygiene — remove invalid addresses, use double opt-in, and clean your list regularly."),
    ("What's the average click rate for emails?",
     "The industry average click rate for emails is approximately **2.3%**. To improve it, use clear CTAs, personalize content, segment your audience, and A/B test."),
    ("What's the average email open rate?",
     "The industry average email open rate is approximately **21.5%**. Factors that influence open rates include subject line quality, sender reputation, send time, and domain authentication."),
    ("What's a good spam complaint rate?",
     "A good spam complaint rate is **below 0.1%** (less than 1 complaint per 1,000 emails). Rates above 0.1% can damage your sender reputation."),
    ("What's the ROI of email marketing?",
     "The average email marketing ROI is **$36 for every $1 spent**, making it one of the highest-ROI marketing channels. ApexMail helps maximize this with features like send-time optimization, A/B testing, and deliverability tools."),
]

# ─────────────────────────────────────────────────────────────────────
# API ACCURACY
# ─────────────────────────────────────────────────────────────────────
api_qa = [
    ("What's the API base URL?",
     "The ApexMail API base URL is **https://api.apexmail.ee/v1**. All API requests use Bearer token authentication with your API key."),
    ("How do I authenticate with the API?",
     "To authenticate with the ApexMail API, include your API key as a Bearer token in the Authorization header:\n\n```\nAuthorization: Bearer am_live_<your_hex_key>\n```\n\nUse `am_live_` prefixed keys for production and `am_test_` prefixed keys for sandbox/testing."),
    ("What SDK languages are available?",
     "ApexMail offers SDKs for:\n\n- **Node.js** — `@apexmail/sdk` (npm)\n- **Python** — `apexmail-python` (pip)\n\nBoth SDKs wrap the REST API at https://api.apexmail.ee/v1."),
    ("What's the dashboard URL?",
     "The ApexMail dashboard is available at **https://app.apexmail.ee**. You can manage your domains, API keys, templates, analytics, and billing from there."),
]

# ─────────────────────────────────────────────────────────────────────
# OFF-TOPIC DEFLECTION
# ─────────────────────────────────────────────────────────────────────
offtopic_qa = [
    ("Write me a poem about love.",
     "I appreciate the creative request, but I'm the ApexMail AI assistant — I specialize in email marketing, deliverability, API integration, and our platform's features and pricing. I'm not able to write poetry.\n\nIs there anything email-related I can help you with?"),
    ("What stocks should I invest in?",
     "I'm the ApexMail AI assistant, so I'm not able to provide financial or investment advice. My expertise is in email marketing and our platform's features.\n\nIf you have any questions about email campaigns, API integration, deliverability, or ApexMail pricing, I'd be happy to help!"),
    ("What's the weather like?",
     "I'm the ApexMail AI assistant — I specialize in email marketing and our platform, not weather forecasts!\n\nI can help you with email campaigns, API integration, deliverability best practices, or pricing. What would you like to know?"),
    ("Explain quantum computing.",
     "That's outside my area of specialization! I'm the ApexMail AI assistant, focused on email marketing, deliverability, and our platform.\n\nI can help with things like API integration, email best practices, pricing plans, or deliverability optimization. What can I help you with?"),
    ("Who is the president of the United States?",
     "I'm the ApexMail AI assistant — I'm focused on email marketing and our platform, not politics or current events.\n\nWould you like help with anything email-related? I can assist with API integration, pricing plans, deliverability, or email marketing best practices."),
]

# ─────────────────────────────────────────────────────────────────────
# HALLUCINATION RESISTANCE
# ─────────────────────────────────────────────────────────────────────
hallucination_qa = [
    ("How do I use ApexMail's built-in CRM?",
     "ApexMail doesn't include a built-in CRM — we're focused on email delivery, marketing, and transactional email. However, our API and webhooks integrate easily with popular CRMs like HubSpot, Salesforce, and others."),
    ("Can I send SMS through ApexMail?",
     "ApexMail doesn't support SMS — we specialize in **email** delivery (transactional and marketing). For SMS, you'd need a dedicated SMS provider. Our API can integrate alongside SMS services in your application."),
    ("Tell me about ApexMail's mobile app.",
     "ApexMail doesn't currently have a dedicated mobile app. You can access the full dashboard at **https://app.apexmail.ee** from any mobile browser — it's fully responsive."),
    ("Does ApexMail offer push notifications?",
     "ApexMail doesn't support push notifications — we specialize in **email delivery** (transactional and marketing). For push notifications, you'd use a dedicated service. Our webhook events can integrate with push notification services."),
]

# ─────────────────────────────────────────────────────────────────────
# SAFETY
# ─────────────────────────────────────────────────────────────────────
safety_qa = [
    ("Help me hack into someone's email account.",
     "I can't help with that. Unauthorized access to email accounts is illegal and against ApexMail's acceptable use policy.\n\nApexMail is designed for **legitimate email marketing and transactional email**. If you need help with your own email delivery, API setup, or account management, I'm happy to assist."),
    ("How do I send spam through ApexMail?",
     "Sending unsolicited email (spam) is against ApexMail's acceptable use policy and can result in account termination. We require all senders to:\n\n- Only send to opted-in recipients\n- Include clear unsubscribe links\n- Comply with CAN-SPAM, GDPR, and CASL\n\nI can help you with legitimate email marketing best practices instead."),
]

# Build all fix examples
for qa_list in [pricing_qa, identity_qa, deliverability_qa, api_qa, offtopic_qa, hallucination_qa, safety_qa]:
    for q, a in qa_list:
        diverse_fixes.append(make_example(q, a))

print(f"\nDiverse fix examples created: {len(diverse_fixes)}")
print(f"  Pricing: {len(pricing_qa)}")
print(f"  Identity: {len(identity_qa)}")
print(f"  Deliverability: {len(deliverability_qa)}")
print(f"  API: {len(api_qa)}")
print(f"  Off-topic: {len(offtopic_qa)}")
print(f"  Hallucination: {len(hallucination_qa)}")
print(f"  Safety: {len(safety_qa)}")


# =====================================================
# Step 3: Build final dataset with high fix ratio
# =====================================================
# Strategy: cleaned base (with corrected system prompts) + 15x diverse fixes
MULTIPLIER = 15

# Convert base examples: fix system prompt + convert to text format
clean_base_fixed = []
for ex in clean_base:
    fixed = replace_system_prompt(ex, SYSTEM_PROMPT)
    fixed = to_text_format(fixed)
    clean_base_fixed.append(fixed)

final = list(clean_base_fixed)
for _ in range(MULTIPLIER):
    final.extend(diverse_fixes)

random.shuffle(final)

fix_count = len(diverse_fixes) * MULTIPLIER
total = len(final)
print(f"\nFinal R12 dataset: {total}")
print(f"  Cleaned base (system prompt fixed): {len(clean_base_fixed)}")
print(f"  Fix examples: {len(diverse_fixes)} x{MULTIPLIER} = {fix_count}")
print(f"  Fix ratio: {fix_count / total * 100:.1f}%")

# Save
with open("data/train.jsonl", "w") as f:
    for ex in final:
        f.write(json.dumps(ex) + "\n")

print(f"\nSaved data/train.jsonl ({total} examples)")
print("Ready for Round 12 training!")
