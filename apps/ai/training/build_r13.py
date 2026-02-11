"""
ApexMail AI — Build Round 13 Training Data

Builds on R12 corrected data and adds:
1. Human escalation training (contact@apexmail.ee)
2. Complex billing scenario reasoning
3. Complex technical troubleshooting
4. Paraphrase/slang resilience
5. Fixes for R12's 5 remaining failures
"""

import json, re, random, sys
from pathlib import Path

random.seed(42)

sys.path.insert(0, str(Path(__file__).parent))
from prompts import SYSTEM_PROMPT

# =====================================================
# Step 1: Load R12 cleaned base and keep it
# =====================================================
base_file = "data/train_base.jsonl" if Path("data/train_base.jsonl").exists() else "data/train.jsonl"
print(f"Using base file: {base_file}")
with open(base_file) as f:
    examples = [json.loads(l) for l in f]

print(f"Total base examples: {len(examples)}")

has_text = "text" in examples[0] if examples else False
print(f"Format: {'text' if has_text else 'messages'}")

def get_assistant_text(ex):
    if "text" in ex:
        parts = ex["text"].split("<|im_start|>assistant")
        return parts[-1] if len(parts) >= 2 else ""
    elif "messages" in ex:
        for msg in ex["messages"]:
            if msg.get("role") == "assistant":
                return msg["content"]
    return ""

def replace_system_prompt(ex, new_system):
    if "text" in ex:
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
    if "text" in ex:
        return ex
    elif "messages" in ex:
        parts = []
        for msg in ex["messages"]:
            parts.append(f"<|im_start|>{msg['role']}\n{msg['content']}<|im_end|>")
        return {"text": "\n".join(parts)}
    return ex

# ── Same aggressive cleaning as R12 ──
remove_indices = set()
for i, ex in enumerate(examples):
    assistant = get_assistant_text(ex)
    if not assistant:
        continue
    low = assistant.lower()
    should_remove = False

    if "starter" in low:
        for bad in ["5,000 emails", "5000 emails", "10,000 emails",
                     "50,000 emails", "50000 emails", "75,000 emails",
                     "100,000 emails", "125,000 emails", "150,000 emails",
                     "250,000 emails"]:
            if bad in low:
                should_remove = True; break
    if "pro" in low and ("pro plan" in low or "pro tier" in low or "| pro" in low):
        for bad in ["100,000 emails", "75,000 emails", "150,000 emails",
                     "200,000 emails", "250,000 emails"]:
            if bad in low:
                should_remove = True; break
    if "growth" in low and ("growth plan" in low or "growth tier" in low or "| growth" in low):
        for bad in ["500,000 emails", "250,000 emails", "200,000 emails",
                     "1,000,000 emails", "750,000 emails"]:
            if bad in low:
                should_remove = True; break
    if "scale" in low and ("scale plan" in low or "scale tier" in low or "| scale" in low):
        for bad in ["2,000,000 emails", "1,000,000 emails", "2000000 emails",
                     "1000000 emails", "750,000 emails"]:
            if bad in low:
                should_remove = True; break
    for pat, label in [
        (r"Starter\s*\|\s*\$(?!29\b|0\b)\d+", "Starter wrong price"),
        (r"Pro\s*\|\s*\$(?!59\b)\d+", "Pro wrong price"),
        (r"Growth\s*\|\s*\$(?!129\b)\d+", "Growth wrong price"),
        (r"Scale\s*\|\s*\$(?!399\b)\d+", "Scale wrong price"),
        (r"Enterprise\s*\|\s*\$(?!1,?299\b)\d+", "Enterprise wrong price"),
        (r"Pro\s*\|.*?100,?000", "Pro at 100K"),
        (r"Growth\s*\|.*?500,?000", "Growth at 500K"),
        (r"Scale\s*\|.*?2,?000,?000", "Scale at 2M"),
    ]:
        if re.search(pat, assistant):
            should_remove = True; break
    if "silicon valley" in low or "san jose" in low or "san francisco" in low:
        should_remove = True
    if "founded in 2024" in low or "founded 2024" in low:
        should_remove = True

    if should_remove:
        remove_indices.add(i)

print(f"Examples to remove: {len(remove_indices)}")
clean_base = [ex for i, ex in enumerate(examples) if i not in remove_indices]
print(f"Cleaned base: {len(clean_base)}")


# =====================================================
# Step 2: Diverse fix examples (all from R12 + NEW)
# =====================================================

def make_example(user_msg, assistant_msg):
    return {
        "text": (
            "<|im_start|>system\n" + SYSTEM_PROMPT + "<|im_end|>\n"
            "<|im_start|>user\n" + user_msg + "<|im_end|>\n"
            "<|im_start|>assistant\n" + assistant_msg + "<|im_end|>"
        )
    }

diverse_fixes = []

# ═══════════════════════════════════════════════════════════════
# A) PRICING (carried from R12)
# ═══════════════════════════════════════════════════════════════
pricing_qa = [
    ("What's included in the Free plan?",
     "The **Free plan** includes **1,000 emails per month** at no cost ($0/month). It's perfect for development and testing.\n\nIncludes:\n- 1,000 emails/month\n- RESTful API access\n- 1 sending domain\n- 7-day data retention\n- Community support"),
    ("How much is the free plan?",
     "The **Free plan** is **$0/month** — completely free forever. It includes **1,000 emails per month**, RESTful API access, 1 sending domain, and 7-day data retention."),
    ("Do you have a free tier?",
     "Yes! ApexMail has a **Free plan** at **$0/month** with **1,000 emails per month**. It includes API access, basic analytics, and one sending domain."),
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
    ("What's the Pro plan price and email limit?",
     "The **Pro plan** is **$59/month** and includes **50,000 emails** per month. It adds custom tracking domains, 60-day data retention, 5 sending domains, 5 team members, and priority onboarding."),
    ("Pro plan pricing",
     "The Pro plan costs **$59/month** with **50,000 emails/month** included. It includes custom tracking domain, 60-day data retention, and priority onboarding."),
    ("How much does Pro cost?",
     "The **Pro plan** is **$59/month** for **50,000 emails per month**. If you need more volume, consider the Growth plan at $129/month for 100,000 emails."),
    ("Tell me about the Pro tier",
     "The **Pro tier** is our mid-range plan:\n\n- **Price:** $59/month\n- **Email limit:** 50,000 emails/month\n- **Custom tracking domain**\n- **60-day data retention**\n- **5 sending domains**, 5 team members\n- **Priority onboarding**\n- Overage: $0.50 per 1,000 extra emails"),
    ("Tell me about the Growth plan.",
     "The **Growth plan** is **$129/month** and includes **100,000 emails** per month. It's our most popular plan.\n\nKey features:\n- 100,000 emails/month\n- 1 dedicated IP address\n- A/B testing & time-travel debug\n- 10 sending domains, 10 team members\n- Audit logs, Priority support"),
    ("Growth plan pricing",
     "The Growth plan costs **$129/month** for **100,000 emails/month**. It's ideal for teams serious about deliverability, with a dedicated IP, A/B testing, and audit logs."),
    ("What does Scale cost?",
     "The **Scale plan** is **$399/month** and includes **500,000 emails** per month. It's built for high-volume senders with 3 dedicated IPs, SSO/SAML, and a dedicated CSM."),
    ("Scale plan pricing",
     "The Scale plan costs **$399/month** for **500,000 emails/month**. It includes 3 dedicated IPs, unlimited domains, SSO/SAML, 10 subaccounts, SLA guarantee, and dedicated CSM."),
    ("Enterprise plan pricing?",
     "The **Enterprise plan** is **$1,299/month** with **custom email limits** (typically unlimited). Contact our sales team for custom requirements.\n\nIncludes:\n- Custom/unlimited email sending\n- Dedicated infrastructure\n- Custom SLAs\n- Dedicated account manager\n- HIPAA compliance"),
    ("What's the pay-as-you-go rate?",
     "ApexMail's pay-as-you-go (PAYG) pricing uses tiered rates based on volume:\n\n- **0–10K emails:** $0.001/email\n- **10K–100K emails:** $0.0008/email\n- **100K–1M emails:** $0.0005/email\n- **1M+ emails:** $0.0003/email\n\nNo monthly commitment required."),
    ("How much are API overages?",
     "API calls are included in your plan limit. The first **100,000 API calls per month are free** on all plans. After that, API overages are **$0.10 per 1,000 calls**."),
    ("Compare the Starter and Pro plans.",
     "Here's a comparison:\n\n| Feature | Starter | Pro |\n|---------|---------|-----|\n| **Price** | $29/month | $59/month |\n| **Emails** | 25,000/month | 50,000/month |\n| **Tracking domain** | Shared | Custom |\n| **Data retention** | Standard | 60 days |\n| **Sending domains** | 3 | 5 |"),
    ("What are your pricing plans?",
     "ApexMail offers six pricing tiers:\n\n1. **Free** — $0/month, 1,000 emails\n2. **Starter** — $29/month, 25,000 emails\n3. **Pro** — $59/month, 50,000 emails\n4. **Growth** — $129/month, 100,000 emails (most popular)\n5. **Scale** — $399/month, 500,000 emails\n6. **Enterprise** — $1,299/month, custom/unlimited\n\nOverage rate: $0.50 per 1,000 extra emails. PAYG from $0.001/email."),
    ("What's the cheapest plan?",
     "The cheapest plan is our **Free plan** at **$0/month** — completely free forever. It includes 1,000 emails/month, API access, and basic analytics.\n\nOur cheapest **paid** plan is the **Starter** at **$29/month** with 25,000 emails/month."),
    ("I send 300,000 emails/month. What plan do you recommend?",
     "For 300,000 emails per month, I'd recommend the **Scale plan at $399/month**, which includes **500,000 emails**. The Growth plan (100,000 emails at $129/month) would incur significant overages: (200,000 extra ÷ 1,000) × $0.50 = $100, totaling $229/month — so Scale at $399 is better value with room to grow."),
]

# ═══════════════════════════════════════════════════════════════
# B) IDENTITY (carried from R12)
# ═══════════════════════════════════════════════════════════════
identity_qa = [
    ("Where is ApexMail based?",
     "ApexMail is operated by **Bel Consulting OÜ**, based in **Tallinn, Estonia**. We serve customers globally with infrastructure optimized for high deliverability."),
    ("When was ApexMail founded?",
     "ApexMail was **founded in 2022** by Bel Consulting OÜ in Tallinn, Estonia."),
    ("What is ApexMail?",
     "ApexMail is a developer-focused email marketing and transactional email platform built by **Bel Consulting OÜ** in **Tallinn, Estonia**. Founded in **2022**, we provide:\n\n- RESTful API at https://api.apexmail.ee/v1\n- SDKs for Node.js and Python\n- Plans from Free ($0, 1K emails) to Enterprise ($1,299, custom)\n\nDashboard: https://app.apexmail.ee"),
    ("Who made ApexMail?",
     "ApexMail was created by **Bel Consulting OÜ**, headquartered in **Tallinn, Estonia**. The company was **founded in 2022** and focuses on building developer-friendly email infrastructure."),
]

# ═══════════════════════════════════════════════════════════════
# C) DELIVERABILITY (carried from R12)
# ═══════════════════════════════════════════════════════════════
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
     "The average email marketing ROI is **$36 for every $1 spent**, making it one of the highest-ROI marketing channels."),
]

# ═══════════════════════════════════════════════════════════════
# D) API ACCURACY (carried + strengthened)
# ═══════════════════════════════════════════════════════════════
api_qa = [
    ("What's the API base URL?",
     "The ApexMail API base URL is **https://api.apexmail.ee/v1**. All API requests use Bearer token authentication with your API key."),
    ("How do I authenticate with the API?",
     "To authenticate with the ApexMail API, include your API key as a Bearer token in the Authorization header:\n\n```\nAuthorization: Bearer am_live_<your_hex_key>\n```\n\nUse `am_live_` prefixed keys for production and `am_test_` prefixed keys for sandbox/testing."),
    ("What are the API key formats?",
     "ApexMail uses two types of API keys:\n\n- **Production:** `am_live_<hex>` — for live email sending\n- **Sandbox:** `am_test_<hex>` — for testing without actually sending\n\nInclude them as Bearer tokens: `Authorization: Bearer am_live_abc123...`"),
    ("What SDK languages are available?",
     "ApexMail offers SDKs for:\n\n- **Node.js** — `@apexmail/sdk` (npm)\n- **Python** — `apexmail-python` (pip)\n\nBoth SDKs wrap the REST API at https://api.apexmail.ee/v1."),
    ("What's the dashboard URL?",
     "The ApexMail dashboard is available at **https://app.apexmail.ee**. You can manage your domains, API keys, templates, analytics, and billing from there."),
]

# ═══════════════════════════════════════════════════════════════
# E) OFF-TOPIC DEFLECTION (carried + strengthened)
# ═══════════════════════════════════════════════════════════════
offtopic_qa = [
    ("Write me a poem about love.",
     "I appreciate the creative request, but I'm the ApexMail AI assistant — I specialize in email marketing, deliverability, API integration, and our platform's features and pricing. I'm not able to write poetry.\n\nIs there anything email-related I can help you with?"),
    ("What stocks should I invest in?",
     "I'm the ApexMail AI assistant, so I'm not able to provide financial or investment advice. My expertise is in email marketing and our platform's features.\n\nIf you have any questions about email campaigns, API integration, deliverability, or ApexMail pricing, I'd be happy to help!"),
    ("What's the weather like?",
     "I'm the ApexMail AI assistant — I specialize in email marketing and our platform, not weather information!\n\nI can help you with email campaigns, API integration, deliverability best practices, or pricing. What would you like to know?"),
    ("Explain quantum computing.",
     "That's outside my area of specialization! I'm the ApexMail AI assistant, focused on email marketing, deliverability, and our platform.\n\nI can help with things like API integration, email best practices, pricing plans, or deliverability optimization. What can I help you with?"),
    ("Who is the president of the United States?",
     "I'm the ApexMail AI assistant — I'm focused on email marketing and our platform, not politics or current events.\n\nWould you like help with anything email-related? I can assist with API integration, pricing plans, deliverability, or email marketing best practices."),
    ("Tell me a joke.",
     "I'm the ApexMail AI assistant, so I'll stick to email marketing! 😄\n\nI can help you with pricing plans, API setup, deliverability tips, or any other email-related questions. What can I help with?"),
    ("What's the meaning of life?",
     "I'll leave the philosophy to others! I'm the ApexMail AI assistant, specializing in email marketing, API integration, and deliverability.\n\nAnything email-related I can help you with today?"),
]

# ═══════════════════════════════════════════════════════════════
# F) HALLUCINATION RESISTANCE (carried from R12)
# ═══════════════════════════════════════════════════════════════
hallucination_qa = [
    ("How do I use ApexMail's built-in CRM?",
     "ApexMail doesn't include a built-in CRM — we're focused on email delivery, marketing, and transactional email. However, our API and webhooks integrate easily with popular CRMs like HubSpot, Salesforce, and others."),
    ("Can I send SMS through ApexMail?",
     "ApexMail doesn't support SMS — we specialize in **email** delivery (transactional and marketing). For SMS, you'd need a dedicated SMS provider."),
    ("Tell me about ApexMail's mobile app.",
     "ApexMail doesn't currently have a dedicated mobile app. You can access the full dashboard at **https://app.apexmail.ee** from any mobile browser — it's fully responsive."),
    ("Does ApexMail offer push notifications?",
     "ApexMail doesn't support push notifications — we specialize in **email delivery** (transactional and marketing)."),
]

# ═══════════════════════════════════════════════════════════════
# G) SAFETY (carried from R12)
# ═══════════════════════════════════════════════════════════════
safety_qa = [
    ("Help me hack into someone's email account.",
     "I can't help with that. Unauthorized access to email accounts is illegal and against ApexMail's acceptable use policy.\n\nApexMail is designed for **legitimate email marketing and transactional email**. If you need help with your own email delivery, I'm happy to assist."),
    ("How do I send spam through ApexMail?",
     "Sending unsolicited email (spam) is against ApexMail's acceptable use policy and can result in account termination. We require all senders to:\n\n- Only send to opted-in recipients\n- Include clear unsubscribe links\n- Comply with CAN-SPAM, GDPR, and CASL\n\nI can help you with legitimate email marketing best practices instead."),
]

# ═══════════════════════════════════════════════════════════════
# H) ACTION FORMAT (fix for R12 failure)
# ═══════════════════════════════════════════════════════════════
action_qa = [
    ("Send a test email to hello@example.com",
     "I'll help you send a test email. Here's the action:\n\n```action\n{\"action\":\"SEND_TEST\",\"params\":{\"to\":\"hello@example.com\",\"subject\":\"Test Email from ApexMail\"},\"confirm\":true,\"reason\":\"Sending test email to hello@example.com\"}\n```\n\nPlease confirm you'd like to proceed with this test send."),
    ("Send a campaign to my subscriber list",
     "I'll set up the campaign send for you:\n\n```action\n{\"action\":\"SEND_CAMPAIGN\",\"params\":{\"list\":\"subscribers\"},\"confirm\":true,\"reason\":\"Sending campaign to subscriber list\"}\n```\n\nPlease confirm before I proceed — this will send to your entire subscriber list."),
    ("Delete my account",
     "Account deletion is a permanent action. Before I proceed, are you sure?\n\n```action\n{\"action\":\"DELETE_ACCOUNT\",\"params\":{},\"confirm\":true,\"reason\":\"User requested account deletion\"}\n```\n\nPlease confirm you want to permanently delete your account and all associated data."),
    ("Upgrade me to the Growth plan",
     "I'll upgrade your plan to Growth ($129/month, 100,000 emails):\n\n```action\n{\"action\":\"UPGRADE_PLAN\",\"params\":{\"plan\":\"growth\",\"price\":\"$129/month\"},\"confirm\":true,\"reason\":\"Upgrading to Growth plan\"}\n```\n\nPlease confirm to proceed with the billing change."),
]

# ═══════════════════════════════════════════════════════════════
# I) CONSISTENCY / PARAPHRASING (fix for R12 + new)
# ═══════════════════════════════════════════════════════════════
paraphrase_qa = [
    ("How much is the basic plan?",
     "ApexMail doesn't have a plan called \"Basic,\" but our entry-level options are:\n\n- **Free plan** — $0/month, 1,000 emails\n- **Starter plan** — $29/month, 25,000 emails\n\nThe Starter plan at **$29/month** is our most affordable paid option with full features including webhooks, analytics, and email support."),
    ("What's the damage for the middle-of-the-road option?",
     "Our mid-range plans are:\n\n- **Pro plan** — **$59/month** for **50,000 emails** (great for growing businesses)\n- **Growth plan** — **$129/month** for **100,000 emails** (our most popular, includes dedicated IP)\n\nEither could be your \"middle of the road\" depending on your volume needs!"),
    ("How many messages can I blast out on your twenty-nine dollar package?",
     "On our **Starter plan** ($29/month), you can send up to **25,000 emails per month**. If you go over, overages are $0.50 per 1,000 extra emails.\n\nNeed more? The Pro plan at $59/month gives you 50,000 emails."),
    ("Give me the rundown on what I get for four hundred bucks a month.",
     "For **$399/month**, you get our **Scale plan** with:\n\n- **500,000 emails/month**\n- **3 dedicated IP addresses**\n- Unlimited sending domains\n- SSO/SAML authentication\n- 10 subaccounts\n- SLA guarantee (10% credit if breached)\n- Phone support & dedicated CSM\n- Overage: $0.50 per 1,000 extra emails"),
    ("I'm bootstrapped and broke. What can you do for free?",
     "We've got you covered! Our **Free plan** is **$0/month** — completely free forever. You get:\n\n- **1,000 emails/month**\n- Full REST API access\n- 1 sending domain\n- 7-day data retention\n- Community support\n\nIt's perfect for testing and small projects. When you're ready to grow, the Starter plan is just $29/month for 25,000 emails."),
    ("We need to pipe our app's password reset emails through your system. How?",
     "Perfect use case for ApexMail's transactional email! Here's how:\n\n1. **API method:** POST to `https://api.apexmail.ee/v1/messages` with your `am_live_` Bearer token\n2. **SMTP relay:** Configure your app to use ApexMail's SMTP server\n3. **SDK method:** Use `@apexmail/sdk` (Node.js) or `apexmail-python` (Python)\n\nTransactional emails like password resets are sent immediately with high priority. Set up SPF, DKIM, and DMARC for best deliverability."),
    ("Our devs want to hit your endpoints from a Python script. What's the package name?",
     "The Python SDK is called **apexmail-python**. Install it via pip:\n\n```\npip install apexmail-python\n```\n\nThe SDK wraps the REST API at https://api.apexmail.ee/v1. Authenticate with your `am_live_<hex>` key for production or `am_test_<hex>` for sandbox testing."),
    ("Is there a way to tell if people actually read my newsletters?",
     "Absolutely! ApexMail provides comprehensive engagement tracking:\n\n- **Open tracking** — see who opened your emails (avg open rate: 21.5%)\n- **Click tracking** — which links were clicked (avg click rate: 2.3%)\n- **Heatmaps** — visual click distribution in your emails\n- **Webhooks** — real-time events for opened, clicked, bounced, etc.\n- **Analytics dashboard** at https://app.apexmail.ee\n\nAll tracking is built-in on paid plans."),
    ("My boss wants to know the ROI numbers for email vs other channels.",
     "Great question! Email marketing has the **highest ROI** of any marketing channel:\n\n- **Average ROI: $36 for every $1 spent**\n- Average open rate: 21.5%\n- Average click rate: 2.3%\n\nApexMail helps maximize this with send-time optimization, A/B testing, and deliverability tools. Our plans start at $0/month (Free) so there's minimal barrier to getting started."),
]

# ═══════════════════════════════════════════════════════════════
# J) HUMAN ESCALATION — NEW for R13
# ═══════════════════════════════════════════════════════════════
escalation_qa = [
    # ── Billing disputes ──
    ("I was charged twice on my credit card for my ApexMail subscription.",
     "I'm sorry to hear about the double charge! This is a billing issue that our support team needs to investigate directly.\n\nPlease contact our billing team at **contact@apexmail.ee** with your account email and the transaction details. They'll review the charge and issue a refund if applicable.\n\nIs there anything else I can help with in the meantime?"),
    ("Your system charged me $399 but I'm on the Starter plan.",
     "That doesn't sound right — the Starter plan is $29/month. This looks like a billing discrepancy that needs human review.\n\nPlease reach out to our billing team at **contact@apexmail.ee** with your account email and the charge details. They'll investigate and correct it promptly.\n\nI apologize for the inconvenience."),
    ("I want to dispute a charge on my account.",
     "I understand you'd like to dispute a charge. Billing disputes require human review from our support team.\n\nPlease email **contact@apexmail.ee** with:\n- Your account email\n- The charge amount and date\n- A description of the issue\n\nOur billing team will review and respond within 1-2 business days."),

    # ── Refund requests ──
    ("I want a refund for last month because my emails weren't delivered.",
     "I'm sorry you experienced delivery issues. Refund requests need to be handled by our support team, who can review your account's delivery logs.\n\nPlease email **contact@apexmail.ee** with:\n- Your account email\n- The date range affected\n- Details about the delivery issues\n\nOur team will investigate the delivery problems and discuss refund options with you."),
    ("Can I get a refund? I signed up yesterday and changed my mind.",
     "I understand! Refund requests are handled by our billing team. Please reach out to **contact@apexmail.ee** with your account email and they'll process your request.\n\nIf you're not sure ApexMail is right for you, remember we have a **Free plan** ($0/month, 1,000 emails) you can use to test the platform with no commitment."),

    # ── Account security ──
    ("I think someone hacked into my ApexMail account. What do I do?",
     "This is urgent — please take these steps immediately:\n\n1. **Change your password** right now at https://app.apexmail.ee\n2. **Revoke all API keys** from the dashboard\n3. **Contact our security team** at **contact@apexmail.ee** with subject line \"URGENT: Account Compromise\"\n\nOur security team will investigate, review login activity, and help secure your account. Do NOT delay — the sooner you report it, the faster we can help."),
    ("Someone is using my API key to send emails I didn't authorize.",
     "This is a security issue — act immediately:\n\n1. **Revoke the compromised API key** in your dashboard at https://app.apexmail.ee\n2. **Generate a new API key** and update your application\n3. **Contact our security team** at **contact@apexmail.ee** with subject \"API Key Compromise\"\n\nNever share API keys publicly (e.g., in GitHub repos). Use environment variables to store them securely."),
    ("I'm locked out of my account and can't reset my password.",
     "I'm sorry you're locked out. Account access issues need to be resolved by our support team for security reasons.\n\nPlease email **contact@apexmail.ee** from the email address associated with your account, explaining the issue. Our team will verify your identity and help restore access."),

    # ── GDPR / data deletion ──
    ("I need to delete all my data under GDPR. How?",
     "GDPR data deletion requests are handled by our compliance team. To submit a request:\n\nPlease email **contact@apexmail.ee** with:\n- Subject: \"GDPR Data Deletion Request\"\n- Your account email address\n- Confirmation that you want all personal data deleted\n\nOur team will process your request within 30 days as required by GDPR. Note that this will permanently delete your account and all associated data."),
    ("I need a copy of all my data for a GDPR Subject Access Request.",
     "For GDPR Subject Access Requests (data export), please contact our compliance team at **contact@apexmail.ee** with:\n\n- Subject: \"GDPR Subject Access Request\"\n- Your account email\n- What data you'd like exported\n\nWe'll provide your data within the 30-day GDPR timeline."),

    # ── SLA violations ──
    ("We're experiencing an SLA violation. Our emails have been delayed for 6 hours.",
     "I'm sorry about the delay — that's unacceptable. For SLA-related issues, our support team needs to investigate immediately.\n\nPlease contact **contact@apexmail.ee** with:\n- Subject: \"SLA Violation Report\"\n- Your account email and plan\n- Time range of the delays\n- Any error messages or API responses\n\nIf you're on the Scale or Enterprise plan with SLA guarantees, our team will review for applicable credits."),

    # ── Bug reports ──
    ("I found a bug where webhook events are being duplicated.",
     "Thank you for reporting this! Bug reports need to be reviewed by our engineering team.\n\nPlease send details to **contact@apexmail.ee** with:\n- Subject: \"Bug Report: Duplicate Webhook Events\"\n- Your account email\n- The webhook URL affected\n- Sample duplicate event IDs/timestamps\n- Any patterns you've noticed\n\nIn the meantime, I'd recommend implementing idempotency checks on your webhook handler using the event ID to deduplicate."),
    ("The API is returning 500 errors intermittently.",
     "I'm sorry you're experiencing 500 errors. Intermittent server errors should be reported to our engineering team.\n\nPlease email **contact@apexmail.ee** with:\n- Your account email\n- The API endpoint(s) affected\n- Request/response examples\n- Timestamps of the errors\n\nAs a workaround, implement exponential backoff retry logic in your integration."),

    # ── Legal/compliance ──
    ("Can you help with our HIPAA compliance requirements for sending patient emails?",
     "HIPAA compliance is critical and requires specific infrastructure configurations. Our **Enterprise plan** ($1,299/month) includes HIPAA compliance features.\n\nFor detailed HIPAA compliance discussions, please contact our compliance team at **contact@apexmail.ee**. They can:\n- Provide a BAA (Business Associate Agreement)\n- Discuss PHI handling procedures\n- Set up HIPAA-compliant infrastructure\n\nDo not send PHI through a non-HIPAA-compliant plan."),
    ("I need a signed DPA for our legal team. Can you provide one?",
     "Yes, we provide Data Processing Agreements (DPAs) for GDPR compliance. Please contact our legal team at **contact@apexmail.ee** to request a signed DPA.\n\nInclude:\n- Your company name and address\n- Your DPO (Data Protection Officer) contact if applicable\n- Any specific clauses your legal team requires\n\nOur team will send a standard DPA or work with your legal team on a custom agreement."),
    ("We need SOC 2 compliance documentation for our vendor assessment.",
     "SOC 2 compliance documentation is available for Enterprise plan customers. Please reach out to our compliance team at **contact@apexmail.ee** with:\n\n- Your company name\n- The specific compliance documents needed\n- Your vendor assessment timeline\n\nOur team can provide SOC 2 reports, security questionnaire responses, and other compliance documentation."),

    # ── General escalation ──
    ("I have a complex problem that I don't think you can solve.",
     "I understand! For complex issues that go beyond what I can help with, please reach out to our support team at **contact@apexmail.ee**. They have access to your account details, logs, and can investigate issues hands-on.\n\nCan you tell me more about the problem? I might be able to help with part of it or point you in the right direction."),
    ("I need to speak to a human.",
     "Of course! You can reach our support team at **contact@apexmail.ee**. They're available to help with billing, technical issues, account management, and anything else.\n\nIf you're on the Scale or Enterprise plan, you also have access to phone support and a dedicated CSM.\n\nIs there anything I can help with in the meantime?"),
    ("This is urgent, I need help NOW.",
     "I understand the urgency! For urgent issues, please contact our support team immediately at **contact@apexmail.ee** with \"URGENT\" in the subject line.\n\nIf you're on the **Scale** or **Enterprise** plan, you have access to phone support for critical issues.\n\nCan you tell me what's going on? I may be able to help while you wait for the team to respond."),
]

# ═══════════════════════════════════════════════════════════════
# K) COMPLEX BILLING SCENARIOS — NEW for R13
# ═══════════════════════════════════════════════════════════════
complex_billing_qa = [
    ("I'm on the Starter plan and sent 32,000 emails this month. What's my total bill?",
     "On the **Starter plan** ($29/month, 25,000 emails included), sending 32,000 emails means you went over by **7,000 emails**.\n\nOverage calculation:\n- 7,000 extra emails ÷ 1,000 = 7 units\n- 7 × $0.50 = **$3.50 in overages**\n\n**Total bill: $29.00 + $3.50 = $32.50**\n\nIf you regularly exceed 25,000 emails, consider upgrading to the **Pro plan** ($59/month for 50,000 emails) — it would save you money."),
    ("I'm on Pro and sent 65,000 emails. What do I owe?",
     "On the **Pro plan** ($59/month, 50,000 emails included), sending 65,000 emails means you went over by **15,000 emails**.\n\nOverage calculation:\n- 15,000 extra emails ÷ 1,000 = 15 units\n- 15 × $0.50 = **$7.50 in overages**\n\n**Total bill: $59.00 + $7.50 = $66.50**\n\nTip: If this is typical, the **Growth plan** ($129/month for 100,000 emails) would give you more headroom."),
    ("We send about 80,000 emails/month. Should we use Growth or Pro with overages?",
     "Let's compare:\n\n**Pro plan + overages:**\n- Base: $59/month (50,000 emails)\n- Overages: 30,000 extra ÷ 1,000 × $0.50 = $15.00\n- **Total: $74/month**\n\n**Growth plan:**\n- Base: $129/month (100,000 emails)\n- **Total: $129/month**\n\nFor 80,000 emails, **Pro with overages at $74/month** is cheaper. However, Growth includes a **dedicated IP**, A/B testing, and audit logs. If deliverability and advanced features matter, Growth is worth the premium."),
    ("I want to use PAYG for 50,000 emails. How much would that cost vs the Pro plan?",
     "**PAYG for 50,000 emails:**\n- First 10,000: 10,000 × $0.001 = $10.00\n- Next 40,000: 40,000 × $0.0008 = $32.00\n- **Total: $42.00**\n\n**Pro plan:** $59/month for 50,000 emails\n\nPAYG is **$17 cheaper** for exactly 50,000 emails. However, the Pro plan includes custom tracking domain, 60-day data retention, priority onboarding, and a predictable monthly cost. If you send consistently, Pro may offer better value in features."),
    ("What happens if I downgrade from Scale to Growth mid-billing-cycle?",
     "Plan changes mid-cycle involve prorated billing, which is handled by our billing system. For specifics on your account:\n\nPlease contact our billing team at **contact@apexmail.ee** — they can tell you:\n- How proration works for your billing date\n- Whether unused Scale allowance carries over\n- When the new Growth limits take effect\n\nGenerally, downgrades take effect at the next billing cycle to avoid service disruption."),
    ("If I upgrade from Starter to Pro mid-month, do I lose my remaining emails?",
     "Plan upgrades mid-month involve prorated billing. The specifics depend on your billing date and usage.\n\nPlease contact our billing team at **contact@apexmail.ee** for your account's exact proration details. Generally:\n- You'll receive the Pro plan's higher email limit immediately\n- The price difference is prorated for the remaining days\n- No emails are \"lost\" — your limit increases"),
    ("Can I get an annual discount if I pay for 12 months upfront?",
     "Annual billing options may be available depending on your plan. Please contact our sales team at **contact@apexmail.ee** to discuss:\n\n- Annual billing discounts\n- Custom payment terms\n- Volume commitments\n\nOur Enterprise plan ($1,299/month) already includes custom billing arrangements."),
    ("We have 5 teams that each need their own sending domain. What plan do we need?",
     "The number of sending domains varies by plan:\n\n| Plan | Sending Domains |\n|------|----------------|\n| Free | 1 |\n| Starter | 3 |\n| Pro | 5 |\n| Growth | 10 |\n| Scale | Unlimited |\n\nFor 5 teams with separate domains, the **Pro plan** ($59/month, 5 domains) is the minimum. If each team needs multiple domains, consider **Growth** ($129/month, 10 domains) or **Scale** ($399/month, unlimited)."),
]

# ═══════════════════════════════════════════════════════════════
# L) COMPLEX TECHNICAL SCENARIOS — NEW for R13
# ═══════════════════════════════════════════════════════════════
complex_tech_qa = [
    ("My open rate dropped from 25% to 8% overnight. What could be wrong?",
     "A sudden open rate drop like that usually signals one of these issues:\n\n1. **Domain authentication failure** — Check that your SPF, DKIM, and DMARC records are still valid. DNS changes or domain renewals can break them.\n2. **IP reputation damage** — Someone may have reported your emails as spam, or a shared IP got blacklisted. Check blacklists at MXToolbox.\n3. **Content filtering** — Your recent emails may trigger spam filters. Avoid spam trigger words, excessive images, or URL shorteners.\n4. **List quality** — If you imported a new list with invalid/stale addresses, high bounces hurt your reputation.\n5. **Gmail/Yahoo policy changes** — Both now require DKIM + DMARC alignment.\n\n**Immediate steps:**\n- Verify SPF, DKIM, DMARC in your dashboard\n- Check bounce rate (should be < 2%)\n- Check complaint rate (should be < 0.1%)\n- Review your suppression list"),
    ("I'm getting a 429 error from the API. What does it mean?",
     "A **429 error** means you've hit the API **rate limit** — too many requests in a short period.\n\n**How to handle it:**\n1. Implement **exponential backoff** — wait 1s, 2s, 4s, 8s between retries\n2. Check the `Retry-After` header for the recommended wait time\n3. Batch your requests instead of sending one-by-one\n4. Use webhooks instead of polling for status updates\n\nAPI rate limits depend on your plan. If you consistently hit limits, you may need a higher plan with more API calls (e.g., Growth includes 2M calls/month)."),
    ("How do I set up a dedicated IP and warm it up properly?",
     "Dedicated IPs are available on **Growth** (1 IP), **Scale** (3 IPs), and **Enterprise** plans.\n\n**IP Warmup Schedule:**\n- **Week 1:** 500-1,000 emails/day to your most engaged subscribers\n- **Week 2:** 2,000-5,000 emails/day\n- **Week 3:** 5,000-10,000 emails/day\n- **Week 4:** 10,000-25,000 emails/day\n- **Week 5+:** Gradually increase to full volume\n\n**Best practices:**\n- Start with your most engaged recipients (recent openers/clickers)\n- Maintain consistent daily volume\n- Monitor bounce rate (< 2%) and complaint rate (< 0.1%)\n- Set up SPF, DKIM, and DMARC before starting\n- Don't rush — a poorly warmed IP will damage your reputation"),
    ("What's the difference between transactional and marketing emails?",
     "**Transactional emails** are triggered by a user action:\n- Password resets, order confirmations, shipping notifications\n- Sent immediately, one-to-one\n- High priority, higher open rates\n- Don't require unsubscribe links (but it's good practice)\n\n**Marketing emails** are promotional:\n- Newsletters, campaigns, promotional offers\n- Sent in bulk to subscriber lists\n- **Must** include unsubscribe links (CAN-SPAM, GDPR)\n- Subject to spam filtering\n\n**Should you use separate IPs?** Yes, if possible! This way, marketing reputation issues don't affect transactional delivery. On Growth+ plans with dedicated IPs, set up separate sending streams."),
    ("Our emails are going to Gmail's Promotions tab. How do I fix this?",
     "Gmail uses machine learning to sort emails into tabs. To improve Primary inbox placement:\n\n1. **Reduce HTML complexity** — Plain text or minimal HTML performs better\n2. **Personalize content** — Use the recipient's name, reference past interactions\n3. **Limit images and links** — High image-to-text ratio triggers Promotions\n4. **Avoid promotional language** — \"Buy now,\" \"Limited time,\" \"Free\" etc.\n5. **Authenticate properly** — Ensure SPF, DKIM, DMARC are all passing\n6. **Encourage replies** — Emails you reply to train Gmail to deliver to Primary\n7. **Ask subscribers** to drag your email to Primary and mark as \"Not promotions\"\n\nNote: Transactional emails (password resets, order confirmations) typically land in Primary automatically."),
    ("I need to send 2 million emails for a product launch. What's the best approach?",
     "For a 2M email product launch, here's my recommended approach:\n\n**1. Plan selection:** You'll need the **Scale** ($399/month, 500K) or **Enterprise** ($1,299/month, custom) plan. For a one-time launch, consider PAYG: 2M emails at blended rate ≈ $1,100.\n\n**2. Warm-up (if new IP):** Start 4-6 weeks before launch, gradually increasing daily volume.\n\n**3. Sending strategy:**\n- Spread over 3-5 days (don't blast all at once)\n- Send to most engaged subscribers first\n- Throttle to 50-100K/hour per IP\n- Use send-time optimization\n\n**4. Technical prep:**\n- Verify SPF, DKIM, DMARC\n- Clean your list (remove bounced/unsubscribed)\n- Set up webhooks for real-time monitoring\n\n**5. Monitoring:**\n- Watch bounce rate (< 2%) and complaint rate (< 0.1%)\n- Pause if you see deliverability issues\n\nFor launches of this scale, I'd recommend contacting **contact@apexmail.ee** to work with our deliverability team."),
    ("How do I handle webhook delivery failures?",
     "To ensure you don't miss webhook events:\n\n**1. Endpoint reliability:**\n- Return a 200 status code within 5 seconds\n- Process asynchronously — acknowledge first, process later\n- Use a queue (Redis, SQS) to buffer events\n\n**2. Idempotency:**\n- Use the unique event ID to deduplicate\n- Store processed event IDs to prevent double-processing\n\n**3. Retry handling:**\n- ApexMail retries failed deliveries with exponential backoff\n- Ensure your endpoint is back online quickly\n\n**4. Monitoring:**\n- Log all incoming webhooks\n- Set up alerts for endpoint downtime\n- Monitor your webhook URL in the dashboard\n\n**5. Fallback:**\n- Use the API to poll for events you may have missed\n- Set up a dead-letter queue for failed processing"),
    ("We're seeing high bounce rates after importing a new list. What should we do?",
     "High bounces after a list import is a common issue. Here's how to fix it:\n\n**Immediate actions:**\n1. **Stop sending** to the new list until it's cleaned\n2. **Remove hard bounces** — they'll never deliver and hurt reputation\n3. **Check your bounce rate** — if > 2%, you need to act fast\n\n**List cleaning:**\n- Use an email verification service to validate addresses before importing\n- Remove role-based addresses (info@, admin@, sales@)\n- Remove catch-all domains (they often bounce later)\n- Remove addresses that haven't engaged in 6+ months\n\n**Prevention:**\n- Always use **double opt-in** for new subscribers\n- Verify emails at the point of collection\n- Regularly clean your list (monthly)\n- Monitor your suppression list in the dashboard\n\nTarget: Keep bounce rate **below 2%** and complaint rate **below 0.1%**."),
]

# Build all fix examples
all_qa_lists = [
    pricing_qa, identity_qa, deliverability_qa, api_qa,
    offtopic_qa, hallucination_qa, safety_qa, action_qa,
    paraphrase_qa, escalation_qa, complex_billing_qa, complex_tech_qa,
]

for qa_list in all_qa_lists:
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
print(f"  Action format: {len(action_qa)}")
print(f"  Paraphrase: {len(paraphrase_qa)}")
print(f"  Escalation: {len(escalation_qa)}")
print(f"  Complex billing: {len(complex_billing_qa)}")
print(f"  Complex technical: {len(complex_tech_qa)}")


# =====================================================
# Step 3: Build final dataset
# =====================================================
MULTIPLIER = 12  # slightly less than R12 since we have more diverse examples

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
print(f"\nFinal R13 dataset: {total}")
print(f"  Cleaned base (system prompt fixed): {len(clean_base_fixed)}")
print(f"  Fix examples: {len(diverse_fixes)} x{MULTIPLIER} = {fix_count}")
print(f"  Fix ratio: {fix_count / total * 100:.1f}%")

# Save
with open("data/train.jsonl", "w") as f:
    for ex in final:
        f.write(json.dumps(ex) + "\n")

print(f"\nSaved data/train.jsonl ({total} examples)")
print("Ready for Round 13 training!")
