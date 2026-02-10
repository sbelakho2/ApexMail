"""
Generate targeted fix examples using the EXACT system prompt from training data.
Fixes pricing hallucination, API URLs, company identity, off-topic deflection.
Each example is repeated with varied phrasing to reinforce the correct facts.
"""
import json
import hashlib
from pathlib import Path

BASE_DIR = Path("/workspace/ApexMail/apps/ai/training")
DATA_DIR = BASE_DIR / "data"

# Extract exact system prompt from first training example
with open(DATA_DIR / "train.jsonl") as f:
    first = json.loads(f.readline())
text = first["text"]
_s = text.find("<|im_start|>system\n") + len("<|im_start|>system\n")
_e = text.find("<|im_end|>", _s)
SYSTEM = text[_s:_e]
print(f"System prompt length: {len(SYSTEM)} chars")


def chatml(user: str, assistant: str) -> str:
    return (
        f"<|im_start|>system\n{SYSTEM}<|im_end|>\n"
        f"<|im_start|>user\n{user}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant}<|im_end|>"
    )


# ═══════════════════════════════════════════════════════════════════════
# PRICING - the #1 failure area. Massive reinforcement.
# ═══════════════════════════════════════════════════════════════════════
PRICING_QA = [
    # --- Starter ---
    ("How much does the Starter plan cost?",
     "The **Starter** plan is **$29/month** and includes **25,000 emails/month** and 250,000 API calls/month. It's our entry-level paid plan, perfect for small businesses getting started with email marketing."),
    ("What's the Starter plan price?",
     "The Starter plan costs **$29/month** with **25,000 emails per month** included."),
    ("Starter plan pricing?",
     "The **Starter** plan is **$29/mo** — 25,000 emails/month and 250,000 API calls/month."),
    ("How many emails on the Starter plan?",
     "The Starter plan ($29/mo) includes **25,000 emails per month**. Overages are $0.50 per 1,000 additional emails."),
    ("Tell me about the Starter plan.",
     "The **Starter** plan costs **$29/month** and includes:\n\n- **25,000 emails/month**\n- 250,000 API calls/month\n- Email templates & analytics\n- API access\n\nIt's ideal for small businesses and startups."),
    ("Starter plan details please.",
     "Here are the **Starter** plan details:\n\n| Feature | Value |\n|---------|-------|\n| Price | **$29/month** |\n| Emails/month | **25,000** |\n| API calls/month | 250,000 |\n| Templates | Included |\n| Analytics | Included |\n\nOverage: $0.50 per 1,000 emails beyond the 25,000 limit."),
    ("What does the Starter plan include?",
     "The **Starter** plan ($29/month) includes **25,000 emails/month**, 250,000 API calls/month, email templates, analytics, and API access."),
    ("How much is the basic plan?",
     "Our entry-level paid plan is the **Starter** plan at **$29/month**. It includes **25,000 emails/month** and 250,000 API calls. We also have a Free tier with 1,000 emails/month."),
    ("Tell me about the Starter tier.",
     "The **Starter** tier is **$29/month** with **25,000 emails/month** and 250,000 API calls. It includes templates, analytics, and full API access."),
    ("What's the cheapest paid plan?",
     "The cheapest paid plan is **Starter** at **$29/month** — it includes **25,000 emails/month** and 250,000 API calls. We also offer a Free plan (1,000 emails/month)."),

    # --- Pro ---
    ("What's the Pro plan price and email limit?",
     "The **Pro** plan is **$59/month** with **100,000 emails/month** and 500,000 API calls/month."),
    ("Pro plan details?",
     "The **Pro** plan costs **$59/month** and includes:\n\n- **100,000 emails/month**\n- 500,000 API calls/month\n- Advanced analytics\n- Priority support\n\nIt's great for growing businesses with higher sending volumes."),
    ("Tell me about the Pro plan.",
     "The **Pro** plan is **$59/month** with **100,000 emails per month** and 500,000 API calls/month. It includes advanced analytics and priority support."),
    ("How much is Pro?",
     "The Pro plan is **$59/month** — 100,000 emails/month and 500,000 API calls."),

    # --- Growth ---
    ("Tell me about the Growth plan.",
     "The **Growth** plan is **$129/month** with **500,000 emails/month** and 2,000,000 API calls/month. It's designed for established businesses with significant email volume."),
    ("Growth plan pricing?",
     "The **Growth** plan costs **$129/month** — 500,000 emails/month and 2,000,000 API calls."),
    ("How much is Growth?",
     "The Growth plan is **$129/month** with **500,000 emails per month**."),

    # --- Scale ---
    ("What does Scale cost?",
     "The **Scale** plan costs **$399/month** with **2,000,000 emails/month** and 10,000,000 API calls/month."),
    ("Scale plan details?",
     "The **Scale** plan is **$399/month** — 2,000,000 emails/month, 10,000,000 API calls, and it's built for high-volume senders."),
    ("How much is the Scale plan?",
     "The Scale plan is **$399/month** with **2,000,000 emails per month** and 10,000,000 API calls."),

    # --- Enterprise ---
    ("Enterprise plan pricing?",
     "The **Enterprise** plan is **$1,299/month** with custom email volume and unlimited API calls. It includes a dedicated account manager, SSO/SAML, and a 99.99% uptime SLA."),
    ("How much is Enterprise?",
     "The Enterprise plan is **$1,299/month** with custom email limits and unlimited API calls."),
    ("What's the most expensive plan?",
     "Our highest-tier plan is **Enterprise** at **$1,299/month** — custom email volume, unlimited API calls, dedicated account manager, SSO, and 99.99% SLA."),

    # --- Comparisons ---
    ("Compare the Starter and Pro plans.",
     "Here's **Starter vs Pro**:\n\n| Feature | Starter | Pro |\n|---------|---------|-----|\n| Price | **$29/mo** | **$59/mo** |\n| Emails/month | **25,000** | **100,000** |\n| API calls/month | 250,000 | 500,000 |\n\nPro offers 4x the email volume for 2x the price."),
    ("Compare all the plans.",
     "Here's our full plan comparison:\n\n| Plan | Price | Emails/mo | API calls/mo |\n|------|-------|-----------|-------------|\n| Starter | **$29** | **25,000** | 250,000 |\n| Pro | **$59** | **100,000** | 500,000 |\n| Growth | **$129** | **500,000** | 2,000,000 |\n| Scale | **$399** | **2,000,000** | 10,000,000 |\n| Enterprise | **$1,299** | Custom | Unlimited |"),
    ("List your plans and prices.",
     "ApexMail plans:\n\n- **Starter**: $29/mo — 25,000 emails\n- **Pro**: $59/mo — 100,000 emails\n- **Growth**: $129/mo — 500,000 emails\n- **Scale**: $399/mo — 2,000,000 emails\n- **Enterprise**: $1,299/mo — Custom/Unlimited\n\nWe also have a Free tier (1,000 emails/month)."),
    ("How much does ApexMail cost?",
     "ApexMail starts free (1,000 emails/mo). Paid plans:\n\n- **Starter**: $29/mo (25,000 emails)\n- **Pro**: $59/mo (100,000 emails)\n- **Growth**: $129/mo (500,000 emails)\n- **Scale**: $399/mo (2,000,000 emails)\n- **Enterprise**: $1,299/mo (unlimited)"),
    ("What are your pricing plans?",
     "Our pricing plans:\n\n| Plan | Price | Emails/mo |\n|------|-------|-----------|\n| Free | $0 | 1,000 |\n| Starter | **$29** | **25,000** |\n| Pro | **$59** | **100,000** |\n| Growth | **$129** | **500,000** |\n| Scale | **$399** | **2,000,000** |\n| Enterprise | **$1,299** | Custom |"),

    # --- Recommendations ---
    ("I send 300,000 emails/month. What plan do you recommend?",
     "For 300,000 emails/month, I recommend the **Growth** plan at **$129/month** — it includes **500,000 emails/month**, giving you room to grow. If you anticipate exceeding 500K, consider **Scale** at **$399/month** (2,000,000 emails)."),
    ("What plan for 50,000 emails per month?",
     "For 50,000 emails/month, the **Pro** plan at **$59/month** is ideal — it includes **100,000 emails/month**, giving you solid headroom. The Starter ($29/mo) only covers 25,000."),
    ("I need to send 1 million emails. Which plan?",
     "For 1 million emails/month, you'd need at least the **Scale** plan at **$399/month** (2,000,000 emails/month). If you need more flexibility, **Enterprise** at **$1,299/month** offers custom limits."),

    # --- Overages ---
    ("How much are overages?",
     "Overage rates:\n- **Email overages**: $0.50 per 1,000 emails over your plan limit\n- **API overages**: First 100K calls free with each plan, then $0.10 per 1,000 calls\n\nPAYG rates: $0.001/email (first 10K), $0.0008 (10K–100K), $0.0005 (100K–1M), $0.0003 (1M+)."),
    ("How much are API overages?",
     "API call overages are **$0.10 per 1,000 calls** beyond your plan's included amount. Each plan includes a generous API allowance:\n- Starter: 250,000 calls\n- Pro: 500,000 calls\n- Growth: 2,000,000 calls\n- Scale: 10,000,000 calls\n- Enterprise: Unlimited"),
]

# ═══════════════════════════════════════════════════════════════════════
# API ACCURACY
# ═══════════════════════════════════════════════════════════════════════
API_QA = [
    ("What's the API base URL?",
     "The ApexMail API base URL is:\n\n```\nhttps://api.apexmail.ee/v1\n```\n\nAll endpoints are relative to this URL. For example: `POST https://api.apexmail.ee/v1/messages` to send an email."),
    ("What's the API endpoint?",
     "The API base URL is **https://api.apexmail.ee/v1**. Key endpoints:\n\n- `POST /v1/messages` — Send email\n- `GET /v1/contacts` — List contacts\n- `GET /v1/analytics/overview` — Analytics\n- `GET /v1/domains` — Domains"),
    ("How do I authenticate with the API?",
     "Authenticate using a Bearer token in the Authorization header:\n\n```\nAuthorization: Bearer am_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n```\n\nAPI keys prefixed with `am_live_` are for production. Use `am_test_` keys for sandbox testing (no actual delivery). Manage keys at https://app.apexmail.ee → Settings → API Keys."),
    ("What's the dashboard URL?",
     "The ApexMail dashboard is at **https://app.apexmail.ee**. From there you can manage campaigns, contacts, templates, analytics, domains, and API keys."),
    ("Where do I find my API key?",
     "Find your API keys at **https://app.apexmail.ee** → **Settings** → **API Keys**.\n\nKey formats:\n- Production: `am_live_` prefix\n- Sandbox: `am_test_` prefix (no real delivery)"),
    ("What format are API keys?",
     "ApexMail API keys use these prefixes:\n- **`am_live_`** — Production (sends real emails)\n- **`am_test_`** — Sandbox (no delivery, for testing)\n\nExample: `am_live_a1b2c3d4e5f6...`"),
]

# ═══════════════════════════════════════════════════════════════════════
# COMPANY IDENTITY
# ═══════════════════════════════════════════════════════════════════════
IDENTITY_QA = [
    ("Who made ApexMail?",
     "ApexMail was built by **Bel Consulting OÜ**, based in **Tallinn, Estonia**. The company was founded in **2022**."),
    ("Who is behind ApexMail?",
     "ApexMail is built by **Bel Consulting OÜ** (Registry Code 16192499), headquartered in **Tallinn, Estonia**, founded in **2022**."),
    ("When was ApexMail founded?",
     "ApexMail was founded in **2022** by Bel Consulting OÜ in Tallinn, Estonia."),
    ("Where is ApexMail based?",
     "ApexMail is based in **Tallinn, Estonia**. The company (**Bel Consulting OÜ**) was founded there in **2022**."),
    ("Tell me about the ApexMail company.",
     "**ApexMail** is a developer-first email platform by **Bel Consulting OÜ** (Registry Code 16192499), headquartered in **Tallinn, Estonia**, founded **2022**.\n\n- API: https://api.apexmail.ee/v1\n- Dashboard: https://app.apexmail.ee\n- Docs: https://docs.apexmail.ee"),
    ("What company runs ApexMail?",
     "ApexMail is operated by **Bel Consulting OÜ**, registered in **Tallinn, Estonia** (Registry Code 16192499). The company was founded in **2022**."),
]

# ═══════════════════════════════════════════════════════════════════════
# OFF-TOPIC DEFLECTION
# ═══════════════════════════════════════════════════════════════════════
DEFLECTION_QA = [
    ("What's the weather like?",
     "I'm ApexMail Assistant — I help with email marketing, not weather! 😊\n\nI can assist with:\n- Email campaigns and API integration\n- Deliverability best practices\n- Pricing and plan selection\n\nWhat can I help you with regarding ApexMail?"),
    ("Write me a poem about love.",
     "I appreciate the creative request, but I'm ApexMail Assistant — I focus on email marketing.\n\nI can help you with:\n- Setting up email campaigns\n- API integration (https://api.apexmail.ee/v1)\n- Deliverability optimization\n- Plan comparison and pricing\n\nWhat would you like to know about ApexMail?"),
    ("What stocks should I invest in?",
     "I'm ApexMail Assistant and I focus on email marketing — I can't provide financial advice.\n\nI can help with:\n- ApexMail features and pricing\n- Email API integration\n- Deliverability best practices\n\nWhat can I help you with regarding email?"),
    ("Tell me a joke.",
     "I'm better at email marketing than comedy! 😊 I'm ApexMail Assistant.\n\nI can help with:\n- Campaign setup and templates\n- API integration\n- Deliverability and analytics\n- Pricing plans ($29–$1,299/mo)\n\nHow can I help with your email needs?"),
    ("Who will win the World Cup?",
     "I'm ApexMail Assistant — I'm great at email deliverability, but sports predictions aren't my strength! 😊\n\nI can help with email marketing questions. What would you like to know about ApexMail?"),
    ("Can you write me a Python web scraper?",
     "I'm ApexMail Assistant — I can help with code for the **ApexMail API**, but not general web scraping.\n\nHere's what I can help with:\n- Sending emails via `POST https://api.apexmail.ee/v1/messages`\n- Managing contacts and domains\n- Webhook integration\n- Using our Node.js or Python SDK\n\nWant a code example for the ApexMail API?"),
    ("What's the capital of France?",
     "I'm ApexMail Assistant — geography isn't my specialty, but email marketing is! 😊\n\nI can help with ApexMail features, pricing, API integration, and deliverability. What email-related questions do you have?"),
    ("Help me with my math homework.",
     "I'm ApexMail Assistant, focused on email marketing — not math tutoring.\n\nI can assist with:\n- ApexMail pricing and plans\n- Email API integration\n- Campaign optimization\n- Deliverability best practices\n\nWhat would you like to know about ApexMail?"),
]

# ═══════════════════════════════════════════════════════════════════════
# DELIVERABILITY
# ═══════════════════════════════════════════════════════════════════════
DELIVERABILITY_QA = [
    ("What's a good bounce rate?",
     "A good bounce rate is **below 2%** overall:\n\n- **Hard bounces** (permanent failures): below 0.5%\n- **Soft bounces** (temporary): below 1.5%\n\nIf your bounce rate exceeds 2%, clean your list and remove invalid addresses. ApexMail auto-suppresses hard bounces."),
    ("What's an acceptable spam complaint rate?",
     "Keep your spam complaint rate **below 0.1%** (1 per 1,000 emails). Google and Yahoo enforce this threshold — exceeding it can land your emails in spam.\n\nTips: use double opt-in, include clear unsubscribe links, and send relevant content."),
    ("What's the average email open rate?",
     "The industry average email open rate is **21.5%**. Ranges by industry:\n\n- Education: ~28%\n- Government: ~27%\n- Technology: ~22%\n- Retail: ~18%\n\nImprove open rates with compelling subject lines, personalization, and optimal send timing."),
    ("What's the average click rate for emails?",
     "The average email click-through rate is **2.3%** across all industries.\n\n- Education: ~4%\n- Technology: ~2.5%\n- Retail: ~2%\n\nImprove clicks with clear CTAs, personalization, and audience segmentation."),
    ("How do I improve deliverability?",
     "Key steps to improve deliverability:\n\n1. **Authenticate**: Set up SPF, DKIM, and DMARC\n2. **Clean lists**: Remove bounces and inactive subscribers\n3. **Monitor rates**: Bounce rate below 2%, complaints below 0.1%\n4. **Warm up IPs**: Start low volume, increase gradually\n5. **Double opt-in**: Ensures valid, engaged subscribers\n6. **Quality content**: Relevant, targeted emails\n\nApexMail auto-configures SPF/DKIM when you verify your domain."),
]

# ═══════════════════════════════════════════════════════════════════════
# ACTION FORMAT
# ═══════════════════════════════════════════════════════════════════════
ACTION_QA = [
    ("Send a test email to hello@example.com",
     'I\'ll prepare that for you. Here\'s the action:\n\n```action\n{"action":"SEND_EMAIL","params":{"to":"hello@example.com","subject":"Test email from ApexMail","html":"<p>This is a test email.</p>"},"confirm":true,"reason":"Sending test email to hello@example.com"}\n```\n\nPlease confirm to proceed. You can also send via the API:\n```bash\ncurl -X POST https://api.apexmail.ee/v1/messages \\\n  -H "Authorization: Bearer am_live_your_key" \\\n  -d \'{"to":"hello@example.com","subject":"Test","html":"<p>Hello!</p>"}\'\n```'),
    ("Delete my account",
     'Account deletion is irreversible. Here\'s the action requiring your confirmation:\n\n```action\n{"action":"DELETE_ACCOUNT","params":{},"confirm":true,"reason":"User requested account deletion"}\n```\n\nThis will permanently delete all data (contacts, campaigns, analytics, API keys). Please type "CONFIRM" to proceed, or contact support@apexmail.ee.'),
    ("Upgrade me to the Growth plan",
     'I\'ll prepare the upgrade. Here\'s the action:\n\n```action\n{"action":"UPGRADE_PLAN","params":{"plan":"growth","price":"$129/mo","emails":"500,000/mo"},"confirm":true,"reason":"User requested upgrade to Growth plan"}\n```\n\nThe Growth plan is $129/month with 500,000 emails/month. Please confirm to proceed, or upgrade at https://app.apexmail.ee/billing.'),
]

# ═══════════════════════════════════════════════════════════════════════
# TECHNICAL DEPTH
# ═══════════════════════════════════════════════════════════════════════
TECHNICAL_QA = [
    ("What is DMARC and why do I need it?",
     "**DMARC** (Domain-based Message Authentication, Reporting & Conformance) protects your domain from spoofing by checking **alignment** between your From: domain and SPF/DKIM authentication.\n\n**How it works:**\n1. Verifies SPF and/or DKIM **alignment** with your sending domain\n2. Applies your **policy** (none → quarantine → reject) for failed checks\n3. Sends reports so you can monitor authentication\n\n**Why you need it:**\n- Prevents domain spoofing\n- Required by Gmail/Yahoo for bulk senders\n- Improves deliverability\n\nExample record: `v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com`"),
    ("How do I set up DKIM?",
     "**DKIM** (DomainKeys Identified Mail) adds a cryptographic signature to verify email authenticity.\n\n**Setup with ApexMail:**\n1. Go to **https://app.apexmail.ee** → **Domains**\n2. Add your domain\n3. Add the CNAME record ApexMail provides to your DNS\n4. Click **Verify**\n\nApexMail uses 2048-bit DKIM keys and handles rotation automatically."),
    ("Explain SPF authentication.",
     "**SPF** (Sender Policy Framework) is a DNS TXT record that lists authorized mail servers for your domain.\n\n**For ApexMail**, add this to your DNS:\n```\nv=spf1 include:spf.apexmail.ee ~all\n```\n\nThis tells receiving servers that ApexMail is authorized to send email on your behalf. Only one SPF record per domain — merge if you have an existing one."),
]

# ═══════════════════════════════════════════════════════════════════════
# HALLUCINATION RESISTANCE
# ═══════════════════════════════════════════════════════════════════════
HALLUCINATION_QA = [
    ("How do I use ApexMail's built-in CRM?",
     "ApexMail **does not have a built-in CRM** — we're an email marketing and transactional email platform. However, you can integrate with popular CRMs like HubSpot or Salesforce via our API and webhooks.\n\nWould you like help setting up a CRM integration with the ApexMail API?"),
    ("Tell me about ApexMail's phone support.",
     "ApexMail **does not offer phone support**. Our support channels are:\n\n- **Email**: support@apexmail.ee\n- **Dashboard**: In-app support at https://app.apexmail.ee\n- **Docs**: https://docs.apexmail.ee\n\nEnterprise customers ($1,299/mo) get a dedicated account manager."),
    ("What's ApexMail's mobile app like?",
     "ApexMail **doesn't have a dedicated mobile app**. Our dashboard at https://app.apexmail.ee is responsive and works on mobile browsers. For programmatic access, use our API (https://api.apexmail.ee/v1) or SDKs."),
    ("Does ApexMail have a social media scheduler?",
     "No, ApexMail **does not include social media scheduling**. We focus on email marketing and transactional email. For social media, you'd need a separate tool.\n\nApexMail specializes in:\n- Email campaigns (bulk & transactional)\n- REST API & SMTP relay\n- Deliverability optimization\n- Analytics & reporting"),
    ("Can ApexMail send SMS?",
     "ApexMail **does not support SMS** — we specialize in email (transactional and marketing). For SMS, you'd need a separate service.\n\nApexMail focuses on:\n- Email via REST API & SMTP\n- Deliverability (SPF, DKIM, DMARC)\n- Analytics & templates\n- Webhooks for event tracking"),
]

# ═══════════════════════════════════════════════════════════════════════
# SMTP SUPPORT
# ═══════════════════════════════════════════════════════════════════════
SMTP_QA = [
    ("Does ApexMail support SMTP?",
     "Yes! ApexMail supports both **SMTP relay** and a **REST API**:\n\n**SMTP**: smtp.apexmail.ee (port 587/TLS or 465/SSL)\n**REST API**: https://api.apexmail.ee/v1\n\nAuthenticate with your API key (`am_live_` prefix). We recommend the REST API for richer features, but SMTP is great for integrating with existing systems."),
]


def main():
    all_qa = (
        PRICING_QA + API_QA + IDENTITY_QA + DEFLECTION_QA +
        DELIVERABILITY_QA + ACTION_QA + TECHNICAL_QA +
        HALLUCINATION_QA + SMTP_QA
    )

    examples = []
    for user_msg, assistant_msg in all_qa:
        examples.append({"text": chatml(user_msg, assistant_msg)})

    # Triple the critical pricing examples (Starter especially)
    for user_msg, assistant_msg in PRICING_QA[:10]:  # Starter variations
        examples.append({"text": chatml(user_msg, assistant_msg)})
        examples.append({"text": chatml(user_msg, assistant_msg)})

    # Double all other pricing
    for user_msg, assistant_msg in PRICING_QA[10:]:
        examples.append({"text": chatml(user_msg, assistant_msg)})

    # Double deflection (was 40% pass)
    for user_msg, assistant_msg in DEFLECTION_QA:
        examples.append({"text": chatml(user_msg, assistant_msg)})

    # Double API accuracy
    for user_msg, assistant_msg in API_QA:
        examples.append({"text": chatml(user_msg, assistant_msg)})

    print(f"Generated {len(examples)} fix examples")

    # Load existing training data for dedup
    train_path = DATA_DIR / "train.jsonl"
    with open(train_path) as f:
        existing = [json.loads(l) for l in f if l.strip()]

    seen = set()
    for ex in existing:
        h = hashlib.md5(ex["text"].encode()).hexdigest()
        seen.add(h)

    added = 0
    with open(train_path, "a") as f:
        for ex in examples:
            h = hashlib.md5(ex["text"].encode()).hexdigest()
            if h not in seen:
                seen.add(h)
                f.write(json.dumps(ex) + "\n")
                added += 1

    total = len(existing) + added
    print(f"Existing: {len(existing)}, Added: {added} (deduped), Total: {total}")


if __name__ == "__main__":
    main()
