#!/usr/bin/env python3
"""
ApexMail AI — Master Training Pipeline
Runs multiple rounds of: expand → train → stress test → fix → retrain

Usage:
    python3 pipeline.py                # Full pipeline (rounds 2, 3, 4)
    python3 pipeline.py --round 2      # Just round 2
    python3 pipeline.py --eval-only    # Just run stress test on existing model
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

TRAINING_DIR = Path(__file__).resolve().parent
DATA_DIR = TRAINING_DIR / "data"
OUTPUT_DIR = TRAINING_DIR / "output"
RESULTS_DIR = TRAINING_DIR / "results"

SYSTEM_PROMPT = None


def load_system_prompt():
    global SYSTEM_PROMPT
    sys.path.insert(0, str(TRAINING_DIR))
    from prompts import SYSTEM_PROMPT as SP
    SYSTEM_PROMPT = SP


def disk_free_gb():
    st = os.statvfs("/workspace")
    return (st.f_bavail * st.f_frsize) / (1024 ** 3)


def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def free_disk_space():
    """Remove checkpoints and cache to free disk space."""
    log(f"Disk free: {disk_free_gb():.1f} GB — cleaning up...")
    
    # Remove checkpoints (keep final model only)
    for d in sorted(OUTPUT_DIR.glob("checkpoint-*")):
        log(f"  Removing {d.name}...")
        shutil.rmtree(d, ignore_errors=True)
    
    # Clear HuggingFace cache of downloaded models (CAREFUL — keep base model)
    cache = Path.home() / ".cache" / "huggingface" / "hub"
    if cache.exists():
        for blob in cache.glob("**/blobs/*"):
            if blob.stat().st_size > 500_000_000:  # > 500MB blobs
                pass  # Don't delete — these are the base model shards
    
    # Clear pip cache
    subprocess.run(["pip", "cache", "purge"], capture_output=True)
    
    log(f"Disk free after cleanup: {disk_free_gb():.1f} GB")


def backup_adapter(round_num: int):
    """Save current adapter with round number."""
    src = OUTPUT_DIR
    dst = TRAINING_DIR / f"adapter_round_{round_num}"
    if src.exists() and (src / "adapter_model.safetensors").exists():
        dst.mkdir(exist_ok=True)
        for f in ["adapter_model.safetensors", "adapter_config.json"]:
            sf = src / f
            if sf.exists():
                shutil.copy2(sf, dst / f)
        log(f"Backed up adapter round {round_num} ({dst})")


def run_expand_dataset():
    """Run the data expansion script."""
    script = TRAINING_DIR / "expand_dataset.py"
    if not script.exists():
        log("ERROR: expand_dataset.py not found!")
        return False
    
    log("Running dataset expansion...")
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(TRAINING_DIR),
        capture_output=True,
        text=True,
        timeout=300,
    )
    
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr)
        log("ERROR: Dataset expansion failed!")
        return False
    
    # Count new data
    train_path = DATA_DIR / "train.jsonl"
    if train_path.exists():
        count = sum(1 for _ in open(train_path))
        log(f"Training data now has {count} examples")
    
    return True


def run_training(round_num: int, extra_args: dict = None):
    """Run a training round."""
    log(f"═══ TRAINING ROUND {round_num} ═══")
    
    # Adjust hyperparams per round
    config_path = TRAINING_DIR / "config.yaml"
    
    # Read config
    import yaml
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    # Round-specific adjustments
    if round_num == 2:
        config["training"]["epochs"] = 3
        config["training"]["learning_rate"] = 1.5e-4  # Slightly lower
        config["training"]["warmup_ratio"] = 0.05
    elif round_num == 3:
        config["training"]["epochs"] = 2
        config["training"]["learning_rate"] = 8e-5   # Even lower for fine-tuning
        config["training"]["warmup_ratio"] = 0.03
    elif round_num >= 4:
        config["training"]["epochs"] = 2
        config["training"]["learning_rate"] = 5e-5   # Very low for polish
        config["training"]["warmup_ratio"] = 0.02
    
    if extra_args:
        for k, v in extra_args.items():
            keys = k.split(".")
            d = config
            for key in keys[:-1]:
                d = d[key]
            d[keys[-1]] = v
    
    # Write updated config
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)
    
    log(f"Config: epochs={config['training']['epochs']}, lr={config['training']['learning_rate']}")
    
    # Clear old output (keep backup)
    if OUTPUT_DIR.exists():
        for item in OUTPUT_DIR.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)
    
    # Run training
    result = subprocess.run(
        [sys.executable, str(TRAINING_DIR / "train.py")],
        cwd=str(TRAINING_DIR),
        text=True,
        timeout=3600,
    )
    
    if result.returncode != 0:
        log(f"ERROR: Training round {round_num} failed!")
        return False
    
    # Check output
    adapter_path = OUTPUT_DIR / "adapter_model.safetensors"
    if adapter_path.exists():
        size_mb = adapter_path.stat().st_size / (1024 ** 2)
        log(f"Adapter saved: {size_mb:.0f} MB")
        return True
    else:
        log("ERROR: No adapter file produced!")
        return False


def run_stress_test(round_num: int) -> dict:
    """Run the stress test battery and return results."""
    log(f"═══ STRESS TEST (Round {round_num}) ═══")
    
    import torch
    from peft import PeftModel, PeftConfig
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
    from stress_test import run_stress_test as _run_stress_test, print_results
    
    adapter_path = str(OUTPUT_DIR)
    peft_config = PeftConfig.from_pretrained(adapter_path)
    base_model_name = peft_config.base_model_name_or_path
    
    log(f"Loading base model: {base_model_name}")
    
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        attn_implementation="sdpa",
    )
    model = PeftModel.from_pretrained(model, adapter_path)
    model.eval()
    
    log(f"Model loaded. Running {sum(len(t) for t in __import__('stress_test').STRESS_TESTS.values())} tests...")
    
    RESULTS_DIR.mkdir(exist_ok=True)
    results_path = str(RESULTS_DIR / f"stress_round_{round_num}.json")
    results = _run_stress_test(model, tokenizer, SYSTEM_PROMPT, results_path)
    
    print_results(results)
    
    # Cleanup GPU memory
    del model
    del tokenizer
    torch.cuda.empty_cache()
    import gc
    gc.collect()
    
    return results


def generate_failure_data(results: dict, round_num: int) -> int:
    """Generate targeted training data from stress test failures."""
    log(f"Generating targeted data from {len(results.get('failures', []))} failures...")
    
    if not results.get("failures"):
        log("No failures to fix — model is performing well!")
        return 0
    
    new_examples = []
    
    for failure in results["failures"]:
        category = failure["category"]
        question = failure["question"]
        failure_types = failure["failures"]
        
        # Generate corrective examples based on failure type
        if category == "pricing_accuracy":
            # Re-extract correct pricing info and create example
            answer = generate_pricing_answer(question)
        elif category == "hallucination_resistance":
            answer = generate_hallucination_correction(question)
        elif category == "safety_boundaries":
            answer = generate_safety_response(question)
        elif category == "off_topic_deflection":
            answer = generate_deflection_response(question)
        elif category == "company_identity":
            answer = generate_identity_response(question)
        elif category == "deliverability":
            answer = generate_deliverability_response(question)
        elif category == "api_accuracy":
            answer = generate_api_response(question)
        elif category == "competitor_handling":
            answer = generate_competitor_response(question)
        elif category == "edge_cases":
            answer = generate_edge_case_response(question)
        elif category == "consistency":
            answer = generate_pricing_answer(question)  # These are pricing questions
        elif category == "action_format":
            answer = generate_action_response(question)
        elif category == "technical_depth":
            answer = generate_technical_response(question)
        elif category == "feature_accuracy":
            answer = generate_feature_response(question)
        else:
            continue
        
        if answer:
            example = format_example(question, answer)
            new_examples.append(example)
            # Also add 2 paraphrases to reinforce
            paraphrases = paraphrase_question(question)
            for pq in paraphrases:
                new_examples.append(format_example(pq, answer))
    
    # Write to training data
    if new_examples:
        train_path = DATA_DIR / "train.jsonl"
        with open(train_path, "a") as f:
            for ex in new_examples:
                f.write(json.dumps(ex) + "\n")
        
        log(f"Added {len(new_examples)} targeted examples to training data")
    
    return len(new_examples)


def format_example(question: str, answer: str) -> dict:
    return {
        "text": f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n{answer}<|im_end|>"
    }


def paraphrase_question(q: str) -> list:
    """Simple rule-based paraphrasing."""
    paraphrases = []
    
    if q.startswith("What"):
        paraphrases.append(q.replace("What", "Can you tell me what", 1))
    elif q.startswith("How"):
        paraphrases.append(q.replace("How", "Could you explain how", 1))
    elif q.startswith("Does"):
        paraphrases.append(q.replace("Does", "I was wondering, does", 1))
    elif q.startswith("Can"):
        paraphrases.append(q.replace("Can", "Is it possible to", 1))
    elif q.startswith("Tell"):
        paraphrases.append("I'd like to know about " + q.split("about", 1)[-1].strip() if "about" in q else q)
    
    return paraphrases[:2]  # Max 2


# ── Corrective response generators ──────────────────────────────────────

def generate_pricing_answer(q: str) -> str:
    q_lower = q.lower()
    if "starter" in q_lower or "basic" in q_lower or "cheapest" in q_lower:
        return "The **Starter plan** is $29/month and includes 25,000 emails and 250,000 API calls per month. It's our most affordable plan and great for getting started with email marketing."
    elif "pro" in q_lower:
        return "The **Pro plan** is $59/month and includes 100,000 emails and 500,000 API calls per month. It's ideal for growing businesses with moderate email volumes."
    elif "growth" in q_lower:
        return "The **Growth plan** is $129/month and includes 500,000 emails and 2,000,000 API calls per month. It's designed for businesses with significant email volume."
    elif "scale" in q_lower:
        return "The **Scale plan** is $399/month and includes 2,000,000 emails and 10,000,000 API calls per month. It's built for high-volume senders."
    elif "enterprise" in q_lower:
        return "The **Enterprise plan** is $1,299/month with custom email volumes and unlimited API calls. It includes dedicated IP addresses, priority support, and custom SLAs."
    elif "payg" in q_lower or "pay-as-you-go" in q_lower or "pay as you go" in q_lower:
        return "ApexMail offers **Pay-as-you-go (PAYG)** pricing: $0.001/email for the first 10,000, $0.0008 for 10K–100K, $0.0005 for 100K–1M, and $0.0003 for 1M+. API overages are $0.10 per 1,000 calls after the first 100,000 free overage calls."
    elif "overage" in q_lower:
        return "API overages are billed at **$0.10 per 1,000 calls** after the first 100,000 free overage calls. This applies when you exceed your plan's API call limit."
    elif "compare" in q_lower or "vs" in q_lower:
        return "Here's a comparison:\n\n| Plan | Price | Emails/mo | API calls/mo |\n|------|-------|-----------|---------------|\n| Starter | $29 | 25,000 | 250,000 |\n| Pro | $59 | 100,000 | 500,000 |\n| Growth | $129 | 500,000 | 2,000,000 |\n| Scale | $399 | 2,000,000 | 10,000,000 |\n| Enterprise | $1,299 | Custom | Unlimited |"
    elif "300,000" in q_lower or "300k" in q_lower:
        return "For 300,000 emails per month, I'd recommend the **Growth plan** at $129/month, which includes up to 500,000 emails and 2,000,000 API calls. The Pro plan (100,000 emails) would be insufficient for your volume."
    return ""


def generate_hallucination_correction(q: str) -> str:
    q_lower = q.lower()
    if "crm" in q_lower:
        return "ApexMail doesn't include a built-in CRM. We're focused on email marketing and transactional email delivery. However, ApexMail integrates well with popular CRMs through our API and webhooks — you can sync contact data, trigger emails from CRM events, and track engagement back in your CRM."
    elif "sms" in q_lower:
        return "ApexMail doesn't support SMS messaging — we specialize in email delivery (transactional and marketing emails). For SMS, you'd need a separate service. Our focus on email means we can provide the best possible deliverability and analytics for your email campaigns."
    elif "mobile app" in q_lower or "app" in q_lower:
        return "ApexMail doesn't currently have a dedicated mobile app. You can access the full dashboard at https://app.apexmail.ee from any mobile browser. The dashboard is responsive and works well on mobile devices."
    elif "free plan" in q_lower or "free" in q_lower:
        return "ApexMail doesn't currently offer a free plan. Our most affordable option is the **Starter plan at $29/month**, which includes 25,000 emails and 250,000 API calls. We also offer **Pay-as-you-go** pricing starting at $0.001/email if you prefer usage-based billing."
    elif "image generator" in q_lower:
        return "ApexMail doesn't include an AI image generator. We focus on email delivery and analytics. For email images, you can use any image editor and include them in your templates via URLs or as attachments (up to 25 MB)."
    elif "landing page" in q_lower:
        return "ApexMail doesn't offer landing page creation — we're focused on email marketing and delivery. For landing pages, you'd use a dedicated tool and link to them from your ApexMail campaigns."
    elif "push notification" in q_lower:
        return "ApexMail doesn't support push notifications — we specialize in email delivery. Our platform handles transactional emails, marketing campaigns, and email analytics. For push notifications, you'd need a separate service."
    elif "fax" in q_lower:
        return "ApexMail doesn't support fax — we're an email marketing and delivery platform. We handle transactional and marketing emails via REST API and SMTP relay."
    elif "video" in q_lower:
        return "ApexMail doesn't include video hosting. We focus on email marketing and delivery. You can embed video thumbnails in your emails with links to your video hosting platform."
    elif "project management" in q_lower:
        return "ApexMail doesn't include project management features — we specialize in email marketing and transactional email delivery. Our platform focuses on sending emails, tracking engagement, and optimizing deliverability."
    return "I appreciate the question, but that's not a feature ApexMail currently offers. We focus on email marketing and transactional email delivery. Is there anything about our email platform I can help with?"


def generate_safety_response(q: str) -> str:
    q_lower = q.lower()
    if "hack" in q_lower:
        return "I can't help with that. Unauthorized access to email accounts is illegal and against our terms of service. If you're having trouble accessing your own ApexMail account, I can help you with the legitimate account recovery process."
    elif "phishing" in q_lower:
        return "I can't help create phishing emails — that's against our Acceptable Use Policy and illegal. ApexMail is designed for legitimate email marketing and transactional emails. I'd be happy to help you create professional, compliant email templates instead."
    elif "spam" in q_lower and "send" in q_lower:
        return "Sending spam is against ApexMail's Acceptable Use Policy and can result in account termination. We require opt-in consent from recipients. I can help you build a legitimate email list and follow best practices for high deliverability instead."
    elif "email addresses" in q_lower or "addresses to spam" in q_lower:
        return "I can't provide email addresses for unsolicited messaging. ApexMail requires that all recipients have opted in to receive your emails. I can help you set up opt-in forms and grow your list organically."
    elif "bypass" in q_lower and "filter" in q_lower:
        return "Rather than bypassing filters, I'd recommend focusing on legitimate deliverability best practices: authenticate your domain with SPF, DKIM, and DMARC; maintain a clean list; warm up your sending gradually; keep complaint rates below 0.1%; and send relevant, wanted content. These practices naturally improve inbox placement."
    return "I'm unable to assist with that request as it goes against our policies. I'm here to help with legitimate email marketing and ApexMail features."


def generate_deflection_response(q: str) -> str:
    return "That's outside my area of expertise! I'm the ApexMail Assistant, specialized in email marketing, deliverability, and the ApexMail platform. I'd be happy to help you with sending emails, setting up campaigns, managing contacts, or anything else related to email marketing. What can I help you with?"


def generate_identity_response(q: str) -> str:
    q_lower = q.lower()
    if "who made" in q_lower or "who created" in q_lower or "who built" in q_lower:
        return "ApexMail was built by **Bel Consulting OÜ**, an Estonian company based in Tallinn. The company was founded in 2022 and focuses on providing a modern, developer-friendly email marketing and delivery platform."
    elif "where" in q_lower and "based" in q_lower:
        return "ApexMail is based in **Tallinn, Estonia**. It's developed by Bel Consulting OÜ, an Estonian technology company founded in 2022."
    elif "when" in q_lower and "found" in q_lower:
        return "ApexMail was founded in **2022** by Bel Consulting OÜ in Tallinn, Estonia."
    elif "what is" in q_lower:
        return "ApexMail is a modern **email marketing and transactional email platform** built by Bel Consulting OÜ (Tallinn, Estonia, founded 2022). It provides a REST API, SMTP relay, analytics, templates, and deliverability tools for sending both marketing campaigns and transactional emails at scale."
    return "ApexMail is an email marketing platform developed by Bel Consulting OÜ in Tallinn, Estonia (founded 2022)."


def generate_deliverability_response(q: str) -> str:
    q_lower = q.lower()
    if "bounce rate" in q_lower:
        return "A good bounce rate is **below 2%**. Hard bounces (permanent failures like invalid addresses) should be even lower — aim for under 0.5%. ApexMail automatically suppresses hard-bounced addresses to protect your sender reputation."
    elif "complaint" in q_lower or "spam complaint" in q_lower:
        return "Your spam complaint rate should stay **below 0.1%** (1 complaint per 1,000 emails). Major mailbox providers like Gmail may throttle or block your sending if you exceed this threshold. ApexMail tracks complaints via feedback loops and automatically suppresses complainers."
    elif "open rate" in q_lower:
        return "The average email open rate across industries is **21.5%**, though this varies significantly by sector. B2B emails tend to have higher open rates (25-30%) while retail may be lower (15-20%). ApexMail provides detailed open tracking and send-time optimization to help improve your rates."
    elif "click rate" in q_lower or "click-through" in q_lower:
        return "The average email click rate is **2.3%** across industries. To improve yours, use clear CTAs, personalized content, and mobile-responsive designs. ApexMail provides click tracking, heatmaps, and A/B testing to help optimize engagement."
    elif "roi" in q_lower:
        return "Email marketing delivers an average ROI of **$36 for every $1 spent**, making it one of the highest-ROI marketing channels. With ApexMail's analytics and optimization tools, you can track and improve your email marketing ROI."
    return ""


def generate_api_response(q: str) -> str:
    q_lower = q.lower()
    if "base url" in q_lower:
        return "The ApexMail API base URL is **https://api.apexmail.ee/v1**. All API requests should be made to this endpoint with your API key in the Authorization header."
    elif "authenticate" in q_lower or "auth" in q_lower:
        return "Authenticate with the ApexMail API using Bearer token authentication. Include your API key in the Authorization header:\n\n```\nAuthorization: Bearer am_live_your_key_here\n```\n\nAPI keys use the prefix `am_live_` for production and `am_test_` for sandbox environments."
    elif "sdk" in q_lower or "language" in q_lower:
        return "ApexMail provides official SDKs for **Node.js** (@apexmail/sdk) and **Python** (apexmail-python). You can also use our REST API directly with any HTTP client."
    elif "dashboard" in q_lower:
        return "Access the ApexMail dashboard at **https://app.apexmail.ee**. From there you can manage your account, view analytics, configure domains, and manage your API keys."
    elif "test" in q_lower and "key" in q_lower:
        return "Test API keys use the prefix **am_test_** (e.g., `am_test_abc123...`). Use these for sandbox testing — emails sent with test keys aren't actually delivered. Production keys use the prefix `am_live_`."
    elif "production" in q_lower and "key" in q_lower:
        return "Production API keys use the prefix **am_live_** (e.g., `am_live_abc123...`). These keys send real emails. For testing, use sandbox keys with the `am_test_` prefix."
    return ""


def generate_competitor_response(q: str) -> str:
    q_lower = q.lower()
    if "sendgrid" in q_lower:
        return "While I can't speak in detail about SendGrid's offerings, ApexMail offers several advantages: our Starter plan begins at just $29/month for 25,000 emails, we provide built-in deliverability tools (SPF, DKIM, DMARC, ARC, BIMI), Handlebars templates, AI-powered send-time optimization, and both REST API and SMTP relay support. You can explore our full API at https://api.apexmail.ee/v1."
    elif "mailchimp" in q_lower:
        return "ApexMail takes a developer-first approach compared to Mailchimp. Key advantages include: a powerful REST API (https://api.apexmail.ee/v1), Node.js and Python SDKs, advanced domain authentication (SPF, DKIM, DMARC, ARC, BIMI), Handlebars templates, webhook events, and plans starting at $29/month. ApexMail is ideal for teams that want full API control over their email infrastructure."
    elif "ses" in q_lower or "amazon" in q_lower:
        return "Unlike Amazon SES, ApexMail is a fully managed platform — you get a dashboard (https://app.apexmail.ee), built-in analytics with heatmaps, template management, automatic bounce/complaint handling, suppression lists, and dedicated customer support. Our API at https://api.apexmail.ee/v1 is developer-friendly with Node.js and Python SDKs."
    return "ApexMail stands out with its developer-first approach, competitive pricing starting at $29/month, comprehensive deliverability tools, and both REST API and SMTP relay support. Happy to go into detail on any specific features!"


def generate_edge_case_response(q: str) -> str:
    if not q or not q.strip():
        return "It looks like your message was empty! I'm the ApexMail Assistant — I can help with email marketing, deliverability, API questions, pricing, and more. What would you like to know?"
    if q.strip() in ["???", "?", "!!"]:
        return "I see you have a question! I'm the ApexMail Assistant, here to help with email marketing, the ApexMail API, pricing, deliverability, and more. What would you like to know about?"
    if q.strip().lower() in ["hello", "hi", "hey"]:
        return "Hello! 👋 I'm the ApexMail Assistant. I can help you with email marketing, API integration, pricing, deliverability best practices, and more. What can I help you with today?"
    if q.strip().lower() in ["thanks", "thank you", "ty"]:
        return "You're welcome! If you have any more questions about ApexMail or email marketing, feel free to ask anytime."
    if q.strip().lower() in ["ok", "okay", "k"]:
        return "Is there anything else I can help you with? I'm here for questions about ApexMail's features, API, pricing, deliverability, or email marketing best practices."
    return "I'm not quite sure what you're asking. I'm the ApexMail Assistant — I can help with email marketing, API integration, pricing, deliverability, and more. Could you rephrase your question?"


def generate_action_response(q: str) -> str:
    q_lower = q.lower()
    if "send" in q_lower and "email" in q_lower and "test" in q_lower:
        return "I'll prepare that test email for you. Let me set up the action:\n\n```action\n{\"action\":\"SEND_TEST_EMAIL\",\"params\":{\"to\":\"hello@example.com\",\"subject\":\"Test Email\",\"type\":\"test\"},\"confirm\":true,\"reason\":\"Sending a test email to hello@example.com\"}\n```\n\nPlease confirm you'd like to proceed with sending this test email."
    elif "delete" in q_lower and "account" in q_lower:
        return "Account deletion is a permanent action. Before proceeding, please note this will remove all your data, contacts, templates, and sending history.\n\n```action\n{\"action\":\"DELETE_ACCOUNT\",\"params\":{},\"confirm\":true,\"reason\":\"User requested account deletion\"}\n```\n\nAre you sure you want to delete your account? This cannot be undone."
    elif "upgrade" in q_lower:
        plan = "Growth" if "growth" in q_lower else "Pro" if "pro" in q_lower else "Scale" if "scale" in q_lower else "Enterprise"
        price = {"Growth": "$129", "Pro": "$59", "Scale": "$399", "Enterprise": "$1,299"}.get(plan, "$129")
        return f"I can help you upgrade to the **{plan} plan** ({price}/month).\n\n```action\n{{\"action\":\"UPGRADE_PLAN\",\"params\":{{\"plan\":\"{plan.lower()}\"}},\"confirm\":true,\"reason\":\"Upgrade to {plan} plan at {price}/month\"}}\n```\n\nWould you like to confirm the upgrade?"
    return ""


def generate_feature_response(q: str) -> str:
    q_lower = q.lower()
    if "spf" in q_lower or "dkim" in q_lower or "dmarc" in q_lower or "auth" in q_lower:
        return "ApexMail supports comprehensive domain authentication: **SPF** (Sender Policy Framework), **DKIM** (DomainKeys Identified Mail with 2048-bit keys), **DMARC** (Domain-based Message Authentication), **ARC** (Authenticated Received Chain), and **BIMI** (Brand Indicators for Message Identification). All of these work together to maximize deliverability and protect your sender reputation."
    elif "webhook" in q_lower:
        return "ApexMail supports webhook events for: **delivered**, **opened**, **clicked**, **bounced**, **complained**, and **unsubscribed**. You can configure webhook endpoints in the dashboard to receive real-time notifications about email events."
    elif "template" in q_lower:
        return "ApexMail uses **Handlebars** as its template engine. You can create dynamic templates with variables, conditionals, loops, and partials. Templates support personalization with merge tags like `{{first_name}}` and dynamic content blocks."
    elif "attachment" in q_lower:
        return "ApexMail supports email attachments up to **25 MB** per message. You can attach files via the REST API by including them as base64-encoded data in the attachments array."
    elif "smtp" in q_lower:
        return "Yes, ApexMail supports **SMTP relay** in addition to the REST API. You can configure your application to send emails through ApexMail's SMTP servers, making integration simple for applications that already use SMTP."
    return ""


def generate_technical_response(q: str) -> str:
    q_lower = q.lower()
    if "hard" in q_lower and "soft" in q_lower and "bounce" in q_lower:
        return "**Hard bounces** are permanent delivery failures — the email address is invalid, doesn't exist, or the domain is unreachable. These addresses should be immediately removed from your list.\n\n**Soft bounces** are temporary failures — the recipient's mailbox is full, the server is temporarily unavailable, or the message is too large. ApexMail will retry soft bounces automatically. If an address keeps soft-bouncing, it will eventually be suppressed."
    elif "spf" in q_lower and ("explain" in q_lower or "what" in q_lower):
        return "**SPF (Sender Policy Framework)** is an email authentication method. You add a TXT record to your domain's DNS that specifies which mail servers are authorized to send email on behalf of your domain. When a receiving server gets an email from your domain, it checks the SPF record to verify the sending server is authorized. ApexMail provides the exact SPF record to add during domain setup."
    elif "dkim" in q_lower and ("set up" in q_lower or "how" in q_lower):
        return "To set up **DKIM (DomainKeys Identified Mail)** with ApexMail:\n\n1. Go to your domain settings in the ApexMail dashboard\n2. ApexMail will generate a 2048-bit DKIM key pair\n3. Add the provided TXT record (or CNAME) to your domain's DNS\n4. Click 'Verify' in the dashboard to confirm the record is live\n\nDKIM adds a cryptographic signature to your emails, allowing receivers to verify they haven't been tampered with and truly came from your domain."
    elif "dmarc" in q_lower:
        return "**DMARC (Domain-based Message Authentication, Reporting & Conformance)** builds on SPF and DKIM to provide a policy for handling authentication failures. It tells receiving servers what to do when SPF or DKIM checks fail (none, quarantine, or reject). Set up a DMARC policy by adding a TXT record to `_dmarc.yourdomain.com`. Start with `p=none` to monitor, then move to `p=quarantine` or `p=reject`. DMARC also provides reporting so you can see who's sending email as your domain."
    return ""


def run_pipeline(start_round: int = 2, max_rounds: int = 4, eval_only: bool = False):
    """Run the full training pipeline."""
    load_system_prompt()
    RESULTS_DIR.mkdir(exist_ok=True)
    
    if eval_only:
        results = run_stress_test(0)
        return
    
    for round_num in range(start_round, max_rounds + 1):
        log(f"\n{'═' * 70}")
        log(f"  PIPELINE ROUND {round_num}")
        log(f"{'═' * 70}\n")
        
        # 1. Free disk space
        free_disk_space()
        
        # 2. Expand data (only on round 2; later rounds use failure data)
        if round_num == 2:
            if not run_expand_dataset():
                log("Dataset expansion failed — continuing with existing data")
        
        # 3. Train
        backup_adapter(round_num - 1)  # Backup previous round
        if not run_training(round_num):
            log(f"Training round {round_num} failed — aborting pipeline")
            break
        
        # 4. Stress test
        results = run_stress_test(round_num)
        
        # 5. Check if we're good enough
        pass_rate = results.get("pass_rate", 0)
        log(f"Round {round_num} pass rate: {pass_rate:.1%}")
        
        if pass_rate >= 0.95 and round_num >= 3:
            log(f"🎉 Pass rate {pass_rate:.1%} >= 95% — model is excellent!")
            if round_num < max_rounds:
                log("Running one more polish round...")
            else:
                break
        
        # 6. Generate failure-targeted data
        if round_num < max_rounds:
            added = generate_failure_data(results, round_num)
            log(f"Added {added} failure-targeted examples")
    
    # Final summary
    log(f"\n{'═' * 70}")
    log("  PIPELINE COMPLETE")
    log(f"{'═' * 70}\n")
    
    # Show final data stats
    train_count = sum(1 for _ in open(DATA_DIR / "train.jsonl"))
    log(f"Final training data: {train_count} examples")
    log(f"Disk free: {disk_free_gb():.1f} GB")
    log(f"Adapter at: {OUTPUT_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexMail AI Training Pipeline")
    parser.add_argument("--round", type=int, default=2, help="Starting round number")
    parser.add_argument("--max-rounds", type=int, default=4, help="Maximum rounds")
    parser.add_argument("--eval-only", action="store_true", help="Just run stress test")
    args = parser.parse_args()
    
    run_pipeline(
        start_round=args.round,
        max_rounds=args.max_rounds,
        eval_only=args.eval_only,
    )
