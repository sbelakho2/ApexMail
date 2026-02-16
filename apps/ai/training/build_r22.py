#!/usr/bin/env python3
"""Build R22 dataset: base 3009 + 60 fix examples = 3069 total."""
import json, random, sys, os
random.seed(42)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from prompts import SYSTEM_PROMPT

def make_chatml(user_q, assistant_a):
    return json.dumps({"text": (
        f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user_q}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant_a}<|im_end|>"
    )})

fixes = []

# ── FIX 1: Colloquial pricing "four hundred bucks" -> Scale $399 ──
price_qs = [
    "Give me the rundown on what I get for four hundred bucks a month.",
    "What do I get for four hundred dollars a month?",
    "Tell me about the four hundred dollar plan.",
    "I can spend about four hundred bucks per month on email. What plan is that?",
    "What does the $400 tier include?",
    "For roughly four hundred a month, what email plan do you have?",
]
price_answers = [
    "For approximately $400/month, you are looking at our **Scale plan at $399/month**. It includes:\n\n- **500,000 emails/month**\n- **10,000,000 API calls/month**\n- **25 team members**\n- **25 sending domains**\n- **3 dedicated IPs included**\n- **SSO (Single Sign-On)**\n- **Advanced analytics**\n- **A/B testing**\n- **Send-time optimisation (AI)**\n- **Priority support**\n\nThe Scale plan is our second-highest tier, perfect for high-volume senders who need enterprise-grade features without custom pricing.",
    "That would be our **Scale plan** at **$399/month**! Here is what you get:\n\n- 500,000 emails per month\n- 10 million API calls per month\n- 25 team members and 25 sending domains\n- 3 dedicated IP addresses\n- SSO, A/B testing, send-time optimisation\n- Advanced analytics and priority support\n\nIt is an excellent plan for businesses with significant email volume. Need even more? Our Enterprise plan at $1,299/month offers custom limits and dedicated support.",
    "Four hundred dollars a month corresponds to our **Scale plan ($399/month)**. Here is the full breakdown:\n\n| Feature | Scale Plan |\n|---------|------------|\n| Price | $399/mo |\n| Emails | 500,000/mo |\n| API calls | 10,000,000/mo |\n| Team members | 25 |\n| Sending domains | 25 |\n| Dedicated IPs | 3 included |\n| SSO | Yes |\n| A/B testing | Yes |\n| Send-time optimisation | Yes |\n| Priority support | Yes |\n\nWould you like help getting started with the Scale plan?",
    "At around four hundred bucks, you are looking at our **Scale plan priced at $399/month**. It is designed for high-volume senders and includes 500,000 emails/month, 10 million API calls, 25 team members, 25 sending domains, 3 dedicated IPs, SSO, A/B testing, AI send-time optimisation, advanced analytics, and priority support.",
    "The plan closest to $400 is our **Scale plan at $399/month**. It comes with 500,000 emails, 10M API calls, 25 team members, 25 domains, 3 dedicated IPs, SSO, A/B testing, send-time optimisation, and priority support. It is our most popular plan for growing businesses with high email volumes.",
    "For four hundred a month, our **Scale plan ($399/month)** is the perfect fit. You will get:\n\n- **500,000 emails/month**\n- **10,000,000 API calls/month**\n- **25 team members** and **25 sending domains**\n- **3 dedicated IP addresses**\n- **SSO**, **A/B testing**, **send-time optimisation**\n- **Advanced analytics** and **priority support**\n\nIt includes everything in Growth ($129) plus SSO, more domains/IPs, and higher limits.",
]

for q, a in zip(price_qs, price_answers):
    fixes.append(make_chatml(q, a))

# ── FIX 2: create_list action for "Create contact list" ──
list_qs = [
    'Create a new contact list called "VIP Customers".',
    'Make a list named "VIP Customers" for me.',
    "I need a new contact list: VIP Customers.",
    "Set up a new mailing list called VIP Customers.",
    'Add a new list named "VIP Customers" to my account.',
    "Please create a contact list with the name VIP Customers.",
]
list_answers = [
    'I will create a new contact list called "VIP Customers" for you. Since this is a medium-risk action that modifies your account, I need your confirmation first.\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Creating a new contact list named VIP Customers"}\n```\n\nPlease confirm you would like me to proceed with creating this list.',
    'Sure! I can create that contact list for you. Here is the action:\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Create a new contact list called VIP Customers"}\n```\n\nThis will create a new empty contact list named "VIP Customers" in your account. Please confirm to proceed.',
    'I will set up a new contact list named "VIP Customers". This requires your confirmation as it modifies your account:\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Creating new contact list: VIP Customers"}\n```\n\nOnce confirmed, the list will be created and you can start adding contacts to it. Would you like to proceed?',
    'Absolutely! Here is the action to create your new contact list:\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Creating a new mailing list named VIP Customers"}\n```\n\nThis is a medium-risk action since it modifies your account structure. Please confirm and I will create the "VIP Customers" list right away.',
    'Let me create that list for you. Since creating a contact list is a medium-risk action, I need your approval:\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Adding a new contact list named VIP Customers to the account"}\n```\n\nOnce you confirm, the "VIP Customers" list will be ready for you to add contacts. Shall I proceed?',
    'I will create a contact list named "VIP Customers" for you:\n\n```action\n{"action":"create_list","params":{"name":"VIP Customers"},"confirm":true,"reason":"Creating contact list: VIP Customers"}\n```\n\nPlease confirm this action. After the list is created, you can add contacts individually or import them from a CSV file.',
]

for q, a in zip(list_qs, list_answers):
    fixes.append(make_chatml(q, a))

# Multiply by 5 copies for reinforcement
all_fixes = fixes * 5
random.shuffle(all_fixes)

# Build final dataset: base + fixes
with open("data/train_base_r17q_from_r17p.jsonl") as f:
    base_lines = [line.strip() for line in f if line.strip()]

all_lines = base_lines + all_fixes
random.shuffle(all_lines)

with open("data/train.jsonl", "w") as f:
    for line in all_lines:
        f.write(line + "\n")

# Create val.jsonl (first 30 lines)
with open("data/val.jsonl", "w") as f:
    for line in all_lines[:30]:
        f.write(line + "\n")

print(f"Base: {len(base_lines)}")
print(f"R22 fixes: {len(all_fixes)}")
print(f"Total train.jsonl: {len(all_lines)}")
print(f"val.jsonl: 30")
