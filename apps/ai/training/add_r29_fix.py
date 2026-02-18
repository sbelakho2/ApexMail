#!/usr/bin/env python3
"""R29: Add exactly 2 copies of the Scale/$399 fix to R27 dataset.
Run AFTER build_r26.py + build_r27.py have already produced train.jsonl"""

import json, random

DATA = "data/train.jsonl"

data = [json.loads(l) for l in open(DATA) if l.strip()]
print(f"R27 base: {len(data)}")

# Extract system prompt
sys_text = data[0]["text"]
sp_s = sys_text.find("<|im_start|>system\n") + len("<|im_start|>system\n")
sp_e = sys_text.find("<|im_end|>", sp_s)
SP = sys_text[sp_s:sp_e]

q = "Give me the rundown on what I get for four hundred bucks a month."
a = (
    "For around $400/month, you are looking at the **Scale plan at $399/month**. "
    "Here is what you get:\n\n"
    "- **500,000 emails/month**\n"
    "- **Unlimited API calls**\n"
    "- **Priority support**\n"
    "- **Up to 15 team members**\n"
    "- **Up to 15 sending domains**\n"
    "- **Dedicated IP included**\n\n"
    "The Scale plan is our most popular choice for high-volume senders. "
    "It includes everything in the Growth plan plus dedicated IP, priority support, "
    "and significantly higher email limits.\n\n"
    "Would you like to get started with the Scale plan, or do you have any specific "
    "questions about its features?"
)

fix = {"text": f"<|im_start|>system\n{SP}<|im_end|>\n<|im_start|>user\n{q}<|im_end|>\n<|im_start|>assistant\n{a}<|im_end|>"}

data.extend([fix, fix])

random.seed(42)
random.shuffle(data)

with open(DATA, "w") as f:
    for d in data:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")

print(f"Total: {len(data)} (+2 fix copies)")
