#!/usr/bin/env python3
"""R32: Substitute ONE example in R27 dataset with a 300K→Scale fix.
Keeps dataset size at exactly 3207 (no additions).
Run AFTER build_r26.py + build_r27.py have already produced train.jsonl"""

import json, random

DATA = "data/train.jsonl"

data = [json.loads(l) for l in open(DATA) if l.strip()]
print(f"R27 base: {len(data)}")

# Extract system prompt from first example
sys_text = data[0]["text"]
sp_s = sys_text.find("<|im_start|>system\n") + len("<|im_start|>system\n")
sp_e = sys_text.find("<|im_end|>", sp_s)
SP = sys_text[sp_s:sp_e]

# The fix: 300K emails should map to Scale plan
q = "I send 300,000 emails/month. What plan do you recommend?"
a = (
    "For **300,000 emails per month**, the **Scale plan at $399/month** is the right fit. "
    "Here is why:\n\n"
    "- The Growth plan only includes **100,000 emails/month** — not enough for your volume\n"
    "- The **Scale plan includes 500,000 emails/month**, comfortably covering your 300,000\n"
    "- You also get **unlimited API calls**, **priority support**, up to **15 team members**, "
    "and a **dedicated IP**\n\n"
    "At 300,000 emails, Scale gives you plenty of headroom without overage charges.\n\n"
    "Would you like to get started with the Scale plan?"
)

fix = {"text": f"<|im_start|>system\n{SP}<|im_end|>\n<|im_start|>user\n{q}<|im_end|>\n<|im_start|>assistant\n{a}<|im_end|>"}

# Find the most similar/redundant example to replace
# Look for pricing examples that mention Growth plan or similar volume questions
candidates = []
for i, d in enumerate(data):
    text = d["text"]
    user_start = text.find("<|im_start|>user\n")
    user_end = text.find("<|im_end|>", user_start)
    if user_start >= 0 and user_end >= 0:
        user_q = text[user_start + len("<|im_start|>user\n"):user_end].strip()
        # Find pricing/plan recommendation questions as substitution candidates
        if any(kw in user_q.lower() for kw in ["300,000", "300k", "what plan"]) and "email" in user_q.lower():
            candidates.append((i, user_q))

print(f"Substitution candidates: {len(candidates)}")
for idx, q_text in candidates:
    print(f"  [{idx}] {q_text[:80]}")

if candidates:
    # Replace the first matching candidate
    replace_idx = candidates[0][0]
    print(f"\nReplacing example at index {replace_idx}")
    data[replace_idx] = fix
else:
    # If no exact match, find a generic plan recommendation duplicate
    print("No exact match — looking for generic plan recommendation duplicates...")
    plan_qs = []
    for i, d in enumerate(data):
        text = d["text"]
        user_start = text.find("<|im_start|>user\n")
        user_end = text.find("<|im_end|>", user_start)
        if user_start >= 0 and user_end >= 0:
            user_q = text[user_start + len("<|im_start|>user\n"):user_end].strip().lower()
            if "what plan" in user_q and "recommend" in user_q:
                plan_qs.append((i, user_q))
    
    print(f"Plan recommendation questions: {len(plan_qs)}")
    for idx, q_text in plan_qs[:5]:
        print(f"  [{idx}] {q_text[:80]}")
    
    if plan_qs:
        # Replace the last one (least likely to be critical)
        replace_idx = plan_qs[-1][0]
        print(f"\nReplacing example at index {replace_idx}")
        data[replace_idx] = fix
    else:
        # Last resort: just replace the last example
        replace_idx = len(data) - 1
        print(f"\nNo candidates found — replacing last example at index {replace_idx}")
        data[replace_idx] = fix

# Reshuffle with same seed as R27 builds use
random.seed(42)
random.shuffle(data)

with open(DATA, "w") as f:
    for d in data:
        f.write(json.dumps(d, ensure_ascii=False) + "\n")

print(f"Total: {len(data)} (substituted 1 example, same size)")
