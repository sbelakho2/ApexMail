#!/usr/bin/env python3
"""
Deep fix for remaining am_prod_ issues.
These are correction questions where the answer mentions am_prod_ —
we need to ensure the answer clearly says am_live_ is correct.
Also fixes the 3 domain auth examples to include SPF/DKIM/DMARC.
"""

import json
import re

TRAIN_FILE = "data/train.jsonl"

def extract_parts(text):
    system = user = assistant = ""
    if "<|im_start|>system\n" in text:
        system = text.split("<|im_start|>system\n")[1].split("<|im_end|>")[0]
    if "<|im_start|>user\n" in text:
        user = text.split("<|im_start|>user\n")[1].split("<|im_end|>")[0]
    if "<|im_start|>assistant\n" in text:
        assistant = text.split("<|im_start|>assistant\n")[1].split("<|im_end|>")[0]
    return system, user, assistant

def rebuild(system, user, assistant):
    return (f"<|im_start|>system\n{system}<|im_end|>\n"
            f"<|im_start|>user\n{user}<|im_end|>\n"
            f"<|im_start|>assistant\n{assistant}<|im_end|>")

def load_jsonl(path):
    examples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                examples.append(json.loads(line))
    return examples

def save_jsonl(examples, path):
    with open(path, "w") as f:
        for ex in examples:
            f.write(json.dumps(ex, ensure_ascii=False) + "\n")

# Correct answers for am_prod_ correction questions
AM_PROD_CORRECTION_ANSWER = (
    "The correct production API key prefix is **am_live_**, not am_prod_. "
    "ApexMail uses two prefixes:\n\n"
    "- **am_live_** — production keys (sends real emails)\n"
    "- **am_test_** — sandbox/test keys (safe for development)\n\n"
    "There is no `am_prod_` prefix. Always use `am_live_` for production."
)

AM_PROD_PREFIX_ANSWER = (
    "Production API keys use the prefix **am_live_** followed by a hex string. "
    "For example: `am_live_abc123def456`.\n\n"
    "Test/sandbox keys use **am_test_**. "
    "There is no `am_prod_` prefix — always use `am_live_` for production."
)

DOMAIN_AUTH_ANSWER = (
    "This is a serious **security** issue that requires immediate action.\n\n"
    "**Contact us now:** contact@apexmail.ee\n\n"
    "**Immediate actions to take:**\n"
    "1. **Check your DNS records** — verify your SPF, DKIM (2048-bit), and DMARC records are correctly configured\n"
    "2. **Revoke any compromised API keys** in your dashboard at https://app.apexmail.ee\n"
    "3. **Generate new API keys** and update your applications\n"
    "4. **Review your domain authentication** — ensure SPF includes only authorized senders, "
    "DKIM keys are not compromised, and DMARC policy is set to `reject` or `quarantine`\n"
    "5. **Contact our security team** at contact@apexmail.ee for further investigation\n\n"
    "Proper domain authentication (SPF, DKIM, DMARC) helps prevent unauthorized use of your domain."
)

def main():
    examples = load_jsonl(TRAIN_FILE)
    fixed = 0
    
    for i, ex in enumerate(examples):
        system, user, assistant = extract_parts(ex["text"])
        user_lower = user.lower()
        
        # Fix am_prod_ correction questions
        if "am_prod_" in assistant:
            if "am_prod_" in user_lower and "am_live_" in user_lower:
                # Correction question: "is it am_prod_ or am_live_?"
                examples[i]["text"] = rebuild(system, user, AM_PROD_CORRECTION_ANSWER)
                fixed += 1
            elif "prefix" in user_lower and "production" in user_lower:
                # "What prefix do production keys have?"
                examples[i]["text"] = rebuild(system, user, AM_PROD_PREFIX_ANSWER)
                fixed += 1
            else:
                # Any other context: just replace am_prod_ with am_live_
                assistant = assistant.replace("am_prod_", "am_live_")
                examples[i]["text"] = rebuild(system, user, assistant)
                fixed += 1
        
        # Fix domain auth confusion (unauthorized emails question)
        if "unauthorized" in user_lower and "domain" in user_lower:
            if "spf" not in assistant.lower() and "dkim" not in assistant.lower():
                examples[i]["text"] = rebuild(system, user, DOMAIN_AUTH_ANSWER)
                fixed += 1
    
    save_jsonl(examples, TRAIN_FILE)
    print(f"Fixed {fixed} remaining issues")
    print(f"Saved {len(examples)} examples to {TRAIN_FILE}")

if __name__ == "__main__":
    main()
