#!/usr/bin/env python3
"""deep_clean.py — Fix ALL wrong facts in training data including system prompts."""
import json
import re

def deep_clean(text):
    """Fix all known wrong facts everywhere in the text."""
    # URLs
    text = text.replace("apexmail.com", "apexmail.ee")
    text = text.replace("apexmail.dev", "apexmail.ee")
    text = text.replace("apexmail.io", "apexmail.ee")
    
    # Old wrong system prompt: Starter ($25/mo, 10,000 emails)
    text = text.replace("$25/mo, 10,000 emails", "$29/mo, 25,000 emails")
    text = text.replace("$25/mo, 10k emails", "$29/mo, 25,000 emails")
    text = text.replace("$25/mo,10,000", "$29/mo, 25,000")
    text = text.replace("Starter ($25/", "Starter ($29/")
    text = text.replace("Starter $25/", "Starter $29/")
    
    # Old wrong Pro: $49/mo
    text = text.replace("Pro ($49/mo", "Pro ($59/mo")
    text = text.replace("Pro $49/", "Pro $59/")
    
    # Old wrong Business plan → Growth
    text = text.replace("Business ($99/mo", "Growth ($129/mo")
    text = text.replace("Business $99/", "Growth $129/")
    
    # Old wrong Enterprise: $249/mo
    text = text.replace("Enterprise ($249/mo", "Enterprise ($1,299/mo")
    
    # Fix Starter email limits: various wrong values → 25,000
    # Pattern: "Starter" ... "10,000 emails" or "10k emails"  
    text = re.sub(r'(Starter[^.\n]{0,50}?)10,000(\s*emails)', r'\g<1>25,000\2', text)
    text = re.sub(r'(Starter[^.\n]{0,50}?)10k(\s*emails)', r'\g<1>25,000\2', text)
    text = re.sub(r'(Starter[^.\n]{0,50}?)5,000(\s*emails)', r'\g<1>25,000\2', text)
    text = re.sub(r'(Starter[^.\n]{0,50}?)3,000(\s*emails)', r'\g<1>25,000\2', text)
    
    # Fix in markdown tables: | Starter | $29 | 10,000 |
    text = re.sub(r'(\|\s*Starter\s*\|\s*\$29[^|]*\|\s*)10[,.]?000', r'\g<1>25,000', text)
    text = re.sub(r'(\|\s*Starter\s*\|\s*\$29[^|]*\|\s*)10k', r'\g<1>25,000', text, flags=re.IGNORECASE)
    
    # Fix Pro email in tables: | Pro | $59 | 30,000 | → 100,000
    text = re.sub(r'(\|\s*Pro\s*\|\s*\$59[^|]*\|\s*)30[,.]?000', r'\g<1>100,000', text)
    
    # Fix Growth in tables: | Growth | $129 | 100,000 | → 500,000  
    text = re.sub(r'(\|\s*Growth\s*\|\s*\$129[^|]*\|\s*)100[,.]?000', r'\g<1>500,000', text)
    
    # Fix Scale in tables: | Scale | $399 | 300,000 | → 2,000,000
    text = re.sub(r'(\|\s*Scale\s*\|\s*\$399[^|]*\|\s*)300[,.]?000', r'\g<1>2,000,000', text)
    text = re.sub(r'(\|\s*Scale\s*\|\s*\$399[^|]*\|\s*)500[,.]?000', r'\g<1>2,000,000', text)
    text = re.sub(r'(\|\s*Scale\s*\|\s*\$399[^|]*\|\s*)1[,.]?000[,.]?000', r'\g<1>2,000,000', text)
    
    # Fix API key prefixes
    text = re.sub(r'prefix is `test_`', 'prefix is `am_test_`', text)
    text = re.sub(r'prefix is `live_`', 'prefix is `am_live_`', text)
    text = re.sub(r'prefix `test_`', 'prefix `am_test_`', text)
    text = re.sub(r'prefix `live_`', 'prefix `am_live_`', text)
    
    return text


def process_file(path):
    print(f"Processing {path}...")
    with open(path) as f:
        items = [json.loads(line) for line in f]
    
    fixed = 0
    for item in items:
        original = item["text"]
        item["text"] = deep_clean(item["text"])
        if item["text"] != original:
            fixed += 1
    
    with open(path, 'w') as f:
        for item in items:
            f.write(json.dumps(item) + '\n')
    
    print(f"  Fixed {fixed}/{len(items)} examples")
    return len(items)


def verify(path):
    with open(path) as f:
        content = f.read()
    
    checks = {
        "apexmail.com": content.count("apexmail.com"),
        "apexmail.dev": content.count("apexmail.dev"),
        "apexmail.io": content.count("apexmail.io"),
        "apexmail.ee": content.count("apexmail.ee"),
        "$25/mo": content.count("$25/mo"),
        "$49/mo": content.count("$49/mo"),
        "$99/mo": content.count("$99/mo"),
        "$249/mo": content.count("$249/mo"),
        "Starter 10,000": len(re.findall(r'Starter[^.\n]{0,50}?10,000', content)),
        "Starter 25,000": len(re.findall(r'Starter[^.\n]{0,50}?25,000', content)),
        "Starter 10k": len(re.findall(r'Starter[^.\n]{0,50}?10k', content, re.IGNORECASE)),
        "$29": content.count("$29"),
        "$59": content.count("$59"),
        "$129": content.count("$129"),
        "$399": content.count("$399"),
        "$1,299": content.count("$1,299"),
        "Bel Consulting": content.count("Bel Consulting"),
        "2022": content.count("2022"),
    }
    
    print(f"\nVerification for {path}:")
    bad_keys = ["apexmail.com", "apexmail.dev", "apexmail.io", "$25/mo", "$49/mo", "$99/mo", "$249/mo", "Starter 10,000", "Starter 10k"]
    for key, count in checks.items():
        is_bad = key in bad_keys
        status = "❌" if (is_bad and count > 0) else "✅"
        print(f"  {status} {key}: {count}")


if __name__ == "__main__":
    process_file("data/train.jsonl")
    process_file("data/val.jsonl")
    verify("data/train.jsonl")
