#!/usr/bin/env python3
"""Final comprehensive pricing sweep of both JSONL files."""
import re

wrong_prices = {
    "Starter": [19, 25, 39],
    "Pro": [49, 69, 79, 99],
    "Growth": [99, 149, 199],
    "Scale": [299, 349, 499],
    "Enterprise": [999, 1499, 1999],
}

wrong_limits = {
    "Pro": [100000, 75000, 25000],
    "Growth": [200000, 150000, 50000],
    "Scale": [250000, 1000000],
    "Enterprise": [1000000, 5000000],
}

files = [
    ("train_agent.jsonl", "data/train_agent.jsonl"),
    ("train.jsonl", "apps/ai/training/data/train.jsonl"),
]

for fname, fpath in files:
    with open(fpath) as f:
        content = f.read()
    print(f"\n=== {fname} ===")
    
    issues = []
    
    # Check for wrong plan prices
    for plan, wrongs in wrong_prices.items():
        for wp in wrongs:
            pattern = rf"{plan}.{{0,20}}\${wp}(?:\b|/)"
            for m in re.finditer(pattern, content):
                s = max(0, m.start() - 10)
                e = min(len(content), m.end() + 20)
                ctx = content[s:e].replace("\n", " ")
                issues.append(f"  WRONG PRICE? {plan}=${wp}: ...{ctx}...")
    
    # Check wrong email limits near plan names
    for plan, wrongs in wrong_limits.items():
        for wl in wrongs:
            pattern = rf"{plan}.{{0,30}}{wl:,}"
            for m in re.finditer(pattern, content):
                s = max(0, m.start() - 10)
                e = min(len(content), m.end() + 20)
                ctx = content[s:e].replace("\n", " ")
                issues.append(f"  WRONG LIMIT? {plan}={wl:,}: ...{ctx}...")
    
    # Check wrong SLAs
    for bad_sla in ["99.99%", "99.95%"]:
        for m in re.finditer(re.escape(bad_sla), content):
            s = max(0, m.start() - 40)
            e = min(len(content), m.end() + 40)
            ctx = content[s:e].replace("\n", " ")
            issues.append(f"  BAD SLA {bad_sla}: ...{ctx}...")
    
    # Check wrong SDK name
    for m in re.finditer(r"@apexmail/sdk(?!-)", content):
        s = max(0, m.start() - 20)
        e = min(len(content), m.end() + 20)
        ctx = content[s:e].replace("\n", " ")
        issues.append(f"  WRONG SDK: ...{ctx}...")
    
    # Check infrastructure leaks
    for term in ["Hetzner", "BullMQ", "GGUF", "vLLM"]:
        for m in re.finditer(term, content, re.IGNORECASE):
            s = max(0, m.start() - 30)
            e = min(len(content), m.end() + 30)
            ctx = content[s:e].replace("\n", " ")
            issues.append(f"  INFRA LEAK {term}: ...{ctx}...")
    
    # Check wrong retention days
    wrong_retention = [
        ("Free", "14"),      # should be 7
        ("Free", "30"),      # should be 7
        ("Starter", "7"),    # should be 30
        ("Starter", "14"),   # should be 30
        ("Pro", "30"),       # should be 60
        ("Pro", "90"),       # should be 60
    ]
    for plan, days in wrong_retention:
        pattern = rf"{plan}.{{0,30}}{days}.{{0,10}}day"
        for m in re.finditer(pattern, content):
            s = max(0, m.start() - 10)
            e = min(len(content), m.end() + 10)
            ctx = content[s:e].replace("\n", " ")
            issues.append(f"  WRONG RETENTION? {plan} {days}d: ...{ctx}...")
    
    if issues:
        for i in issues:
            print(i)
    else:
        print("  ALL CLEAN")

print("\nDone.")
