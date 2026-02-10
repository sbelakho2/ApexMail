#!/usr/bin/env python3
"""final_sweep.py — Fix ALL remaining wrong pricing values."""
import json
import re

for fname in ["data/train.jsonl", "data/val.jsonl"]:
    items = []
    fixed = 0
    with open(fname) as f:
        for line in f:
            item = json.loads(line)
            orig = item["text"]
            t = item["text"]
            
            # Fix $25/month (not just $25/mo)
            t = t.replace("$25/month", "$29/month")
            t = t.replace("$49/month", "$59/month")
            t = t.replace("$99/month", "$129/month")
            
            # Fix remaining Starter + 10,000 emails patterns
            t = re.sub(r"(Starter[^\n]{0,80}?)10,000(\s*emails)", r"\g<1>25,000\2", t)
            
            # Fix "225,000" (glitch from double-replacement)
            t = t.replace("225,000 emails", "25,000 emails")
            
            # Fix $25 near Starter (broader pattern)
            t = re.sub(r"Starter[^\n]*?\$25\b", lambda m: m.group(0).replace("$25", "$29"), t)
            
            item["text"] = t
            if t != orig:
                fixed += 1
            items.append(item)
    
    with open(fname, "w") as f:
        for item in items:
            f.write(json.dumps(item) + "\n")
    
    print(f"{fname}: fixed {fixed}")

# Final verification
with open("data/train.jsonl") as f:
    content = f.read()

bad_keys = ["$25/mo", "$25/month", "$49/mo", "$49/month", "$99/mo", "$99/month", "225,000 emails"]
print("\nRemaining bad values:")
all_clean = True
for k in bad_keys:
    v = content.count(k)
    status = "FAIL" if v > 0 else "OK"
    if v > 0:
        all_clean = False
    print(f"  [{status}] {k}: {v}")

pat = re.compile(r"Starter[^\n]{0,50}?10,000")
starter_10k = len(pat.findall(content))
if starter_10k > 0:
    all_clean = False
print(f"  [{'FAIL' if starter_10k > 0 else 'OK'}] Starter+10,000: {starter_10k}")

pat2 = re.compile(r"Starter[^\n]{0,50}?25,000")
print(f"\nCorrect values:")
print(f"  $29: {content.count('$29')}")
print(f"  $59: {content.count('$59')}")
print(f"  Starter+25,000: {len(pat2.findall(content))}")

if all_clean:
    print("\nALL CLEAN! Ready for training.")
else:
    print("\nSome bad values remain.")
