#!/usr/bin/env python3
"""Fix wrong contact limits in train.jsonl and pricing/retention bugs in train_agent.jsonl."""
import re

# ============================================================
# FIX 1: train.jsonl — wrong contact limits
# ============================================================
print("=== FIX 1: train.jsonl contact limits ===")

fpath = "apps/ai/training/data/train.jsonl"
with open(fpath) as f:
    content = f.read()

# Wrong:  Free: 500, Pro: 15,000, Growth: 50,000, Scale: 200,000
# Correct: Free: 100, Pro: 10,000, Growth: 25,000, Scale: 100,000

wrong_contacts = (
    "- Free: 500\\n"
    "- Starter: 5,000\\n"
    "- Pro: 15,000\\n"
    "- Growth: 50,000\\n"
    "- Scale: 200,000\\n"
    "- Enterprise: Unlimited"
)
correct_contacts = (
    "- Free: 100\\n"
    "- Starter: 5,000\\n"
    "- Pro: 10,000\\n"
    "- Growth: 25,000\\n"
    "- Scale: 100,000\\n"
    "- Enterprise: Unlimited"
)

c_before = content.count(wrong_contacts)
print(f"  Before: {c_before} occurrences of wrong contact limits")

content = content.replace(wrong_contacts, correct_contacts)

c_after = content.count(correct_contacts)
print(f"  After: {c_after} occurrences of correct contact limits")

with open(fpath, "w") as f:
    f.write(content)
print(f"  Fixed {c_before} occurrences in train.jsonl")

# Also check for bold markdown variant
wrong_contacts_bold = (
    "- **Free**: 500\\n"
    "- **Starter**: 5,000\\n"
    "- **Pro**: 15,000\\n"
    "- **Growth**: 50,000\\n"
    "- **Scale**: 200,000\\n"
    "- **Enterprise**: Unlimited"
)
correct_contacts_bold = (
    "- **Free**: 100\\n"
    "- **Starter**: 5,000\\n"
    "- **Pro**: 10,000\\n"
    "- **Growth**: 25,000\\n"
    "- **Scale**: 100,000\\n"
    "- **Enterprise**: Unlimited"
)

with open(fpath) as f:
    content = f.read()

c_before2 = content.count(wrong_contacts_bold)
if c_before2 > 0:
    content = content.replace(wrong_contacts_bold, correct_contacts_bold)
    with open(fpath, "w") as f:
        f.write(content)
    print(f"  Also fixed {c_before2} bold-markdown variant occurrences")
else:
    print("  No bold-markdown variant found (OK)")

# ============================================================
# FIX 2: train_agent.jsonl — wrong plan prices
# ============================================================
print("\n=== FIX 2: train_agent.jsonl pricing ===")

fpath2 = "data/train_agent.jsonl"
with open(fpath2) as f:
    content = f.read()

# 2a: Wrong pricing table: Starter $25/mo | 10,000 => $25/mo | 50,000
replacements = [
    # Table format: Starter $25/mo | 10,000 => $25/mo | 50,000
    ("| **Starter** | $25/mo | 10,000 |", "| **Starter** | $25/mo | 50,000 |"),
    # Table format: Pro $50/mo | 50,000 — price wrong (emails wrong)
    ("| **Pro** | $50/mo | 50,000 |", "| **Pro** | $65/mo | 150,000 |"),
    # Table format: Growth $100/mo | 100,000 — price wrong (emails wrong)
    ("| **Growth** | $100/mo | 100,000 |", "| **Growth** | $150/mo | 500,000 |"),
    # Upgrade recommendation: Starter ($25/mo) for 100,000 API calls
    ("Upgrade to Starter** ($25/mo) for 100,000 API calls", "Upgrade to Starter** ($25/mo) for 250,000 API calls"),
    # Inline mentions: Pro plan ($50/mo)
    ("Pro plan ($50/mo)", "Pro plan ($65/mo)"),
    # Plan: Growth ($100/mo)
    ("Plan: Growth ($100/mo)", "Plan: Growth ($150/mo)"),
    # Growth plan ($100/mo)
    ("Growth plan ($100/mo)", "Growth plan ($150/mo)"),
    # Alternatively, the Pro plan ($50/mo) includes
    ("the Pro plan ($50/mo) includes", "the Pro plan ($65/mo) includes"),
]

total_fixed = 0
for old, new in replacements:
    cnt = content.count(old)
    if cnt > 0:
        content = content.replace(old, new)
        print(f"  '{old}' => '{new}': {cnt} replacements")
        total_fixed += cnt

# 2b: Wrong retention — fabricated body/event retention
# Pattern: "Starter | **3 days** | 30 days" => just "Starter | **30 days**"
# More complex — need to see exact patterns first
retention_replacements = [
    # Table: | Starter | **3 days** | 30 days |
    ("| Starter | **3 days** | 30 days |", "| Starter | **30 days** |"),
    ("| Growth | **7 days** | 60 days |", "| Growth | **90 days** |"),
    ("| Scale | **14 days** | 90 days |", "| Scale | **365 days** |"),
    ("| Enterprise | **30 days** | 365 days |", "| Enterprise | **730 days** |"),
    # List format: Starter: 3 days events / 30 days analytics
    ("Starter: 3 days events / 30 days analytics", "Starter: 30 days"),
    ("Growth: 7 days / 60 days", "Growth: 90 days"),
    ("Scale: 14 days / 90 days", "Scale: 365 days"),
    ("Enterprise: 30 days / 365 days", "Enterprise: 730 days"),
    # Simple list: | Starter | 3 days |
    ("| Starter | 3 days |", "| Starter | 30 days |"),
    ("| Growth | 7 days |", "| Growth | 90 days |"),
    ("| Scale | 14 days |", "| Scale | 365 days |"),
    ("| Enterprise | 30 days |", "| Enterprise | 730 days |"),
]

for old, new in retention_replacements:
    cnt = content.count(old)
    if cnt > 0:
        content = content.replace(old, new)
        print(f"  '{old}' => '{new}': {cnt} replacements")
        total_fixed += cnt

print(f"\n  Total replacements in train_agent.jsonl: {total_fixed}")

with open(fpath2, "w") as f:
    f.write(content)

print("\nAll fixes applied.")
