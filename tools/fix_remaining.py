#!/usr/bin/env python3
"""Fix remaining Pro email references: L226, L533, L596, L612, L744, L758."""
import json, re

filepath = 'data/train_agent.jsonl'

with open(filepath) as f:
    lines = f.readlines()

fixes_applied = 0

# Fix specific patterns that weren't caught by v2 script
for i in range(len(lines)):
    ln = i + 1
    data = json.loads(lines[i])
    text = data['text']
    original = text
    
    # L226/L612: "the Pro plan ($65/mo) includes 50,000 emails"
    if ln in (226, 612):
        text = text.replace(
            'the Pro plan ($65/mo) includes 50,000 emails',
            'the Pro plan ($65/mo) includes 150,000 emails'
        )
        # Also fix savings comparison
        text = text.replace(
            "that would save you $27.50/month",
            "but you don't need that upgrade since 45K fits within Starter's 50K limit"
        )
    
    # L533/L596: "Pro ($65/mo)** which gives you 50,000 emails/month"
    if ln in (533, 596):
        text = text.replace(
            'Pro ($65/mo)** which gives you 50,000 emails/month',
            'Pro ($65/mo)** which gives you 150,000 emails/month'
        )
        text = text.replace('nearly double the capacity', 'triple the capacity')
    
    # L744/L758: "Pro plan at $65/mo includes 50,000 emails"
    if ln in (744, 758):
        text = text.replace(
            'Pro plan at $65/mo includes 50,000 emails',
            'Pro plan at $65/mo includes 150,000 emails'
        )
    
    if text != original:
        data['text'] = text
        lines[i] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes_applied += 1
        print(f"  Fixed L{ln}")

with open(filepath, 'w') as f:
    f.writelines(lines)

print(f"\nFixed {fixes_applied} additional lines")
