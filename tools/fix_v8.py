#!/usr/bin/env python3
"""Fix v8: Fix Free plan API limits on L234, L699, L987."""
import json

FILEPATH = 'data/train_agent.jsonl'

with open(FILEPATH) as f:
    lines = f.readlines()

fixes = 0

def fix(ln, old, new, desc):
    global fixes
    idx = ln - 1
    data = json.loads(lines[idx])
    text = data['text']
    if old in text:
        text = text.replace(old, new)
        data['text'] = text
        lines[idx] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: {desc}")
    else:
        print(f"  L{ln}: NOT FOUND — {desc}")

# L234: Free plan limit "10,000" in usage stats context
fix(234, 
    '- **Limit:** 10,000\n\nYou\'re close to your API call limit. Once you hit 10,000, API calls will be rejected.',
    '- **Limit:** 50,000\n\nYou\'ve used 8,900 of your 50,000 monthly API call limit. You still have plenty of capacity.',
    'Free API limit 10K→50K')

# Also fix the remaining count and percentage if present
fix(234,
    '- **Remaining:** 1,100\n- **Limit:** 50,000',
    '- **Remaining:** 41,100\n- **Limit:** 50,000',
    'Free API remaining 1,100→41,100')

# Fix percentage too
fix(234,
    '- **Used:** 8,900 (89%)',
    '- **Used:** 8,900 (18%)',
    'Free API used % 89→18')

# L699/L987: Free plan "10,000 monthly limit" and remaining
for ln in [699, 987]:
    fix(ln,
        'Free plan\'s **10,000 monthly limit**',
        'Free plan\'s **50,000 monthly limit**',
        'Free API limit 10K→50K')
    
    fix(ln,
        'only **1,100 API calls** remaining — you\'ve used 89%',
        '**41,100 API calls** remaining — you\'ve used 18%',
        'Free API remaining & percentage fix')

with open(FILEPATH, 'w') as f:
    f.writelines(lines)

print(f"\nTotal fixes: {fixes}")
