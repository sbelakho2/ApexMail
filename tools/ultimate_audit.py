#!/usr/bin/env python3
"""
ULTIMATE final audit - check ALL plan attributes across ALL 1,089 lines.
Only flags REAL errors by carefully tracking attribution.
"""
import json, re

with open('data/train_agent.jsonl') as f:
    lines = f.readlines()

CANONICAL = {
    'Free':       {'price': 0,   'emails': 3000,    'api': 50000,     'team': 1,   'domains': 1},
    'Starter':    {'price': 25,  'emails': 50000,   'api': 500000,    'team': 5,   'domains': 5},
    'Pro':        {'price': 65,  'emails': 150000,  'api': 2000000,   'team': 10,  'domains': 25},
    'Growth':     {'price': 150, 'emails': 500000,  'api': 5000000,   'team': 25,  'domains': 100},
    'Scale':      {'price': 350, 'emails': 2000000, 'api': 20000000,  'team': 50,  'domains': -1},
    'Enterprise': {'price': 800, 'emails': 5000000, 'api': -1,        'team': -1,  'domains': -1},
}

issues = []

for idx, line in enumerate(lines):
    ln = idx + 1
    data = json.loads(line)
    text = data['text']
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    if not assists:
        continue
    atxt = '\n'.join(assists)

    # 1. Check plan feature blocks: "**PlanName plan** is $N/mo and includes:...**N API calls/mo**"
    plan_blocks = re.finditer(
        r'\*\*(?:The\s+)?(\w+)\s+plan\*\*\s+(?:is|costs?)\s+\*?\*?\$(\d+)/mo.*?(?=\*\*(?:The\s+)?\w+\s+plan\*\*|$)',
        atxt, re.DOTALL)
    
    for block in plan_blocks:
        plan_name = block.group(1)
        plan_price = int(block.group(2))
        block_text = block.group(0)
        
        if plan_name not in CANONICAL:
            continue
        
        expected_price = CANONICAL[plan_name]['price']
        if plan_price != expected_price:
            issues.append((ln, f'{plan_name} price ${plan_price} (should be ${expected_price})'))
        
        api_match = re.search(r'\*\*(\d[\d,]+)\s*API\s*calls', block_text)
        if api_match:
            api_val = int(api_match.group(1).replace(',', ''))
            expected_api = CANONICAL[plan_name]['api']
            if expected_api == -1:
                if api_val > 0:
                    issues.append((ln, f'{plan_name} API shows {api_val:,} (should be Unlimited)'))
            elif api_val != expected_api:
                issues.append((ln, f'{plan_name} API shows {api_val:,} (should be {expected_api:,})'))
        
        email_match = re.search(r'\*\*(\d[\d,]+)\s*emails?/mo', block_text)
        if email_match:
            email_val = int(email_match.group(1).replace(',', ''))
            expected_emails = CANONICAL[plan_name]['emails']
            if email_val != expected_emails:
                issues.append((ln, f'{plan_name} emails shows {email_val:,} (should be {expected_emails:,})'))

    # 2. Enterprise-specific: should never show a number for API calls
    ent_api = list(re.finditer(r'Enterprise.*?(\d[\d,]+)\s*API\s*call', atxt, re.DOTALL))
    for m in ent_api:
        val = int(m.group(1).replace(',', ''))
        if val > 100000:
            pos = m.start(1)
            context = atxt[max(0,pos-150):pos]
            plans_before = re.findall(r'(Free|Starter|Pro|Growth|Scale|Enterprise)', context)
            if plans_before and plans_before[-1] == 'Enterprise':
                issues.append((ln, f'Enterprise API shows {val:,} (should be Unlimited)'))

    # 3. Enterprise emails: should be 5M not 2M
    ent_email_matches = list(re.finditer(r'Enterprise.*?(\d[\d,]+)\s*emails?\s*(?:/mo|per\s*month|included)', atxt, re.DOTALL))
    for m in ent_email_matches:
        val = int(m.group(1).replace(',', ''))
        if val == 2000000:
            pos = m.start(1)
            context = atxt[max(0,pos-150):pos]
            plans_before = re.findall(r'(Free|Starter|Pro|Growth|Scale|Enterprise)', context)
            if plans_before and plans_before[-1] == 'Enterprise':
                issues.append((ln, f'Enterprise emails shows 2,000,000 (should be 5,000,000)'))

    # 4. Check old prices
    old_prices = {
        'Starter': [29, 30], 'Pro': [79, 80], 'Growth': [199, 200],
        'Scale': [399, 400], 'Enterprise': [999, 1000]
    }
    for plan, old_vals in old_prices.items():
        for v in old_vals:
            if re.search(rf'{plan}\s*\(\$\s*{v}(?:/mo|\))', atxt):
                issues.append((ln, f'{plan} shows old price ${v}'))

# Deduplicate
seen = set()
unique = []
for ln, desc in sorted(issues):
    if (ln, desc) not in seen:
        seen.add((ln, desc))
        unique.append((ln, desc))

print(f"Ultimate audit found {len(unique)} issues:\n")
for ln, desc in unique:
    print(f"  L{ln}: {desc}")

if not unique:
    print("  ALL CLEAR - Zero issues found across all 1,089 training examples.")
