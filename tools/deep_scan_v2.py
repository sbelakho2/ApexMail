#!/usr/bin/env python3
"""Deep scan for remaining errors: API calls, old email limits, old prices."""
import json, re

with open('data/train_agent.jsonl') as f:
    lines = f.readlines()

# Wrong API call values to search for (old/wrong values)
wrong_api = {
    'Free': ['10,000 API', '10000 API', '10K API'],
    'Starter': ['250,000 API', '250000 API', '250K API'],
    'Pro': ['500,000 API', '500000 API', '500K API'],
    'Growth': ['1,000,000 API', '1000000 API', '1M API'],
    'Scale': ['5,000,000 API', '5000000 API', '5M API'],
    'Enterprise': ['20,000,000 API', '20000000 API', '20M API'],
}

# Old/wrong email limits
old_emails = {
    'Starter': ['25,000 emails', '25K emails', '25,000 email'],
    'Pro': ['100,000 emails', '100K emails'],
    'Growth': ['250,000 emails', '250K emails'],
    'Scale': ['1,000,000 emails', '1M emails'],
    'Enterprise': ['2,000,000 emails', '2M emails'],
}

issues = []
for i, line in enumerate(lines, 1):
    data = json.loads(line)
    text = data['text']
    
    # Extract assistant portions only
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    atxt = '\n'.join(assists)
    
    # 1. Wrong API calls
    for plan, wrongs in wrong_api.items():
        for w in wrongs:
            if w in atxt:
                # Check context: is this actually about this plan?
                # Find location and check 100 chars before
                idx = atxt.find(w)
                context = atxt[max(0,idx-100):idx+len(w)+50]
                issues.append((i, f'WRONG_API: {plan} — found "{w}"', context.replace('\n', ' | ')))

    # 2. Old email limits  
    for plan, wrongs in old_emails.items():
        for w in wrongs:
            if w in atxt:
                idx = atxt.find(w)
                context = atxt[max(0,idx-100):idx+len(w)+50]
                issues.append((i, f'OLD_EMAIL: {plan} — found "{w}"', context.replace('\n', ' | ')))

    # 3. Check for "100,000 API" attributed to Starter (should be 500,000)
    if '100,000 API' in atxt:
        idx = atxt.find('100,000 API')
        context = atxt[max(0,idx-100):idx+60]
        # Only flag if near "Starter"
        if 'Starter' in context or 'starter' in context:
            issues.append((i, 'WRONG_API: Starter — found "100,000 API" near Starter', context.replace('\n', ' | ')))

    # 4. Free plan API calls specifically
    if re.search(r'(?:Free|free).*?10,000 API', atxt, re.DOTALL):
        issues.append((i, 'FREE_API: Free plan shows 10,000 API (should be 50,000)', ''))
    if '**10,000 API calls' in atxt:
        idx = atxt.find('**10,000 API calls')
        context = atxt[max(0,idx-80):idx+60]
        issues.append((i, 'FREE_API: bold "10,000 API calls" (should be 50,000)', context.replace('\n', ' | ')))

print(f"Found {len(issues)} potential issues:\n")
for ln, desc, ctx in sorted(issues):
    print(f"  L{ln}: {desc}")
    if ctx:
        print(f"         Context: ...{ctx[:150]}...")
    print()
