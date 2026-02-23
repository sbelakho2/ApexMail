#!/usr/bin/env python3
"""Check specific lines for remaining real errors after v6 fixes."""
import json, re

with open('data/train_agent.jsonl') as f:
    lines = f.readlines()

# Lines to check for real issues
check_lines = [60, 224, 241, 244, 299, 304, 312, 318, 321, 324, 348, 354, 357, 
               421, 427, 444, 446, 503, 515, 525, 620, 672, 699, 715, 733, 738, 
               783, 788, 813, 829, 856, 863, 888, 900, 901, 905, 906, 908, 915,
               929, 932, 937, 948, 949, 964, 987, 1020, 1026]

for ln in check_lines:
    data = json.loads(lines[ln-1])
    text = data['text']
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    atxt = '\n'.join(assists)
    
    # Check for specific error patterns
    issues = []
    
    # Enterprise API: should be "Unlimited", not 20M or 20,000,000
    ent_api_wrong = re.findall(r'Enterprise.*?(\d[\d,]*\s*(?:API|api)\s*calls)', atxt)
    for match in ent_api_wrong:
        if 'Unlimited' not in match:
            issues.append(f"Enterprise API: {match}")
    
    # Growth showing 20M (cascading bug)
    growth_20m = re.findall(r'Growth.*?20[,.]?000[,.]?000\s*API', atxt)
    if growth_20m:
        issues.append(f"Growth shows 20M API (should be 5M)")
    growth_20m2 = re.findall(r'Growth.*?20M\s*API', atxt)
    if growth_20m2:
        issues.append(f"Growth shows 20M API (short)")
    
    # Enterprise email: should be 5M not 2M  
    if 'Enterprise' in atxt:
        ent_2m = re.findall(r'Enterprise.*?(?:2,000,000|2M)\s*email', atxt, re.DOTALL)
        if ent_2m:
            issues.append("Enterprise email shows 2M (should be 5M)")
    
    # Starter API showing wrong (should be 500K)
    if 'Starter' in atxt:
        starter_api = re.findall(r'Starter.*?(\d[\d,]*)\s*API\s*calls', atxt, re.DOTALL)
        for val in starter_api:
            num = int(val.replace(',', ''))
            if num != 500000 and num != 50000:  # 50K is Free plan, not Starter
                issues.append(f"Starter API shows {val} (should be 500,000)")
    
    if issues:
        print(f"\nL{ln}: ISSUES FOUND:")
        for issue in issues:
            print(f"  - {issue}")
        # Show relevant snippet
        for issue_type in ['20,000,000 API', '20M API', '2,000,000 emails', '2M email']:
            if issue_type in atxt:
                idx = atxt.find(issue_type)
                snippet = atxt[max(0,idx-100):idx+len(issue_type)+50]
                print(f"  Context: ...{snippet.replace(chr(10), ' | ')}...")
