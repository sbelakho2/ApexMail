#!/usr/bin/env python3
"""Show exact text matched by deep_scan for each flagged line to identify false positives."""
import json, re

filepath = 'data/train_agent.jsonl'

with open(filepath) as f:
    lines = f.readlines()

flagged = [42, 69, 104, 115, 141, 226, 289, 316, 341, 365, 419, 533, 596, 603, 612, 666, 744, 758, 763, 766, 982, 988]

for ln in flagged:
    data = json.loads(lines[ln - 1])
    text = data['text']
    assist_parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(assist_parts)
    lower = assistant.lower()
    
    real_issues = []
    
    # Check old_pro_emails: does assistant say Pro has 50K emails?
    m1 = re.search(r'pro.*?(?:\$65|\bpro\b).*?50[,.]?000\s*(?:emails|included)', lower)
    if m1:
        start = max(0, m1.start() - 20)
        end = min(len(lower), m1.end() + 20)
        snippet = lower[start:end].replace('\n', '↵')
        # Check if 150,000 is also present nearby (already fixed)
        context = lower[max(0,m1.start()-50):min(len(lower),m1.end()+50)]
        if '150,000' in context or '150000' in context:
            real_issues.append(f"  old_pro_emails: FALSE POSITIVE (150K found nearby)")
            real_issues.append(f"    matched: ...{snippet}...")
        else:
            real_issues.append(f"  old_pro_emails: REAL ISSUE")
            real_issues.append(f"    matched: ...{snippet}...")
    
    # Check old_pro_emails_v2
    m2 = re.search(r'pro\s*\(\$65(?:/mo)?\).*?50[,.]?000\s*emails', lower)
    if m2:
        start = max(0, m2.start() - 20)
        end = min(len(lower), m2.end() + 20)
        snippet = lower[start:end].replace('\n', '↵')
        context = lower[max(0,m2.start()-50):min(len(lower),m2.end()+50)]
        if '150,000' in context or '150000' in context:
            real_issues.append(f"  old_pro_emails_v2: FALSE POSITIVE (150K found nearby)")
        else:
            real_issues.append(f"  old_pro_emails_v2: REAL ISSUE")
            real_issues.append(f"    matched: ...{snippet}...")
    
    # Check old_pro_limits: "pro ... 5 domains/team"
    m3 = re.search(r'pro.*?5\s+(?:domains?|team\s+members?)', lower)
    if m3:
        start = max(0, m3.start() - 30)
        end = min(len(lower), m3.end() + 30)
        snippet = lower[start:end].replace('\n', '↵')
        # Check if it's "vs. 5" (comparison to Starter) or "5 domains" in a Starter context
        ctx = lower[max(0,m3.start()-80):min(len(lower),m3.end()+30)]
        if 'vs.' in ctx or 'vs ' in ctx:
            real_issues.append(f"  old_pro_limits: FALSE POSITIVE (comparison 'vs 5' to Starter)")
            real_issues.append(f"    matched: ...{snippet}...")
        elif 'starter' in ctx.lower() and '25 domains' not in ctx:
            real_issues.append(f"  old_pro_limits: FALSE POSITIVE (Starter context, 5 is correct)")
            real_issues.append(f"    matched: ...{snippet}...")
        else:
            real_issues.append(f"  old_pro_limits: NEEDS REVIEW")
            real_issues.append(f"    matched: ...{snippet}...")
    
    if real_issues:
        print(f"\n{'='*60}")
        print(f"L{ln}:")
        for r in real_issues:
            print(r)

print(f"\n{'='*60}")
print("Done. Review 'REAL ISSUE' and 'NEEDS REVIEW' lines above.")
