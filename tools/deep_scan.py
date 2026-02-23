#!/usr/bin/env python3
"""
DEEP SCAN: Find ALL instances of old pricing data in training examples.

Old vs New pricing:
- Starter: 25,000 → 50,000 emails; $29→$25; 3 domains→5; 3 team→5
- Pro: 50,000 → 150,000 emails; $59→$65; 5 domains→25; 5 team→10
- Growth: 100,000 → 500,000; $129→$150; 10 domains→100; 10 team→25
- Scale: 500,000 → 2,000,000; $399→$350; 50 domains→Unlimited; 25 team→50
- Enterprise: 2,000,000 → 5,000,000; $1,299→$800; 100 domains→Unlimited; 50→Unlimited

Also check for:
- Wrong overage rate ($0.50/1K instead of $0.40/1K)
- Wrong team/domain counts
- Wrong PAYG calculations
- Wrong addition
"""

import json
import re
from collections import defaultdict

filepath = 'data/train_agent.jsonl'

# OLD pricing values to flag
OLD_VALUES = {
    'Starter': {'emails': 25000, 'price': 29, 'domains': 3, 'team': 3},
    'Pro': {'emails': 50000, 'price': 59, 'domains': 5, 'team': 5},
    'Growth': {'emails': 100000, 'price': 129, 'domains': 10, 'team': 10},
    'Scale': {'emails': 500000, 'price': 399, 'domains': 50, 'team': 25},
    'Enterprise': {'emails': 2000000, 'price': 1299, 'domains': 100, 'team': 50},
}

NEW_VALUES = {
    'Starter': {'emails': 50000, 'price': 25, 'domains': 5, 'team': 5, 'contacts': 10000, 'retention': 30, 'webhooks': 5},
    'Pro': {'emails': 150000, 'price': 65, 'domains': 25, 'team': 10, 'contacts': 50000, 'retention': 60, 'webhooks': 10},
    'Growth': {'emails': 500000, 'price': 150, 'domains': 100, 'team': 25, 'contacts': 200000, 'retention': 90, 'webhooks': 25},
    'Scale': {'emails': 2000000, 'price': 350, 'domains': -1, 'team': 50, 'contacts': 500000, 'retention': 365, 'webhooks': -1},
    'Enterprise': {'emails': 5000000, 'price': 800, 'domains': -1, 'team': -1, 'contacts': -1, 'retention': 730, 'webhooks': -1},
}

issues = []
issue_categories = defaultdict(list)

with open(filepath) as f:
    lines = f.readlines()

for i, raw in enumerate(lines, 1):
    data = json.loads(raw)
    text = data['text']
    
    # Get assistant responses only (not system prompt reference docs)
    assist_parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(assist_parts)
    if not assistant:
        continue
    
    lower = assistant.lower()
    
    # ─── Check 1: Starter with 25,000 email limit ───
    # Pattern: "Starter ... 25,000 emails" or "25,000 included"
    if re.search(r'starter.*?25[,.]?000\s*(?:emails|included|email)', lower) or \
       re.search(r'25[,.]?000\s*(?:emails|included).*?starter', lower):
        issue_categories['old_starter_emails'].append(i)
        issues.append(f"L{i}: OLD Starter email limit (25K instead of 50K)")
    
    # ─── Check 2: Pro with 50,000 email limit in assistant response ───
    # Only flag when explicitly saying Pro has 50K limit, not when 50K appears inside 150,000
    if re.search(r'pro.*?(?:\$65|\bpro\b).*?(?<!1)\b50[,.]?000\s*(?:emails|included)', lower):
        issue_categories['old_pro_emails'].append(i)
        issues.append(f"L{i}: OLD Pro email limit (50K instead of 150K)")
    
    # Also catch: "Pro ($65/mo): 50,000 emails"
    if re.search(r'pro\s*\(\$65(?:/mo)?\).*?(?<!1)\b50[,.]?000\s*emails', lower):
        issue_categories['old_pro_emails_v2'].append(i)
        issues.append(f"L{i}: Pro shown as 50K emails (should be 150K)")
    
    # ─── Check 3: Wrong Starter team/domain counts ───
    if re.search(r'starter.*?3\s+(?:domains?|team\s+members?)', lower):
        issue_categories['old_starter_limits'].append(i)
        issues.append(f"L{i}: OLD Starter limits (3 domains/team instead of 5)")
    
    # ─── Check 4: Wrong Pro team/domain counts ───
    # Use word boundary to avoid matching '5' inside '25', '15', '45' etc.
    if re.search(r'\bpro\b.*?(?<!\d)5\s+(?:domains?|team\s+members?)', lower):
        # Exclude comparisons like "vs. 5" and customer-setup descriptions
        ctx = lower
        m_pro = re.search(r'\bpro\b.*?(?<!\d)5\s+(?:domains?|team\s+members?)', ctx)
        if m_pro:
            matched_ctx = ctx[max(0,m_pro.start()-20):m_pro.end()+20]
            if 'vs.' not in matched_ctx and 'vs ' not in matched_ctx:
                issue_categories['old_pro_limits'].append(i)
                issues.append(f"L{i}: OLD Pro limits (5 domains/team instead of 25 domains, 10 team)")
    
    # ─── Check 5: Wrong overage rate ($0.50/1K) ───
    if re.search(r'\$0\.50\s*(?:per|/)\s*(?:1[,.]?000|thousand)', lower):
        issue_categories['wrong_overage_rate'].append(i)
        issues.append(f"L{i}: Wrong overage rate $0.50/1K (should be $0.40/1K)")
    
    # ─── Check 6: Old plan prices ───
    if '$29' in assistant and 'starter' in lower:
        issue_categories['old_starter_price'].append(i)
        issues.append(f"L{i}: OLD Starter price $29 (should be $25)")
    if '$59' in assistant and 'pro' in lower:
        issue_categories['old_pro_price'].append(i)
        issues.append(f"L{i}: OLD Pro price $59 (should be $65)")
    if '$129' in assistant and 'growth' in lower:
        issue_categories['old_growth_price'].append(i)
        issues.append(f"L{i}: OLD Growth price $129 (should be $150)")
    if '$399' in assistant and 'scale' in lower:
        issue_categories['old_scale_price'].append(i)
        issues.append(f"L{i}: OLD Scale price $399 (should be $350)")
    if '$1,299' in assistant and 'enterprise' in lower:
        issue_categories['old_enterprise_price'].append(i)
        issues.append(f"L{i}: OLD Enterprise price $1,299 (should be $800)")
    
    # ─── Check 7: Arithmetic verification ───
    # "$X + $Y = $Z" patterns
    for m in re.finditer(r'\$([\d.]+)\s*\+\s*\$([\d.]+)\s*=\s*\*?\*?\$?([\d.]+)', assistant):
        a, b, c = float(m.group(1)), float(m.group(2)), float(m.group(3))
        expected = round(a + b, 2)
        if abs(c - expected) > 0.05 and abs(c - expected) < 100:
            # Check if it's actually a 3-term sum (look for preceding +)
            start = m.start()
            prefix = assistant[max(0,start-30):start]
            if re.search(r'\$[\d.]+\s*\+\s*$', prefix):
                continue  # 3-term sum, the regex caught the last 2 terms
            issue_categories['wrong_addition'].append(i)
            issues.append(f"L{i}: ARITHMETIC: ${a} + ${b} = ${c} (should be ${expected})")
    
    # "N ÷ 1,000 × $0.40 = $X" patterns (overage calculations)
    for m in re.finditer(r'([\d,]+)\s*÷\s*1[,.]?000\s*[×x]\s*\$([\d.]+)\s*=\s*\*?\*?\$?([\d.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        rate = float(m.group(2))
        claimed = float(m.group(3))
        expected = round(qty / 1000 * rate, 2)
        if abs(claimed - expected) > 0.05:
            issue_categories['wrong_overage_math'].append(i)
            issues.append(f"L{i}: MATH: {qty:,} ÷ 1K × ${rate} = ${claimed} (should be ${expected})")
    
    # "N extra = $X" (overage cost shorthand)
    for m in re.finditer(r'([\d,]+)\s+(?:extra|overage)\s*(?:emails?)?\s*=\s*\$?([\d.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        claimed = float(m.group(2))
        expected = round(qty * 0.40 / 1000, 2)
        if abs(claimed - expected) > 0.10 and qty > 100:
            issue_categories['wrong_overage_shorthand'].append(i)
            issues.append(f"L{i}: OVERAGE: {qty:,} extra = ${claimed} (should be ${expected} at $0.40/1K)")

# Report
print("=" * 72)
print("DEEP PRICING ACCURACY SCAN")
print("=" * 72)

print(f"\nTotal issues found: {len(issues)}")
print(f"\nBy category:")
for cat, lines_list in sorted(issue_categories.items()):
    unique_lines = sorted(set(lines_list))
    print(f"  {cat}: {len(unique_lines)} lines → {unique_lines}")

print(f"\nDetailed issues:")
seen = set()
for issue in issues:
    if issue not in seen:
        seen.add(issue)
        print(f"  {issue}")

# Flag lines that need fixing
all_problem_lines = set()
for lines_list in issue_categories.values():
    all_problem_lines.update(lines_list)
print(f"\n{'='*72}")
print(f"LINES NEEDING FIXES: {sorted(all_problem_lines)}")
print(f"Total: {len(all_problem_lines)} lines")
print(f"{'='*72}")
