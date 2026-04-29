#!/usr/bin/env python3
"""Deep verify: check overage math on L104 and L341, and all PAYG calculations."""
import json
import re

from common_paths import data_path

filepath = str(data_path("train_agent.jsonl"))

def check_overage_math(line_num, text):
    """Verify overage calculations in assistant responses."""
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    
    issues = []
    
    # Pattern: "X extra = $Y.YY" (overage at $0.40/1K)
    for m in re.finditer(r'([\d,]+)\s+extra\s*(?:emails?)?\s*=\s*\$?([\d.]+)', assistant):
        extra = int(m.group(1).replace(',', ''))
        claimed_cost = float(m.group(2))
        expected_cost = round(extra * 0.40 / 1000, 2)
        if abs(claimed_cost - expected_cost) > 0.05:
            issues.append(f"  L{line_num}: {extra:,} extra = ${claimed_cost} (should be ${expected_cost} at $0.40/1K)")
    
    # Pattern: "N × $0.0008" or "N × $0.001" (PAYG tier math)  
    for m in re.finditer(r'([\d,]+)\s*[×x]\s*\$?([\d.]+)\s*(?:=|→)\s*\$?([\d.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        rate = float(m.group(2))
        claimed_result = float(m.group(3))
        expected_result = round(qty * rate, 2)
        if abs(claimed_result - expected_result) > 0.05:
            issues.append(f"  L{line_num}: {qty:,} × ${rate} = ${claimed_result} (should be ${expected_result})")
    
    # Pattern: "$A + $B + ... + $N = $Total" (multi-term addition)
    for m in re.finditer(r'(\$[\d.]+(?:\s*\+\s*\$[\d.]+)+)\s*=\s*\*?\*?\$?([\d.]+)', assistant):
        terms_str = m.group(1)
        claimed = float(m.group(2))
        terms = [float(t) for t in re.findall(r'\$([\d.]+)', terms_str)]
        expected = round(sum(terms), 2)
        if abs(claimed - expected) > 0.05:
            terms_text = ' + '.join(f'${t}' for t in terms)
            issues.append(f"  L{line_num}: {terms_text} = ${claimed} (should be ${expected})")
    
    return issues


all_issues = []
with open(filepath) as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data['text']
        issues = check_overage_math(i, text)
        if issues:
            all_issues.extend(issues)

print("=" * 70)
print("DEEP MATH VERIFICATION (overages + PAYG arithmetic)")
print("=" * 70)
print(f"\nIssues found: {len(all_issues)}")
for issue in all_issues:
    print(issue)

if not all_issues:
    print("\n✅ All arithmetic checks out!")
