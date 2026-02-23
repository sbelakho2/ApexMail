#!/usr/bin/env python3
"""
COMPREHENSIVE SCAN v2: Find ALL old pricing values across ALL plans in assistant responses.
Canonical source: docs/pricing.md (February 2026 / effective March 2026)
"""
import json, re
from collections import defaultdict

filepath = 'data/train_agent.jsonl'

# Canonical values
PLANS = {
    'Free':       {'price': 0,   'emails': 3000,     'domains': 1,   'team': 1,   'contacts': 500,     'retention': 7,   'webhooks': 0},
    'Starter':    {'price': 25,  'emails': 50000,    'domains': 5,   'team': 5,   'contacts': 10000,   'retention': 30,  'webhooks': 5},
    'Pro':        {'price': 65,  'emails': 150000,   'domains': 25,  'team': 10,  'contacts': 50000,   'retention': 60,  'webhooks': 10},
    'Growth':     {'price': 150, 'emails': 500000,   'domains': 100, 'team': 25,  'contacts': 200000,  'retention': 90,  'webhooks': 25},
    'Scale':      {'price': 350, 'emails': 2000000,  'domains': -1,  'team': 50,  'contacts': 500000,  'retention': 365, 'webhooks': -1},
    'Enterprise': {'price': 800, 'emails': 5000000,  'domains': -1,  'team': -1,  'contacts': -1,      'retention': 730, 'webhooks': -1},
}

# OLD values to flag
OLD = {
    'Starter':    {'emails': [25000], 'price': [29], 'domains': [3, 25], 'team': [3]},
    'Pro':        {'emails': [50000], 'price': [59], 'domains': [5], 'team': [5]},
    'Growth':     {'emails': [100000], 'price': [129], 'domains': [10], 'team': [10]},
    'Scale':      {'emails': [500000], 'price': [399], 'domains': [50], 'team': [25]},
    'Enterprise': {'emails': [2000000], 'price': [1299], 'domains': [100], 'team': [50]},
}

issues = defaultdict(list)

def fmt_num(n):
    """Formats for regex matching."""
    if n >= 1000000:
        return [f"{n:,}", f"{n//1000000}M", f"{n//1000000},{str(n%1000000).zfill(3)}" if n % 1000000 else f"{n//1000000},000,000"]
    elif n >= 1000:
        return [f"{n:,}", f"{n//1000}K", f"{n//1000},{str(n%1000).zfill(3)}" if n % 1000 else f"{n//1000},000"]
    return [str(n)]

def build_number_pattern(n):
    """Build regex that matches various representations of a number."""
    patterns = []
    if n >= 1000000:
        m = n // 1000000
        patterns.extend([f"{n:,}", f"(?<!\\d){m}[,.]?000[,.]?000", f"{m}M", f"{m} million"])
    elif n >= 1000:
        k = n // 1000
        patterns.extend([f"{n:,}", f"(?<!\\d){k}[,.]?000(?!,000)", f"{k}K", f"{k} thousand"])
    else:
        patterns.append(f"(?<!\\d){n}(?!\\d)")
    return '|'.join(patterns)

with open(filepath) as f:
    lines = f.readlines()

for i, raw in enumerate(lines, 1):
    data = json.loads(raw)
    text = data['text']
    
    # Extract assistant responses only
    assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(assists)
    if not assistant:
        continue
    lower = assistant.lower()
    
    for plan_name, old_vals in OLD.items():
        plan_lower = plan_name.lower()
        
        # Check old email limits
        for old_email in old_vals.get('emails', []):
            num_pat = build_number_pattern(old_email)
            # Match: "Plan ... old_number emails" or table rows with plan + old number
            pat = rf'{plan_lower}.*?(?:{num_pat})\s*(?:emails|included|email)'
            m = re.search(pat, lower, re.DOTALL)
            if m:
                ctx = lower[max(0,m.start()-10):min(len(lower),m.end()+10)]
                # Check it's not inside a larger correct number
                new_email = PLANS[plan_name]['emails']
                new_pat = build_number_pattern(new_email)
                if not re.search(new_pat, ctx):
                    snippet = assistant[max(0,m.start()-30):min(len(assistant),m.end()+30)].replace('\n','↵')[:100]
                    issues[f'{plan_name}_emails'].append((i, snippet))
        
        # Check old prices
        for old_price in old_vals.get('price', []):
            if f'${old_price}' in assistant and plan_lower in lower:
                issues[f'{plan_name}_price'].append((i, f'${old_price}'))
        
        # Check old domain counts (word-boundary aware)
        for old_dom in old_vals.get('domains', []):
            # Match: plan context + old_dom domains
            pat = rf'{plan_lower}.*?(?<!\d){old_dom}\s+(?:domains?|custom\s+domains?)'
            m = re.search(pat, lower, re.DOTALL)
            if m:
                snippet = assistant[max(0,m.start()-20):min(len(assistant),m.end()+20)].replace('\n','↵')[:100]
                # Exclude if correct value is nearby
                ctx = lower[max(0,m.start()-10):min(len(lower),m.end()+10)]
                correct_dom = PLANS[plan_name]['domains']
                if correct_dom > 0 and f'{correct_dom} domain' not in ctx and f'{correct_dom} custom' not in ctx:
                    issues[f'{plan_name}_domains'].append((i, snippet))
        
        # Check old team counts (word-boundary aware)
        for old_team in old_vals.get('team', []):
            pat = rf'{plan_lower}.*?(?<!\d){old_team}\s+team\s+members?'
            m = re.search(pat, lower, re.DOTALL)
            if m:
                snippet = assistant[max(0,m.start()-20):min(len(assistant),m.end()+20)].replace('\n','↵')[:100]
                correct_team = PLANS[plan_name]['team']
                ctx = lower[max(0,m.start()-10):min(len(lower),m.end()+10)]
                if correct_team > 0 and f'{correct_team} team' not in ctx:
                    issues[f'{plan_name}_team'].append((i, snippet))
    
    # Check overage math: N × $0.40/1K should equal N/1000*0.40
    for m in re.finditer(r'([\d,]+)\s*[×x]\s*\$0\.40\s*/\s*(?:1[,.]?000|1K)\s*=\s*\$?([\d.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        claimed = float(m.group(2))
        expected = round(qty / 1000 * 0.40, 2)
        if abs(claimed - expected) > 0.05:
            issues['overage_math'].append((i, f"{qty:,} × $0.40/1K = ${claimed} (expected ${expected})"))
    
    # Also check: "N,000 emails × $0.40/1,000 = $X" variant
    for m in re.finditer(r'([\d,]+)\s*(?:emails?\s*)?[×x]\s*\$0\.40\s*/\s*1[,.]?000\s*=\s*\$?([\d.]+)', assistant):
        qty = int(m.group(1).replace(',', ''))
        claimed = float(m.group(2))
        expected = round(qty / 1000 * 0.40, 2)
        if abs(claimed - expected) > 0.05:
            if (i, f"{qty:,} × $0.40/1K = ${claimed} (expected ${expected})") not in issues['overage_math']:
                issues['overage_math'].append((i, f"{qty:,} × $0.40/1K = ${claimed} (expected ${expected})"))

    # PAYG rate displayed as $1.00/1K or $0.80/1K — these are CORRECT per-1K rates
    # $0.001/email = $1.00/1K, $0.0008/email = $0.80/1K — NOT errors
    # (Removed false positive check)


print("=" * 72)
print("COMPREHENSIVE PRICING SCAN v2 — ALL PLANS")
print("=" * 72)

total = 0
for cat in sorted(issues.keys()):
    items = issues[cat]
    unique_lines = sorted(set(ln for ln, _ in items))
    total += len(unique_lines)
    print(f"\n{cat}: {len(unique_lines)} lines")
    for ln, snippet in sorted(set(items)):
        print(f"  L{ln}: {snippet}")

print(f"\n{'='*72}")
print(f"TOTAL UNIQUE ISSUES: {total}")
print(f"{'='*72}")

# Collect all affected lines
all_lines = set()
for items in issues.values():
    for ln, _ in items:
        all_lines.add(ln)
print(f"AFFECTED LINES: {sorted(all_lines)}")
print(f"TOTAL AFFECTED: {len(all_lines)} lines")
