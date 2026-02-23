#!/usr/bin/env python3
"""
Fix v5: Targeted fixes for 14 confirmed real errors (7 duplicate pairs).
Each fix is based on manual review of the full assistant response.
"""
import json, re

FILEPATH = 'data/train_agent.jsonl'

with open(FILEPATH) as f:
    lines = f.readlines()

# Backup
with open(FILEPATH + '.bak5', 'w') as f:
    f.writelines(lines)

fixes = 0

def fix_line(ln, old_str, new_str, desc):
    """Replace old_str with new_str in the given line number."""
    global fixes
    idx = ln - 1
    data = json.loads(lines[idx])
    text = data['text']
    if old_str in text:
        text = text.replace(old_str, new_str)
        data['text'] = text
        lines[idx] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: {desc}")
        return True
    else:
        print(f"  L{ln}: NOT FOUND — {desc}")
        return False


# ═══════════════════════════════════════════════════════════════════
# 1. L69/L766: Starter comparison for 30K emails
#    Old Starter had 25K → 5K overage. New Starter has 50K → NO overage.
#    Fix: Remove overage line, total = $25.00, update comparison text.
# ═══════════════════════════════════════════════════════════════════

for ln in [69, 766]:
    fix_line(ln,
        '**Starter ($25/mo):**\\n- Includes 50,000 emails\\n- Overage: 5,000 × $0.40/1,000 = $2.00\\n- **Total: $31.50/mo**',
        '**Starter ($25/mo):**\\n- Includes 50,000 emails\\n- No overage (30K is within the 50K limit)\\n- **Total: $25.00/mo**',
        'Starter: removed overage (30K < 50K), total $25')
    
    fix_line(ln,
        '**Starter at $31.50 is significantly cheaper**',
        '**Starter at $25.00 is significantly cheaper**',
        'Updated total reference')

# ═══════════════════════════════════════════════════════════════════
# 2. L96/L635: Growth comparison for 250K emails
#    Old Growth had 100K. New Growth has 500K. 250K < 500K → no overage.
#    Fix: Growth at $150 with no overage is cheaper than PAYG $157.
# ═══════════════════════════════════════════════════════════════════

for ln in [96, 635]:
    fix_line(ln,
        'For comparison, a Growth plan ($150/mo) includes 100K emails — 150K overage at $0.40/1K = $75, total $204. Scale ($350) includes 500K. So PAYG at $157 is the cheapest option for 250K emails/month.',
        'For comparison, a Growth plan ($150/mo) includes 500,000 emails — 250K is well within the limit, so no overages. Total: **$150/mo**. Scale ($350) includes 2,000,000. **Growth at $150 is actually cheaper than PAYG at $157** — plus you get A/B testing, a dedicated IP, and priority support.',
        'Updated Growth (500K) and Scale (2M) comparison')

# ═══════════════════════════════════════════════════════════════════
# 3. L169/L657: API calls comparison — ALL numbers wrong
# ═══════════════════════════════════════════════════════════════════

for ln in [169, 657]:
    # Fix the headline
    fix_line(ln,
        'The Scale plan ($350/month) includes **5,000,000** API calls per month.',
        'The Scale plan ($350/month) includes **20,000,000** API calls per month.',
        'Scale API calls: 5M → 20M')
    
    # Fix the comparison list
    fix_line(ln,
        '- Free: 10,000\\n- Starter: 250,000\\n- Pro: 500,000\\n- Growth: 1,000,000\\n- **Scale: 5,000,000**\\n- Enterprise: 20,000,000',
        '- Free: 50,000\\n- Starter: 500,000\\n- Pro: 2,000,000\\n- Growth: 5,000,000\\n- **Scale: 20,000,000**\\n- Enterprise: Unlimited',
        'Fixed all API call counts')
    
    fix_line(ln,
        'If you exceed 5,000,000 API calls on Scale',
        'If you exceed 20,000,000 API calls on Scale',
        'Fixed overage threshold')

# ═══════════════════════════════════════════════════════════════════
# 4. L217/L384: Enterprise HIPAA description — 2M → 5M emails
# ═══════════════════════════════════════════════════════════════════

for ln in [217, 384]:
    fix_line(ln,
        '10 dedicated IPs and 2M emails/month',
        '10 dedicated IPs and 5M emails/month',
        'Enterprise emails: 2M → 5M')

# ═══════════════════════════════════════════════════════════════════
# 5. L228/L967: Growth→Pro downgrade — A/B testing & send-time opt
#    are available on Pro (Pro+), so they're NOT lost on downgrade.
# ═══════════════════════════════════════════════════════════════════

for ln in [228, 967]:
    fix_line(ln,
        'Features lost on Growth → Pro downgrade:\\n- Dedicated IP(s)\\n- A/B testing\\n- Send-time optimization (AI)\\n- Audit logs\\n- Priority support (→ standard email support)\\n- 100 domains → 25 domains\\n- 25 team members → 10 team members',
        'Features lost on Growth → Pro downgrade:\\n- Dedicated IP (Growth includes 1 free; Pro requires $30/mo add-on)\\n- Audit logs (Growth+ only)\\n- Priority support → email support\\n- 100 domains → 25 domains\\n- 25 team members → 10 team members',
        'Removed A/B testing & send-time opt from lost features (both available on Pro)')

# ═══════════════════════════════════════════════════════════════════
# 6. L232/L1053: Enterprise email limit 2M → 5M + recalc remaining
# ═══════════════════════════════════════════════════════════════════

for ln in [232, 1053]:
    fix_line(ln,
        'Your Enterprise plan includes **2,000,000** emails per month.\\nThat leaves **550,000 emails** remaining',
        'Your Enterprise plan includes **5,000,000** emails per month.\\nThat leaves **3,550,000 emails** remaining',
        'Enterprise: 2M→5M emails, remaining 550K→3.55M')

# ═══════════════════════════════════════════════════════════════════
# 7. L709/L1015: Growth 100K→500K, Scale 500K→2M in PAYG comparison
# ═══════════════════════════════════════════════════════════════════

for ln in [709, 1015]:
    fix_line(ln,
        '- **Growth ($150)**: 100K included + 150K overage at $0.40/1K = $75 → **$204 total**\\n- **Scale ($350)**: 500K included → **$350 total** (overkill)',
        '- **Growth ($150)**: 500K included — 250K is within the limit → **$150 total** (no overages)\\n- **Scale ($350)**: 2M included → **$350 total** (overkill)',
        'Updated Growth (500K) and Scale (2M)')
    
    fix_line(ln,
        '**PAYG at $157** is the cheapest option for 250K emails. But if you also need features like A/B testing or dedicated IPs (Growth+), factor that in.',
        '**Growth at $150** is actually the cheapest option for 250K emails — cheaper than PAYG ($157) and includes A/B testing, a dedicated IP, and priority support.',
        'Updated recommendation: Growth cheaper than PAYG')


with open(FILEPATH, 'w') as f:
    f.writelines(lines)

print(f"\nTotal fixes applied: {fixes}")
