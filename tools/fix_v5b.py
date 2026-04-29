#!/usr/bin/env python3
"""
Fix v5b: Handle the 8 fixes that failed because of newline encoding issues.
This script works on the raw text directly (not escaped JSON).
"""
import json, re

from common_paths import data_path

FILEPATH = str(data_path("train_agent.jsonl"))

with open(FILEPATH) as f:
    lines = f.readlines()

fixes = 0

def fix_in_text(ln, old_str, new_str, desc):
    """Replace in the actual text content (not JSON-escaped)."""
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
        # Show nearby content
        assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        for a in assists:
            # Search for key phrases
            for key in old_str.split('\n')[:2]:
                key = key.strip()
                if len(key) > 10 and key in a:
                    idx2 = a.find(key)
                    print(f"    Found partial match near: ...{a[max(0,idx2-20):idx2+80]}...")
                    break
        return False


# ═══ 1. L69/L766: Starter overage removal ═══
for ln in [69, 766]:
    fix_in_text(ln,
        '**Starter ($25/mo):**\n- Includes 50,000 emails\n- Overage: 5,000 × $0.40/1,000 = $2.00\n- **Total: $31.50/mo**',
        '**Starter ($25/mo):**\n- Includes 50,000 emails\n- No overage (30K is within the 50K limit)\n- **Total: $25.00/mo**',
        'Starter: removed overage, total $25')

# ═══ 2. L169/L657: Fix API call list ═══
for ln in [169, 657]:
    fix_in_text(ln,
        '- Free: 10,000\n- Starter: 250,000\n- Pro: 500,000\n- Growth: 1,000,000\n- **Scale: 5,000,000**\n- Enterprise: 20,000,000',
        '- Free: 50,000\n- Starter: 500,000\n- Pro: 2,000,000\n- Growth: 5,000,000\n- **Scale: 20,000,000**\n- Enterprise: Unlimited',
        'Fixed all API call counts')

# ═══ 3. L228/L967: Growth→Pro downgrade features ═══
for ln in [228, 967]:
    fix_in_text(ln,
        'Features lost on Growth → Pro downgrade:\n- Dedicated IP(s)\n- A/B testing\n- Send-time optimization (AI)\n- Audit logs\n- Priority support (→ standard email support)\n- 100 domains → 25 domains\n- 25 team members → 10 team members',
        'Features lost on Growth → Pro downgrade:\n- Dedicated IP (Growth includes 1 free; Pro requires $30/mo add-on)\n- Audit logs (Growth+ only)\n- Priority support → email support\n- 100 domains → 25 domains\n- 25 team members → 10 team members',
        'Removed A/B & send-time from lost features')

# ═══ 4. L232/L1053: Enterprise 2M→5M + remaining calc ═══
for ln in [232, 1053]:
    fix_in_text(ln,
        'Your Enterprise plan includes **2,000,000** emails per month.\nThat leaves **550,000 emails** remaining',
        'Your Enterprise plan includes **5,000,000** emails per month.\nThat leaves **3,550,000 emails** remaining',
        'Enterprise: 2M→5M, remaining recalc')

# ═══ 5. L709/L1015: Growth/Scale comparison ═══
for ln in [709, 1015]:
    fix_in_text(ln,
        '- **Growth ($150)**: 100K included + 150K overage at $0.40/1K = $75 → **$204 total**\n- **Scale ($350)**: 500K included → **$350 total** (overkill)',
        '- **Growth ($150)**: 500K included — 250K is within the limit → **$150 total** (no overages)\n- **Scale ($350)**: 2M included → **$350 total** (overkill)',
        'Growth 100K→500K, Scale 500K→2M')

with open(FILEPATH, 'w') as f:
    f.writelines(lines)

print(f"\nTotal fixes applied: {fixes}")
