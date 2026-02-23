#!/usr/bin/env python3
"""Fix the final 4 lines: L310, L334, L814, L1044 with targeted replacements."""
import json

filepath = 'data/train_agent.jsonl'
with open(filepath) as f:
    lines = f.readlines()

fixes = 0

# ═══ L310 + L1044: Fix "25 team members" → "10 team members" in Pro section ═══
for ln in [310, 1044]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    # Only the second assistant response has this
    old = "Custom tracking domain, A/B testing, 25 domains, 25 team members"
    new = "Custom tracking domain, A/B testing, 25 domains, 10 team members"
    if old in text:
        text = text.replace(old, new)
        data['text'] = text
        lines[ln - 1] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: Fixed Pro team 25→10")
    else:
        print(f"  L{ln}: Pattern not found!")
        # Show what's there
        import re
        assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        for i, a in enumerate(assists):
            if 'team' in a:
                idx = a.find('team')
                print(f"    assist[{i}]: ...{a[max(0,idx-50):idx+50]}...")

# ═══ L334 + L814: Full rewrite of comparison table ═══
# User sends 74,200 emails on PAYG. Compare plans:
# Starter ($25): 50K included → 74.2K - 50K = 24.2K overage → 24.2K/1K × $0.40 = $9.68 → total $34.68
# Pro ($65): 150K included → NO overage → total $65.00
for ln in [334, 814]:
    data = json.loads(lines[ln - 1])
    text = data['text']
    
    old_response = (
        'Let me analyze your usage to see if a plan would save you money.\\n\\n'
        '**Your current PAYG cost this month (74,200 emails):**\\n'
        '- 10K × $0.001 = $10.00\\n'
        '- 64.2K × $0.0008 = $51.36\\n'
        '- **Total: $61.36**\\n\\n'
        '**Compared to plans:**\\n'
        '| Plan | Base | Included | Overage | Total |\\n'
        '|------|------|----------|---------|-------|\\n'
        '| Starter ($25) | $25 | 25K | 49.2K × $0.40/1K = $24.60 | **$53.60** |\\n'
        '| Pro ($65) | $65 | 150K | 24.2K × $0.40/1K = $12.10 | **$71.10** |\\n\\n'
        '**Starter + overages ($53.60) would save you ~$7.76/month** vs PAYG.\\n\\n'
        'But consider the trade-offs:\\n'
        '- Starter gives you **webhooks** (you already have one set up), **5 domains** (you have 2), and **email support**\\n'
        '- PAYG keeps you flexible with no commitment\\n'
        '- Your volume is growing (52K → 74K) — if you hit 80K+, Starter savings increase\\n\\n'
        '**My recommendation:** If your volume stays above 60K, switch to Starter. Would you like me to walk through the upgrade?'
    )
    
    new_response = (
        'Let me analyze your usage to see if a plan would save you money.\\n\\n'
        '**Your current PAYG cost this month (74,200 emails):**\\n'
        '- 10K × $0.001 = $10.00\\n'
        '- 64.2K × $0.0008 = $51.36\\n'
        '- **Total: $61.36**\\n\\n'
        '**Compared to plans:**\\n'
        '| Plan | Base | Included | Overage | Total |\\n'
        '|------|------|----------|---------|-------|\\n'
        '| Starter ($25) | $25 | 50K | 24.2K × $0.40/1K = $9.68 | **$34.68** |\\n'
        '| Pro ($65) | $65 | 150K | None (74.2K < 150K) | **$65.00** |\\n\\n'
        '**Starter + overages ($34.68) would save you ~$26.68/month** vs PAYG.\\n\\n'
        'But consider the trade-offs:\\n'
        '- Starter gives you **webhooks** (you already have one set up), **5 domains** (you have 2), and **email support**\\n'
        '- PAYG keeps you flexible with no commitment\\n'
        '- Your volume is growing (52K → 74K) — if you hit 80K+, Starter savings increase\\n\\n'
        '**My recommendation:** Switch to Starter — at $34.68/month (vs $61.36 for PAYG), you save ~$26.68/month and get webhooks, templates, and email support. Would you like me to walk through the upgrade?'
    )
    
    if old_response in text:
        text = text.replace(old_response, new_response)
        data['text'] = text
        lines[ln - 1] = json.dumps(data, ensure_ascii=False) + '\n'
        fixes += 1
        print(f"  L{ln}: Rewrote comparison table")
    else:
        # Try with the raw content (not escaped)
        import re
        assists = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        # Try direct replacement on the text
        old_table = (
            '| Starter ($25) | $25 | 25K | 49.2K × $0.40/1K = $24.60 | **$53.60** |\n'
            '| Pro ($65) | $65 | 150K | 24.2K × $0.40/1K = $12.10 | **$71.10** |'
        )
        new_table = (
            '| Starter ($25) | $25 | 50K | 24.2K × $0.40/1K = $9.68 | **$34.68** |\n'
            '| Pro ($65) | $65 | 150K | None (74.2K < 150K) | **$65.00** |'
        )
        if old_table in text:
            text = text.replace(old_table, new_table)
            text = text.replace(
                'Starter + overages ($53.60) would save you ~$7.76/month',
                'Starter + overages ($34.68) would save you ~$26.68/month'
            )
            text = text.replace(
                '**My recommendation:** If your volume stays above 60K, switch to Starter. Would you like me to walk through the upgrade?',
                '**My recommendation:** Switch to Starter — at $34.68/month (vs $61.36 for PAYG), you save ~$26.68/month and get webhooks, templates, and email support. Would you like me to walk through the upgrade?'
            )
            data['text'] = text
            lines[ln - 1] = json.dumps(data, ensure_ascii=False) + '\n'
            fixes += 1
            print(f"  L{ln}: Rewrote comparison table (direct)")
        else:
            print(f"  L{ln}: Could not match old table — checking content:")
            for a in assists:
                if 'Starter' in a and '$25' in a and 'Pro' in a:
                    # Find the table
                    for line in a.split('\n'):
                        if 'Starter' in line or 'Pro' in line:
                            print(f"    {line}")

with open(filepath, 'w') as f:
    f.writelines(lines)

print(f"\nFixed {fixes} lines total")
