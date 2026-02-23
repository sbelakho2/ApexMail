#!/usr/bin/env python3
"""
COMPREHENSIVE TRAINING DATA FIX SCRIPT v2
==========================================
Fixes all errors across 42+ lines in data/train_agent.jsonl.
Uses line-by-line context-aware replacements instead of lookbehinds.
"""

import json
import re
import sys

filepath = 'data/train_agent.jsonl'
backup_path = 'data/train_agent.jsonl.bak3'


def fix_assistant_text(line_num, text):
    """Apply domain/team/email fixes to assistant responses only."""
    fixes = []
    
    # Split into messages
    parts = re.split(r'(<\|im_start\|>(?:system|user|tool|assistant)\n)', text)
    
    new_parts = []
    current_role = None
    
    for part in parts:
        role_match = re.match(r'<\|im_start\|>(\w+)\n', part)
        if role_match:
            current_role = role_match.group(1)
            new_parts.append(part)
            continue
        
        if current_role != 'assistant':
            new_parts.append(part)
            continue
        
        original = part
        
        # Process line by line with context tracking
        lines_list = part.split('\n')
        in_pro = False
        in_starter = False
        fixed_lines = []
        
        for ln in lines_list:
            # Track which plan section we're in
            if re.search(r'\*?\*?Pro\*?\*?\s*(?:\(?\$65|plan)', ln, re.I):
                in_pro = True
                in_starter = False
            elif re.search(r'\*?\*?Starter\*?\*?\s*(?:\(?\$25|plan)', ln, re.I):
                in_starter = True
                in_pro = False
            elif re.search(r'\*?\*?(?:Growth|Scale|Enterprise|Free)\*?\*?\s*(?:\(?\$|plan)', ln, re.I):
                in_pro = False
                in_starter = False
            
            # ─── Starter: 3 domains → 5, 3 team → 5 ───
            if in_starter or ('starter' in ln.lower() and ('domain' in ln.lower() or 'team' in ln.lower())):
                ln = re.sub(r'\b3 domains\b', '5 domains', ln)
                ln = re.sub(r'\b3 team members\b', '5 team members', ln)
                ln = re.sub(r'\b3 team\b(?! member)', '5 team', ln)
            
            # ─── Pro: 5 domains → 25, 5 team → 10 ───
            if in_pro or ('pro' in ln.lower() and ('domain' in ln.lower() or 'team' in ln.lower())):
                ln = re.sub(r'\b5 domains\b', '25 domains', ln)
                ln = re.sub(r'\b5 team members\b', '10 team members', ln)
                ln = re.sub(r'\b5 team\b(?! member)', '10 team', ln)
                # Fix "vs. 3" → "vs. 5" in Pro context
                ln = re.sub(r'\(vs\.\s*3\)', '(vs. 5)', ln)
            
            # ─── Fix "$1.50/1K" anywhere ───
            ln = ln.replace('$1.50/1K', '$0.40/1K')
            ln = re.sub(r'\$1\.50/1,000', '$0.40/1,000', ln)
            
            fixed_lines.append(ln)
        
        part = '\n'.join(fixed_lines)
        
        # ─── Pro email limit: 50K → 150K ───
        # "Pro ($65/mo): 50,000 emails"
        part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\)\s*:\s*)50,000 emails', r'\g<1>150,000 emails', part, flags=re.I)
        # "Pro ($65/mo) for 50,000 emails"
        part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\)\s*(?:for|includes|with)\s*)50,000\s*emails', r'\g<1>150,000 emails', part, flags=re.I)
        # "Pro plan at $65/month includes 50,000 emails"
        part = re.sub(r'(Pro\s+plan\s+at\s+\$65(?:/month)?\s+includes\s+)50,000\s+emails', r'\g<1>150,000 emails', part, flags=re.I)
        # "upgrading to Pro ($65/mo) which gives you 50,000 emails"
        part = re.sub(r'(Pro\s*\(\$65(?:/mo)?\)\s*(?:which gives you|for)\s*)50,000\s+emails', r'\g<1>150,000 emails', part, flags=re.I)
        # "Pro ... 50,000 included" in line context
        part = re.sub(r'(Pro.*?)(\b50,000 included\b)', lambda m: m.group(1) + '150,000 included', part, flags=re.I)
        # Table row with Pro
        part = re.sub(r'(\|\s*\*?\*?Pro\*?\*?\s*\|[^|]*\|[^|]*\|[^|]*?)\b50,000 emails\b', r'\g<1>150,000 emails', part)
        
        if part != original:
            fixes.append(f"L{line_num}: fixes applied")
        
        new_parts.append(part)
    
    return ''.join(new_parts), fixes


# ═══════════════════════════════════════════════════════════════════════
# SPECIFIC RESPONSE REWRITES for bad calculation chains
# ═══════════════════════════════════════════════════════════════════════

REWRITES = {}

# L42 & L603: Starter 35K emails (35K < 50K, no overages)
_old_42 = (
    'On the **Starter plan ($25/month)**, you get 50,000 emails included.\n'
    '\n'
    '**Calculation:**\n'
    '- Overage: 35,000 - 25,000 = **10,000 extra emails**\n'
    '- Cost: 10,000 ÷ 1,000 × $0.40 = **$5.00**\n'
    '- Total: $25 + $5 = **$34.00**\n'
    '\n'
    'Tip: If your volume stays around 35K, the Pro plan ($65) includes 50K emails with no overages. But at 35K, Starter + overages ($34) is still cheaper.'
)
_new_42 = (
    'On the **Starter plan ($25/month)**, you get 50,000 emails included.\n'
    '\n'
    'Since 35,000 is **within your 50,000 email limit**, there are **no overages** this month.\n'
    '\n'
    '**Total bill: $25.00**\n'
    '\n'
    'You\'re at **70% usage** — plenty of headroom. If your volume grows past 50K regularly, the **Pro plan ($65/mo)** gives you 150,000 emails/month plus custom tracking domains and A/B testing.'
)
REWRITES[42] = (_old_42, _new_42)
REWRITES[603] = (_old_42, _new_42)

# L689 & L851: Starter vs Pro for 30K
_old_689 = (
    'Let\'s compare for **30,000 emails/month**:\n'
    '\n'
    '**Starter ($25/month):**\n'
    '- 25,000 included → 5,000 overage\n'
    '- Overage: 5,000 ÷ 1,000 × $0.40 = $2.50\n'
    '- Total: **$31.50/month**\n'
    '- 3 domains, 3 team members, analytics, data export\n'
    '\n'
    '**Pro ($65/month):**\n'
    '- 50,000 included → no overage\n'
    '- Total: **$65.00/month**\n'
    '- 5 domains, 5 team members, custom tracking domain, 60-day retention\n'
    '\n'
    '**Price difference:** $27.50/month more for Pro.\n'
    '\n'
    '**Recommendation:** Go with **Starter at $31.50** if you just need basic sending. Choose **Pro at $65** if you need custom tracking domains, more team seats, or expect to grow past 40K/month soon (where Starter overages make Pro cheapest).'
)
_new_689 = (
    'Let\'s compare for **30,000 emails/month**:\n'
    '\n'
    '**Starter ($25/month):**\n'
    '- 50,000 included → no overage at 30K\n'
    '- Total: **$25.00/month**\n'
    '- 5 domains, 5 team members, webhooks, analytics, data export\n'
    '\n'
    '**Pro ($65/month):**\n'
    '- 150,000 included → no overage\n'
    '- Total: **$65.00/month**\n'
    '- 25 domains, 10 team members, custom tracking domain, A/B testing, 60-day retention\n'
    '\n'
    '**Price difference:** $40.00/month more for Pro.\n'
    '\n'
    '**Recommendation:** Go with **Starter at $25** — 30K fits well within the 50K limit with no overages. Choose **Pro at $65** if you need custom tracking domains, A/B testing, more domains (25 vs 5), or expect to grow past 50K/month soon.'
)
REWRITES[689] = (_old_689, _new_689)
REWRITES[851] = (_old_689, _new_689)

# L310 & L1044: 40K emails pricing
_old_310 = (
    'For **40,000 emails/month**, here are your best options:\n'
    '\n'
    '**Option 1: Pro plan — $65/month**\n'
    '- Includes 50,000 emails/month (you\'d use 80%)\n'
    '- 50,000 emails of headroom for growth\n'
    '- Custom tracking domain, 5 domains\n'
    '\n'
    '**Option 2: Starter plan — $25/month + overages**\n'
    '- Includes 50,000 emails. You\'d go over by 15,000\n'
    '- Overage: 15,000 ÷ 1,000 × $0.40 = **$7.50**\n'
    '- Total: $25 + $7.50 = **$36.50/month**\n'
    '\n'
    '**Option 3: Pay-As-You-Go**\n'
    '- First 10K: $0.001 × 10,000 = $10\n'
    '- Next 30K: $0.0008 × 30,000 = $24\n'
    '- Total: **$34/month**\n'
    '\n'
    '**Recommendation:** The **Pro plan at $65** is the most predictable and includes features like custom tracking domains. PAYG is cheaper at $34 but doesn\'t include a custom tracking domain. The Starter+overage option is the cheapest at $36.50 but you lose domain capacity (3 vs 5).'
)
_new_310 = (
    'For **40,000 emails/month**, here are your best options:\n'
    '\n'
    '**Option 1: Starter plan — $25/month** ✅ Best value\n'
    '- Includes 50,000 emails/month — 40K is within your limit (80% usage)\n'
    '- No overages at this volume\n'
    '- Total: **$25.00/month**\n'
    '- 5 domains, 5 team members, webhooks\n'
    '\n'
    '**Option 2: Pro plan — $65/month**\n'
    '- Includes 150,000 emails/month — massive headroom for growth\n'
    '- Total: **$65.00/month**\n'
    '- Custom tracking domain, A/B testing, 25 domains, 10 team members\n'
    '\n'
    '**Option 3: Pay-As-You-Go**\n'
    '- First 10K: $0.001 × 10,000 = $10\n'
    '- Next 30K: $0.0008 × 30,000 = $24\n'
    '- Total: **$34/month**\n'
    '\n'
    '**Recommendation:** **Starter at $25** is the best value — 40K fits within the 50K limit with no overages. Choose **Pro at $65** if you need custom tracking domains, A/B testing, or expect to grow past 50K/month. PAYG at $34 is $9 more than Starter and doesn\'t include webhooks or templates.'
)
REWRITES[310] = (_old_310, _new_310)
REWRITES[1044] = (_old_310, _new_310)

# L104 & L341: PAYG value for 74.2K
_old_104 = (
    'Let\'s analyze your **Pay-As-You-Go** costs:\n'
    '\n'
    'Your current month: **74,200 emails** ≈ **$61** (10K × $0.001 = $10 + 64.2K × $0.0008 = $51.36)\n'
    '\n'
    '**Compare to monthly plans:**\n'
    '- **Starter ($25/mo):** 50,000 emails — you\'d need overages for 49,200 extra = $24.60 → **$53.60 total** ✅ Cheaper\n'
    '- **Pro ($65/mo):** 50,000 emails — you\'d need overages for 24,200 extra = $12.10 → **$71.10 total** ❌ More expensive\n'
    '- **Growth ($150/mo):** 500,000 emails — **$150** ❌ More expensive\n'
    '\n'
    'At your current volume, PAYG at ~$61/mo is a decent deal. However, if you\'re growing (52K last month → 74K this month), the **Starter plan at $25** plus overages might save you about $7/mo. If you expect to regularly exceed 50K emails, consider upgrading to Pro.'
)
_new_104 = (
    'Let\'s analyze your **Pay-As-You-Go** costs:\n'
    '\n'
    'Your current month: **74,200 emails** ≈ **$61.36** (10K × $0.001 = $10 + 64.2K × $0.0008 = $51.36)\n'
    '\n'
    '**Compare to monthly plans:**\n'
    '- **Starter ($25/mo):** 50,000 emails included — you\'d need overages for 24,200 extra at $0.40/1K = $9.68 → **$34.68 total** ✅ Much cheaper\n'
    '- **Pro ($65/mo):** 150,000 emails included — 74.2K is well within the limit → **$65.00 total**\n'
    '- **Growth ($150/mo):** 500,000 emails — **$150** ❌ More expensive\n'
    '\n'
    'At your current volume, **Starter at ~$35/mo** is actually the cheapest option — even cheaper than PAYG at $61. If you\'re growing (52K last month → 74K this month) and expect to regularly exceed 100K, consider **Pro at $65** which covers up to 150K with no overages.'
)
REWRITES[104] = (_old_104, _new_104)
REWRITES[341] = (_old_104, _new_104)


def main():
    with open(filepath) as f:
        lines = f.readlines()
    
    print(f"Read {len(lines)} training examples")
    
    # Backup
    with open(backup_path, 'w') as f:
        f.writelines(lines)
    print(f"Backup saved to {backup_path}")
    
    fixed_lines = set()
    new_lines = []
    
    for i, raw in enumerate(lines, 1):
        data = json.loads(raw)
        text = data['text']
        original = text
        
        # 1. Apply specific response rewrites first
        if i in REWRITES:
            old_str, new_str = REWRITES[i]
            if old_str in text:
                text = text.replace(old_str, new_str)
            else:
                print(f"  WARNING: L{i} rewrite pattern not found!")
        
        # 2. Fix L533/L596: overage math 2800 ÷ 1K × $0.40 = $1.40 → $1.12
        if i in (533, 596):
            text = text.replace('2,800 ÷ 1,000 × $0.40 = **$1.40**', '2,800 ÷ 1,000 × $0.40 = **$1.12**')
        
        # 3. Fix L783/L964: Growth 142K no overages
        if i in (783, 964):
            text = text.replace(
                '- Overage: 142,000 - 100,000 = **42,000 extra emails**\n- Cost: 42,000 ÷ 1,000 × $0.40 = **$21.00**',
                'Since 142,000 is **well within your 500,000 email limit**, there are **no overages** this month.\n- Extra cost: **$0.00**'
            )
            # Fix total
            text = re.sub(r'\$150\s*\+\s*\$21(?:\.00)?\s*=\s*\*?\*?\$171(?:\.00)?\*?\*?', '**$150.00**', text)
        
        # 4. Fix L226/L612: 45K on Starter, no overages  
        if i in (226, 612):
            text = text.replace(
                "If you send 45,000 emails, you'd go over by 35,000",
                "Since 45,000 is within your 50,000 email limit, there are **no overages**"
            )
            text = text.replace(
                '35,000 overage × $1.50/1K = **$52.50**',
                'You still have 5,000 emails remaining in your allocation.'
            )
            text = re.sub(r'Total.*?\$77\.50.*', 'Total: **$25.00** (no overages)', text)
        
        # 5. Fix L419: Starter 18,240 of 25K → 50K
        if i == 419:
            text = text.replace("**18,240** of **25,000** emails", "**18,240** of **50,000** emails")
            text = text.replace('25,000 − 18,240 = **6,760 emails**', '50,000 − 18,240 = **31,760 emails**')
            text = text.replace('73% of monthly limit', '36% of monthly limit')
        
        # 6. Fix L115/L763: Pro comparison for 50K PAYG
        if i in (115, 763):
            text = text.replace(
                'Pro plan at $65/month includes 50,000 emails',
                'Pro plan at $65/month includes 150,000 emails'
            )
            text = text.replace('PAYG saves you $17/month', 'PAYG saves you $23/month at 50K volume, though Pro gives you 3× the email capacity')
        
        # 7. Apply general assistant-only fixes (domain/team/Pro email)
        text, fixes = fix_assistant_text(i, text)
        
        if text != original:
            fixed_lines.add(i)
        
        data['text'] = text
        new_lines.append(json.dumps(data, ensure_ascii=False) + '\n')
    
    # Write
    with open(filepath, 'w') as f:
        f.writelines(new_lines)
    
    print(f"\n{'='*60}")
    print(f"FIXES APPLIED: {len(fixed_lines)} lines modified")
    print(f"Fixed lines: {sorted(fixed_lines)}")
    print(f"{'='*60}")
    
    return len(fixed_lines)


if __name__ == '__main__':
    n = main()
    print(f"\nDone. {n} lines fixed.")
