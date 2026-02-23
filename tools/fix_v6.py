#!/usr/bin/env python3
"""
Comprehensive fix v6: Fix ALL remaining wrong API call counts and email limits.

Error categories found:
1. Free plan: 10,000 API → 50,000
2. Starter: 250,000 API → 500,000  
3. Pro: 500,000 API → 2,000,000
4. Growth: 1,000,000 API → 5,000,000
5. Scale: 5,000,000 API → 20,000,000
6. Enterprise: 20,000,000 API → Unlimited
7. Enterprise email: "2M emails" or "2,000,000 emails" → 5M in Enterprise context
8. Scale: wrong API 5M → 20M in description
9. Starter domains: "3 sending domains" → 5 domains (some lines show 3)

Strategy: Parse each line, fix in assistant text only, use context-aware replacements.
"""
import json, re, sys

FILEPATH = 'data/train_agent.jsonl'

with open(FILEPATH) as f:
    lines = f.readlines()

total_fixes = 0
fixed_lines = set()

def apply_fix(idx, text, old, new, desc):
    global total_fixes
    if old in text:
        text = text.replace(old, new)
        total_fixes += 1
        fixed_lines.add(idx + 1)
        print(f"  L{idx+1}: {desc}")
        return text
    return text


for idx in range(len(lines)):
    data = json.loads(lines[idx])
    text = data['text']
    original_text = text
    ln = idx + 1
    
    # Extract assistant text boundaries for context checking
    assists = list(re.finditer(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL))
    if not assists:
        continue
    
    # Work on the full text but only match patterns in assistant portions
    for m in assists:
        atxt = m.group(1)
        astart = m.start(1)
        aend = m.end(1)
        
        new_atxt = atxt
        
        # ═══════════════════════════════════════════════════════════
        # 1. Fix API call TABLES (plan-by-plan comparison lists)
        # ═══════════════════════════════════════════════════════════
        # Pattern: "| Free | 10,000 |" in tables
        table_fixes = [
            (r'\| Free \| 10,000 \|', '| Free | 50,000 |', 'Table: Free 10K→50K API'),
            (r'\| Starter \| 250,000 \|', '| Starter | 500,000 |', 'Table: Starter 250K→500K API'),
            (r'\| Pro \| 500,000 \|', '| Pro | 2,000,000 |', 'Table: Pro 500K→2M API'),
            (r'\| Growth \| 1,000,000 \|', '| Growth | 5,000,000 |', 'Table: Growth 1M→5M API'),
            (r'\| Scale \| 5,000,000 \|', '| Scale | 20,000,000 |', 'Table: Scale 5M→20M API'),
            (r'\| Enterprise \| 20,000,000 \|', '| Enterprise | Unlimited |', 'Table: Enterprise 20M→Unlimited API'),
        ]
        for pat, repl, desc in table_fixes:
            m2 = re.search(pat, new_atxt)
            if m2:
                new_atxt = re.sub(pat, repl, new_atxt)
                total_fixes += 1
                fixed_lines.add(ln)
                print(f"  L{ln}: {desc}")
        
        # ═══════════════════════════════════════════════════════════
        # 2. Fix bullet-list API comparisons  
        # Pattern: "- Free: 10,000" or "- **Free**: 10,000"
        # ═══════════════════════════════════════════════════════════ 
        list_fixes = [
            ('- Free: 10,000\n', '- Free: 50,000\n', 'List: Free 10K→50K'),
            ('- Starter: 250,000\n', '- Starter: 500,000\n', 'List: Starter 250K→500K'),
            ('- Pro: 500,000\n', '- Pro: 2,000,000\n', 'List: Pro 500K→2M'),
            ('- Growth: 1,000,000\n', '- Growth: 5,000,000\n', 'List: Growth 1M→5M'),
            ('- **Scale: 5,000,000**\n', '- **Scale: 20,000,000**\n', 'List: Scale 5M→20M'),
            ('- Enterprise: 20,000,000\n', '- Enterprise: Unlimited\n', 'List: Enterprise 20M→Unlimited'),
        ]
        for old, new, desc in list_fixes:
            if old in new_atxt:
                new_atxt = new_atxt.replace(old, new)
                total_fixes += 1
                fixed_lines.add(ln)
                print(f"  L{ln}: {desc}")
        
        # ═══════════════════════════════════════════════════════════
        # 3. Fix "Starter plan with 250,000 API calls" pattern
        # ═══════════════════════════════════════════════════════════
        starter_api_patterns = [
            ('250,000 API calls', '500,000 API calls'),
            ('250K API calls', '500K API calls'),
        ]
        for old, new in starter_api_patterns:
            if old in new_atxt:
                # Only replace near "Starter" context (within 200 chars)
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):  # reverse to preserve indices
                    context = new_atxt[max(0,pos-200):pos+len(old)+50]
                    if 'Starter' in context or 'starter' in context:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Starter API {old}→{new}")
        
        # ═══════════════════════════════════════════════════════════
        # 4. Fix Free plan "10,000 API calls" 
        # ═══════════════════════════════════════════════════════════
        free_api_patterns = [
            ('**10,000 API calls/mo**', '**50,000 API calls/mo**'),
            ('**10,000 API calls**', '**50,000 API calls**'),
            ('10,000 API calls', '50,000 API calls'),
        ]
        for old, new in free_api_patterns:
            if old in new_atxt:
                # Only replace in Free plan context
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+200]
                    if 'Free' in context or 'free plan' in context.lower():
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Free API {old}→{new}")
        
        # ═══════════════════════════════════════════════════════════
        # 5. Fix Pro plan "500,000 API calls"
        # ═══════════════════════════════════════════════════════════
        pro_api_patterns = [
            ('**500,000 API calls/mo**', '**2,000,000 API calls/mo**'),
            ('**500,000 API calls**', '**2,000,000 API calls**'),
            ('500,000 API calls/mo', '2,000,000 API calls/mo'),
            ('500,000 API calls/month', '2,000,000 API calls/month'),
        ]
        for old, new in pro_api_patterns:
            if old in new_atxt:
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+200]
                    if 'Pro' in context and 'Pro plan' in context or '**Pro' in context or '$65' in context:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Pro API {old}→{new}")
        
        # ═══════════════════════════════════════════════════════════  
        # 6. Fix Growth plan "1,000,000 API calls"
        # ═══════════════════════════════════════════════════════════
        growth_api_patterns = [
            ('**1,000,000 API calls/mo**', '**5,000,000 API calls/mo**'),
            ('**1,000,000 API calls**', '**5,000,000 API calls**'),
            ('1,000,000 API calls/mo', '5,000,000 API calls/mo'),
            ('1,000,000 API calls/month', '5,000,000 API calls/month'),
        ]
        for old, new in growth_api_patterns:
            if old in new_atxt:
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+200]
                    if 'Growth' in context:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Growth API {old}→{new}")
        
        # ═══════════════════════════════════════════════════════════
        # 7. Fix Scale plan "5,000,000 API calls"
        # ═══════════════════════════════════════════════════════════
        scale_api_patterns = [
            ('**5,000,000 API calls per month**', '**20,000,000 API calls per month**'),
            ('**5,000,000 API calls/mo**', '**20,000,000 API calls/mo**'),
            ('5,000,000 API calls/mo', '20,000,000 API calls/mo'),
            ('5,000,000 API calls per month', '20,000,000 API calls per month'),
            ('5M API calls/month', '20M API calls/month'),
            ('5M API calls/mo', '20M API calls/mo'),
        ]
        for old, new in scale_api_patterns:
            if old in new_atxt:
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+200]
                    if 'Scale' in context or '$350' in context:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Scale API {old}→{new}")

        # Also handle: "Scale plan allows 5,000,000 API calls/mo"
        if '5,000,000 API calls' in new_atxt:
            positions = [m3.start() for m3 in re.finditer(r'5,000,000 API calls', new_atxt)]
            for pos in reversed(positions):
                context = new_atxt[max(0,pos-100):pos+30]
                if 'Scale' in context or '$350' in context:
                    new_atxt = new_atxt[:pos] + '20,000,000 API calls' + new_atxt[pos+21:]
                    total_fixes += 1
                    fixed_lines.add(ln)
                    print(f"  L{ln}: Scale API 5M→20M (inline)")
        
        # ═══════════════════════════════════════════════════════════
        # 8. Fix Enterprise plan "20,000,000 API calls" → Unlimited
        # But DON'T change Scale's "20,000,000 API calls" (correct for Scale)
        # ═══════════════════════════════════════════════════════════
        ent_api_patterns = [
            ('**20,000,000 API calls/mo**', '**Unlimited API calls**'),
            ('20,000,000 API calls/mo', 'Unlimited API calls'),            
            ('20,000,000 API calls/month', 'Unlimited API calls/month'),
            ('20M API calls/month', 'Unlimited API calls'),
            ('20M API calls/mo', 'Unlimited API calls'),
        ]
        for old, new in ent_api_patterns:
            if old in new_atxt:
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+50]
                    # Only change if it's clearly about Enterprise, NOT Scale
                    near_enterprise = 'Enterprise' in context or '$800' in context
                    near_scale = 'Scale' in context or '$350' in context
                    if near_enterprise and not near_scale:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Enterprise API 20M→Unlimited")
        
        # Handle "Enterprise... 20M API calls" shorter pattern  
        if '20M API calls' in new_atxt:
            positions = [m3.start() for m3 in re.finditer(r'20M API calls', new_atxt)]
            for pos in reversed(positions):
                context = new_atxt[max(0,pos-200):pos+20]
                near_enterprise = 'Enterprise' in context or '$800' in context
                near_scale = 'Scale' in context or '$350' in context
                if near_enterprise and not near_scale:
                    new_atxt = new_atxt[:pos] + 'Unlimited API calls' + new_atxt[pos+14:]
                    total_fixes += 1
                    fixed_lines.add(ln)
                    print(f"  L{ln}: Enterprise API 20M→Unlimited (short)")

        # ═══════════════════════════════════════════════════════════
        # 9. Fix Enterprise email limit: 2,000,000 → 5,000,000 
        # when attributed to Enterprise (not Scale which is correctly 2M)
        # ═══════════════════════════════════════════════════════════
        
        # Pattern: "Enterprise... 2,000,000 emails" or "Enterprise... 2M emails"
        ent_email_patterns = [
            ('2,000,000** emails/month', '5,000,000** emails/month'),
            ("2,000,000 emails/month (currently", "5,000,000 emails/month (currently"),
        ]
        for old, new in ent_email_patterns:
            if old in new_atxt:
                positions = [m3.start() for m3 in re.finditer(re.escape(old), new_atxt)]
                for pos in reversed(positions):
                    context = new_atxt[max(0,pos-200):pos+len(old)+50]
                    if 'Enterprise' in context or '$800' in context:
                        new_atxt = new_atxt[:pos] + new + new_atxt[pos+len(old):]
                        total_fixes += 1
                        fixed_lines.add(ln)
                        print(f"  L{ln}: Enterprise email 2M→5M")
        
        # Scale plan with wrong email count: "Scale plan includes 2,000,000 emails"
        # Scale = 2M — this is CORRECT, don't touch

        # ═══════════════════════════════════════════════════════════
        # 10. Fix Scale user pages showing "2M emails, 20M API calls"
        # These show Scale limits: 2M emails (correct) + 20M API (correct)
        # But they're flagged because "Enterprise" appears in system prompt
        # → These are CORRECT, skip them
        # ═══════════════════════════════════════════════════════════
        
        # ═══════════════════════════════════════════════════════════
        # 11. Fix Scale descriptions showing wrong API: 5M → 20M
        # "Scale ($350/mo) also includes: 2,000,000 emails/mo, 5,000,000 API calls/mo"
        # ═══════════════════════════════════════════════════════════
        if 'Scale' in new_atxt and '5,000,000 API calls' in new_atxt:
            # Already handled above in step 7
            pass
        
        # ═══════════════════════════════════════════════════════════
        # 12. Fix Enterprise comparison mentions: "Enterprise ($800) includes 2M"
        # ═══════════════════════════════════════════════════════════
        ent_short = [
            ('Enterprise ($800) includes 2M', 'Enterprise ($800) includes 5M'),
            ('Enterprise ($800): 2M', 'Enterprise ($800): 5M'),
            ('Enterprise ($800/mo) with 2M', 'Enterprise ($800/mo) with 5M'),
        ]
        for old, new in ent_short:
            if old in new_atxt:
                new_atxt = new_atxt.replace(old, new)
                total_fixes += 1
                fixed_lines.add(ln)
                print(f"  L{ln}: Enterprise short 2M→5M")
        
        # ═══════════════════════════════════════════════════════════
        # 13. Scale user "2M emails" in plan comparison  
        # "Scale plan at $350/mo for 2M emails" — CORRECT for Scale
        # "Scale plan includes 2,000,000 emails" — CORRECT for Scale
        # "Enterprise includes 5M emails" — CORRECT (already fixed above)
        # ═══════════════════════════════════════════════════════════
        
        # "Scale plan includes **2,000,000 emails per month**" → CORRECT, leave
        # "Scale plan includes **2,000,000 emails/month**" → CORRECT, leave
        
        # But: "Your Scale plan includes **2,000,000 emails per month**" 
        # Scanner flagged as "Enterprise 2M" but it's about Scale → CORRECT
        # Leave these alone.
        
        # ═══════════════════════════════════════════════════════════
        # 14. Fix Starter domains: "3 sending domains" → "5 sending domains"
        # (some lines show 3 instead of 5 for Starter)
        # ═══════════════════════════════════════════════════════════
        if '3 sending domains' in new_atxt:
            positions = [m3.start() for m3 in re.finditer(r'3 sending domains', new_atxt)]
            for pos in reversed(positions):
                context = new_atxt[max(0,pos-150):pos+20]
                if 'Starter' in context or '$25' in context:
                    new_atxt = new_atxt[:pos] + '5 sending domains' + new_atxt[pos+18:]
                    total_fixes += 1
                    fixed_lines.add(ln)
                    print(f"  L{ln}: Starter domains 3→5")

        # ═══════════════════════════════════════════════════════════
        # 15. Fix Growth API "not 2 million" correction responses
        # L620/L905: "Growth plan includes **1,000,000 API calls/month** — not 2 million"
        # Should be: "Growth plan includes **5,000,000 API calls/month**"
        # ═══════════════════════════════════════════════════════════
        bad_correction = '**1,000,000 API calls/month** — not 2 million'
        if bad_correction in new_atxt:
            new_atxt = new_atxt.replace(bad_correction, '**5,000,000 API calls/month**')
            total_fixes += 1
            fixed_lines.add(ln)
            print(f"  L{ln}: Growth API correction fix (1M→5M)")
        
        # Apply changes back to full text
        if new_atxt != atxt:
            text = text[:astart] + new_atxt + text[aend:]
    
    if text != original_text:
        data['text'] = text
        lines[idx] = json.dumps(data, ensure_ascii=False) + '\n'

with open(FILEPATH, 'w') as f:
    f.writelines(lines)

print(f"\n{'='*60}")
print(f"Total fixes: {total_fixes}")
print(f"Lines affected: {len(fixed_lines)}")
print(f"Lines: {sorted(fixed_lines)}")
