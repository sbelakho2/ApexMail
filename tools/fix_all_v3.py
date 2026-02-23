#!/usr/bin/env python3
"""
COMPREHENSIVE FIX v3: Fix ALL old pricing values across ALL plans in assistant responses.
Works on assistant text only (preserves system prompts).

Canonical values:
  Free:       $0/3K emails/1 domain/1 team
  Starter:    $25/50K emails/5 domains/5 team/5 webhooks/30d retention
  Pro:        $65/150K emails/25 domains/10 team/10 webhooks/60d retention
  Growth:     $150/500K emails/100 domains/25 team/25 webhooks/90d retention
  Scale:      $350/2M emails/Unlimited domains/50 team/Unlimited webhooks/365d retention
  Enterprise: $800/5M emails/Unlimited domains/Unlimited team/Unlimited webhooks/730d retention
"""
import json, re, sys

filepath = 'data/train_agent.jsonl'

with open(filepath) as f:
    lines = f.readlines()

# Backup
with open(filepath + '.bak4', 'w') as f:
    f.writelines(lines)

fixes_applied = 0
fix_details = []

def fix_assistant_text(text, line_num):
    """Apply all pricing fixes to assistant portions only."""
    global fixes_applied, fix_details
    
    parts = []
    last_end = 0
    changed = False
    
    for m in re.finditer(r'(<\|im_start\|>assistant\n)(.*?)(<\|im_end\|>)', text, re.DOTALL):
        # Add everything before this assistant block
        parts.append(text[last_end:m.start()])
        
        prefix = m.group(1)  # <|im_start|>assistant\n
        assistant = m.group(2)
        suffix = m.group(3)  # <|im_end|>
        
        original_assistant = assistant
        
        # ═══════════════════════════════════════════════════════
        # ENTERPRISE: 2,000,000 → 5,000,000 emails
        # ═══════════════════════════════════════════════════════
        # Only replace when in Enterprise context (within ~200 chars of "Enterprise")
        def fix_enterprise_emails(txt):
            # Pattern: near "Enterprise" context, replace 2,000,000/2M with 5,000,000/5M
            def repl_ent(m):
                full = m.group(0)
                full = re.sub(r'(?<!\d)2,000,000(?!\d)', '5,000,000', full)
                full = re.sub(r'(?<!\d)2,000,000(?!\d)', '5,000,000', full)
                full = re.sub(r'\b2M\b', '5M', full)
                full = re.sub(r'\b2 million\b', '5 million', full)
                return full
            return re.sub(r'(?i)(?:enterprise.{0,200}(?:2,000,000|2M|2 million).{0,50}(?:emails?|included)|(?:2,000,000|2M|2 million)\s*(?:emails?|included).{0,200}enterprise)', repl_ent, txt, flags=re.DOTALL)
        
        # Simple approach: look for Enterprise blocks and replace
        # "2,000,000 emails" near "Enterprise" → "5,000,000 emails"
        if 'nterprise' in assistant:
            # Enterprise email limit
            assistant = re.sub(
                r'((?:Enterprise|enterprise).{0,300}?)(?<!\d)(2,000,000)(\s*(?:emails|email))',
                lambda m: m.group(1) + '5,000,000' + m.group(3),
                assistant, flags=re.DOTALL
            )
            assistant = re.sub(
                r'((?:Enterprise|enterprise).{0,100}?)\b2M\b(\s*emails)',
                lambda m: m.group(1) + '5M' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # SCALE: 500,000 → 2,000,000 emails
        # ═══════════════════════════════════════════════════════
        if 'cale' in assistant:
            assistant = re.sub(
                r'((?:Scale|scale).{0,300}?)(?<!\d)(500,000)(\s*(?:emails|email))',
                lambda m: m.group(1) + '2,000,000' + m.group(3),
                assistant, flags=re.DOTALL
            )
            assistant = re.sub(
                r'((?:Scale|scale).{0,100}?)\b500K\b(\s*emails)',
                lambda m: m.group(1) + '2M' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # GROWTH: 100,000 → 500,000 emails (if still present)
        # ═══════════════════════════════════════════════════════
        if 'rowth' in assistant:
            assistant = re.sub(
                r'((?:Growth|growth).{0,300}?)(?<!\d)(100,000)(\s*(?:emails|email))',
                lambda m: m.group(1) + '500,000' + m.group(3),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # GROWTH: 10 team → 25 team
        # ═══════════════════════════════════════════════════════
        if 'rowth' in assistant:
            # "Growth plan supports up to 10 team members"
            assistant = re.sub(
                r'((?:Growth|growth).{0,200}?)(?<!\d)10(\s+team\s+members?)',
                lambda m: m.group(1) + '25' + m.group(2),
                assistant, flags=re.DOTALL
            )
            # Table rows: "| 10 |" in Growth context — skip, too dangerous
        
        # ═══════════════════════════════════════════════════════
        # GROWTH: 10 domains → 100 domains
        # ═══════════════════════════════════════════════════════
        if 'rowth' in assistant:
            assistant = re.sub(
                r'((?:Growth|growth).{0,200}?)(?<!\d)10(\s+(?:domains?|custom\s+domains?))',
                lambda m: m.group(1) + '100' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # SCALE: 25 team → 50 team
        # ═══════════════════════════════════════════════════════
        if 'cale' in assistant:
            assistant = re.sub(
                r'((?:Scale|scale).{0,200}?)(?<!\d)25(\s+team\s+members?)',
                lambda m: m.group(1) + '50' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # PRO: 50,000 → 150,000 emails (remaining cases)
        # ═══════════════════════════════════════════════════════
        if 'ro' in assistant.lower():
            # "Pro ... 50,000 emails" (not inside 150,000)
            assistant = re.sub(
                r'((?:\bPro\b|\bpro\b).{0,300}?)(?<!1)(?<!\d)\b(50,000)(\s*(?:emails|email))',
                lambda m: m.group(1) + '150,000' + m.group(3),
                assistant, flags=re.DOTALL
            )
            assistant = re.sub(
                r'((?:\bPro\b|\bpro\b).{0,100}?)(?<!1)\b50K\b(\s*(?:emails|email))',
                lambda m: m.group(1) + '150K' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # PRO: 5 team → 10 team (only where Pro is the plan being described)
        # ═══════════════════════════════════════════════════════
        if 'ro' in assistant.lower():
            assistant = re.sub(
                r'((?:\bPro\b|\bpro\b).{0,200}?)(?<!\d)5(\s+team\s+members?)',
                lambda m: m.group(1) + '10' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        # ═══════════════════════════════════════════════════════
        # PRO: 5 domains → 25 domains (where Pro is context)
        # ═══════════════════════════════════════════════════════
        # This is tricky — "5 domains" is correct for Starter
        # Only fix when preceded by "Pro" context specifically
        # Not applying a broad regex here — will handle in specific line fixes
        
        # ═══════════════════════════════════════════════════════
        # OVERAGE MATH: 5,000 × $0.40/1,000 = $2.50 → $2.00
        # ═══════════════════════════════════════════════════════
        assistant = assistant.replace('5,000 × $0.40/1,000 = $2.50', '5,000 × $0.40/1,000 = $2.00')
        assistant = assistant.replace('5,000 × $0.40/1K = $2.50', '5,000 × $0.40/1K = $2.00')
        
        # Fix total that includes the $2.50: "$25 + $2.50 = $27.50 → $25 + $2.00 = $27.00"
        # Actually need to check what the total calculation looks like
        assistant = assistant.replace('$25 + $2.50 = $27.50', '$25 + $2.00 = $27.00')
        assistant = assistant.replace('$25.00 + $2.50 = $27.50', '$25.00 + $2.00 = $27.00')
        assistant = assistant.replace('Total: $27.50/mo', 'Total: $27.00/mo')
        
        # ═══════════════════════════════════════════════════════
        # STARTER: 25 domains → 5 domains (WRONG inflation)
        # ═══════════════════════════════════════════════════════
        if 'tarter' in assistant:
            assistant = re.sub(
                r'((?:Starter|starter).{0,200}?)(?<!\d)25(\s+domains?)',
                lambda m: m.group(1) + '5' + m.group(2),
                assistant, flags=re.DOTALL
            )
        
        if assistant != original_assistant:
            changed = True
        
        parts.append(prefix + assistant + suffix)
        last_end = m.end()
    
    # Add any trailing text
    parts.append(text[last_end:])
    
    new_text = ''.join(parts)
    if new_text != text:
        fixes_applied += 1
        fix_details.append(f"  L{line_num}: fixed")
        return new_text, True
    return text, False

# Apply fixes
for i in range(len(lines)):
    data = json.loads(lines[i])
    text = data['text']
    new_text, changed = fix_assistant_text(text, i + 1)
    if changed:
        data['text'] = new_text
        lines[i] = json.dumps(data, ensure_ascii=False) + '\n'

with open(filepath, 'w') as f:
    f.writelines(lines)

print(f"Fixed {fixes_applied} lines")
for detail in sorted(fix_details):
    print(detail)
