#!/usr/bin/env python3
"""
Fix v4: Fix Pro domains back to 25 (v3 accidentally changed them).
Also fix L334/L814 comparison tables and L310/L1044 comprehensive tables.
"""
import json, re

filepath = 'data/train_agent.jsonl'

with open(filepath) as f:
    lines = f.readlines()

fixes = 0

def fix_assistant(text, line_num):
    """Fix Pro domain count and other remaining issues in assistant responses."""
    global fixes
    parts = []
    last_end = 0
    changed = False
    
    for m in re.finditer(r'(<\|im_start\|>assistant\n)(.*?)(<\|im_end\|>)', text, re.DOTALL):
        parts.append(text[last_end:m.start()])
        prefix = m.group(1)
        assistant = m.group(2)
        suffix = m.group(3)
        original = assistant
        
        # ═══ Fix Pro domains: 5 → 25 (where in Pro context) ═══
        # Table row: "| **Pro** | ... | 5 domains"
        assistant = re.sub(
            r'(\|\s*\*?\*?Pro\*?\*?\s*\|.*?)(?<!\d)5(\s+domains)',
            lambda m: m.group(1) + '25' + m.group(2),
            assistant
        )
        
        # Bullet: "- Pro: 5 domains" → "- Pro: 25 domains"
        assistant = re.sub(
            r'(-\s*Pro\s*:\s*)(?<!\d)5(\s+domains)',
            lambda m: m.group(1) + '25' + m.group(2),
            assistant
        )
        
        # "Pro plan ... 5 domains" (within same sentence/line context)
        assistant = re.sub(
            r'(Pro\s+(?:plan\s+)?(?:\([^)]+\)\s*)?.*?)(?<!\d)5(\s+domains)',
            lambda m: m.group(1) + '25' + m.group(2) if len(m.group(1)) < 100 else m.group(0),
            assistant
        )
        
        # "Pro ($65/mo):...5 custom domains" patterns
        assistant = re.sub(
            r'(Pro\s*\(\$65(?:/mo)?\).*?)(?<!\d)5(\s+(?:custom\s+)?domains)',
            lambda m: m.group(1) + '25' + m.group(2) if len(m.group(1)) < 150 else m.group(0),
            assistant, flags=re.DOTALL
        )
        
        # ═══ Fix Pro team: 5 → 10 (table row pattern) ═══
        assistant = re.sub(
            r'(\|\s*\*?\*?Pro\*?\*?\s*\|.*?)(?<!\d)5(\s+team)',
            lambda m: m.group(1) + '10' + m.group(2),
            assistant
        )
        
        # ═══ Fix Scale team: 25 → 50 (table row pattern) ═══
        assistant = re.sub(
            r'(\|\s*\*?\*?Scale\*?\*?\s*\|.*?)(?<!\d)25(\s+team)',
            lambda m: m.group(1) + '50' + m.group(2),
            assistant
        )
        
        # ═══ Fix Pro emails: 50,000/50K remaining in table rows ═══
        # Table: "| Pro | $65 | 50K |" or "| Pro | $65 | 50,000 |" 
        assistant = re.sub(
            r'(\|\s*(?:\*?\*?)?Pro(?:\s*\(\$65\))?\s*\|.*?)\b50,000\b',
            lambda m: m.group(1) + '150,000' if len(m.group(1)) < 80 else m.group(0),
            assistant
        )
        assistant = re.sub(
            r'(\|\s*(?:\*?\*?)?Pro(?:\s*\(\$65\))?\s*\|.*?)\b50K\b',
            lambda m: m.group(1) + '150K' if len(m.group(1)) < 80 else m.group(0),
            assistant
        )
        
        if assistant != original:
            changed = True
        
        parts.append(prefix + assistant + suffix)
        last_end = m.end()
    
    parts.append(text[last_end:])
    new_text = ''.join(parts)
    
    if new_text != text:
        fixes += 1
        return new_text, True
    return text, False

for i in range(len(lines)):
    data = json.loads(lines[i])
    new_text, changed = fix_assistant(data['text'], i + 1)
    if changed:
        data['text'] = new_text
        lines[i] = json.dumps(data, ensure_ascii=False) + '\n'

with open(filepath, 'w') as f:
    f.writelines(lines)

print(f"Fixed {fixes} lines")
