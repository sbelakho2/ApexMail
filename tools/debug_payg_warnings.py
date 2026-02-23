#!/usr/bin/env python3
"""Debug: check PAYG warnings and XXX placeholder."""
import json
import re

filepath = 'data/train_agent.jsonl'

# Check PAYG warnings on specific lines
payg_lines = [104, 160, 287, 341, 416, 505]
print("=" * 60)
print("PAYG WARNINGS")
print("=" * 60)
for target in payg_lines:
    with open(filepath) as f:
        for i, line in enumerate(f, 1):
            if i == target:
                data = json.loads(line)
                text = data.get('text', '')
                # Get assistant text
                parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
                assistant = '\n'.join(parts)
                # Show PAYG-related content
                for m in re.finditer(r'(.{0,80}50[,.]?000.{0,150})', assistant, re.I):
                    snippet = m.group(0).replace('\n', ' ')
                    print(f"\nL{i}: ...{snippet[:200]}...")
                break

# Check XXX on line 30
print("\n" + "=" * 60)
print("XXX PLACEHOLDER ON LINE 30")
print("=" * 60)
with open(filepath) as f:
    for i, line in enumerate(f, 1):
        if i == 30:
            data = json.loads(line)
            text = data.get('text', '')
            parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
            for p in parts:
                if 'XXX' in p or 'xxx' in p.lower():
                    # Show context
                    idx = p.upper().find('XXX')
                    snippet = p[max(0, idx-100):idx+100]
                    print(f"Context: ...{snippet}...")
            break

# Count how many unique PAYG errors vs false positives
print("\n" + "=" * 60)
print("ALL 50K PAYG MENTIONS")
print("=" * 60)
with open(filepath) as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data.get('text', '')
        parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
        assistant = '\n'.join(parts)
        if '50,000 emails' in assistant.lower() or '50000 emails' in assistant.lower():
            # Look for cost mentions near it
            for m in re.finditer(r'50[,.]?000\s+emails.*?(?:total|cost|=|would be)\s*:?\s*\*?\*?\$?([\d.]+)', assistant.lower()):
                val = float(m.group(1))
                if abs(val - 42.0) > 0.5:
                    context = assistant[max(0, m.start()-50):m.end()+50].replace('\n', ' ')
                    print(f"L{i}: ${val} — ...{context[:200]}...")
