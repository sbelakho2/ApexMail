#!/usr/bin/env python3
"""Debug remaining Pro issues - show exact text patterns."""
import json, re

filepath = 'data/train_agent.jsonl'

# Pro email limit issues
pro_email_lines = [42, 104, 115, 226, 341, 419, 533, 596, 603, 612, 744, 758, 763, 988]
# Pro domain/team issues  
pro_limit_lines = [69, 141, 289, 316, 365, 666, 766, 982]

with open(filepath) as f:
    lines = f.readlines()

print("=" * 72)
print("REMAINING PRO EMAIL 50K REFERENCES")
print("=" * 72)
for ln in pro_email_lines:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    for m in re.finditer(r'.{0,60}(?:pro|Pro).{0,30}50[,.]?000.{0,40}', assistant):
        print(f"  L{ln}: {m.group(0).strip()[:130]}")
    for m in re.finditer(r'.{0,30}50[,.]?000.{0,30}(?:pro|Pro).{0,40}', assistant):
        print(f"  L{ln}: {m.group(0).strip()[:130]}")

print("\n" + "=" * 72)
print("REMAINING PRO DOMAIN/TEAM REFERENCES")
print("=" * 72)
for ln in pro_limit_lines:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    for m in re.finditer(r'.{0,60}(?:5 domains|5 team).{0,60}', assistant, re.I):
        print(f"  L{ln}: {m.group(0).strip()[:130]}")
