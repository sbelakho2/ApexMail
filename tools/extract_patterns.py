#!/usr/bin/env python3
"""
Extract exact text patterns for lines that need domain/team fixes.
Shows the exact strings around '3 domains' / '3 team' / '5 domains' / '5 team'
"""
import json
import re

filepath = 'data/train_agent.jsonl'

# Group 1: Starter 3 domains/team
starter_lines = [126, 141, 148, 246, 289, 334, 365, 450, 534, 633, 668, 785, 814, 834, 864, 904, 982, 1019]
# Group 2: Pro 5 domains/team  
pro_lines = [69, 141, 246, 289, 316, 365, 450, 534, 666, 744, 758, 766, 982, 1019]
# Group 3: Pro 50K emails
pro_email_lines = [104, 115, 226, 341, 419, 533, 596, 612, 744, 758, 763, 988]
# Group 4: Lines with overage math errors
math_lines = [42, 310, 533, 596, 603, 689, 783, 851, 964, 1044]

with open(filepath) as f:
    lines = f.readlines()

# Show patterns for each group
print("=" * 72)
print("GROUP 1: Starter '3 domains' / '3 team' patterns")  
print("=" * 72)
for ln in starter_lines[:5]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    for m in re.finditer(r'.{0,50}(?:3 domains|3 team).{0,50}', assistant, re.I):
        print(f"  L{ln}: ...{m.group(0).strip()}...")

print("\n" + "=" * 72)
print("GROUP 2: Pro '5 domains' / '5 team' patterns")
print("=" * 72)
for ln in pro_lines[:5]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    for m in re.finditer(r'.{0,50}(?:5 domains|5 team).{0,50}', assistant, re.I):
        print(f"  L{ln}: ...{m.group(0).strip()}...")

print("\n" + "=" * 72)
print("GROUP 3: Pro '50,000 emails' patterns")
print("=" * 72)
for ln in pro_email_lines[:5]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    assistant = '\n'.join(parts)
    for m in re.finditer(r'.{0,80}(?:pro|Pro).{0,20}50[,.]?000.{0,50}', assistant):
        print(f"  L{ln}: ...{m.group(0).strip()[:130]}...")

print("\n" + "=" * 72)
print("GROUP 4a: Lines 42/603 full overage section")
print("=" * 72)
for ln in [42, 603, 689, 851]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    print(f"\n  L{ln}:")
    for p in parts:
        print(f"  {p.strip()[:500]}")

print("\n" + "=" * 72)
print("GROUP 4b: Lines 310/1044 full response")
print("=" * 72)
for ln in [310, 1044]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    print(f"\n  L{ln}:")
    for j, p in enumerate(parts):
        print(f"  ASSISTANT [{j+1}]:\n  {p.strip()[:600]}")

print("\n" + "=" * 72)
print("GROUP 4c: Lines 533/596 (Pro+overage)")
print("=" * 72)
for ln in [533, 596]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    print(f"\n  L{ln}:")
    for p in parts:
        for m in re.finditer(r'.{0,50}(?:overage|Pro|50,000|2,800).{0,100}', p):
            print(f"  ...{m.group(0).strip()[:150]}...")

print("\n" + "=" * 72)
print("GROUP 4d: Lines 783/964 (42,000 overage)")
print("=" * 72)
for ln in [783, 964]:
    data = json.loads(lines[ln-1])
    text = data['text']
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    print(f"\n  L{ln}:")
    for p in parts:
        for m in re.finditer(r'.{0,50}(?:overage|42,000).{0,100}', p):
            print(f"  ...{m.group(0).strip()[:150]}...")
