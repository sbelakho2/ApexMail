#!/usr/bin/env python3
"""Debug: inspect tool_call block format in training data."""
import json
import re

with open('data/train_agent.jsonl') as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data.get('text', '')
        blocks = re.findall(r'```tool_call\n(.*?)\n```', text, re.DOTALL)
        if blocks and i <= 10:
            for j, block in enumerate(blocks):
                print(f"=== LINE {i}, TOOL_CALL {j+1} ===")
                print(repr(block[:300]))
                try:
                    json.loads(block)
                    print("  -> VALID JSON")
                except json.JSONDecodeError as e:
                    print(f"  -> INVALID: {e}")
                print()
        if i > 10:
            break

# Also check: what do tool_result blocks look like?
print("=" * 60)
print("TOOL RESULT FORMAT")
print("=" * 60)
with open('data/train_agent.jsonl') as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data.get('text', '')
        results = re.findall(r'```tool_result\n(.*?)\n```', text, re.DOTALL)
        if results and i <= 10:
            for j, block in enumerate(results):
                print(f"=== LINE {i}, TOOL_RESULT {j+1} ===")
                print(repr(block[:300]))
                print()
        if i > 10:
            break

# Check what the actual im_start>tool blocks look like
print("=" * 60)
print("IM_START TOOL BLOCKS")
print("=" * 60)
with open('data/train_agent.jsonl') as f:
    for i, line in enumerate(f, 1):
        data = json.loads(line)
        text = data.get('text', '')
        if '<|im_start|>tool' in text and i <= 5:
            parts = re.findall(r'<\|im_start\|>tool\n(.*?)<\|im_end\|>', text, re.DOTALL)
            for j, p in enumerate(parts):
                print(f"=== LINE {i}, TOOL MSG {j+1} ===")
                print(repr(p[:300]))
                print()
