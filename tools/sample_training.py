#!/usr/bin/env python3
"""Quick sampler to inspect training data structure."""
import json

with open('data/train_agent.jsonl') as f:
    for i, line in enumerate(f):
        data = json.loads(line)
        text = data.get('text', '')
        if 'tool_call' in text and 'tool_result' in text:
            print(f'=== LINE {i+1} (with tool calls) ===')
            print(text[:5000])
            print()
            break

# Also show last few examples to check diversity
with open('data/train_agent.jsonl') as f:
    lines = f.readlines()
    for idx in [len(lines)-3, len(lines)-2, len(lines)-1]:
        data = json.loads(lines[idx])
        text = data.get('text', '')
        print(f'=== LINE {idx+1} ===')
        # Show just assistant response
        parts = text.split('<|im_start|>assistant\n')
        if len(parts) > 1:
            resp = parts[1].split('<|im_end|>')[0][:300]
            print(f'Assistant: {resp}...')
        print()
