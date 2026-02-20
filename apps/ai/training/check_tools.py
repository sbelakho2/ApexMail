#!/usr/bin/env python3
"""Show the 4 tool_call examples and check what format they use."""
import json

count = 0
with open('/workspace/train_agent.jsonl') as f:
    for i, line in enumerate(f):
        data = json.loads(line)
        text = data['text']
        idx = text.rfind('<|im_start|>assistant\n')
        if idx >= 0:
            response = text[idx:]
            if '```tool_call' in response or 'tool_call' in response.split('<|im_end|>')[0]:
                count += 1
                resp_clean = response.split('<|im_end|>')[0].replace('<|im_start|>assistant\n', '')
                print(f"=== Tool call example {count} (line {i+1}) ({len(resp_clean)} chars) ===")
                print(resp_clean[:600])
                print()
                if count >= 6:
                    break

print(f"\nTotal tool_call examples found: {count}")

# Also look at what patterns the 55 failing tests need
# Check how many examples have specific number patterns
specific_numbers = 0
with open('/workspace/train_agent.jsonl') as f:
    for line in f:
        data = json.loads(line)
        text = data['text']
        idx = text.rfind('<|im_start|>assistant\n')
        if idx >= 0:
            response = text[idx:].split('<|im_end|>')[0]
            # Check for domain-specific facts
            if any(x in response for x in ['2,000,000', '5,000,000', '1,000,000', '25,000', '50,000', '500,000']):
                specific_numbers += 1

print(f"Examples with specific plan numbers: {specific_numbers}")
