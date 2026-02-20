#!/usr/bin/env python3
"""Analyze training data for behavioral pattern coverage."""
import json

esc_count = 0
tool_count = 0
clarify_count = 0
total = 0

with open('/workspace/train_agent.jsonl') as f:
    for line in f:
        data = json.loads(line)
        msgs = data.get('messages', [])
        for m in msgs:
            if m['role'] == 'assistant':
                content = m['content']
                if 'contact@apexmail.ee' in content:
                    esc_count += 1
                if '```tool_call' in content:
                    tool_count += 1
                if '?' in content and ('clarif' in content.lower() or 'could you' in content.lower() or 'can you' in content.lower()):
                    clarify_count += 1
        total += 1

print(f'Total examples: {total}')
print(f'Assistant responses with contact@apexmail.ee: {esc_count}')
print(f'Assistant responses with tool_call blocks: {tool_count}')
print(f'Assistant responses with clarifying questions: {clarify_count}')
