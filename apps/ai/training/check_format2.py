#!/usr/bin/env python3
"""Extract and display assistant response from first few examples."""
import json

with open('/workspace/train_agent.jsonl') as f:
    for i, line in enumerate(f):
        if i >= 3:
            break
        data = json.loads(line)
        text = data['text']
        
        # Find assistant response
        idx = text.rfind('<|im_start|>assistant\n')
        if idx >= 0:
            response = text[idx + len('<|im_start|>assistant\n'):]
            # Trim at end token
            end_idx = response.find('<|im_end|>')
            if end_idx >= 0:
                response = response[:end_idx]
            print(f"=== Example {i+1} assistant response ({len(response)} chars) ===")
            print(response[:500])
            print()

# Count behavioral patterns in assistant responses
print("\n=== BEHAVIORAL PATTERN ANALYSIS ===")
esc = tool = clarify = thinking = 0
total = 0
with open('/workspace/train_agent.jsonl') as f:
    for line in f:
        data = json.loads(line)
        text = data['text']
        idx = text.rfind('<|im_start|>assistant\n')
        if idx >= 0:
            response = text[idx:]
            if 'contact@apexmail.ee' in response:
                esc += 1
            if '```tool_call' in response or '```\ntool_call' in response:
                tool += 1
            if '?' in response:
                clarify += 1
            if '<think>' in response:
                thinking += 1
        total += 1

print(f"Total: {total}")
print(f"Escalation (contact@apexmail.ee): {esc}")
print(f"Tool calls: {tool}")
print(f"Questions (?): {clarify}")
print(f"Thinking tags (<think>): {thinking}")
