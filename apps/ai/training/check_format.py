#!/usr/bin/env python3
"""Check training data format and content."""
import json

with open('/workspace/train_agent.jsonl') as f:
    line = f.readline()
    data = json.loads(line)

print("Keys:", list(data.keys()))
print()

if 'messages' in data:
    msgs = data['messages']
elif 'conversations' in data:
    msgs = data['conversations']
else:
    # Show whatever keys exist
    for k, v in data.items():
        val = str(v)
        print(f"{k}: {val[:200]}")
    msgs = []

for m in msgs:
    role = m.get('role', m.get('from', 'unknown'))
    content = m.get('content', m.get('value', ''))
    print(f"\n--- {role} ---")
    print(content[:300])

# Also check a few more examples for 'contact@apexmail.ee'
print("\n\n=== SEARCHING ALL EXAMPLES ===")
count = 0
found_esc = 0
found_tool = 0
found_q = 0
with open('/workspace/train_agent.jsonl') as f:
    for line in f:
        data = json.loads(line)
        # Check all values
        text = json.dumps(data)
        if 'contact@apexmail' in text:
            # Check if it's in assistant response
            for k, v in data.items():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            role = item.get('role', item.get('from', ''))
                            content = item.get('content', item.get('value', ''))
                            if role == 'assistant' and 'contact@apexmail' in content:
                                found_esc += 1
                            if role == 'assistant' and 'tool_call' in content:
                                found_tool += 1
                            if role == 'assistant' and '?' in content:
                                found_q += 1
        count += 1

print(f"Total examples: {count}")
print(f"Escalation in assistant: {found_esc}")
print(f"Tool call in assistant: {found_tool}")
print(f"Questions in assistant: {found_q}")
