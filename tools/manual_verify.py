#!/usr/bin/env python3
"""
Manual verification: Show exact context for each of the 48 flagged issues.
This helps distinguish real errors from false positives.
"""
import json, re

FILEPATH = 'data/train_agent.jsonl'

with open(FILEPATH) as f:
    lines = f.readlines()

flagged_lines = [69, 96, 141, 148, 169, 217, 228, 232, 310, 334, 365, 384, 635, 657, 709, 751, 766, 814, 904, 967, 1015, 1040, 1044, 1053]

def get_assistant(text):
    parts = re.findall(r'<\|im_start\|>assistant\n(.*?)(?:<\|im_end\|>|$)', text, re.DOTALL)
    return '\n---NEXT_ASSISTANT---\n'.join(parts)

for ln in flagged_lines:
    data = json.loads(lines[ln - 1])
    text = data['text']
    assistant = get_assistant(text)
    
    # Also get the plan from system prompt
    sys_match = re.search(r'Plan:\s*(\w+)', text)
    plan = sys_match.group(1) if sys_match else 'unknown'
    
    print(f"\n{'='*70}")
    print(f"L{ln} | Plan: {plan} | Assistant length: {len(assistant)} chars")
    print(f"{'='*70}")
    
    # Print full assistant response (truncated at 3000 chars)
    if len(assistant) > 3000:
        print(assistant[:3000])
        print(f"\n... ({len(assistant) - 3000} more chars)")
    else:
        print(assistant)
