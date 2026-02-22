#!/usr/bin/env python3
"""Merge original R15 training data with fix examples.

Takes the original train_agent_r15_backup.jsonl (with tool_call patterns,
data lookups, clarifications, etc.), updates their system prompts to the
corrected version, then appends the curated fix examples.
"""
import json
import re
import random

random.seed(42)

# Load original R15 data (has tool call patterns, data lookup, etc.)
with open("/workspace/train_agent_r15_backup.jsonl") as f:
    original = [json.loads(l) for l in f]
print(f"Original examples: {len(original)}")

# Load fix examples (knowledge corrections + migration)
with open("/workspace/data/train.jsonl") as f:
    fixes = [json.loads(l) for l in f]
print(f"Fix examples: {len(fixes)}")

# Get the SYSTEM_PROMPT from fixes (they all have the correct one)
fix_text = fixes[0]["text"]
new_sys_match = re.search(
    r"<\|im_start\|>system\n(.*?)<\|im_end\|>", fix_text, re.DOTALL
)
new_sys = new_sys_match.group(1)
print(f"System prompt length: {len(new_sys)}")

# Update system prompts in original data
updated = []
for ex in original:
    text = ex["text"]
    old_match = re.search(
        r"<\|im_start\|>system\n(.*?)<\|im_end\|>", text, re.DOTALL
    )
    if old_match:
        text = text.replace(old_match.group(1), new_sys)
    updated.append({"text": text})

# Merge: original (system prompt updated) + fix examples
merged = updated + fixes
random.shuffle(merged)
print(f"Merged total: {len(merged)}")

# Save
with open("/workspace/train_agent_r15.jsonl", "w") as f:
    for ex in merged:
        f.write(json.dumps(ex, ensure_ascii=False) + "\n")
print(f"Saved train_agent_r15.jsonl ({len(merged)} examples)")
