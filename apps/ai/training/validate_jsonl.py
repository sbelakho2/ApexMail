#!/usr/bin/env python3
import json

errors = []
with open("data/train_agent.jsonl") as f:
    for i, line in enumerate(f, 1):
        try:
            obj = json.loads(line)
            text = obj["text"]
            if "<|im_start|>system" not in text:
                errors.append(f"Line {i}: missing system turn")
            if "<|im_start|>user" not in text:
                errors.append(f"Line {i}: missing user turn")
            if "<|im_start|>assistant" not in text:
                errors.append(f"Line {i}: missing assistant turn")
            if not text.endswith("<|im_end|>"):
                errors.append(f"Line {i}: does not end with <|im_end|>")
        except json.JSONDecodeError as e:
            errors.append(f"Line {i}: JSON error: {e}")

print(f"Lines checked: {i}")
print(f"Errors: {len(errors)}")
for e in errors[:10]:
    print(f"  {e}")
if not errors:
    print("ALL VALIDATIONS PASSED")
