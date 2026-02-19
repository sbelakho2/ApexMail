#!/usr/bin/env python3
"""Fix v2: revert thinking prefix, keep strip + larger tokens."""

filepath = "/workspace/train/run_all_tests.py"
with open(filepath, "r") as f:
    content = f.read()

# Revert thinking prefix in single-turn (back to original)
content = content.replace(
    'f"<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n"\n    )',
    'f"<|im_start|>assistant\\n"\n    )'
)

# Revert thinking prefix in multi-turn (back to original)
content = content.replace(
    'messages + "<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n"',
    'messages + "<|im_start|>assistant\\n"'
)

# Keep max_new_tokens=1536 (already set)
# Keep thinking strip (already set)

with open(filepath, "w") as f:
    f.write(content)

# Verify
assert '<think>' not in open(filepath).read().split('def run_inference')[1].split('prompt = (')[0][:500]
print("Reverted thinking prefix. Kept: max_new_tokens=1536, thinking strip.")
print("Verifying...")
c = open(filepath).read()
assert 'max_new_tokens=1536' in c, "max_new_tokens not found"
assert 'Strip any thinking' in c, "strip not found"
assert '<think>\\n\\n</think>' not in c, "thinking prefix still present!"
print("All checks passed!")
