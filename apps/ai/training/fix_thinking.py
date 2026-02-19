#!/usr/bin/env python3
"""Fix run_all_tests.py to suppress Qwen3 thinking mode at inference time."""

import sys

filepath = "/workspace/train/run_all_tests.py"
with open(filepath, "r") as f:
    content = f.read()

original = content

# Fix 1: Add <think>\n\n</think>\n\n after assistant\n in single-turn prompt
content = content.replace(
    'f"<|im_start|>assistant\\n"\n    )',
    'f"<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n"\n    )'
)

# Fix 2: Same for multi-turn prompt
content = content.replace(
    'messages + "<|im_start|>assistant\\n"',
    'messages + "<|im_start|>assistant\\n<think>\\n\\n</think>\\n\\n"'
)

# Fix 3: Increase max_new_tokens for safety
content = content.replace("max_new_tokens=768", "max_new_tokens=1536")

# Fix 4: Add thinking strip to response extraction in run_inference
old_return = '''    return response.strip()


def run_multiturn_test'''
new_return = '''    # Strip any thinking blocks that leaked through
    import re as _re
    response = _re.sub(r"<think>.*?</think>", "", response, flags=_re.DOTALL).strip()
    return response.strip()


def run_multiturn_test'''
content = content.replace(old_return, new_return)

# Fix 5: Add thinking strip to multiturn response extraction
old_mt_response = '''            response = response.strip()

            checks = step["check_assistant"]'''
new_mt_response = '''            response = response.strip()
            # Strip any thinking blocks
            import re as _re
            response = _re.sub(r"<think>.*?</think>", "", response, flags=_re.DOTALL).strip()

            checks = step["check_assistant"]'''
content = content.replace(old_mt_response, new_mt_response)

changes = 0
if content != original:
    with open(filepath, "w") as f:
        f.write(content)
    # Count changes
    for fix_name, old_text in [
        ("thinking prefix (single)", 'f"<|im_start|>assistant\\n"\n    )'),
        ("thinking prefix (multi)", 'messages + "<|im_start|>assistant\\n"'),
        ("max_new_tokens", "max_new_tokens=768"),
    ]:
        if old_text not in content:
            changes += 1
            print(f"  Applied: {fix_name}")
    if "Strip any thinking" in content:
        changes += 1
        print(f"  Applied: thinking strip")
    print(f"Total changes applied: {changes}")
else:
    print("WARNING: No changes made!")
    sys.exit(1)
