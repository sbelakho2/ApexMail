#!/usr/bin/env python3
"""Patch train.py to handle pre-formatted text data (no messages column)."""

with open("train.py") as f:
    content = f.read()

old = '''    def format_chat(example):
        """Apply the chat template to produce the full text."""
        text = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    dataset = dataset.map(format_chat, remove_columns=["messages"])'''

new = '''    # Handle both pre-formatted text and messages format
    if "messages" in dataset["train"].column_names:
        def format_chat(example):
            """Apply the chat template to produce the full text."""
            text = tokenizer.apply_chat_template(
                example["messages"],
                tokenize=False,
                add_generation_prompt=False,
            )
            return {"text": text}
        dataset = dataset.map(format_chat, remove_columns=["messages"])
    else:
        console.print("[yellow]Data already in text format — skipping chat template[/yellow]")'''

if old in content:
    content = content.replace(old, new)
    with open("train.py", "w") as f:
        f.write(content)
    print("✓ Patched format_chat to handle both formats")
else:
    print("✗ Could not find exact match")
    # Try to check what's there
    if "format_chat" in content:
        import re
        m = re.search(r"def format_chat.*?dataset = dataset\.map\(format_chat.*?\)", content, re.DOTALL)
        if m:
            print(f"Found: {repr(m.group()[:200])}")

# Also patch the post-training eval to handle text-only format
old_eval = '        messages = item["messages"][:2]  # system + user only'
new_eval = '''        # Handle both formats
        if "messages" in item:
            messages = item["messages"][:2]  # system + user only
        else:
            # Extract from pre-formatted text
            import re as _re
            text = item.get("text", "")
            user_match = _re.search(r'<\\|im_start\\|>user\\n(.*?)<\\|im_end\\|>', text, _re.DOTALL)
            sys_match = _re.search(r'<\\|im_start\\|>system\\n(.*?)<\\|im_end\\|>', text, _re.DOTALL)
            messages = []
            if sys_match:
                messages.append({"role": "system", "content": sys_match.group(1)})
            if user_match:
                messages.append({"role": "user", "content": user_match.group(1)})
            if not messages:
                continue'''

if old_eval in content:
    content2 = content.replace(old_eval, new_eval)
    with open("train.py", "w") as f:
        f.write(content2)
    print("✓ Patched post-training eval to handle text format")
else:
    print("✗ Could not find eval section (may already be patched or removed)")
