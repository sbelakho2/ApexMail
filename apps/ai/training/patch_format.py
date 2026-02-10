"""Patch train.py to handle pre-formatted text data."""
import re

with open("train.py") as f:
    content = f.read()

old = '    dataset = dataset.map(format_chat, remove_columns=["messages"])'
new = """    # Only apply format_chat if data has "messages" column (not pre-formatted "text")
    if "messages" in dataset["train"].column_names:
        dataset = dataset.map(format_chat, remove_columns=["messages"])
    else:
        console.print("[yellow]Data already in text format, skipping format_chat[/yellow]")"""

if old in content:
    content = content.replace(old, new)
    with open("train.py", "w") as f:
        f.write(content)
    print("Patched train.py successfully!")
else:
    print("Already patched or pattern not found")
    # Check if it's already patched
    if 'if "messages" in dataset["train"].column_names:' in content:
        print("Already patched!")
    else:
        print("ERROR: Could not find the pattern to patch")
