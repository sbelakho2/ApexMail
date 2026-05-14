"""
Shared utilities for training data fix scripts.

Provides JSONL reading/writing with backup, assistant-text-only editing,
and common fix patterns used across all fix scripts.
"""

import json
import re
import shutil
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


def read_jsonl(path: Path) -> List[dict]:
    """Read a JSONL file and return parsed objects."""
    with open(path) as f:
        return [json.loads(line) for line in f]


def write_jsonl(path: Path, records: List[dict], backup: bool = True) -> None:
    """Write records to a JSONL file, optionally creating a .bak backup."""
    if backup and path.exists():
        bak = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, bak)

    with open(path, 'w') as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')


def iter_jsonl(path: Path):
    """Generator yielding (line_num, parsed_dict) for a JSONL file."""
    with open(path) as f:
        for i, line in enumerate(f, 1):
            yield i, json.loads(line)


def split_messages(text: str) -> List[Tuple[Optional[str], str]]:
    """Split ChatML text into (role, content) pairs."""
    parts = re.split(r'(<\|im_start\|>(?:system|user|tool|assistant)\n)', text)
    result: List[Tuple[Optional[str], str]] = []
    current_role = None

    for part in parts:
        role_match = re.match(r'<\|im_start\|>(\w+)\n', part)
        if role_match:
            current_role = role_match.group(1)
            result.append((current_role, ''))
        elif current_role:
            role, _ = result[-1]
            result[-1] = (role, part)
        else:
            result.append((None, part))

    return result


def edit_assistant_text(text: str, editor: Callable[[str], str]) -> str:
    """
    Apply `editor` function to all assistant messages in a ChatML text.
    Non-assistant messages are left unchanged.
    """
    parts = re.split(r'(<\|im_start\|>(?:system|user|tool|assistant)\n)', text)
    new_parts = []
    current_role = None

    for part in parts:
        role_match = re.match(r'<\|im_start\|>(\w+)\n', part)
        if role_match:
            current_role = role_match.group(1)
            new_parts.append(part)
            continue

        if current_role == 'assistant':
            new_parts.append(editor(part))
        else:
            new_parts.append(part)

    return ''.join(new_parts)


def apply_line_fixes(
    filepath: Path,
    fixers: Dict[int, Callable[[str], str]],
    global_fixer: Optional[Callable[[int, str], Tuple[str, List[str]]]] = None,
) -> int:
    """
    Apply line-specific fixers (by line number) and an optional global fixer
    to a JSONL file. Returns total number of lines modified.
    """
    records = read_jsonl(filepath)
    fixed_count = 0

    for i, rec in enumerate(records, 1):
        text = rec.get('text', '')
        original = text

        # Apply line-specific rewrite
        if i in fixers:
            text = fixers[i](text)

        # Apply global fixer
        if global_fixer:
            text, _ = global_fixer(i, text)

        if text != original:
            rec['text'] = text
            fixed_count += 1

    write_jsonl(filepath, records)
    return fixed_count
