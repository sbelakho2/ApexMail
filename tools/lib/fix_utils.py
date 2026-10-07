"""
Shared utilities for training data fix scripts.

Provides JSONL reading/writing with backup, assistant-text-only editing,
and common fix patterns used across all fix scripts.
"""

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple


class UnsafeWriteError(RuntimeError):
    """Refused to overwrite an existing data file without a backup."""


def read_jsonl(path: Path) -> List[dict]:
    """Read a JSONL file and return parsed objects."""
    with open(path) as f:
        return [json.loads(line) for line in f]


def _prepare_write(path: Path, backup: bool, dry_run: bool) -> bool:
    """Apply the backup-or-dry-run guard. False = dry run, write nothing."""
    path = Path(path)
    if dry_run:
        return False
    if path.exists():
        if not backup:
            raise UnsafeWriteError(
                f"refusing to overwrite {path} without a backup "
                f"(pass backup=True or dry_run=True)"
            )
        bak = path.with_suffix(path.suffix + ".bak")
        shutil.copy2(path, bak)
    return True


def write_jsonl(
    path: Path,
    records: List[dict],
    backup: bool = True,
    dry_run: bool = False,
) -> bool:
    """Write records to a JSONL file under the backup-or-dry-run guard.

    Safety contract (coverage audit U-2b): overwriting an EXISTING file
    requires `backup=True` — a `<path>.bak` copy is made first and the write
    is refused with UnsafeWriteError otherwise. `dry_run=True` writes
    nothing and returns False. Returns True when the file was written.
    """
    if not _prepare_write(Path(path), backup, dry_run):
        return False
    with open(path, 'w') as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
    return True


def write_lines(
    path: Path,
    lines: List[str],
    backup: bool = True,
    dry_run: bool = False,
) -> bool:
    """Write raw text lines under the same backup-or-dry-run guard.

    Used by rewriters that must preserve unparseable lines verbatim.
    """
    if not _prepare_write(Path(path), backup, dry_run):
        return False
    with open(path, 'w') as f:
        f.writelines(lines)
    return True


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
    dry_run: bool = False,
) -> int:
    """
    Apply line-specific fixers (by line number) and an optional global fixer
    to a JSONL file. Returns total number of lines modified. Honors the
    backup-or-dry-run guard: a backup is always written before the file is
    overwritten, and dry_run=True changes nothing on disk.
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

    write_jsonl(filepath, records, backup=True, dry_run=dry_run)
    return fixed_count


def self_test() -> int:
    """Can-fail probe for the backup-or-dry-run guard (coverage audit U-2b)."""
    import tempfile

    failures: List[str] = []
    with tempfile.TemporaryDirectory(prefix="apexmail-fixutils-selftest-") as tmp:
        target = Path(tmp) / "corpus.jsonl"
        original = {"text": "original"}
        write_jsonl(target, [original], backup=False)  # new file: allowed
        before = target.read_text()

        # Dry run must change nothing on disk.
        changed = write_jsonl(target, [{"text": "dry"}], dry_run=True)
        if changed is not False or target.read_text() != before:
            failures.append("dry_run wrote to disk")

        # Backupless overwrite of an existing file must be refused.
        try:
            write_jsonl(target, [{"text": "unsafe"}], backup=False)
        except UnsafeWriteError:
            pass
        else:
            failures.append("backup=False overwrite of an existing file was allowed")
        if target.read_text() != before:
            failures.append("refused write still modified the file")

        # Backed-up overwrite succeeds and leaves the original in .bak.
        write_jsonl(target, [{"text": "fixed"}], backup=True)
        backup = target.with_suffix(target.suffix + ".bak")
        if not backup.exists() or backup.read_text() != before:
            failures.append("backup was not created (or does not hold the original)")
        if json.loads(target.read_text().strip())["text"] != "fixed":
            failures.append("guarded write did not update the file")

        # write_lines shares the same guard.
        raw = Path(tmp) / "raw.jsonl"
        write_lines(raw, ["not json\n"], backup=False)
        try:
            write_lines(raw, ["other\n"], backup=False)
        except UnsafeWriteError:
            pass
        else:
            failures.append("write_lines allowed a backupless overwrite")

    if failures:
        for failure in failures:
            print(f"SELFTEST FAIL: {failure}", file=sys.stderr)
        return 1
    print("fix_utils self-test passed: dry-run, refusal, and backup paths behave")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    print("lib.fix_utils is a library; run with --self-test", file=sys.stderr)
    raise SystemExit(2)
