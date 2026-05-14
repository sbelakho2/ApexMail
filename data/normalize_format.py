#!/usr/bin/env python3
"""
normalize_format.py — Convert all training data files to uniform chat format.

Converts val.jsonl and test.jsonl (prompt/completion format → messages format)
to match train.jsonl's chat format {"messages": [...]}.

Usage:
    python normalize_format.py                          # normalize all data files
    python normalize_format.py --dry-run                # preview changes
    python normalize_format.py --check                  # just check consistency
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def detect_format(entry: dict) -> str:
    """Detect the format of a training data entry."""
    if "messages" in entry:
        return "chat"
    if "text" in entry:
        if "<|im_start|>" in entry.get("text", ""):
            return "chatml_text"
        return "prompt_completion"
    if "prompt" in entry or "completion" in entry:
        return "prompt_completion"
    return "unknown"


def convert_to_chat(entry: dict) -> dict:
    """Convert any format to chat format."""
    fmt = detect_format(entry)
    
    if fmt == "chat":
        return entry
    
    if fmt == "chatml_text":
        # Already has text in chat ML format but missing messages array
        text = entry.get("text", "")
        # Extract system from text
        system_match = __import__("re").search(r"<|im_start|>system\n(.+?)<|im_end|>", text, __import__("re").DOTALL)
        user_match = __import__("re").search(r"<|im_start|>user\n(.+?)<|im_end|>", text, __import__("re").DOTALL)
        assistant_match = __import__("re").search(r"<|im_start|>assistant\n(.+?)(?:<|im_end|>|$)", text, __import__("re").DOTALL)
        
        messages = []
        if system_match:
            messages.append({"role": "system", "content": system_match.group(1).strip()})
        if user_match:
            messages.append({"role": "user", "content": user_match.group(1).strip()})
        if assistant_match:
            messages.append({"role": "assistant", "content": assistant_match.group(1).strip()})
        
        if messages:
            result = {
                "messages": messages,
                "format": "chat",
            }
            # Preserve system_prompt_id if present
            if "system_prompt_id" in entry:
                result["system_prompt_id"] = entry["system_prompt_id"]
            return result
    
    if fmt == "prompt_completion":
        messages = []
        prompt = entry.get("prompt", entry.get("text", ""))
        completion = entry.get("completion", "")
        
        # Try to extract system prompt
        system_match = __import__("re").search(
            r"<|im_start|>system\n(.+?)<|im_end|>", prompt, __import__("re").DOTALL
        )
        if system_match:
            messages.append({"role": "system", "content": system_match.group(1).strip()})
            prompt = __import__("re").sub(
                r"<|im_start|>system\n.+?<|im_end|>\n?", "", prompt, count=1
            )
        
        # Clean up user/assistant markers
        user_content = __import__("re").sub(
            r"<|im_start|>user\n", "", prompt
        ).replace("<|im_end|>", "").strip()
        
        if user_content:
            messages.append({"role": "user", "content": user_content})
        if completion:
            assistant_content = __import__("re").sub(
                r"<|im_start|>assistant\n", "", completion
            ).replace("<|im_end|>", "").strip()
            messages.append({"role": "assistant", "content": assistant_content})
        
        if messages:
            result = {"messages": messages, "format": "chat"}
            if "system_prompt_id" in entry:
                result["system_prompt_id"] = entry["system_prompt_id"]
            return result
    
    return entry


def normalize_file(filepath: str | Path, dry_run: bool = False) -> dict:
    """Normalize a single JSONL file to chat format."""
    path = Path(filepath)
    if not path.exists():
        return {"file": str(path), "status": "not_found", "entries": 0, "converted": 0}
    
    entries = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    
    converted = 0
    normalized = []
    for entry in entries:
        new_entry = convert_to_chat(entry)
        if detect_format(new_entry) != detect_format(entry):
            converted += 1
        normalized.append(new_entry)
    
    if not dry_run and converted > 0:
        with open(path, "w") as f:
            for entry in normalized:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    
    return {
        "file": str(path),
        "status": "ok",
        "entries": len(entries),
        "converted": converted,
        "format": detect_format(normalized[0]) if normalized else "unknown",
    }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Normalize training data files to uniform chat format"
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview changes only")
    parser.add_argument("--check", action="store_true", help="Just check consistency")
    args = parser.parse_args()
    
    data_dir = Path(__file__).resolve().parents[1] / "data"
    files = [
        data_dir / "train.jsonl",
        data_dir / "val.jsonl",
        data_dir / "test.jsonl",
        data_dir / "golden_qa.jsonl",
    ]
    
    results = []
    for f in files:
        result = normalize_file(f, dry_run=args.dry_run or args.check)
        results.append(result)
        print(f"  {result['file']}: {result['entries']} entries, "
              f"{result['converted']} converted, format={result['format']}")
    
    # Check consistency
    formats = {r["format"] for r in results if r["status"] == "ok"}
    all_consistent = len(formats) <= 1
    
    if args.check:
        print(f"\nConsistency check: {'✅ PASS' if all_consistent else '❌ FAIL'}")
        if not all_consistent:
            print(f"  Found formats: {formats}")
        return 0 if all_consistent else 1
    
    if args.dry_run:
        print(f"\nDry run: {sum(r['converted'] for r in results)} entries would be converted")
    else:
        print(f"\nNormalized: {sum(r['converted'] for r in results)} entries converted")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
