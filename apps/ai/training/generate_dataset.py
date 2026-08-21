#!/usr/bin/env python3
"""
ApexMail AI — Dataset Splitter

Splits data/train_agent.jsonl into train / val / test JSONL files
for use by train.py and evaluation scripts.

Splits are STABLE PER ROW: each row's bucket is derived from a hash of its
canonical JSON content, so re-running the splitter (or appending new rows)
never moves an existing row between train/val/test. The previous
shuffle+seed approach re-shuffled the whole corpus whenever rows were
appended (for example by generate_recovered_training.py), which leaked old
val/test rows into train.

Usage:
    python generate_dataset.py                    # 80/10/10 split (default)
    python generate_dataset.py --val 0.15 --test 0.05
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from common_paths import TRAIN_JSONL, DATA_DIR


def row_bucket(row: dict, val_frac: float, test_frac: float) -> str:
    """Deterministically assign a row to train/val/test from its content.

    The bucket depends only on the row's canonical JSON and the split
    fractions — not on row order or on the presence of other rows.
    """
    payload = json.dumps(row, sort_keys=True, ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).digest()
    roll = int.from_bytes(digest[:8], "big") / 2**64
    if roll < val_frac:
        return "val"
    if roll < val_frac + test_frac:
        return "test"
    return "train"


def main() -> None:
    parser = argparse.ArgumentParser(description="Split training data into train/val/test sets")
    parser.add_argument("--input", default=str(TRAIN_JSONL), help="Source JSONL file")
    parser.add_argument("--output-dir", default=str(DATA_DIR), help="Output directory for splits")
    parser.add_argument("--val", type=float, default=0.10, help="Validation set fraction (default: 0.10)")
    parser.add_argument("--test", type=float, default=0.10, help="Test set fraction (default: 0.10)")
    parser.add_argument("--dry-run", action="store_true", help="Print counts without writing files")
    args = parser.parse_args()

    assert 0 < args.val < 1, f"--val must be between 0 and 1, got {args.val}"
    assert 0 < args.test < 1, f"--test must be between 0 and 1, got {args.test}"
    assert args.val + args.test < 1, "val + test must be < 1"

    # Load data
    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    with open(input_path) as f:
        examples = [json.loads(line) for line in f if line.strip()]

    total = len(examples)
    print(f"Loaded {total} examples from {input_path}")

    # Stable per-row assignment (content hash → bucket)
    train_set, val_set, test_set = [], [], []
    for example in examples:
        bucket = row_bucket(example, args.val, args.test)
        if bucket == "val":
            val_set.append(example)
        elif bucket == "test":
            test_set.append(example)
        else:
            train_set.append(example)

    print(f"Split: train={len(train_set)}, val={len(val_set)}, test={len(test_set)}")

    if args.dry_run:
        print("Dry run — no files written.")
        return

    # Write output files
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, data in [("train", train_set), ("val", val_set), ("test", test_set)]:
        out_path = out_dir / f"{name}.jsonl"
        with open(out_path, "w", encoding="utf-8") as f:
            for item in data:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"  Wrote {len(data)} examples to {out_path}")

    # Verify round-trip
    total_written = 0
    for name in ["train", "val", "test"]:
        with open(out_dir / f"{name}.jsonl") as f:
            count = sum(1 for line in f if line.strip())
            total_written += count
    assert total_written == total, f"Verification failed: {total_written} != {total}"
    print(f"\nVerification passed: {total_written} total examples across 3 files")


if __name__ == "__main__":
    main()
