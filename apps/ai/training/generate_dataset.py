#!/usr/bin/env python3
"""
ApexMail AI — Dataset Splitter

Splits data/train_agent.jsonl into train / val / test JSONL files
for use by train.py and evaluation scripts.

Usage:
    python generate_dataset.py                    # 80/10/10 split (default)
    python generate_dataset.py --val 0.15 --test 0.05
    python generate_dataset.py --seed 123
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Split training data into train/val/test sets")
    parser.add_argument("--input", default="data/train_agent.jsonl", help="Source JSONL file")
    parser.add_argument("--output-dir", default="data", help="Output directory for splits")
    parser.add_argument("--val", type=float, default=0.10, help="Validation set fraction (default: 0.10)")
    parser.add_argument("--test", type=float, default=0.10, help="Test set fraction (default: 0.10)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
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

    # Shuffle deterministically
    random.seed(args.seed)
    random.shuffle(examples)

    # Compute split indices
    n_val = int(total * args.val)
    n_test = int(total * args.test)
    n_train = total - n_val - n_test

    train_set = examples[:n_train]
    val_set = examples[n_train : n_train + n_val]
    test_set = examples[n_train + n_val :]

    print(f"Split: train={len(train_set)}, val={len(val_set)}, test={len(test_set)}")

    if args.dry_run:
        print("Dry run — no files written.")
        return

    # Write output files
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for name, data in [("train", train_set), ("val", val_set), ("test", test_set)]:
        out_path = out_dir / f"{name}.jsonl"
        with open(out_path, "w") as f:
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
