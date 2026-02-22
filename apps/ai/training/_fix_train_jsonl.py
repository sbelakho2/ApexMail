#!/usr/bin/env python3
"""One-time script to fix train.jsonl (secondary training data).

Fixes:
  1. "99.99% SLA with credits" for Enterprise → "99.9% SLA (25% credit cap)"
  2. SLA API response example with "99.99%" uptime target → "99.9%"
  3. "Redis sliding window" in rate limit description → remove Redis detail
  4. "Redis sliding-window counter" mentions → remove Redis detail
"""
import os
import sys

TRAIN_FILE = os.path.join(
    os.path.dirname(__file__), "data", "train.jsonl"
)


def main():
    with open(TRAIN_FILE, "r") as f:
        data = f.read()

    original_len = len(data)
    total = 0

    # ── Fix 1: "99.99% SLA with credits" → "99.9% SLA (25% credit cap)" ──
    old = "99.99% SLA with credits"
    new = "99.9% SLA (25% credit cap)"
    n = data.count(old)
    data = data.replace(old, new)
    total += n
    print(f"  Fix 1 — Enterprise SLA '99.99%': {n} replacements")

    # ── Fix 2: SLA API response with wrong 99.99% target ──
    old2 = '"target": "99.99%"'
    new2 = '"target": "99.9%"'
    n = data.count(old2)
    data = data.replace(old2, new2)
    total += n
    print(f"  Fix 2 — SLA API target '99.99%': {n} replacements")

    old3 = '"actual": "99.995%"'
    new3 = '"actual": "99.95%"'
    n = data.count(old3)
    data = data.replace(old3, new3)
    total += n
    print(f"  Fix 2b — SLA API actual '99.995%': {n} replacements")

    # ── Fix 3: "Redis sliding window" → "sliding window" ──
    # In system prompt: "all plans, Redis sliding window"
    old4 = "Redis sliding window"
    new4 = "sliding window"
    n = data.count(old4)
    data = data.replace(old4, new4)
    total += n
    print(f"  Fix 3 — 'Redis sliding window': {n} replacements")

    # ── Fix 4: "Redis sliding-window counter" → "sliding-window counter" ──
    old5 = "Redis sliding-window counter"
    new5 = "sliding-window counter"
    n = data.count(old5)
    data = data.replace(old5, new5)
    total += n
    print(f"  Fix 4 — 'Redis sliding-window counter': {n} replacements")

    # ── Write back ──
    with open(TRAIN_FILE, "w") as f:
        f.write(data)

    print(f"\nTotal replacements: {total}")
    print(f"File size: {original_len} → {len(data)} bytes")

    # ── Verify ──
    checks = {
        "99.99%": data.count("99.99%"),
        "Hetzner": data.count("Hetzner"),
        "PostgreSQL": data.count("PostgreSQL"),
        "Redis": data.count("Redis"),
        "BullMQ": data.count("BullMQ"),
    }
    print("\nRemaining mentions:")
    all_clean = True
    for key, cnt in checks.items():
        status = "✓" if cnt == 0 else f"✗ ({cnt})"
        print(f"  {key}: {status}")
        if cnt > 0:
            all_clean = False

    if all_clean:
        print("\n✅ All train.jsonl issues fixed!")
    else:
        print("\n⚠️  Some issues may remain — verify context.")


if __name__ == "__main__":
    main()
