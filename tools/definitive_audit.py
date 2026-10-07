#!/usr/bin/env python3
"""
RETIRED (2026-10-07, coverage audit U-4) — historical one-off tool.

What it was
-----------
A line-by-line pricing audit of the historical `apps/ai/training/data/
train_agent.jsonl` corpus (1,089 lines) against `tools/lib/pricing.py`. It
was written against a long-gone pricing generation: a different plan schema
(TitleCase keys, `price`/`contacts`/`webhooks` fields) and a different
canonical catalog.

Why it is retired
-----------------
1. It cannot run: `from lib.pricing import PLANS as _CANONICAL_PLANS,
   PAYG_TIERS, DEDICATED_IP_PRICE, OVERAGE_RATE_PER_1K` — those three names
   have never existed in tools/lib/pricing.py (verified ImportError), and no
   plan row carries the `price`/`contacts` keys the script reads next
   (KeyError).
2. Its data source is gone: `train_agent.jsonl` was removed from
   apps/ai/training/data/ (only the `augmented_*.jsonl` corpus remains), so
   even a repaired import would fail on open.
3. Its report path printed success without running — "✅ ALL 1,089 LINES
   CLEAN" — the exact forged-success class this retirement removes.

A replacement, if one is ever needed, must derive every expectation from the
canonical platform catalog and validate the CURRENT corpus files in
apps/ai/training/data/ (see tools/validate_pricing_drift.py for the
field-by-field mirror gate and tools/check_eval_corpora.py for the AI
goldens). Do not resurrect this file.

This stub intentionally has NO success path: running it always exits 2.
"""

import sys

MESSAGE = """definitive_audit.py is RETIRED (coverage audit U-4).

Reason: it cannot import (nonexistent lib.pricing names) and its corpus
(apps/ai/training/data/train_agent.jsonl) no longer exists; its report path
printed "ALL 1,089 LINES CLEAN" without ever completing a run.

Use tools/validate_pricing_drift.py (canonical catalog + tools/lib/pricing.py
mirror, per-field) and tools/check_eval_corpora.py instead. See the module
docstring for the full retirement record."""


def main() -> int:
    print(MESSAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
