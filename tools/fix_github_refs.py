#!/usr/bin/env python3
"""Replace old apexmail GitHub URLs with the canonical Bel-Consulting-OU/ApexMail URL."""
import os
import re

BASE = "/Users/sabelakhoua/IdeaProjects/ApexMail"

# Files to process
FILES = [
    "apps/ai/training/data/train_r27_backup.jsonl",
    "apps/ai/training/data/train.jsonl",
    "apps/ai/training/data/train_base_r17o_from_r17n.jsonl",
    "apps/ai/training/data/train_base_r17q_from_r17p.jsonl",
    "apps/ai/training/data/train_base_r17m_from_r17l.jsonl",
    "apps/ai/training/data/train_base_r17p_from_r17o.jsonl",
    "data/train_agent.jsonl",
    "apps/ai/training/generate_r7_fixes.py",
    "apps/ai/training/generate_fixes_v2.py",
]

PUBLIC = "github.com/Bel-Consulting-OU/ApexMail"

# Order matters: most specific first
REPLACEMENTS = [
    (r"github\.com/apexmail/apexmail/issues", f"{PUBLIC}/issues"),
    (r"github\.com/apexmail/apexmail-go", f"{PUBLIC}/packages/sdk-go"),
    (r"github\.com/apexmail/apexmail-python", PUBLIC),
    (r"github\.com/apexmail/apexmail-ruby", PUBLIC),
    (r"github\.com/apexmail/apexmail-java", PUBLIC),
    (r"github\.com/apexmail/apexmail", PUBLIC),
    (r"github\.com/apexmail(?=[^-/a-zA-Z])", PUBLIC),
]

for rel in FILES:
    path = os.path.join(BASE, rel)
    if not os.path.exists(path):
        print(f"SKIP (not found): {rel}")
        continue
    with open(path, "r", encoding="utf-8") as fh:
        original = fh.read()
    updated = original
    for pattern, replacement in REPLACEMENTS:
        updated = re.sub(pattern, replacement, updated)
    if updated != original:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(updated)
        print(f"CHANGED: {rel}")
    else:
        print(f"unchanged: {rel}")
