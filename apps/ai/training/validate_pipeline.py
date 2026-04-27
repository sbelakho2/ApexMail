#!/usr/bin/env python3
"""Final validation of all ApexMail AI training pipeline files."""
import ast
import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

PASS = 0
FAIL = 0

def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ✅ {label}")
    else:
        FAIL += 1
        print(f"  ❌ {label}: {detail}")

# ── 1. Syntax checks ────────────────────────────────────────────────
print("\n=== 1. Python Syntax ===")
py_files = [
    "prompts_v2.py", "test_agent.py", "stress_test.py", "stress_test_agent.py",
    "run_test_agent.py", "run_stress_r15.py", "generate_dataset.py", "train.py",
]
for pf in py_files:
    try:
        with open(SCRIPT_DIR / pf) as f:
            ast.parse(f.read())
        check(pf, True)
    except SyntaxError as e:
        check(pf, False, str(e))

# ── 2. Import resolution ────────────────────────────────────────────
print("\n=== 2. Import Resolution ===")
try:
    from prompts_v2 import build_system_prompt, EXAMPLE_CONTEXTS, PRICING_TABLE
    check("prompts_v2 exports", True)
except Exception as e:
    check("prompts_v2 exports", False, str(e))

try:
    from test_agent import ALL_TESTS
    check("test_agent.ALL_TESTS", True)
except Exception as e:
    check("test_agent.ALL_TESTS", False, str(e))

try:
    from stress_test import STRESS_TESTS
    check("stress_test.STRESS_TESTS", True)
except Exception as e:
    check("stress_test.STRESS_TESTS", False, str(e))

# ── 3. Test counts ──────────────────────────────────────────────────
print("\n=== 3. Test Counts ===")
total_tests = sum(len(v) for v in ALL_TESTS.values())
check(f"test_agent: {total_tests} tests across {len(ALL_TESTS)} categories", total_tests >= 180)

total_stress = sum(len(v) for v in STRESS_TESTS.values())
check(f"stress_test: {total_stress} tests across {len(STRESS_TESTS)} categories", total_stress >= 170)

# ── 4. Context profiles ─────────────────────────────────────────────
print("\n=== 4. Context Profiles ===")
check(f"prompts_v2: {len(EXAMPLE_CONTEXTS)} profiles", len(EXAMPLE_CONTEXTS) >= 50)

# Verify all contexts referenced in tests exist
referenced = set()
for cat, tests in ALL_TESTS.items():
    for t in tests:
        ctx = t.get("context")
        if ctx:
            referenced.add(ctx)
missing_ctx = referenced - set(EXAMPLE_CONTEXTS.keys())
check(f"All test contexts exist in prompts_v2 ({len(referenced)} referenced)", len(missing_ctx) == 0,
      f"missing: {missing_ctx}")

# ── 5. Pricing consistency ──────────────────────────────────────────
print("\n=== 5. Pricing Consistency ===")
check("Starter $25 in PRICING_TABLE", "$25/mo" in PRICING_TABLE or "$25" in PRICING_TABLE)
check("Pro $65 in PRICING_TABLE", "$65/mo" in PRICING_TABLE or "$65" in PRICING_TABLE)
check("Growth $150 in PRICING_TABLE", "$150/mo" in PRICING_TABLE or "$150" in PRICING_TABLE)
check("Scale $350 in PRICING_TABLE", "$350/mo" in PRICING_TABLE or "$350" in PRICING_TABLE)
check("Enterprise $800 in PRICING_TABLE", "$800/mo" in PRICING_TABLE or "$800" in PRICING_TABLE)
# Verify no stale pricing
for stale in ["$29/mo", "$59/mo", "$129/mo", "$399/mo", "$1,299/mo"]:
    check(f"No stale {stale}", stale not in PRICING_TABLE, f"found {stale}")

# ── 6. Config file ──────────────────────────────────────────────────
print("\n=== 6. Config File ===")
try:
    import yaml
    with open(SCRIPT_DIR / "config.yaml") as f:
        cfg = yaml.safe_load(f)
    check("config.yaml loads", True)
    check("model.base present", "base" in cfg.get("model", {}))
    check("lora config present", "r" in cfg.get("lora", {}))
    check("dataset paths present", "train_file" in cfg.get("dataset", {}))
except Exception as e:
    check("config.yaml", False, str(e))

# ── 7. Data files ───────────────────────────────────────────────────
print("\n=== 7. Data Files ===")
data_dir = (SCRIPT_DIR / "../../../data").resolve()  # apps/ai/training -> project root/data
for df in ["train_agent.jsonl", "train.jsonl", "val.jsonl", "test.jsonl", "golden_qa.jsonl"]:
    path = data_dir / df
    exists = path.exists()
    if exists:
        with open(path) as f:
            count = sum(1 for line in f if line.strip())
        check(f"{df}: {count} examples", count > 0)
    else:
        check(df, False, "file not found")

# Split integrity
train_c = sum(1 for l in open(data_dir / "train.jsonl") if l.strip())
val_c = sum(1 for l in open(data_dir / "val.jsonl") if l.strip())
test_c = sum(1 for l in open(data_dir / "test.jsonl") if l.strip())
total_c = sum(1 for l in open(data_dir / "train_agent.jsonl") if l.strip())
check(f"Split integrity: {train_c}+{val_c}+{test_c}={train_c+val_c+test_c} == {total_c}",
      train_c + val_c + test_c == total_c)

# ── 8. Golden QA format ─────────────────────────────────────────────
print("\n=== 8. Golden QA Format ===")
golden_path = data_dir / "golden_qa.jsonl"
items = [json.loads(l) for l in open(golden_path) if l.strip()]
check(f"golden_qa.jsonl: {len(items)} items", len(items) >= 50)
all_valid = all(
    len(item["messages"]) == 3
    and item["messages"][0]["role"] == "system"
    and item["messages"][1]["role"] == "user"
    and item["messages"][2]["role"] == "assistant"
    for item in items
)
check("All items have system+user+assistant", all_valid)
all_non_empty = all(
    all(str(message.get("content", "")).strip() for message in item["messages"])
    for item in items
)
check("All golden QA messages have non-empty content", all_non_empty)
all_expected_outputs = all(
    str(item["messages"][2].get("content", "")).strip()
    for item in items
)
check("All golden QA items include expected assistant outputs", all_expected_outputs)

# ── Summary ─────────────────────────────────────────────────────────
print(f"\n{'='*50}")
print(f"RESULTS: {PASS} passed, {FAIL} failed")
if FAIL == 0:
    print("🎉 ALL CHECKS PASSED — Pipeline is production-ready!")
else:
    print(f"⚠️  {FAIL} check(s) need attention")
sys.exit(0 if FAIL == 0 else 1)
