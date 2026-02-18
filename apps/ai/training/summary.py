#!/usr/bin/env python3
"""Quick summary of dataset and test suite."""
import json
import sys
sys.path.insert(0, ".")

with open("data/train_agent.jsonl") as f:
    data = [json.loads(l) for l in f]

multi_turn = sum(1 for d in data if d["text"].count("<|im_start|>user") > 1)
tool_calls = sum(1 for d in data if "<|im_start|>tool" in d["text"])
single = len(data) - multi_turn

total_words = sum(len(d["text"].split()) for d in data)
est_tokens = int(total_words * 1.3)

print("=== FINAL DATASET SUMMARY ===")
print(f"Total examples:     {len(data)}")
print(f"Single-turn:        {single}")
print(f"Multi-turn:         {multi_turn}")
print(f"With tool calls:    {tool_calls}")
print(f"Estimated tokens:   ~{est_tokens:,}")
print(f"Avg tokens/example: ~{est_tokens // len(data):,}")
print()

from prompts_v2 import EXAMPLE_CONTEXTS
markers = {
    "starter_healthy": "acmecorp.com",
    "growth_dkim_fail": "techflow.io",
    "free_hitting_limits": "myshop.com",
    "scale_deliverability": "198.51.100.12",
    "pro_new_user": "startupxyz.com",
    "enterprise_compliance": "globalbank.com",
    "no_context": "No customer-specific context",
}
print("Context profile usage:")
for k in EXAMPLE_CONTEXTS:
    m = markers.get(k, "")
    count = sum(1 for d in data if m in d["text"][:2000])
    print(f"  {k:30s}: {count}")
print()

from test_agent import ALL_TESTS
total_tests = 0
print("=== TEST SUITE SUMMARY ===")
for cat, tests in ALL_TESTS.items():
    n = len(tests)
    total_tests += n
    print(f"  {cat:25s}: {n}")
print(f"  {'TOTAL':25s}: {total_tests}")
