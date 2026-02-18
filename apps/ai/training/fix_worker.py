#!/usr/bin/env python3
"""Fix run_test_worker.py: add R34 test import and fix BASE_DIR path."""
import re

with open("run_test_worker.py") as f:
    lines = f.readlines()

# Remove any existing R34 import blocks (from bad sed)
cleaned = []
skip_until_pass = False
i = 0
while i < len(lines):
    line = lines[i]
    if "stress_test_r34" in line:
        # Skip this try block (go back to find the "try:")
        while cleaned and cleaned[-1].strip() in ("", "try:"):
            cleaned.pop()
        # Skip forward until we find the matching except/pass
        while i < len(lines) and not (lines[i].strip() == "pass" and i > 0 and "except" in lines[i-1]):
            i += 1
        i += 1  # skip the 'pass' line
        continue
    cleaned.append(line)
    i += 1

# Find the EXTRA_TESTS except/pass block end and insert R34 after it
result = []
inserted = False
for i, line in enumerate(cleaned):
    result.append(line)
    if not inserted and line.strip() == "pass" and i > 0 and "ImportError" in cleaned[i-1]:
        result.append("\n")
        result.append("try:\n")
        result.append("    from stress_test_r34 import R34_TESTS\n")
        result.append("    for k, v in R34_TESTS.items():\n")
        result.append("        if k in STRESS_TESTS:\n")
        result.append("            STRESS_TESTS[k].extend(v)\n")
        result.append("        else:\n")
        result.append("            STRESS_TESTS[k] = v\n")
        result.append("except ImportError:\n")
        result.append("    pass\n")
        inserted = True

# Fix BASE_DIR path
final = []
for line in result:
    line = line.replace("/workspace/ApexMail/apps/ai/training", "/workspace/training")
    final.append(line)

with open("run_test_worker.py", "w") as f:
    f.writelines(final)

print("Fixed run_test_worker.py")
