#!/usr/bin/env python3
"""Extract and display failures from stress test results."""
import json

data = []
for gpu in range(4):
    path = f"/tmp/results_gpu{gpu}.json"
    try:
        data.extend(json.load(open(path)))
    except:
        pass

data.sort(key=lambda x: x.get("idx", 0))
passed = sum(1 for r in data if r.get("passed"))
total = len(data)
print(f"OVERALL: {passed}/{total} ({passed/total*100:.1f}%)")
print()

for r in data:
    if not r.get("passed", True):
        idx = r.get("idx", 0)
        cat = r.get("category", "?")
        q = r.get("question", "?")
        resp = r.get("response", "")
        fails = r.get("failures", [])
        print("=" * 70)
        print(f"[{idx+1}] {cat}")
        print(f"Q: {q}")
        print(f"Response: {resp[:800]}")
        print(f"Failures: {fails}")
        print()
