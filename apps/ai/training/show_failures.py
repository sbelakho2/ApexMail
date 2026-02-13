"""show_failures.py — Pretty-print failure details from stress test JSON."""
import json, sys

path = sys.argv[1] if len(sys.argv) > 1 else "stress_test_results.json"
with open(path) as f:
    results = json.load(f)

print(f"\n{'='*70}")
print(f"  RESULTS: {results['total_passed']}/{results['total_tests']} ({results['pass_rate']:.1%})")
print(f"{'='*70}")

# Category summary
print(f"\n  {'Category':<35} {'P':>4} / {'T':>4}  {'Rate':>6}")
print(f"  {'-'*35} {'-'*4}   {'-'*4}  {'-'*6}")
for cat, d in sorted(results["categories"].items(), key=lambda x: x[1]["pass_rate"]):
    mark = "✓" if d["pass_rate"] == 1.0 else "✗" if d["pass_rate"] < 1.0 else "~"
    print(f"  {mark} {cat:<33} {d['passed']:>4} / {d['total']:>4}  {d['pass_rate']:>5.0%}")

# Failure details
if results["failures"]:
    print(f"\n  FAILURES ({len(results['failures'])}):")
    print(f"  {'='*66}")
    for f in results["failures"]:
        print(f"\n  [{f['category']}]")
        print(f"  Q: {f['question'][:80]}")
        print(f"  R: {f['response'][:200]}")
        for fail in f["failures"]:
            print(f"    → {fail}")

print(f"\n{'='*70}\n")
