import json, sys
from collections import defaultdict

fname = sys.argv[1] if len(sys.argv) > 1 else "output_agent/unified_results_r9c.json"

with open(fname) as f:
    data = json.load(f)

s = data["summary"]
print("%s: %d/%d = %.1f%%" % (fname, s["passed"], s["total"], s["passed"]*100.0/s["total"]))

cats = defaultdict(lambda: {"pass": 0, "fail": 0})
fails = []
for r in data["results"]:
    cat = r.get("category", "unknown")
    if r["passed"]:
        cats[cat]["pass"] += 1
    else:
        cats[cat]["fail"] += 1
        fails.append((r["id"], r.get("failures", []), r.get("response_preview", r.get("response", "")[:200])))

print()
for cat in sorted(cats.keys()):
    p = cats[cat]["pass"]
    f = cats[cat]["fail"]
    t = p + f
    if f > 0:
        print("  %s: %d/%d FAIL" % (cat, p, t))
    else:
        print("  %s: %d/%d pass" % (cat, p, t))

print("\nFAILURES (%d):" % len(fails))
for fid, reasons, preview in fails:
    print("  %s" % fid)
    for reason in reasons[:3]:
        print("    -> %s" % reason)
    print("    Response: %s..." % preview[:150])
