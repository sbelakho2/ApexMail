#!/usr/bin/env python3
"""Per-file coverage from an lcov artifact: worst files first."""
import sys, collections
path = sys.argv[1]
crate_filter = sys.argv[2] if len(sys.argv) > 2 else None
top = int(sys.argv[3]) if len(sys.argv) > 3 else 20
files = {}
cur = None
for line in open(path, errors='ignore'):
    if line.startswith('SF:'):
        cur = line[3:].strip(); files[cur] = [0, 0]
    elif line.startswith('DA:') and cur:
        p = line[3:].strip().split(',')
        if len(p) >= 2:
            try: c = int(p[1])
            except ValueError: continue
            files[cur][0 if c > 0 else 1] += 1
rows = []
for f, (c, u) in files.items():
    if crate_filter and f"/crates/{crate_filter}/" not in f: continue
    t = c + u
    if t: rows.append((u, 100.0 * c / t, c, t, f))
rows.sort(reverse=True)
tc = sum(r[2] for r in rows); tu = sum(r[0] for r in rows)
print(f"files={len(rows)} covered={tc} uncovered={tu} pct={100*tc/(tc+tu) if tc+tu else 0:.2f}%")
for u, pct, c, t, f in rows[:top]:
    print(f"{u:6} uncov  {pct:5.1f}%  {t:6} lines  {f}")
