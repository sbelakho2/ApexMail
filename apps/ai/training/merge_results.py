#!/usr/bin/env python3
"""Merge 4-GPU test results and print summary."""
import json

all_results = []
for gpu in range(4):
    path = f'/tmp/results_gpu{gpu}.json'
    data = json.load(open(path))
    all_results.extend(data)
    passed = sum(1 for r in data if r['passed'])
    print(f'  GPU {gpu}: {passed}/{len(data)} passed')

all_results.sort(key=lambda x: x['idx'])
total = len(all_results)
passed = sum(1 for r in all_results if r['passed'])
failed = total - passed

print()
print('=' * 60)
print(f'OVERALL: {passed}/{total} ({passed/total*100:.1f}%)')
print('=' * 60)

cats = {}
for r in all_results:
    cat = r['category']
    if cat not in cats: cats[cat] = {'p': 0, 'f': 0}
    if r['passed']: cats[cat]['p'] += 1
    else: cats[cat]['f'] += 1

for cat, v in sorted(cats.items()):
    t = v['p'] + v['f']
    pct = v['p']/t*100 if t else 0
    marker = '' if v['f'] == 0 else ' ✗'
    print(f'  {cat:30s}: {v["p"]}/{t} ({pct:.0f}%){marker}')

if failed > 0:
    print()
    print(f'FAILURES ({failed}):')
    for r in all_results:
        if not r['passed']:
            print(f'  [{r["idx"]+1}] ({r["category"]}) {r["question"][:70]}')
            for f in r['failures']:
                print(f'      {f}')

# Save full results
with open('/workspace/training/test_results.json', 'w') as f:
    json.dump(all_results, f, indent=2)
print(f'\nFull results saved to /workspace/training/test_results.json')
