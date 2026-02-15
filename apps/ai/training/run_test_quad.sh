#!/bin/bash
# run_test_quad.sh — Run stress tests in parallel across 4 GPUs
# Usage: bash run_test_quad.sh

set -e

cd /workspace/ApexMail/apps/ai/training

# Count total tests
TOTAL=$(python3 -c "
import sys; sys.path.insert(0, '.')
from stress_test import STRESS_TESTS
try:
    from stress_test_extra import EXTRA_TESTS
    for k, v in EXTRA_TESTS.items():
        if k in STRESS_TESTS:
            STRESS_TESTS[k].extend(v)
        else:
            STRESS_TESTS[k] = v
except ImportError:
    pass
total = sum(len(v) for v in STRESS_TESTS.values())
print(total)
")

echo "Total tests: $TOTAL"
QUARTER=$(( (TOTAL + 3) / 4 ))  # round up
S1=0; E1=$QUARTER
S2=$QUARTER; E2=$(( QUARTER * 2 ))
S3=$(( QUARTER * 2 )); E3=$(( QUARTER * 3 ))
S4=$(( QUARTER * 3 )); E4=$TOTAL

echo "GPU 0: tests $S1-$E1"
echo "GPU 1: tests $S2-$E2"
echo "GPU 2: tests $S3-$E3"
echo "GPU 3: tests $S4-$E4"
echo ""

# Clean old results
rm -f /tmp/results_gpu{0,1,2,3}.json

# Launch 4 workers in parallel
CUDA_VISIBLE_DEVICES=0 python3 run_test_worker.py $S1 $E1 /tmp/results_gpu0.json $TOTAL &
PID0=$!
CUDA_VISIBLE_DEVICES=1 python3 run_test_worker.py $S2 $E2 /tmp/results_gpu1.json $TOTAL &
PID1=$!
CUDA_VISIBLE_DEVICES=2 python3 run_test_worker.py $S3 $E3 /tmp/results_gpu2.json $TOTAL &
PID2=$!
CUDA_VISIBLE_DEVICES=3 python3 run_test_worker.py $S4 $E4 /tmp/results_gpu3.json $TOTAL &
PID3=$!

echo "Workers launched: PIDs $PID0 $PID1 $PID2 $PID3"
echo "Waiting for all workers..."

wait $PID0 $PID1 $PID2 $PID3

echo ""
echo "All workers done. Merging results..."

# Merge and summarize
python3 -c "
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

# Category breakdown
cats = {}
for r in all_results:
    cat = r['category']
    if cat not in cats:
        cats[cat] = {'p': 0, 'f': 0}
    if r['passed']:
        cats[cat]['p'] += 1
    else:
        cats[cat]['f'] += 1

for cat, v in sorted(cats.items()):
    t = v['p'] + v['f']
    pct = v['p']/t*100 if t else 0
    marker = '' if v['f'] == 0 else ' ✗'
    print(f'  {cat:30s}: {v[\"p\"]}/{t} ({pct:.0f}%){marker}')

if failed > 0:
    print()
    print(f'FAILURES ({failed}):')
    for r in all_results:
        if not r['passed']:
            print(f'  [{r[\"idx\"]+1}] ({r[\"category\"]}) {r[\"question\"][:70]}')
            for f in r['failures']:
                print(f'      {f}')
"
