#!/bin/bash
# Parallel stress test launcher — runs 2 workers on 2 GPUs, then merges results.
cd /workspace/ApexMail/apps/ai/training

TOTAL=657
MID=$((TOTAL / 2))  # 328
TIMEOUT=5400  # 90 minutes max per worker

# Clean old results
rm -f /tmp/results_gpu0.json /tmp/results_gpu1.json /tmp/test_gpu0.log /tmp/test_gpu1.log

echo "Launching GPU 0 (tests 0-$MID) and GPU 1 (tests $MID-$TOTAL)..."
echo "Timeout: ${TIMEOUT}s per worker"

CUDA_VISIBLE_DEVICES=0 timeout $TIMEOUT python3 run_test_worker.py 0 $MID /tmp/results_gpu0.json $TOTAL > /tmp/test_gpu0.log 2>&1 &
PID0=$!

CUDA_VISIBLE_DEVICES=1 timeout $TIMEOUT python3 run_test_worker.py $MID $TOTAL /tmp/results_gpu1.json $TOTAL > /tmp/test_gpu1.log 2>&1 &
PID1=$!

echo "GPU 0 PID: $PID0 | GPU 1 PID: $PID1"
echo "Waiting for both to finish..."

wait $PID0
STATUS0=$?
echo "GPU 0 done (exit=$STATUS0)!"

wait $PID1
STATUS1=$?
echo "GPU 1 done (exit=$STATUS1)!"

# Verify result files exist
if [ ! -f /tmp/results_gpu0.json ]; then
    echo "ERROR: GPU 0 results missing!"
fi
if [ ! -f /tmp/results_gpu1.json ]; then
    echo "ERROR: GPU 1 results missing!"
fi

# Merge results
python3 -c "
import json

r0 = json.load(open('/tmp/results_gpu0.json'))
r1 = json.load(open('/tmp/results_gpu1.json'))
all_r = sorted(r0 + r1, key=lambda x: x['idx'])

passed = sum(1 for r in all_r if r['passed'])
total = len(all_r)
failed = total - passed
pct = passed / total * 100 if total else 0

# Category breakdown
cats = {}
failures = []
for r in all_r:
    cat = r['category']
    if cat not in cats:
        cats[cat] = {'passed': 0, 'failed': 0}
    if r['passed']:
        cats[cat]['passed'] += 1
    else:
        cats[cat]['failed'] += 1
        failures.append(r)

print()
print('=' * 60)
print(f'OVERALL: {passed}/{total} ({pct:.1f}%)')
print('=' * 60)
for cat, cr in cats.items():
    cp, cf = cr['passed'], cr['failed']
    ct = cp + cf
    cr['rate'] = round(cp / ct * 100, 1) if ct else 0
    print(f'  {cat:25s}: {cp}/{ct} ({cr[\"rate\"]:.0f}%)')

print()
for f in failures:
    print(f'FAIL [{f[\"idx\"]+1}/657] ({f[\"category\"]}) {f[\"question\"][:60]}')
    print(f'  {f[\"failures\"]}')

out = dict(passed=passed, failed=failed, categories=cats, failures=failures)
json.dump(out, open('/workspace/ApexMail/apps/ai/training/stress_results.json','w'), indent=2)
print(f'\nResults saved.')
"
