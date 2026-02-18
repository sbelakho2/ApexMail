#!/bin/bash
# run_test_quad.sh — Run stress tests in parallel across 4 GPUs
set -e
cd /workspace/training

# Count total tests
TOTAL=$(python3 -c "
import sys; sys.path.insert(0, '.')
from stress_test import STRESS_TESTS
try:
    from stress_test_extra import EXTRA_TESTS
    for k, v in EXTRA_TESTS.items():
        if k in STRESS_TESTS: STRESS_TESTS[k].extend(v)
        else: STRESS_TESTS[k] = v
except ImportError: pass
try:
    from stress_test_r34 import R34_TESTS
    for k, v in R34_TESTS.items():
        if k in STRESS_TESTS: STRESS_TESTS[k].extend(v)
        else: STRESS_TESTS[k] = v
except ImportError: pass
total = sum(len(v) for v in STRESS_TESTS.values())
print(total)
")

echo "Total tests: $TOTAL"
QUARTER=$(( (TOTAL + 3) / 4 ))
S1=0; E1=$QUARTER
S2=$QUARTER; E2=$(( QUARTER * 2 ))
S3=$(( QUARTER * 2 )); E3=$(( QUARTER * 3 ))
S4=$(( QUARTER * 3 )); E4=$TOTAL

echo "GPU 0: tests $S1-$E1"
echo "GPU 1: tests $S2-$E2"
echo "GPU 2: tests $S3-$E3"
echo "GPU 3: tests $S4-$E4"
echo ""

rm -f /tmp/results_gpu{0,1,2,3}.json

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

python3 /workspace/training/merge_results.py
