#!/bin/bash
# launch_loop.sh — Wait for current tests, then start the automated loop
# Usage: nohup bash launch_loop.sh > /workspace/loop_launcher.log 2>&1 &

set -e

echo "=== ApexMail Loop Launcher ==="
echo "$(date): Waiting for current test run to finish..."

# Wait for the run_all_tests.py process to finish
while pgrep -f "run_all_tests.py" > /dev/null 2>&1; do
    PROGRESS=$(tail -1 /workspace/test_unified.log 2>/dev/null | grep -oP '\[\d+/\d+\]' | tail -1 || echo "unknown")
    echo "$(date): Tests still running... $PROGRESS"
    sleep 30
done

echo "$(date): Test run finished!"

# Copy test results as iteration 0 results
RESULTS_SRC="/workspace/test_results_r15_unified.json"
RESULTS_DST="/workspace/loop_iter_00/test_results.json"

if [ -f "$RESULTS_SRC" ]; then
    cp "$RESULTS_SRC" "$RESULTS_DST"
    echo "$(date): Copied results to $RESULTS_DST"
    
    # Show summary
    python3 -c "
import json
with open('$RESULTS_DST') as f:
    r = json.load(f)
s = r['summary']
print(f\"Results: {s['passed']}/{s['total']} ({s['percentage']}%)\")
print(f\"By category:\")
for cat, data in sorted(s.get('by_category', {}).items()):
    p, t = data.get('passed', 0), data.get('total', 0)
    pct = p/t*100 if t > 0 else 0
    marker = '✅' if p == t else '❌'
    print(f'  {marker} {cat}: {p}/{t} ({pct:.0f}%)')
"
else
    echo "$(date): ❌ Results file not found at $RESULTS_SRC"
    exit 1
fi

echo ""
echo "$(date): Starting automated loop from ANALYZE phase..."
echo "=========================================="

# Start the loop from analyze (we already have adapter + results for iter 0)
cd /workspace
python3 loop_train_test_fix.py \
    --start-from analyze \
    --iteration 0 \
    --target-accuracy 99.0 \
    --max-iterations 10 \
    2>&1 | tee /workspace/loop_main.log
