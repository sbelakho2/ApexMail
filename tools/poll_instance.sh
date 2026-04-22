#!/bin/bash
set -euo pipefail
# Poll vast.ai instance until it's running
INSTANCE_ID="${VAST_INSTANCE_ID:?Set VAST_INSTANCE_ID environment variable}"
MAX_ATTEMPTS="${VAST_MAX_POLL_ATTEMPTS:-60}"
ATTEMPT=0

while [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; do
    ATTEMPT=$((ATTEMPT + 1))
    vastai start instance "$INSTANCE_ID" 2>/dev/null || true
    sleep 60
    STATE=$(vastai show instances --raw 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['cur_state'])" 2>/dev/null) || STATE="unknown"
    echo "$(date +%H:%M:%S) [$ATTEMPT/$MAX_ATTEMPTS] State: $STATE"
    if [ "$STATE" = "running" ]; then
        echo "INSTANCE IS RUNNING!"
        exit 0
    fi
done

echo "ERROR: Instance did not start after $MAX_ATTEMPTS attempts" >&2
exit 1
