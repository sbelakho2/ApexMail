#!/bin/bash
# Poll vast.ai instance until it's running
INSTANCE_ID=31553904

while true; do
    vastai start instance $INSTANCE_ID 2>/dev/null
    sleep 60
    STATE=$(vastai show instances --raw 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['cur_state'])" 2>/dev/null)
    echo "$(date +%H:%M:%S) State: $STATE"
    if [ "$STATE" = "running" ]; then
        echo "INSTANCE IS RUNNING!"
        break
    fi
done
