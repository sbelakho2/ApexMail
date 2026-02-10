#!/bin/bash
# Polls vast.ai instance until it's running, then downloads the adapter
set -e

INSTANCE_ID=31130509
SSH_HOST="ssh7.vast.ai"
SSH_PORT=10508
LOCAL_DIR="/home/aaron/apexmail-adapter"
VASTAI="$HOME/.local/bin/vastai"
MAX_ATTEMPTS=120  # 120 * 30s = 1 hour max wait

mkdir -p "$LOCAL_DIR"

echo "$(date): Waiting for instance $INSTANCE_ID to come back online..."

for i in $(seq 1 $MAX_ATTEMPTS); do
    status=$($VASTAI show instances --raw 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print(d[0]['actual_status'] if d else 'none')" 2>/dev/null || echo "error")
    
    # Also get the SSH port in case it changed
    ssh_info=$($VASTAI show instances --raw 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d:
    print(d[0].get('ssh_host',''),d[0].get('ssh_port',''))
" 2>/dev/null || echo "")

    echo "$(date): Attempt $i/$MAX_ATTEMPTS - Status: $status"
    
    if [ "$status" = "running" ]; then
        echo "$(date): Instance is RUNNING! Waiting 30s for SSH to be ready..."
        sleep 30
        
        # Extract SSH details
        SSH_HOST=$(echo "$ssh_info" | awk '{print $1}')
        SSH_PORT=$(echo "$ssh_info" | awk '{print $2}')
        echo "$(date): SSH: $SSH_HOST:$SSH_PORT"
        
        # Download adapter
        echo "$(date): Downloading adapter..."
        rsync -avz --progress -e "ssh -p $SSH_PORT -o StrictHostKeyChecking=no" \
            root@${SSH_HOST}:/workspace/ApexMail/apps/ai/training/output/ \
            "$LOCAL_DIR/"
        
        echo "$(date): Downloading training logs..."
        scp -P "$SSH_PORT" -o StrictHostKeyChecking=no \
            root@${SSH_HOST}:/workspace/ApexMail/apps/ai/training/train_round3.log \
            "$LOCAL_DIR/train_round3.log" 2>/dev/null || true
        
        scp -P "$SSH_PORT" -o StrictHostKeyChecking=no \
            root@${SSH_HOST}:/workspace/ApexMail/apps/ai/training/stress_results.json \
            "$LOCAL_DIR/stress_results.json" 2>/dev/null || true
        
        # Download data files too
        echo "$(date): Downloading training data..."
        mkdir -p "$LOCAL_DIR/data"
        rsync -avz --progress -e "ssh -p $SSH_PORT -o StrictHostKeyChecking=no" \
            root@${SSH_HOST}:/workspace/ApexMail/apps/ai/training/data/ \
            "$LOCAL_DIR/data/" 2>/dev/null || true
        
        echo "$(date): Download complete! Files in $LOCAL_DIR:"
        ls -la "$LOCAL_DIR/"
        
        echo ""
        echo "$(date): ADAPTER DOWNLOADED SUCCESSFULLY"
        echo "$(date): adapter_model.safetensors size: $(du -h "$LOCAL_DIR/adapter_model.safetensors" 2>/dev/null | cut -f1 || echo 'not found')"
        exit 0
    fi
    
    sleep 30
done

echo "$(date): Timed out waiting for instance after $MAX_ATTEMPTS attempts"
exit 1
