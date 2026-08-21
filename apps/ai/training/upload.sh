#!/bin/bash
# ============================================================================
# Upload training files to a remote training instance
# ============================================================================
# Usage: ./upload.sh <host> <port> <ssh_key> [train_script]
#
# host, port, and ssh_key are REQUIRED — no host, key path, or other
# deployment details are defaulted or stored in this script.
#
# Examples:
#   ./upload.sh <host> <port> ~/.ssh/<key>                    # train_4gpu.py
#   ./upload.sh <host> <port> ~/.ssh/<key> train_8gpu.py
#   HOST=user@remote WORKSPACE_DIR=/opt/train ./upload.sh <host> <port> ~/.ssh/<key>
# ============================================================================

set -e

# Use WORKSPACE_DIR env var (fallback to /workspace)
WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"

HOST="${1:?Usage: $0 <host> <port> <ssh_key> [train_script]}"
PORT="${2:?Usage: $0 <host> <port> <ssh_key> [train_script]}"
SSH_KEY="${3:?Usage: $0 <host> <port> <ssh_key> [train_script] — no default key path is assumed}"
TRAIN_SCRIPT="${4:-train_4gpu.py}"

LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$LOCAL_DIR/../../.." && pwd)"
WORKSPACE="${WORKSPACE_DIR:-/workspace}"

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[UPLOAD]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Test connection
log "Testing connection to $HOST:$PORT..."
ssh -i "$SSH_KEY" -p "$PORT" -o ConnectTimeout=30 -o StrictHostKeyChecking=accept-new \
    "root@$HOST" 'echo "Connection OK"' || error "Cannot connect"

log "Uploading training files..."

# Upload training script (configurable: default train_4gpu.py)
if [ -f "$LOCAL_DIR/$TRAIN_SCRIPT" ]; then
    scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
        "$LOCAL_DIR/$TRAIN_SCRIPT" "root@$HOST:$WORKSPACE/" && log "  $TRAIN_SCRIPT"
else
    error "Training script not found: $LOCAL_DIR/$TRAIN_SCRIPT"
fi

# Also upload any other training scripts that exist (multi-GPU variants)
for alt_script in train_8gpu.py train_4gpu.py train_2gpu.py train_ddp.py train_fsdp.py train_qlora.py; do
    if [ "$alt_script" != "$TRAIN_SCRIPT" ] && [ -f "$LOCAL_DIR/$alt_script" ]; then
        scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
            "$LOCAL_DIR/$alt_script" "root@$HOST:$WORKSPACE/" && log "  $alt_script"
    fi
done

# Upload pipeline
scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
    "$LOCAL_DIR/pipeline.sh" "root@$HOST:$WORKSPACE/" && log "  pipeline.sh"

# Upload test scripts if they exist
for test_script in test_agent.py stress_test.py stress_test_agent.py; do
    if [ -f "$LOCAL_DIR/$test_script" ]; then
        scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
            "$LOCAL_DIR/$test_script" "root@$HOST:$WORKSPACE/" && log "  $test_script"
    fi
done

# Upload training data
DATASET="$PROJECT_ROOT/data/train_agent.jsonl"
if [ -f "$DATASET" ]; then
    log "Uploading training dataset..."
    scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
        "$DATASET" "root@$HOST:$WORKSPACE/train_agent.jsonl" && log "  train_agent.jsonl"
else
    error "Dataset not found at $DATASET"
fi

# Make pipeline executable
ssh -i "$SSH_KEY" -p "$PORT" -o StrictHostKeyChecking=accept-new "root@$HOST" \
    "chmod +x $WORKSPACE/pipeline.sh"

# Verify
log "Verifying uploads..."
ssh -i "$SSH_KEY" -p "$PORT" -o StrictHostKeyChecking=accept-new "root@$HOST" "
    echo 'Files in /workspace:'
    ls -la $WORKSPACE/*.py $WORKSPACE/*.sh 2>/dev/null | head -10
    echo ''
    echo 'Dataset:'
    wc -l $WORKSPACE/train_agent.jsonl 2>/dev/null || echo '  (not found)'
    echo ''
    echo 'Model:'
    ls -d $WORKSPACE/models/Qwen* 2>/dev/null || echo '  (not found - download needed)'
"

log "Upload complete!"
echo ""
echo "Uploaded files:"
echo "  Training script : $TRAIN_SCRIPT"
echo "  Pipeline        : pipeline.sh"
echo "  Test scripts    : (auto-detected)"
echo "  Dataset         : train_agent.jsonl"
echo ""
echo "Next steps on remote:"
echo "  1. ssh -i $SSH_KEY -p $PORT root@$HOST"
echo "  2. cd /workspace"
echo "  3. ./pipeline.sh verify"
echo "  4. ./pipeline.sh train"
echo "  5. ./pipeline.sh status"
echo ""
echo "To upload a different training script, pass it as 4th argument:"
echo "  $0 $HOST $PORT \"$SSH_KEY\" train_8gpu.py"
