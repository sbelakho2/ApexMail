#!/bin/bash
# ============================================================================
# Upload training files to Vast.ai instance
# ============================================================================
# Usage: ./upload.sh <host> <port> [ssh_key]
#
# Example:
#   ./upload.sh 54.233.120.77 44968 ~/.ssh/vastai_new
# ============================================================================

set -e

HOST="${1:?Usage: $0 <host> <port> [ssh_key]}"
PORT="${2:?Usage: $0 <host> <port> [ssh_key]}"
SSH_KEY="${3:-~/.ssh/vastai_new}"

LOCAL_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$LOCAL_DIR/../../.." && pwd)"
WORKSPACE="/workspace"

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

# Upload training script
scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
    "$LOCAL_DIR/train_4gpu.py" "root@$HOST:$WORKSPACE/" && log "  train_4gpu.py"

# Upload pipeline
scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
    "$LOCAL_DIR/pipeline.sh" "root@$HOST:$WORKSPACE/" && log "  pipeline.sh"

# Upload test script if exists
if [ -f "$LOCAL_DIR/test_agent.py" ]; then
    scp -i "$SSH_KEY" -P "$PORT" -o StrictHostKeyChecking=accept-new \
        "$LOCAL_DIR/test_agent.py" "root@$HOST:$WORKSPACE/" && log "  test_agent.py"
fi

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
echo "Next steps on remote:"
echo "  1. ssh -i $SSH_KEY -p $PORT root@$HOST"
echo "  2. cd /workspace"
echo "  3. ./pipeline.sh verify"
echo "  4. ./pipeline.sh train"
echo "  5. ./pipeline.sh status"
