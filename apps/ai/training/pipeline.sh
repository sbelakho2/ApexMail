#!/bin/bash
# ============================================================================
# ApexMail Agent Training Pipeline for 4× B200 GPUs
# ============================================================================
# Usage:
#   ./pipeline.sh train     # Run training
#   ./pipeline.sh test      # Run tests on adapter
#   ./pipeline.sh status    # Check training status
#   ./pipeline.sh full      # Train + test (blocking)
# ============================================================================

set -e

WORKSPACE="/workspace"
MODEL_PATH="$WORKSPACE/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH="$WORKSPACE/train_agent.jsonl"
OUTPUT_DIR="$WORKSPACE/output_agent"
TRAIN_LOG="$WORKSPACE/train.log"
TEST_LOG="$WORKSPACE/test.log"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARNING:${NC} $1"; }
error() { echo -e "${RED}[$(date +%H:%M:%S)] ERROR:${NC} $1"; exit 1; }

verify_env() {
    log "Verifying environment..."
    
    GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader | wc -l)
    log "  GPUs detected: $GPU_COUNT"
    
    if [ ! -d "$MODEL_PATH" ]; then
        error "Model not found at $MODEL_PATH"
    fi
    log "  Model: OK"
    
    if [ ! -f "$DATA_PATH" ]; then
        error "Dataset not found at $DATA_PATH"
    fi
    EXAMPLE_COUNT=$(wc -l < "$DATA_PATH")
    log "  Dataset: $EXAMPLE_COUNT examples"
    
    python3 -c "import torch, transformers, peft, trl, datasets" 2>/dev/null || \
        error "Missing Python packages"
    log "  Python packages: OK"
    
    log "Environment verified!"
}

run_training() {
    log "Starting 4-GPU training..."
    
    pkill -f "torchrun.*train_4gpu" 2>/dev/null || true
    sleep 2
    
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    
    export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True,max_split_size_mb:512
    export NCCL_ALGO=Ring
    export NCCL_NET_GDR_LEVEL=5
    export NCCL_P2P_LEVEL=NVL
    export NCCL_MIN_NCHANNELS=16
    export MODEL_PATH="$MODEL_PATH"
    export DATA_PATH="$DATA_PATH"
    export OUTPUT_DIR="$OUTPUT_DIR"
    
    cd "$WORKSPACE"
    
    log "Training log: $TRAIN_LOG"
    
    nohup torchrun --nproc_per_node=4 train_4gpu.py > "$TRAIN_LOG" 2>&1 &
    TRAIN_PID=$!
    
    log "Training launched (PID: $TRAIN_PID)"
    log "Monitor with: tail -f $TRAIN_LOG"
    
    echo $TRAIN_PID > "$WORKSPACE/.train_pid"
}

check_status() {
    log "Checking training status..."
    
    if pgrep -f "torchrun.*train_4gpu" > /dev/null; then
        TRAIN_PID=$(pgrep -f "torchrun.*train_4gpu" | head -1)
        log "Training is RUNNING (PID: $TRAIN_PID)"
        
        echo ""
        nvidia-smi --query-gpu=index,memory.used,utilization.gpu --format=csv
        echo ""
        
        if [ -f "$TRAIN_LOG" ]; then
            log "Last training metrics:"
            grep -E "loss|epoch" "$TRAIN_LOG" | tail -5
        fi
    else
        warn "Training is NOT running"
        
        if [ -f "$OUTPUT_DIR/adapter_model.safetensors" ]; then
            log "Training COMPLETED - adapter found"
            ls -la "$OUTPUT_DIR/"
        elif [ -f "$TRAIN_LOG" ]; then
            log "Last log entries:"
            tail -20 "$TRAIN_LOG"
        fi
    fi
}

run_tests() {
    log "Running tests on trained adapter..."
    
    if [ ! -f "$OUTPUT_DIR/adapter_model.safetensors" ]; then
        error "No adapter found at $OUTPUT_DIR"
    fi
    
    cd "$WORKSPACE"
    
    if [ -f "test_agent.py" ]; then
        log "Running agent tests..."
        python3 test_agent.py \
            --base-model "$MODEL_PATH" \
            --adapter "$OUTPUT_DIR" \
            --auto-device-map 2>&1 | tee "$TEST_LOG"
    else
        warn "test_agent.py not found"
    fi
}

run_full() {
    verify_env
    run_training
    
    log "Waiting for training to complete..."
    
    while pgrep -f "torchrun.*train_4gpu" > /dev/null; do
        sleep 60
        if [ -f "$TRAIN_LOG" ]; then
            LAST=$(grep -oP "epoch.*?[0-9.]+" "$TRAIN_LOG" 2>/dev/null | tail -1 || echo "starting...")
            log "Progress: $LAST"
        fi
    done
    
    log "Training completed!"
    
    if [ ! -f "$OUTPUT_DIR/adapter_model.safetensors" ]; then
        error "Training failed - no adapter saved"
    fi
    
    run_tests
}

case "${1:-help}" in
    verify)
        verify_env
        ;;
    train)
        verify_env
        run_training
        ;;
    test)
        run_tests
        ;;
    full)
        run_full
        ;;
    status)
        check_status
        ;;
    help|*)
        echo "ApexMail Agent Training Pipeline (4× B200 GPUs)"
        echo ""
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  verify  - Verify environment"
        echo "  train   - Start training (background)"
        echo "  test    - Run tests on adapter"
        echo "  full    - Train + test (blocking)"
        echo "  status  - Check training status"
        echo ""
        echo "Workflow:"
        echo "  1. $0 verify"
        echo "  2. $0 train"
        echo "  3. $0 status"
        echo "  4. $0 test"
        ;;
esac
