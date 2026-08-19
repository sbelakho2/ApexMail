#!/bin/bash
# ============================================================================
# ApexMail Agent Training Pipeline for 4× B200 GPUs
# ============================================================================
# Usage:
#   ./pipeline.sh validate  # Validate pricing data
#   ./pipeline.sh train     # Run training
#   ./pipeline.sh test      # Run tests on adapter
#   ./pipeline.sh status    # Check training status
#   ./pipeline.sh full      # Validate → train → test (blocking)
# ============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
CONFIG_PATH="${AI_TRAINING_CONFIG:-$SCRIPT_DIR/config.yaml}"
MODEL_PATH="${AI_MODEL_BASE:-/workspace/models/Qwen3-Next-80B-A3B-Instruct}"
DATA_PATH="$PROJECT_ROOT/data/train.jsonl"
OUTPUT_DIR="${AI_OUTPUT_DIR:-$PROJECT_ROOT/artifacts/ai-training/output}"
TRAIN_LOG="${AI_TRAIN_LOG:-$PROJECT_ROOT/artifacts/ai-training/train.log}"
TEST_LOG="${AI_TEST_LOG:-$PROJECT_ROOT/artifacts/ai-training/test.log}"
TRAIN_EXTRA_ARGS=()

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
    
    python3 -c "import torch, transformers, peft, trl, datasets, yaml" 2>/dev/null || \
        error "Missing Python packages"
    log "  Python packages: OK"
    
    log "Environment verified!"
}

run_training() {
    log "Starting QLoRA training with the maintained train.py entrypoint..."
    mkdir -p "$OUTPUT_DIR" "$(dirname "$TRAIN_LOG")"
    
    export PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True,max_split_size_mb:512
    export NCCL_ALGO=Ring
    export NCCL_NET_GDR_LEVEL=5
    export NCCL_P2P_LEVEL=NVL
    export NCCL_MIN_NCHANNELS=16
    export AI_MODEL_BASE="$MODEL_PATH"
    export AI_OUTPUT_DIR="$OUTPUT_DIR"
    export AI_LOGS_DIR="${AI_LOGS_DIR:-$(dirname "$TRAIN_LOG")/logs}"
    
    local gpu_count
    gpu_count="${AI_TRAINING_GPUS:-$(nvidia-smi --query-gpu=name --format=csv,noheader | wc -l | tr -d ' ')}"
    [ "$gpu_count" -gt 0 ] || error "No CUDA GPUs available"

    cd "$PROJECT_ROOT"
    
    log "Training log: $TRAIN_LOG"
    
    if [ "${AI_TRAINING_BACKGROUND:-false}" = "true" ]; then
        nohup torchrun --standalone --nproc_per_node="$gpu_count" "$SCRIPT_DIR/train.py" \
            --config "$CONFIG_PATH" "${TRAIN_EXTRA_ARGS[@]}" > "$TRAIN_LOG" 2>&1 &
        TRAIN_PID=$!
        log "Training launched (PID: $TRAIN_PID)"
        echo "$TRAIN_PID" > "$(dirname "$TRAIN_LOG")/.train_pid"
    else
        torchrun --standalone --nproc_per_node="$gpu_count" "$SCRIPT_DIR/train.py" \
            --config "$CONFIG_PATH" "${TRAIN_EXTRA_ARGS[@]}" 2>&1 | tee "$TRAIN_LOG"
    fi
}

check_status() {
    log "Checking training status..."
    
    if pgrep -f "torchrun.*train.py" > /dev/null; then
        TRAIN_PID=$(pgrep -f "torchrun.*train.py" | head -1)
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
    
    cd "$PROJECT_ROOT"
    
    if [ -f "$SCRIPT_DIR/test_agent.py" ]; then
        log "Running agent tests..."
        python3 "$SCRIPT_DIR/test_agent.py" \
            --base-model "$MODEL_PATH" \
            --adapter "$OUTPUT_DIR" \
            --auto-device-map 2>&1 | tee "$TEST_LOG"
    else
        warn "test_agent.py not found"
    fi
}

run_validate_pricing() {
    log "Validating pricing data against canonical rates..."
    
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    
    if [ -f "$SCRIPT_DIR/validate_pricing.py" ]; then
        python3 "$SCRIPT_DIR/validate_pricing.py" --verbose
        if [ $? -eq 0 ]; then
            log "Pricing validation PASSED"
        else
            error "Pricing validation FAILED — fix pricing before training"
        fi
    else
        warn "validate_pricing.py not found — skipping pricing validation"
    fi
}

# Called only by the AI service's operator-configured `AI_TRAINING_RUNNER`.
# Arguments are parsed as data, never evaluated as shell code. On success the
# underlying trainer must have emitted a real metrics.json artifact.
run_managed_job() {
    local job_id=""
    local model_id=""
    local epochs=""
    local artifact_dir=""

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --job-id) job_id="${2:?missing value for --job-id}"; shift 2 ;;
            --model-id) model_id="${2:?missing value for --model-id}"; shift 2 ;;
            --epochs) epochs="${2:?missing value for --epochs}"; shift 2 ;;
            --artifact-dir) artifact_dir="${2:?missing value for --artifact-dir}"; shift 2 ;;
            *) error "Unknown managed-job option: $1" ;;
        esac
    done

    [[ "$job_id" =~ ^[0-9a-fA-F-]{36}$ ]] || error "Invalid job ID"
    [[ "$model_id" =~ ^[A-Za-z0-9._-]{1,128}$ ]] || error "Invalid model ID"
    [[ "$epochs" =~ ^[0-9]+$ ]] && [ "$epochs" -ge 1 ] && [ "$epochs" -le 100 ] || error "Invalid epoch count"
    [[ "$artifact_dir" = /* ]] || error "Artifact directory must be absolute"

    OUTPUT_DIR="$artifact_dir/model"
    TRAIN_LOG="$artifact_dir/train.log"
    export AI_OUTPUT_DIR="$OUTPUT_DIR"
    export AI_LOGS_DIR="$artifact_dir/logs"
    TRAIN_EXTRA_ARGS=(--epochs "$epochs" --metrics-output "$artifact_dir/metrics.json")
    mkdir -p "$artifact_dir"

    log "Running managed training job $job_id for model $model_id"
    verify_env
    run_training
    [ -s "$artifact_dir/metrics.json" ] || error "Training completed without metrics.json"
    python3 - "$artifact_dir/metrics.json" <<'PY'
import json
import math
import sys

path = sys.argv[1]
with open(path) as handle:
    metrics = json.load(handle)
loss = metrics.get("loss")
if not isinstance(loss, (int, float)) or not math.isfinite(loss):
    raise SystemExit("metrics.json must contain a finite real loss")
print(f"Validated training artifact with loss={loss}")
PY
}

run_full() {
    run_validate_pricing
    verify_env
    run_training
    
    log "Waiting for training to complete..."
    
    while pgrep -f "torchrun.*train.py" > /dev/null; do
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
    --job-id)
        run_managed_job "$@"
        ;;
    validate)
        run_validate_pricing
        ;;
    verify)
        verify_env
        ;;
    train)
        verify_env
        AI_TRAINING_BACKGROUND=true run_training
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
        echo "  validate  - Validate pricing data against canonical rates"
        echo "  verify    - Verify environment"
        echo "  train     - Start training in the background"
        echo "  test      - Run tests on adapter"
        echo "  full      - Validate → train → test (blocking)"
        echo "  status    - Check training status"
        echo ""
        echo "Workflow:"
        echo "  1. $0 validate"
        echo "  2. $0 verify"
        echo "  3. $0 train"
        echo "  4. $0 status"
        echo "  5. $0 test"
        echo ""
        echo "Managed runner: set AI_TRAINING_RUNNER to this executable and invoke it only through ai-service."
        ;;
esac
