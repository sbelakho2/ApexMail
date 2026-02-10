#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  ApexMail AI — vast.ai Training Runner
# ═══════════════════════════════════════════════════════════════════════════════
#  Runs the full training pipeline on a vast.ai instance:
#    1. Generate dataset
#    2. Train QLoRA adapter
#    3. Evaluate on golden set
#    4. Export to ONNX
#    5. Sync results back
#
#  Usage (on the vast.ai instance):
#    cd /workspace/training && ./vastai_train.sh
#    cd /workspace/training && ./vastai_train.sh --skip-export  # train only
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

WORKDIR="/workspace/training"
SKIP_EXPORT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-export) SKIP_EXPORT=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Activate venv
source "${WORKDIR}/.venv/bin/activate"
cd "${WORKDIR}"

echo "═══════════════════════════════════════════════════════════"
echo "  ApexMail AI — Training Pipeline"
echo "  Model: Qwen/Qwen2.5-7B-Instruct"
echo "  GPU:   $(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
echo "═══════════════════════════════════════════════════════════"

# ── Step 1: Generate dataset ─────────────────────────────────────────────────
echo ""
echo "══ Step 1: Generate dataset ══"
python3 generate_dataset.py
echo ""

# ── Step 2: Train ────────────────────────────────────────────────────────────
echo "══ Step 2: Train QLoRA adapter ══"
echo "  Training in tmux session 'train' — attach with: tmux attach -t train"
echo ""

# Run training (not in tmux so we can chain steps)
python3 train.py 2>&1 | tee "logs/train_$(date +%Y%m%d_%H%M%S).log"

echo ""
echo "  ✓ Training complete"

# ── Step 3: Evaluate ─────────────────────────────────────────────────────────
echo ""
echo "══ Step 3: Evaluate on golden set ══"
python3 eval.py 2>&1 | tee "logs/eval_$(date +%Y%m%d_%H%M%S).log"

# ── Step 4: Export to ONNX ───────────────────────────────────────────────────
if [[ "${SKIP_EXPORT}" == "false" ]]; then
    echo ""
    echo "══ Step 4: Export to ONNX ══"
    python3 export_onnx.py 2>&1 | tee "logs/export_$(date +%Y%m%d_%H%M%S).log"
else
    echo ""
    echo "══ Step 4: Skipping ONNX export (--skip-export) ══"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Pipeline complete!"
echo ""
echo "  Artifacts:"
echo "    Adapter:     output/"
echo "    ONNX:        onnx_model/"
echo "    Eval:        eval_results/"
echo "    Logs:        logs/"
echo ""
echo "  To download ONNX model to your VPS:"
echo "    rsync -avz vast:${WORKDIR}/onnx_model/ ./onnx_model/"
echo "═══════════════════════════════════════════════════════════"
