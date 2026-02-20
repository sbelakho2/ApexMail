#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# serve_model.sh — Launch llama-server sidecar for ApexMail AI
#
# Usage:
#   ./serve_model.sh                        # use default GGUF
#   ./serve_model.sh /path/to/model.gguf    # use specific GGUF
#   LLAMA_PORT=8082 ./serve_model.sh        # custom port
#
# Requires llama.cpp to be built:
#   git clone https://github.com/ggerganov/llama.cpp
#   cd llama.cpp && cmake -B build && cmake --build build -j
#
# On the vast.ai GPU box the binary is at:
#   /workspace/llama.cpp/build/bin/llama-server
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

# ── Defaults (override via env vars) ─────────────────────────
LLAMA_CPP_DIR="${LLAMA_CPP_DIR:-/workspace/llama.cpp}"
LLAMA_SERVER="${LLAMA_SERVER:-${LLAMA_CPP_DIR}/build/bin/llama-server}"
LLAMA_PORT="${LLAMA_PORT:-8081}"
LLAMA_HOST="${LLAMA_HOST:-0.0.0.0}"
LLAMA_THREADS="${LLAMA_THREADS:-$(nproc 2>/dev/null || echo 4)}"
LLAMA_CTX="${LLAMA_CTX:-8192}"
LLAMA_BATCH="${LLAMA_BATCH:-512}"
LLAMA_GPU_LAYERS="${LLAMA_GPU_LAYERS:-999}"   # offload all layers to GPU
LLAMA_PARALLEL="${LLAMA_PARALLEL:-1}"          # concurrent request slots

# Default model path (Q4_K_M quantised GGUF from export_gguf.py)
DEFAULT_MODEL="/workspace/train/output_agent/qwen3-8b-apexmail-Q4_K_M.gguf"
MODEL_PATH="${1:-${LLAMA_MODEL:-${DEFAULT_MODEL}}}"

# ── Pre-flight checks ────────────────────────────────────────
if [[ ! -x "$LLAMA_SERVER" ]]; then
    echo "❌  llama-server not found at: $LLAMA_SERVER"
    echo "    Build it:  cd $LLAMA_CPP_DIR && cmake -B build -DGGML_CUDA=ON && cmake --build build --config Release -j"
    exit 1
fi

if [[ ! -f "$MODEL_PATH" ]]; then
    echo "❌  Model GGUF not found at: $MODEL_PATH"
    echo "    Run export_gguf.py first to create the quantised model."
    exit 1
fi

echo "🚀  Starting llama-server"
echo "    Model:     $MODEL_PATH"
echo "    Port:      $LLAMA_PORT"
echo "    Threads:   $LLAMA_THREADS"
echo "    Context:   $LLAMA_CTX"
echo "    GPU layers: $LLAMA_GPU_LAYERS"
echo ""

# ── Launch ────────────────────────────────────────────────────
exec "$LLAMA_SERVER" \
    --model "$MODEL_PATH" \
    --host "$LLAMA_HOST" \
    --port "$LLAMA_PORT" \
    --threads "$LLAMA_THREADS" \
    --ctx-size "$LLAMA_CTX" \
    --batch-size "$LLAMA_BATCH" \
    --n-gpu-layers "$LLAMA_GPU_LAYERS" \
    --parallel "$LLAMA_PARALLEL" \
    --log-disable \
    --metrics
