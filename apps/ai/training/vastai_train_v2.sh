#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  ApexMail AI — vast.ai Full Training Pipeline (v2)
# ═══════════════════════════════════════════════════════════════════════════════
#  End-to-end training pipeline:
#    1. Generate comprehensive dataset (v2)
#    2. Generate 1000-question eval set
#    3. Train QLoRA adapter
#    4. Evaluate on golden set + full eval set
#    5. Export to GGUF (primary for CPU inference)
#    6. Optionally export to ONNX (fallback)
#    7. Package artifacts for download
#
#  Usage (on the vast.ai instance):
#    cd /workspace/training && ./vastai_train_v2.sh
#    cd /workspace/training && ./vastai_train_v2.sh --skip-gguf
#    cd /workspace/training && ./vastai_train_v2.sh --include-bitext
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

WORKDIR="/workspace/training"
SKIP_GGUF=false
SKIP_ONNX=true   # GGUF is primary; skip ONNX by default
INCLUDE_BITEXT=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-gguf)    SKIP_GGUF=true; shift ;;
        --include-onnx) SKIP_ONNX=false; shift ;;
        --include-bitext) INCLUDE_BITEXT=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# Activate venv
source "${WORKDIR}/.venv/bin/activate"
cd "${WORKDIR}"

# Timestamp for this run
TS=$(date +%Y%m%d_%H%M%S)
mkdir -p logs

echo "═══════════════════════════════════════════════════════════"
echo "  ApexMail AI — Training Pipeline v2"
echo "  Model:   Qwen/Qwen2.5-7B-Instruct"
echo "  GPU:     $(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
echo "  VRAM:    $(nvidia-smi --query-gpu=memory.total --format=csv,noheader | head -1)"
echo "  Time:    ${TS}"
echo "═══════════════════════════════════════════════════════════"

# ── Step 1: Generate comprehensive dataset ───────────────────────────────────
echo ""
echo "══ Step 1: Generate training dataset (v2) ══"
BITEXT_FLAG=""
if [[ "${INCLUDE_BITEXT}" == "true" ]]; then
    BITEXT_FLAG="--include-bitext"
    echo "  Including Bitext customer support dataset from HuggingFace"
fi
python3 generate_dataset_v2.py ${BITEXT_FLAG} 2>&1 | tee "logs/dataset_${TS}.log"

echo ""
echo "  Dataset files:"
wc -l data/*.jsonl

# ── Step 2: Generate evaluation set ──────────────────────────────────────────
echo ""
echo "══ Step 2: Generate 1000-question evaluation set ══"
python3 generate_eval_set.py --output data/eval_1000.jsonl 2>&1 | tee "logs/eval_gen_${TS}.log"

# ── Step 3: Train QLoRA adapter ──────────────────────────────────────────────
echo ""
echo "══ Step 3: Train QLoRA adapter ══"
echo "  This will take 30-90 minutes depending on GPU..."
echo ""

python3 train.py 2>&1 | tee "logs/train_${TS}.log"

echo ""
echo "  ✓ Training complete"

# ── Step 4: Evaluate ─────────────────────────────────────────────────────────
echo ""
echo "══ Step 4a: Evaluate on golden set ══"
python3 eval.py 2>&1 | tee "logs/eval_golden_${TS}.log"

echo ""
echo "══ Step 4b: Evaluate on full 1000-question set ══"
python3 eval.py --golden data/eval_1000.jsonl --output eval_results_full 2>&1 | tee "logs/eval_full_${TS}.log"

# ── Step 5: Export to GGUF ───────────────────────────────────────────────────
if [[ "${SKIP_GGUF}" == "false" ]]; then
    echo ""
    echo "══ Step 5: Export to GGUF (CPU inference) ══"
    python3 export_gguf.py 2>&1 | tee "logs/export_gguf_${TS}.log"
else
    echo ""
    echo "══ Step 5: Skipping GGUF export (--skip-gguf) ══"
fi

# ── Step 6: Optionally export to ONNX ────────────────────────────────────────
if [[ "${SKIP_ONNX}" == "false" ]]; then
    echo ""
    echo "══ Step 6: Export to ONNX (fallback) ══"
    python3 export_onnx.py 2>&1 | tee "logs/export_onnx_${TS}.log"
else
    echo ""
    echo "══ Step 6: Skipping ONNX export (use --include-onnx to enable) ══"
fi

# ── Step 7: Package artifacts ────────────────────────────────────────────────
echo ""
echo "══ Step 7: Package artifacts ══"

ARTIFACT_DIR="${WORKDIR}/artifacts_${TS}"
mkdir -p "${ARTIFACT_DIR}"

# Copy GGUF models
if [[ -d "${WORKDIR}/gguf_model" ]]; then
    cp -r "${WORKDIR}/gguf_model" "${ARTIFACT_DIR}/"
    echo "  ✓ GGUF models copied"
fi

# Copy eval results
if [[ -d "${WORKDIR}/eval_results" ]]; then
    cp -r "${WORKDIR}/eval_results" "${ARTIFACT_DIR}/"
fi
if [[ -d "${WORKDIR}/eval_results_full" ]]; then
    cp -r "${WORKDIR}/eval_results_full" "${ARTIFACT_DIR}/"
fi

# Copy system prompt
if [[ -f "${WORKDIR}/gguf_model/system_prompt.txt" ]]; then
    cp "${WORKDIR}/gguf_model/system_prompt.txt" "${ARTIFACT_DIR}/"
fi

# Copy training config
cp "${WORKDIR}/config.yaml" "${ARTIFACT_DIR}/"

# Create manifest
cat > "${ARTIFACT_DIR}/README.md" << 'MANIFEST'
# ApexMail AI Model Artifacts

## Files
- `gguf_model/apexmail-7b-q4_k_m.gguf` — Primary model (Q4_K_M, ~4.4 GB)
- `gguf_model/apexmail-7b-q5_k_m.gguf` — Higher quality (Q5_K_M, ~5.1 GB)
- `gguf_model/apexmail-7b-q8_0.gguf`   — Highest quality (Q8_0, ~7.7 GB)
- `gguf_model/system_prompt.txt`        — System prompt for inference
- `config.yaml`                         — Training configuration
- `eval_results/`                       — Golden set evaluation results
- `eval_results_full/`                  — Full 1000-question evaluation results

## Usage with llama.cpp

```bash
# Server mode (recommended)
llama-server -m gguf_model/apexmail-7b-q4_k_m.gguf \
  -c 4096 --system-prompt-file gguf_model/system_prompt.txt

# CLI mode
llama-cli -m gguf_model/apexmail-7b-q4_k_m.gguf \
  --system-prompt-file gguf_model/system_prompt.txt \
  -p "What plans does ApexMail offer?"
```

## Usage with llama-cpp-python

```python
from llama_cpp import Llama

model = Llama("gguf_model/apexmail-7b-q4_k_m.gguf", n_ctx=4096)

SYSTEM_PROMPT = open("gguf_model/system_prompt.txt").read()

response = model.create_chat_completion(
    messages=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "What plans does ApexMail offer?"},
    ],
    temperature=0.1,
    max_tokens=512,
)

print(response["choices"][0]["message"]["content"])
```

## Model Details
- Base: Qwen/Qwen2.5-7B-Instruct
- Method: QLoRA (r=64, alpha=128)
- Fine-tuned for: ApexMail customer support, email marketing assistant
- CPU inference: ✅ ARM (NEON) and x86 (AVX2/AVX512)
MANIFEST

echo "  ✓ Artifacts packaged in ${ARTIFACT_DIR}"

# Show sizes
echo ""
echo "  Artifact sizes:"
du -sh "${ARTIFACT_DIR}"/* 2>/dev/null | head -20

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Pipeline complete!"
echo ""
echo "  Artifacts:  ${ARTIFACT_DIR}/"
echo "  Logs:       logs/"
echo ""
echo "  To download to local machine:"
echo "    rsync -avz --progress vast:${ARTIFACT_DIR}/ ~/apexmail-model/"
echo "═══════════════════════════════════════════════════════════"
