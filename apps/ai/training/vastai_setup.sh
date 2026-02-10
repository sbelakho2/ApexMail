#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  ApexMail AI — vast.ai Instance Setup
# ═══════════════════════════════════════════════════════════════════════════════
#  Run this ONCE after SSH-ing into a fresh vast.ai instance.
#  Installs dependencies and downloads the base model.
#
#  Usage (on the vast.ai instance):
#    cd /workspace/training && ./vastai_setup.sh
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "═══════════════════════════════════════════════════════════"
echo "  ApexMail AI — vast.ai Setup"
echo "═══════════════════════════════════════════════════════════"

WORKDIR="/workspace/training"

# ── System packages ──────────────────────────────────────────────────────────
echo ""
echo "1. Installing system packages..."
apt-get update -qq && apt-get install -y -qq \
    git \
    vim \
    htop \
    nvtop \
    tmux \
    rsync \
    build-essential \
    cmake \
    2>/dev/null

# ── Python environment ───────────────────────────────────────────────────────
echo ""
echo "2. Creating Python venv..."
python3 -m venv "${WORKDIR}/.venv"
source "${WORKDIR}/.venv/bin/activate"

# ── Install dependencies ────────────────────────────────────────────────────
echo ""
echo "3. Installing Python packages..."
pip install --upgrade pip setuptools wheel
pip install -r "${WORKDIR}/requirements.txt"

# Flash Attention needs special install with CUDA
echo ""
echo "4. Installing Flash Attention 2..."
pip install flash-attn --no-build-isolation 2>/dev/null || {
    echo "  ⚠ Flash Attention install failed (may need different CUDA version)."
    echo "    Training will fall back to sdpa attention."
}

# ── Download base model ──────────────────────────────────────────────────────
echo ""
echo "5. Pre-downloading Qwen 2.5-7B-Instruct..."
python3 -c "
from transformers import AutoModelForCausalLM, AutoTokenizer

print('  Downloading tokenizer...')
tokenizer = AutoTokenizer.from_pretrained(
    'Qwen/Qwen2.5-7B-Instruct',
    trust_remote_code=True,
)
print(f'  Tokenizer vocab: {tokenizer.vocab_size}')

print('  Downloading model weights (this may take 5-15 min)...')
# Just download, don't load into GPU yet
from huggingface_hub import snapshot_download
snapshot_download('Qwen/Qwen2.5-7B-Instruct')
print('  ✓ Model downloaded to HF cache')
"

# ── Verify GPU ───────────────────────────────────────────────────────────────
echo ""
echo "6. Verifying GPU..."
python3 -c "
import torch
print(f'  PyTorch:    {torch.__version__}')
print(f'  CUDA:       {torch.version.cuda}')
print(f'  GPU count:  {torch.cuda.device_count()}')
for i in range(torch.cuda.device_count()):
    props = torch.cuda.get_device_properties(i)
    print(f'  GPU {i}:     {props.name} ({props.total_mem / 1e9:.1f} GB)')
print(f'  bf16:       {torch.cuda.is_bf16_supported()}')
"

# ── Verify imports ───────────────────────────────────────────────────────────
echo ""
echo "7. Verifying key imports..."
python3 -c "
import transformers, peft, trl, bitsandbytes, datasets, optimum
print(f'  transformers: {transformers.__version__}')
print(f'  peft:         {peft.__version__}')
print(f'  trl:          {trl.__version__}')
print(f'  bitsandbytes: {bitsandbytes.__version__}')
print(f'  datasets:     {datasets.__version__}')
print(f'  optimum:      {optimum.__version__}')
try:
    import flash_attn
    print(f'  flash_attn:   {flash_attn.__version__}')
except ImportError:
    print('  flash_attn:   NOT INSTALLED (will use sdpa)')
"

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Setup complete!"
echo ""
echo "  Next:  ./vastai_train.sh"
echo "═══════════════════════════════════════════════════════════"
