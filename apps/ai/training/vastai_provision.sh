#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  ApexMail AI — vast.ai Instance Provisioner
# ═══════════════════════════════════════════════════════════════════════════════
#  Finds and rents a GPU instance on vast.ai for Qwen 7B QLoRA training.
#
#  Requirements:
#    pip install vastai
#    export VAST_API_KEY=<your-key>  (or put it in .vast_api_key)
#
#  Usage:
#    ./vastai_provision.sh              # auto-select cheapest A100/A6000
#    ./vastai_provision.sh --gpu a100   # prefer A100
#    ./vastai_provision.sh --dry-run    # show matches, don't rent
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────
GPU_FILTER="a100|a6000|4090|l40"   # GPUs with enough VRAM for 7B QLoRA
MIN_VRAM_GB=24                      # 7B QLoRA needs ~18-22 GB, 24 GB minimum
MIN_DISK_GB=80                      # model weights + dataset + checkpoints
MAX_PRICE_HR=1.50                   # $/hr max
DOCKER_IMAGE="pytorch/pytorch:2.3.1-cuda12.1-cudnn8-devel"
DRY_RUN=false

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gpu)    GPU_FILTER="$2"; shift 2 ;;
        --max-price) MAX_PRICE_HR="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── API key ──────────────────────────────────────────────────────────────────
if [[ -z "${VAST_API_KEY:-}" ]]; then
    if [[ -f "${SCRIPT_DIR}/.vast_api_key" ]]; then
        export VAST_API_KEY="$(cat "${SCRIPT_DIR}/.vast_api_key")"
    else
        echo "ERROR: Set VAST_API_KEY or create .vast_api_key file"
        exit 1
    fi
fi

echo "═══════════════════════════════════════════════════════════"
echo "  ApexMail AI — vast.ai GPU Provisioner"
echo "═══════════════════════════════════════════════════════════"
echo "  GPU filter:   ${GPU_FILTER}"
echo "  Min VRAM:     ${MIN_VRAM_GB} GB"
echo "  Min disk:     ${MIN_DISK_GB} GB"
echo "  Max price:    \$${MAX_PRICE_HR}/hr"
echo "  Docker image: ${DOCKER_IMAGE}"
echo "═══════════════════════════════════════════════════════════"

# ── Search for offers ────────────────────────────────────────────────────────
echo ""
echo "Searching for GPU instances..."

vastai search offers \
    "gpu_ram >= ${MIN_VRAM_GB}" \
    "disk_space >= ${MIN_DISK_GB}" \
    "dph_total <= ${MAX_PRICE_HR}" \
    "cuda_vers >= 12.0" \
    "reliability >= 0.95" \
    "inet_down >= 200" \
    --order "dph_total" \
    --limit 10

if [[ "${DRY_RUN}" == "true" ]]; then
    echo ""
    echo "[DRY RUN] Would select cheapest matching instance."
    exit 0
fi

# ── Select cheapest ──────────────────────────────────────────────────────────
echo ""
echo "Selecting cheapest instance..."

OFFER_ID=$(vastai search offers \
    "gpu_ram >= ${MIN_VRAM_GB}" \
    "disk_space >= ${MIN_DISK_GB}" \
    "dph_total <= ${MAX_PRICE_HR}" \
    "cuda_vers >= 12.0" \
    "reliability >= 0.95" \
    "inet_down >= 200" \
    --order "dph_total" \
    --limit 1 \
    --raw | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['id']) if d else sys.exit(1)")

echo "  Selected offer: ${OFFER_ID}"

# ── Create instance ──────────────────────────────────────────────────────────
echo ""
echo "Creating instance..."

INSTANCE_ID=$(vastai create instance "${OFFER_ID}" \
    --image "${DOCKER_IMAGE}" \
    --disk "${MIN_DISK_GB}" \
    --ssh \
    --direct \
    --raw | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('new_contract', d.get('id', '')))")

echo "  Instance ID: ${INSTANCE_ID}"
echo "${INSTANCE_ID}" > "${SCRIPT_DIR}/vast_instance_id.txt"

# ── Wait for instance to be ready ────────────────────────────────────────────
echo ""
echo "Waiting for instance to start..."

for i in $(seq 1 60); do
    STATUS=$(vastai show instance "${INSTANCE_ID}" --raw | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('actual_status', 'unknown'))")

    if [[ "${STATUS}" == "running" ]]; then
        echo "  ✓ Instance is running!"
        break
    fi
    echo "  Status: ${STATUS} (attempt ${i}/60)"
    sleep 10
done

# ── Get SSH details ──────────────────────────────────────────────────────────
echo ""
echo "Instance details:"
vastai show instance "${INSTANCE_ID}"

SSH_CMD=$(vastai ssh-url "${INSTANCE_ID}" 2>/dev/null || echo "")

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Instance ${INSTANCE_ID} is READY"
echo ""
echo "  SSH:  ${SSH_CMD:-Check 'vastai show instance ${INSTANCE_ID}'}"
echo ""
echo "  Next steps:"
echo "    1. SSH into the instance"
echo "    2. Run:  ./vastai_setup.sh"
echo "    3. Run:  ./vastai_train.sh"
echo "═══════════════════════════════════════════════════════════"
