#!/bin/bash
# launch_r22.sh — Launch optimized 4-GPU training for R22
set -e
cd /workspace/ApexMail/apps/ai/training

export NCCL_P2P_DISABLE=1
export NCCL_IB_DISABLE=1
export NCCL_SOCKET_TIMEOUT=600000
export TORCH_NCCL_BLOCKING_WAIT=1

echo "=== R22 Training Launch ==="
echo "Date: $(date)"
echo "GPUs: $(nvidia-smi -L | wc -l)"
echo "Dataset: $(wc -l < data/train.jsonl) examples"
echo "Config: batch=7/GPU, grad_accum=1, LR=2e-4, 4 epochs"
echo "=========================="

torchrun --nproc_per_node=4 train.py
