# ApexMail AI — Qwen 2.5-7B-Instruct Training

Fine-tunes [Qwen 2.5-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-7B-Instruct) with QLoRA for the ApexMail customer support assistant. Designed for training on [vast.ai](https://vast.ai) GPU instances.

## Architecture

```
User question
    │
    ▼
┌──────────────────────┐
│  Qwen 2.5-7B-Instruct │  ← Fine-tuned with QLoRA (LoRA r=64, α=128)
│  (ONNX Runtime, CPU)  │  ← Exported & quantised to INT8 for prod
└──────────────────────┘
    │
    ▼
Grounded answer (pricing, API, features, actions)
```

## Requirements

- **Training**: A100 40GB / A6000 48GB / RTX 4090 24GB (vast.ai)
- **Inference**: Any VPS with ≥16 GB RAM (ONNX Runtime CPU)
- **Python**: 3.10+

## Quick Start

### 1. Provision a GPU on vast.ai

```bash
pip install vastai
export VAST_API_KEY=<your-key>
./vastai_provision.sh
```

### 2. Upload training code to the instance

```bash
# Get SSH details
vastai show instance $(cat vast_instance_id.txt)

# Upload
rsync -avz --exclude='.venv' --exclude='output' --exclude='onnx_model' \
    ./ vast_instance:/workspace/training/
```

### 3. Set up the instance

```bash
ssh vast_instance
cd /workspace/training
./vastai_setup.sh    # installs deps, downloads model (~15 min)
```

### 4. Run training

```bash
./vastai_train.sh    # generate data → train → eval → export ONNX
```

### 5. Download the ONNX model

```bash
rsync -avz vast_instance:/workspace/training/onnx_model/ ./onnx_model/
```

## File Structure

```
training/
├── config.yaml           # All hyper-parameters & paths
├── prompts.py            # System prompt & relevance keywords (shared)
├── generate_dataset.py   # Seed examples + augmentation → JSONL
├── train.py              # QLoRA fine-tuning with SFTTrainer
├── eval.py               # Golden-set evaluation with A/B/C/D/F grading
├── export_onnx.py        # Merge adapter → ONNX → optional INT8
├── requirements.txt      # Python dependencies
├── vastai_provision.sh   # Find & rent a GPU instance
├── vastai_setup.sh       # Install deps on the instance
├── vastai_train.sh       # Run the full pipeline
├── data/                 # Generated JSONL datasets
│   ├── train.jsonl
│   ├── val.jsonl
│   └── test.jsonl
├── output/               # LoRA adapter checkpoints
├── output-merged/        # Merged full model (temporary)
├── onnx_model/           # ONNX export for production
├── eval_results/         # Evaluation results JSON
└── logs/                 # Training & eval logs
```

## Training Details

| Parameter | Value |
|-----------|-------|
| Base model | Qwen/Qwen2.5-7B-Instruct |
| Method | QLoRA (4-bit NF4 + LoRA r=64) |
| Target modules | q/k/v/o/gate/up/down_proj |
| Effective batch size | 16 (4 × 4 grad accum) |
| Learning rate | 2e-4, cosine schedule |
| Epochs | 4 |
| Max sequence length | 4096 |
| Packing | Yes |
| Attention | Flash Attention 2 |
| Precision | bf16 |
| Optimizer | paged_adamw_8bit |

## Evaluation

The model is evaluated against a golden QA set covering:

- **Pricing**: Plan details, PAYG rates, overages
- **API**: Base URL, authentication, SDKs, rate limits
- **Deliverability**: Domain setup, DKIM/SPF/DMARC, benchmarks
- **Features**: Webhooks, templates, automation
- **Actions**: Structured command generation with confirmation
- **Safety**: Off-topic rejection, no hallucination
- **Anti-hallucination**: Correctly denying non-existent features

Ship threshold: **95% A-grade** on the golden set.

## Cost Estimate

| Instance | $/hr | Training time | Total cost |
|----------|------|---------------|------------|
| A100 40GB | ~$0.80 | ~1-2 hr | ~$1.60 |
| A6000 48GB | ~$0.50 | ~2-3 hr | ~$1.50 |
| RTX 4090 24GB | ~$0.40 | ~2-3 hr | ~$1.20 |

*Prices vary by availability on vast.ai.*
