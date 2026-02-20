# ApexMail AI — Qwen3.5-8B Training

Fine-tunes [Qwen3.5-8B](https://huggingface.co/Qwen/Qwen3.5-8B) with QLoRA for the ApexMail customer support agent. Designed for training on [vast.ai](https://vast.ai) GPU instances.

## Architecture

```
User question
    │
    ▼
┌──────────────────────────────────────┐
│  llama-server (llama.cpp)            │  ← Serves Qwen3.5-8B GGUF Q4_K_M
│  OpenAI-compatible /v1/chat/completions │  ← HTTP sidecar on the VPS
└──────────────────────────────────────┘
    ▲                    │
    │ HTTP (OpenAI API)  │ streamed response
    │                    ▼
┌──────────────────────────────────────┐
│  @apexmail/ai — InferenceEngine      │  ← Thin HTTP client in Node.js
│  (replaces onnxruntime-node stub)    │
└──────────────────────────────────────┘
    │
    ▼
Grounded answer (pricing, API, features, actions)
```

### Why llama.cpp server instead of ONNX Runtime

- **3–5× faster** on CPU (SIMD-optimised kernels: AVX2/AVX512/NEON)
- **Simpler Node.js integration** — plain HTTP client, no native `.node` bindings
- **Streaming** out of the box via SSE
- **Model hot-swap** without restarting the Node.js process
- **Drop-in replacement** for hosted models (point the same client at GPT-4o if needed)

## Requirements

- **Training**: A100 40GB / A6000 48GB / RTX 4090 24GB (vast.ai)
- **Inference**: Any VPS with ≥8 GB RAM for Q4_K_M (~5 GB model size), ≥10 GB for Q5_K_M
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
rsync -avz --exclude='.venv' --exclude='output' --exclude='gguf_model' \
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
./vastai_train.sh    # generate data → train → eval → export GGUF
```

### 5. Download the GGUF model

```bash
rsync -avz vast_instance:/workspace/training/gguf_model/ ./gguf_model/
```

### 6. Run llama-server on the VPS

```bash
# Install llama.cpp (already built by vastai_setup.sh)
llama-server \
  --model ./gguf_model/qwen3.5-8b-q4_k_m.gguf \
  --host 0.0.0.0 \
  --port 8080 \
  --ctx-size 8192 \
  --n-predict 1024 \
  --threads $(nproc)
```

The service exposes an OpenAI-compatible API at `http://<vps>:8080/v1`. Point the
`LLAMA_SERVER_URL` environment variable in `@apexmail/ai` to this address.

## File Structure

```
training/
├── config.yaml           # All hyper-parameters & paths
├── prompts_v2.py         # System prompt, customer contexts, tool definitions
├── build_agent.py        # Training dataset builder (ChatML multi-turn)
├── train_agent.sh        # 4-GPU DDP training launch script
├── train.py              # QLoRA fine-tuning with SFTTrainer
├── eval.py               # Golden-set evaluation with A/B/C/D/F grading
├── export_gguf.py        # Merge adapter → GGUF → Q4_K_M / Q5_K_M / Q8_0
├── export_onnx.py        # (legacy) Merge adapter → ONNX INT8 — not used in prod
├── test_agent.py         # Full agent test suite (9 categories, 230 tests)
├── run_all_tests.py      # Run test suite against a live llama-server
├── requirements.txt      # Python dependencies
├── vastai_provision.sh   # Find & rent a GPU instance
├── vastai_setup.sh       # Install deps, build llama.cpp, download model
├── vastai_train.sh       # Run the full pipeline
├── data/                 # Generated JSONL datasets
│   ├── train_agent.jsonl # Primary agent training set (~3300 examples)
│   ├── val.jsonl
│   └── test.jsonl
├── output_agent/         # LoRA adapter checkpoints
├── output-merged/        # Merged full model (temporary, for GGUF export)
├── gguf_model/           # GGUF exports for production (Q4_K_M primary)
├── eval_results/         # Evaluation results JSON
└── logs/                 # Training & eval logs
```

## Training Details

| Parameter | Value |
|-----------|-------|
| Base model | Qwen/Qwen3.5-8B |
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
