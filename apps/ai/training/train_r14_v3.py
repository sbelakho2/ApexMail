#!/usr/bin/env python3
"""
R14 Training — Qwen3-Next-80B-A3B-Instruct (MoE)
4-GPU Data Parallelism: Each GPU loads full 4-bit model (~40GB)
Launch: torchrun --nproc_per_node 4 train_r14_v3.py
"""
import os, json, time, torch
from datasets import Dataset
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

# ── Config ──
MODEL_DIR  = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH  = "/workspace/train/data/train_agent.jsonl"
OUTPUT_DIR = "/workspace/output_agent"
os.makedirs(OUTPUT_DIR, exist_ok=True)

local_rank = int(os.environ.get("LOCAL_RANK", 0))
world_size = int(os.environ.get("WORLD_SIZE", 1))

def log(msg):
    if local_rank == 0:
        print(msg, flush=True)

log("=" * 60)
log(f"R14 TRAINING — 4-GPU Data Parallel (world_size={world_size})")
log("=" * 60)

# ── Tokenizer ──
log("[1/5] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# ── Model — each GPU loads the full 4-bit model ──
log(f"[2/5] Loading model on {world_size} GPUs (4-bit, ~40GB each)...")

# Stagger loads slightly to avoid disk I/O thundering herd
if local_rank > 0:
    time.sleep(local_rank * 10)

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_DIR,
    quantization_config=bnb_config,
    device_map={"": local_rank},       # full model on THIS gpu
    attn_implementation="sdpa",
    dtype=torch.bfloat16,
    trust_remote_code=True,
)
model.config.use_cache = False

used = torch.cuda.memory_allocated(local_rank) / 1e9
total = torch.cuda.get_device_properties(local_rank).total_memory / 1e9
print(f"  [rank {local_rank}] GPU {local_rank}: {used:.1f}GB / {total:.1f}GB", flush=True)

# ── LoRA ──
log("[3/5] Applying LoRA...")
model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

lora_cfg = LoraConfig(
    r=64,
    lora_alpha=128,
    lora_dropout=0.05,
    target_modules=[
        "q_proj","k_proj","v_proj","o_proj",
        "in_proj_qkvz","in_proj_ba","out_proj",
        "shared_expert.gate_proj",
        "shared_expert.up_proj",
        "shared_expert.down_proj",
    ],
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_cfg)

if local_rank == 0:
    tp = sum(p.numel() for p in model.parameters() if p.requires_grad)
    ap = sum(p.numel() for p in model.parameters())
    log(f"  Trainable: {tp:,} / {ap:,} ({100*tp/ap:.2f}%)")

# ── Dataset ──
log("[4/5] Loading dataset...")
with open(DATA_PATH) as f:
    raw = [json.loads(l) for l in f]
texts = [ex["text"] for ex in raw if ex.get("text","").strip()]
dataset = Dataset.from_dict({"text": texts})
log(f"  Examples: {len(dataset)}")

# ── Training ──
log("[5/5] Starting training...")

# effective batch = per_device(2) * gpus(4) * accum(4) = 32
training_args = SFTConfig(
    output_dir=OUTPUT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=2,
    gradient_accumulation_steps=4,
    learning_rate=1.5e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    weight_decay=0.01,
    bf16=True,
    logging_steps=5,
    save_strategy="epoch",
    save_total_limit=2,
    gradient_checkpointing=True,
    gradient_checkpointing_kwargs={"use_reentrant": True},
    optim="paged_adamw_8bit",
    max_grad_norm=0.3,
    report_to="none",
    dataloader_num_workers=2,
    remove_unused_columns=False,
    ddp_find_unused_parameters=False,
    max_length=4096,
    packing=False,
    dataset_text_field="text",
    dataloader_pin_memory=True,
)

trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    processing_class=tokenizer,
)

if local_rank == 0:
    spe = max(1, len(dataset) // (2 * world_size * 4))
    log(f"  Steps/epoch: ~{spe}  |  Total: ~{spe*3}")
    log(f"  Effective batch: {2 * world_size * 4}")

trainer.train()

# ── Save (rank 0 only) ──
if local_rank == 0:
    log("\nSaving adapter...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    tp = sum(p.numel() for p in model.parameters() if p.requires_grad)
    ap = sum(p.numel() for p in model.parameters())
    info = {
        "model": MODEL_DIR, "trainable_params": tp, "total_params": ap,
        "examples": len(dataset), "epochs": 3, "batch_size": 2,
        "grad_accum": 4, "learning_rate": 1.5e-4,
        "lora_r": 64, "lora_alpha": 128, "gpus": world_size,
    }
    with open(os.path.join(OUTPUT_DIR, "training_info.json"), "w") as f:
        json.dump(info, f, indent=2)
    log(f"Adapter saved to {OUTPUT_DIR}")
    log("DONE!")
