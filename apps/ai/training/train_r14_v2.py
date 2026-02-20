#!/usr/bin/env python3
"""
R14 Training — Qwen3-Next-80B-A3B-Instruct (MoE) 
Optimized for 4x NVIDIA B200 with QLoRA pipeline parallel
"""
import os
import json
import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

# ── Performance tweaks ──
os.environ["PYTORCH_ALLOC_CONF"] = "expandable_segments:True"
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.benchmark = True

# ── Config ──
MODEL_DIR = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH = "/workspace/train/data/train_agent.jsonl"
OUTPUT_DIR = "/workspace/output_agent"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("R14 TRAINING — Qwen3-Next-80B-A3B-Instruct (MoE)")
print("  Pipeline parallel across 4x B200 — Optimized")
print("=" * 60)

# ── GPU Info ──
n_gpus = torch.cuda.device_count()
print(f"\nGPUs available: {n_gpus}")
for i in range(n_gpus):
    total = torch.cuda.get_device_properties(i).total_memory / 1e9
    print(f"  GPU {i}: {total:.1f}GB — {torch.cuda.get_device_name(i)}")

# ── Tokenizer ──
print("\n[1/5] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# ── Model ──
print("[2/5] Loading model with 4-bit quantization...")

# Check if flash-linear-attention is available
try:
    import fla
    print("  flash-linear-attention: AVAILABLE (fast path)")
except ImportError:
    print("  flash-linear-attention: NOT available (torch fallback)")

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_DIR,
    quantization_config=bnb_config,
    device_map="auto",
    attn_implementation="sdpa",
    dtype=torch.bfloat16,
    trust_remote_code=True,
)
model.config.use_cache = False

for i in range(n_gpus):
    used = torch.cuda.memory_allocated(i) / 1e9
    total = torch.cuda.get_device_properties(i).total_memory / 1e9
    print(f"  GPU {i}: {used:.1f}GB / {total:.1f}GB")

# ── LoRA ──
print("[3/5] Applying LoRA...")
model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

lora_config = LoraConfig(
    r=64,
    lora_alpha=128,
    lora_dropout=0.05,
    target_modules=[
        "q_proj", "k_proj", "v_proj", "o_proj",
        "in_proj_qkvz", "in_proj_ba", "out_proj",
        "shared_expert.gate_proj",
        "shared_expert.up_proj",
        "shared_expert.down_proj",
    ],
    modules_to_save=None,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
total_params = sum(p.numel() for p in model.parameters())
print(f"  Trainable: {trainable:,} / {total_params:,} ({100*trainable/total_params:.2f}%)")

# ── Dataset ──
print("[4/5] Loading dataset...")
with open(DATA_PATH) as f:
    raw = [json.loads(l) for l in f]

texts = []
for ex in raw:
    # Data already has 'text' field from build_agent.py
    text = ex.get("text", "")
    if text.strip():
        texts.append(text)

dataset = Dataset.from_dict({"text": texts})
print(f"  Examples: {len(dataset)}")

# ── Training ──
print("[5/5] Starting training...")

training_args = SFTConfig(
    output_dir=OUTPUT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=8,
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
    dataloader_num_workers=4,
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

steps_per_epoch = max(1, len(dataset) // (training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps))
total_steps = steps_per_epoch * 3
print(f"  Expected: ~{total_steps} steps ({steps_per_epoch}/epoch)")
print(f"  Effective batch size: {training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps}")

trainer.train()

# ── Save ──
print("\nSaving adapter...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

info = {
    "model": MODEL_DIR,
    "trainable_params": trainable,
    "total_params": total_params,
    "examples": len(dataset),
    "epochs": 3,
    "batch_size": training_args.per_device_train_batch_size,
    "grad_accum": training_args.gradient_accumulation_steps,
    "learning_rate": training_args.learning_rate,
    "lora_r": 64,
    "lora_alpha": 128,
}
with open(os.path.join(OUTPUT_DIR, "training_info.json"), "w") as f:
    json.dump(info, f, indent=2)

print(f"Adapter saved to {OUTPUT_DIR}")
print("DONE!")
