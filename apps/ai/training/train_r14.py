#!/usr/bin/env python3
"""
R14 Training Script — Qwen3-Next-80B-A3B-Instruct (MoE)
4x NVIDIA B200, QLoRA fine-tuning
Target: attention + shared_expert + gate (skip individual experts)
"""

import os
import torch
import json
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training, TaskType
from trl import SFTTrainer

# ── Config ──
MODEL_PATH = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH  = "/workspace/train/data/train_agent.jsonl"
OUTPUT_DIR = "/workspace/output_agent"

# ── Quantization (4-bit for 80B model) ──
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

print("=" * 60)
print("R14 TRAINING — Qwen3-Next-80B-A3B-Instruct (MoE)")
print("=" * 60)

# ── Tokenizer ──
print("\n[1/5] Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.pad_token_id = tokenizer.eos_token_id

# ── Model ──
print("[2/5] Loading model with 4-bit quantization...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    quantization_config=bnb_config,
    device_map="auto",
    dtype=torch.bfloat16,
    trust_remote_code=True,
    attn_implementation="sdpa",
)
model.config.use_cache = False
model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)

# Print GPU memory after loading
for i in range(torch.cuda.device_count()):
    alloc = torch.cuda.memory_allocated(i) / 1e9
    total = torch.cuda.get_device_properties(i).total_mem / 1e9
    print(f"  GPU {i}: {alloc:.1f}GB / {total:.1f}GB")

# ── LoRA Config (MoE-aware) ──
# Target: attention projections + shared expert + gate router
# Skip individual experts (512 per layer = too many params)
print("[3/5] Applying LoRA...")
lora_config = LoraConfig(
    task_type=TaskType.CAUSAL_LM,
    r=64,
    lora_alpha=128,
    lora_dropout=0.05,
    target_modules=[
        # Standard attention
        "q_proj", "k_proj", "v_proj", "o_proj",
        # Linear attention projections
        "in_proj_qkvz", "in_proj_ba", "out_proj",
        # Shared expert (always active — critical for fine-tuning)
        "shared_expert.gate_proj",
        "shared_expert.up_proj",
        "shared_expert.down_proj",
        # Router gate (teaches task-specific expert routing)
        "mlp.gate",
        # Shared expert gate
        "shared_expert_gate",
    ],
    modules_to_save=None,
    bias="none",
)

model = get_peft_model(model, lora_config)
trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
total_params = sum(p.numel() for p in model.parameters())
print(f"  Trainable: {trainable:,} / {total_params:,} ({100*trainable/total_params:.2f}%)")

# ── Dataset ──
print("[4/5] Loading dataset...")
dataset = load_dataset("json", data_files=DATA_PATH, split="train")
print(f"  Examples: {len(dataset)}")

# ── Training ──
print("[5/5] Starting training...")
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=3,
    per_device_train_batch_size=1,
    gradient_accumulation_steps=16,
    learning_rate=1.5e-4,
    lr_scheduler_type="cosine",
    warmup_ratio=0.05,
    weight_decay=0.01,
    bf16=True,
    logging_steps=5,
    save_strategy="epoch",
    save_total_limit=2,
    gradient_checkpointing=True,
    gradient_checkpointing_kwargs={"use_reentrant": False},
    optim="paged_adamw_8bit",
    max_grad_norm=0.3,
    report_to="none",
    dataloader_num_workers=4,
    remove_unused_columns=False,
    ddp_find_unused_parameters=False,
)

trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=dataset,
    processing_class=tokenizer,
    max_seq_length=4096,
    dataset_text_field="text",
    packing=True,
)

trainer.train()

# ── Save ──
print("\nSaving adapter...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

# Final GPU stats
for i in range(torch.cuda.device_count()):
    alloc = torch.cuda.memory_allocated(i) / 1e9
    print(f"  GPU {i} peak: {torch.cuda.max_memory_allocated(i)/1e9:.1f}GB")

print("\n✅ R14 Training complete!")
print(f"Adapter saved to: {OUTPUT_DIR}")
