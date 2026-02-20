#!/usr/bin/env python3
"""
R14 Training Script - DeepSpeed ZeRO-3 + LoRA for 4-GPU B200
Model: Qwen3-Next-80B-A3B-Instruct (MoE, 80B total, ~3B active)

Strategy:
  - bf16 (NO quantization) + DeepSpeed ZeRO-3 weight sharding
  - Model (160GB bf16) sharded across 4 GPUs => ~40GB each
  - LoRA on attention + linear attention + shared expert layers
  - True data parallelism: ALL 4 GPUs compute simultaneously

Launch:
  deepspeed --num_gpus 4 train_r14_ds.py
"""

import os
import sys
import json
import time
import torch
import logging

# ── Env setup ──────────────────────────────────────────────────────
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"

# TF32 for Blackwell
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── Paths ──────────────────────────────────────────────────────────
MODEL_PATH = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH = "/workspace/train_agent.jsonl"
OUTPUT_DIR = "/workspace/output_agent"
DS_CONFIG = "/workspace/ds_config.json"

def main():
    log.info("=" * 60)
    log.info("R14 DeepSpeed ZeRO-3 + LoRA Training")
    log.info("=" * 60)

    # ── Check GPU info ─────────────────────────────────────────────
    n_gpus = torch.cuda.device_count()
    log.info(f"GPUs available: {n_gpus}")
    for i in range(n_gpus):
        name = torch.cuda.get_device_name(i)
        mem = torch.cuda.get_device_properties(i).total_memory / 1e9
        log.info(f"  GPU {i}: {name} ({mem:.1f} GB)")

    # ── Load tokenizer ─────────────────────────────────────────────
    from transformers import AutoTokenizer
    log.info(f"Loading tokenizer from {MODEL_PATH}")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    log.info(f"Tokenizer loaded. Vocab size: {tokenizer.vocab_size}")

    # ── Load model (bf16, NO device_map - DeepSpeed handles sharding) ──
    from transformers import AutoModelForCausalLM
    log.info(f"Loading model in bf16 from {MODEL_PATH}")
    log.info("  (DeepSpeed ZeRO-3 will shard across all GPUs)")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        dtype=torch.bfloat16,
        trust_remote_code=True,
        low_cpu_mem_usage=True,
        use_cache=False,  # Required for gradient checkpointing
    )
    log.info(f"Model loaded in {time.time()-t0:.1f}s")

    # ── Apply LoRA ─────────────────────────────────────────────────
    from peft import LoraConfig, get_peft_model
    lora_config = LoraConfig(
        r=64,
        lora_alpha=128,
        target_modules=[
            # Standard full attention
            "q_proj", "k_proj", "v_proj", "o_proj",
            # Linear attention (Mamba-like)
            "in_proj_qkvz", "in_proj_ba", "out_proj",
            # Shared expert MLP
            "shared_expert.gate_proj",
            "shared_expert.up_proj",
            "shared_expert.down_proj",
        ],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    log.info("Applying LoRA...")
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    # ── Load dataset ───────────────────────────────────────────────
    from datasets import load_dataset
    dataset = load_dataset("json", data_files=DATA_PATH, split="train")
    log.info(f"Dataset: {len(dataset)} examples")

    # ── Training config ────────────────────────────────────────────
    from trl import SFTTrainer, SFTConfig

    # Effective batch = per_device(2) * gpus(4) * grad_accum(4) = 32
    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        deepspeed=DS_CONFIG,

        # Precision
        bf16=True,

        # Batch size
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,

        # Schedule
        num_train_epochs=3,
        learning_rate=1.5e-4,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        weight_decay=0.01,

        # Logging & saving
        logging_steps=1,
        save_strategy="epoch",
        save_total_limit=2,

        # Data
        max_length=4096,
        dataset_text_field="text",
        packing=False,

        # Memory optimization
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": True},

        # Performance
        dataloader_num_workers=8,
        dataloader_pin_memory=True,

        # Misc
        report_to="none",
        seed=42,
        remove_unused_columns=False,
    )

    # ── Create trainer ─────────────────────────────────────────────
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer,
    )

    # ── Train! ─────────────────────────────────────────────────────
    log.info("Starting training...")
    log.info(f"  Effective batch size: {training_args.per_device_train_batch_size * n_gpus * training_args.gradient_accumulation_steps}")
    log.info(f"  Epochs: {training_args.num_train_epochs}")
    log.info(f"  Total steps: {len(dataset) // (training_args.per_device_train_batch_size * n_gpus * training_args.gradient_accumulation_steps) * int(training_args.num_train_epochs)}")
    result = trainer.train()

    # ── Save ───────────────────────────────────────────────────────
    log.info("Saving model...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)

    log.info("=" * 60)
    log.info(f"Training complete! Loss: {result.training_loss:.4f}")
    log.info(f"Output saved to: {OUTPUT_DIR}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
