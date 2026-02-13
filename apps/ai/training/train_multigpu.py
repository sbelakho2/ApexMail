#!/usr/bin/env python3
"""
ApexMail AI — Multi-GPU QLoRA Training (DDP)
=============================================
Optimized for 2xB200 (366 GB VRAM total).
Uses accelerate DDP so BOTH GPUs compute in parallel.

Launch:
    accelerate launch --num_processes=2 train_multigpu.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

import torch
import yaml
from datasets import load_dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("apexmail.train")

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

LOCAL_RANK = int(os.environ.get("LOCAL_RANK", 0))
WORLD_SIZE = int(os.environ.get("WORLD_SIZE", 1))
IS_MAIN = LOCAL_RANK == 0


def log(msg: str):
    if IS_MAIN:
        print(msg, flush=True)


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    # Try to enable memory-efficient SDPA backends (Blackwell sm_100)
    try:
        torch.backends.cuda.enable_mem_efficient_sdp(True)
        torch.backends.cuda.enable_math_sdp(True)
    except Exception:
        pass

    log("=" * 70)
    log("  ApexMail AI — Multi-GPU QLoRA Training (DDP)")
    log(f"  LOCAL_RANK={LOCAL_RANK}  WORLD_SIZE={WORLD_SIZE}")
    log("=" * 70)

    cfg = load_config()
    model_cfg = cfg["model"]
    quant_cfg = cfg["quantisation"]
    train_cfg = cfg["training"]
    lora_cfg = cfg["lora"]
    paths = cfg["paths"]

    # GPU info
    if torch.cuda.is_available():
        props = torch.cuda.get_device_properties(LOCAL_RANK)
        log(f"  GPU {LOCAL_RANK}: {props.name} — {props.total_memory / 1e9:.1f} GB")

    # ── Tokenizer ────────────────────────────────────────────────────────
    tokenizer = AutoTokenizer.from_pretrained(
        model_cfg["base"],
        revision=model_cfg.get("revision", "main"),
        trust_remote_code=True,
        padding_side="right",
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id

    # ── Model — each GPU loads its OWN copy (DDP) ───────────────────────
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=quant_cfg["load_in_4bit"],
        bnb_4bit_quant_type=quant_cfg["bnb_4bit_quant_type"],
        bnb_4bit_compute_dtype=getattr(torch, quant_cfg["bnb_4bit_compute_dtype"]),
        bnb_4bit_use_double_quant=quant_cfg["bnb_4bit_use_double_quant"],
    )

    log(f"  [GPU {LOCAL_RANK}] Loading 4-bit model...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        model_cfg["base"],
        revision=model_cfg.get("revision", "main"),
        quantization_config=bnb_config,
        torch_dtype=getattr(torch, model_cfg["torch_dtype"]),
        attn_implementation=model_cfg.get("attn_implementation", "sdpa"),
        # KEY: each GPU gets its own copy — enables true DDP
        device_map={"": LOCAL_RANK},
        trust_remote_code=True,
    )
    log(f"  [GPU {LOCAL_RANK}] Model loaded in {time.time() - t0:.1f}s")

    # ── LoRA ─────────────────────────────────────────────────────────────
    model = prepare_model_for_kbit_training(
        model, use_gradient_checkpointing=train_cfg.get("gradient_checkpointing", True)
    )
    lora = LoraConfig(
        r=lora_cfg["r"],
        lora_alpha=lora_cfg["alpha"],
        lora_dropout=lora_cfg["dropout"],
        bias=lora_cfg["bias"],
        task_type=lora_cfg["task_type"],
        target_modules=lora_cfg["target_modules"],
    )
    model = get_peft_model(model, lora)
    if IS_MAIN:
        trainable, total = 0, 0
        for p in model.parameters():
            total += p.numel()
            if p.requires_grad:
                trainable += p.numel()
        log(f"  Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    # ── Dataset ──────────────────────────────────────────────────────────
    ds = load_dataset("json", data_files={
        "train": cfg["dataset"]["train_file"],
        "validation": cfg["dataset"]["val_file"],
    })
    log(f"  Train: {len(ds['train'])}  Val: {len(ds['validation'])}")

    # ── Training config — MAXIMISE VRAM usage ────────────────────────────
    # 2xB200 = 366 GB total.  Model in 4-bit = ~4 GB per GPU.
    # With packing + seq=4096, each sample is a FULL 4096-token sequence.
    # SDPA attention backward needs O(n²) memory: batch × 28 heads × 4096².
    # flash-attn doesn't support B200 (sm_100) yet, so we keep batch small
    # and use gradient_accumulation to maintain large effective batch.
    # batch=4 per GPU × 2 GPUs × 6 accum = 48 effective
    PER_DEVICE_BATCH = 4
    GRAD_ACCUM = 6
    effective = PER_DEVICE_BATCH * WORLD_SIZE * GRAD_ACCUM
    log(f"  Batch: {PER_DEVICE_BATCH}/GPU × {WORLD_SIZE} GPUs × {GRAD_ACCUM} accum = {effective} effective")

    for d in [paths["output_dir"], paths["logs_dir"]]:
        Path(d).mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    training_args = SFTConfig(
        output_dir=paths["output_dir"],
        max_length=train_cfg["max_seq_length"],
        packing=train_cfg.get("packing", True),
        dataset_text_field="text",

        num_train_epochs=train_cfg["num_train_epochs"],
        per_device_train_batch_size=PER_DEVICE_BATCH,
        per_device_eval_batch_size=PER_DEVICE_BATCH,
        gradient_accumulation_steps=GRAD_ACCUM,

        learning_rate=train_cfg["learning_rate"],
        lr_scheduler_type=train_cfg["lr_scheduler_type"],
        warmup_ratio=train_cfg["warmup_ratio"],
        weight_decay=train_cfg["weight_decay"],

        gradient_checkpointing=train_cfg["gradient_checkpointing"],
        gradient_checkpointing_kwargs=train_cfg.get("gradient_checkpointing_kwargs"),
        optim=train_cfg["optim"],
        bf16=True,
        tf32=True,

        logging_steps=2,
        eval_strategy="no",            # skip eval for speed
        save_strategy="steps",
        save_steps=50,
        save_total_limit=3,

        report_to="tensorboard",
        seed=42,
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        logging_dir=paths["logs_dir"],
        run_name=f"apexmail-r17d-2xB200-{ts}",

        # DDP settings
        ddp_find_unused_parameters=False,
        ddp_backend="nccl",
    )

    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=ds["train"],
        eval_dataset=ds["validation"],
        processing_class=tokenizer,
    )

    # ── Train ────────────────────────────────────────────────────────────
    log("\n  Starting training...")
    t0 = time.time()
    result = trainer.train()
    elapsed = time.time() - t0

    log(f"\n  Training complete in {elapsed / 60:.1f} min")
    log(f"  Final loss: {result.metrics.get('train_loss', 'N/A')}")

    # Save (only main process)
    if IS_MAIN:
        trainer.save_model()
        tokenizer.save_pretrained(paths["output_dir"])
        metrics = result.metrics
        metrics["train_runtime_minutes"] = elapsed / 60
        metrics["effective_batch_size"] = effective
        metrics["world_size"] = WORLD_SIZE
        with open(Path(paths["output_dir"]) / "train_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)
        log(f"  Adapter saved to {paths['output_dir']}")

    log("=" * 70)
    log("  DONE")
    log("=" * 70)


if __name__ == "__main__":
    main()
