#!/usr/bin/env python3
"""
ApexMail Agent Training - 8× RTX 5090 GPUs (32GB each)
QLoRA 4-bit with model parallelism across all GPUs.

Model: Qwen3-Next-80B-A3B-Instruct (MoE ~80B total, ~3B active)
QLoRA: r=64, alpha=128, 4-bit NF4 quantization
VRAM budget: 8 × 32GB = 256GB total
  - 4-bit model sharded via device_map="auto": ~5GB/GPU
  - Remaining per GPU: ~27GB for activations + optimizer states
"""
import os, time, json, torch

# ── Critical env vars ──
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:256"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "16"
os.environ["MKL_NUM_THREADS"] = "16"
os.environ["TRITON_CACHE_DIR"] = "/workspace/.triton_cache"

from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths ──
MODEL_PATH = os.environ.get("MODEL_PATH", "/workspace/models/Qwen3-Next-80B-A3B-Instruct")
DATA_PATH  = os.environ.get("DATA_PATH", "/workspace/data/train.jsonl")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/workspace/output_agent")


def main():
    gpu_count = torch.cuda.device_count()
    gpu_name = torch.cuda.get_device_properties(0).name
    gpu_mem = torch.cuda.get_device_properties(0).total_memory // (1024**3)

    print("=" * 70)
    print("ApexMail Agent Training - QLoRA 4-bit + Model Parallelism")
    print(f"  GPUs: {gpu_count} × {gpu_name} ({gpu_mem}GB each)")
    print(f"  Total VRAM: {gpu_mem * gpu_count}GB")
    print(f"  PyTorch: {torch.__version__}  CUDA: {torch.version.cuda}")
    print(f"  Mode: QLoRA NF4 with device_map='auto'")
    print("=" * 70)

    # ── 1. Load tokenizer ────────────────────────────────────
    print("\nLoading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load model in 4-bit with device_map="auto" ────────
    print("Loading model in 4-bit NF4 across all GPUs...")
    print(f"  Base model: ~80B params → ~40GB in 4-bit → ~{40//gpu_count}GB/GPU")
    t0 = time.time()

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        quantization_config=bnb_config,
        device_map="auto",
        trust_remote_code=True,
        attn_implementation="eager",
        low_cpu_mem_usage=True,
    )
    load_time = time.time() - t0
    print(f"Model loaded in {load_time:.1f}s")

    # Show device distribution
    device_counts = {}
    for name, param in model.named_parameters():
        dev = str(param.device)
        device_counts[dev] = device_counts.get(dev, 0) + 1
    for dev, count in sorted(device_counts.items()):
        print(f"  {dev}: {count} parameters")

    # ── 3. Enable gradient checkpointing ──────────────────────
    print("\nEnabling gradient checkpointing...")
    model.gradient_checkpointing_enable(
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )

    # ── 4. Apply LoRA ─────────────────────────────────────────
    print("Applying LoRA (r=64, alpha=128)...")
    t1 = time.time()
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
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    print(f"LoRA applied in {time.time()-t1:.1f}s")

    # Show VRAM usage after model setup
    for i in range(gpu_count):
        used = torch.cuda.memory_allocated(i) / (1024**3)
        total = torch.cuda.get_device_properties(i).total_memory / (1024**3)
        print(f"  GPU {i}: {used:.1f}/{total:.1f} GB ({used/total*100:.0f}%)")

    # ── 5. Load dataset ──────────────────────────────────────
    print(f"\nLoading dataset from {DATA_PATH}...")
    ds = load_dataset("json", data_files=DATA_PATH, split="train")
    print(f"Dataset: {len(ds)} examples")

    # ── 6. Training config ───────────────────────────────────
    total_examples = len(ds)
    per_device_batch = 1    # Conservative for activations headroom
    grad_accum = 16         # Effective batch = 1 * 16 = 16
    effective_batch = per_device_batch * grad_accum
    steps_per_epoch = max(1, total_examples // effective_batch)
    num_epochs = 3
    total_steps = steps_per_epoch * num_epochs

    print(f"\nTraining config (QLoRA, Model Parallelism, {gpu_count} GPUs):")
    print(f"  Per-device batch:   {per_device_batch}")
    print(f"  Grad accumulation:  {grad_accum}")
    print(f"  Effective batch:    {effective_batch}")
    print(f"  Steps/epoch:        {steps_per_epoch}")
    print(f"  Total steps:        {total_steps} ({num_epochs} epochs)")
    print(f"  Max sequence len:   512")
    print(f"  LoRA: r=64, alpha=128 (QLoRA NF4)")
    print(f"  Learning rate:      2e-4 (cosine decay)")

    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=per_device_batch,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=num_epochs,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        bf16=True,
        logging_steps=1,
        save_strategy="epoch",
        save_total_limit=2,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_length=512,
        dataset_text_field="text",
        report_to="none",
        # ── Data loading ──
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        dataloader_prefetch_factor=4,
        remove_unused_columns=True,
        dataloader_drop_last=True,
        seed=42,
        ddp_timeout=7200,
    )

    # ── 7. Create trainer and train ──────────────────────────
    print("\nCreating SFTTrainer...")
    t3 = time.time()
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=ds,
        processing_class=tok,
    )
    print(f"Trainer created in {time.time()-t3:.1f}s")

    print(f"\n{'='*70}")
    print(f"Starting training: {total_steps} steps, {num_epochs} epochs")
    print(f"Model parallelism across {gpu_count} GPUs")
    print(f"{'='*70}\n")

    train_start = time.time()
    trainer.train()
    train_time = time.time() - train_start

    # ── 8. Save adapter ──────────────────────────────────────
    print(f"\nTraining completed in {train_time/60:.1f} minutes")
    print("Saving adapter...")
    trainer.save_model(OUTPUT_DIR)
    tok.save_pretrained(OUTPUT_DIR)
    metrics = trainer.state.log_history
    with open(os.path.join(OUTPUT_DIR, "train_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)
    if metrics:
        losses = [m for m in metrics if "loss" in m]
        if losses:
            print(f"\nFinal training loss: {losses[-1].get('loss', 'N/A')}")
    print(f"\n{'='*70}")
    print(f"Training complete! Adapter saved to: {OUTPUT_DIR}")
    print(f"Total training time: {train_time/60:.1f} minutes")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
