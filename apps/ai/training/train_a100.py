#!/usr/bin/env python3
"""
ApexMail Agent Training — 8× A100-SXM4-80GB (640GB total VRAM)
Full bf16 FSDP with LoRA r=128.

Model: Qwen3-Next-80B-A3B-Instruct (MoE ~80B total, ~3B active)
LoRA: r=128, alpha=256, ~184M trainable params
FSDP: full_shard auto_wrap on Qwen3NextDecoderLayer

Memory budget per GPU:
  Model shards (bf16): ~152GB / 8 = ~19GB
  LoRA + optimizer:    ~0.2GB
  Activations (grad ckpt, batch=2, seq=4096): ~10-20GB
  Total: ~30-40GB / 80GB available → comfortable headroom
"""
import os, sys, time, json, torch

# ── Critical env vars — MUST be set before any torch distributed init ──
os.environ["CUDA_DEVICE_MAX_CONNECTIONS"] = "1"
os.environ["NCCL_ALGO"] = "Ring"
os.environ["NCCL_NET_GDR_LEVEL"] = "5"
os.environ["NCCL_P2P_LEVEL"] = "NVL"
os.environ["NCCL_CROSS_NIC"] = "1"
os.environ["NCCL_IB_QPS_PER_CONNECTION"] = "4"
os.environ["NCCL_MIN_NCHANNELS"] = "16"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:512"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "16"
os.environ["MKL_NUM_THREADS"] = "16"

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths (overridable via env) ─────────────────────────────────
MODEL_PATH = os.environ.get("MODEL_PATH", "/workspace/models/Qwen3-Next-80B-A3B-Instruct")
TRAIN_DATA = os.environ.get("TRAIN_DATA", "/workspace/data/train.jsonl")
VAL_DATA   = os.environ.get("VAL_DATA",   "/workspace/data/val.jsonl")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR",  "/workspace/output_agent")


def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 8))
    is_main = local_rank == 0

    torch.cuda.set_device(local_rank)

    if is_main:
        gpu_name = torch.cuda.get_device_properties(0).name
        gpu_mem  = torch.cuda.get_device_properties(0).total_memory // (1024**3)
        print("=" * 70)
        print("ApexMail Agent Training — 8× A100-SXM4-80GB FSDP")
        print(f"  GPUs:     {world_size} × {gpu_name} ({gpu_mem}GB each)")
        print(f"  Total:    {gpu_mem * world_size}GB VRAM")
        print(f"  PyTorch:  {torch.__version__}")
        print(f"  CUDA:     {torch.version.cuda}")
        print(f"  Mode:     Full bf16 + LoRA r=128 + FSDP full_shard")
        print("=" * 70)

    # ── 1. Load tokenizer ────────────────────────────────────────
    if is_main:
        print("\n[1/7] Loading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load model — FSDP handles sharding ───────────────────
    # cpu_ram_efficient_loading=True in FSDP config ensures only rank 0
    # loads weights; FSDP broadcasts via sync_module_states.
    if is_main:
        print("[2/7] Loading model (bf16, FSDP will shard across GPUs)...")
    t0 = time.time()

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        attn_implementation="eager",   # Safest for GatedDeltaNet arch
        low_cpu_mem_usage=True,
    )
    if is_main:
        print(f"    Model loaded in {time.time()-t0:.1f}s")
        total_params = sum(p.numel() for p in model.parameters())
        print(f"    Total parameters: {total_params/1e9:.2f}B")

    # ── 3. Apply LoRA r=128 ─────────────────────────────────────
    if is_main:
        print("[3/7] Applying LoRA (r=128, alpha=256)...")
    t1 = time.time()
    lora_config = LoraConfig(
        r=128,
        lora_alpha=256,
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
    if is_main:
        model.print_trainable_parameters()
        print(f"    LoRA applied in {time.time()-t1:.1f}s")

    # ── 4. Cast LoRA params to bf16 for FSDP dtype uniformity ────
    if is_main:
        print("[4/7] Casting LoRA params to bf16...")
    for name, param in model.named_parameters():
        if param.requires_grad and param.dtype != torch.bfloat16:
            param.data = param.data.to(torch.bfloat16)

    # ── 5. Load datasets ────────────────────────────────────────
    if is_main:
        print(f"[5/7] Loading datasets...")
        print(f"    Train: {TRAIN_DATA}")
        print(f"    Val:   {VAL_DATA}")
    train_ds = load_dataset("json", data_files=TRAIN_DATA, split="train")
    val_ds   = load_dataset("json", data_files=VAL_DATA, split="train")
    if is_main:
        print(f"    Train: {len(train_ds)} examples")
        print(f"    Val:   {len(val_ds)} examples")

    # ── 6. Training config — 8× A100-80GB FSDP ──────────────────
    per_device_batch = 2      # Per GPU
    grad_accum       = 4      # Effective batch = 2 × 4 × 8 = 64
    effective_batch  = per_device_batch * grad_accum * world_size
    steps_per_epoch  = max(1, len(train_ds) // effective_batch)
    num_epochs       = 3
    total_steps      = steps_per_epoch * num_epochs

    if is_main:
        print(f"[6/7] Training hyperparameters:")
        print(f"    Per-device batch:    {per_device_batch}")
        print(f"    Grad accumulation:   {grad_accum}")
        print(f"    Effective batch:     {effective_batch}")
        print(f"    Steps/epoch:         {steps_per_epoch}")
        print(f"    Total steps:         {total_steps} ({num_epochs} epochs)")
        print(f"    Max sequence length: 4096")
        print(f"    Learning rate:       2e-4 (cosine)")
        print(f"    LoRA: r=128, alpha=256")

    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=per_device_batch,
        per_device_eval_batch_size=per_device_batch,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=num_epochs,
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        bf16=True,
        logging_steps=1,
        save_strategy="epoch",
        save_total_limit=2,
        eval_strategy="epoch",
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_length=4096,
        dataset_text_field="text",
        report_to="none",
        # ── Data loading ─────────────────────────────────────────
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        dataloader_prefetch_factor=4,
        remove_unused_columns=True,
        dataloader_drop_last=True,
        seed=42,
        # ── FSDP config ─────────────────────────────────────────
        fsdp="full_shard auto_wrap",
        fsdp_config={
            "transformer_layer_cls_to_wrap": ["Qwen3NextDecoderLayer"],
            "backward_prefetch": "backward_pre",
            "forward_prefetch": True,
            "cpu_ram_efficient_loading": True,
            "sync_module_states": True,
            "use_orig_params": True,
        },
        ddp_timeout=7200,
        local_rank=local_rank,
    )

    # ── 7. Create trainer and train ─────────────────────────────
    if is_main:
        print("[7/7] Creating SFTTrainer...")
    t3 = time.time()
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tok,
    )
    if is_main:
        print(f"    Trainer created in {time.time()-t3:.1f}s")

    if is_main:
        print(f"\n{'='*70}")
        print(f"STARTING TRAINING")
        print(f"  {total_steps} steps × {num_epochs} epochs across {world_size} GPUs")
        print(f"  FSDP full_shard on Qwen3NextDecoderLayer")
        print(f"{'='*70}\n")

    train_start = time.time()
    result = trainer.train()
    train_time = time.time() - train_start

    # ── 8. Save adapter + metrics ────────────────────────────────
    if is_main:
        print(f"\nTraining completed in {train_time/60:.1f} minutes")
        print(f"  Train loss: {result.training_loss:.4f}")
        print("Saving adapter...")

    trainer.save_model(OUTPUT_DIR)

    if is_main:
        tok.save_pretrained(OUTPUT_DIR)

        # Save full training log
        metrics = trainer.state.log_history
        with open(os.path.join(OUTPUT_DIR, "train_metrics.json"), "w") as f:
            json.dump(metrics, f, indent=2)

        # Print summary
        train_losses = [m["loss"] for m in metrics if "loss" in m]
        eval_losses  = [m["eval_loss"] for m in metrics if "eval_loss" in m]

        print(f"\n{'='*70}")
        print("TRAINING SUMMARY")
        print(f"  Duration:        {train_time/60:.1f} minutes")
        print(f"  Final train loss: {train_losses[-1]:.4f}" if train_losses else "  No train losses logged")
        print(f"  Final eval loss:  {eval_losses[-1]:.4f}" if eval_losses else "  No eval losses logged")
        if len(train_losses) > 1:
            print(f"  Loss reduction:  {train_losses[0]:.4f} → {train_losses[-1]:.4f}")
        print(f"  Adapter saved to: {OUTPUT_DIR}")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
