#!/usr/bin/env python3
"""
ApexMail Agent Training - 4× B200 GPUs (183GB each)
Optimized for maximum stability and throughput with FSDP.

Model: Qwen3-Next-80B-A3B-Instruct (MoE ~80B total, ~3B active)
LoRA: r=128, alpha=256, 184M trainable params
"""
import os, time, json, torch

# ── Critical env vars — MUST be set before any torch imports ──
os.environ["CUDA_DEVICE_MAX_CONNECTIONS"] = "1"
os.environ["NCCL_ALGO"] = "Ring"
os.environ["NCCL_NET_GDR_LEVEL"] = "5"
os.environ["NCCL_P2P_LEVEL"] = "NVL"
os.environ["NCCL_CROSS_NIC"] = "1"
os.environ["NCCL_IB_QPS_PER_CONNECTION"] = "4"
os.environ["NCCL_MIN_NCHANNELS"] = "16"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:512"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["OMP_NUM_THREADS"] = "8"
os.environ["MKL_NUM_THREADS"] = "8"

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths (can be overridden via env vars) ─────────────────────
MODEL_PATH = os.environ.get("MODEL_PATH", "/workspace/models/Qwen3-Next-80B-A3B-Instruct")
DATA_PATH  = os.environ.get("DATA_PATH", "/workspace/train_agent.jsonl")
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "/workspace/output_agent")


def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 4))
    is_main = local_rank == 0

    torch.cuda.set_device(local_rank)

    if is_main:
        print("=" * 70)
        print("ApexMail Agent Training - 4× B200 FSDP")
        print(f"  GPUs: {world_size} × NVIDIA B200 (183GB each)")
        print(f"  PyTorch: {torch.__version__}")
        print(f"  CUDA: {torch.version.cuda}")
        print("=" * 70)

    # ── 1. Load tokenizer ────────────────────────────────────
    if is_main:
        print("\nLoading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load model — NO device_map (FSDP handles sharding) ─
    if is_main:
        print("Loading model for 4-GPU FSDP sharding...")
    t0 = time.time()

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        attn_implementation="eager",
        low_cpu_mem_usage=True,
    )
    if is_main:
        print(f"Model loaded in {time.time()-t0:.1f}s")

    # ── 3. Apply LoRA r=128 ──────────────────────────────────
    if is_main:
        print("Applying LoRA (r=128, alpha=256)...")
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
        print(f"LoRA applied in {time.time()-t1:.1f}s")

    # ── 4. Cast LoRA params to bf16 for FSDP dtype uniformity ─
    if is_main:
        print("Casting LoRA parameters to bf16...")
    for name, param in model.named_parameters():
        if param.requires_grad and param.dtype != torch.bfloat16:
            param.data = param.data.to(torch.bfloat16)

    # ── 5. Load dataset ──────────────────────────────────────
    if is_main:
        print(f"\nLoading dataset from {DATA_PATH}...")
    ds = load_dataset("json", data_files=DATA_PATH, split="train")
    if is_main:
        print(f"Dataset: {len(ds)} examples")

    # ── 6. Training config — OPTIMIZED FOR 4× B200 ───────────
    total_examples = len(ds)
    per_device_batch = 2    # Conservative for stability
    grad_accum = 4          # Effective batch = 2 * 4 * 4 = 32
    effective_batch = per_device_batch * grad_accum * world_size
    steps_per_epoch = max(1, total_examples // effective_batch)
    num_epochs = 3
    total_steps = steps_per_epoch * num_epochs

    if is_main:
        print(f"\nTraining config (FSDP, {world_size} GPUs):")
        print(f"  Per-device batch:   {per_device_batch}")
        print(f"  Grad accumulation:  {grad_accum}")
        print(f"  Effective batch:    {effective_batch}")
        print(f"  Steps/epoch:        {steps_per_epoch}")
        print(f"  Total steps:        {total_steps} ({num_epochs} epochs)")
        print(f"  LoRA: r=128, alpha=256")
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
        save_strategy="no",  # No checkpoints = save storage
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_length=4096,
        dataset_text_field="text",
        report_to="none",
        # ── Data loading ──────────────────────────────────────
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        dataloader_prefetch_factor=4,
        remove_unused_columns=True,
        dataloader_drop_last=True,
        seed=42,
        # ── FSDP config for 4 GPUs ────────────────────────────
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

    # ── 7. Create trainer and train ──────────────────────────
    if is_main:
        print("\nCreating SFTTrainer...")
    t3 = time.time()
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=ds,
        processing_class=tok,
    )
    if is_main:
        print(f"Trainer created in {time.time()-t3:.1f}s")

    if is_main:
        print(f"\n{'='*70}")
        print(f"Starting training: {total_steps} steps, {num_epochs} epochs")
        print(f"All {world_size} GPUs computing in parallel via FSDP")
        print(f"{'='*70}\n")

    train_start = time.time()
    trainer.train()
    train_time = time.time() - train_start

    # ── 8. Save adapter ──────────────────────────────────────
    if is_main:
        print(f"\nTraining completed in {train_time/60:.1f} minutes")
        print("Saving adapter...")
    trainer.save_model(OUTPUT_DIR)
    if is_main:
        tok.save_pretrained(OUTPUT_DIR)
        metrics = trainer.state.log_history
        if metrics:
            last = metrics[-1]
            print(f"\nFinal metrics: {json.dumps(last, indent=2)}")
        print(f"\n{'='*70}")
        print(f"Training complete! Adapter saved to: {OUTPUT_DIR}")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
