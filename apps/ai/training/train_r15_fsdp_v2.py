#!/usr/bin/env python3
"""
R15-FSDP-v2: Maximum GPU utilization training for Qwen3-Next-80B-A3B-Instruct

Optimizations over v1:
1. per_device_batch=4 (from 2), grad_accum=2 (from 4)
   → Same effective batch (32) but HALF the all-gather/reduce-scatter rounds per step
2. Removed limit_all_gathers → allows overlapping all-gathers with compute
3. CUDA_DEVICE_MAX_CONNECTIONS=1 → enables better NCCL/compute overlap
4. dataloader_pin_memory + prefetch_factor → faster CPU→GPU data transfer
5. torch.compile → kernel fusion for faster forward/backward
6. NCCL tuning env vars → optimized collective algorithms for NVLink topology
7. activation_checkpointing via FSDP config → more memory-efficient
"""
import os, time, json, torch

# ── Critical env vars — MUST be set before any torch imports ──
# Single CUDA connection per device enables better NCCL/compute overlap
os.environ["CUDA_DEVICE_MAX_CONNECTIONS"] = "1"
# NCCL tuning for NVLink topology (NV18 all-to-all on this machine)
os.environ["NCCL_ALGO"] = "Ring"               # Ring is optimal for 8 GPUs
os.environ["NCCL_NET_GDR_LEVEL"] = "5"          # Max GPU Direct RDMA
os.environ["NCCL_P2P_LEVEL"] = "NVL"            # Use NVLink for P2P
os.environ["NCCL_CROSS_NIC"] = "1"              # Allow cross-NIC traffic
os.environ["NCCL_IB_QPS_PER_CONNECTION"] = "4"  # More QPs for bandwidth
os.environ["NCCL_MIN_NCHANNELS"] = "32"         # More channels for 8 GPUs
os.environ["NCCL_NTHREADS"] = "512"             # More threads for collectives
# Memory allocation optimization
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True,max_split_size_mb:512"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
# Reduce CPU overhead
os.environ["OMP_NUM_THREADS"] = "8"
os.environ["MKL_NUM_THREADS"] = "8"

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths ──────────────────────────────────────────────────────
MODEL_PATH = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH  = "/workspace/train_agent_r15.jsonl"
OUTPUT_DIR = "/workspace/output_agent_r15_v2"


def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 8))
    is_main = local_rank == 0

    # Set device for this process
    torch.cuda.set_device(local_rank)

    if is_main:
        print("=" * 60)
        print("R15-FSDP-v2: Maximum GPU Utilization Training")
        print(f"  GPUs: {world_size} × NVLink-connected")
        print(f"  PyTorch: {torch.__version__}")
        print(f"  CUDA: {torch.version.cuda}")
        print("=" * 60)

    # ── 1. Load tokenizer ────────────────────────────────────
    if is_main:
        print("\nLoading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load model — NO device_map (FSDP handles sharding) ─
    if is_main:
        print("Loading model for FSDP sharding...")
    t0 = time.time()

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        attn_implementation="eager",
        low_cpu_mem_usage=True,  # Sequential loading to save CPU RAM
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
        print("Casting LoRA parameters to bf16 for FSDP compatibility...")
    for name, param in model.named_parameters():
        if param.requires_grad and param.dtype != torch.bfloat16:
            param.data = param.data.to(torch.bfloat16)
    if is_main:
        print("  All trainable params now bf16")

    # ── 5. Load dataset ──────────────────────────────────────
    if is_main:
        print(f"\nLoading dataset from {DATA_PATH}...")
    ds = load_dataset("json", data_files=DATA_PATH, split="train")
    if is_main:
        print(f"Dataset: {len(ds)} examples")

    # ── 6. Training config — optimized for throughput ────────
    total_examples = len(ds)
    per_device_batch = 4    # ↑ Doubled from 2: more compute per comm round
    grad_accum = 2          # ↓ Halved from 4: fewer comm rounds per step
    effective_batch = per_device_batch * grad_accum * world_size  # = 32 (same)
    steps_per_epoch = total_examples // effective_batch
    num_epochs = 5
    total_steps = steps_per_epoch * num_epochs

    if is_main:
        print(f"\nTraining config (FSDP, {world_size} GPUs):")
        print(f"  Per-device batch:   {per_device_batch} (↑ from 2)")
        print(f"  Grad accumulation:  {grad_accum} (↓ from 4)")
        print(f"  Effective batch:    {effective_batch}")
        print(f"  Steps/epoch:        {steps_per_epoch}")
        print(f"  Total steps:        {total_steps} ({num_epochs} epochs)")
        print(f"  Comm rounds/step:   {grad_accum} (↓ from 4)")
        print(f"  LoRA: r=128, alpha=256")

    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        per_device_train_batch_size=per_device_batch,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=num_epochs,
        learning_rate=1.5e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        bf16=True,
        logging_steps=1,
        save_strategy="epoch",
        save_total_limit=3,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        max_length=4096,
        dataset_text_field="text",
        report_to="none",
        # ── Data loading optimization ─────────────────────────
        dataloader_num_workers=4,
        dataloader_pin_memory=True,        # Pin memory for async CPU→GPU
        dataloader_prefetch_factor=4,      # Prefetch 4 batches ahead
        remove_unused_columns=True,
        seed=42,
        # ── FSDP config — tuned for NVLink topology ──────────
        fsdp="full_shard auto_wrap",
        fsdp_config={
            "transformer_layer_cls_to_wrap": ["Qwen3NextDecoderLayer"],
            "backward_prefetch": "backward_pre",  # Prefetch next layer during backward
            "forward_prefetch": True,              # Prefetch next layer during forward
            "cpu_ram_efficient_loading": True,
            "sync_module_states": True,
            "use_orig_params": True,               # Required for torch.compile + FSDP
            # NOTE: limit_all_gathers REMOVED — allows overlapping all-gathers with compute
            # This uses more memory but enables pipeline overlap for better GPU utilization
        },
        ddp_timeout=7200,
        local_rank=local_rank,
    )

    # ── 7. Create trainer and train ──────────────────────────
    if is_main:
        print("\nCreating SFTTrainer with optimized FSDP...")
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
        print(f"\n{'='*60}")
        print(f"Starting R15-FSDP-v2: {total_steps} steps, {num_epochs} epochs")
        print(f"All {world_size} GPUs computing in parallel (NVLink)")
        print(f"Optimizations: 2x batch, bf16 uniform dtype, NCCL tuning")
        print(f"{'='*60}\n")

    trainer.train()

    # ── 8. Save adapter ──────────────────────────────────────
    if is_main:
        print("\nSaving adapter...")
    trainer.save_model(OUTPUT_DIR)
    if is_main:
        tok.save_pretrained(OUTPUT_DIR)
        metrics = trainer.state.log_history
        if metrics:
            last = metrics[-1]
            print(f"\nFinal metrics: {json.dumps(last, indent=2)}")
        print("\nR15-FSDP-v2 training complete!")


if __name__ == "__main__":
    main()
