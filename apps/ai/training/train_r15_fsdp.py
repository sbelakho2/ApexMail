#!/usr/bin/env python3
"""
R15-FSDP: Qwen3-Next-80B-A3B-Instruct — FSDP Training (all 4 GPUs active)
Uses FSDP (Fully Sharded Data Parallel) so ALL 4 GPUs compute simultaneously.
Each GPU processes different data while model params are sharded across GPUs.
"""
import os, time, json, torch

# ── FSDP must NOT use device_map ──────────────────────────────
# FSDP handles distribution; device_map conflicts with it
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths ──────────────────────────────────────────────────────
MODEL_PATH = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH  = "/workspace/train_agent_r15.jsonl"
OUTPUT_DIR = "/workspace/output_agent_r15"

def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    is_main = local_rank == 0

    if is_main:
        print("=" * 60)
        print("R15-FSDP: 4-GPU Fully Sharded Data Parallel Training")
        print("=" * 60)

    # ── 1. Load tokenizer ────────────────────────────────────
    if is_main:
        print("\nLoading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load model — NO device_map (FSDP handles sharding) ─
    if is_main:
        print("Loading model (FSDP will shard across GPUs)...")
    t0 = time.time()

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        attn_implementation="eager",
        # NO device_map — FSDP handles distribution
        # low_cpu_mem_usage=True loads sequentially to save RAM
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

    # ── 4. Load dataset ──────────────────────────────────────
    if is_main:
        print(f"\nLoading dataset from {DATA_PATH}...")
    ds = load_dataset("json", data_files=DATA_PATH, split="train")
    if is_main:
        print(f"Dataset: {len(ds)} examples")

    # ── 5. Training config with FSDP ─────────────────────────
    total_examples = len(ds)
    per_device_batch = 2
    grad_accum = 4
    num_gpus = int(os.environ.get("WORLD_SIZE", 4))
    effective_batch = per_device_batch * grad_accum * num_gpus
    steps_per_epoch = total_examples // effective_batch
    num_epochs = 5
    total_steps = steps_per_epoch * num_epochs

    if is_main:
        print(f"\nTraining config (FSDP, {num_gpus} GPUs):")
        print(f"  Per-device batch: {per_device_batch}")
        print(f"  Grad accumulation: {grad_accum}")
        print(f"  Effective batch: {effective_batch}")
        print(f"  Steps/epoch: {steps_per_epoch}")
        print(f"  Total steps: {total_steps} ({num_epochs} epochs)")

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
        dataloader_num_workers=4,
        remove_unused_columns=True,
        seed=42,
        # ── FSDP config (built-in to Trainer) ────────────────
        fsdp="full_shard auto_wrap",
        fsdp_config={
            "transformer_layer_cls_to_wrap": ["Qwen3NextDecoderLayer"],
            "backward_prefetch": "backward_pre",
            "forward_prefetch": True,
            "cpu_ram_efficient_loading": True,
            "sync_module_states": True,
            "use_orig_params": True,
            "limit_all_gathers": True,
        },
        # DDP settings for FSDP
        ddp_timeout=7200,
        local_rank=local_rank,
    )

    # ── 6. Create trainer ────────────────────────────────────
    if is_main:
        print("\nCreating SFTTrainer with FSDP...")
    t3 = time.time()
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=ds,
        processing_class=tok,
    )
    if is_main:
        print(f"Trainer created in {time.time()-t3:.1f}s")

    # ── 7. Train ─────────────────────────────────────────────
    if is_main:
        print(f"\n{'='*60}")
        print(f"Starting R15-FSDP: {total_steps} steps, {num_epochs} epochs")
        print(f"All {num_gpus} GPUs computing in parallel!")
        print(f"{'='*60}\n")

    trainer.train()

    # ── 8. Save ──────────────────────────────────────────────
    if is_main:
        print("\nSaving adapter...")
    trainer.save_model(OUTPUT_DIR)
    if is_main:
        tok.save_pretrained(OUTPUT_DIR)
        metrics = trainer.state.log_history
        if metrics:
            last = metrics[-1]
            print(f"\nFinal metrics: {json.dumps(last, indent=2)}")
        print("\nR15-FSDP training complete!")

if __name__ == "__main__":
    main()
