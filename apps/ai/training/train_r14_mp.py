#!/usr/bin/env python3
"""
R14 Model-Parallel Training - device_map="auto" + LoRA for 4x B200
No DeepSpeed. Single process. Model sharded across GPUs by layers.

Launch:
  python3 train_r14_mp.py
"""

import os
import time
import torch
import logging

os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "expandable_segments:True"
torch.backends.cuda.matmul.allow_tf32 = True
torch.backends.cudnn.allow_tf32 = True

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

MODEL_PATH = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH  = "/workspace/train_agent.jsonl"
OUTPUT_DIR = "/workspace/output_agent"


def main():
    n_gpus = torch.cuda.device_count()
    log.info("=" * 60)
    log.info(f"R14: Model-Parallel + LoRA ({n_gpus}x GPU)")
    log.info("=" * 60)
    for i in range(n_gpus):
        mem = torch.cuda.get_device_properties(i).total_memory / 1e9
        log.info(f"  GPU {i}: {torch.cuda.get_device_name(i)} ({mem:.1f} GB)")

    # 1. Load tokenizer
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    log.info(f"Tokenizer: vocab={tokenizer.vocab_size}")

    # 2. Load model with auto device_map -> pipeline parallel across GPUs
    from transformers import AutoModelForCausalLM
    log.info("Loading model with device_map='auto'...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True,
        use_cache=False,
        low_cpu_mem_usage=True,
    )
    load_time = time.time() - t0
    log.info(f"Model loaded in {load_time:.1f}s")

    # Show device distribution
    device_counts = {}
    for name, param in model.named_parameters():
        dev = str(param.device)
        device_counts[dev] = device_counts.get(dev, 0) + 1
    for dev, cnt in sorted(device_counts.items()):
        log.info(f"  {dev}: {cnt} params")

    # 3. Enable gradient checkpointing
    model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})

    # 4. Apply LoRA
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
    lora_config = LoraConfig(
        r=64,
        lora_alpha=128,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "in_proj_qkvz", "in_proj_ba", "out_proj",
            "shared_expert.gate_proj",
            "shared_expert.up_proj",
            "shared_expert.down_proj",
        ],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )

    log.info("Applying LoRA...")
    t0 = time.time()
    model = get_peft_model(model, lora_config)
    log.info(f"LoRA applied in {time.time()-t0:.1f}s")
    model.print_trainable_parameters()

    # 5. Load dataset
    from datasets import load_dataset
    dataset = load_dataset("json", data_files=DATA_PATH, split="train")
    log.info(f"Dataset: {len(dataset)} examples")

    # 6. Training config (no deepspeed, single process)
    from trl import SFTTrainer, SFTConfig

    # With device_map="auto", per_device_batch is for the single process
    # Effective batch = per_device * grad_accum = 4 * 8 = 32
    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        bf16=True,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=8,
        num_train_epochs=3,
        learning_rate=1.5e-4,
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        weight_decay=0.01,
        logging_steps=1,
        save_strategy="epoch",
        save_total_limit=2,
        max_length=4096,
        dataset_text_field="text",
        packing=False,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        report_to="none",
        seed=42,
        remove_unused_columns=False,
        ddp_find_unused_parameters=False,
    )

    log.info("Creating SFTTrainer...")
    t0 = time.time()
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer,
    )
    log.info(f"Trainer created in {time.time()-t0:.1f}s")

    eff_batch = 4 * 8  # per_device * grad_accum (single process)
    steps_per_epoch = len(dataset) // eff_batch
    total_steps = steps_per_epoch * 3
    log.info(f"Effective batch: {eff_batch}, Steps/epoch: {steps_per_epoch}, Total: {total_steps}")
    log.info("Starting training...")

    result = trainer.train()

    log.info("Saving adapter...")
    trainer.save_model(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    log.info(f"DONE! Loss: {result.training_loss:.4f} -> {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
