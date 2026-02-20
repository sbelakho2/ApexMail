#!/usr/bin/env python3
"""
R14 Fast Training - DeepSpeed ZeRO-3 + LoRA for 4x B200
Let SFTTrainer handle model loading + DeepSpeed + LoRA natively.

Launch:
  deepspeed --num_gpus 4 train_r14_fast.py
"""

import os
import json
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

DS_CONFIG = {
    "bf16": {"enabled": True},
    "zero_optimization": {
        "stage": 3,
        "overlap_comm": True,
        "contiguous_gradients": True,
        "reduce_bucket_size": 5e8,
        "stage3_prefetch_bucket_size": 5e8,
        "stage3_param_persistence_threshold": 1e6,
        "stage3_max_live_parameters": 3e9,
        "stage3_max_reuse_distance": 3e9,
        "stage3_gather_16bit_weights_on_model_save": True,
        "sub_group_size": 1e9,
    },
    "gradient_clipping": 1.0,
    "train_micro_batch_size_per_gpu": "auto",
    "gradient_accumulation_steps": "auto",
    "train_batch_size": "auto",
    "steps_per_print": 1,
}


def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    is_main = local_rank == 0
    n_gpus = torch.cuda.device_count()

    if is_main:
        log.info("=" * 60)
        log.info("R14: DeepSpeed ZeRO-3 + LoRA (Trainer-managed loading)")
        log.info("=" * 60)
        for i in range(n_gpus):
            mem = torch.cuda.get_device_properties(i).total_memory / 1e9
            log.info(f"  GPU {i}: {torch.cuda.get_device_name(i)} ({mem:.1f} GB)")

    ds_config_path = "/workspace/ds_config_auto.json"
    if is_main:
        with open(ds_config_path, "w") as f:
            json.dump(DS_CONFIG, f, indent=2)
    time.sleep(2)

    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    if is_main:
        log.info(f"Tokenizer: vocab={tokenizer.vocab_size}")

    from peft import LoraConfig
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

    from datasets import load_dataset
    dataset = load_dataset("json", data_files=DATA_PATH, split="train")
    if is_main:
        log.info(f"Dataset: {len(dataset)} examples")

    from trl import SFTTrainer, SFTConfig

    model_kwargs = {
        "torch_dtype": torch.bfloat16,
        "trust_remote_code": True,
        "use_cache": False,
        "low_cpu_mem_usage": True,
    }

    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        deepspeed=ds_config_path,
        model_init_kwargs=model_kwargs,
        bf16=True,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
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
        gradient_checkpointing_kwargs={"use_reentrant": True},
        dataloader_num_workers=4,
        dataloader_pin_memory=True,
        report_to="none",
        seed=42,
        remove_unused_columns=False,
    )

    if is_main:
        log.info("Creating SFTTrainer (handles model + LoRA + DeepSpeed)...")
    t0 = time.time()

    trainer = SFTTrainer(
        model=MODEL_PATH,
        args=training_args,
        train_dataset=dataset,
        peft_config=lora_config,
        processing_class=tokenizer,
    )

    if is_main:
        log.info(f"Trainer created in {time.time()-t0:.1f}s")
        eff_batch = 2 * n_gpus * 4
        log.info(f"Effective batch: {eff_batch}, Steps/epoch: {len(dataset)//eff_batch}")
        log.info("Starting training...")

    result = trainer.train()

    if is_main:
        log.info("Saving...")
    trainer.save_model(OUTPUT_DIR)
    if is_main:
        tokenizer.save_pretrained(OUTPUT_DIR)
        log.info(f"DONE! Loss: {result.training_loss:.4f} -> {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
