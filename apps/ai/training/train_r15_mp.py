#!/usr/bin/env python3
"""
R15: Qwen3-Next-80B-A3B-Instruct — Enhanced LoRA Training
Changes from R14:
- LoRA r=128, alpha=256 (doubled from r=64, alpha=128)
- 5 epochs instead of 3
- Augmented dataset with 85+ new behavioral examples (tool calls, escalation, context, clarification)
- Same device_map="auto" approach that worked in R14
"""
import os, time, json, torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import LoraConfig, get_peft_model
from trl import SFTTrainer, SFTConfig
from datasets import load_dataset

# ── Paths ──────────────────────────────────────────────────────
MODEL_PATH  = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
DATA_PATH   = "/workspace/train_agent_r15.jsonl"
OUTPUT_DIR  = "/workspace/output_agent_r15"

# ── 1. Load tokenizer ────────────────────────────────────────
print("Loading tokenizer...")
tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
if tok.pad_token is None:
    tok.pad_token = tok.eos_token

# ── 2. Load model with device_map="auto" ────────────────────
print("Loading model with device_map='auto'...")
t0 = time.time()
model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    attn_implementation="eager",
)
print(f"Model loaded in {time.time()-t0:.1f}s")

# Show device distribution
from collections import Counter
dev_counts = Counter()
for name, param in model.named_parameters():
    dev_counts[str(param.device)] += 1
print(f"Device distribution: {dict(dev_counts)}")

# ── 3. Apply LoRA with r=128 ─────────────────────────────────
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
model.print_trainable_parameters()
print(f"LoRA applied in {time.time()-t1:.1f}s")

# ── 4. Load and tokenize dataset ────────────────────────────
print(f"Loading dataset from {DATA_PATH}...")
t2 = time.time()
ds = load_dataset("json", data_files=DATA_PATH, split="train")
print(f"Dataset: {len(ds)} examples, loaded in {time.time()-t2:.1f}s")

# ── 5. Training config ──────────────────────────────────────
total_examples = len(ds)
per_device_batch = 4
grad_accum = 8
effective_batch = per_device_batch * grad_accum  # 32
steps_per_epoch = total_examples // effective_batch
num_epochs = 5
total_steps = steps_per_epoch * num_epochs

print(f"\nTraining config:")
print(f"  Examples: {total_examples}")
print(f"  Effective batch: {effective_batch}")
print(f"  Steps/epoch: {steps_per_epoch}")
print(f"  Total steps: {total_steps} ({num_epochs} epochs)")
print(f"  LoRA r=128, alpha=256")

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
)

# ── 6. Create trainer and train ──────────────────────────────
print("\nCreating SFTTrainer...")
t3 = time.time()
trainer = SFTTrainer(
    model=model,
    args=training_args,
    train_dataset=ds,
    processing_class=tok,
)
print(f"Trainer created in {time.time()-t3:.1f}s")

print(f"\n{'='*60}")
print(f"Starting R15 training: {total_steps} steps, {num_epochs} epochs")
print(f"LoRA r=128 alpha=256 | {total_examples} examples")
print(f"{'='*60}\n")

trainer.train()

# ── 7. Save adapter ─────────────────────────────────────────
print("\nSaving adapter...")
trainer.save_model(OUTPUT_DIR)
tok.save_pretrained(OUTPUT_DIR)
print(f"Adapter saved to {OUTPUT_DIR}")

# Print final metrics
metrics = trainer.state.log_history
if metrics:
    last = metrics[-1]
    print(f"\nFinal metrics: {json.dumps(last, indent=2)}")
print("\nR15 training complete!")
