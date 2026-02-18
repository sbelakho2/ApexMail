#!/usr/bin/env bash
# ============================================================
# ApexMail Agent Training — Remote Launch Script (v2)
#
# Usage:
#   bash train_agent.sh          # Full 4-GPU DDP training
#   bash train_agent.sh --test   # Run test suite after training
#
# Prerequisites (already on remote):
#   - /workspace/models/Qwen3-8B
#   - /workspace/train/data/train_agent.jsonl
#   - /workspace/train/prompts_v2.py
#   - /workspace/train/test_agent.py
#   - /workspace/train/run_test_agent.py
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

MODEL_PATH="/workspace/models/Qwen3-8B"
DATA_PATH="data/train_agent.jsonl"
OUTPUT_DIR="output_agent"
NUM_GPUS=4
EPOCHS=3
BATCH_PER_GPU=7
MAX_SEQ_LEN=4096

echo "========================================="
echo "  ApexMail Agent Training v2"
echo "========================================="
echo "Model:    $MODEL_PATH"
echo "Data:     $DATA_PATH"
echo "Output:   $OUTPUT_DIR"
echo "GPUs:     $NUM_GPUS"
echo "Epochs:   $EPOCHS"
echo "Batch:    $BATCH_PER_GPU per GPU"
echo "Seq len:  $MAX_SEQ_LEN"
echo "========================================="

# Validate
if [ ! -f "$DATA_PATH" ]; then
    echo "ERROR: Training data not found at $DATA_PATH"
    echo "Run 'python build_agent.py' first."
    exit 1
fi

SAMPLE_COUNT=$(wc -l < "$DATA_PATH")
echo "Training samples: $SAMPLE_COUNT"
echo ""

# Clean previous output
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# ── Training script ──────────────────────────────────────────
cat > train_agent_inner.py << 'TRAIN_SCRIPT'
import os
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

def main():
    model_path = os.environ.get("MODEL_PATH", "/workspace/models/Qwen3-8B")
    data_path = os.environ.get("DATA_PATH", "data/train_agent.jsonl")
    output_dir = os.environ.get("OUTPUT_DIR", "output_agent")
    epochs = int(os.environ.get("EPOCHS", "3"))
    batch_size = int(os.environ.get("BATCH_PER_GPU", "7"))
    max_seq_len = int(os.environ.get("MAX_SEQ_LEN", "4096"))

    local_rank = int(os.environ.get("LOCAL_RANK", 0))

    # ── Tokenizer ──
    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ── Quantization ──
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    # ── Model ──
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        quantization_config=bnb_config,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        device_map={"": local_rank},
    )
    model = prepare_model_for_kbit_training(model)

    # ── LoRA ──
    lora_config = LoraConfig(
        r=64,
        lora_alpha=128,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)

    if local_rank == 0:
        trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
        total = sum(p.numel() for p in model.parameters())
        print(f"Trainable: {trainable:,} / {total:,} ({100*trainable/total:.2f}%)")

    # ── Dataset ──
    dataset = load_dataset("json", data_files=data_path, split="train")
    if local_rank == 0:
        print(f"Dataset: {len(dataset)} examples")

    # ── Training config ──
    training_args = SFTConfig(
        output_dir=output_dir,
        num_train_epochs=epochs,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=1,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        learning_rate=2e-4,
        lr_scheduler_type="cosine",
        warmup_ratio=0.05,
        bf16=True,
        logging_steps=5,
        save_strategy="epoch",
        save_total_limit=2,
        optim="paged_adamw_8bit",
        max_length=max_seq_len,
        packing=False,
        dataset_text_field="text",
        ddp_find_unused_parameters=False,
        dataloader_num_workers=4,
        report_to="none",
    )

    # ── Trainer ──
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        processing_class=tokenizer,
    )

    if local_rank == 0:
        print("Starting training...")

    trainer.train()

    if local_rank == 0:
        print("Saving final adapter...")
        model.save_pretrained(output_dir)
        tokenizer.save_pretrained(output_dir)
        print(f"Saved to {output_dir}/")

if __name__ == "__main__":
    main()
TRAIN_SCRIPT

# ── Launch DDP training ──
echo "Launching $NUM_GPUS-GPU DDP training..."
echo ""

export MODEL_PATH DATA_PATH OUTPUT_DIR EPOCHS BATCH_PER_GPU MAX_SEQ_LEN

torchrun \
    --nproc_per_node=$NUM_GPUS \
    --master_port=29500 \
    train_agent_inner.py \
    2>&1 | tee "$OUTPUT_DIR/train.log" &

TRAIN_PID=$!

# Monitor progress
echo "Training PID: $TRAIN_PID"
echo "Log: $OUTPUT_DIR/train.log"
echo ""
echo "Monitor with: tail -f $OUTPUT_DIR/train.log"
echo ""
echo "When training shows 100%, if it hangs (DDP barrier issue):"
echo "  pkill -9 -f 'torchrun|train_agent_inner'"
echo "  LATEST=\$(ls -td $OUTPUT_DIR/checkpoint-* | head -1)"
echo "  cp \$LATEST/adapter_* $OUTPUT_DIR/"
echo ""

wait $TRAIN_PID
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "Training process exited with code $EXIT_CODE"
    echo "Checking for completed checkpoint..."
    LATEST=$(ls -td "$OUTPUT_DIR"/checkpoint-* 2>/dev/null | head -1 || true)
    if [ -n "$LATEST" ] && [ -f "$LATEST/adapter_model.safetensors" ]; then
        echo "Found checkpoint at $LATEST, copying adapter files..."
        cp "$LATEST"/adapter_* "$OUTPUT_DIR/" 2>/dev/null || true
        cp "$LATEST"/tokenizer* "$OUTPUT_DIR/" 2>/dev/null || true
        cp "$LATEST"/special_tokens* "$OUTPUT_DIR/" 2>/dev/null || true
        cp "$LATEST"/vocab* "$OUTPUT_DIR/" 2>/dev/null || true
        cp "$LATEST"/merges* "$OUTPUT_DIR/" 2>/dev/null || true
        echo "Adapter files recovered."
    fi
fi

echo ""
echo "========================================="
echo "  Training Complete"
echo "========================================="

# ── Run tests if requested ──
if [[ "${1:-}" == "--test" ]]; then
    echo ""
    echo "Running agent test suite..."
    python run_test_agent.py --adapter "$OUTPUT_DIR" --output "$OUTPUT_DIR/test_results.json"
fi
