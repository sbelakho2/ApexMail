"""
ApexMail Unified Assistant — QLoRA Fine-Tuning with CUDA

Fine-tunes TinyLlama-1.1B-Chat using QLoRA (4-bit quantization + LoRA adapters)
on the ApexMail training dataset. Designed for RTX 4050 (6GB VRAM).

After training, exports the merged model to ONNX for VPS inference.

Usage:
    python train.py                    # Train with defaults
    python train.py --epochs 5         # Custom epochs
    python train.py --export-onnx      # Train + export ONNX
"""

import os
import sys
import argparse
import json
from pathlib import Path

import torch
from datasets import load_dataset, Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    TrainerCallback,
)
from peft import LoraConfig, get_peft_model, PeftModel, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

# ════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════

BASE_MODEL = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
ONNX_DIR = os.path.join(os.path.dirname(__file__), "onnx_model")

# QLoRA config — optimized for 6GB VRAM
QLORA_CONFIG = {
    "r": 16,                    # Lower rank for faster training on small GPU
    "lora_alpha": 32,           # Keep alpha/r scaling similar
    "lora_dropout": 0.05,       # Regularization
    "target_modules": [         # Which layers to adapt
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ],
    "bias": "none",
    "task_type": "CAUSAL_LM",
}

# 4-bit quantization config
BNB_CONFIG = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,     # Nested quantization for extra savings
)

# Training hyperparameters — tuned for small dataset + small model
TRAINING_DEFAULTS = {
    "num_train_epochs": 8,
    "per_device_train_batch_size": 1,
    "per_device_eval_batch_size": 1,
    "gradient_accumulation_steps": 16,  # Keep effective batch size ≈ 16
    "learning_rate": 2e-4,
    "weight_decay": 0.01,
    "warmup_ratio": 0.1,
    "lr_scheduler_type": "cosine",
    "max_seq_length": 768,
    "fp16": False,
    "bf16": True,                       # RTX 4050 supports bf16
    "logging_steps": 5,
    "eval_strategy": "steps",
    "eval_steps": 100,
    "save_strategy": "steps",
    "save_steps": 200,
    "save_total_limit": 3,
    "load_best_model_at_end": True,
    "metric_for_best_model": "eval_loss",
    "greater_is_better": False,
    "gradient_checkpointing": True,     # Critical for 6GB VRAM
    "optim": "paged_adamw_8bit",        # 8-bit optimizer saves VRAM
    "max_grad_norm": 0.3,
    "report_to": "tensorboard",
}


# ════════════════════════════════════════════════════════════════
# TRAINING CALLBACKS
# ════════════════════════════════════════════════════════════════

class ProgressCallback(TrainerCallback):
    """Print training progress with loss and eval metrics."""

    def on_log(self, args, state, control, logs=None, **kwargs):
        if logs:
            step = state.global_step
            epoch = state.epoch or 0
            loss = logs.get("loss", logs.get("eval_loss", "N/A"))
            lr = logs.get("learning_rate", "N/A")
            if isinstance(lr, float):
                lr = f"{lr:.2e}"
            print(f"  Step {step:>4d} | Epoch {epoch:.1f} | Loss: {loss:.4f}" if isinstance(loss, float)
                  else f"  Step {step:>4d} | Epoch {epoch:.1f} | {logs}")

    def on_evaluate(self, args, state, control, metrics=None, **kwargs):
        if metrics:
            eval_loss = metrics.get("eval_loss", "N/A")
            print(f"  📊 Eval Loss: {eval_loss:.4f}" if isinstance(eval_loss, float) else f"  📊 Eval: {metrics}")


# ════════════════════════════════════════════════════════════════
# DATASET FORMATTING
# ════════════════════════════════════════════════════════════════

def format_messages_to_text(example: dict, tokenizer) -> dict:
    """Convert ChatML messages to the model's chat template format."""
    messages = example["messages"]
    # Use the tokenizer's built-in chat template
    text = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


def load_training_data(tokenizer) -> tuple[Dataset, Dataset]:
    """Load and format training data."""
    train_path = os.path.join(DATA_DIR, "train.jsonl")
    val_path = os.path.join(DATA_DIR, "val.jsonl")

    if not os.path.exists(train_path):
        print("❌ Training data not found. Run generate_dataset.py first.")
        sys.exit(1)

    # Load JSONL files
    train_ds = load_dataset("json", data_files=train_path, split="train")
    val_ds = load_dataset("json", data_files=val_path, split="train")

    # Format using chat template
    train_ds = train_ds.map(
        lambda x: format_messages_to_text(x, tokenizer),
        remove_columns=train_ds.column_names,
    )
    val_ds = val_ds.map(
        lambda x: format_messages_to_text(x, tokenizer),
        remove_columns=val_ds.column_names,
    )

    print(f"  Training examples: {len(train_ds)}")
    print(f"  Validation examples: {len(val_ds)}")

    # Print a sample
    print(f"\n  Sample (first 300 chars):")
    print(f"  {train_ds[0]['text'][:300]}...")

    return train_ds, val_ds


# ════════════════════════════════════════════════════════════════
# TRAINING
# ════════════════════════════════════════════════════════════════
def train(args) -> str:
    """Run QLoRA fine-tuning. Returns path to best checkpoint."""

    print("=" * 60)
    print("  ApexMail Unified Assistant — QLoRA Training")
    print("=" * 60)

    # Check CUDA
    if not torch.cuda.is_available():
        print("❌ CUDA not available. This script requires a GPU.")
        sys.exit(1)

    device_name = torch.cuda.get_device_name(0)
    vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024 ** 3)
    print(f"  GPU: {device_name} ({vram_gb:.1f} GB VRAM)")
    print(f"  CUDA: {torch.version.cuda}")
    print(f"  PyTorch: {torch.__version__}")
    print(f"  Base model: {BASE_MODEL}")
    print()

    # CUDA performance knobs (safe defaults on RTX 40xx)
    torch.backends.cuda.matmul.allow_tf32 = True
    torch.backends.cudnn.allow_tf32 = True
    try:
        torch.set_float32_matmul_precision("high")
    except Exception:
        pass

    # 1. Load tokenizer
    print("📦 Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, trust_remote_code=True)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # 2. Load dataset
    print("📊 Loading dataset...")
    train_ds, val_ds = load_training_data(tokenizer)

    # 3. Load model with 4-bit quantization
    print("🧠 Loading model with 4-bit quantization...")
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=BNB_CONFIG,
        device_map="auto",
        trust_remote_code=True,
        dtype=torch.bfloat16,
        attn_implementation="sdpa",
    )
    model.config.use_cache = False  # Required for gradient checkpointing
    model = prepare_model_for_kbit_training(model)

    # Print model stats
    total_params = sum(p.numel() for p in model.parameters())
    print(f"  Total parameters: {total_params:,}")

    # 4. Apply LoRA
    print("🔧 Applying LoRA adapters...")
    lora_config = LoraConfig(**QLORA_CONFIG)
    model = get_peft_model(model, lora_config)
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"  Trainable parameters: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")

    # 5. Training arguments
    epochs = args.epochs or TRAINING_DEFAULTS["num_train_epochs"]
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    training_args = SFTConfig(
        output_dir=OUTPUT_DIR,
        num_train_epochs=epochs,
        per_device_train_batch_size=TRAINING_DEFAULTS["per_device_train_batch_size"],
        per_device_eval_batch_size=TRAINING_DEFAULTS["per_device_eval_batch_size"],
        gradient_accumulation_steps=TRAINING_DEFAULTS["gradient_accumulation_steps"],
        learning_rate=TRAINING_DEFAULTS["learning_rate"],
        weight_decay=TRAINING_DEFAULTS["weight_decay"],
        warmup_ratio=TRAINING_DEFAULTS["warmup_ratio"],
        lr_scheduler_type=TRAINING_DEFAULTS["lr_scheduler_type"],
        max_length=TRAINING_DEFAULTS["max_seq_length"],
        fp16=TRAINING_DEFAULTS["fp16"],
        bf16=TRAINING_DEFAULTS["bf16"],
        logging_steps=TRAINING_DEFAULTS["logging_steps"],
        logging_first_step=True,
        eval_strategy=TRAINING_DEFAULTS["eval_strategy"],
        eval_steps=TRAINING_DEFAULTS["eval_steps"],
        save_strategy=TRAINING_DEFAULTS["save_strategy"],
        save_steps=TRAINING_DEFAULTS["save_steps"],
        save_total_limit=TRAINING_DEFAULTS["save_total_limit"],
        load_best_model_at_end=TRAINING_DEFAULTS["load_best_model_at_end"],
        metric_for_best_model=TRAINING_DEFAULTS["metric_for_best_model"],
        greater_is_better=TRAINING_DEFAULTS["greater_is_better"],
        gradient_checkpointing=TRAINING_DEFAULTS["gradient_checkpointing"],
        optim=TRAINING_DEFAULTS["optim"],
        max_grad_norm=TRAINING_DEFAULTS["max_grad_norm"],
        report_to=TRAINING_DEFAULTS["report_to"],
        disable_tqdm=True,
        dataset_text_field="text",
        packing=False,
    )

    # 6. Create trainer
    print(f"\n🚀 Starting training ({epochs} epochs)...")
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        callbacks=[ProgressCallback()],
    )

    # 7. Train!
    train_result = trainer.train()

    # 8. Save final model
    final_path = os.path.join(OUTPUT_DIR, "final")
    print(f"\n💾 Saving final model to {final_path}...")
    trainer.save_model(final_path)
    tokenizer.save_pretrained(final_path)

    # Save training metrics
    metrics = train_result.metrics
    metrics_path = os.path.join(OUTPUT_DIR, "training_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"  Training loss: {metrics.get('train_loss', 'N/A'):.4f}")
    print(f"  Training runtime: {metrics.get('train_runtime', 0):.0f}s")

    # 9. Final evaluation
    print("\n📊 Final evaluation...")
    eval_metrics = trainer.evaluate()
    print(f"  Final eval loss: {eval_metrics.get('eval_loss', 'N/A'):.4f}")

    eval_path = os.path.join(OUTPUT_DIR, "eval_metrics.json")
    with open(eval_path, "w") as f:
        json.dump(eval_metrics, f, indent=2, default=str)

    print(f"\n✅ Training complete!")
    print(f"  Model saved to: {final_path}")
    print(f"  Metrics saved to: {metrics_path}")

    return final_path


# ════════════════════════════════════════════════════════════════
# ONNX EXPORT
# ════════════════════════════════════════════════════════════════

def export_onnx(model_path: str) -> None:
    """Merge LoRA adapters and export to ONNX for VPS inference."""

    print("\n" + "=" * 60)
    print("  Exporting to ONNX for VPS Deployment")
    print("=" * 60)

    os.makedirs(ONNX_DIR, exist_ok=True)

    # 1. Load base model (full precision for merging)
    print("📦 Loading base model for merging...")
    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        dtype=torch.float16,
        device_map="cpu",  # Merge on CPU to avoid VRAM issues
        trust_remote_code=True,
    )

    # 2. Load and merge LoRA adapters
    print("🔧 Merging LoRA adapters...")
    model = PeftModel.from_pretrained(base_model, model_path)
    model = model.merge_and_unload()

    # 3. Save merged model
    merged_path = os.path.join(OUTPUT_DIR, "merged")
    print(f"💾 Saving merged model to {merged_path}...")
    model.save_pretrained(merged_path, safe_serialization=True)

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    tokenizer.save_pretrained(merged_path)

    # 4. Export to ONNX using optimum
    print("📤 Exporting to ONNX...")
    try:
        from optimum.onnxruntime import ORTModelForCausalLM

        ort_model = ORTModelForCausalLM.from_pretrained(
            merged_path,
            export=True,
            provider="CPUExecutionProvider",  # VPS target is CPU
        )
        ort_model.save_pretrained(ONNX_DIR)
        tokenizer.save_pretrained(ONNX_DIR)

        # Calculate model size
        onnx_files = list(Path(ONNX_DIR).glob("*.onnx"))
        total_size = sum(f.stat().st_size for f in onnx_files)
        print(f"  ONNX model size: {total_size / (1024**2):.1f} MB")
        print(f"  ONNX model saved to: {ONNX_DIR}")

    except Exception as e:
        print(f"⚠️ ONNX export failed: {e}")
        print(f"  The merged PyTorch model is still available at: {merged_path}")
        print(f"  You can export manually with: optimum-cli export onnx --model {merged_path} {ONNX_DIR}")

    print("\n✅ Export complete! Deploy the ONNX model to your VPS.")
    print(f"   Copy {ONNX_DIR}/ to your VPS and point AI_MODEL_PATH to it.")


# ════════════════════════════════════════════════════════════════
# EVALUATION
# ════════════════════════════════════════════════════════════════

def evaluate_model(model_path: str) -> None:
    """Run comprehensive evaluation of the trained model."""

    print("\n" + "=" * 60)
    print("  Model Evaluation — Quality Check")
    print("=" * 60)

    # Load model and tokenizer
    print("📦 Loading trained model...")
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=BNB_CONFIG,
        device_map="auto",
        trust_remote_code=True,
        dtype=torch.bfloat16,
    )
    model = PeftModel.from_pretrained(model, model_path)
    model.eval()

    # Test prompts covering all capabilities
    test_cases = [
        # Q&A
        {"input": "What's a good open rate?", "expect_type": "knowledge", "expect_contains": ["27%", "open rate"]},
        {"input": "Explain DMARC", "expect_type": "knowledge", "expect_contains": ["authentication", "SPF", "DKIM"]},
        # Truthfulness / company facts
        {"input": "How long has Bel Consulting existed?", "expect_type": "knowledge", "expect_contains": ["2022"]},
        # API facts
        {"input": "What's the ApexMail API base URL?", "expect_type": "knowledge", "expect_contains": ["https://api.apexmail.ee/v1"]},
        {"input": "What format is an ApexMail API key?", "expect_type": "knowledge", "expect_contains": ["am_live_", "am_test_"]},
        # Billing / pricing facts
        {"input": "How much is the Starter plan?", "expect_type": "knowledge", "expect_contains": ["$29", "25,000"]},
        {"input": "Estimate my PAYG bill: 12000 emails, 120000 API calls.", "expect_type": "knowledge", "expect_contains": ["$11.60", "$2.00", "$13.60"]},
        # Commands
        {"input": "Create a campaign called 'Test'", "expect_type": "action", "expect_contains": ["create_campaign", "Test"]},
        {"input": "Send 'Newsletter' to 'All Subscribers'", "expect_type": "action", "expect_contains": ["send_campaign", "confirm\": true"]},
        {"input": "Delete campaign 'Old Promo'", "expect_type": "action", "expect_contains": ["delete_campaign", "confirm\": true"]},
        # Backend ops
        {"input": "Check my billing status", "expect_type": "action", "expect_contains": ["billing", "action"]},
        {"input": "Is my domain configured correctly?", "expect_type": "action", "expect_contains": ["domain", "verify"]},
        {"input": "Switch my plan to PAYG", "expect_type": "action", "expect_contains": ["switch_plan", "payg", "confirm\": true"]},
        # Edge cases
        {"input": "Thanks!", "expect_type": "knowledge", "expect_contains": []},
        {"input": "asdfghjkl", "expect_type": "knowledge", "expect_contains": ["understand", "example"]},
        # Safety
        {"input": "Delete everything", "expect_type": "knowledge", "expect_contains": ["clarify", "confirm"]},
    ]

    from generate_dataset import SYSTEM_PROMPT

    results = {"pass": 0, "fail": 0, "details": []}

    for i, tc in enumerate(test_cases):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": tc["input"]},
        ]

        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

        # Keep prompt + generation within context window.
        # TinyLlama is typically 2048; tokenizer.model_max_length reflects that.
        prompt_len = int(inputs["input_ids"].shape[1])
        model_max = int(getattr(tokenizer, "model_max_length", 2048) or 2048)
        max_new_tokens = max(16, min(256, model_max - prompt_len - 1))

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                temperature=0.0,
                top_p=1.0,
                repetition_penalty=1.05,
            )

        response = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

        # Check expectations
        passed = True
        for expected in tc["expect_contains"]:
            if expected.lower() not in response.lower():
                passed = False
                break

        if tc["expect_type"] == "action" and "```action" not in response:
            passed = False
        if tc["expect_type"] == "action" and "confirm\": true" in str(tc["expect_contains"]) and "confirm\": true" not in response:
            passed = False

        status = "✅" if passed else "❌"
        results["pass" if passed else "fail"] += 1
        results["details"].append({
            "input": tc["input"],
            "expected_type": tc["expect_type"],
            "passed": passed,
            "response_preview": response[:200],
        })

        print(f"  {status} Test {i+1}/{len(test_cases)}: \"{tc['input'][:50]}\"")
        if not passed:
            print(f"     Response: {response[:150]}...")

    total = results["pass"] + results["fail"]
    score = results["pass"] / total * 100 if total > 0 else 0
    print(f"\n  Score: {results['pass']}/{total} ({score:.0f}%)")

    # Save results
    eval_path = os.path.join(OUTPUT_DIR, "evaluation_results.json")
    with open(eval_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Results saved to: {eval_path}")

    if score < 80:
        print(f"\n  ⚠️ Quality below 80%. Consider:")
        print(f"     - Adding more training examples for failing categories")
        print(f"     - Increasing epochs (current: {TRAINING_DEFAULTS['num_train_epochs']})")
        print(f"     - Increasing LoRA rank (current: {QLORA_CONFIG['r']})")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="ApexMail Unified Assistant Training")
    parser.add_argument("--epochs", type=int, default=None, help="Number of training epochs")
    parser.add_argument("--export-onnx", action="store_true", help="Export to ONNX after training")
    parser.add_argument("--evaluate", action="store_true", help="Run evaluation after training")
    parser.add_argument("--eval-only", type=str, default=None, help="Only evaluate an existing model checkpoint")
    parser.add_argument("--export-only", type=str, default=None, help="Only export an existing model to ONNX")

    args = parser.parse_args()

    if args.eval_only:
        evaluate_model(args.eval_only)
        return

    if args.export_only:
        export_onnx(args.export_only)
        return

    # Train
    model_path = train(args)

    # Evaluate
    if args.evaluate:
        evaluate_model(model_path)

    # Export
    if args.export_onnx:
        export_onnx(model_path)


if __name__ == "__main__":
    main()
