"""MPS LoRA training for Qwen on Apple Silicon."""
import json, os, sys, time, argparse
from pathlib import Path
import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer, Trainer, TrainingArguments, DataCollatorForLanguageModeling

DATA_DIR = "../../../data"
MAX_LEN = 2048

def load_data(files):
    exs = []
    for f in files:
        p = Path(DATA_DIR) / f
        if p.exists():
            with open(p) as fh:
                for line in fh:
                    if line.strip():
                        try: exs.append({"text": json.loads(line)["text"]})
                        except: pass
    return Dataset.from_list(exs)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--model", default="Qwen/Qwen2.5-1.5B-Instruct")
    p.add_argument("--output-dir", default="output_mps")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=2)
    p.add_argument("--grad-accum", type=int, default=4)
    p.add_argument("--learning-rate", type=float, default=2e-4)
    p.add_argument("--lora-rank", type=int, default=32)
    p.add_argument("--lora-alpha", type=int, default=64)
    args = p.parse_args()

    device = "mps" if torch.backends.mps.is_available() else "cpu"
    print(f"Device: {device} | Model: {args.model}")
    
    print("[1/4] Loading tokenizer + model...")
    tok = AutoTokenizer.from_pretrained(args.model, trust_remote_code=True)
    if tok.pad_token is None: tok.pad_token = tok.eos_token
    
    model = AutoModelForCausalLM.from_pretrained(
        args.model, torch_dtype=torch.bfloat16, device_map=device,
        trust_remote_code=True, low_cpu_mem_usage=True)
    model.gradient_checkpointing_enable()
    print(f"      Model: {model.num_parameters()/1e9:.1f}B params")
    
    print(f"[2/4] Applying LoRA (r={args.lora_rank}, alpha={args.lora_alpha})...")
    lora = LoraConfig(r=args.lora_rank, lora_alpha=args.lora_alpha, target_modules=[
        "q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
        lora_dropout=0.05, bias="none", task_type=TaskType.CAUSAL_LM)
    model = get_peft_model(model, lora)
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"      Trainable: {trainable/1e6:.1f}M ({100*trainable/model.num_parameters():.2f}%)")
    
    print("[3/4] Loading data...")
    ds = load_data(["train_agent.jsonl","augmented_pricing_recall.jsonl",
                     "augmented_adversarial___edge_case.jsonl","augmented_multi-turn_conversations.jsonl"])
    print(f"      {len(ds)} examples")
    
    def tokenize(ex):
        return tok(ex["text"], truncation=True, max_length=MAX_LEN, padding=False)
    ds = ds.map(tokenize, remove_columns=["text"])
    
    ta = TrainingArguments(
        output_dir=args.output_dir, num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate, lr_scheduler_type="cosine", warmup_ratio=0.1,
        weight_decay=0.01, bf16=(device=="mps"), logging_steps=10,
        save_strategy="epoch", save_total_limit=2, report_to="none",
        dataloader_num_workers=0, gradient_checkpointing=True,
        optim="adamw_torch", seed=42)
    
    trainer = Trainer(model=model, args=ta, train_dataset=ds,
                      data_collator=DataCollatorForLanguageModeling(tok, mlm=False))
    
    eff = args.batch_size * args.grad_accum
    print(f"[4/4] Training ({args.epochs} epochs, eff_batch={eff})...\n")
    trainer.train()
    
    print(f"\nSaving adapter to {args.output_dir}...")
    model.save_pretrained(args.output_dir)
    tok.save_pretrained(args.output_dir)
    print("Done!")

if __name__ == "__main__":
    main()
