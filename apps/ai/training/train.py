#!/usr/bin/env python3
"""
ApexMail AI — Qwen3-Next-80B-A3B-Instruct QLoRA Fine-Tuning

Trains a QLoRA adapter on Qwen3-Next-80B-A3B-Instruct (MoE ~80B, ~3B active) using SFTTrainer.
Designed for 4× NVIDIA B200 (183 GB each) on vast.ai.

Workflow:
    1. generate_dataset.py  → data/{train,val,test}.jsonl
    2. train.py             → output/  (LoRA adapter checkpoints)
    3. Optional export step → handled by separate deployment tooling
    4. eval.py              → eval_results/ (golden-set evaluation)

Usage:
    python train.py                          # train with config.yaml defaults
    python train.py --epochs 2 --lr 1e-4     # override hyper-params
    python train.py --resume output/checkpoint-200   # resume from checkpoint
"""

from __future__ import annotations

import json
import os
import sys
import time
import logging
from datetime import datetime
from itertools import islice
from pathlib import Path

import torch
import yaml
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datasets import load_dataset
from training_data import expand_system_prompt_refs
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer, SFTConfig

console = Console()
app = typer.Typer(pretty_exceptions_enable=False)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("apexmail.train")


def load_config(path: str = "config.yaml") -> dict:
    """Load training configuration from YAML."""
    with open(path) as f:
        cfg = yaml.safe_load(f)

    # The managed runner controls these deployment paths. They are not taken
    # from an API request and allow each job to produce an isolated artifact.
    if model_base := os.environ.get("AI_MODEL_BASE"):
        cfg["model"]["base"] = model_base
    if output_dir := os.environ.get("AI_OUTPUT_DIR"):
        cfg["paths"]["output_dir"] = output_dir
    if logs_dir := os.environ.get("AI_LOGS_DIR"):
        cfg["paths"]["logs_dir"] = logs_dir
    return cfg


def print_gpu_info() -> None:
    """Print GPU information for verification."""
    if not torch.cuda.is_available():
        console.print("[red]ERROR: CUDA not available. Cannot train.[/red]")
        sys.exit(1)

    table = Table(title="GPU Information")
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")

    for i in range(torch.cuda.device_count()):
        props = torch.cuda.get_device_properties(i)
        table.add_row(f"GPU {i}", props.name)
        table.add_row(f"  VRAM", f"{props.total_memory / 1e9:.1f} GB")
        table.add_row(f"  Compute", f"{props.major}.{props.minor}")

    table.add_row("PyTorch", torch.__version__)
    table.add_row("CUDA", torch.version.cuda or "N/A")

    console.print(table)


def create_tokenizer(cfg: dict) -> AutoTokenizer:
    """Load and configure the Qwen tokenizer."""
    model_cfg = cfg["model"]
    tokenizer = AutoTokenizer.from_pretrained(
        model_cfg["base"],
        revision=model_cfg.get("revision", "main"),
        trust_remote_code=model_cfg.get("trust_remote_code", True),
        padding_side="right",
    )
    # Qwen3 uses <|endoftext|> as EOS and <|im_end|> as chat turn end.
    # Ensure pad token is set (required for batched training).
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer.pad_token_id = tokenizer.eos_token_id
    return tokenizer


def create_model(cfg: dict) -> AutoModelForCausalLM:
    """Load Qwen3-Next-80B-A3B-Instruct in 4-bit QLoRA mode."""
    model_cfg = cfg["model"]
    quant_cfg = cfg["quantisation"]

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=quant_cfg["load_in_4bit"],
        bnb_4bit_quant_type=quant_cfg["bnb_4bit_quant_type"],
        bnb_4bit_compute_dtype=getattr(torch, quant_cfg["bnb_4bit_compute_dtype"]),
        bnb_4bit_use_double_quant=quant_cfg["bnb_4bit_use_double_quant"],
    )

    # For DDP multi-GPU: each process loads onto its own GPU via LOCAL_RANK
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    device_map = {"": local_rank}

    model = AutoModelForCausalLM.from_pretrained(
        model_cfg["base"],
        revision=model_cfg.get("revision", "main"),
        quantization_config=bnb_config,
        torch_dtype=getattr(torch, model_cfg["torch_dtype"]),
        attn_implementation=model_cfg.get("attn_implementation", "sdpa"),
        device_map=device_map,
        trust_remote_code=model_cfg.get("trust_remote_code", True),
    )

    model = prepare_model_for_kbit_training(
        model, use_gradient_checkpointing=cfg["training"]["gradient_checkpointing"]
    )
    return model


def validate_lora_targets(model: AutoModelForCausalLM, target_modules: list[str]) -> None:
    """Fail fast when config names modules that do not exist on the loaded model."""
    module_names = [name for name, _ in model.named_modules()]
    missing_targets = [
        target
        for target in target_modules
        if not any(name == target or name.endswith(f".{target}") for name in module_names)
    ]

    if missing_targets:
        raise ValueError(
            "LoRA target_modules not found on the loaded model: "
            + ", ".join(missing_targets)
        )


def create_lora(cfg: dict, model: AutoModelForCausalLM) -> AutoModelForCausalLM:
    """Apply LoRA adapter to the model."""
    lora_cfg = cfg["lora"]
    validate_lora_targets(model, lora_cfg["target_modules"])
    peft_config = LoraConfig(
        r=lora_cfg["r"],
        lora_alpha=lora_cfg["alpha"],
        lora_dropout=lora_cfg["dropout"],
        bias=lora_cfg["bias"],
        task_type=lora_cfg["task_type"],
        target_modules=lora_cfg["target_modules"],
    )
    model = get_peft_model(model, peft_config)

    # Print trainable params
    trainable, total = 0, 0
    for _, p in model.named_parameters():
        total += p.numel()
        if p.requires_grad:
            trainable += p.numel()

    pct = 100.0 * trainable / total
    console.print(
        f"[cyan]Trainable params:[/cyan] {trainable:,} / {total:,} ({pct:.2f}%)"
    )
    return model


def load_data(cfg: dict, tokenizer: AutoTokenizer):
    """Load and tokenize the ChatML JSONL dataset."""
    train_cfg = cfg["training"]
    ds_cfg = cfg["dataset"]

    data_files = {
        "train": ds_cfg["train_file"],
        "validation": ds_cfg["val_file"],
    }
    dataset = load_dataset(
        "json",
        data_files=data_files,
    )
    dataset["train"] = expand_system_prompt_refs(dataset["train"], data_files["train"])
    dataset["validation"] = expand_system_prompt_refs(dataset["validation"], data_files["validation"])

    def format_chat(example):
        """Apply the chat template to produce the full text."""
        text = tokenizer.apply_chat_template(
            example["messages"],
            tokenize=False,
            add_generation_prompt=False,
        )
        return {"text": text}

    # Only apply format_chat if data has "messages" column (not pre-formatted "text")
    if "messages" in dataset["train"].column_names:
        dataset = dataset.map(format_chat, remove_columns=["messages"])
    elif "text" not in dataset["train"].column_names:
        console.print("[red]ERROR: Dataset must have 'messages' or 'text' column[/red]")
        sys.exit(1)
    else:
        console.print("[cyan]Dataset already has 'text' column — skipping format_chat[/cyan]")

    console.print(f"[cyan]Train examples:[/cyan] {len(dataset['train'])}")
    console.print(f"[cyan]Val examples:[/cyan]   {len(dataset['validation'])}")

    # Show one example
    sample = dataset["train"][0]["text"]
    console.print(Panel(
        sample[:500] + ("..." if len(sample) > 500 else ""),
        title="Sample training text",
        border_style="dim",
    ))

    return dataset


def run_eval_after_training(
    model: AutoModelForCausalLM,
    tokenizer: AutoTokenizer,
    cfg: dict,
) -> None:
    """Run a quick sanity eval on the golden set after training."""
    eval_cfg = cfg.get("evaluation", {})
    golden_path = eval_cfg.get("golden_set", "data/golden_qa.jsonl")

    if not Path(golden_path).exists():
        console.print("[yellow]No golden set found — skipping post-train eval.[/yellow]")
        return

    console.print("\n[bold cyan]── Post-Training Evaluation ──[/bold cyan]")

    model.eval()
    correct = 0
    total = 0

    with open(golden_path) as f:
        for item in islice((json.loads(line) for line in f if line.strip()), 50):
            messages = item["messages"][:2]  # system + user only
            prompt = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
            inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

            with torch.inference_mode():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=eval_cfg.get("max_new_tokens", 512),
                    temperature=eval_cfg.get("temperature", 0.1),
                    top_p=eval_cfg.get("top_p", 0.9),
                    do_sample=True,
                    pad_token_id=tokenizer.pad_token_id,
                )

            generated_tokens = outputs[0][inputs["input_ids"].shape[1]:].detach().cpu()
            response = tokenizer.decode(
                generated_tokens,
                skip_special_tokens=True,
            ).strip()

            if len(response) > 20 and not _is_degenerate(response):
                correct += 1
            total += 1

            del generated_tokens
            del outputs
            del inputs

    if torch.cuda.is_available():
        torch.cuda.empty_cache()

    pct = 100.0 * correct / total if total > 0 else 0
    console.print(f"  Quick eval: {correct}/{total} ({pct:.1f}%) non-degenerate responses")


def _is_degenerate(text: str) -> bool:
    """Check if a response is degenerate (repetitive/empty)."""
    # Check for excessive repetition
    words = text.split()
    if len(words) < 5:
        return True
    # If any 4-word phrase repeats more than 5 times, it's degenerate
    for i in range(len(words) - 3):
        phrase = " ".join(words[i : i + 4])
        if text.count(phrase) > 5:
            return True
    return False


@app.command()
def main(
    config: str = typer.Option("config.yaml", help="Path to config YAML"),
    epochs: int | None = typer.Option(None, help="Override num_train_epochs"),
    lr: float | None = typer.Option(None, help="Override learning rate"),
    batch_size: int | None = typer.Option(None, help="Override per-device batch size"),
    max_seq_len: int | None = typer.Option(None, help="Override max_seq_length"),
    resume: str | None = typer.Option(None, help="Resume from checkpoint path"),
    no_eval: bool = typer.Option(False, help="Skip post-training eval"),
    metrics_output: str = typer.Option(
        "", help="Write real training/evaluation metrics to this JSON file",
    ),
) -> None:
    """Fine-tune Qwen3-Next-80B-A3B-Instruct with QLoRA."""
    console.print(Panel(
        "[bold]ApexMail AI — Qwen3-Next-80B QLoRA Training[/bold]\n"
        "Fine-tuning for email marketing support assistant",
        border_style="cyan",
    ))

    # Load config
    cfg = load_config(config)

    # Apply CLI overrides
    if epochs is not None:
        cfg["training"]["num_train_epochs"] = epochs
    if lr is not None:
        cfg["training"]["learning_rate"] = lr
    if batch_size is not None:
        cfg["training"]["per_device_train_batch_size"] = batch_size
    if max_seq_len is not None:
        cfg["training"]["max_seq_length"] = max_seq_len

    # GPU check
    print_gpu_info()

    # Create output dirs
    train_cfg = cfg["training"]
    paths = cfg["paths"]
    for d in [paths["output_dir"], paths["logs_dir"]]:
        Path(d).mkdir(parents=True, exist_ok=True)

    # Timestamp for logging
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = Path(paths["logs_dir"]) / f"train_{ts}.log"
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    logger.info("Config: %s", json.dumps(cfg, indent=2, default=str))

    # ── Load tokenizer & model ───────────────────────────────────────────
    console.print("\n[bold]Loading tokenizer...[/bold]")
    tokenizer = create_tokenizer(cfg)

    console.print("[bold]Loading model in 4-bit...[/bold]")
    t0 = time.time()
    model = create_model(cfg)
    console.print(f"  Model loaded in {time.time() - t0:.1f}s")

    console.print("[bold]Applying LoRA adapter...[/bold]")
    model = create_lora(cfg, model)

    # ── Load dataset ─────────────────────────────────────────────────────
    console.print("\n[bold]Loading dataset...[/bold]")
    dataset = load_data(cfg, tokenizer)

    # ── Training arguments ───────────────────────────────────────────────
    training_args = SFTConfig(
        output_dir=paths["output_dir"],
        max_length=train_cfg["max_seq_length"],
        packing=train_cfg.get("packing", False),  # F-08: Disabled packing to prevent cross-sample attention leakage
        dataset_text_field="text",
        num_train_epochs=train_cfg["num_train_epochs"],
        per_device_train_batch_size=train_cfg["per_device_train_batch_size"],
        per_device_eval_batch_size=train_cfg["per_device_eval_batch_size"],
        gradient_accumulation_steps=train_cfg["gradient_accumulation_steps"],
        learning_rate=train_cfg["learning_rate"],
        lr_scheduler_type=train_cfg["lr_scheduler_type"],
        warmup_ratio=train_cfg["warmup_ratio"],
        weight_decay=train_cfg["weight_decay"],
        gradient_checkpointing=train_cfg["gradient_checkpointing"],
        gradient_checkpointing_kwargs=train_cfg.get("gradient_checkpointing_kwargs"),
        optim=train_cfg["optim"],
        bf16=train_cfg["bf16"],
        tf32=train_cfg.get("tf32", True),
        logging_steps=train_cfg["logging_steps"],
        eval_strategy=train_cfg["eval_strategy"],
        eval_steps=train_cfg["eval_steps"],
        save_strategy=train_cfg["save_strategy"],
        save_steps=train_cfg["save_steps"],
        save_total_limit=train_cfg["save_total_limit"],
        load_best_model_at_end=train_cfg["load_best_model_at_end"],
        metric_for_best_model=train_cfg["metric_for_best_model"],
        greater_is_better=train_cfg["greater_is_better"],
        report_to=train_cfg["report_to"],
        seed=train_cfg["seed"],
        dataloader_num_workers=train_cfg.get("dataloader_num_workers", 4),
        dataloader_pin_memory=train_cfg.get("dataloader_pin_memory", True),
        logging_dir=paths["logs_dir"],
        run_name=f"apexmail-qwen3-80b-{ts}",
    )

    # ── Trainer ──────────────────────────────────────────────────────────
    trainer = SFTTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset["validation"],
        processing_class=tokenizer,
    )

    # ── Train ────────────────────────────────────────────────────────────
    console.print("\n[bold green]Starting training...[/bold green]")
    t0 = time.time()

    train_result = trainer.train(resume_from_checkpoint=resume)

    elapsed = time.time() - t0
    console.print(f"\n[bold green]Training complete in {elapsed / 60:.1f} min[/bold green]")

    # Log metrics
    metrics = train_result.metrics
    metrics["train_runtime_minutes"] = elapsed / 60
    trainer.log_metrics("train", metrics)
    trainer.save_metrics("train", metrics)

    # Save final adapter
    trainer.save_model()
    tokenizer.save_pretrained(paths["output_dir"])
    console.print(f"[green]✓ Adapter saved to {paths['output_dir']}[/green]")

    # ── Eval ─────────────────────────────────────────────────────────────
    eval_metrics: dict = {}
    if not no_eval:
        eval_metrics = trainer.evaluate()
        trainer.log_metrics("eval", eval_metrics)
        trainer.save_metrics("eval", eval_metrics)
        console.print(f"  Eval loss: {eval_metrics.get('eval_loss', 'N/A')}")

        # Run golden-set eval
        run_eval_after_training(model, tokenizer, cfg)

    # The managed API runner consumes this artifact only after the real
    # training process exits successfully. Do not synthesize loss values.
    if metrics_output:
        metrics_path = Path(metrics_output)
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        reported_loss = eval_metrics.get("eval_loss", metrics.get("train_loss"))
        artifact = {
            "loss": float(reported_loss) if reported_loss is not None else None,
            "train_metrics": metrics,
            "evaluation": eval_metrics,
            "adapter_path": str(Path(paths["output_dir"]).resolve()),
            "completed_at": datetime.now().astimezone().isoformat(),
        }
        metrics_path.write_text(json.dumps(artifact, indent=2, default=str) + "\n")
        console.print(f"[green]✓ Metrics written to {metrics_path}[/green]")

    console.print(Panel(
        f"[bold green]Done![/bold green]\n"
        f"  Adapter: {paths['output_dir']}\n"
        f"  Logs:    {log_file}\n"
        f"  Next:    python export_onnx.py",
        border_style="green",
    ))


if __name__ == "__main__":
    app()
