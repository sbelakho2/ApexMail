#!/usr/bin/env python3
"""
ApexMail AI — ONNX Export

Merges the QLoRA adapter into the base model and exports to ONNX
for production inference via ONNX Runtime on the VPS.

Steps:
    1. Load base Qwen 2.5-7B-Instruct (full precision)
    2. Load & merge LoRA adapter weights
    3. Export to ONNX via optimum
    4. Optionally quantise to INT8 for CPU inference

Usage:
    python export_onnx.py                              # defaults from config.yaml
    python export_onnx.py --adapter output/checkpoint-300
    python export_onnx.py --no-quantise                # skip INT8 step
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import torch
import yaml
import typer
from rich.console import Console
from rich.panel import Panel
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from optimum.onnxruntime import ORTModelForCausalLM
from optimum.exporters.onnx import main_export

console = Console()
app = typer.Typer(pretty_exceptions_enable=False)


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


@app.command()
def main(
    config: str = typer.Option("config.yaml", help="Config YAML path"),
    adapter: str | None = typer.Option(None, help="Adapter dir (default: config output_dir)"),
    no_quantise: bool = typer.Option(False, help="Skip INT8 quantisation"),
) -> None:
    """Merge LoRA adapter and export Qwen 7B to ONNX."""
    console.print(Panel(
        "[bold]ApexMail AI — ONNX Export[/bold]\n"
        "Merge QLoRA adapter → ONNX → optional INT8 quantisation",
        border_style="cyan",
    ))

    cfg = load_config(config)
    model_name = cfg["model"]["base"]
    adapter_dir = adapter or cfg["paths"]["output_dir"]
    merged_dir = cfg["paths"]["merged_dir"]
    onnx_dir = cfg["paths"]["onnx_dir"]
    onnx_cfg = cfg.get("onnx", {})

    # ── Step 1: Load base model (full precision for merge) ───────────────
    console.print("\n[bold]1. Loading base model (full precision)...[/bold]")
    t0 = time.time()

    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        trust_remote_code=True,
    )

    base_model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float16,
        device_map="auto",
        trust_remote_code=True,
    )
    console.print(f"  Loaded in {time.time() - t0:.1f}s")

    # ── Step 2: Load and merge LoRA ──────────────────────────────────────
    console.print(f"\n[bold]2. Merging LoRA adapter from {adapter_dir}...[/bold]")
    t0 = time.time()

    model = PeftModel.from_pretrained(base_model, adapter_dir)
    model = model.merge_and_unload()
    console.print(f"  Merged in {time.time() - t0:.1f}s")

    # ── Step 3: Save merged model ────────────────────────────────────────
    console.print(f"\n[bold]3. Saving merged model to {merged_dir}...[/bold]")
    Path(merged_dir).mkdir(parents=True, exist_ok=True)
    model.save_pretrained(merged_dir)
    tokenizer.save_pretrained(merged_dir)
    console.print(f"  [green]✓ Merged model saved[/green]")

    # Free GPU memory before ONNX export
    del model, base_model
    torch.cuda.empty_cache()

    # ── Step 4: Export to ONNX ───────────────────────────────────────────
    console.print(f"\n[bold]4. Exporting to ONNX ({onnx_dir})...[/bold]")
    t0 = time.time()

    Path(onnx_dir).mkdir(parents=True, exist_ok=True)

    main_export(
        model_name_or_path=merged_dir,
        output=Path(onnx_dir),
        task="text-generation-with-past",
        opset=onnx_cfg.get("opset", 17),
        device="cpu",
        fp16=False,
        trust_remote_code=True,
    )

    # Copy tokenizer files to ONNX dir
    for f in Path(merged_dir).glob("tokenizer*"):
        shutil.copy2(f, Path(onnx_dir) / f.name)
    for f in Path(merged_dir).glob("special_tokens*"):
        shutil.copy2(f, Path(onnx_dir) / f.name)
    # Copy generation_config and config
    for fname in ["config.json", "generation_config.json"]:
        src = Path(merged_dir) / fname
        if src.exists():
            shutil.copy2(src, Path(onnx_dir) / fname)

    console.print(f"  Exported in {time.time() - t0:.1f}s")

    # ── Step 5: Optional INT8 quantisation ───────────────────────────────
    if not no_quantise:
        quantise_to = onnx_cfg.get("quantise_to", "int8")
        console.print(f"\n[bold]5. Quantising to {quantise_to}...[/bold]")
        t0 = time.time()

        from optimum.onnxruntime import ORTQuantizer
        from optimum.onnxruntime.configuration import AutoQuantizationConfig

        quantizer = ORTQuantizer.from_pretrained(onnx_dir)
        qconfig = AutoQuantizationConfig.avx512_vnni(
            is_static=False,
            per_channel=False,
        )
        quantiser_output = Path(onnx_dir) / "quantised"
        quantiser_output.mkdir(exist_ok=True)
        quantizer.quantize(
            save_dir=quantiser_output,
            quantization_config=qconfig,
        )
        console.print(f"  Quantised in {time.time() - t0:.1f}s")
        console.print(f"  [green]✓ Quantised model: {quantiser_output}[/green]")
    else:
        console.print("\n[dim]5. Skipping quantisation (--no-quantise)[/dim]")

    # ── Summary ──────────────────────────────────────────────────────────
    onnx_files = list(Path(onnx_dir).glob("*.onnx"))
    total_size = sum(f.stat().st_size for f in onnx_files) / (1024 ** 3)

    console.print(Panel(
        f"[bold green]Export complete![/bold green]\n"
        f"  ONNX dir:  {onnx_dir}\n"
        f"  Files:     {len(onnx_files)} .onnx files\n"
        f"  Size:      {total_size:.2f} GB\n"
        f"  Provider:  {onnx_cfg.get('provider', 'CPUExecutionProvider')}\n\n"
        f"  Copy {onnx_dir}/ to your VPS for production inference.",
        border_style="green",
    ))


if __name__ == "__main__":
    app()
