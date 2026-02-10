#!/usr/bin/env python3
"""
ApexMail AI — GGUF Export

Merges the QLoRA adapter into the base model and converts to GGUF format
for production inference via llama.cpp on CPU (ARM or x86).

GGUF is vastly faster than ONNX for 7B models on CPU because:
  - llama.cpp uses optimised SIMD kernels (AVX2/AVX512/NEON)
  - k-quants preserve quality at low bit widths
  - KV-cache and memory management are CPU-optimised

Steps:
    1. Load base model + merge LoRA adapter
    2. Save merged model in safetensors format
    3. Convert to GGUF via llama.cpp's convert script
    4. Quantise to Q4_K_M, Q5_K_M, Q8_0

Usage:
    python export_gguf.py                               # defaults from config.yaml
    python export_gguf.py --adapter output/checkpoint-300
    python export_gguf.py --quant Q5_K_M                # override quantisation
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import torch
import yaml
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

console = Console()
app = typer.Typer(pretty_exceptions_enable=False)

LLAMA_CPP_DIR = Path("/workspace/llama.cpp")


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def ensure_llama_cpp() -> Path:
    """Clone and build llama.cpp if not present."""
    if LLAMA_CPP_DIR.exists() and (LLAMA_CPP_DIR / "llama-quantize").exists():
        console.print("  [green]llama.cpp already built[/green]")
        return LLAMA_CPP_DIR

    console.print("  Cloning llama.cpp...")
    if LLAMA_CPP_DIR.exists():
        shutil.rmtree(LLAMA_CPP_DIR)

    subprocess.run(
        ["git", "clone", "--depth=1", "https://github.com/ggerganov/llama.cpp", str(LLAMA_CPP_DIR)],
        check=True,
        capture_output=True,
    )

    console.print("  Building llama.cpp (CPU only)...")
    subprocess.run(
        ["make", "-j", str(os.cpu_count() or 4), "llama-quantize"],
        cwd=LLAMA_CPP_DIR,
        check=True,
        capture_output=True,
    )

    # Install Python conversion deps
    requirements = LLAMA_CPP_DIR / "requirements.txt"
    if requirements.exists():
        subprocess.run(
            ["pip", "install", "-q", "-r", str(requirements)],
            check=True,
            capture_output=True,
        )
    else:
        subprocess.run(
            ["pip", "install", "-q", "gguf", "numpy", "sentencepiece"],
            check=True,
            capture_output=True,
        )

    console.print("  [green]✓ llama.cpp built successfully[/green]")
    return LLAMA_CPP_DIR


def convert_to_gguf(merged_dir: Path, gguf_dir: Path) -> Path:
    """Convert HF safetensors model to GGUF F16."""
    gguf_f16 = gguf_dir / "apexmail-7b-f16.gguf"

    console.print(f"  Converting to GGUF F16...")
    convert_script = LLAMA_CPP_DIR / "convert_hf_to_gguf.py"

    cmd = [
        "python3", str(convert_script),
        str(merged_dir),
        "--outfile", str(gguf_f16),
        "--outtype", "f16",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        console.print(f"[red]Convert error: {result.stderr}[/red]")
        raise RuntimeError(f"GGUF conversion failed: {result.stderr}")

    size_gb = gguf_f16.stat().st_size / (1024 ** 3)
    console.print(f"  [green]✓ F16 GGUF: {gguf_f16} ({size_gb:.2f} GB)[/green]")
    return gguf_f16


def quantise_gguf(gguf_f16: Path, gguf_dir: Path, quant_type: str) -> Path:
    """Quantise GGUF model to a specific quant type."""
    output = gguf_dir / f"apexmail-7b-{quant_type.lower()}.gguf"

    console.print(f"  Quantising to {quant_type}...")
    quantize_bin = LLAMA_CPP_DIR / "llama-quantize"

    result = subprocess.run(
        [str(quantize_bin), str(gguf_f16), str(output), quant_type],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        console.print(f"[red]Quantise error: {result.stderr}[/red]")
        raise RuntimeError(f"Quantisation failed for {quant_type}: {result.stderr}")

    size_gb = output.stat().st_size / (1024 ** 3)
    console.print(f"  [green]✓ {quant_type}: {output} ({size_gb:.2f} GB)[/green]")
    return output


@app.command()
def main(
    config: str = typer.Option("config.yaml", help="Config YAML path"),
    adapter: str | None = typer.Option(None, help="Adapter dir (default: config output_dir)"),
    quant: str | None = typer.Option(None, help="Override primary quantisation type"),
    skip_merge: bool = typer.Option(False, help="Skip merge (use existing merged dir)"),
) -> None:
    """Merge LoRA adapter and export to GGUF for CPU inference."""
    console.print(Panel(
        "[bold]ApexMail AI — GGUF Export[/bold]\n"
        "Merge QLoRA adapter → GGUF → quantise for CPU (ARM/x86)",
        border_style="cyan",
    ))

    cfg = load_config(config)
    model_name = cfg["model"]["base"]
    adapter_dir = adapter or cfg["paths"]["output_dir"]
    merged_dir = Path(cfg["paths"]["merged_dir"])
    gguf_dir = Path(cfg["paths"]["gguf_dir"])
    export_cfg = cfg.get("export", {}).get("gguf", {})

    primary_quant = quant or export_cfg.get("quantisation", "Q4_K_M")
    extra_quants = export_cfg.get("extra_quants", [])

    gguf_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Merge LoRA ───────────────────────────────────────────────
    if not skip_merge:
        console.print("\n[bold]1. Loading base model + merging LoRA...[/bold]")
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

        console.print(f"  Loading adapter from {adapter_dir}...")
        model = PeftModel.from_pretrained(base_model, adapter_dir)
        model = model.merge_and_unload()
        console.print(f"  Merged in {time.time() - t0:.1f}s")

        console.print(f"\n[bold]2. Saving merged model to {merged_dir}...[/bold]")
        merged_dir.mkdir(parents=True, exist_ok=True)
        model.save_pretrained(merged_dir, safe_serialization=True)
        tokenizer.save_pretrained(merged_dir)
        console.print(f"  [green]✓ Merged model saved[/green]")

        # Free GPU memory
        del model, base_model
        torch.cuda.empty_cache()
    else:
        console.print("\n[bold]1-2. Using existing merged model...[/bold]")
        if not merged_dir.exists():
            console.print(f"[red]ERROR: {merged_dir} not found. Run without --skip-merge.[/red]")
            raise typer.Exit(1)

    # ── Step 3: Clone/build llama.cpp ────────────────────────────────────
    console.print(f"\n[bold]3. Ensuring llama.cpp is available...[/bold]")
    ensure_llama_cpp()

    # ── Step 4: Convert to GGUF F16 ─────────────────────────────────────
    console.print(f"\n[bold]4. Converting to GGUF F16...[/bold]")
    t0 = time.time()
    gguf_f16 = convert_to_gguf(merged_dir, gguf_dir)
    console.print(f"  Converted in {time.time() - t0:.1f}s")

    # ── Step 5: Quantise ─────────────────────────────────────────────────
    console.print(f"\n[bold]5. Quantising...[/bold]")
    all_quants = [primary_quant] + [q for q in extra_quants if q != primary_quant]
    quant_files: list[tuple[str, Path, float]] = []

    for qt in all_quants:
        t0 = time.time()
        output = quantise_gguf(gguf_f16, gguf_dir, qt)
        elapsed = time.time() - t0
        size_gb = output.stat().st_size / (1024 ** 3)
        quant_files.append((qt, output, size_gb))

    # ── Step 6: Copy system prompt alongside model ───────────────────────
    console.print(f"\n[bold]6. Bundling system prompt...[/bold]")
    from prompts import SYSTEM_PROMPT
    prompt_file = gguf_dir / "system_prompt.txt"
    prompt_file.write_text(SYSTEM_PROMPT)
    console.print(f"  [green]✓ System prompt saved to {prompt_file}[/green]")

    # ── Optionally remove F16 GGUF to save space ────────────────────────
    if gguf_f16.exists() and len(quant_files) > 0:
        console.print(f"\n  Removing F16 GGUF ({gguf_f16.stat().st_size / 1e9:.1f} GB) to save disk...")
        gguf_f16.unlink()

    # ── Summary ──────────────────────────────────────────────────────────
    table = Table(title="GGUF Export Summary")
    table.add_column("Quantisation", style="cyan")
    table.add_column("File", style="dim")
    table.add_column("Size", justify="right", style="green")
    for qt, path, size in quant_files:
        marker = " ⬅ primary" if qt == primary_quant else ""
        table.add_row(f"{qt}{marker}", path.name, f"{size:.2f} GB")
    console.print(table)

    console.print(Panel(
        f"[bold green]GGUF export complete![/bold green]\n\n"
        f"  Primary:  {gguf_dir}/apexmail-7b-{primary_quant.lower()}.gguf\n"
        f"  Dir:      {gguf_dir}\n\n"
        f"  Run with llama.cpp:\n"
        f"    llama-server -m {gguf_dir}/apexmail-7b-{primary_quant.lower()}.gguf \\\n"
        f"      -c 4096 --system-prompt-file {gguf_dir}/system_prompt.txt\n\n"
        f"  Or with llama-cpp-python:\n"
        f"    pip install llama-cpp-python\n"
        f"    from llama_cpp import Llama\n"
        f"    model = Llama('{gguf_dir}/apexmail-7b-{primary_quant.lower()}.gguf', n_ctx=4096)",
        border_style="green",
    ))


if __name__ == "__main__":
    app()
