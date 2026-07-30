#!/usr/bin/env python3
"""
Merge QLoRA adapter into base model and convert to GGUF for llama.cpp CPU inference.

This is the critical bridge between training and production deployment.
Without this step, the llama-server cannot load the fine-tuned Qwen model
because llama.cpp does not support loading PEFT/LoRA adapters directly.

Usage:
    # Merge adapter into base model (produces full model weights)
    python merge_and_export.py --base models/Qwen2.5-7B-Instruct \
                               --adapter output/ \
                               --output merged_model/

    # Convert merged model to GGUF for llama.cpp
    python merge_and_export.py --convert-gguf \
                               --merged merged_model/ \
                               --gguf-output models/qwen2.5-7b-apexmail.iq3_m.gguf \
                               --quant iq3_m

    # Full pipeline: merge + convert
    python merge_and_export.py --base models/Qwen2.5-7B-Instruct \
                               --adapter output/ \
                               --gguf-output models/qwen2.5-7b-apexmail.iq3_m.gguf \
                               --quant iq3_m
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer


def merge_adapter(base_path: str, adapter_path: str, output_path: str) -> None:
    """Load base model + LoRA adapter, merge weights, save full model."""
    print(f"[1/3] Loading tokenizer from {base_path}...")
    tokenizer = AutoTokenizer.from_pretrained(base_path, trust_remote_code=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[2/3] Loading base model from {base_path}...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        base_path,
        torch_dtype=torch.bfloat16,
        trust_remote_code=False,
        device_map="auto",
        low_cpu_mem_usage=True,
    )
    print(f"      Base model loaded in {time.time() - t0:.1f}s")

    if adapter_path and Path(adapter_path).exists():
        print(f"      Loading adapter from {adapter_path}...")
        t0 = time.time()
        model = PeftModel.from_pretrained(model, adapter_path)
        print(f"      Adapter loaded in {time.time() - t0:.1f}s")
        print(f"      Merging adapter weights into base model...")
        model = model.merge_and_unload()
        print(f"      Merge complete.")
    else:
        print(f"      No adapter found at {adapter_path} — exporting base model only.")

    print(f"[3/3] Saving merged model to {output_path}...")
    model.save_pretrained(output_path, safe_serialization=True)
    tokenizer.save_pretrained(output_path)
    print(f"      Done. Merged model saved to {output_path}")


def convert_to_gguf(
    merged_path: str,
    gguf_output: str,
    quant: str = "iq3_m",
    llama_cpp_dir: str | None = None,
) -> None:
    """Convert merged HuggingFace model to GGUF using llama.cpp's convert_hf_to_gguf.py."""
    if llama_cpp_dir is None:
        llama_cpp_dir = os.environ.get("LLAMA_CPP_DIR", "./llama.cpp")
    llama_cpp = Path(llama_cpp_dir)
    convert_script = llama_cpp / "convert_hf_to_gguf.py"

    if not convert_script.exists():
        raise FileNotFoundError(
            f"llama.cpp convert script not found at {convert_script}. "
            f"Clone from https://github.com/ggerganov/llama.cpp or set LLAMA_CPP_DIR env var."
        )

    fp16_output = str(Path(gguf_output).with_suffix(".fp16.gguf"))

    print(f"\n[Convert] Converting {merged_path} → {fp16_output}...")
    subprocess.run(
        [
            sys.executable,
            str(convert_script),
            merged_path,
            "--outfile", fp16_output,
            "--outtype", "f16",
        ],
        check=True,
    )
    print(f"      FP16 GGUF written to {fp16_output}")

    # Quantize
    quantize_bin = llama_cpp / "llama-quantize"
    if not quantize_bin.exists():
        quantize_bin = Path("./llama-quantize")
    if not quantize_bin.exists():
        raise FileNotFoundError(
            f"llama-quantize binary not found. Build llama.cpp first: cd {llama_cpp_dir} && make"
        )

    print(f"\n[Quantize] Converting {fp16_output} → {gguf_output} ({quant})...")
    subprocess.run(
        [str(quantize_bin), fp16_output, gguf_output, quant],
        check=True,
    )
    print(f"      Quantized GGUF written to {gguf_output}")

    # Clean up intermediate FP16 file to save disk
    fp16_path = Path(fp16_output)
    if fp16_path.exists():
        fp16_path.unlink()
        print(f"      Removed intermediate {fp16_output}")

    # Print size info
    gguf_path = Path(gguf_output)
    size_gb = gguf_path.stat().st_size / (1024 ** 3)
    print(f"\n      Final GGUF: {gguf_path.name} ({size_gb:.2f} GB)")


def validate_gguf(gguf_path: str) -> bool:
    """Quick validation that the GGUF file is non-empty and has the right magic bytes."""
    path = Path(gguf_path)
    if not path.exists():
        print(f"❌ GGUF file not found: {gguf_path}")
        return False
    size_mb = path.stat().st_size / (1024 ** 2)
    if size_mb < 10:
        print(f"❌ GGUF file too small ({size_mb:.1f} MB) — likely corrupted")
        return False
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic != b"GGUF":
        print(f"❌ Invalid GGUF magic bytes: {magic!r}")
        return False
    print(f"✅ GGUF validated: {gguf_path} ({size_mb:.1f} MB)")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge QLoRA adapter + convert to GGUF for llama.cpp deployment"
    )
    parser.add_argument("--base", type=str, required=True, help="Path to base model")
    parser.add_argument("--adapter", type=str, default="", help="Path to LoRA adapter directory")
    parser.add_argument("--output", type=str, default="merged_model", help="Output directory for merged model")
    parser.add_argument("--convert-gguf", action="store_true", help="Convert merged model to GGUF")
    parser.add_argument("--gguf-output", type=str, default="", help="Output GGUF file path")
    parser.add_argument("--quant", type=str, default="iq3_m", choices=["q4_k_m", "iq3_m", "q5_k_m", "q8_0"],
                        help="GGUF quantization type (default: iq3_m for 7B)")
    parser.add_argument("--llama-cpp-dir", type=str, default="", help="Path to llama.cpp directory")
    parser.add_argument("--skip-merge", action="store_true", help="Skip merge, only convert existing merged model")
    parser.add_argument("--validate", action="store_true", help="Validate GGUF file after conversion")
    args = parser.parse_args()

    if not args.skip_merge:
        merge_adapter(args.base, args.adapter, args.output)

    if args.convert_gguf:
        merged = args.output if not args.skip_merge else args.base
        gguf_out = args.gguf_output or f"models/qwen-apexmail.{args.quant}.gguf"
        llama_dir = args.llama_cpp_dir or None
        convert_to_gguf(merged, gguf_out, args.quant, llama_dir)

        if args.validate:
            validate_gguf(gguf_out)

    print("\n✅ Merge + GGUF export complete.")
    if args.convert_gguf:
        print(f"\n   Deploy with:\n   llama-server -m {args.gguf_output or gguf_out} --host 127.0.0.1 --port 8081 --threads 8 --ctx-size 4096")


if __name__ == "__main__":
    main()
