#!/usr/bin/env python3
"""
Evaluate the trained LoRA adapter on test set + golden QA.
Tests: generation quality, loss on test set, golden QA accuracy.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from pathlib import Path

from common_paths import GOLDEN_QA_JSONL, TEST_JSONL
from training_data import expand_system_prompt_refs

# Heavy ML imports live inside main() so the pure scoring helpers
# (score_golden_answer / extract_price_tokens) stay importable — and
# unit-testable — without torch/peft/transformers installed.

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("evaluate")

SEP = "=" * 70

# Canonical monthly plan prices (EUR) from
# services/mail-server/crates/billing-service/src/plans.rs — used for the
# exact-price-match check on pricing answers.
CANONICAL_PLAN_PRICES = {0, 25, 65, 150, 350, 3000}
PRICE_TOKEN_RE = re.compile(r"€\s?(\d[\d,]*)")


def extract_price_tokens(text: str) -> list[int]:
    """Whole-euro price tokens appearing in a golden answer / generation."""
    tokens = []
    for m in PRICE_TOKEN_RE.finditer(text):
        try:
            tokens.append(int(m.group(1).replace(",", "")))
        except ValueError:
            continue
    return tokens


def score_golden_answer(expected: str, generated: str) -> dict:
    """Score one golden QA answer.

    Returns:
      keyword_recall: overlap of distinctive expected keywords in the
        generation (NOT semantic accuracy — honest naming).
      price_match: None when the expected answer contains no prices,
        otherwise whether every canonical price it quotes also appears in
        the generation and no non-canonical plan price was invented.
      correct: keyword recall threshold met AND (if prices are expected)
        the price check passed.
    """
    expected_lower = expected.lower()
    generated_lower = generated.lower()

    key_terms = [t.strip() for t in expected_lower.split() if len(t.strip()) > 4][:10]
    matches = sum(1 for t in key_terms if t in generated_lower)
    keyword_recall = matches / max(len(key_terms), 1)

    expected_prices = {p for p in extract_price_tokens(expected) if p in CANONICAL_PLAN_PRICES}
    if expected_prices:
        generated_prices = set(extract_price_tokens(generated))
        price_match = expected_prices.issubset(generated_prices) and not (
            generated_prices - CANONICAL_PLAN_PRICES - {0}
        )
    else:
        price_match = None

    correct = keyword_recall > 0.3 and price_match is not False
    return {
        "keyword_recall": round(keyword_recall, 2),
        "price_match": price_match,
        "correct": correct,
    }


# Model / adapter paths — set via environment when running on cloud instances.
# Falls back to paths matching the local config.yaml convention.
MODEL_PATH: str = os.environ.get(
    "MODEL_PATH",
    "/workspace/models/Qwen3-Next-80B-A3B-Instruct",
)
ADAPTER_DIR: str = os.environ.get(
    "ADAPTER_DIR",
    "/workspace/output_agent",
)

_EVAL_RESULTS_DIR = Path(ADAPTER_DIR)
_EVAL_RESULTS_PATH = _EVAL_RESULTS_DIR / "eval_results.json"


def main() -> None:
    import torch
    from datasets import load_dataset
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    log.info(SEP)
    log.info("ApexMail Agent — Post-Training Evaluation")
    log.info(SEP)

    # ── 1. Load tokenizer ──────────────────────────────────────────────────────
    log.info("[1/5] Loading tokenizer …")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=False)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # ── 2. Load base model + adapter ───────────────────────────────────────────
    log.info("[2/5] Loading base model + LoRA adapter …")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=False,
        attn_implementation="eager",
        device_map="auto",
        low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(model, ADAPTER_DIR)
    model.eval()
    log.info("    Loaded in %.1fs", time.time() - t0)

    # ── 3. Evaluate test set loss ──────────────────────────────────────────────
    log.info("[3/5] Computing test set loss …")
    try:
        test_ds = load_dataset("json", data_files=str(TEST_JSONL), split="train")
    except Exception as exc:
        log.error("Failed to load test dataset %s: %s", TEST_JSONL, exc)
        sys.exit(1)
    test_ds = expand_system_prompt_refs(test_ds, str(TEST_JSONL))
    total_loss = 0.0
    total_tokens = 0
    num_samples = len(test_ds)

    for i, example in enumerate(test_ds):
        text = example["text"]
        inputs = tok(text, return_tensors="pt", truncation=True, max_length=4096)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = model(**inputs, labels=inputs["input_ids"])
        total_loss += outputs.loss.item() * inputs["input_ids"].shape[1]
        total_tokens += inputs["input_ids"].shape[1]
        if (i + 1) % 10 == 0:
            log.info("    Processed %d/%d test examples …", i + 1, num_samples)

    avg_loss = total_loss / total_tokens
    perplexity = torch.exp(torch.tensor(avg_loss)).item()
    log.info("    Test loss:       %.4f", avg_loss)
    log.info("    Test perplexity: %.2f", perplexity)

    # ── 4. Golden QA evaluation ────────────────────────────────────────────────
    log.info("[4/5] Evaluating on golden QA set …")
    try:
        with open(GOLDEN_QA_JSONL) as f:
            golden = [json.loads(line) for line in f]
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        log.error("Failed to load golden QA set %s: %s", GOLDEN_QA_JSONL, exc)
        sys.exit(1)

    golden_results: list[dict] = []
    correct = 0
    for i, qa in enumerate(golden):
        # Handle both 'text' (ChatML) and 'messages' (openai-style) formats
        if "text" in qa:
            text = qa["text"]
            parts = text.rsplit("<|im_start|>assistant\n", 1)
            if len(parts) < 2:
                continue
            prompt = parts[0] + "<|im_start|>assistant\n"
            expected = parts[1].replace("<|im_end|>", "").strip()[:200]
        elif "messages" in qa:
            msgs = qa["messages"]
            prompt_parts: list[str] = []
            expected = ""
            for msg in msgs:
                role = msg["role"]
                content = msg["content"]
                if role == "assistant" and msg == msgs[-1]:
                    expected = content[:200]
                else:
                    prompt_parts.append(f"<|im_start|>{role}\n{content}<|im_end|>")
            prompt = "\n".join(prompt_parts) + "\n<|im_start|>assistant\n"
        else:
            continue

        inputs = tok(prompt, return_tensors="pt", truncation=True, max_length=3072)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}

        with torch.no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=512,
                do_sample=False,
                temperature=1.0,
                pad_token_id=tok.pad_token_id,
            )

        generated = tok.decode(
            output_ids[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True,
        ).strip()

        score = score_golden_answer(expected, generated)
        match_score = score["keyword_recall"]

        if score["correct"]:
            correct += 1
        golden_results.append({
            "index": i,
            "keyword_recall": score["keyword_recall"],
            "price_match": score["price_match"],
            "correct": score["correct"],
            "expected_prefix": expected[:100],
            "generated_prefix": generated[:100],
        })
        if (i + 1) % 10 == 0:
            log.info("    Processed %d/%d golden QA examples …", i + 1, len(golden))

    golden_recall = correct / max(len(golden_results), 1) * 100
    log.info(
        "    Golden QA keyword recall (+price check): %d/%d (%.1f%%)",
        correct,
        len(golden_results),
        golden_recall,
    )

    # ── 5. Generation quality samples ──────────────────────────────────────────
    log.info("[5/5] Generating sample responses …")
    sample_prompts = [
        "What plans does ApexMail offer and what are the prices?",
        "How do I authenticate with the ApexMail API?",
        "What is the overage rate for the Scale plan?",
        "How do I set up DKIM for my domain?",
        "What compliance certifications does ApexMail have?",
    ]

    system_prompt = (
        "You are ApexMail Agent — the AI support agent for the ApexMail email "
        "platform (Backend: apexmail.ee). Be helpful, accurate, and concise. "
        "Contact: support@apexmail.ee"
    )

    for prompt_text in sample_prompts:
        full_prompt = (
            "<|im_start|>system\n" + system_prompt + "<|im_end|>\n"
            "<|im_start|>user\n" + prompt_text + "<|im_end|>\n"
            "<|im_start|>assistant\n"
        )
        inputs = tok(full_prompt, return_tensors="pt", truncation=True, max_length=2048)
        inputs = {k: v.to(model.device) for k, v in inputs.items()}

        with torch.no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=300,
                do_sample=False,
                temperature=1.0,
                pad_token_id=tok.pad_token_id,
            )

        response = tok.decode(
            output_ids[0][inputs["input_ids"].shape[1]:],
            skip_special_tokens=True,
        ).strip()
        log.info("  Q: %s", prompt_text)
        log.info("  A: %s", response[:300])

    # ── Save results ───────────────────────────────────────────────────────────
    results = {
        "test_loss": avg_loss,
        "test_perplexity": perplexity,
        "test_samples": num_samples,
        # Honest naming: this is keyword recall with an exact-price-match
        # gate for pricing answers, not semantic accuracy.
        "golden_qa_keyword_recall": golden_recall,
        "golden_qa_correct": correct,
        "golden_qa_total": len(golden_results),
        "golden_qa_details": golden_results,
    }
    _EVAL_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(_EVAL_RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)

    log.info(SEP)
    log.info("EVALUATION SUMMARY")
    log.info("  Test Loss:        %.4f", avg_loss)
    log.info("  Test Perplexity:  %.2f", perplexity)
    log.info("  Golden QA recall:  %d/%d (%.1f%%)", correct, len(golden_results), golden_recall)
    log.info("  Results saved to: %s", _EVAL_RESULTS_PATH)
    log.info(SEP)


if __name__ == "__main__":
    main()
