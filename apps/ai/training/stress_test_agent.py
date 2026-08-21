#!/usr/bin/env python3
"""
ApexMail Agent Stress Test Runner
Runs repeated generation over key prompts and reports stability and factual compliance.
"""

import argparse
import json
import re
from statistics import mean


def normalize_text(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation for fuzzy matching."""
    text = text.lower().strip()
    text = re.sub(r"[,\.\!\?\:\;\"\'\-\(\)]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def load_model(base_model_path: str, adapter_path: str | None, device_map: str | None):
    """Load base model + optional LoRA adapter.  Returns (model, tokenizer)."""
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    tokenizer = AutoTokenizer.from_pretrained(base_model_path, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        torch_dtype=torch.bfloat16,
        device_map=device_map or "cpu",
        trust_remote_code=True,
    )
    if adapter_path:
        print(f"Loading adapter from {adapter_path}...")
        model = PeftModel.from_pretrained(model, adapter_path)
    model.eval()
    return model, tokenizer


def generate_response(model, tokenizer, prompt: str, *, max_tokens: int = 256) -> str:
    """Run a single inference turn and return the decoded response text."""
    import torch

    messages = [{"role": "user", "content": prompt}]
    input_ids = tokenizer.apply_chat_template(messages, return_tensors="pt", add_generation_prompt=True)
    input_ids = input_ids.to(model.device)

    with torch.no_grad():
        output_ids = model.generate(
            input_ids,
            max_new_tokens=max_tokens,
            do_sample=False,
            temperature=1.0,
            top_p=1.0,
        )

    new_tokens = output_ids[0][input_ids.shape[-1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True).strip()


STRESS_CASES = [
    {
        "name": "starter_price_and_limits",
        "input": "Summarize Starter pricing and limits in one short paragraph.",
        "must_include": ["€25", "50000", "500000 api"],
        "must_not_include": ["€29", "250000 api"],
    },
    {
        "name": "pro_price_and_limits",
        "input": "Summarize Pro pricing and limits in one short paragraph.",
        "must_include": ["€65", "150000", "2000000 api"],
        "must_not_include": ["€59", "500000 api"],
    },
    {
        "name": "enterprise_compliance",
        "input": "What compliance and API limits does Enterprise include?",
        "must_include": ["hipaa", "soc2", "unlimited api"],
        "must_not_include": ["20000000 api"],
    },
    {
        "name": "overage_rates",
        "input": "What are ApexMail overage rates for emails and API calls?",
        "must_include": ["€0.40", "1000 emails", "€0.10", "1000 api"],
        "must_not_include": ["€0.90", "€1.00"],
    },
]


def check_case(response_text: str, case: dict) -> tuple[bool, list[str]]:
    normalized_response = normalize_text(response_text)
    failures = []

    for include_token in case["must_include"]:
        if normalize_text(include_token) not in normalized_response:
            failures.append(f"missing:{include_token}")

    for forbidden_token in case["must_not_include"]:
        if normalize_text(forbidden_token) in normalized_response:
            failures.append(f"forbidden:{forbidden_token}")

    return len(failures) == 0, failures


def run_stress(model, tokenizer, iterations: int, max_tokens: int, verbose: bool) -> dict:
    detailed_results = []
    case_pass_rates = {}

    for case in STRESS_CASES:
        pass_flags = []
        case_failures = []

        for iteration_index in range(iterations):
            response = generate_response(model, tokenizer, case["input"], max_tokens=max_tokens)
            passed, failures = check_case(response, case)
            pass_flags.append(1 if passed else 0)

            if failures:
                case_failures.append(
                    {
                        "iteration": iteration_index + 1,
                        "failures": failures,
                        "response_preview": response[:240],
                    }
                )

        pass_rate = mean(pass_flags) * 100
        case_pass_rates[case["name"]] = pass_rate

        detailed_results.append(
            {
                "name": case["name"],
                "iterations": iterations,
                "pass_rate": pass_rate,
                "failures": case_failures,
            }
        )

        status = "PASS" if pass_rate == 100 else "WARN" if pass_rate >= 90 else "FAIL"
        print(f"[{status}] {case['name']}: {pass_rate:.1f}%")
        if verbose and case_failures:
            print(f"  First failure: {case_failures[0]}")

    overall_rate = mean(case_pass_rates.values()) if case_pass_rates else 0.0
    print(f"\nOverall stability score: {overall_rate:.1f}%")

    return {
        "iterations": iterations,
        "max_tokens": max_tokens,
        "overall_stability_score": overall_rate,
        "per_case": case_pass_rates,
        "details": detailed_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Stress test ApexMail Agent")
    parser.add_argument("--base-model", required=True, help="Base model path")
    parser.add_argument("--adapter", help="LoRA adapter path")
    parser.add_argument("--auto-device-map", action="store_true", help="Use auto device map")
    parser.add_argument("--iterations", type=int, default=20, help="Generations per test case")
    parser.add_argument("--max-tokens", type=int, default=256, help="Max new tokens per response")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()

    device_map = "auto" if args.auto_device_map else None
    model, tokenizer = load_model(args.base_model, args.adapter, device_map)

    results = run_stress(
        model=model,
        tokenizer=tokenizer,
        iterations=args.iterations,
        max_tokens=args.max_tokens,
        verbose=args.verbose,
    )

    if args.output:
        with open(args.output, "w") as output_file:
            json.dump(results, output_file, indent=2)
        print(f"Saved stress report to {args.output}")


if __name__ == "__main__":
    main()
