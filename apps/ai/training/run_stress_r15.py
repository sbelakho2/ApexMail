#!/usr/bin/env python3
"""
ApexMail R15 Stress Test Runner — runs stress_test.py + stress_test_extra.py
~250 additional stress tests beyond the unified runner's R34 tests.

Usage:
  python3 run_stress_r15.py --base-model /workspace/models/Qwen3-Next-80B-A3B-Instruct \
      --adapter /workspace/output_agent_r15_v2/ --auto-device-map
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(__file__))

from stress_test import STRESS_TESTS
try:
    from stress_test_extra import EXTRA_TESTS
except ImportError:
    EXTRA_TESTS = {}

from prompts_v2 import build_system_prompt


@dataclass
class TestResult:
    test_id: str
    name: str
    category: str
    passed: bool
    response: str = ""
    failures: list = field(default_factory=list)
    duration: float = 0.0


def grade_response(test: dict, response: str) -> list:
    """Grade a response against a stress test's checks."""
    failures = []
    resp_lower = response.lower()
    checks = test.get("checks", test)

    # must_contain — ALL must be present
    for phrase in checks.get("must_contain", []):
        if phrase.lower() not in resp_lower:
            failures.append(f"MISSING required: '{phrase}'")

    # must_contain_any — at least ONE
    any_of = checks.get("must_contain_any", []) or checks.get("must_contain_one_of", [])
    if any_of and not any(p.lower() in resp_lower for p in any_of):
        failures.append(f"MISSING at least one of: {any_of}")

    # must_not_contain — NONE should be present
    for phrase in checks.get("must_not_contain", []):
        if phrase and phrase.lower() in resp_lower:
            failures.append(f"FORBIDDEN found: '{phrase}'")

    # must_match_regex
    for pattern in checks.get("must_match_regex", []):
        if not re.search(pattern, response):
            failures.append(f"REGEX not matched: '{pattern}'")

    return failures


def run_inference(model, tokenizer, question: str, device="cuda:0") -> str:
    import torch

    system_prompt = build_system_prompt("no_context")
    prompt = (
        f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
        f"<|im_start|>user\n{question}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )

    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096)
    inputs = {k: v.to(device) for k, v in inputs.items()}

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=768,
            do_sample=False,
            repetition_penalty=1.15,
            eos_token_id=tokenizer.convert_tokens_to_ids("<|im_end|>"),
            pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
        )

    full_text = tokenizer.decode(outputs[0], skip_special_tokens=False)
    response = ""
    if "<|im_start|>assistant\n" in full_text:
        response = full_text.split("<|im_start|>assistant\n")[-1]
        if "<|im_end|>" in response:
            response = response.split("<|im_end|>")[0]
    return response.strip()


def main():
    parser = argparse.ArgumentParser(description="R15 Stress Test Runner (~250 tests)")
    parser.add_argument("--adapter", type=str, required=True)
    parser.add_argument("--base-model", type=str, default="/workspace/models/Qwen3-Next-80B-A3B-Instruct")
    parser.add_argument("--device", type=str, default="cuda:0")
    parser.add_argument("--auto-device-map", action="store_true")
    parser.add_argument("--output", type=str, default="test_results_r15_stress.json")
    parser.add_argument("--category", type=str, help="Run one category only")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    # Merge all stress tests
    all_tests = {}
    all_tests.update(STRESS_TESTS)
    for k, v in EXTRA_TESTS.items():
        if k in all_tests:
            all_tests[k].extend(v)
        else:
            all_tests[k] = v

    # Build flat test list
    test_list = []
    for category, tests in all_tests.items():
        if args.category and category != args.category:
            continue
        for i, t in enumerate(tests):
            test_list.append((category, i, t))

    print(f"Total stress tests: {len(test_list)} across {len(all_tests)} categories")

    if args.dry_run:
        for cat in sorted(all_tests):
            print(f"  {cat}: {len(all_tests[cat])}")
        return

    # Load model
    print("Loading model...")
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    dmap = "auto" if args.auto_device_map else args.device
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.bfloat16,
        device_map=dmap,
        trust_remote_code=True,
    )
    print(f"Loading adapter from {args.adapter}...")
    model = PeftModel.from_pretrained(base_model, args.adapter)
    model.eval()

    print(f"\nRunning {len(test_list)} stress tests...\n")

    all_results = []
    t0 = time.time()

    for idx, (category, test_idx, test) in enumerate(test_list):
        start = time.time()
        question = test.get("q", test.get("question", ""))
        test_id = f"stress_{category}_{test_idx+1:03d}"

        response = run_inference(model, tokenizer, question, args.device)
        fails = grade_response(test, response)

        result = TestResult(
            test_id=test_id,
            name=f"{category}_{test_idx+1}",
            category=category,
            passed=len(fails) == 0,
            response=response[:500],
            failures=fails,
            duration=time.time() - start,
        )
        all_results.append(result)

        icon = "✅" if result.passed else "❌"
        print(f"  [{idx+1}/{len(test_list)}] {icon} {test_id} ({category}) [{result.duration:.1f}s]")
        if not result.passed:
            for f in fails:
                print(f"      ⚠ {f}")

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 70)
    passed = sum(1 for r in all_results if r.passed)
    total = len(all_results)
    pct = 100 * passed / total if total else 0
    print(f"STRESS TESTS: {passed}/{total} ({pct:.1f}%) in {elapsed:.0f}s\n")

    # By category
    categories = {}
    for r in all_results:
        if r.category not in categories:
            categories[r.category] = {"passed": 0, "total": 0}
        categories[r.category]["total"] += 1
        if r.passed:
            categories[r.category]["passed"] += 1

    for key in sorted(categories):
        c = categories[key]
        p, t = c["passed"], c["total"]
        cpct = 100 * p / t if t else 0
        bar = "█" * int(cpct / 5) + "░" * (20 - int(cpct / 5))
        print(f"  {key:40s} {p:3d}/{t:3d} {cpct:5.1f}% {bar}")

    # Failed tests
    failed = [r for r in all_results if not r.passed]
    if failed:
        print(f"\n{'='*70}")
        print(f"FAILED TESTS ({len(failed)}):\n")
        for r in failed[:30]:
            print(f"  {r.category} | {r.test_id}")
            for f in r.failures:
                print(f"    → {f}")
            if r.response:
                preview = r.response[:200].replace("\n", " ")
                print(f"    Response: {preview}...")
            print()

    # Write results
    output = {
        "summary": {
            "passed": passed,
            "total": total,
            "percentage": round(pct, 1),
            "elapsed_seconds": round(elapsed, 1),
            "by_category": categories,
        },
        "results": [
            {
                "id": r.test_id,
                "name": r.name,
                "category": r.category,
                "passed": r.passed,
                "failures": r.failures,
                "response_preview": r.response,
                "duration": round(r.duration, 2),
            }
            for r in all_results
        ],
    }
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {args.output}")


if __name__ == "__main__":
    main()
