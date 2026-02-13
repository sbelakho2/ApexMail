"""Parallel stress test runner — splits tests across 2 GPUs for 2× speed."""
import sys, json, os, torch, multiprocessing as mp
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE_DIR = Path("/workspace/ApexMail/apps/ai/training")
ADAPTER_PATH = BASE_DIR / "output"
MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct"

sys.path.insert(0, str(BASE_DIR))
from prompts import SYSTEM_PROMPT
from stress_test import STRESS_TESTS, grade_response

try:
    from stress_test_extra import EXTRA_TESTS
    for k, v in EXTRA_TESTS.items():
        if k in STRESS_TESTS:
            STRESS_TESTS[k].extend(v)
        else:
            STRESS_TESTS[k] = v
    print(f"Loaded {sum(len(v) for v in EXTRA_TESTS.values())} extra tests")
except ImportError:
    print("No extra tests found")

SEP = "=" * 60


def flatten_tests():
    """Flatten all tests into a list of (index, category, test_dict)."""
    flat = []
    idx = 0
    for category, tests in STRESS_TESTS.items():
        for test in tests:
            flat.append((idx, category, test))
            idx += 1
    return flat


def worker(gpu_id, test_items, total, result_queue):
    """Worker process: loads model on specific GPU and runs assigned tests."""
    os.environ["CUDA_VISIBLE_DEVICES"] = str(gpu_id)

    print(f"[GPU {gpu_id}] Loading model...")
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
    )
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb,
        device_map="auto",
        attn_implementation="sdpa",
        cache_dir="/workspace/.hf_home",
    )
    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME, cache_dir="/workspace/.hf_home"
    )
    model = PeftModel.from_pretrained(model, str(ADAPTER_PATH))
    model.eval()
    print(f"[GPU {gpu_id}] Model loaded! Processing {len(test_items)} tests...")

    results = []
    for idx, category, test in test_items:
        q = test["q"]
        checks = test["checks"]
        short_q = q[:60]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": q},
        ]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer(text, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inputs,
                max_new_tokens=512,
                temperature=0.3,
                top_p=0.9,
                do_sample=True,
                repetition_penalty=1.15,
                pad_token_id=tokenizer.eos_token_id,
            )
        resp = tokenizer.decode(
            out[0][inputs.input_ids.shape[-1] :], skip_special_tokens=True
        ).strip()

        result = grade_response(q, resp, checks, category)
        ok = result.get("pass", False)
        tag = "PASS" if ok else "FAIL: " + str(result.get("failures", []))
        print(f"[{idx+1}/{total}] ({category}) {short_q}...\n  {tag}")

        results.append(
            dict(
                idx=idx,
                category=category,
                question=q,
                response=resp[:500],
                passed=ok,
                failures=result.get("failures", []),
            )
        )

    result_queue.put(results)
    print(f"[GPU {gpu_id}] Done — {len(results)} tests complete.")


def run():
    all_tests = flatten_tests()
    total = len(all_tests)
    print(f"Total tests: {total}")

    # Split evenly across 2 GPUs
    mid = total // 2
    gpu0_tests = all_tests[:mid]
    gpu1_tests = all_tests[mid:]
    print(f"GPU 0: {len(gpu0_tests)} tests | GPU 1: {len(gpu1_tests)} tests")

    ctx = mp.get_context("spawn")
    q = ctx.Queue()

    p0 = ctx.Process(target=worker, args=(0, gpu0_tests, total, q))
    p1 = ctx.Process(target=worker, args=(1, gpu1_tests, total, q))

    p0.start()
    p1.start()
    p0.join()
    p1.join()

    # Collect results
    all_results = []
    while not q.empty():
        all_results.extend(q.get())

    # Sort by original index
    all_results.sort(key=lambda r: r["idx"])

    # Aggregate
    passed = sum(1 for r in all_results if r["passed"])
    failed = total - passed
    categories = {}
    failures = []

    for r in all_results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = dict(passed=0, failed=0)
        if r["passed"]:
            categories[cat]["passed"] += 1
        else:
            categories[cat]["failed"] += 1
            failures.append(r)

    overall = passed / total * 100 if total > 0 else 0

    print("\n" + SEP)
    print(f"OVERALL: {passed}/{total} ({overall:.1f}%)")
    print(SEP)
    for cat, cr in categories.items():
        cp = cr["passed"]
        cf = cr["failed"]
        ct = cp + cf
        cr["rate"] = round(cp / ct * 100, 1) if ct > 0 else 0
        print(f"  {cat:25s}: {cp}/{ct} ({cr['rate']:.0f}%)")

    # Save results
    out = dict(passed=passed, failed=failed, categories=categories, failures=failures)
    out_path = BASE_DIR / "stress_results.json"
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nResults saved to {out_path}")
    return out


if __name__ == "__main__":
    run()
