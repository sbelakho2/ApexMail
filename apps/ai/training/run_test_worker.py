"""Single-GPU worker for parallel stress testing.
Usage: CUDA_VISIBLE_DEVICES=X python3 run_test_worker.py <start_idx> <end_idx> <output_file> [total]
"""
import sys, json, os, gc, tempfile, shutil
import torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE_DIR = Path("/workspace/ApexMail/apps/ai/training")
ADAPTER_PATH = BASE_DIR / "output"
MODEL_NAME = "/workspace/models/Qwen3-8B"

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
except ImportError:
    pass


def flatten_tests():
    flat = []
    for category, tests in STRESS_TESTS.items():
        for test in tests:
            flat.append((category, test))
    return flat


def main():
    start_idx = int(sys.argv[1])
    end_idx = int(sys.argv[2])
    output_file = sys.argv[3]
    total = int(sys.argv[4]) if len(sys.argv) > 4 else end_idx
    gpu = os.environ.get("CUDA_VISIBLE_DEVICES", "?")

    all_tests = flatten_tests()
    my_tests = all_tests[start_idx:end_idx]
    print(f"[GPU {gpu}] Loading model for tests {start_idx}-{end_idx} ({len(my_tests)} tests)...", flush=True)

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME, quantization_config=bnb, device_map="auto",
        attn_implementation="sdpa", cache_dir="/workspace/.hf_home",
    )
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir="/workspace/.hf_home")
    model = PeftModel.from_pretrained(model, str(ADAPTER_PATH))
    model.eval()
    print(f"[GPU {gpu}] Model loaded!", flush=True)

    results = []
    for i, (category, test) in enumerate(my_tests):
        idx = start_idx + i
        q = test["q"]
        checks = test["checks"]

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": q},
        ]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True, enable_thinking=False)
        inputs = tokenizer(text, return_tensors="pt").to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inputs, max_new_tokens=768, do_sample=False,
                repetition_penalty=1.15, pad_token_id=tokenizer.eos_token_id,
            )
        resp = tokenizer.decode(out[0][inputs.input_ids.shape[-1]:], skip_special_tokens=True).strip()

        result = grade_response(q, resp, checks, category)
        ok = result.get("pass", False)
        tag = "PASS" if ok else "FAIL: " + str(result.get("failures", []))
        print(f"[{idx+1}/{total}] ({category}) {q[:60]}...\n  {tag}", flush=True)

        results.append(dict(
            idx=idx, category=category, question=q,
            response=resp[:500], passed=ok,
            failures=result.get("failures", []),
        ))

    # Free GPU memory BEFORE writing JSON to avoid cleanup hangs
    del model
    del tokenizer
    gc.collect()
    torch.cuda.empty_cache()

    # Atomic write: write to temp file then rename
    passed = sum(1 for r in results if r["passed"])
    output_dir = os.path.dirname(output_file) or "/tmp"
    fd, tmp_path = tempfile.mkstemp(dir=output_dir, suffix=".json.tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(results, f, indent=2)
        shutil.move(tmp_path, output_file)
        print(f"[GPU {gpu}] Results written to {output_file}", flush=True)
    except Exception as e:
        print(f"[GPU {gpu}] ERROR writing results: {e}", flush=True)
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    print(f"[GPU {gpu}] Done: {passed}/{len(results)} passed", flush=True)
    os._exit(0)  # Hard exit to avoid model destructor hangs


if __name__ == "__main__":
    main()
