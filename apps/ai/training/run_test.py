"""Standalone stress test runner - loads model and runs all tests."""
import sys, json, torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

BASE_DIR = Path("/workspace/ApexMail/apps/ai/training")
ADAPTER_PATH = BASE_DIR / "output"
MODEL_NAME = "Qwen/Qwen2.5-7B-Instruct"

# Use the SAME system prompt from prompts.py that the training data uses.
# This is critical — if the test uses a different prompt, the model can't
# ground its answers in the factual data it learned to reference.
sys.path.insert(0, str(BASE_DIR))
from prompts import SYSTEM_PROMPT

SEP = "=" * 60


def load_model():
    print("Loading base model...")
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
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, cache_dir="/workspace/.hf_home")
    print("Loading adapter...")
    model = PeftModel.from_pretrained(model, str(ADAPTER_PATH))
    model.eval()
    print("Model loaded!")
    return model, tokenizer


def generate(model, tokenizer, question, max_new=512):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": question},
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new,
            temperature=0.3,
            top_p=0.9,
            do_sample=True,
            repetition_penalty=1.15,
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(out[0][inputs.input_ids.shape[-1]:], skip_special_tokens=True).strip()


from stress_test import STRESS_TESTS, grade_response


def run():
    model, tokenizer = load_model()
    results = dict(passed=0, failed=0, categories={}, failures=[])
    total = sum(len(tests) for tests in STRESS_TESTS.values())
    done = 0

    for category, tests in STRESS_TESTS.items():
        cp, cf = 0, 0
        for test in tests:
            done += 1
            q = test["q"]
            checks = test["checks"]
            short_q = q[:60]
            print(f"\n[{done}/{total}] ({category}) {short_q}...")
            resp = generate(model, tokenizer, q)
            result = grade_response(q, resp, checks, category)
            ok = result.get("pass", False)
            if ok:
                cp += 1
                results["passed"] += 1
                print("  PASS")
            else:
                cf += 1
                results["failed"] += 1
                results["failures"].append(
                    dict(
                        category=category,
                        question=q,
                        response=resp[:500],
                        details=result.get("failures", []),
                    )
                )
                print("  FAIL: " + str(result.get("failures", [])))

        tot_cat = cp + cf
        rate = cp / tot_cat * 100 if tot_cat > 0 else 0
        results["categories"][category] = dict(
            passed=cp, failed=cf, rate=round(rate, 1)
        )
        print(f"\n  >> {category}: {cp}/{tot_cat} ({rate:.0f}%)")

    tp = results["passed"]
    tf = results["failed"]
    tt = tp + tf
    overall = tp / tt * 100 if tt > 0 else 0

    print("\n" + SEP)
    print(f"OVERALL: {tp}/{tt} ({overall:.1f}%)")
    print(SEP)
    for cat, r in results["categories"].items():
        rr = r["rate"]
        pp = r["passed"]
        ff = r["failed"]
        tot_c = pp + ff
        print(f"  {cat:25s}: {pp}/{tot_c} ({rr:.0f}%)")

    out_path = BASE_DIR / "stress_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")
    return results


if __name__ == "__main__":
    run()
