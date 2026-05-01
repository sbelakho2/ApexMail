#!/usr/bin/env python3
"""
Evaluate the trained LoRA adapter on test set + golden QA.
Tests: generation quality, loss on test set, golden QA accuracy.
"""
import os, json, time, torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
from datasets import load_dataset
from training_data import expand_system_prompt_refs

MODEL_PATH  = "/workspace/models/Qwen3-Next-80B-A3B-Instruct"
ADAPTER_DIR = "/workspace/output_agent"
TEST_DATA   = "/workspace/data/test.jsonl"
GOLDEN_QA   = "/workspace/data/golden_qa.jsonl"

SEP = "=" * 70


def main():
    print(SEP)
    print("ApexMail Agent - Post-Training Evaluation")
    print(SEP)

    # Load tokenizer
    print("\n[1/5] Loading tokenizer...")
    tok = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    # Load base model + adapter
    print("[2/5] Loading base model + LoRA adapter...")
    t0 = time.time()
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
        attn_implementation="eager",
        device_map="auto",
        low_cpu_mem_usage=True,
    )
    model = PeftModel.from_pretrained(model, ADAPTER_DIR)
    model.eval()
    print(f"    Loaded in {time.time()-t0:.1f}s")

    # Evaluate test set loss
    print("[3/5] Computing test set loss...")
    test_ds = load_dataset("json", data_files=TEST_DATA, split="train")
    test_ds = expand_system_prompt_refs(test_ds, TEST_DATA)
    total_loss = 0
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
            print(f"    Processed {i+1}/{num_samples} test examples...")

    avg_loss = total_loss / total_tokens
    perplexity = torch.exp(torch.tensor(avg_loss)).item()
    print(f"    Test loss: {avg_loss:.4f}")
    print(f"    Test perplexity: {perplexity:.2f}")

    # Golden QA evaluation
    print("[4/5] Evaluating on golden QA set...")
    with open(GOLDEN_QA) as f:
        golden = [json.loads(line) for line in f]

    golden_results = []
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
            # Build prompt from all messages except last assistant response
            prompt_parts = []
            expected = ""
            for msg in msgs:
                role = msg["role"]
                content = msg["content"]
                if role == "assistant" and msg == msgs[-1]:
                    expected = content[:200]
                else:
                    prompt_parts.append(
                        f"<|im_start|>{role}\n{content}<|im_end|>"
                    )
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

        # Check if key terms from expected are in generated
        expected_lower = expected.lower()
        generated_lower = generated.lower()

        # Simple keyword matching for correctness
        key_terms = [t.strip() for t in expected_lower.split() if len(t.strip()) > 4][:10]
        matches = sum(1 for t in key_terms if t in generated_lower)
        match_score = matches / max(len(key_terms), 1)
        is_correct = match_score > 0.3

        if is_correct:
            correct += 1
        golden_results.append({
            "index": i,
            "match_score": round(match_score, 2),
            "correct": is_correct,
            "expected_prefix": expected[:100],
            "generated_prefix": generated[:100],
        })
        if (i + 1) % 10 == 0:
            print(f"    Processed {i+1}/{len(golden)} golden QA examples...")

    golden_accuracy = correct / max(len(golden_results), 1) * 100
    print(f"    Golden QA accuracy: {correct}/{len(golden_results)} ({golden_accuracy:.1f}%)")

    # Generation quality samples
    print("[5/5] Generating sample responses...")
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
        print(f"\n  Q: {prompt_text}")
        print(f"  A: {response[:300]}")

    # Save results
    results = {
        "test_loss": avg_loss,
        "test_perplexity": perplexity,
        "test_samples": num_samples,
        "golden_qa_accuracy": golden_accuracy,
        "golden_qa_correct": correct,
        "golden_qa_total": len(golden_results),
        "golden_qa_details": golden_results,
    }
    with open("/workspace/output_agent/eval_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + SEP)
    print("EVALUATION SUMMARY")
    print(f"  Test Loss:        {avg_loss:.4f}")
    print(f"  Test Perplexity:  {perplexity:.2f}")
    print(f"  Golden QA:        {correct}/{len(golden_results)} ({golden_accuracy:.1f}%)")
    print(f"  Results saved to: /workspace/output_agent/eval_results.json")
    print(SEP)


if __name__ == "__main__":
    main()
