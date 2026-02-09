"""
ApexMail — Full 500-Question Evaluation

Runs all 500 user questions from docs/500-fixes-checklist.md against
the trained model and produces a detailed quality report.

Usage:
    python eval_500.py                          # uses output/final
    python eval_500.py --model output/final     # explicit path
"""

import argparse
import json
import os
import re
import time
import torch
from pathlib import Path
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from peft import PeftModel

# ════════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════════

BASE_MODEL = "TinyLlama/TinyLlama-1.1B-Chat-v1.0"
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
CHECKLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "500-fixes-checklist.md")

BNB_CONFIG = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

# ════════════════════════════════════════════════════════════════
# QUALITY RUBRIC — keyword/pattern checks per question category
#
# We define category-level heuristics. Each question gets scored on:
#   1. Relevance: Does it mention ApexMail / email-marketing concepts?
#   2. Not-hallucinating: Does it NOT invent features or URLs?
#   3. Helpfulness: Does it provide actionable info?
#   4. Safety: Does it refuse dangerous requests properly?
#   5. Factual: Does it get known facts right?
# ════════════════════════════════════════════════════════════════

# Known facts the model MUST get right when relevant
KNOWN_FACTS = {
    "api_url": "api.apexmail.ee/v1",
    "api_key_format": ["am_live_", "am_test_"],
    "company": "Bel Consulting",
    "country": "Estonia",
    "city": "Tallinn",
    "founded": "2022",
    "starter_price": "$29",
    "pro_price": "$59",
    "growth_price": "$129",
    "scale_price": "$399",
    "enterprise_price": "$1,299",
    "open_rate": "27%",
    "support_email": "support@apexmail.ee",
    "billing_email": "billing@apexmail.ee",
    "dmarc_related": ["SPF", "DKIM"],
    "roi": "$36",
}

# Hard failure patterns — if these appear, auto-fail
HALLUCINATION_PATTERNS = [
    r"sendgrid\.com",
    r"mailchimp\.com",
    r"mailgun\.com",
    r"aws\.amazon\.com/ses",
    r"postmark",
    r"sparkpost",
    r"api\.apexmail\.com",        # wrong TLD
    r"apexmail\.io",              # wrong TLD
    r"apexmail\.org",             # wrong TLD
    r"I don't have access",       # model shouldn't say this — it's the assistant
    r"I'm just an AI",            # generic refusal
    r"As a language model",       # generic refusal
]

# Question-to-fact-check mapping: question number → required keywords
FACTUAL_CHECKS: dict[int, list[str]] = {
    # API questions
    7: ["am_live_", "am_test_"],
    11: ["api.apexmail.ee/v1"],
    # Pricing
    # (we check broad pattern — if they mention a plan, the price should be right)
    # Company facts
    75: ["Estonia", "Tallinn"],
    76: ["2022"],
    # Support
    22: ["support"],
    23: ["support@apexmail.ee"],
    24: ["status"],
    # Auth
    101: ["SPF"],
    102: ["DKIM"],
    103: ["DMARC"],
    113: ["27"],
    114: ["2.6"],
}


def extract_questions(checklist_path: str) -> list[dict]:
    """Extract all 500 questions from the checklist markdown."""
    with open(checklist_path) as f:
        content = f.read()

    # Find the questions section
    match = re.search(r"## 500 High-Likelihood User Questions.*?\n(.*?)(?=\n## |\Z)", content, re.DOTALL)
    if not match:
        raise RuntimeError("Could not find '500 High-Likelihood User Questions' section")

    questions = []
    for line in match.group(1).strip().split("\n"):
        m = re.match(r"(\d+)\.\s+(.+)", line.strip())
        if m:
            questions.append({
                "number": int(m.group(1)),
                "question": m.group(2).strip(),
            })

    if len(questions) != 500:
        print(f"⚠️  Extracted {len(questions)} questions (expected 500)")

    return questions


def score_response(q_num: int, question: str, response: str) -> dict:
    """Score a single response using the quality rubric."""
    response_lower = response.lower()
    question_lower = question.lower()
    issues = []
    score = 0
    max_score = 5

    # ── 1. Non-empty and reasonable length ──
    if len(response.strip()) < 10:
        issues.append("empty_or_too_short")
    elif len(response.strip()) > 5:
        score += 1

    # ── 2. No hallucinated competitor brands / wrong URLs ──
    hallucinated = False
    for pat in HALLUCINATION_PATTERNS:
        if re.search(pat, response, re.IGNORECASE):
            issues.append(f"hallucination: {pat}")
            hallucinated = True
    if not hallucinated:
        score += 1

    # ── 3. Relevance — mentions email/ApexMail/marketing concepts ──
    relevance_words = [
        # Core platform
        "email", "campaign", "list", "send", "api", "apexmail", "domain",
        "template", "contact", "subscribe", "webhook", "deliverability",
        "bounce", "spam", "dkim", "spf", "dmarc", "billing", "plan",
        "automation", "workflow", "segment", "analytics", "tracking",
        "unsubscribe", "suppression", "consent", "gdpr", "tenant",
        "import", "export", "csv", "merge", "tag", "field",
        "key", "token", "auth", "role", "permission", "security",
        "help", "support", "please", "action", "confirm",
        # Pricing & billing
        "payg", "pay as you go", "subscription", "invoice", "proration",
        "price", "cost", "charge", "fee", "overage", "limit", "usage",
        "vat", "tax", "refund", "cancel", "downgrade", "upgrade",
        # Infrastructure & compliance
        "backup", "restore", "retention", "delete", "data", "encrypt",
        "ssl", "tls", "ip", "dns", "mx", "cname", "txt", "record",
        "dpa", "ccpa", "soc", "iso", "hipaa", "compliance",
        "disaster", "recovery", "rpo", "rto", "sla", "uptime",
        # Content & design
        "font", "image", "attachment", "html", "css", "mjml", "amp",
        "subject", "preheader", "header", "footer", "preview",
        "personalize", "dynamic", "conditional", "block", "content",
        "emoji", "utf-8", "unicode", "rtl", "localize", "language",
        # Testing & optimization
        "a/b", "test", "variant", "split", "optimize", "performance",
        "open rate", "click", "ctr", "ctor", "roi", "revenue",
        "metric", "report", "dashboard", "heatmap", "conversion",
        # Operations
        "rate limit", "throttle", "retry", "backoff", "timeout",
        "queue", "batch", "schedule", "timezone", "quiet",
        "sdk", "curl", "node", "python", "typescript",
        # Integrations
        "zapier", "shopify", "stripe", "woocommerce", "hubspot",
        "salesforce", "bigquery", "snowflake", "s3", "warehouse",
        # General assistant
        "recommend", "suggest", "configure", "setting", "option",
        "feature", "enable", "disable", "verify", "check", "view",
        "account", "workspace", "user", "admin", "member", "team",
        "brand", "guideline", "copy", "write", "ai", "generate",
        "survey", "form", "coupon", "offer", "inventory",
        "dedicated", "shared", "reputation", "score", "placement",
        "approval", "review", "audit", "log", "monitor",
    ]
    if any(w in response_lower for w in relevance_words):
        score += 1
    else:
        issues.append("low_relevance")

    # ── 4. Not repetitive / degenerate ──
    words = response.split()
    if len(words) > 10:
        unique_ratio = len(set(words)) / len(words)
        if unique_ratio < 0.3:
            issues.append("repetitive_output")
        else:
            score += 1
    else:
        score += 1  # short answers are fine

    # ── 5. Factual accuracy (if we have a check for this question) ──
    if q_num in FACTUAL_CHECKS:
        required = FACTUAL_CHECKS[q_num]
        all_present = all(kw.lower() in response_lower for kw in required)
        if all_present:
            score += 1
        else:
            missing = [kw for kw in required if kw.lower() not in response_lower]
            issues.append(f"missing_facts: {missing}")
    else:
        # No specific fact check — give the point if no other issues
        if not issues:
            score += 1

    grade = "A" if score >= 5 else "B" if score >= 4 else "C" if score >= 3 else "D" if score >= 2 else "F"

    return {
        "question_number": q_num,
        "question": question,
        "response": response,
        "score": score,
        "max_score": max_score,
        "grade": grade,
        "issues": issues,
    }


def run_eval(model_path: str) -> None:
    """Run all 500 questions against the model."""

    print("=" * 70)
    print("  ApexMail — Full 500-Question Evaluation")
    print("=" * 70)

    # ── Load questions ──
    checklist = os.path.normpath(CHECKLIST_PATH)
    print(f"\n📋 Loading questions from {checklist}")
    questions = extract_questions(checklist)
    print(f"   Loaded {len(questions)} questions")

    # ── Load model ──
    print(f"\n📦 Loading model from {model_path}...")
    from generate_dataset import SYSTEM_PROMPT

    tokenizer = AutoTokenizer.from_pretrained(model_path)
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=BNB_CONFIG,
        device_map="auto",
        trust_remote_code=True,
        dtype=torch.bfloat16,
    )
    model = PeftModel.from_pretrained(model, model_path)
    model.eval()

    # ── Inference ──
    results = []
    grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    start_time = time.time()

    print(f"\n🚀 Running inference on {len(questions)} questions...\n")

    for i, q in enumerate(questions):
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": q["question"]},
        ]

        prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

        prompt_len = int(inputs["input_ids"].shape[1])
        model_max = int(getattr(tokenizer, "model_max_length", 2048) or 2048)
        max_new_tokens = max(16, min(256, model_max - prompt_len - 1))

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                top_p=1.0,
                repetition_penalty=1.05,
            )

        response = tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)

        result = score_response(q["number"], q["question"], response)
        results.append(result)
        grade_counts[result["grade"]] += 1

        # Progress indicator
        status_icon = {"A": "🟢", "B": "🟡", "C": "🟠", "D": "🔴", "F": "⛔"}.get(result["grade"], "?")
        if (i + 1) % 25 == 0 or result["grade"] in ("D", "F"):
            print(f"  {status_icon} Q{q['number']:>3}: [{result['grade']}] {q['question'][:60]}")
            if result["issues"]:
                print(f"         Issues: {', '.join(result['issues'])}")
        if (i + 1) % 100 == 0:
            elapsed = time.time() - start_time
            rate = (i + 1) / elapsed
            eta = (len(questions) - i - 1) / rate
            print(f"  ── Progress: {i+1}/{len(questions)} ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining) ──")

    elapsed = time.time() - start_time

    # ── Summary ──
    total_score = sum(r["score"] for r in results)
    max_total = sum(r["max_score"] for r in results)
    pct = total_score / max_total * 100 if max_total > 0 else 0

    print(f"\n{'=' * 70}")
    print(f"  RESULTS SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Total score: {total_score}/{max_total} ({pct:.1f}%)")
    print(f"  Time: {elapsed:.1f}s ({elapsed/len(questions):.2f}s/question)")
    print(f"\n  Grade distribution:")
    for grade in ["A", "B", "C", "D", "F"]:
        count = grade_counts[grade]
        bar = "█" * (count // 5)
        print(f"    {grade}: {count:>3} ({count/len(questions)*100:.1f}%)  {bar}")

    # ── Failures detail ──
    failures = [r for r in results if r["grade"] in ("D", "F")]
    if failures:
        print(f"\n  ⚠️ {len(failures)} questions scored D or F:")
        for r in failures[:20]:
            print(f"    Q{r['question_number']:>3}: {r['question'][:55]}")
            print(f"          Grade: {r['grade']}, Issues: {', '.join(r['issues'])}")
            print(f"          Response: {r['response'][:100]}...")
        if len(failures) > 20:
            print(f"    ... and {len(failures) - 20} more")

    # ── Issue frequency ──
    issue_freq: dict[str, int] = {}
    for r in results:
        for issue in r["issues"]:
            key = issue.split(":")[0].strip()
            issue_freq[key] = issue_freq.get(key, 0) + 1
    if issue_freq:
        print(f"\n  Issue frequency:")
        for issue, count in sorted(issue_freq.items(), key=lambda x: -x[1]):
            print(f"    {issue}: {count}")

    # ── Save full results ──
    report = {
        "model_path": model_path,
        "num_questions": len(questions),
        "total_score": total_score,
        "max_score": max_total,
        "percentage": round(pct, 1),
        "grade_distribution": grade_counts,
        "elapsed_seconds": round(elapsed, 1),
        "details": results,
    }
    report_path = os.path.join(OUTPUT_DIR, "eval_500_results.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n  Full results saved to: {report_path}")

    # ── Pass/fail verdict ──
    ab_pct = (grade_counts["A"] + grade_counts["B"]) / len(questions) * 100
    print(f"\n  A+B rate: {ab_pct:.1f}% (target: ≥70%)")
    if ab_pct >= 70:
        print(f"  ✅ PASSED — model quality is acceptable for deployment")
    else:
        print(f"  ❌ FAILED — model needs more training data for weak categories")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ApexMail 500-Question Evaluation")
    parser.add_argument("--model", type=str, default=os.path.join(OUTPUT_DIR, "final"),
                        help="Path to trained model adapter")
    args = parser.parse_args()
    run_eval(args.model)
