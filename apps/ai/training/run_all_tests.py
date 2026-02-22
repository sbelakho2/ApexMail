#!/usr/bin/env python3
"""
ApexMail Unified Test Runner — runs BOTH test suites:
  1. test_agent.py  (189 tests, 14 categories)
  2. stress_test_r34.py (171 tests, 26 categories)
Total: 360 tests (340+ single-turn + multi-turn)

Usage on remote (8× B200):
  python run_all_tests.py --adapter output/
  python run_all_tests.py --adapter output/ --suite agent      # only test_agent
  python run_all_tests.py --adapter output/ --suite stress     # only stress_test
  python run_all_tests.py --adapter output/ --category safety  # single category
  python run_all_tests.py --dry-run                            # validate structure only
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, os.path.dirname(__file__))

from test_agent import ALL_TESTS as AGENT_TESTS
from stress_test_r34 import R34_TESTS
from prompts_v2 import build_system_prompt

# ──────────────────────────────────────────────────────────────
# Mock tool results (shared with run_test_agent.py)
# ──────────────────────────────────────────────────────────────
MOCK_TOOL_RESULTS = {
    "get_dns_records": {
        "marketing.techflow.io": '{"domain":"marketing.techflow.io","records":{"spf":{"status":"pass"},"dkim":{"status":"missing","expected_host":"apexmail._domainkey.marketing.techflow.io"},"dmarc":{"status":"fail"}}}',
    },
    "search_events": '{"events":[{"message_id":"msg_test1","status":"delivered","opened":false}]}',
    "get_suppression_status": '{"email":"test@example.com","suppressed":true,"reason":"unsubscribe"}',
    "list_webhooks": '{"webhooks":[{"id":"wh_1","url":"https://example.com/webhook","status":"failing","last_status_code":404}]}',
    "get_usage_stats": '{"plan":"Scale","emails":{"used":425000,"limit":500000},"api_calls":{"used":3200000,"limit":5000000},"days_remaining":10}',
    "get_deliverability_report": '{"overall_score":62,"delivery_rate":92.0,"bounce_rate":4.7,"complaint_rate":0.13}',
    "check_blocklist": '{"ip":"198.51.100.12","listings":[{"blocklist":"Spamhaus SBL","listed":true}]}',
    "get_analytics_dashboard": '{"emails_sent":1450000,"delivery_rate":99.0,"bounce_rate":0.5}',
    "get_campaign_stats": '{"campaign":"Test Campaign","sent":10000,"delivered":9800}',
    "list_automations": '{"automations":[{"name":"Welcome Series","status":"active"}]}',
    "get_message_status": '{"message_id":"msg_test","status":"deferred","attempts":3}',
    "get_domain_health": '{"domain":"example.com","spf":"pass","dkim":"pass","dmarc":"pass"}',
    "get_domain_status": '{"domain":"example.com","status":"verified"}',
    "list_contacts": '{"contacts":[{"email":"test@example.com","tags":["customer"]}]}',
    "get_contact": '{"email":"test@example.com","tags":["customer"]}',
    "get_message_events": '{"events":[{"type":"delivered","timestamp":"2026-02-18T10:00:00Z"}]}',
    "get_webhook_deliveries": '{"deliveries":[{"status":404,"timestamp":"2026-02-18T10:00:00Z"}]}',
}


@dataclass
class TestResult:
    test_id: str
    name: str
    category: str
    suite: str  # "agent" or "stress"
    passed: bool
    response: str = ""
    failures: list = field(default_factory=list)
    duration: float = 0.0


def extract_tool_call(response: str) -> Optional[dict]:
    pattern = r'```tool_call\s*\n(.*?)\n```'
    match = re.search(pattern, response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
    return None


def check_test(test: dict, response: str) -> list:
    """Run all checks, return list of failure strings."""
    failures = []
    resp_lower = response.lower()

    # must_contain — ALL must be present
    for phrase in test.get("must_contain", []):
        if phrase.lower() not in resp_lower:
            failures.append(f"MISSING required: '{phrase}'")

    # must_contain_one_of / must_contain_any — at least ONE
    one_of = test.get("must_contain_one_of", []) or test.get("must_contain_any", [])
    if one_of and not any(p.lower() in resp_lower for p in one_of):
        failures.append(f"MISSING at least one of: {one_of}")

    # must_contain_one_of_2 — second group, at least ONE
    one_of_2 = test.get("must_contain_one_of_2", [])
    if one_of_2 and not any(p.lower() in resp_lower for p in one_of_2):
        failures.append(f"MISSING at least one of (group 2): {one_of_2}")

    # must_not_contain — NONE should be present
    for phrase in test.get("must_not_contain", []):
        if phrase and phrase.lower() in resp_lower:
            failures.append(f"FORBIDDEN found: '{phrase}'")

    # must_match_regex
    for pattern in test.get("must_match_regex", []):
        if not re.search(pattern, response):
            failures.append(f"REGEX not matched: '{pattern}'")

    # is_clarification
    if test.get("is_clarification") and "?" not in response:
        failures.append("CLARIFICATION expected but no '?' found")

    # tool_call_check
    tc = test.get("tool_call_check")
    if tc:
        tool_data = extract_tool_call(response)
        if tool_data is None:
            failures.append("TOOL_CALL expected but no valid ```tool_call``` block found")
        else:
            actual_tool = tool_data.get("tool", "")
            if "required_tool" in tc and actual_tool != tc["required_tool"]:
                failures.append(f"TOOL wrong: expected '{tc['required_tool']}', got '{actual_tool}'")
            if "required_tool_one_of" in tc and actual_tool not in tc["required_tool_one_of"]:
                failures.append(f"TOOL wrong: expected one of {tc['required_tool_one_of']}, got '{actual_tool}'")
            params = tool_data.get("params", {})
            for param in tc.get("required_params", []):
                if param not in params:
                    failures.append(f"PARAM missing: '{param}'")
            if "required_params_one_of" in tc and not any(p in params for p in tc["required_params_one_of"]):
                failures.append(f"PARAM missing: need one of {tc['required_params_one_of']}")

    return failures


# ──────────────────────────────────────────────────────────────
# Convert stress_test_r34 tests → unified format
# ──────────────────────────────────────────────────────────────
def normalize_stress_tests() -> dict:
    """Convert R34_TESTS into the same format as test_agent ALL_TESTS."""
    result = {}
    for section, tests in R34_TESTS.items():
        normalized = []
        for i, t in enumerate(tests):
            checks = t.get("checks", {})
            entry = {
                "id": f"r34_{section}_{i+1:03d}",
                "name": f"{section}_{i+1}",
                "context": "no_context",
                "question": t["q"],
            }
            if "must_contain" in checks:
                entry["must_contain"] = checks["must_contain"]
            if "must_contain_any" in checks:
                entry["must_contain_one_of"] = checks["must_contain_any"]
            if "must_not_contain" in checks:
                entry["must_not_contain"] = checks["must_not_contain"]
            normalized.append(entry)
        result[f"r34_{section}"] = normalized
    return result


# ──────────────────────────────────────────────────────────────
# Inference
# ──────────────────────────────────────────────────────────────
def run_inference(model, tokenizer, test: dict, device="cuda:0") -> str:
    import torch

    ctx_key = test.get("context", "no_context")
    system_prompt = build_system_prompt(ctx_key)
    question = test["question"]

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


def run_multiturn_test(model, tokenizer, test: dict, device="cuda:0") -> list[TestResult]:
    import torch

    ctx_key = test.get("context", "no_context")
    system_prompt = build_system_prompt(ctx_key)
    conversation = test["conversation"]

    results = []
    messages = f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
    turn_idx = 0

    for step in conversation:
        if "role" in step:
            if step["role"] == "user":
                messages += f"<|im_start|>user\n{step['content']}<|im_end|>\n"
            elif step["role"] == "tool":
                messages += f"<|im_start|>tool\n{step['content']}<|im_end|>\n"
        elif "check_assistant" in step:
            turn_idx += 1
            prompt = messages + "<|im_start|>assistant\n"
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
            response = response.strip()

            checks = step["check_assistant"]
            sub_test = {
                "id": f"{test['id']}_turn{turn_idx}",
                "name": f"{test['name']}_turn{turn_idx}",
                **checks,
            }
            fails = check_test(sub_test, response)
            r = TestResult(
                test_id=sub_test["id"],
                name=sub_test["name"],
                category="multi_turn",
                suite="agent",
                passed=len(fails) == 0,
                response=response[:500],
                failures=fails,
            )
            results.append(r)
            messages += f"<|im_start|>assistant\n{response}<|im_end|>\n"

            tool_data = extract_tool_call(response)
            if tool_data and tool_data.get("tool"):
                tool_name = tool_data["tool"]
                mock = MOCK_TOOL_RESULTS.get(tool_name, '{"error":"Unknown tool"}')
                if isinstance(mock, dict):
                    params = tool_data.get("params", {})
                    domain = params.get("domain", "")
                    mock = mock.get(domain, json.dumps({"error": f"No mock for {domain}"}))
                messages += f"<|im_start|>tool\n{mock}<|im_end|>\n"

    return results


def get_mock_tool_result(tool_name: str, params: dict = None) -> str:
    result = MOCK_TOOL_RESULTS.get(tool_name, '{"error":"Unknown tool"}')
    if isinstance(result, dict) and params:
        domain = params.get("domain", "")
        if domain in result:
            return result[domain]
        return json.dumps({"error": f"No mock for {domain}"})
    return result if isinstance(result, str) else json.dumps(result)


# ──────────────────────────────────────────────────────────────
# Dry-run (no model)
# ──────────────────────────────────────────────────────────────
def dry_run():
    """Validate all test structures without loading a model."""
    print("=" * 60)
    print("DRY RUN — Validating test structure")
    print("=" * 60)

    stress = normalize_stress_tests()
    total = issues = 0

    # Agent tests
    print("\n=== test_agent.py ===")
    for category, tests in AGENT_TESTS.items():
        count = len(tests)
        total += count
        print(f"  {category}: {count}")
        for t in tests:
            has_q = "question" in t or "conversation" in t
            has_check = any(k in t for k in [
                "must_contain", "must_contain_one_of", "must_not_contain",
                "must_match_regex", "tool_call_check", "is_clarification",
            ])
            if "conversation" in t:
                has_check = any("check_assistant" in s for s in t["conversation"])
            if not (has_q and has_check):
                issues += 1
                print(f"    ❌ {t.get('id','?')} — missing question or checks")

    # Stress tests
    print("\n=== stress_test_r34.py ===")
    for category, tests in stress.items():
        count = len(tests)
        total += count
        print(f"  {category}: {count}")

    print(f"\n{'='*60}")
    print(f"Total tests: {total}")
    print(f"  Agent suite: {sum(len(v) for v in AGENT_TESTS.values())}")
    print(f"  Stress suite: {sum(len(v) for v in stress.values())}")
    print(f"Issues: {issues}")

    # Validate prompts
    from prompts_v2 import EXAMPLE_CONTEXTS
    for key in EXAMPLE_CONTEXTS:
        try:
            sp = build_system_prompt(key)
            assert len(sp) > 100
            print(f"  ✅ Context '{key}': {len(sp)} chars")
        except Exception as e:
            print(f"  ❌ Context '{key}': {e}")
            issues += 1

    return total, issues


# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="ApexMail Unified Test Runner — 360 tests")
    parser.add_argument("--adapter", type=str, help="Path to LoRA adapter")
    parser.add_argument("--base-model", type=str, default="/workspace/models/Qwen3-Next-80B-A3B-Instruct")
    parser.add_argument("--device", type=str, default="cuda:0")
    parser.add_argument("--auto-device-map", action="store_true", help="Use device_map='auto' for large models")
    parser.add_argument("--suite", type=str, choices=["all", "agent", "stress"], default="all")
    parser.add_argument("--category", type=str, help="Run one category only")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--output", type=str, default="test_results_unified.json")
    args = parser.parse_args()

    if args.dry_run:
        total, issues = dry_run()
        sys.exit(0 if issues == 0 else 1)

    # ── Load model ──────────────────────────────────────────────
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
    if args.adapter:
        print(f"Loading adapter from {args.adapter}...")
        model = PeftModel.from_pretrained(base_model, args.adapter)
    else:
        model = base_model
    model.eval()
    # For auto device map, find the first device to pass to run_inference
    if args.auto_device_map:
        args.device = "cuda:0"  # input tensors go to first GPU, model handles routing

    # ── Build unified test list ─────────────────────────────────
    test_list = []  # [(category, test_dict, suite)]

    if args.suite in ("all", "agent"):
        for cat, tests in AGENT_TESTS.items():
            if args.category and cat != args.category:
                continue
            for t in tests:
                test_list.append((cat, t, "agent"))

    if args.suite in ("all", "stress"):
        stress = normalize_stress_tests()
        for cat, tests in stress.items():
            if args.category and cat != args.category:
                continue
            for t in tests:
                test_list.append((cat, t, "stress"))

    print(f"\nRunning {len(test_list)} tests ({args.suite} suite)...\n")

    # ── Execute ─────────────────────────────────────────────────
    all_results = []
    t0 = time.time()

    for i, (category, test, suite) in enumerate(test_list):
        start = time.time()

        if "conversation" in test:
            multi_results = run_multiturn_test(model, tokenizer, test, args.device)
            for r in multi_results:
                r.duration = time.time() - start
                r.category = category
                r.suite = suite
            all_results.extend(multi_results)
            ok = all(r.passed for r in multi_results)
            icon = "✅" if ok else "❌"
            print(f"  [{i+1}/{len(test_list)}] {icon} {test['id']} ({category}) "
                  f"[{len(multi_results)} turns, {time.time()-start:.1f}s]")
        else:
            response = run_inference(model, tokenizer, test, args.device)
            fails = check_test(test, response)
            result = TestResult(
                test_id=test["id"],
                name=test["name"],
                category=category,
                suite=suite,
                passed=len(fails) == 0,
                response=response[:500],
                failures=fails,
                duration=time.time() - start,
            )
            all_results.append(result)
            icon = "✅" if result.passed else "❌"
            print(f"  [{i+1}/{len(test_list)}] {icon} {test['id']} ({category}) [{result.duration:.1f}s]")
            if not result.passed:
                for f in fails:
                    print(f"      ⚠ {f}")

    elapsed = time.time() - t0

    # ── Summary ─────────────────────────────────────────────────
    print("\n" + "=" * 70)
    passed = sum(1 for r in all_results if r.passed)
    total = len(all_results)
    pct = 100 * passed / total if total else 0
    print(f"OVERALL: {passed}/{total} ({pct:.1f}%) in {elapsed:.0f}s\n")

    # By suite
    for s in ("agent", "stress"):
        sr = [r for r in all_results if r.suite == s]
        if not sr:
            continue
        sp = sum(1 for r in sr if r.passed)
        st = len(sr)
        spct = 100 * sp / st if st else 0
        print(f"  [{s.upper():6s}] {sp:3d}/{st:3d} ({spct:.1f}%)")

    # By category
    print()
    categories = {}
    for r in all_results:
        key = f"{r.suite}:{r.category}"
        if key not in categories:
            categories[key] = {"passed": 0, "total": 0}
        categories[key]["total"] += 1
        if r.passed:
            categories[key]["passed"] += 1

    for key in sorted(categories):
        c = categories[key]
        p, t = c["passed"], c["total"]
        cpct = 100 * p / t if t else 0
        bar = "█" * int(cpct / 5) + "░" * (20 - int(cpct / 5))
        print(f"  {key:40s} {p:3d}/{t:3d} {cpct:5.1f}% {bar}")

    # ── Failed tests detail ─────────────────────────────────────
    failed = [r for r in all_results if not r.passed]
    if failed:
        print(f"\n{'='*70}")
        print(f"FAILED TESTS ({len(failed)}):\n")
        for r in failed[:30]:  # Show first 30
            print(f"  {r.suite}:{r.category} | {r.test_id} | {r.name}")
            for f in r.failures:
                print(f"    → {f}")
            if r.response:
                preview = r.response[:200].replace("\n", " ")
                print(f"    Response: {preview}...")
            print()

    # ── Write results ───────────────────────────────────────────
    output = {
        "summary": {
            "passed": passed,
            "total": total,
            "percentage": round(pct, 1),
            "elapsed_seconds": round(elapsed, 1),
            "by_suite": {
                s: {
                    "passed": sum(1 for r in all_results if r.suite == s and r.passed),
                    "total": sum(1 for r in all_results if r.suite == s),
                }
                for s in ("agent", "stress")
            },
            "by_category": categories,
        },
        "results": [
            {
                "id": r.test_id,
                "name": r.name,
                "category": r.category,
                "suite": r.suite,
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

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
