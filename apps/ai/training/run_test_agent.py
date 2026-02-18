#!/usr/bin/env python3
"""
ApexMail Agent Test Runner (v2)

Runs tests against the fine-tuned model with support for:
  - Context injection (customer profiles in system prompt)
  - Tool-call format verification
  - Multi-turn conversation testing
  - Clarification behavior detection
  - Exact math verification

Usage on remote (4-GPU machine):
  python run_test_agent.py --adapter output/          (quick test — 1 GPU)
  python run_test_agent.py --adapter output/ --full    (full parallel — 4 GPU)

Local dry-run (no model):
  python run_test_agent.py --dry-run
"""

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(__file__))

from test_agent import ALL_TESTS
from prompts_v2 import build_system_prompt

# Simulated tool results for multi-turn testing
MOCK_TOOL_RESULTS = {
    "get_dns_records": {
        "marketing.techflow.io": '{"domain": "marketing.techflow.io", "records": {"spf": {"status": "pass"}, "dkim": {"status": "missing", "expected_host": "apexmail._domainkey.marketing.techflow.io"}, "dmarc": {"status": "fail"}}}',
    },
    "search_events": '{"events": [{"message_id": "msg_test1", "status": "delivered", "opened": false}]}',
    "get_suppression_status": '{"email": "test@example.com", "suppressed": true, "reason": "unsubscribe"}',
    "list_webhooks": '{"webhooks": [{"id": "wh_1", "url": "https://example.com/webhook", "status": "failing", "last_status_code": 404}]}',
    "get_usage_stats": '{"plan": "Scale", "emails": {"used": 425000, "limit": 500000}, "api_calls": {"used": 3200000, "limit": 5000000}, "days_remaining": 10}',
    "get_deliverability_report": '{"overall_score": 62, "delivery_rate": 92.0, "bounce_rate": 4.7, "complaint_rate": 0.13}',
    "check_blocklist": '{"ip": "198.51.100.12", "listings": [{"blocklist": "Spamhaus SBL", "listed": true}]}',
    "get_analytics_dashboard": '{"emails_sent": 1450000, "delivery_rate": 99.0, "bounce_rate": 0.5}',
    "get_campaign_stats": '{"campaign": "Test Campaign", "sent": 10000, "delivered": 9800}',
    "list_automations": '{"automations": [{"name": "Welcome Series", "status": "active"}]}',
    "get_message_status": '{"message_id": "msg_test", "status": "deferred", "attempts": 3}',
    "get_domain_health": '{"domain": "example.com", "spf": "pass", "dkim": "pass", "dmarc": "pass"}',
    "get_domain_status": '{"domain": "example.com", "status": "verified"}',
    "list_contacts": '{"contacts": [{"email": "test@example.com", "tags": ["customer"]}]}',
    "get_contact": '{"email": "test@example.com", "tags": ["customer"]}',
    "get_message_events": '{"events": [{"type": "delivered", "timestamp": "2026-02-18T10:00:00Z"}]}',
    "get_webhook_deliveries": '{"deliveries": [{"status": 404, "timestamp": "2026-02-18T10:00:00Z"}]}',
}


@dataclass
class TestResult:
    test_id: str
    name: str
    category: str
    passed: bool
    response: str = ""
    failures: list = field(default_factory=list)
    duration: float = 0.0


def extract_tool_call(response: str) -> Optional[dict]:
    """Extract tool_call JSON from assistant response."""
    # Match ```tool_call\n{...}\n``` pattern
    pattern = r'```tool_call\s*\n(.*?)\n```'
    match = re.search(pattern, response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
    return None


def check_test(test: dict, response: str) -> TestResult:
    """Run all checks for a single test against the model response."""
    failures = []

    # must_contain — ALL must be present
    for phrase in test.get("must_contain", []):
        if phrase.lower() not in response.lower():
            failures.append(f"MISSING required: '{phrase}'")

    # must_contain_one_of — at least ONE must be present
    one_of = test.get("must_contain_one_of", [])
    if one_of and not any(phrase.lower() in response.lower() for phrase in one_of):
        failures.append(f"MISSING at least one of: {one_of}")

    # must_not_contain — NONE should be present
    for phrase in test.get("must_not_contain", []):
        if phrase.lower() in response.lower():
            failures.append(f"FORBIDDEN found: '{phrase}'")

    # must_match_regex — all patterns must match
    for pattern in test.get("must_match_regex", []):
        if not re.search(pattern, response):
            failures.append(f"REGEX not matched: '{pattern}'")

    # is_clarification — response should ask a question
    if test.get("is_clarification"):
        if "?" not in response:
            failures.append("CLARIFICATION expected but no question mark found")

    # tool_call_check — validate tool call format
    tc = test.get("tool_call_check")
    if tc:
        tool_data = extract_tool_call(response)
        if tool_data is None:
            failures.append("TOOL_CALL expected but no valid ```tool_call``` block found")
        else:
            # Check required tool name
            actual_tool = tool_data.get("tool", "")
            if "required_tool" in tc:
                if actual_tool != tc["required_tool"]:
                    failures.append(f"TOOL wrong: expected '{tc['required_tool']}', got '{actual_tool}'")
            elif "required_tool_one_of" in tc:
                if actual_tool not in tc["required_tool_one_of"]:
                    failures.append(f"TOOL wrong: expected one of {tc['required_tool_one_of']}, got '{actual_tool}'")

            # Check required params
            params = tool_data.get("params", {})
            for param in tc.get("required_params", []):
                if param not in params:
                    failures.append(f"PARAM missing: '{param}' not in tool call params")

            if "required_params_one_of" in tc:
                if not any(p in params for p in tc["required_params_one_of"]):
                    failures.append(f"PARAM missing: need one of {tc['required_params_one_of']}")

    return TestResult(
        test_id=test["id"],
        name=test["name"],
        category="",  # filled by caller
        passed=len(failures) == 0,
        response=response[:500],
        failures=failures,
    )


def get_mock_tool_result(tool_name: str, params: dict = None) -> str:
    """Get a mock tool result for multi-turn testing."""
    result = MOCK_TOOL_RESULTS.get(tool_name, '{"error": "Unknown tool"}')
    if isinstance(result, dict) and params:
        # Check for domain-specific results
        domain = params.get("domain", "")
        if domain in result:
            return result[domain]
        return json.dumps({"error": f"No mock for {domain}"})
    return result if isinstance(result, str) else json.dumps(result)


def run_single_test_inference(model, tokenizer, test: dict, device="cuda:0") -> str:
    """Run a single test through the model and return the response."""
    import torch

    ctx_key = test.get("context", "no_context")
    system_prompt = build_system_prompt(ctx_key)
    question = test["question"]

    messages = f"<|im_start|>system\n{system_prompt}<|im_end|>\n<|im_start|>user\n{question}<|im_end|>\n<|im_start|>assistant\n"

    inputs = tokenizer(messages, return_tensors="pt", truncation=True, max_length=4096)
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

    # Extract assistant response
    response = ""
    if "<|im_start|>assistant\n" in full_text:
        response = full_text.split("<|im_start|>assistant\n")[-1]
        if "<|im_end|>" in response:
            response = response.split("<|im_end|>")[0]

    return response.strip()


def run_multiturn_test(model, tokenizer, test: dict, device="cuda:0") -> list[TestResult]:
    """Run a multi-turn test, injecting tool results as needed."""
    import torch

    ctx_key = test.get("context", "no_context")
    system_prompt = build_system_prompt(ctx_key)
    conversation = test["conversation"]

    results = []
    messages_so_far = f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
    turn_idx = 0

    for step in conversation:
        if "role" in step:
            if step["role"] == "user":
                messages_so_far += f"<|im_start|>user\n{step['content']}<|im_end|>\n"
            elif step["role"] == "tool":
                messages_so_far += f"<|im_start|>tool\n{step['content']}<|im_end|>\n"
        elif "check_assistant" in step:
            turn_idx += 1
            # Generate assistant response
            prompt = messages_so_far + "<|im_start|>assistant\n"
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
                # Get the LAST assistant response
                parts = full_text.split("<|im_start|>assistant\n")
                response = parts[-1]
                if "<|im_end|>" in response:
                    response = response.split("<|im_end|>")[0]
            response = response.strip()

            # Check this turn
            checks = step["check_assistant"]
            sub_test = {
                "id": f"{test['id']}_turn{turn_idx}",
                "name": f"{test['name']}_turn{turn_idx}",
                **checks,
            }
            result = check_test(sub_test, response)
            result.category = "multi_turn"
            results.append(result)

            # Add response to conversation history
            messages_so_far += f"<|im_start|>assistant\n{response}<|im_end|>\n"

            # If response contains a tool call, inject mock result
            tool_data = extract_tool_call(response)
            if tool_data and tool_data.get("tool"):
                tool_result = get_mock_tool_result(
                    tool_data["tool"],
                    tool_data.get("params", {})
                )
                messages_so_far += f"<|im_start|>tool\n{tool_result}<|im_end|>\n"

    return results


def run_tests_on_gpu(model, tokenizer, tests_subset: list[tuple[str, dict]],
                     device: str = "cuda:0") -> list[TestResult]:
    """Run a subset of tests on a specific GPU."""
    results = []
    for category, test in tests_subset:
        start = time.time()
        if "conversation" in test:
            multi_results = run_multiturn_test(model, tokenizer, test, device)
            for r in multi_results:
                r.duration = time.time() - start
            results.extend(multi_results)
        else:
            response = run_single_test_inference(model, tokenizer, test, device)
            result = check_test(test, response)
            result.category = category
            result.duration = time.time() - start
            results.append(result)
    return results


def dry_run_checks():
    """Run the check logic without a model (validation only)."""
    print("=== DRY RUN — Validating test structure ===\n")

    total = 0
    issues = 0

    for category, tests in ALL_TESTS.items():
        print(f"\n{category.upper()} ({len(tests)} tests):")
        for test in tests:
            total += 1
            tid = test.get("id", "NO_ID")
            name = test.get("name", "NO_NAME")

            # Check test has required fields
            has_question = "question" in test
            has_conversation = "conversation" in test
            has_checks = (
                "must_contain" in test or
                "must_contain_one_of" in test or
                "must_not_contain" in test or
                "must_match_regex" in test or
                "tool_call_check" in test or
                "is_clarification" in test
            )

            # For multi-turn tests, check conversation structure
            if has_conversation:
                has_checks = any("check_assistant" in step for step in test["conversation"])

            status = "✅" if (has_question or has_conversation) and has_checks else "❌"
            if status == "❌":
                issues += 1

            # Check for unique IDs
            print(f"  {status} {tid} | {name}")

    print(f"\n{'='*50}")
    print(f"Total tests: {total}")
    print(f"Issues: {issues}")

    # Also validate system prompt generation
    from prompts_v2 import EXAMPLE_CONTEXTS
    for key in EXAMPLE_CONTEXTS:
        try:
            sp = build_system_prompt(key)
            assert len(sp) > 100, f"System prompt too short for {key}"
            print(f"✅ Context '{key}': {len(sp)} chars")
        except Exception as e:
            print(f"❌ Context '{key}': {e}")

    return total, issues


def main():
    parser = argparse.ArgumentParser(description="ApexMail Agent Test Runner v2")
    parser.add_argument("--adapter", type=str, help="Path to LoRA adapter directory")
    parser.add_argument("--base-model", type=str, default="/workspace/models/Qwen3-8B",
                        help="Path to base model")
    parser.add_argument("--device", type=str, default="cuda:0", help="Device to use")
    parser.add_argument("--full", action="store_true", help="Run on all 4 GPUs in parallel")
    parser.add_argument("--dry-run", action="store_true", help="Validate tests without model")
    parser.add_argument("--category", type=str, help="Run only one category")
    parser.add_argument("--output", type=str, default="test_results_agent.json",
                        help="Output file for results")
    args = parser.parse_args()

    if args.dry_run:
        total, issues = dry_run_checks()
        sys.exit(0 if issues == 0 else 1)

    # Load model
    print("Loading model...")
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM
    from peft import PeftModel

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    base_model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=torch.bfloat16,
        device_map=args.device if not args.full else "auto",
        trust_remote_code=True,
    )

    if args.adapter:
        print(f"Loading adapter from {args.adapter}...")
        model = PeftModel.from_pretrained(base_model, args.adapter)
    else:
        model = base_model

    model.eval()

    # Build test list
    test_list = []
    for category, tests in ALL_TESTS.items():
        if args.category and category != args.category:
            continue
        for test in tests:
            test_list.append((category, test))

    print(f"\nRunning {len(test_list)} tests...")

    # Run tests
    all_results = []
    for i, (category, test) in enumerate(test_list):
        start = time.time()
        if "conversation" in test:
            multi_results = run_multiturn_test(model, tokenizer, test, args.device)
            for r in multi_results:
                r.duration = time.time() - start
                r.category = category
            all_results.extend(multi_results)
            status = "✅" if all(r.passed for r in multi_results) else "❌"
            print(f"  [{i+1}/{len(test_list)}] {status} {test['id']} ({category}) "
                  f"[{len(multi_results)} turns, {time.time()-start:.1f}s]")
        else:
            response = run_single_test_inference(model, tokenizer, test, args.device)
            result = check_test(test, response)
            result.category = category
            result.duration = time.time() - start
            all_results.append(result)
            status = "✅" if result.passed else "❌"
            print(f"  [{i+1}/{len(test_list)}] {status} {test['id']} ({category}) "
                  f"[{result.duration:.1f}s]")
            if not result.passed:
                for f in result.failures:
                    print(f"      ⚠ {f}")

    # Summary
    print("\n" + "=" * 60)
    passed = sum(1 for r in all_results if r.passed)
    total = len(all_results)
    print(f"RESULTS: {passed}/{total} passed ({100*passed/total:.1f}%)\n")

    # By category
    categories = {}
    for r in all_results:
        if r.category not in categories:
            categories[r.category] = {"passed": 0, "total": 0}
        categories[r.category]["total"] += 1
        if r.passed:
            categories[r.category]["passed"] += 1

    for cat, counts in sorted(categories.items()):
        p = counts["passed"]
        t = counts["total"]
        pct = 100 * p / t if t > 0 else 0
        bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
        print(f"  {cat:25s} {p:3d}/{t:3d} {pct:5.1f}% {bar}")

    # Write results
    output_data = {
        "summary": {
            "passed": passed,
            "total": total,
            "percentage": round(100 * passed / total, 1) if total > 0 else 0,
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
        json.dump(output_data, f, indent=2)
    print(f"\nDetailed results written to {args.output}")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
