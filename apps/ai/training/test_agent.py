#!/usr/bin/env python3
"""
ApexMail Agent Test Runner
Tests the trained LoRA adapter against expected behaviors.

Exports:
  TEST_CASES — legacy list-of-dict test cases (used by run_tests below)
  ALL_TESTS  — unified dict {category: [test, ...]} consumed by
               run_test_agent.py and validate_pipeline.py (>= 180 tests)
"""
import argparse
import json
import os
import re
import sys

# torch / transformers / peft are imported lazily inside functions that need them
# so that run_test_agent.py and validate_pipeline.py can import ALL_TESTS without
# requiring a CUDA environment.

# ── System prompt (must match training) ─────────────────────────
SYSTEM_PROMPT = """You are ApexMail Agent — the AI support agent for the ApexMail email platform (Bel Consulting OÜ, Tallinn, Estonia, founded 2022).
You have access to the customer's account context and can help with billing, technical issues, and general questions.

ApexMail Pricing (effective March 2026):
- Free: $0, 3,000 emails/mo, 50,000 API calls/mo, 1 domain, 1 team, 7 days retention
- Starter: $25/mo, 50,000 emails/mo, 500,000 API calls/mo, 5 domains, 5 team, 30 days retention
- Pro: $65/mo, 150,000 emails/mo, 2,000,000 API calls/mo, 25 domains, 10 team, 60 days retention, A/B testing, send-time optimization
- Growth: $150/mo, 500,000 emails/mo, 5,000,000 API calls/mo, 100 domains, 25 team, 90 days retention, 1 dedicated IP included
- Scale: $350/mo, 2,000,000 emails/mo, 20,000,000 API calls/mo, unlimited domains, 50 team, 365 days retention, 3 dedicated IPs included, SSO/SAML
- Enterprise: $800/mo, 5,000,000 emails/mo, unlimited API calls, unlimited domains and team, 730 days retention, 10 dedicated IPs included, HIPAA/SOC2/white-label

Overages: $0.40 per 1,000 emails; $0.10 per 1,000 API calls (first 100,000 API calls free on all plans)
Dedicated IP add-on: $30/mo on Pro+ (Growth includes 1, Scale 3, Enterprise 10)
Annual billing: 2 months free (~17% discount) — annual prices: Starter $250, Pro $650, Growth $1,500, Scale $3,500, Enterprise $8,000

Be helpful, accurate, and concise. For account-specific actions, use tool calls."""


def load_model(base_model_path: str, adapter_path: str = None, device_map: str = "auto"):
    """Load base model with optional LoRA adapter."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    print(f"Loading tokenizer from {base_model_path}...")
    tokenizer = AutoTokenizer.from_pretrained(base_model_path, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    
    print(f"Loading model from {base_model_path}...")
    model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        torch_dtype=torch.bfloat16,
        device_map=device_map,
        trust_remote_code=True,
    )
    
    if adapter_path:
        print(f"Loading LoRA adapter from {adapter_path}...")
        model = PeftModel.from_pretrained(model, adapter_path)
    
    model.eval()
    return model, tokenizer


def generate_response(model, tokenizer, user_message: str, max_tokens: int = 512):
    """Generate a response from the model."""
    import torch

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]
    
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=max_tokens,
            temperature=0.7,
            do_sample=True,
            pad_token_id=tokenizer.pad_token_id,
        )
    
    response = tokenizer.decode(outputs[0][inputs['input_ids'].shape[1]:], skip_special_tokens=True)
    return response.strip()


# ── Test cases ──────────────────────────────────────────────────
TEST_CASES = [
    {
        "name": "pricing_pro_plan",
        "input": "How much does the Pro plan cost?",
        "required": ["$65", "150,000", "2,000,000 API"],
        "forbidden": ["$49", "$99", "500,000 API"],
    },
    {
        "name": "pricing_starter",
        "input": "What's the Starter plan price?",
        "required": ["$25", "50,000 emails", "500,000 API"],
        "forbidden": ["$20", "$15", "250,000 API"],
    },
    {
        "name": "pricing_scale",
        "input": "Tell me about the Scale plan",
        "required": ["$350", "2,000,000 emails", "20,000,000 API", "SSO", "3 dedicated IP"],
        "forbidden": ["5,000,000 API", "$250"],
    },
    {
        "name": "pricing_enterprise",
        "input": "What's included in Enterprise?",
        "required": ["$800", "5,000,000 emails", "unlimited API", "10 dedicated IP"],
        "forbidden": ["2,000,000 emails", "20,000,000 API"],
    },
    {
        "name": "growth_plan_limits",
        "input": "What are the limits on Growth?",
        "required": ["500,000 emails", "5,000,000 API", "25 team", "100 domains", "1 dedicated IP"],
        "forbidden": ["250,000 emails", "1,000,000 API"],
    },
    {
        "name": "overage_rate_emails",
        "input": "What are the email overage charges?",
        "required": ["$0.40", "1,000 emails"],
        "forbidden": ["$0.90", "$1.00"],
    },
    {
        "name": "overage_rate_api",
        "input": "What are API overage charges?",
        "required": ["$0.10", "1,000 API", "100,000 free"],
        "forbidden": ["$0.40", "10,000 free"],
    },
    {
        "name": "dedicated_ip_addon",
        "input": "How much is a dedicated IP add-on?",
        "required": ["$30", "Pro"],
        "forbidden": ["$50", "$20"],
    },
    {
        "name": "dedicated_ip_included",
        "input": "Which plans include dedicated IPs?",
        "required": ["Growth includes 1", "Scale includes 3", "Enterprise includes 10"],
        "forbidden": ["Starter includes", "Free includes"],
    },
    {
        "name": "annual_discount",
        "input": "Is there a discount for annual billing?",
        "required": ["annual", "2 months free", "17%"],
        "forbidden": ["20%", "3 months"],
    },
    {
        "name": "retention_free",
        "input": "How long is data retained on the free plan?",
        "required": ["7 days", "Free"],
        "forbidden": ["1 day", "30 days"],
    },
    {
        "name": "retention_enterprise",
        "input": "What's Enterprise data retention?",
        "required": ["730 days", "Enterprise"],
        "forbidden": ["365 days", "90 days"],
    },
    {
        "name": "feature_ab_testing",
        "input": "Do I get A/B testing on Pro?",
        "required": ["Pro", "A/B"],
        "forbidden": ["Starter"],
    },
    {
        "name": "company_info",
        "input": "Who makes ApexMail?",
        "required": ["Bel Consulting", "Estonia"],
        "forbidden": ["Resend", "SendGrid"],
    },
    {
        "name": "greeting",
        "input": "Hi, I need help with my account",
        "required": [],  # Just check it responds helpfully
        "forbidden": ["error", "cannot", "don't know"],
    },
]


# ── Build ALL_TESTS (unified dict consumed by run_test_agent / validate_pipeline) ──
def _build_all_tests() -> dict[str, list[dict]]:
    """
    Merge TEST_CASES (basic) + stress_test.STRESS_TESTS into one dict
    keyed by category, with each entry normalized to:
      {id, name, question, must_contain, must_not_contain, must_contain_any, ...}
    """
    # Import stress tests (sibling module)
    sys.path.insert(0, os.path.dirname(__file__) or ".")
    from stress_test import STRESS_TESTS

    all_tests: dict[str, list[dict]] = {}

    # 1. Convert legacy TEST_CASES → "basic" category
    basic = []
    for idx, tc in enumerate(TEST_CASES, start=1):
        basic.append({
            "id": f"basic_{idx:03d}",
            "name": tc["name"],
            "question": tc["input"],
            "must_contain": tc.get("required", []),
            "must_not_contain": tc.get("forbidden", []),
        })
    all_tests["basic"] = basic

    # 2. Convert each STRESS_TESTS category
    for category, tests in STRESS_TESTS.items():
        converted = []
        for idx, st in enumerate(tests, start=1):
            checks = st.get("checks", {})
            entry: dict = {
                "id": f"{category}_{idx:03d}",
                "name": f"{category}_{idx:03d}",
                "question": st["q"],
            }
            # Flatten checks into top-level keys
            if "must_contain" in checks:
                entry["must_contain"] = checks["must_contain"]
            if "must_not_contain" in checks:
                entry["must_not_contain"] = checks["must_not_contain"]
            if "must_contain_any" in checks:
                entry["must_contain_any"] = checks["must_contain_any"]
            # Pass through any extra check keys (regex, length, etc.)
            for key in ("must_match_regex", "min_length", "max_length"):
                if key in checks:
                    entry[key] = checks[key]
            # Forward optional stress-test fields
            if "context" in st:
                entry["context"] = st["context"]
            if "conversation" in st:
                entry["conversation"] = st["conversation"]
            if "tool_call_check" in st:
                entry["tool_call_check"] = st["tool_call_check"]
            if "is_clarification" in st:
                entry["is_clarification"] = st["is_clarification"]
            converted.append(entry)
        all_tests[category] = converted

    return all_tests


ALL_TESTS = _build_all_tests()


def run_tests(model, tokenizer, verbose: bool = False):
    """Run all test cases and report results."""
    passed = 0
    failed = 0
    results = []
    
    print(f"\n{'='*60}")
    print(f"Running {len(TEST_CASES)} tests...")
    print(f"{'='*60}\n")
    
    for test in TEST_CASES:
        response = generate_response(model, tokenizer, test["input"])
        response_lower = response.lower()
        
        # Check required terms
        missing = []
        for req in test["required"]:
            if req.lower() not in response_lower:
                missing.append(req)
        
        # Check forbidden terms
        found_forbidden = []
        for forb in test["forbidden"]:
            if forb.lower() in response_lower:
                found_forbidden.append(forb)
        
        success = len(missing) == 0 and len(found_forbidden) == 0
        
        if success:
            passed += 1
            status = "✓ PASS"
        else:
            failed += 1
            status = "✗ FAIL"
        
        results.append({
            "name": test["name"],
            "passed": success,
            "missing": missing,
            "forbidden_found": found_forbidden,
            "response": response[:200] if verbose else None,
        })
        
        print(f"{status}: {test['name']}")
        if verbose or not success:
            print(f"  Input: {test['input'][:60]}...")
            print(f"  Response: {response[:100]}...")
            if missing:
                print(f"  Missing: {missing}")
            if found_forbidden:
                print(f"  Forbidden found: {found_forbidden}")
        print()
    
    print(f"{'='*60}")
    print(f"Results: {passed}/{len(TEST_CASES)} passed ({100*passed/len(TEST_CASES):.1f}%)")
    print(f"{'='*60}")
    
    return {
        "passed": passed,
        "failed": failed,
        "total": len(TEST_CASES),
        "pass_rate": 100 * passed / len(TEST_CASES),
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(description="Test ApexMail Agent")
    parser.add_argument("--base-model", required=True, help="Base model path")
    parser.add_argument("--adapter", help="LoRA adapter path")
    parser.add_argument("--auto-device-map", action="store_true", help="Use auto device map")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output JSON file")
    args = parser.parse_args()
    
    device_map = "auto" if args.auto_device_map else None
    model, tokenizer = load_model(args.base_model, args.adapter, device_map)
    
    results = run_tests(model, tokenizer, args.verbose)
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")
    
    sys.exit(0 if results["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
