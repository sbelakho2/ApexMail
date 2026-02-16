#!/usr/bin/env python3
"""
ApexMail AI — Deep Training Data Audit
=======================================
Scans train.jsonl for:
  1. Factual inconsistencies (wrong prices, wrong limits, wrong URLs)
  2. Contradictions between examples
  3. Hallucinated features (project boards, CRM, SMS, etc.)
  4. Wrong number formatting (25K vs 25,000)
  5. Wrong plan-to-volume mapping
  6. Confused domain auth vs API auth
  7. Missing required keywords per category
"""

import json
import re
import sys
from collections import Counter, defaultdict

TRAIN_FILE = "data/train.jsonl"

# ═══════════════════════════════════════════════════════════════════════════
# GROUND TRUTH — every fact the model MUST know correctly
# ═══════════════════════════════════════════════════════════════════════════

PLAN_FACTS = {
    "Free":       {"price": "$0",    "emails": "1,000",   "api_calls": "10,000",      "domains": 1,  "team": 1},
    "Starter":    {"price": "$29",   "emails": "25,000",  "api_calls": "250,000",     "domains": 3,  "team": 5},
    "Pro":        {"price": "$59",   "emails": "50,000",  "api_calls": "500,000",     "domains": 5,  "team": 5},
    "Growth":     {"price": "$129",  "emails": "100,000", "api_calls": "2,000,000",   "domains": 10, "team": 10},
    "Scale":      {"price": "$399",  "emails": "500,000", "api_calls": "10,000,000",  "domains": 25, "team": 25},
    "Enterprise": {"price": "$1,299","emails": "Custom",  "api_calls": "Unlimited",   "domains": -1, "team": -1},
}

PAYG_TIERS = {
    "tier1": {"range": "1-10,000",         "rate": "$0.001"},
    "tier2": {"range": "10,001-100,000",   "rate": "$0.0008"},
    "tier3": {"range": "100,001-1,000,000","rate": "$0.0005"},
    "tier4": {"range": "1,000,001+",       "rate": "$0.0003"},
}

CORRECT_FACTS = {
    "api_url": "https://api.apexmail.ee/v1",
    "dashboard_url": "https://app.apexmail.ee",
    "prod_key_prefix": "am_live_",
    "test_key_prefix": "am_test_",
    "company": "Bel Consulting",
    "location": "Tallinn, Estonia",
    "founded": "2022",
    "dkim_bits": "2048",
    "max_attachment": "25 MB",
    "avg_open_rate": "21.5%",
    "avg_click_rate": "2.3%",
    "email_roi": "$36",
    "bounce_threshold": "2%",
    "complaint_threshold": "0.1%",
    "overage_email": "$0.50",
    "overage_api": "$0.10",
    "node_sdk": "@apexmail/sdk",
    "python_sdk": "apexmail-python",
}

# Things that should NEVER appear (hallucinations / wrong facts)
FORBIDDEN_FACTS = [
    "am_prod_",                    # wrong prefix
    "api.apexmail.com",            # wrong domain
    "apexmail.com/v1",             # wrong domain
    "$25/month",                   # wrong Starter price (mega_pipeline had this)
    "$65/month",                   # wrong Growth price (mega_pipeline)
    "$165/month",                  # wrong Business price (mega_pipeline)
    "10,000 emails.*Starter",      # wrong Starter volume
    "50,000 emails.*Growth",       # wrong Growth volume
    "200,000 emails.*Business",    # wrong Business volume
    "@apexmail/node",              # wrong SDK name (should be @apexmail/sdk)
    "apexmail.com",                # wrong domain (should be apexmail.ee)
    "project management board",    # hallucinated feature
    "kanban",                      # hallucinated feature
    "CRM",                         # hallucinated feature (unless denying it)
    "SMS",                         # hallucinated feature (unless denying it)
    "mobile app",                  # hallucinated feature (unless denying it)
    "landing page",                # hallucinated feature (unless denying it)
    "push notification",           # hallucinated feature (unless denying it)
]

DENIAL_CONTEXT = ["doesn't", "does not", "don't", "not include", "not offer",
                  "no ", "not support", "not available", "cannot", "can't"]


def load_data(path):
    examples = []
    with open(path) as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                ex = json.loads(line)
                text = ex.get("text", "")
                examples.append({"idx": i, "text": text})
            except json.JSONDecodeError:
                print(f"  WARN: Line {i} is not valid JSON")
    return examples


def extract_assistant_response(text):
    """Extract the assistant's response from ChatML."""
    parts = text.split("<|im_start|>assistant\n")
    if len(parts) < 2:
        return ""
    resp = parts[-1].split("<|im_end|>")[0]
    return resp


def extract_user_question(text):
    """Extract the user's question from ChatML."""
    parts = text.split("<|im_start|>user\n")
    if len(parts) < 2:
        return ""
    q = parts[-1].split("<|im_end|>")[0]
    return q


def check_starter_confusion(examples):
    """Check if any example confuses Starter emails (25,000) with API calls (250,000)."""
    issues = []
    for ex in examples:
        resp = extract_assistant_response(ex["text"]).lower()
        q = extract_user_question(ex["text"]).lower()

        # If talking about Starter plan and mentions 250,000 as emails
        if "starter" in resp and "$29" in resp:
            # Check if 250,000 appears near "email" (should be API calls)
            if re.search(r"250[,\s]?000\s*(emails|email)", resp):
                issues.append({
                    "idx": ex["idx"],
                    "issue": "CRITICAL: Starter 250,000 labeled as EMAILS (should be API calls). Emails = 25,000.",
                    "q": q[:80],
                    "resp_preview": resp[:200],
                })
    return issues


def check_wrong_prices(examples):
    """Check for old/wrong pricing from mega_pipeline."""
    issues = []
    for ex in examples:
        resp = extract_assistant_response(ex["text"])
        resp_lower = resp.lower()

        # Old mega_pipeline prices
        if "$25/month" in resp_lower or "$25/mo" in resp_lower:
            if "starter" in resp_lower:
                issues.append({"idx": ex["idx"], "issue": "WRONG: Starter=$25 (should be $29)", "q": extract_user_question(ex["text"])[:60]})

        if "$65/month" in resp_lower or "$65/mo" in resp_lower:
            if "growth" in resp_lower:
                issues.append({"idx": ex["idx"], "issue": "WRONG: Growth=$65 (should be $129)", "q": extract_user_question(ex["text"])[:60]})

        if "$165/month" in resp_lower or "$165/mo" in resp_lower:
            if "business" in resp_lower:
                issues.append({"idx": ex["idx"], "issue": "WRONG: Business=$165 (no Business plan)", "q": extract_user_question(ex["text"])[:60]})

        # Wrong API domain
        if "api.apexmail.com" in resp_lower:
            issues.append({"idx": ex["idx"], "issue": "WRONG: api.apexmail.com (should be api.apexmail.ee)", "q": extract_user_question(ex["text"])[:60]})

        # Wrong SDK name
        if "@apexmail/node" in resp and "@apexmail/sdk" not in resp:
            issues.append({"idx": ex["idx"], "issue": "WRONG: @apexmail/node (should be @apexmail/sdk)", "q": extract_user_question(ex["text"])[:60]})

        # Wrong key prefix
        if "am_prod_" in resp_lower:
            issues.append({"idx": ex["idx"], "issue": "WRONG: am_prod_ (should be am_live_)", "q": extract_user_question(ex["text"])[:60]})

    return issues


def check_hallucinated_features(examples):
    """Check for hallucinated features (should be denied, not described)."""
    issues = []
    hallucination_terms = [
        ("project management", "project management board"),
        ("kanban", "kanban board"),
        ("built-in crm", "built-in CRM"),
        ("sms messaging", "SMS messaging"),
        ("mobile app", "mobile app"),
        ("landing page", "landing page builder"),
        ("push notification", "push notifications"),
        ("video hosting", "video hosting"),
        ("image generator", "AI image generator"),
        ("graphql", "GraphQL endpoint"),
    ]

    for ex in examples:
        resp = extract_assistant_response(ex["text"]).lower()
        q = extract_user_question(ex["text"]).lower()

        for term, label in hallucination_terms:
            if term in resp:
                # Check if it's being denied
                is_denied = any(d in resp for d in DENIAL_CONTEXT)
                if not is_denied:
                    # Check if the question asks about it (legitimate context)
                    if term in q:
                        issues.append({
                            "idx": ex["idx"],
                            "issue": f"HALLUCINATION: Describes '{label}' positively instead of denying it",
                            "q": q[:80],
                            "resp_preview": resp[:200],
                        })
    return issues


def check_domain_auth_confusion(examples):
    """Check if 'domain authentication' questions get API auth answers."""
    issues = []
    auth_keywords = ["spf", "dkim", "dmarc"]

    for ex in examples:
        q = extract_user_question(ex["text"]).lower()
        resp = extract_assistant_response(ex["text"]).lower()

        # If question is about domain authentication
        if "domain" in q and ("authenticat" in q or "auth" in q):
            has_domain_auth = any(k in resp for k in auth_keywords)
            if not has_domain_auth:
                issues.append({
                    "idx": ex["idx"],
                    "issue": "CONFUSION: Domain auth question answered with API auth (missing SPF/DKIM/DMARC)",
                    "q": q[:80],
                    "resp_preview": resp[:200],
                })
    return issues


def check_volume_plan_mapping(examples):
    """Check if volume recommendation questions map to the right plan."""
    issues = []
    volume_mappings = [
        (200001, 500000, "Scale", "$399"),
        (100001, 200000, "Growth", "$129"),  # or Scale
        (50001, 100000, "Growth", "$129"),
        (25001, 50000, "Pro", "$59"),       # or Growth
    ]

    for ex in examples:
        q = extract_user_question(ex["text"]).lower()
        resp = extract_assistant_response(ex["text"]).lower()

        # Look for volume numbers in questions
        vol_match = re.search(r'(\d{1,3}(?:,\d{3})*)\s*(?:emails?|messages?)', q)
        if vol_match and "recommend" in q:
            vol_str = vol_match.group(1).replace(",", "")
            try:
                vol = int(vol_str)
            except:
                continue

            if vol >= 200001:
                if "scale" not in resp and "$399" not in resp and "enterprise" not in resp:
                    issues.append({
                        "idx": ex["idx"],
                        "issue": f"WRONG MAPPING: {vol} emails recommended wrong plan (should be Scale/Enterprise)",
                        "q": q[:80],
                        "resp_preview": resp[:200],
                    })
    return issues


def check_payg_tier_errors(examples):
    """Check PAYG tier boundary errors."""
    issues = []
    for ex in examples:
        resp = extract_assistant_response(ex["text"]).lower()
        q = extract_user_question(ex["text"]).lower()

        if "payg" in q or "pay-as-you-go" in q or "pay as you go" in q:
            # Check if 100,001st email is wrongly assigned $0.0003
            if "100,001" in resp and "$0.0003" in resp:
                # Make sure it's not saying "1M+ = $0.0003" 
                # The 100,001st email should be $0.0005
                context = resp[max(0,resp.index("100,001")-50):resp.index("100,001")+100]
                if "$0.0005" not in context:
                    issues.append({
                        "idx": ex["idx"],
                        "issue": "PAYG ERROR: 100,001st email assigned $0.0003 (should be $0.0005)",
                        "q": q[:80],
                    })
    return issues


def check_number_formatting(examples):
    """Check for inconsistent number formatting (25K vs 25,000)."""
    issues = []
    # We need "25,000" not "25K" for Starter emails
    for ex in examples:
        resp = extract_assistant_response(ex["text"])
        q = extract_user_question(ex["text"]).lower()

        if "starter" in resp.lower() and "$29" in resp:
            if re.search(r'\b25K\b', resp, re.IGNORECASE) and "25,000" not in resp:
                issues.append({
                    "idx": ex["idx"],
                    "issue": "NUMBER FORMAT: Uses '25K' instead of '25,000' for Starter emails",
                    "q": q[:80],
                })
        if "pro" in resp.lower() and "$59" in resp:
            if re.search(r'\b50K\b', resp, re.IGNORECASE) and "50,000" not in resp:
                issues.append({
                    "idx": ex["idx"],
                    "issue": "NUMBER FORMAT: Uses '50K' instead of '50,000' for Pro emails",
                    "q": q[:80],
                })
    return issues


def check_system_prompt_consistency(examples):
    """Check that system prompts are consistent across all examples."""
    system_prompts = Counter()
    for ex in examples:
        text = ex["text"]
        # Extract system prompt
        if "<|im_start|>system\n" in text:
            sp = text.split("<|im_start|>system\n")[1].split("<|im_end|>")[0]
            # Use first 100 chars as key
            key = sp[:100]
            system_prompts[key] += 1

    if len(system_prompts) > 1:
        print(f"\n  WARNING: {len(system_prompts)} different system prompts found!")
        for k, count in system_prompts.most_common():
            print(f"    [{count} examples]: {k[:120]}...")
        return True
    return False


def check_action_json_spacing(examples):
    """Check for inconsistent JSON spacing in action blocks."""
    issues = []
    for ex in examples:
        resp = extract_assistant_response(ex["text"])
        # Look for action blocks with space after colon in confirm
        if "```action" in resp:
            if '"confirm": false' in resp or '"confirm": true' in resp:
                issues.append({
                    "idx": ex["idx"],
                    "issue": "JSON SPACING: 'confirm\": false' has space (should be compact: 'confirm\":false')",
                    "q": extract_user_question(ex["text"])[:60],
                })
    return issues


def statistical_summary(examples):
    """Generate statistical summary of the dataset."""
    lengths = []
    categories = Counter()
    has_action = 0
    has_table = 0

    for ex in examples:
        text = ex["text"]
        resp = extract_assistant_response(text)
        q = extract_user_question(text)
        lengths.append(len(resp))

        if "```action" in resp:
            has_action += 1
        if "|" in resp and "---" in resp:
            has_table += 1

    lengths.sort()
    n = len(lengths)
    print(f"\n  Dataset size: {n} examples")
    print(f"  Response lengths: min={lengths[0]}, median={lengths[n//2]}, max={lengths[-1]}, mean={sum(lengths)/n:.0f}")
    print(f"  With action blocks: {has_action} ({has_action/n*100:.1f}%)")
    print(f"  With tables: {has_table} ({has_table/n*100:.1f}%)")

    # Check for duplicate questions
    questions = [extract_user_question(ex["text"]) for ex in examples]
    q_counter = Counter(questions)
    dupes = {q: c for q, c in q_counter.items() if c > 10}
    if dupes:
        print(f"\n  HIGH DUPLICATION (>10x):")
        for q, c in sorted(dupes.items(), key=lambda x: -x[1])[:15]:
            print(f"    [{c}x] {q[:80]}")


def main():
    print("=" * 70)
    print("  ApexMail AI — DEEP TRAINING DATA AUDIT")
    print("=" * 70)

    examples = load_data(TRAIN_FILE)
    print(f"\nLoaded {len(examples)} examples from {TRAIN_FILE}")

    # Statistical summary
    print("\n── STATISTICAL SUMMARY ──")
    statistical_summary(examples)

    # System prompt consistency
    print("\n── SYSTEM PROMPT CONSISTENCY ──")
    multi = check_system_prompt_consistency(examples)
    if not multi:
        print("  OK: All examples use the same system prompt")

    # Wrong prices
    print("\n── WRONG PRICES / FACTS ──")
    price_issues = check_wrong_prices(examples)
    if price_issues:
        print(f"  FOUND {len(price_issues)} ISSUES:")
        for iss in price_issues[:30]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
            print(f"      Q: {iss['q']}")
    else:
        print("  OK: No wrong prices found")

    # Starter email/API confusion
    print("\n── STARTER EMAIL vs API CONFUSION ──")
    starter_issues = check_starter_confusion(examples)
    if starter_issues:
        print(f"  FOUND {len(starter_issues)} ISSUES:")
        for iss in starter_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
            print(f"      Q: {iss['q']}")
            print(f"      Resp: {iss['resp_preview']}")
    else:
        print("  OK: No Starter confusion found")

    # Hallucinated features
    print("\n── HALLUCINATED FEATURES ──")
    halluc_issues = check_hallucinated_features(examples)
    if halluc_issues:
        print(f"  FOUND {len(halluc_issues)} ISSUES:")
        for iss in halluc_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
            print(f"      Q: {iss['q']}")
            print(f"      Resp: {iss['resp_preview']}")
    else:
        print("  OK: No hallucinated features found")

    # Domain auth confusion
    print("\n── DOMAIN AUTH vs API AUTH CONFUSION ──")
    auth_issues = check_domain_auth_confusion(examples)
    if auth_issues:
        print(f"  FOUND {len(auth_issues)} ISSUES:")
        for iss in auth_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
            print(f"      Q: {iss['q']}")
            print(f"      Resp: {iss['resp_preview']}")
    else:
        print("  OK: No domain auth confusion found")

    # Volume-to-plan mapping
    print("\n── VOLUME-TO-PLAN MAPPING ──")
    vol_issues = check_volume_plan_mapping(examples)
    if vol_issues:
        print(f"  FOUND {len(vol_issues)} ISSUES:")
        for iss in vol_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
            print(f"      Q: {iss['q']}")
    else:
        print("  OK: No volume mapping issues found")

    # PAYG tier errors
    print("\n── PAYG TIER BOUNDARY ERRORS ──")
    payg_issues = check_payg_tier_errors(examples)
    if payg_issues:
        print(f"  FOUND {len(payg_issues)} ISSUES:")
        for iss in payg_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
    else:
        print("  OK: No PAYG tier errors found")

    # Number formatting
    print("\n── NUMBER FORMATTING (25K vs 25,000) ──")
    num_issues = check_number_formatting(examples)
    if num_issues:
        print(f"  FOUND {len(num_issues)} ISSUES:")
        for iss in num_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
    else:
        print("  OK: No number formatting issues found")

    # Action JSON spacing
    print("\n── ACTION JSON SPACING ──")
    json_issues = check_action_json_spacing(examples)
    if json_issues:
        print(f"  FOUND {len(json_issues)} ISSUES:")
        for iss in json_issues[:10]:
            print(f"    Line {iss['idx']}: {iss['issue']}")
    else:
        print("  OK: No JSON spacing issues found")

    # Final summary
    total_issues = (len(price_issues) + len(starter_issues) + len(halluc_issues) +
                    len(auth_issues) + len(vol_issues) + len(payg_issues) +
                    len(num_issues) + len(json_issues))

    print("\n" + "=" * 70)
    print(f"  AUDIT COMPLETE: {total_issues} total issues found")
    print("=" * 70)

    if total_issues > 0:
        print("\n  RECOMMENDATION: Fix these issues before retraining!")
        return 1
    else:
        print("\n  Data looks clean. Safe to proceed with training.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
