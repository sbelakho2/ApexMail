#!/usr/bin/env python3
"""
test_fixes.py — runnable test suite for the audit fixes in apps/ai.

No pytest required: `python3 apps/ai/training/test_fixes.py` runs everything
and exits non-zero on failure. Functions are also pytest-compatible.

Covers:
  - validate_pricing.py canonical EUR table + adversarial wrong prices
  - sweep_currency_to_eur.py rules (numbers, tier-3 rate, USD facts, idempotence)
  - augment_training_data.py (PAYG boundaries, no negative volumes, Unlimited
    rendering, dynamic DNS guidance)
  - evaluate.py keyword_recall + exact-price-match gate
  - evaluate_granular.py (found_wrong used, per-(plan,question) keying,
    PAYG boundary math)
  - generate_dataset.py stable per-row splits (appending never moves rows)
  - prompts_v2.py canonical EUR pricing table, apexmail.ee domain
  - validate_data_prices.py adversarial corpus detection
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

TRAINING_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TRAINING_DIR))

import augment_training_data as augment  # noqa: E402
import evaluate_granular as granular  # noqa: E402
import generate_dataset  # noqa: E402
import validate_data_prices  # noqa: E402
import validate_pricing  # noqa: E402
from evaluate import score_golden_answer  # noqa: E402
from sweep_currency_to_eur import sweep_text  # noqa: E402
from prompts_v2 import PRICING_TABLE, PAYG_INFO, build_system_prompt  # noqa: E402

CANONICAL = {"free": 0, "starter": 25, "pro": 65, "growth": 150, "scale": 350, "enterprise": 3000}


# ── validate_pricing ───────────────────────────────────────────────────────

def test_canonical_table_matches_plans_rs():
    assert validate_pricing.PRICE_BY_PLAN["starter"] == "€25"
    assert validate_pricing.PRICE_BY_PLAN["pro"] == "€65"
    assert validate_pricing.PRICE_BY_PLAN["growth"] == "€150"
    assert validate_pricing.PRICE_BY_PLAN["scale"] == "€350"
    assert validate_pricing.PRICE_BY_PLAN["enterprise"] == "€3,000"
    assert validate_pricing.PRICE_BY_PLAN["free"] == "€0"


def test_wrong_plan_prices_are_rejected():
    findings = validate_pricing.validate_pricing_in_text(
        "The Starter plan costs €15/month and Pro is $79/month."
    )
    messages = " | ".join(f["message"] for f in findings)
    assert "€25" in messages, f"Starter wrong price not flagged: {messages}"
    assert "€65" in messages, f"Pro wrong price not flagged: {messages}"


def test_dollar_symbol_is_reported_even_with_right_number():
    findings = validate_pricing.validate_pricing_in_text("Growth $150/month")
    assert len(findings) == 1
    assert "EUR" in findings[0]["message"]


def test_correct_euro_prices_pass():
    assert validate_pricing.validate_pricing_in_text(
        "Starter (€25/month), Pro (€65/mo), Enterprise (€3,000/month), Free plan is €0."
    ) == []


# ── sweep rules ────────────────────────────────────────────────────────────

def test_sweep_fixes_wrong_prices_and_tier3_rate():
    counters: dict[str, int] = {}
    out = sweep_text("**Pro ($79/month)** and **Starter ($15/month)** tier $0.40/1K", counters)
    assert "€65" in out and "$79" not in out
    assert "€25" in out and "$15" not in out
    assert "€0.50/1K" in out, "PAYG tier-3 per-1K rate must be 0.50, not 0.40"


def test_sweep_preserves_payg_api_fifteen_euro_total():
    counters: dict[str, int] = {}
    out = sweep_text("API overage: 150K extra at $0.10/1K = $15", counters)
    assert "€15" in out, "the PAYG API €15 total must keep its number"


def test_sweep_rewords_third_party_usd_facts():
    counters: dict[str, int] = {}
    out = sweep_text("Penalties: up to **$51,744 per email**; Critical: $500–$5,000", counters)
    assert "USD 51,744" in out and "$51,744" not in out
    assert "USD 500–5,000" in out


def test_sweep_is_idempotent():
    sample = "Starter ($15) Pro ($79) $0.40/1K Beyond 100K: $0.40 per 1,000"
    once = sweep_text(sample, {})
    twice = sweep_text(once, {})
    assert once == twice


# ── augment_training_data ──────────────────────────────────────────────────

def test_payg_cost_tier_one_covers_exactly_ten_thousand():
    assert augment._payg_cost(10_000) == 10.00
    # 10,000 × 0.001 + 1 × 0.0008 = 10.0008 → 10.00
    assert augment._payg_cost(10_001) == 10.00
    assert augment._payg_cost(50_000) == 42.00
    assert augment._payg_cost(100_000) == 82.00


def test_generated_pricing_examples_have_no_negative_volumes():
    for example in augment.generate_pricing_examples():
        text = example["text"]
        assert "| -" not in text.replace("| -", "| -"), text[:200]
        for part in text.split("|"):
            part = part.strip()
            assert not (part.startswith("-") and part[1:2].isdigit()), f"negative cell {part!r}"


def test_comparison_table_renders_unlimited_limits():
    examples = augment.generate_pricing_examples()
    compare = next(e for e in examples if "Compare the Scale and Enterprise" in e["text"])
    assert "Unlimited" in compare["text"]
    assert "1,000,000" not in compare["text"], "plans.rs -1 limits must render as Unlimited"
    assert "1,000,000,000" not in compare["text"]


def test_augmented_data_teaches_dynamic_dns_only():
    corpus = ""
    for example in augment.generate_pricing_examples() + augment.generate_adversarial_examples() \
            + augment.generate_multiturn_examples():
        corpus += example["text"]
    for banned in ("include:_spf.apexmail.ee", "include:spf.apexmail.ee",
                   "dkim.apexmail.ee", "bounce.apexmail.ee",
                   "apexmail._domainkey"):
        assert banned not in corpus, f"static DNS claim {banned!r} must not be taught"
    assert "Dashboard" in corpus or "dashboard" in corpus


# ── evaluate.py scorer ─────────────────────────────────────────────────────

def test_keyword_recall_naming_and_pass():
    score = score_golden_answer(
        "The Pro plan costs €65/month and includes 150,000 emails.",
        "Pro is €65/month with 150,000 emails included.",
    )
    assert "keyword_recall" in score
    assert score["price_match"] is True
    assert score["correct"] is True


def test_wrong_price_fails_even_with_good_keyword_overlap():
    score = score_golden_answer(
        "The Pro plan costs €65/month and includes 150,000 emails.",
        "The Pro plan costs €30/month and includes 150,000 emails for the price.",
    )
    assert score["price_match"] is False
    assert score["correct"] is False, "exact-price-match gate must reject wrong prices"


def test_non_pricing_answer_has_no_price_gate():
    score = score_golden_answer("SPF, DKIM and DMARC authenticate your mail.",
                                "SPF, DKIM and DMARC authenticate your mail.")
    assert score["price_match"] is None
    assert score["correct"] is True


# ── evaluate_granular ──────────────────────────────────────────────────────

def test_found_wrong_numbers_fail_the_check():
    result = granular.check_pricing_in_response(
        "The Pro plan is €65/month and the add-on is €30/mo.", expected_plan="pro"
    )
    assert result["passed"], "canonical price + canonical add-on should pass"
    result = granular.check_pricing_in_response(
        "The Pro plan is €65/month plus €89 setup.", expected_plan="pro"
    )
    assert not result["passed"], "extra wrong number must fail (found_wrong now used)"
    assert any(v.get("wrong_number") for v in result["violations"])


def test_granular_payg_boundaries():
    assert granular._payg_cost(10_000) == 10.00
    assert granular._payg_cost(10_001) == 10.00  # 10,000 × 0.001 + 1 × 0.0008
    assert granular._payg_cost(50_000) == 42.00


def test_repeated_plan_questions_are_all_evaluated():
    pro_questions = [q for q, plan, _ in granular.PRICING_TESTS if plan == "pro"]
    assert len(pro_questions) >= 2, "fixture needs repeated plans"
    responses = {f"pro::{q}": "€65" for q in pro_questions}
    results = granular.run_deterministic_checks(responses)
    details = results["pricing_accuracy"]["details"]
    assert len(details) == len(pro_questions), (
        f"all {len(pro_questions)} pro questions must be evaluated, got {len(details)}"
    )


def test_feature_gate_hipaa_matches_plans_rs():
    hipaa = next(t for t in granular.FEATURE_TESTS if t[2] == "HIPAA")
    assert hipaa[3] is False, "plans.rs: hipaa_compliance is false on every plan"


# ── generate_dataset stable splits ─────────────────────────────────────────

def test_row_bucket_is_deterministic_and_order_independent():
    row = {"text": "Starter is €25/mo", "id": 1}
    first = generate_dataset.row_bucket(row, 0.10, 0.10)
    assert first == generate_dataset.row_bucket(row, 0.10, 0.10)
    assert first == generate_dataset.row_bucket(row, 0.10, 0.10)


def test_appending_rows_never_moves_existing_rows():
    rows = [{"text": f"example {i} costs €25"} for i in range(200)]
    fractions = (0.10, 0.10)
    before = {json.dumps(r, sort_keys=True): generate_dataset.row_bucket(r, *fractions) for r in rows}
    # Append 50 more rows: every original row must keep its bucket.
    rows += [{"text": f"new {i}"} for i in range(50)]
    after = {json.dumps(r, sort_keys=True): generate_dataset.row_bucket(r, *fractions) for r in rows}
    for key, bucket in before.items():
        assert after[key] == bucket, f"row moved from {bucket} to {after[key]}"


def test_split_fractions_hold_at_scale():
    rows = [{"text": f"row {i}"} for i in range(5_000)]
    counts = {"train": 0, "val": 0, "test": 0}
    for row in rows:
        counts[generate_dataset.row_bucket(row, 0.10, 0.10)] += 1
    assert 0.07 * len(rows) < counts["val"] < 0.13 * len(rows)
    assert 0.07 * len(rows) < counts["test"] < 0.13 * len(rows)


# ── prompts_v2 ─────────────────────────────────────────────────────────────

def test_pricing_table_is_canonical_euro():
    for price in ("€0", "€25", "€65", "€150", "€350", "€3,000"):
        assert price in PRICING_TABLE, f"{price} missing from PRICING_TABLE"
    assert "$" not in PRICING_TABLE
    assert "$" not in PAYG_INFO
    for rate in ("€0.001", "€0.0008", "€0.0005", "€0.0003", "€0.40", "€0.10"):
        assert rate in PAYG_INFO, f"{rate} missing from PAYG_INFO"


def test_system_prompt_uses_apexmail_ee():
    prompt = build_system_prompt("starter_healthy")
    assert "apexmail.com" not in prompt
    assert "support@apexmail.ee" in prompt


# ── validate_data_prices (adversarial corpus detection) ────────────────────

def test_validator_catches_adversarial_corpus(tmp_path: Path) -> None:
    bad_rows = [
        {"messages": [{"role": "assistant", "content": "Starter costs €15/month"}]},
        {"messages": [{"role": "assistant", "content": "PAYG is €0.007 per email"}]},
        {"messages": [{"role": "assistant", "content": "| Tier | -5,000 |"}]},
        {"messages": [{"role": "assistant", "content": "Pro $65/month"}]},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bad.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for row in bad_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        problems = validate_data_prices.validate_file(path)
        joined = "\n".join(problems)
        assert "starter" in joined.lower()
        assert "per-email rate" in joined
        assert "negative volume" in joined
        assert "'$' price remains" in joined


def test_validator_passes_canonical_corpus(tmp_path: Path) -> None:
    good_rows = [
        {"messages": [{"role": "assistant", "content": "Starter is €25/month; Pro €65."}]},
        {"messages": [{"role": "assistant", "content": "PAYG: €0.001 per email; overage €0.40 per 1,000."}]},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "good.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for row in good_rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        assert validate_data_prices.validate_file(path) == []


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]


def main() -> int:
    import inspect

    failures = 0
    for test in TESTS:
        try:
            if len(inspect.signature(test).parameters) > 0:
                test(Path(tempfile.mkdtemp()))
            else:
                test()
            print(f"  PASS {test.__name__}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"  FAIL {test.__name__}: {exc}")
    print(f"\n{len(TESTS) - failures}/{len(TESTS)} tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
