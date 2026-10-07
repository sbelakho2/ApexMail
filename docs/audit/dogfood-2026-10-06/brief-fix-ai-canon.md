# FIX FLEET — apps/ai pricing canon (whole slice)

You are a FIX agent. The AI training/eval pipeline carries an INVERTED pricing canon that
contradicts the product's single source of truth. Fix the whole slice; do not leave a single stale
reference. Work in /Users/sabelakhoua/IdeaProjects/ApexMail.

## Canonical truth (services/mail-server/crates/platform-catalog/src/lib.rs)
Free €0 / 3,000 emails / 30,000 API calls / 7-day retention / 1 team / 1 domain.
Developer €29 (annual €290) / 50,000 / 500,000 / 30 / 5 / 5.
Pro €89 (annual €890) / 150,000 / 2,000,000 / 60 / 10 / 25.
Growth €229 (annual €2,290) / 500,000 / 5,000,000 / 90 / 25 / 100.
Business €699 (annual €6,990) / 2,000,000 / 20,000,000 / 365 / 50 / unlimited.
Enterprise Cloud €1,750 (annual €17,500) / 5,000,000 / unlimited / 730 / unlimited / unlimited.
PAYG tiers 0.0010 / 0.0008 / 0.0005 / 0.0003 EUR/email; overage 80/60/35/35/35 millicents.
Free launch allowance 30,000 emails in the first 30 days (a PROMO, not the monthly limit).

## The work
`validate_pricing.py` and `prompts_v2.py`, `validate_data_prices.py`, `test_agent.py` were already
corrected. The rest of the slice still carries the stale table — 369 literal references across:
`training/data/augmented_pricing_recall.jsonl` (79), `generate_gap_training.py` (74),
`.../augmented_pricing_recall_train.jsonl` (66), `extract_full_recovered.py` (50), `stress_test.py`
(38), `integrate_recovered.py` (28), `test_fixes.py` (26), `generate_recovered_training.py` (17),
`sweep_currency_to_eur.py` (16), `.../augmented_pricing_recall_val.jsonl` (13),
`extract_all_recovered.py` (12), `validate_pipeline.py` (11), `test_aggressively.py` (9),
`stress_test_agent.py`, `augment_training_data.py`, `TRAINING_REPORT.md`, plus whatever
`grep -rn "€25\|€65\|€150\|€350\|€3,000"` still finds.

1. **One canon, one import.** Any file that generates, augments, validates or asserts prices must
   derive from `CANONICAL_PRICING` in `validate_pricing.py` (import it) — never re-hardcode a
   number. `sweep_currency_to_eur.py` (a one-shot migration) may keep its rules but must target the
   canonical values.
2. **Rewrite the corpora.** Run the pipeline's own correction path (`python validate_pricing.py
   --fix`) or the sweep script on the JSONL data, then re-run `validate_pricing.py` and
   `validate_pipeline.py` until both pass with zero findings. Training data that teaches €65 for Pro
   must not survive.
3. **Fix the assertions.** `stress_test_agent.py` `must_include` lists and `test_fixes.py` /
   `test_aggressively.py` expectations must assert the CANONICAL prices; a test that requires a
   wrong price can never pass against a correct model.
4. **TRAINING_REPORT.md** (and any doc in the slice) must state the canonical table; where it calls
   the correct prices "stale", correct the claim.
5. Prove it: `python validate_pricing.py` and `python validate_pipeline.py` pass; the grep above
   returns nothing outside historical/one-shot-migration files (which must name the canonical
   target).

## Rules
- You own `apps/ai/**` only. Do not touch `services/**` or `tools/**` (other agents own those).
- No placeholders; no deleting tests to make them pass — fix their expectations.
- Report: per item FIXED (evidence: command + result) / NOT FIXED (exact blocker).
