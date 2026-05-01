# Training And Evaluation Data

This directory contains versioned JSONL datasets used for ApexMail QA, model training, and evaluation.

## Canonical Metadata

- Human-readable guidance: `data/README.md`
- Machine-readable metadata: `data/manifest.json`
- Canonical pricing reference for data refreshes: `docs/pricing.md`

## Dataset Rules

1. Bump the dataset version in `data/manifest.json` whenever records are added, removed, or semantically rewritten.
2. Update the `provenance` and `source_of_truth` fields when a dataset is regenerated from a new source.
3. Keep pricing- or plan-sensitive examples aligned with `docs/pricing.md` before committing.
4. Do not overwrite recovered datasets without recording how they were produced.
5. Store repeated system prompts in `data/system_prompts.json` and reference them from JSONL records with `system_prompt_id`; training entrypoints expand those references at load time.

## Files

- `golden_qa.jsonl`: curated regression questions and answers for high-signal QA checks.
- `system_prompts.json`: shared prompt catalog used by compact `train.jsonl`, `val.jsonl`, and `test.jsonl` records.
- `train.jsonl`: primary model training corpus.
- `train_agent.jsonl`: agent-specific training examples.
- `val.jsonl`: validation set used during tuning.
- `test.jsonl`: holdout test set.
- `recovered_training.jsonl`: recovered historical data retained for traceability until fully superseded.
