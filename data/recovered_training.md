# Recovered Training Data

> **File:** [`data/recovered_training.jsonl`](recovered_training.jsonl)
> **Last updated:** 2026-04-30
> **Records:** 31

## Purpose

This file contains recovered historical training examples that were retained for auditability and selective backfill. It exists alongside the primary curated datasets (`train.jsonl`, `val.jsonl`, `test.jsonl`) to preserve traceability until every record is either re-curated into the canonical corpus or formally retired.

## Format

Standard JSONL (JSON Lines) format — one JSON object per line. Each record has the following structure:

```json
{
  "text": "<|im_start|>system\nYou are ApexMail Agent...\n<|im_end|>\n<|im_start|>user\n...\n<|im_end|>\n<|im_start|>assistant\n...\n<|im_end|>"
}
```

### Fields

| Field  | Type   | Description                                            |
|--------|--------|--------------------------------------------------------|
| `text` | string | Full ChatML-formatted conversation (system + user + assistant turns). Contains pricing tables, account context, and diagnostic interactions. |

## Provenance

- **Source:** Legacy training corpus extracted from a prior pipeline iteration
- **Recovery date:** 2026-04-30
- **Recovery method:** Automated extraction from historical training snapshots
- **Quality:** Not manually reviewed — contains duplicates with canonical sets and may include outdated pricing references

## Differences from Canonical Datasets

| Aspect               | `recovered_training.jsonl`                          | `train.jsonl` / `val.jsonl` / `test.jsonl`          |
|----------------------|-----------------------------------------------------|------------------------------------------------------|
| **Curated**          | ❌ No — raw historical dump                         | ✅ Yes — manually reviewed and maintained            |
| **Deduplicated**     | ❌ Contains duplicates across records               | ✅ Cross-split deduplication enforced                |
| **Pricing**          | May contain outdated prices                         | ✅ Aligned with `docs/pricing.md`                    |
| **Format**           | Full ChatML in `text` field                         | Compact format with `system_prompt_id` references    |
| **Usage**            | Audit / backfill reference only                     | Primary training and evaluation                      |

## Usage Policy

1. **Do not** use for active training without deduplication against the canonical sets.
2. **Do not** rely on pricing data in this file — cross-reference against [`docs/pricing.md`](../docs/pricing.md) before using any record that discusses pricing.
3. Records SHOULD be migrated to the canonical format (`system_prompt_id` references) before being re-introduced into training.
4. This file will be retired once all records are either re-curated or explicitly excluded.

## Related Files

- [`data/README.md`](README.md) — General data directory documentation
- [`data/manifest.json`](manifest.json) — Machine-readable dataset metadata
- [`data/system_prompts.json`](system_prompts.json) — Shared prompt catalog
- [`data/golden_qa.jsonl`](golden_qa.jsonl) — Curated regression QA dataset
