# Retired Model-Training Archive

This directory no longer provides a model-training, evaluation, model-upload, adapter-export, or model-promotion workflow.

The deployed `ai-service` provides authenticated deterministic email-assistance helpers only. It does **not** host a language model, execute model inference, train a model, run an autonomous agent, or accept model artifacts.

## Why this was retired

The former QLoRA/agent pipeline produced unsupported behavior and contained synthetic product, DNS, routing, and tool-execution claims. It had no governed production promotion path, tenant-isolation model, or matching runtime. Keeping runnable scripts or deploy-shaped artifacts would misrepresent the product.

## Future work

A future model program must be introduced as a separately reviewed design. Before any training code or corpus is reintroduced, it needs:

1. a deployed, authenticated, tenant-isolated runtime;
2. an approved data-governance and provenance process;
3. factual sources tied to current API and delivery contracts;
4. evaluation for security, privacy, and cross-tenant isolation;
5. artifact signing, review, rollback, and deployment controls.

Until then, model artifacts and generated training outputs are ignored by version control and must not be treated as deployable.