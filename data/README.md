# Retired Model-Training Data

This directory intentionally contains no active model-training, agent-training, validation, or model-evaluation corpus.

The prior JSONL corpus and shared system prompts were removed because they trained unsupported autonomous-agent behavior and contained fictional product, account, DNS, routing, and delivery claims. No application or deployment path loads them.

The deployed `ai-service` is limited to deterministic helpers and does not consume a model or a training corpus. Do not add a data file here merely to enable offline experimentation.

Any future corpus requires an approved design that establishes provenance, privacy review, factual API/delivery sources, tenant isolation, evaluation, and a controlled artifact-promotion path before it can be committed or used.
