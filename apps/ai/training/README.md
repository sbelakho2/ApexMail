# Model Training Pipeline

This directory provides the **reviewed offline training runner** for the
deployed `ai-service`.

The `ai-service` itself does not host a language model or run inference for
requests: it exposes authenticated deterministic email-assistance helpers
(analytics, content scoring, send-time recommendations) and an optional
agent-assisted email drafting flow. When the operator sets
`AI_TRAINING_RUNNER` to this pipeline, the service can trigger governed
training runs (`validate → train → test`) and record their artifacts.

## What lives here

- `pipeline.sh` — the runner: `validate`, `train`, `test`, `status`, `full`.
  Called only by `ai-service` via `AI_TRAINING_RUNNER` (an absolute
  executable path) or manually on the training host.
- `train.py` — QLoRA fine-tuning driver (config-driven, 4× B200 setup).
- `config.yaml` — the QLoRA/model configuration used by `train.py`.
- `README.md` — this file.

## Contract with ai-service

- `AI_TRAINING_RUNNER` must be an existing absolute executable path;
  otherwise training requests return "training unavailable".
- The runner is invoked with `--job-id`, `--model-id`, `--epochs` and
  `--artifact-dir` and must write a validated `metrics.json` into the
  artifact directory.
- Generated artifacts are gitignored; nothing here is deployed into the
  mail path. Training is a separate, operator-gated process.

## Governance

Any change to the model program (new base model, new corpus, changed
prompt/agent behavior) requires:

1. a deployed, authenticated, tenant-isolated runtime;
2. an approved data-governance and provenance process;
3. factual sources tied to current API and delivery contracts;
4. evaluation for security, privacy, and cross-tenant isolation;
5. artifact signing, review, rollback, and deployment controls.
