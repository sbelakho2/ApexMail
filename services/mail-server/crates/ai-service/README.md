# ai-service

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT DEPLOYED: this crate's server binary is not in the deployment Dockerfile or compose files, and no production service depends on it. Compile/test target only.

`ai-service` contains small, deterministic email-assistance helpers. It is **not** a model-serving, LLM, autonomous-agent, or training service.

## Supported behavior

- Template-based subject-line suggestions.
- Fixed-rule subject-line scoring and improvement suggestions.
- Selection of the highest score supplied in engagement data for send-time assistance.
- Basic text sentiment, summary, and local analytics utility functions.
- HTML sanitization and preview generation.

The authenticated HTTP routes are:

- `POST /suggest`
- `POST /optimize-time`
- `POST /content/score`

Each route returns its deterministic method in the response. `GET /health` is public and declares that model serving and training are unavailable.

## Explicit non-goals

This crate does not load or execute models, call external AI providers, train models, persist tenant experiment data, choose campaign variants autonomously, or send mail. The retired `/predict`, `/models`, `/train`, and `/bandits` routes are intentionally not registered.

A future model-serving system requires a separate design covering authenticated tenant boundaries, approved artifacts, offline and online evaluation, promotion/rollback, observability, data governance, and deployment.

## Development

```sh
cargo test -p ai-service --lib --bins
```
