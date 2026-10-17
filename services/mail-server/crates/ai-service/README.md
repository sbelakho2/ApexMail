# ai-service

> **STATUS**
> Deployed as the internal `ai-service` container (port 3012, service-token
> auth). The chat pipeline is grounded (docs retrieval + canonical facts) and
> FAILS CLOSED while `AI_MODEL_ENABLED=false`: no model runtime, no
> generation — the chat endpoint returns an honest human-escalation.
> Routes registered: /health /suggest /optimize-time /content/score /models
> /predict /train /training/jobs/:id /evaluate /domains/dns-records /chat
> /admin/reindex /admin/chat/history.
>
> `/chat` is scoped by the REQUIRED `x-apexmail-tenant-id` header, and
> `/admin/chat/history` by BOTH that header and the REQUIRED
> `x-apexmail-user-id` header: assistant history is per USER (the console
> sessions are per-user and `docs/user-guide/assistant.md` promises
> conversations are visible only to the user they belong to), so a request
> without the user identity is refused rather than returning every
> teammate's turns.

> **STATUS — READ BEFORE RELYING ON THIS CRATE**
> NOT DEPLOYED: this crate's server binary is not in the deployment Dockerfile or compose files, and no production service depends on it. Compile/test target only.

`ai-service` contains small, deterministic email-assistance helpers. It is **not** a model-serving, LLM, autonomous-agent, or training service.

## Supported behavior

- Template-based subject-line suggestions.
- Fixed-rule subject-line scoring and improvement suggestions.
- Selection of the highest score supplied in engagement data for send-time assistance.
- Basic text sentiment, summary, and local analytics utility functions.
- HTML sanitization and preview generation.

## Configuration

`AI_EMAIL_AGENT_ENABLED` (default `false`) spawns the draft-only email
answering agent. It is opt-in by construction: the agent refuses to start
without mandatory human approval (`AI_EMAIL_REQUIRE_APPROVAL`), every reply it
writes is stored `pending_approval=true` for review, and no auto-send exists
anywhere in the path. With the gate off, nothing is spawned.

The authenticated HTTP routes are:

- `POST /suggest`
- `POST /optimize-time`
- `POST /content/score`

Each route returns its deterministic method in the response. `GET /health` is public and declares that model serving and training are unavailable.

## Explicit non-goals

The deterministic helpers above do not load or execute models or call external AI providers. The opt-in, approval-gated draft agent (see Configuration) uses the configured LLM client but never sends mail and never approves its own output. This crate does not train models, persist tenant experiment data, choose campaign variants autonomously, or send mail. The retired `/predict`, `/models`, `/train`, and `/bandits` routes are intentionally not registered.

A future model-serving system requires a separate design covering authenticated tenant boundaries, approved artifacts, offline and online evaluation, promotion/rollback, observability, data governance, and deployment.

## Development

```sh
cargo test -p ai-service --lib --bins
```
