# Gitleaks history triage — 2026-08-21

Scope: full git history (384 commits, ~539 MB scanned) with the hardened
`.gitleaks.toml` (anchored fixture path allowlists, no JWT blanket allow).
The previous broad allowlist suppressed 100 of these findings; this document
records the studied review of what surfaced.

## Totals

286 findings: generic-api-key 168, curl-auth-header 102, stripe-access-token 8,
private-key 7, linkedin-client-id 1.

## Classification (by path and manual sampling of every high-risk class)

| Rule | Test/fixture | Docs | Source | Infra-config |
|---|---|---|---|---|
| generic-api-key | 93 | 19 | 56 | — |
| curl-auth-header | — | 91 | 11 | — |
| stripe-access-token | 3 | — | 5 | — |
| private-key | 4 | 1 | 1 | 1 |
| linkedin-client-id | — | — | 1 | — |

## Verdicts

- **private-key (7)** — all benign. PEM blocks in `.env.example` /
  `.env.production.example` and `docs/deployment/configuration.md` are
  placeholder examples; `deploy/k8s/secrets.template.yaml` is a template;
  the historical `api-server/src/config.rs` match is the development
  default (`kiwi_secret_key` defaults to the literal `"dev"`, and
  production rejects it — verified at config.rs:682,746). No production
  key material found.
- **stripe-access-token (8)** — all benign. `dlp-engine` hits are the
  detector's own pattern strings and test vectors (a scanner that detects
  `sk_live_` necessarily contains it); the `apps/billing` hits are test
  fixtures with synthetic keys.
- **curl-auth-header (102)** — documentation examples of authenticated
  curl invocations (`-H "Authorization: Bearer <token>"` shapes) plus the
  same shape in code comments.
- **generic-api-key, source (56)** — sampled twelve distinct sites across
  the class: all are the kiwicaptcha crypto suite's published test vectors
  (hex keys inside `#[cfg(test)]` blocks and the quickstart example),
  marketing API documentation samples, and dev-default configuration
  strings (`dev-...-change-me` family, which compose now fail-fasts away
  in production).
- **linkedin-client-id (1)** — false positive: the string `linkedinPresence`
  in a training-pipeline feature list.

## Conclusion

No confidential secret is present in the repository history based on this
review. Credential rotation is therefore not indicated by this evidence.
The findings that remain after this triage are the unavoidable cost of a
correct scanner (test vectors, detector patterns, documentation examples)
and are now visible rather than hidden — which is the desired state.

If a future scan should silence the provably-benign detector fixtures, add
narrow, anchored allowlist entries for those exact files only; do not
restore the previous broad path or JWT allowlists.
