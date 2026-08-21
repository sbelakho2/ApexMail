# Troubleshooting

The public failure codes and the common failure modes operators and
integrators hit, with pointers to the authoritative documents.

## Public violation codes

Token-level failures collapse to the single public code
`invalid_or_expired`: wrong scope, IP mismatch, expired,
malformed/badly-signed tokens, too-fast solves, wrong region, wrong policy
epoch, missing client IP, counter/length violations, insufficient work,
indeterminate consumption. The client gets no oracle for which check
failed; the precise reason stays in the logs. Two refusals stay distinct:

- `rate_limited`: the Argon2id admission budget is exhausted. It is
  retryable, and the challenge is not burned.
- `temporary_unavailable`: the security storage or admission backend is
  unavailable. It is retryable, never a guessed success, and never
  `invalid_or_expired`.

The risk-decision codes stay as-is: `kiwi.post_solve_rejected` /
`kiwi.post_solve_step_up_required` (and `kiwi.post_solve_chain_required`
for chained challenges).

Endpoint-level JSON error codes:

| Code | Meaning |
|------|---------|
| `RATE_LIMITED` | per-client issuance limit exceeded (429) |
| `GLOBAL_RATE_LIMITED` | deployment-wide issuance limit exceeded (429) |
| `RISK_DENIED` | risk engine or outstanding-cap refusal (429; retry_after_ms on the process cap) |
| `SCOPE_LIMITED` | per-scope issuance cap exceeded (429) |
| `CROSS_ORIGIN_DENIED` | same-origin check failed (403) |
| `origin_rejected` | origin laundering defense refused the request (403) |
| `CROSS_SITE_REJECTED` | `Sec-Fetch-Site: cross-site` with fetch metadata enforced (403) |
| `FRAMING_REJECTED` | `Content-Length` + `Transfer-Encoding` or duplicate `Content-Length` (400) |
| `DUPLICATE_HEADER` | duplicate security-singular header (400) |
| `CANONICAL_PATH_REQUIRED` | noncanonical request target (404) |
| `UNSUPPORTED_CONTENT_ENCODING` | non-`identity` Content-Encoding (415) |
| `UNSUPPORTED_MEDIA_TYPE` | non-JSON Content-Type (415) |
| `QUERY_PARAMETERS_NOT_ALLOWED` | query parameters on the challenge POST (422) |
| `UNKNOWN_FIELDS` / `INVALID_JSON` | unknown fields / non-object body (422) |
| `DUPLICATE_FIELD` | duplicate JSON object key (422) |
| `INVALID_SCOPE` / `INVALID_REQUEST_BINDING` | identifier charset/length violation (422) |
| `BODY_TOO_LARGE` | challenge body over 8 KiB (413) |
| `AMBIGUOUS_FORWARDING` | trusted peer sent both forwarding headers with rejection enabled (400) |
| `SERVICE_UNAVAILABLE` | stale security-policy state refuses issuance (503) |
| `memory_budget_invariant` | readiness memory-budget invariant violated (503) |

## Common failure modes

**"LogicException: ArrayStorage configured outside test/dev".** the bundle
fails fast because in-memory storage cannot enforce single-use across
workers. Configure a shared storage: `RedisStorage` (recommended) or a
PSR-6 pool via the `storage` option. See
[getting-started.md](getting-started.md#installation) and
[operations.md](operations.md#shared-storage).

**Verification fails with `invalid_or_expired` after a config change.**
Check, in order: the secret key matches issuance (`KIWI_SECRET_KEY` is the
same key the Rust implementation uses). The policy epoch must be unchanged
(`risk.policy_version`; a bump invalidates all outstanding challenges). The
region must match (`risk.region`). The client IP used at verification must
be the same canonical IP the challenge bound to. Logs carry the precise
reason, never an IP, cookie value, decision id or nonce; see
[privacy.md](privacy.md#logs-and-metrics-never-carry-identity).

**Argon2id solves never complete in the browser.** Argon2id mode requires
WASM; the memory-hard solver has no JS fallback. Check CSP: the worker
needs `worker-src blob:` (the driver builds it from a Blob URL of locally
embedded code) and `script-src` needs `'wasm-unsafe-eval'`. The
authoritative requirements are in
[`SECURITY.md`](../../../../../SECURITY.md#csp--worker-requirements); the
recommended profile is in [getting-started.md](getting-started.md).

**Challenges are rejected as `rate_limited` under load.** the Argon2id
admission budget is saturated. The challenge is not burned; the client may
retry shortly. Size `argon2_max_concurrent_verifications` from benchmarks; see
[operations.md](operations.md#concurrency-must-be-benchmark-derived),
and keep the maximum verification request runtime below the lease lifetime
(`argon2_lease_ms`).

**Cross-origin 403s.** `same_origin_only` (forced true under strict
privacy) rejects requests whose `Origin` does not match the expected
origin. In production behind shared infrastructure, set `public_base_url`
so the check compares against server config, never the `Host` header. See
the same-origin enforcement section in
[security-hardening.md](security-hardening.md#same-origin-enforcement).

**The widget page works but the challenge endpoint 404s.** the canonical
path is a fixed ASCII target; anything else (trailing slash, dot segments,
percent-encoded bytes) is refused before any handling. Also verify the
route is registered: if the application configures `framework.router`
itself, import the bundle's routes file manually (`@KiwiCaptchaBundle/Resources/config/routes.php`). See [getting-started.md](getting-started.md#challenge-endpoint).

**No CORS headers on the response.** by design. The bundle emits no CORS
headers; origin enforcement is authorization and runs on every security
response regardless of CORS. If your reverse proxy adds CORS headers, it
must add `Vary: Origin` itself. See
[security-hardening.md](security-hardening.md#cors-is-not-authorization).

**A retried token returns `temporary_unavailable`.** the consume is
indeterminate (consumed without a committed result, still-pending record,
or no storage wired). The token is NOT burned; a retry after recovery
consumes and derives exactly once. A replayed token with a stored result
returns the same outcome deterministically. See
[security-hardening.md](security-hardening.md#ambiguous-consume-deterministic-retry).

**A mobile client's solve is rejected after a network change.** exact-IP
binding fails closed on a different network (the challenge is burned
single-use and the client re-solves). Prefer `request_binding` for mobile
clients; the QUIC migration policy is in
[operations.md](operations.md#quic-ip-migration-policy).

**The risk layer answers `RISK_DENIED` unexpectedly.** check the scope's
`base_risk`, `minimum` and `degraded` actions, the per-scope issuance cap,
and the outstanding-challenge caps. A risk-backend outage degrades to the
scope's `degraded` action (default `allow`); the risk layer is never a
single point of failure. See [risk-engine.md](risk-engine.md).

**Mixed-version deployments.** keep old binaries out of the pool with the
central security-policy hash; the readiness contract is in
[operations.md](operations.md#health-endpoints-rollback-resistant-readiness).

## Related resources

- [`SECURITY.md`](../../../../../SECURITY.md): supported versions and how to
  report a vulnerability.
- [claims-registry.md](claims-registry.md): the behaviors pinned by tests.
- [glossary.md](glossary.md): terminology used in the codes above.
