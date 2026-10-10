"""dogfood-v2 — a wider, more adversarial, self-proving dogfood harness.

Lane D1 (docs/audit/dogfood-v2-2026-10-09/brief-d1-harness.md).

Package layout:
  config.py     runtime configuration + paths
  httpc.py      paced HTTP client with cookie jar / host routing / CSRF
  kiwi.py       KiwiCaptcha challenge mint + proof-of-work solver (legitimate)
  mail.py       mail-plane source abstraction (Mailpit live / fixture mailbox)
  dataplane.py  SQL data-plane abstraction (psql live / fixture in-memory)
  identity.py   product-lifecycle identity provisioning (owner/member/operator/keys)
  fixtures.py   disposable, unique-id resource fixtures per tenant
  ledger.py     mechanical surface enumeration from sources of truth
  coverage.py   coverage.json, fail-if-unprobed rule, allowlist validation
  registry.py   probe registry (id, partition, surfaces, severity)
  findings.py   machine-readable findings model
  runner.py     execution engine (bounded concurrency, summary, exit codes)
  probes/       the attack batteries, one module per surface class
  selftest.py   disposable honest fixture server (--self-test)
  mutation.py   scratch-copy mutation seeding + targeted build + run (--mutation-test)
"""

HARNESS_VERSION = "2.1.0"
# 2.1.0 (lane D2 triage): single-prefix route attribution + masked Rust/SQL
# literal scanners (no phantom or doubled surfaces), DDoS_BLOCKED limiter
# recovery, captcha-issuance pacing, designed-state compose checks,
# partition-aware schema-orphan scan, precise env-consumer analysis.
