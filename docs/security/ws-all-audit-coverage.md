# WS-ALL Audit Coverage Ledger

This ledger closes the WS-ALL M-58 coverage gap by assigning every crate that was outside WS1-WS7 to an explicit audit surface, test owner, and verification command. Keep this file updated when workspace members are added or renamed.

| Crate | Primary Surface | Existing Coverage | Required Verification |
| --- | --- | --- | --- |
| `ai-embeddings` | embedding generation, chunking, vector search routes | functional AI tests cover embedding/search workflows | `cargo test --manifest-path services/mail-server/Cargo.toml -p ai-embeddings --lib` and `cargo test --manifest-path services/mail-server/Cargo.toml -p functional-tests --test functional_ai` |
| `devex-service` | onboarding, SDK management, webhook tester | service lib compile/test coverage | `cargo test --manifest-path services/mail-server/Cargo.toml -p devex-service --lib` |
| `edge-cases` | EAI, attachment, calendar, and delivery edge-case parsing | service lib compile/test coverage | `cargo test --manifest-path services/mail-server/Cargo.toml -p edge-cases --lib` |
| `fingerprint` | JA4/TLS and HTTP/2 fingerprint parsing | dedicated unit tests | `cargo test --manifest-path services/mail-server/Cargo.toml -p fingerprint` |
| `functional-tests` | end-to-end functional harness for AI, billing, compliance, templates, rate limits | integration tests under `tests/` | `cargo test --manifest-path services/mail-server/Cargo.toml -p functional-tests --tests` |
| `fuzz-tests` | property-based/fuzz harness for crypto, security, billing, services, validation | fuzz/property tests under `tests/` | `cargo test --manifest-path services/mail-server/Cargo.toml -p fuzz-tests --tests` |
| `queue-provider` | queue schema, provider abstraction, scheduler | service lib compile/test coverage | `cargo test --manifest-path services/mail-server/Cargo.toml -p queue-provider --lib` |
| `smoke-tests` | smoke harness for service construction and critical workflows | smoke tests under `tests/` | `cargo test --manifest-path services/mail-server/Cargo.toml -p smoke-tests --tests` |

## Governance

- `tools/check_audit_coverage.py` fails CI if any required crate disappears from this ledger.
- New workspace crates must be assigned either a dedicated audit workstream or an entry in this ledger before merge.
- Test-only crates still need explicit coverage because they protect high-risk cross-crate behavior.
