# ApexMail current readiness (generated)

GENERATED FILE: do not edit by hand. `tools/generate_current_readiness.py`
rebuilds this dashboard from mechanical sources: `ci/required-lanes.txt`,
`docs/invariants.toml`, `ci/test-expectations.toml`, the migration tree,
the CI stage sources and the nine pinned verdict rules encoded in the
generator. `ci/stages/validate.sh` runs the generator with `--check` and
fails the validate stage when this file drifts from the tree. Dated audit
records live under `docs/audit/history/` and are never edited after the
fact.

Last generated: 2026-10-30T02:51:11Z

## Owner-gated by design

These items need an environment value, a credential or an owner decision
that no CI run can supply. Each names its gate:

- Real-model corpora: the replay runs only with `AI_MODEL_API_KEY` plus a
  non-mock `AI_MODEL_ENDPOINT`; without them the lane records NOT
  EXECUTED (`tools/run_real_model_eval.sh`).
- Production PITR enablement: the operator includes
  `deploy/docker-compose.wal-archive.yml` and sets `WAL_ARCHIVE_TARGET`
  plus the archive key on the deploy host.
- Second host: the warm standby overlay needs `STANDBY_PRIMARY_HOST` and
  the replication password file on operator infrastructure.
- GitHub required status checks: owner directive, deliberately skipped
  (the contexts are published; pinning them required is the owner's
  step).

## Release gates

`ci/required-lanes.txt` holds 128 rows and every row resolves to a lane a stage actually runs (the `tools/check_waivers.py --check-lanes` parse).

Stage lanes (one row each): fetch, validate, docs, ui, test, security.

| Stage | Gate lanes |
|---|---|
| docs | 3: docs-architecture-truth, docs-architecture-truth-selftest, repo-map-up-to-date |
| security | 8: cargo-vet, migrator-apply-clean-db, migrator-apply-idempotency, migrator-dry-run, semgrep-sast, sqlx-migrate-clean-db, sqlx-migrate-idempotency, trivy-fs |
| test | 27: canary-lane-real-mail-qualification, real-model-eval-lane, cargo-deny, cargo-machete, contrast-gate, dogfood-harness-self-test, dogfood-ledger, feature-entitlement-classification, i18n-gate, journey-lane-live-stack, layout-gate, pre-commit-parity, satellite-kiwicaptcha-wasm, satellite-smtp-auth-proxy, sdk-go, sdk-java, sdk-php, sdk-python, sdk-ruby, sdk-typescript, security-feature-flags, static-lint-hadolint, static-lint-py-compile, static-lint-shellcheck, tag-balance-gate, workspace-dependency-cycles, workspace-suite |
| ui | 7: ui-accessibility-gate-e, ui-dead-links-gate-i, ui-flash-copy-gate-c, ui-form-hygiene-gate-d, ui-marketing-token-contrast-gate-m, ui-strings-catalog-drift-gate-k, ui-terminology-gate-j |
| validate | 77: alerting-rules, ark-authority-mirror, ark-console-artifact, ark-design-law, ark-marketing-artifact, ark-pdf-design-authority, ark-pdf-design-authority-self-test, asset-budget, asset-budget-self-test, capability-claims-vs-production-wiring, customer-dto-boundary, customer-dto-boundary-self-test, current-readiness-generated, deliverability-report-backed-by-its-artifact, docs-lint-integrity, docs-lint-ratchet, eval-corpora-vs-canonical-facts, external-route-census, forbidden-patterns, homepage-metrics-backed-by-their-artifact, image-pinning-checker-committed-fixtures, invariant-and-expectations-registry, invariant-registry-self-test, kiwi-marketing-isolation, kiwi-mirror-parity, knowledge-consistency-canonical-catalog, lane-waivers, legacy-processor, legacy-processor-self-test, legal-identity, marketing-broken-links, marketing-content-voice, marketing-font-optimization, marketing-html-validation, marketing-image-optimization, marketing-nginx-serving, marketing-page-content, marketing-pricing-freshness, marketing-seo-validation, marketing-serving-whitelist, marketing-wcag-contrast-heuristic, migration-sql-lint, no-generated-artifacts-tracked, outbound-delivery-contract, pg-pitr-restore-self-test, pg-wal-archive-self-test, postgres-backup-retention-self-test, postgres-restore-drill-self-test, postgres-wal-base-backup-self-test, payment-neutrality, pricing-drift, processor-legal-facts, production-env-contract, production-env-contract-values, production-env-forwarding, production-mollie-payment-wiring, public-artifacts-allowlist, public-artifacts-gate-self-test, repo-map-up-to-date, risk-lua-parity, rollback-plan-present, route-census-self-test, rust-panic-paths, sdk-version-lockstep, security-posture-baseline, soc-evidence-cadence, standby-contract, stub-ban, stub-ban-self-test, subprocessor-register-derived-from-deployment-config, template-leaks, tool-selftest-detector-self-test, tool-selftest-inventory, topology-contracts, waiver-gate-self-test, web-error-honesty, web-error-honesty-self-test |

## Invariants

`docs/invariants.toml` registers 27 invariants: 26 enforced, 1 planned.

enforced (26):
  I1, I2, I3, I4, I5, I6, I7, I8, I9, I10, I11, I12, I13, I14, I15, I16,
  I18, I19, I20, I21, I22, I23, I24, I25, I26, I27

planned (1):
  I17

## Test-scope evidence

- SQL migrations under `services/mail-server/migrations/`: 259 files, latest `287_processor_ledger_vocabulary.sql`.
- Tool migrations under `tools/migrations/`: 35 files.
- Packages registered in `ci/test-expectations.toml`: 69.
- Tools: 80 Python scripts at the top of `tools/`; the CI stages invoke 54 of them; 2 carry a meta-exemption with a reason. The validate.tool-selftest-inventory lane proves every invoked tool keeps a working self-test.

## Audit verdicts (code-derived)

Each row is the output of a rule in `tools/generate_current_readiness.py` that pins files, content needles and required-lane rows. A pinned file that disappears flips its row to OPEN on the next generation; nothing here is maintained by hand.

6 LANDED, 3 OWNER-GATED.

| Verdict | Status | Derivation |
|---|---|---|
| auth SLI | LANDED | 3 pinned files + 4 needles hold; lanes validate.alerting-rules |
| placement cohort | LANDED | 2 pinned files + 1 needle hold; lanes test.workspace-suite |
| webhook contract | LANDED | 2 pinned files + 2 needles hold; lanes test.workspace-suite |
| canary lane | LANDED | 2 pinned files + 4 needles hold; lanes test.canary-lane-real-mail-qualification |
| PITR drill | OWNER-GATED | evidence holds; execution needs WAL_ARCHIVE_TARGET (deploy/docker-compose.wal-archive.yml) |
| standby | OWNER-GATED | evidence holds; execution needs STANDBY_PRIMARY_HOST (deploy/docker-compose.standby-remote.yml) |
| onboarding machine | LANDED | 2 pinned files + 3 needles hold; lanes test.workspace-suite |
| DT executor | OWNER-GATED | evidence holds; execution needs HETZNER_API_TOKEN (services/mail-server/crates/enterprise/src/dedicated_exec.rs) |
| billing neutrality | LANDED | 7 pinned files + 4 needles hold; lanes validate.payment-neutrality |
