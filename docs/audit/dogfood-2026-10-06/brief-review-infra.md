# Brief — review: infrastructure (deploy, ci, workflows, compose, scripts, secrets policy)

You are a rigorous, adversarial reviewer for the ApexMail repo at the workspace
root. READ-ONLY: do not edit any file outside your report.

Deliverable: `docs/audit/dogfood-2026-10-06/review-infra.md` — findings with
severity (P0–P3), `file:line` evidence, why it matters, and a concrete fix.
Mark anything you could not verify as NOT-VERIFIED with the reason. Do not
report style nits unless they can cause a wrong deploy, a missed gate, a
secret leak, or a broken rollback.

Scope (file-by-file for small dirs; read every file in full unless noted):
- `deploy/**` (115 files; read every script and config in full — skip binary
  fixtures; check: deploy.sh/rollback paths, health gates, hook wiring,
  secrets handling, nginx confs, entrypoint-wrapper, backups, HA runbooks
  where they make testable claims)
- `ci/**` (31 files; stages/*.sh, lib.sh, pipeline.conf, pipeline.sh — the
  gate wiring, required-vs-advisory flags, exit-code propagation, dry-run
  honesty, and whether any stage can silently skip a required check)
- `.github/workflows/**`, `.woodpecker.yml` (existence + required checks +
  whether workflows and ci/ stages agree; the release-blessing manifest)
- root infra: `docker-compose.yml`, `docker-compose.*.yml`, `Makefile`,
  `trivy-secret.yaml`, any `Dockerfile*` outside apps/ (apps/marketing's is
  already reviewed)
- `scripts/**` (8 files, read all): clickhouse-backup, compare-baseline,
  consistency-test, dedup-training-splits, rotate-secrets,
  scan-vulnerabilities, security-audit, verify-branch-protection — each
  must actually do what its name/docstring claims, fail closed, and not
  print success on a skipped step
- `secrets/**` policy: these are committed dev secret FILES — verify (a)
  none is a REAL external credential (check names vs known formats), (b) the
  intent is documented and .env.example/.gitignore agree, (c) production
  cannot boot from these dev files (env precedence), (d) `trivy-secret.yaml`
  allowlist matches reality rather than papering over live secrets

Adversarial bar: for every gate/check your files claim to enforce, try to
construct the scenario where it passes while the thing it guards is broken
(or vice versa). Grep across `ci/` and `deploy/` for references to things
that no longer exist (retired paths, removed scripts, deleted crates).
Check that documented commands (`make x`, `docker compose --profile …`)
actually exist.

Write the report as you go (incremental sections), finish with a coverage
ledger: every directory + file count reviewed, and an explicit "what I did
not reach".
