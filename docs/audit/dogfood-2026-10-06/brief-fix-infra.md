# FIX FLEET — infra findings (from docs/audit/dogfood-2026-10-06/review-infra.md)

You are a FIX agent with a rigorous mandate. Work in
/Users/sabelakhoua/IdeaProjects/ApexMail. READ docs/audit/dogfood-2026-10-06/review-infra.md
in full first — it carries file:line evidence for every item below.

Own these paths ONLY: `ci/**`, `deploy/**`, `scripts/**`, `.woodpecker.yml`,
`.github/workflows/**`, `tools/` (only if a fix needs a helper), docs you must
update to keep claims true (`deploy/rollback-plan.md`,
`docs/deployment/migration-rollback.md`). Do NOT touch
`services/mail-server/**`, `apps/**`, or `packages/**` — other agents own them.

## Items (fix every P1 and P2; P3s as listed)

P1:
1. verify-stage auto-rollback unreachable: `ci/stages/deploy.sh` overwrites
   `.last-deployed-sha` with the NEW sha before `ci/stages/verify.sh` reads it
   (verify.sh:293-297). Fix the ordering/state so the pre-deploy sha survives
   into verify; the rollback must trigger on a verify failure.
2. `ci/stages/verify.sh:301-311`: rollback retags by compose key (`tracking`)
   but inspects image names (`tracking-service`) — silently skips tracking;
   and the missing-image policy is inverted vs its comment. Fix both; prove
   with a synthetic compose/image set fixture.
3. `deploy/scripts/deploy.sh:379,505-533`: manual rollback no-ops because the
   digest override stays in `COMPOSE_FILES`. Fix the override precedence;
   prove with a dry-run harness.
4. `deploy/scripts/deploy.sh:179-180`: manual deploy deletes the pipeline's
   own systemd units (`rm -f /etc/systemd/system/apexmail-*.service`). Fix
   to remove only units this script installs (or none).
5. `scripts/rotate-secrets.sh:499-500`: `backup_current_secrets` runs before
   `BACKUP_KEYS` is populated → empty backups + false success; `--rollback`
   never finds one. Fix the ordering/keys; prove with a local dry-run
   (temp dir) that a rotation then rollback restores the file contents.
6. `ci/pipeline.sh:88` + `fetch.sh`: a gates-only run (`--stages
   validate,ui,test,security` / `--skip-deploy`) can bless a never-deployed
   sha (the release-blessing manifest must only record a sha that was
   deployed and verified, or name the run as a non-deploy verification and
   never advance `.last-deployed-sha`).

P2:
7. `redis-backup`/`analytics-backup` exist in compose but are absent from the
   deploy/verify service lists → silently never run. Add them (and prove the
   lists now cover every backup service in compose; add a check that they
   stay covered).
8. Required lanes that warn-skip and can still bless when python3/zola are
   missing (`ui`/`validate`/`test`): a REQUIRED gate must fail closed when
   its runtime is missing (match the repo's `ci_check` conventions); keep the
   advisory override for triage.
9. `scripts/clickhouse-backup.sh`: ignores the query exit status and reports
   success on empty backups, then prunes older good ones. Fix: capture exit
   status, verify a non-empty backup before success, prune only after
   verification.
10. gitleaks "full history" scan under the documented `--depth 1` bootstrap:
    fetch full history (or fail honest) so the required secret scan is real.
11. Documented fresh-host bootstrap installs no `gh`/token while `fetch.sh`
    hard-fails without them: make bootstrap install/verify what fetch needs,
    or make fetch's requirement explicit and detectable at bootstrap time.

P3: fix items 12-20 from the review where mechanical (dead `image_name_guard`
version-tag check; `compare-baseline.sh` fail-open without bc;
`ci/woodpecker/toolchain.sh` divergent-unreferenced — reconcile or delete +
update references; stale workflow-archive references; hard-fail on non-git
deploy dir with a clear message; the CTA gate that cannot fail — make it
enforce the real CTA invariant or un-wire it and say why). For each P3, a
one-line justification in your report if you leave it.

## Rules
- No deploy, no production actions, no host-state mutation. Fixing deploy
  scripts is editing them + local dry-run proof only.
- Every fix needs PROOF it can fail: a shell probe/fixture/dry-run — capture
  the command + output in your report (docs/audit/dogfood-2026-10-06/fix-report-infra.md).
- Keep `bash -n` / `sh -n` clean; run any self-tests the touched tools have.
- Keep claims true: if a fix changes behavior a doc describes, update the doc
  in the same change.
- Report per item: FIXED (evidence) or a named blocker.
