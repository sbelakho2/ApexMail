# Self-hosted CI/CD — operations runbook

The production CI/CD pipeline lives in [`ci/`](../../ci/README.md) and runs
ON the deploy host — it does not depend on GitHub Actions, GitHub runners,
GHCR or the GitHub API. The full design, the workflow-by-workflow
replacement map, and the host installation steps are in
[`ci/README.md`](../../ci/README.md). This page is the operator cheat-sheet.

## Daily operation (on the deploy host)

```sh
/opt/apexmail/ci/pipeline.sh status     # last run, failure marker, containers
/opt/apexmail/ci/pipeline.sh list       # stages + timeouts
/opt/apexmail/ci/pipeline.sh run        # full pipeline now
journalctl -t apexmail-ci -f            # follow pipeline logging
systemctl list-timers apexmail-pipeline.timer
```

Run artifacts: `/opt/apexmail/ci/runs/<UTC-timestamp>/` —
`manifest.json`, `stages/<stage>.log`, provenance, fmt/clippy/audit reports,
`_sqlx_migrations` backup (migrate stage), SBOMs (images stage). Kept to the
newest 30 runs.

## What the timer does every 5 minutes

`apexmail-pipeline.service` runs `ci/pipeline.sh run`:

1. **fetch** — `git fetch origin main` over the deploy key; refuses to build
   anything not pushed to origin/main.
2. **validate / test / security** — the CI lane (all gates from the former
   GitHub workflows; see the replacement map in `ci/README.md`).
3. **images / migrate / deploy / verify** — build all service images, run the
   migration gate (with a pre-run `_sqlx_migrations` backup), recreate the
   compose stack, reload nginx, and verify the rollout (health, HTTP, SMTP,
   TLS, cache coherence).
4. **notify** — on failure: `ci/.last-failure`, `journalctl -t apexmail-ci`,
   and an email enqueued through the platform's own `email_queue` (rate
   limited to one per 30 minutes).

A hard failure in any stage stops the line — services are never recreated on
a red build. Only one run executes at a time (lock).

## Common tasks

| Task | Command |
|---|---|
| Re-run after fixing a red stage | `ci/pipeline.sh run --stages <stage>,deploy,verify` |
| CI only, no deploy | `ci/pipeline.sh run --skip-deploy` |
| Validate a branch before merge (any machine) | `ci/check-pr.sh <branch-or-sha>` |
| Ad-hoc security audit | `ci/pipeline.sh run --stages security` |
| Manual rollback | see `deploy/rollback-plan.md` (images are tagged `:<sha>` locally) |
| Bypass a wedged run | `systemctl stop apexmail-pipeline.service`, remove `ci/runs/.locks/` |

## Known currently-advisory gates (as of 2026-08-21)

`cargo fmt`, `cargo clippy -D warnings` and the fresh-DB migration check run
on every pipeline execution but report rather than block
(`CI_FMT_CHECK`/`CI_CLIPPY_CHECK`/`CI_MIGRATION_CHECK` in
`ci/pipeline.conf`) — the tree carries committed drift against them today.
Flip each to `required` as the corresponding cleanup lands. Details:
`ci/README.md` §9 (F1, F7, F8).
