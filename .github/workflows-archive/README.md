# Archived GitHub Actions workflows — superseded by the self-hosted pipeline

GitHub Actions is no longer part of ApexMail's CI/CD: the account's Actions
billing failed in August 2026 and the owner's standing directive is that CI
must not depend on GitHub at all. Every workflow that used to live in
`.github/workflows/` is archived here, verbatim, for reference.

**The one and only pipeline is [`ci/pipeline.sh`](../../ci/README.md).**
It runs on the deploy host itself (systemd timer + optional webhook), covers
build, test, security, images, migrations, deploy, verification, and
notification, and contains the full workflow→stage replacement map in
[ci/README.md §2](../../ci/README.md#2-workflow-replacement-map--every-file-in-githubworkflows).

`.github/workflows/` is intentionally **empty**. If a workflow file ever
reappears there, `ci/stages/validate.sh` fails the run until a replacement-map
row exists for it — and adding a row for a NEW workflow requires justifying
why it should exist at all instead of a pipeline stage.

## Why each file was archived

| Bucket | Meaning |
|---|---|
| REPLACED (16) | The check now runs in a `ci/` stage — often with more teeth (host-enforced gating instead of advisory PR checks). See the per-file table in ci/README.md §2. |
| MOVED-TO-ARCHIVE (6) | Not part of the deploy gate by design (load tests, mutation testing, browser-dependent QA, external link crawling, Dependabot). Manual invocations are documented in the same table. |

Restoring GitHub Actions would mean re-adding a second, competing pipeline —
don't. Add or extend a `ci/` stage instead.
