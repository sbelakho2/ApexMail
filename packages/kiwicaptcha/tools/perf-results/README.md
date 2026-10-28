# Retained performance run records

Files here are the `--json-out` records of controlled timing runs (the
strict manual hard-ratchet benchmarks). Each record carries the command,
configuration, environment, source commit, the measured distributions
and the ratchet verdict, so a controlled measurement stays auditable
instead of living only in terminal scrollback.

## The flag

`packages/kiwicaptcha/tools/perf-bench.php`,
`perf-bench-risk.php`, `perf-wait.php` and `perf-wait-replica.php`
accept `--json-out <path>`. The record is written whether the run
passes or fails its ratchet, because a failing run is the one whose
provenance matters most. The exit status changes only on an unwritable
path, because a missing record is worse than a failed run. The flag
never changes what is measured. `perf-bench.php --iterations N` and
`--warmup N` keep a test run small, and the record's `configuration`
names them.

The schema string is `kiwicaptcha.perf-run/1`. The common envelope:

- `schema`, `tool`, `generated_at`, `command`.
- `baseline_file`: the baseline record the ratchet consulted, null
  when the tool applies no ratchet.
- `environment`: `php_version`, `php_sapi`, `os`, `arch`, `cpu_model`,
  `cpu_count`, `memory_total_bytes`, `runner`, `redis`. The
  `runner` block carries the identity variables the environment
  exposes (`CI`, `GITHUB_*`, `RUNNER_*`, `KIWI_*` and similar)
  or null. The `redis` block carries the wire target and the server
  version, or null when no Redis was used. A Redis target never
  carries a credential: the userinfo is replaced with `<redacted>`.
- `source`: the commit and whether tracked files were modified, or
  null outside a checkout.
- The tool body: `measurements`, `configuration`, the ratchet verdict
  per p95 and an overall `verdict`. The wait fixtures apply no
  ratchet, so their measurement leaves carry `"ratchet": null`. Every
  value that cannot be determined is an explicit null, never an
  omission.

Retain a new record by running a benchmark on the controlled machine
with `--json-out`, pointing it at a new file under this directory, for
example:

    php packages/kiwicaptcha/tools/perf-bench-risk.php --redis \
      --json-out packages/kiwicaptcha/tools/perf-results/risk-latency-<date>.json

The strict-baseline and Redis-URL environment controls are the same ones
the manual benchmark workflow sets.

Do not raise a ratchet from a shared-runner sample. The dedicated
benchmark path is the controlled machine, and the shared-runner timing
steps stay advisory.
