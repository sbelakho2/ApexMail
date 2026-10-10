# Retained performance run records

Files here are the `--json-out` records of controlled latency runs (the
strict manual hard-ratchet benchmarks). Each record carries the command,
configuration, environment, source commit, the measured distribution and
the ratchet verdict, so a controlled measurement stays auditable instead
of living only in terminal scrollback.

Retain a new record by running the benchmark on the controlled machine
with `--json-out`, pointing it at a new file under this directory, for
example:

    php packages/kiwicaptcha/tools/perf-bench-risk.php --redis \
      --json-out packages/kiwicaptcha/tools/perf-results/risk-latency-<date>.json

The strict-baseline and Redis-URL environment controls are the same ones
the manual benchmark workflow sets.

Do not raise a ratchet from a shared-runner sample. The dedicated
benchmark path is the controlled machine, and the shared-runner timing
steps stay advisory.
