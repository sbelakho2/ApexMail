# Secrets Handling

ApexMail secret material must not be committed to Git. Local development secret files live under `secrets/`, which is ignored at the repository root, and production deployments should source equivalent values from the platform secret manager.

## Required Local Compose Files

The dev compose stack mounts these local files (seeded automatically by
`tools/run-compose-smoke.sh`; create them by hand for a manual `up`):

- `secrets/postgres_password.txt`
- `secrets/redis_password.txt`
- `secrets/clickhouse_password.txt`

For production-shaped env files, run `make verify-env ENV_FILE=<file>` (or
`tools/validate-prod-env.sh <file>`) — it derives the required variable set
from the `${VAR:?}` guards in docker-compose*.yml and fails fast on missing
or placeholder values, including the `PROD_*_FILE` secret-file paths.

## JWT Secrets

The Rust API server uses RS256 keys and expects these environment variables:

- `JWT_PRIVATE_KEY_PEM`
- `JWT_PUBLIC_KEY_PEM`

The Enterprise service still uses its separate internal HS256 `JWT_SECRET` until it migrates to the shared RSA verifier. Do not reuse a legacy `secrets/jwt_secret.txt` value for the API server; generate and store the API RSA key pair in the production secret manager.

## Git History Check

As of May 1, 2026, `git log --all -- secrets` returns no entries in this repository state, and `git ls-files secrets` returns no tracked secret files.