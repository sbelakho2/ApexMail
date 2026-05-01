# Secrets Handling

ApexMail secret material must not be committed to Git. Local development secret files live under `secrets/`, which is ignored at the repository root, and production deployments should source equivalent values from the platform secret manager.

## Required Local Compose Files

Run `tools/validate-compose-secrets.sh` before starting the Docker Compose stack. The helper fails fast when these local files are missing or empty:

- `secrets/postgres_password.txt`
- `secrets/redis_password.txt`
- `secrets/clickhouse_password.txt`

## JWT Secrets

The Rust API server uses RS256 keys and expects these environment variables:

- `JWT_PRIVATE_KEY_PEM`
- `JWT_PUBLIC_KEY_PEM`

The Enterprise service still uses its separate internal HS256 `JWT_SECRET` until it migrates to the shared RSA verifier. Do not reuse a legacy `secrets/jwt_secret.txt` value for the API server; generate and store the API RSA key pair in the production secret manager.

## Git History Check

As of May 1, 2026, `git log --all -- secrets` returns no entries in this repository state, and `git ls-files secrets` returns no tracked secret files.