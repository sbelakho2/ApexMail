# Hetzner Production Deploy — MOVED

This checklist has been **merged into
[`../DEPLOYMENT.md`](../DEPLOYMENT.md)** — the single canonical deployment
document. Keeping two copies of the host/secrets/bootstrap procedure let them
drift apart (this file still described "15 PROD_*_FILE secrets" when the
compose contract required 24, and a service list without `billing-service`
and `sales-autopilot`).

Everything that used to live here now lives there:

| Old section (this file) | New location |
|---|---|
| SSH key installation | [DEPLOYMENT.md § Fresh-host bootstrap](../DEPLOYMENT.md#fresh-host-bootstrap-one-time) step 1 |
| `hetzner-bootstrap.sh` host setup | same, step 2 |
| Host-key capture (`ssh-keyscan`) | same, step 3 |
| Rendering the production `.env` + the `PROD_*_FILE` secret table | [§ Rendered production secrets (the real 24)](../DEPLOYMENT.md#rendered-production-secrets-the-real-24) |
| GitHub secrets table + `gh secret set` commands | § Fresh-host bootstrap, step 5 |
| Triggering the deploy + what the workflow does | § Deployment methods |
| Let's Encrypt issuance (`issue-letsencrypt.sh`) | § Fresh-host bootstrap, step 7 and § TLS certificate management |
| Rotation (SSH key / secrets / GHCR token) | [`docs/operations/secret-rotation.md`](../../docs/operations/secret-rotation.md) and `scripts/rotate-secrets.sh` |

Validate your rendered env locally before uploading it:

```sh
make verify-env ENV_FILE=.env.production
```
