# Emergency Key Revocation Runbook

> **Severity:** SEV1/SEV2 — Act immediately upon suspected key compromise.
> **Last Updated:** 2026-10-07

## Scope

This runbook covers the revocation surfaces that exist in the shipped
services: tenant API keys, enterprise sub-account API keys, user sessions, and
platform-wide credential rotation. There is no admin endpoint that revokes
arbitrary key material in bulk; platform-wide compromise is handled by
rotating the underlying secrets (see [Platform-wide compromise](#platform-wide-compromise)).

| Key / credential | Revocation surface | Permission |
|---|---|---|
| Tenant API key | `DELETE /v1/auth/api-keys/:id` | `api-keys:write` scope |
| Enterprise sub-account API key | `POST /api/enterprise/sub-accounts/:id/api-keys/:key_id/revoke` | Enterprise auth context, parent-tenant access |
| User session(s) | `POST /v1/auth/sessions/revoke` | Authenticated user (own sessions) |
| `API_KEY_HASH_SECRET` | Secret rotation (invalidates every stored key hash) | Operator |
| JWT signing keys | Secret rotation with `JWT_PREVIOUS_PUBLIC_KEYS_PEM` overlap | Operator |
| DKIM / webhook / other platform secrets | [Secret Rotation Runbook](secret-rotation.md) | Operator |

The API key deletion path is implemented in
[`api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs)
(`revoke_api_key`, `DELETE /v1/auth/api-keys/:id`) and removes the row from
`api_keys` for the caller's tenant, then invalidates the Redis auth cache
entry (`apexmail:api_key_cache:<key_hash>`). Verify with
`grep -n "api-keys/:id" services/mail-server/crates/api-server/src/routes/auth.rs`.

## Revoke a tenant API key

The tenant must hold an authenticated session or API key with the
`api-keys:write` scope. The handler is tenant-scoped: a key that belongs to a
different tenant returns `404` and is not touched.

```bash
curl -i -X DELETE https://api.apexmail.ee/v1/auth/api-keys/<key-id> \
  -H "Authorization: Bearer <session-or-api-key>"
# 204 No Content on success; 404 when the id does not exist for this tenant.
```

No request body and no `X-2FA-Code` header are read by the handler. Find the
id from the tenant console (Settings → API keys) or, as an operator, by
prefix:

```bash
psql "$DATABASE_URL" -c "
  SELECT id, key_prefix, name, created_at, expires_at
  FROM api_keys
  WHERE tenant_id = '<tenant-id>'
  ORDER BY created_at DESC;
"
```

Then verify the key is unusable (`401`):

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://api.apexmail.ee/v1/domains \
  -H "X-API-Key: <revoked-key-value>"
# Expected: 401
```

## Revoke an enterprise sub-account API key

Enterprise sub-account keys are revoked through the enterprise service. The
caller must have access to the sub-account's parent tenant; the handler
verifies that before revoking.

```bash
curl -i -X POST \
  https://enterprise.apexmail.ee/api/enterprise/sub-accounts/<sub-account-id>/api-keys/<key-id>/revoke \
  -H "Authorization: Bearer <enterprise-token>"
```

The same route is also mounted without the `/api/enterprise` prefix on the
enterprise service (see `services/mail-server/crates/enterprise/src/routes.rs`).

## Revoke user sessions

`POST /v1/auth/sessions/revoke` revokes either one named session or every
session of the calling user. Ownership is checked before the Redis revocation
marker is written, so a foreign session id cannot be revoked.

```bash
# One session
curl -X POST https://api.apexmail.ee/v1/auth/sessions/revoke \
  -H "Authorization: Bearer <user-token>" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "<session-id>"}'

# Every session of this user (including the current one)
curl -X POST https://api.apexmail.ee/v1/auth/sessions/revoke \
  -H "Authorization: Bearer <user-token>" \
  -H "Content-Type: application/json" \
  -d '{"revoke_all": true}'
```

There is no separate tenant-wide "kill all sessions" endpoint: tenant
suspension through the admin tenants surface is the platform-side control, and
each affected user re-authenticates after their session marker is checked.

## Platform-wide compromise

When the compromise is not limited to one tenant key, no admin bulk-revocation
endpoint exists. Rotate the underlying secret instead, following
[Secret Rotation Runbook](secret-rotation.md):

1. **`API_KEY_HASH_SECRET` rotation invalidates every API key at once.** The
   stored `key_hash` values were produced with the old secret, so every key
   fails verification after the new secret is deployed. This is the closest
   shipped equivalent to a global API-key revocation. Re-issue credentials to
   affected tenants afterwards.
2. **JWT signing keys:** stage the new key pair and keep the old public key in
   `JWT_PREVIOUS_PUBLIC_KEYS_PEM` for the overlap window, then remove it.
3. **Per-domain DKIM keys:** re-issue the domain's key pair through the domain
   verification flow; the previous selector stays resolvable during DNS
   propagation.
4. **Webhook signing secret:** rotate `WEBHOOK_SIGNING_SECRET` and re-deliver
   with the new signature scheme per the secret rotation runbook.

### Emergency direct-database fallback

If the API is unreachable, delete the compromised rows directly and invalidate
their cache entries. The API deletes rows rather than marking them revoked, so
the direct path must match that behavior:

```bash
psql "$DATABASE_URL" -c "
  DELETE FROM api_keys
  WHERE id::text = '<key-id>' AND tenant_id = '<tenant-id>'
  RETURNING key_hash;
"
# For each returned key_hash, drop the auth cache entry:
# redis-cli DEL "apexmail:api_key_cache:<key_hash>"
```

Cache entries are keyed `apexmail:api_key_cache:<key_hash>`; the API deletes
the entry as part of the revocation handler, so a direct-DB fallback must do
the same or a live instance can keep accepting the key until the cache entry
expires or is evicted.

## Incident response checklist

### Immediate (0–15 minutes)

- [ ] Identify the compromised credential and its tenant / sub-account
- [ ] Revoke the tenant API key (`DELETE /v1/auth/api-keys/:id`) or the
      enterprise sub-account key
- [ ] Revoke the affected user's sessions if a session token leaked
- [ ] Confirm `401` with the revoked credential
- [ ] Notify the on-call security engineer (SEV1) and begin audit review

### Short-term (15–60 minutes)

- [ ] Re-issue credentials to the affected tenant
- [ ] If the blast radius extends beyond one key, rotate `API_KEY_HASH_SECRET`
      and/or the JWT signing keys
- [ ] Review `api_keys` rows and auth logs for use of the compromised key
- [ ] Document scope in the incident record

### Recovery (1–24 hours)

- [ ] Verify services with the new credentials
- [ ] Monitor for residual unauthorized attempts
- [ ] Prepare the post-mortem

## Known gaps (follow-up work)

These capabilities are documented in older revisions but do **not** exist in the
shipped code; do not attempt them during an incident:

- No `POST /v1/admin/keys/revoke` (or unrevoke) endpoint, and no admin
  bulk-revocation API at all. The only revocation surfaces are the three
  routes above plus secret rotation.
- No `key_kid`, `key_version`, `key_status`, `revoked_at` bookkeeping columns
  on runtime-provisioned `api_keys` tables, and no `encryption_keys` table.
  The API deletion is the record; it is not separately audit-logged by the
  handler.
- No `X-2FA-Code` header requirement on API key deletion: the handler enforces
  the `api-keys:write` scope only.
- No `notify_affected_tenants` or `rotate_immediately` behavior on revocation.
  Tenant notification is a manual operator step.

## References

- [Secret Rotation Runbook](secret-rotation.md) — non-emergency rotation
- [Incident Response Runbook](runbooks/incident-response.md) — general incident
  response
- [Data Protection Architecture](../security/data-protection.md) — encryption
  key management design
- [`api-server/src/routes/auth.rs`](../../services/mail-server/crates/api-server/src/routes/auth.rs)
  — `DELETE /v1/auth/api-keys/:id`, `POST /v1/auth/sessions/revoke`
- [`enterprise/src/routes.rs`](../../services/mail-server/crates/enterprise/src/routes.rs)
  — sub-account API key revoke
