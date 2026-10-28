#!/usr/bin/env python3
"""Seed the canary stack for the real-mail qualification lane.

Runs against the ISOLATED canary compose project (tools/run_canary_lane.sh).
Everything is created through product-owned shapes:

  * tenant / owner user / wildcard-scope API key — SQL inserts mirroring
    tools/dogfood-live-capabilities.py (the key hash is the product's
    HMAC-SHA256(key, API_KEY_HASH_SECRET) form read from the live
    api-server's own environment);
  * the sending domain — POST /v1/domains, so the product generates a REAL
    encrypted DKIM keypair for it (the worker refuses unsigned SMTP);
  * verification flags — SQL UPDATE to verified/verified/ses_verified TRUE
    (the canary receiver has no DNS to walk, same as every dev dogfood seed).

Output: one JSON line on stdout with the identity the driver needs. No
secrets besides the freshly minted lane-local API key, which never leaves
this machine's lane process boundary.

Usage: canary_seed.py --project NAME --api-base URL --domain-suffix SUFFIX
Exit codes: 0 = seeded, 1 = failure, 2 = usage.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
import urllib.request
import uuid

RUNNER_SHA = "622d54f343f74a3cba95e7fcd262496950b9d16c9dfef1ca6745b9cb7f28ecc6"  # noqa: E501 - pinned reviewed artifact


FILES = ["-f", "docker-compose.yml", "-f", "docker-compose.override.yml",
         "-f", "deploy/docker-compose.canary.yml", "--env-file", ".env"]


def compose(project: str, *args: str) -> str:
    proc = subprocess.run(
        ["docker", "compose", "-p", project, *FILES, *args],
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args[:3])} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def sql(project: str, statement: str) -> None:
    compose(project, "exec", "-T", "postgres",
            "psql", "-U", "apexmail", "-d", "apexmail", "-v", "ON_ERROR_STOP=1",
            "-c", statement)


def gen_id(n: int = 26) -> str:
    """The tenants/users VARCHAR(26) id domain (the dogfood helper's shape)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def api_key_hash(raw: str, secret: str) -> str:
    return hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--domain-suffix", default="canary.test")
    args = ap.parse_args()

    tenant_id = gen_id()  # tenants.id: VARCHAR(26)
    user_id = str(uuid.uuid4())  # users.id: UUID (the dogfood shape)
    raw_key = "am_canary_" + secrets.token_hex(24)
    tag = secrets.token_hex(4)
    domain = f"canary-{tag}.{args.domain_suffix}"

    secret = compose(args.project, "exec", "-T", "api-server",
                     "printenv", "API_KEY_HASH_SECRET").strip()
    if not secret:
        print("canary_seed: API_KEY_HASH_SECRET is empty in the stack", file=sys.stderr)
        return 1

    sql(args.project, (
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) "
        f"VALUES ('{tenant_id}', 'Canary Lane {tag}', 'canary-{tag}', 'starter', 'active', NOW(), NOW())"
    ))
    sql(args.project, (
        "INSERT INTO users (id, tenant_id, email, password_hash, role, status, email_verified, created_at, updated_at) "
        f"VALUES ('{user_id}', '{tenant_id}', 'canary-{tag}@{domain}', 'x', 'owner', 'active', TRUE, NOW(), NOW())"
    ))
    sql(args.project, (
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at, updated_at) "
        f"VALUES (gen_random_uuid(), '{tenant_id}', 'canary-lane', "
        f"'{api_key_hash(raw_key, secret)}', '{raw_key[:12]}', '[\"*\"]'::jsonb, NOW(), NOW())"
    ))

    # The sending domain through the PRODUCT route: real encrypted DKIM keys.
    req = urllib.request.Request(
        args.api_base.rstrip("/") + "/v1/domains",
        data=json.dumps({"name": domain}).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": raw_key},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            created = json.loads(response.read())
    except urllib.error.HTTPError as error:  # pragma: no cover - surfaced verbatim
        print(f"canary_seed: POST /v1/domains failed {error.code}: {error.read()[:300]!r}", file=sys.stderr)
        return 1
    domain_id = created.get("data", created).get("id")
    if not domain_id:
        print(f"canary_seed: domain response carried no id: {created!r}", file=sys.stderr)
        return 1

    sql(args.project, (
        "UPDATE domains SET status='verified', verified=TRUE, ses_verified=TRUE, "
        "spf_verified=TRUE, dkim_verified=TRUE, dmarc_verified=TRUE, "
        "return_path_verified=TRUE, updated_at=NOW() "
        f"WHERE id='{domain_id}'"
    ))

    print(json.dumps({
        "tenant_id": tenant_id,
        "api_key": raw_key,
        "domain": domain,
        "domain_id": domain_id,
        "from": f"canary@{domain}",
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
