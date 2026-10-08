#!/usr/bin/env python3
"""Lane A (final live-verification wave) fixture provisioning + evidence.

Builds every fixture probes A1..A7 need through the PRODUCT's own lifecycle
(signup -> Mailpit verification link -> login -> TOTP MFA), then writes the
sessions/credentials to

    docs/audit/dogfood-2026-10-06/evidence-final-auth/state.json

so each probe can be executed as a literal curl command against the running
stack (the brief requires exact commands + observed output, not harness
assertions).

usage: tools/verify-final-auth.py prep
"""
from __future__ import annotations

import base64
import importlib.util
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path("/Users/sabelakhoua/IdeaProjects/ApexMail")
EVID = ROOT / "docs/audit/dogfood-2026-10-06/evidence-final-auth"
EVID.mkdir(parents=True, exist_ok=True)
STATE = EVID / "state.json"

_spec = importlib.util.spec_from_file_location(
    "dogfood_live_console", ROOT / "tools/dogfood-live-console.py"
)
dlc = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(dlc)

PASSWORD = dlc.PASSWORD


def jwt_payload(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def step_fresh_totp(secret: str) -> str:
    """TOTP for the NEXT 30-second step.

    The server keeps a per-step replay guard, and the signup lifecycle just
    consumed the current step's code; sleeping to the next boundary is the
    only way to get a code the guard has not seen.
    """
    remaining = 30 - (int(time.time()) % 30)
    time.sleep(remaining + 2)
    return dlc.totp(secret)


def new_login(email: str, secret: str) -> "dlc.Session":
    """A fresh JSON-API login for an MFA-enabled user."""
    s = dlc.Session(email)
    s.handshake()
    st, text, _ = s.post("/v1/auth/login", {"email": email, "password": PASSWORD})
    if st not in (200, 202):
        raise RuntimeError(f"login {st}: {text[:300]}")
    if "am_session" not in s.jar:
        payload = json.loads(text)
        if payload.get("status") != "mfa_required":
            raise RuntimeError(f"unexpected login payload: {text[:300]}")
        last = ""
        for _attempt in range(2):
            st, text, _ = s.post(
                "/v1/auth/mfa/verify",
                {"challenge_token": payload["challengeToken"], "mfaCode": step_fresh_totp(secret)},
            )
            last = f"{st}: {text[:200]}"
            if st == 200 and "am_session" in s.jar:
                break
        if st != 200 or "am_session" not in s.jar:
            raise RuntimeError(f"mfa verify {last}")
    s.email = email
    s.user_id = dlc.db_one(f"SELECT id::text FROM users WHERE email = '{email}';")
    s.tenant_id = dlc.db_one(f"SELECT tenant_id FROM users WHERE email = '{email}';")
    s.refresh_csrf()
    return s


def dump(s: "dlc.Session", secret: str = "") -> dict:
    cookie = s.jar.get("am_session", "")
    payload = jwt_payload(cookie) if cookie else {}
    return {
        "email": s.email,
        "password": PASSWORD,
        "mfa_secret": secret or getattr(s, "mfa_secret", ""),
        "user_id": s.user_id,
        "tenant_id": s.tenant_id,
        "cookie": cookie,
        "csrf_cookie": s.jar.get("csrf_token", ""),
        "csrf": s.csrf,
        "jti": payload.get("jti", ""),
        "jwt_payload": payload,
    }


def prep() -> None:
    state: dict = json.loads(STATE.read_text()) if STATE.exists() else {}
    tag = uuid.uuid4().hex[:8]

    # ── A1/A2 identity user (MFA enabled) ──────────────────────────────────
    if "id_user" not in state:
        email = f"fa-id-{tag}@dogfood.test"
        s, _ = dlc.signup("A1", email, company="Final Auth Identity")
        secret = getattr(s, "mfa_secret", "")
        s_b = new_login(email, secret)
        state["id_user"] = {
            "owner": dump(s, secret),
            "session_a": dump(s, secret),
            "session_b": dump(s_b, secret),
        }
        STATE.write_text(json.dumps(state, indent=1))
        # A1 uses sessions A/B; A2 needs two CONSOLE logins for the same
        # identity — done with literal curl in the probe phase.
        print(f"A1/A2 identity: {email} tenant={s.tenant_id}")

    # ── A3 template-validation user, upgraded via product plan_overrides ───
    if "tpl_user" not in state:
        email = f"fa-tpl-{tag}@dogfood.test"
        s, _ = dlc.signup("A3", email, company="Final Auth Templates")
        secret = getattr(s, "mfa_secret", "")
        dlc.db(
            "INSERT INTO plan_overrides (tenant_id, plan, overridden_by, reason, active) "
            f"VALUES ('{s.tenant_id}', 'growth', 'verify-final-auth', 'A3 fixture', true) "
            "ON CONFLICT DO NOTHING;"
        )
        st, text, _ = s.post(
            "/v1/templates",
            {"name": "A3 seed", "subject": "seed", "html_body": "<p>seed</p>"},
        )
        if st != 201:
            raise RuntimeError(f"seed template {st}: {text[:300]}")
        tpl_id = json.loads(text)["id"]
        u = dump(s, secret)
        u["seed_template_id"] = tpl_id
        state["tpl_user"] = u
        STATE.write_text(json.dumps(state, indent=1))
        print(f"A3 templates: {email} tenant={s.tenant_id} tpl={tpl_id}")

    # ── A4 domain-cap user (free plan, one domain already created) ─────────
    if "dom_user" not in state:
        email = f"fa-dom-{tag}@dogfood.test"
        s, _ = dlc.signup("A4", email, company="Final Auth Domains", plan="free")
        secret = getattr(s, "mfa_secret", "")
        d1 = f"fa4-a-{tag}.apexdogfood.test"
        st, text, _ = s.post("/v1/domains", {"name": d1})
        if st != 201:
            raise RuntimeError(f"seed domain {st}: {text[:300]}")
        u = dump(s, secret)
        u["domain1"] = d1
        u["domain1_id"] = json.loads(text)["id"]
        state["dom_user"] = u
        STATE.write_text(json.dumps(state, indent=1))
        print(f"A4 domains: {email} tenant={s.tenant_id} domain1={d1}")

    # ── A6 non-admin tenant API key ────────────────────────────────────────
    if "nonadmin_key" not in state:
        src = state.get("tpl_user") or state.get("id_user", {}).get("owner")
        if not src:
            raise RuntimeError("A6 needs the A1/A3 session (missing state)")
        csrf = src["csrf"]
        req = urllib.request.Request(
            "http://127.0.0.1:8080/v1/auth/api-keys",
            data=json.dumps(
                {"name": f"fa-nonadmin-{tag}", "scopes": ["templates:read"]}
            ).encode(),
            headers={
                "Host": "127.0.0.1",
                "Content-Type": "application/json",
                "X-CSRF-Token": csrf,
                "Cookie": f"am_session={src['cookie']}; csrf_token={src['csrf_cookie']}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
                status = resp.status
        except urllib.error.HTTPError as e:  # noqa: F821
            body = json.loads(e.read().decode())
            status = e.code
        if status != 201:
            raise RuntimeError(f"non-admin key creation {status}: {body}")
        state["nonadmin_key"] = {
            "key": body["key"],
            "id": body["id"],
            "tenant_id": src["tenant_id"],
            "owner_session": src["cookie"],
            "owner_csrf": csrf,
            "owner_csrf_cookie": src["csrf_cookie"],
        }
        STATE.write_text(json.dumps(state, indent=1))
        print(f"A6 non-admin key: {body['key_prefix']} scopes={body['scopes']}")

    STATE.write_text(json.dumps(state, indent=1))
    print(f"state -> {STATE}")


def _totp_cli(secret: str, fresh: bool) -> str:
    if fresh:
        remaining = 30 - (int(time.time()) % 30)
        time.sleep(remaining + 2)
    else:
        remaining = 30 - (int(time.time()) % 30)
        if remaining < 4:
            time.sleep(remaining + 2)
    return dlc.totp(secret)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    if sys.argv[1] == "prep":
        prep()
    elif sys.argv[1] == "totp":
        # usage: verify-final-auth.py totp <secret> [fresh]
        print(_totp_cli(sys.argv[2], len(sys.argv) > 3 and sys.argv[3] == "fresh"))
    else:
        print(__doc__)
        sys.exit(2)
