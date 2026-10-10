"""Auth-lifecycle and credential-artifact probes (partition: auth).

Covers the documented lifecycle end to end (signup → verification → login →
MFA), every single-use artifact's replay behavior, session rotation/logout
scope, password reset, CSRF, and the KiwiCaptcha contract itself.
"""
from __future__ import annotations

import json
import time
import uuid

from ..assertions import Checks, refusal_ok
from ..identity import (
    PASSWORD, Session, fresh_totp, fresh_totp_next_window, login, observation, signup_only, totp,
    unreachable,
)
from ..kiwi import KiwiError
from ..registry import probe


@probe("p.auth.csrf_contract", "auth", severity="P1",
       description="CSRF handshake + cookie-write refusal without the header")
def csrf_contract(ctx):
    checks = Checks("p.auth.csrf_contract", "api:GET /v1/auth/csrf")
    anon = Session(ctx, "csrf-probe")
    resp = anon.get("/v1/auth/csrf")
    body = resp.json() or {}
    checks.add(
        "GET /v1/auth/csrf issues a token and a csrf cookie",
        resp.status == 200 and bool(body.get("token")) and "csrf_token" in resp.headers.get("set-cookie", ""),
        observed=f"status={resp.status} token={'yes' if body.get('token') else 'no'}", surface="api:GET /v1/auth/csrf",
    )
    # cookie-only write without the header must be refused
    owner = ctx.identity("owner_a")
    jar_only = dict(owner.session.jar)
    resp = ctx.http.post(
        "/v1/contacts", {"email": f"csrf-probe-{uuid.uuid4().hex[:8]}@dogfood.test"},
        cookie_header="; ".join(f"{k}={v}" for k, v in jar_only.items()),
    )
    refusal_ok(checks, resp, "cookie-authenticated write without X-CSRF-Token is refused", surface="api:POST /v1/contacts", severity="P1")
    resp = ctx.http.post(
        "/v1/contacts", {"email": f"csrf-probe2-{uuid.uuid4().hex[:8]}@dogfood.test"},
        cookie_header="; ".join(f"{k}={v}" for k, v in jar_only.items()),
        headers={"X-CSRF-Token": "not-a-valid-token"},
    )
    refusal_ok(checks, resp, "write with a malformed CSRF token is refused", surface="api:POST /v1/contacts", severity="P1")
    return checks.obs


@probe("p.auth.signup_verification", "auth", severity="P1",
       description="Signup mints no session; verification token is single-use and tamper-proof")
def signup_verification(ctx):
    checks = Checks("p.auth.signup_verification", "api:POST /v1/auth/signup")
    email = f"dgv2-verify-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = Session(ctx, "signup-verify")
    session.handshake()
    resp = session.post(
        "/v1/auth/signup",
        {"email": email, "password": PASSWORD, "company_name": "Dogfood v2 Verify", "plan": "free"},
        kiwi_scope="signup",
    )
    checks.add(
        "signup answers 202 and mints no session before verification",
        resp.status in (200, 201, 202) and "am_session" not in session.jar,
        observed=f"status={resp.status} session={'no' if 'am_session' not in session.jar else 'YES'}",
        expected="202 without am_session", surface="api:POST /v1/auth/signup", severity="P1",
    )
    # duplicate signup must not fork the account (anti-enumeration 202, one row)
    duplicate = Session(ctx, "signup-dup")
    duplicate.handshake()
    dup_resp = duplicate.post(
        "/v1/auth/signup",
        {"email": email, "password": PASSWORD, "company_name": "Dogfood v2 Dup", "plan": "free"},
        kiwi_scope="signup",
    )
    if ctx.db is not None:
        count = ctx.db.count("users", email=email)
        checks.add(
            "duplicate signup cannot fork the account",
            count <= 1 and dup_resp.status < 500,
            observed=f"users rows={count} dup_status={dup_resp.status}",
            expected="exactly one users row", surface="api:POST /v1/auth/signup", severity="P1",
        )
    link = ""
    for _ in range(20):
        links = [l for l in ctx.mail.links(email, "verify") if "/verify-email" in l]
        if links:
            link = "/" + links[0].split("://", 1)[1].split("/", 1)[1]
            break
        time.sleep(1)
    if not link:
        checks.unreachable("verification mail reached the mail plane", f"no verify mail for {email}")
        return checks.obs
    first = ctx.http.get(link, host=ctx.cfg.host)
    checks.add(
        "the verification link verifies the address",
        first.status in (200, 302, 303),
        observed=f"status={first.status}", expected="200/3xx", surface="api:GET /v1/auth/verify-email/:token",
        severity="P1",
    )
    replay = ctx.http.get(link, host=ctx.cfg.host)
    checks.add(
        "the verification link is single-use (replay refused)",
        replay.status >= 400 and replay.status < 500,
        observed=f"replay status={replay.status} body={replay.text[:120]!r}",
        expected="4xx on replay (a 2xx is a consumed-artifact replay)",
        surface="api:GET /v1/auth/verify-email/:token", severity="P1",
    )
    tampered = link.replace("/verify-email/", "/verify-email/tampered-")
    tampered_resp = ctx.http.get(tampered, host=ctx.cfg.host)
    checks.add(
        "a tampered verification token is refused",
        tampered_resp.status >= 400 and tampered_resp.status < 500 and tampered_resp.status != 404,
        observed=f"status={tampered_resp.status}", expected="4xx validation refusal",
        surface="api:GET /v1/auth/verify-email/:token",
    )
    return checks.obs


@probe("p.auth.kiwi_contract", "auth", severity="P1",
       description="KiwiCaptcha: token required, single-use, scope-bound; wrong-scope refused")
def kiwi_contract(ctx):
    checks = Checks("p.auth.kiwi_contract", "api:POST /v1/auth/login")
    target = f"dgv2-kiwi-{uuid.uuid4().hex[:8]}@dogfood.test"
    anon = Session(ctx, "kiwi-probe")
    anon.handshake()
    missing = anon.post("/v1/auth/login", {"email": target, "password": "Wrong!Passw0rd-2026"})
    named = missing.status >= 400 and "CAPTCHA" in json.dumps(missing.json() or {}).upper()
    checks.add(
        "login without a captcha token is refused with a named CAPTCHA error",
        missing.status >= 400 and named,
        observed=f"status={missing.status} body={missing.text[:160]!r}",
        expected="4xx naming CAPTCHA_REQUIRED", surface="api:POST /v1/auth/login", severity="P1",
    )
    # a token minted for another scope must be rejected on login
    try:
        wrong_scope = ctx.kiwi_solver.token("forgot-password")
    except KiwiError as error:
        checks.unreachable("mint a wrong-scope captcha token", str(error))
        return checks.obs
    wrong = anon.post("/v1/auth/login", {"email": target, "password": "Wrong!Passw0rd-2026", "kiwi__token": wrong_scope})
    checks.add(
        "a captcha token minted for another scope is refused on login",
        wrong.status >= 400,
        observed=f"status={wrong.status} body={wrong.text[:160]!r}",
        expected="4xx (scope-bound proof)", surface="api:POST /v1/auth/login", severity="P1",
    )
    # a replayed token (already consumed) must be refused
    try:
        token = ctx.kiwi_solver.token("login")
    except KiwiError as error:
        checks.unreachable("mint a captcha token for replay", str(error))
        return checks.obs
    first = anon.post("/v1/auth/login", {"email": target, "password": "Wrong!Passw0rd-2026", "kiwi__token": token})
    second = anon.post("/v1/auth/login", {"email": target, "password": "Wrong!Passw0rd-2026", "kiwi__token": token})
    checks.add(
        "a replayed captcha token is refused (single-use)",
        second.status >= 400 and second.status < 500,
        observed=f"first={first.status} replay={second.status} body={second.text[:120]!r}",
        expected="the second submission must be refused", surface="api:POST /v1/auth/login", severity="P1",
    )
    return checks.obs


@probe("p.auth.first_login_mfa", "auth", severity="P1",
       description="First login forces MFA setup; wrong TOTP refused; challenge single-use")
def first_login_mfa(ctx):
    checks = Checks("p.auth.first_login_mfa", "api:POST /v1/auth/mfa/verify")
    email = f"dgv2-mfa-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = signup_only(ctx, email, company="Dogfood v2 MFA")
    resp = session.post("/v1/auth/login", {"email": email, "password": PASSWORD}, kiwi_scope="login")
    payload = resp.json() or {}
    if resp.status == 202 and payload.get("status") == "mfa_setup_required":
        checks.add(
            "the first login forces MFA setup (202 mfa_setup_required)",
            True, observed=f"status={resp.status} status_field={payload.get('status')}",
            expected="202 mfa_setup_required", surface="api:POST /v1/auth/login", severity="P1",
        )
    else:
        checks.add(
            "the first login forces MFA setup (202 mfa_setup_required)",
            False, observed=f"status={resp.status} body={resp.text[:200]!r}",
            expected="202 mfa_setup_required (a session before MFA would be a bypass)",
            surface="api:POST /v1/auth/login", severity="P1",
        )
        checks.add("first-login session must not pre-exist MFA", "am_session" not in session.jar,
                   observed="session cookie present" if "am_session" in session.jar else "no session",
                   surface="api:POST /v1/auth/login", severity="P0")
        return checks.obs
    challenge = payload.get("challengeToken") or ""
    secret = payload.get("secret") or ""
    if not challenge or not secret:
        checks.unreachable("mfa challenge token + secret returned", resp.text[:160])
        return checks.obs
    wrong = session.post(
        "/v1/auth/mfa/verify", {"challenge_token": challenge, "mfaCode": "000000"},
        kiwi_scope="mfa-verify",
    )
    checks.add(
        "a wrong TOTP is refused",
        wrong.status >= 400 and wrong.status < 500,
        observed=f"status={wrong.status} body={wrong.text[:140]!r}",
        expected="4xx invalid MFA code", surface="api:POST /v1/auth/mfa/verify", severity="P1",
    )
    reused = session.post(
        "/v1/auth/mfa/verify", {"challenge_token": challenge, "mfaCode": fresh_totp(secret)},
        kiwi_scope="mfa-verify",
    )
    checks.add(
        "the MFA challenge token is single-use (replay after a failed attempt refused)",
        "am_session" not in session.jar,
        observed=f"status={reused.status} session={'minted' if 'am_session' in session.jar else 'none'} body={reused.text[:140]!r}",
        expected="no session from a consumed challenge", surface="api:POST /v1/auth/mfa/verify", severity="P1",
    )
    # a fresh login completes MFA and mints the session
    fresh = Session(ctx, "mfa-complete")
    fresh.handshake()  # a fresh Session needs its CSRF token before any POST
    resp2 = fresh.post("/v1/auth/login", {"email": email, "password": PASSWORD}, kiwi_scope="login")
    payload2 = resp2.json() or {}
    if resp2.status == 202 and payload2.get("status") in ("mfa_setup_required", "mfa_required"):
        secret2 = payload2.get("secret") or secret
        done = fresh.post(
            "/v1/auth/mfa/verify",
            {"challenge_token": payload2.get("challengeToken", ""),
             "mfaCode": fresh_totp_next_window(secret2)},
            kiwi_scope="mfa-verify",
        )
        checks.add(
            "a correct TOTP mints the session",
            done.status == 200 and "am_session" in fresh.jar,
            observed=f"status={done.status} session={'yes' if 'am_session' in fresh.jar else 'no'}",
            expected="200 + am_session", surface="api:POST /v1/auth/mfa/verify", severity="P1",
        )
        body = done.json() or {}
        recovery = body.get("recovery_codes") or body.get("data", {}).get("recovery_codes")
        checks.add(
            "MFA setup returns one-time recovery codes",
            bool(recovery), observed=f"recovery_codes={len(recovery or [])}",
            expected="recovery codes issued at enrolment", surface="api:POST /v1/auth/mfa/verify",
        )
    else:
        checks.add(
            "a correct TOTP mints the session",
            False, observed=f"second login status={resp2.status} body={resp2.text[:180]!r}",
            expected="the enrolled account answers an MFA challenge", surface="api:POST /v1/auth/mfa/verify", severity="P1",
        )
    return checks.obs


@probe("p.auth.session_lifecycle", "auth", severity="P1",
       description="Login rotation (AR-005), sessions list, logout is current-session-only (D-1)")
def session_lifecycle(ctx):
    checks = Checks("p.auth.session_lifecycle", "api:GET /v1/auth/sessions")
    email = f"dgv2-sessions-{uuid.uuid4().hex[:10]}@dogfood.test"
    base = signup_only(ctx, email, company="Dogfood v2 Sessions")
    login(ctx, base)
    user_id = ""
    if ctx.db is not None:
        user_id = str((ctx.db.row("users", email=email) or {}).get("id", ""))
    sessions = base.get("/v1/auth/sessions")
    # The endpoint answers a top-level ARRAY of sessions; older wrappers used
    # {sessions:[...]}. Handle both without assuming a dict (the previous
    # `body.get` died on the array shape: probe could not execute).
    body = sessions.json()
    if isinstance(body, list):
        rows = body
    else:
        body = body if isinstance(body, dict) else {}
        rows = body.get("sessions") or body.get("data") or []
    if isinstance(rows, dict):
        rows = rows.get("sessions") or []
    checks.add(
        "GET /v1/auth/sessions lists sessions with a current marker",
        sessions.status == 200 and isinstance(rows, list) and any(r.get("current") for r in rows if isinstance(r, dict)),
        observed=f"status={sessions.status} rows={len(rows) if isinstance(rows, list) else '?'} body={sessions.text[:160]!r}",
        expected="200 array with one current session", surface="api:GET /v1/auth/sessions", severity="P1",
    )
    # AR-005: a second login rotates sessions — the first cookie must be refused.
    second = Session(ctx, "sessions-second")
    second.email = email
    second.mfa_secret = base.mfa_secret
    second.handshake()
    resp2 = second.post("/v1/auth/login", {"email": email, "password": PASSWORD}, kiwi_scope="login")
    payload2 = resp2.json() or {}
    if resp2.status == 202 and payload2.get("status"):
        second.post(
            "/v1/auth/mfa/verify",
            {"challenge_token": payload2.get("challengeToken", ""),
             "mfaCode": fresh_totp_next_window(payload2.get("secret") or second.mfa_secret)},
            kiwi_scope="mfa-verify",
        )
    if "am_session" in second.jar:
        checks.add("a second login of the same account mints a session",
                   200 <= resp2.status < 300 or resp2.status == 202,
                   observed=f"status={resp2.status}", surface="api:POST /v1/auth/login", severity="P1")
        rotated = base.get("/v1/auth/me")
        checks.add(
            "the earlier session is revoked by the login rotation (AR-005)",
            rotated.status in (401, 403),
            observed=f"first session after second login: /v1/auth/me = {rotated.status}",
            expected="401/403 (rotation revokes previously-minted sessions)",
            surface="api:GET /v1/auth/me", severity="P1",
        )
    else:
        checks.add(
            "a second login of the same account mints a session",
            False,
            observed=f"status={resp2.status} body={resp2.text[:180]!r}",
            expected="the account can log in on a second client",
            surface="api:POST /v1/auth/login", severity="P1",
        )
        checks.add("login rotation could not be exercised (no second session)", False,
                   observed="no session minted",
                   expected="rotation must be observable", surface="api:POST /v1/auth/login",
                   severity="P1", kind="unreachable")
        return checks.obs
    # logout scope: current-session-only, per the docs and the D-1 fix.
    if ctx.live_like() and user_id:
        from ..dbctl import redis_cli

        tenant = str((ctx.db.row("users", email=email) or {}).get("tenant_id", ""))
        # The current session id (for the exact per-session marker key) and
        # the PRE-logout state of the user-wide marker: an EARLIER legitimate
        # revocation (e.g. a password reset revokes all other sessions) may
        # already have written it — the check is the DELTA this logout makes.
        sessions_before = second.get("/v1/auth/sessions")
        rows_before = sessions_before.json()
        if isinstance(rows_before, dict):
            rows_before = rows_before.get("sessions") or rows_before.get("data") or []
        current_id = next(
            (r.get("id", "") for r in (rows_before or []) if isinstance(r, dict) and r.get("current")),
            "",
        )
        user_wide_before = redis_cli(
            ctx.cfg, "exists", f"apexmail:session_revoked_after:{tenant}:{user_id}"
        ).strip()
        logout = second.post("/v1/auth/logout", {})
        checks.add("POST /v1/auth/logout answers 2xx", 200 <= logout.status < 300,
                   observed=f"status={logout.status}", surface="api:POST /v1/auth/logout", severity="P1")
        gone = second.get("/v1/auth/me")
        checks.add("the logged-out session is refused afterwards", gone.status in (401, 403),
                   observed=f"status={gone.status}", expected="401/403",
                   surface="api:GET /v1/auth/me", severity="P1")
        user_wide = redis_cli(ctx.cfg, "exists",
                              f"apexmail:session_revoked_after:{tenant}:{user_id}").strip()
        # DELTA semantics: this logout must not be what CREATES the user-wide
        # marker. (A pre-existing marker is another flow's legitimate
        # revocation, not a D-1 regression.)
        checks.add(
            "logout writes a PER-SESSION marker, not a user-wide revocation (D-1 regression)",
            not (user_wide_before in ("0", "") and user_wide not in ("0", "")),
            observed=f"user-wide before={user_wide_before} after={user_wide}",
            expected="this logout writes no apexmail:session_revoked_after:<tenant>:<user> key",
            surface="api:POST /v1/auth/logout", severity="P1",
        )
        # The per-session marker key is `apexmail:session_revoked:<session_id>`
        # (the session id, NOT the user id — the previous filter matched
        # nothing and reported a false negative).
        per_session = redis_cli(
            ctx.cfg, "exists", f"apexmail:session_revoked:{current_id}"
        ).strip() if current_id else "0"
        checks.add(
            "logout writes the per-session revocation marker",
            per_session not in ("0", ""),
            observed=f"session={current_id or 'unknown'} marker_exists={per_session}",
            expected="apexmail:session_revoked:<session_id> present for the logged-out session",
            surface="api:POST /v1/auth/logout", severity="P1",
        )
    else:
        logout = second.post("/v1/auth/logout", {})
        checks.add("POST /v1/auth/logout answers 2xx", 200 <= logout.status < 300,
                   observed=f"status={logout.status}", surface="api:POST /v1/auth/logout", severity="P1")
        gone = second.get("/v1/auth/me")
        checks.add("the logged-out session is refused afterwards", gone.status in (401, 403),
                   observed=f"status={gone.status}", expected="401/403",
                   surface="api:GET /v1/auth/me", severity="P1")
    return checks.obs


@probe("p.auth.password_reset", "auth", severity="P1",
       description="Forgot-password → reset link → new password; token single-use; old sessions revoked")
def password_reset(ctx):
    checks = Checks("p.auth.password_reset", "api:POST /v1/auth/forgot-password")
    email = f"dgv2-reset-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = signup_only(ctx, email, company="Dogfood v2 Reset")
    login(ctx, session)
    old_session_alive = session.get("/v1/auth/me").status == 200
    anon = Session(ctx, "reset-anon")
    anon.handshake()
    resp = anon.post("/v1/auth/forgot-password", {"email": email}, kiwi_scope="forgot-password")
    checks.add("forgot-password accepts a known address", resp.status in (200, 202),
               observed=f"status={resp.status}", surface="api:POST /v1/auth/forgot-password", severity="P1")
    link = ""
    for _ in range(20):
        links = [l for l in ctx.mail.links(email, "reset") if "/reset-password" in l]
        if links:
            link = "/" + links[0].split("://", 1)[1].split("/", 1)[1]
            break
        time.sleep(1)
    if not link:
        checks.unreachable("reset mail reached the mail plane", f"no reset mail for {email}")
        return checks.obs
    new_password = "Dogfood!2026-Reset-Horse-7"
    token = link.split("/reset-password/", 1)[1].split("?", 1)[0] if "/reset-password/" in link else ""
    reset = anon.post(
        "/v1/auth/reset-password",
        {"token": token, "email": email, "password": new_password, "confirmPassword": new_password},
        kiwi_scope="reset-password",
    )
    checks.add("reset-password with the mailed token succeeds",
               reset.status in (200, 201, 202, 204), observed=f"status={reset.status} body={reset.text[:160]!r}",
               surface="api:POST /v1/auth/reset-password", severity="P1")
    replay = anon.post(
        "/v1/auth/reset-password",
        {"token": token, "email": email, "password": new_password, "confirmPassword": new_password},
        kiwi_scope="reset-password",
    )
    checks.add("the reset token is single-use (replay refused)",
               replay.status >= 400 and replay.status < 500,
               observed=f"replay status={replay.status} body={replay.text[:140]!r}",
               surface="api:POST /v1/auth/reset-password", severity="P1")
    if old_session_alive:
        stale = session.get("/v1/auth/me")
        checks.add("the reset revokes previously-issued sessions",
                   stale.status in (401, 403), observed=f"pre-reset session status={stale.status}",
                   expected="401/403 after a password reset", surface="api:GET /v1/auth/me", severity="P1")
    fresh = Session(ctx, "reset-fresh")
    fresh.email = email
    fresh.handshake()
    logged = fresh.post("/v1/auth/login", {"email": email, "password": new_password}, kiwi_scope="login")
    checks.add("login with the NEW password proceeds to MFA",
               logged.status in (200, 201, 202), observed=f"status={logged.status}",
               surface="api:POST /v1/auth/login", severity="P1")
    return checks.obs


@probe("p.auth.anti_enumeration", "auth", severity="P2",
       description="forgot-password does not reveal account existence")
def anti_enumeration(ctx):
    checks = Checks("p.auth.anti_enumeration", "api:POST /v1/auth/forgot-password")
    owner = ctx.identity("owner_a")
    absent = Session(ctx, "enum-absent")
    absent.handshake()
    resp_absent = absent.post("/v1/auth/forgot-password", {"email": f"dgv2-absent-{uuid.uuid4().hex[:8]}@dogfood.test"},
                              kiwi_scope="forgot-password")
    resp_present = absent.post("/v1/auth/forgot-password", {"email": owner.email}, kiwi_scope="forgot-password")
    same_body = (resp_absent.text[:200] == resp_present.text[:200])
    both_limited = resp_absent.status == 429 and resp_present.status == 429
    checks.add(
        "absent vs present forgot-password answers are indistinguishable",
        same_body or both_limited,
        observed=f"absent={resp_absent.status} present={resp_present.status} identical={same_body}",
        expected="identical bodies (anti-enumeration) or both throttled",
        surface="api:POST /v1/auth/forgot-password",
    )
    return checks.obs


@probe("p.auth.api_key_lifecycle", "auth", severity="P2",
       description="API key mint → scoped use → revoke; scope enforcement is named")
def api_key_lifecycle(ctx):
    checks = Checks("p.auth.api_key_lifecycle", "api:POST /v1/auth/api-keys")
    owner = ctx.identity("owner_a")
    key_resp = owner.session.post("/v1/auth/api-keys", {"name": "dogfood-v2 auth probe", "scopes": ["contacts:read"]})
    body = key_resp.json() or {}
    data = body.get("data") or body
    key = data.get("key") or data.get("api_key") or data.get("secret") or ""
    key_id = data.get("id") or (data.get("api_key") or {}).get("id") if isinstance(data.get("api_key"), dict) else data.get("id")
    checks.add("an API key with a limited scope is minted (secret returned once)",
               key_resp.status in (200, 201) and bool(key),
               observed=f"status={key_resp.status} key={'yes' if key else 'no'}",
               surface="api:POST /v1/auth/api-keys", severity="P2")
    if not key:
        return checks.obs
    allowed = ctx.http.get("/v1/contacts?limit=1", headers={"X-API-Key": key})
    checks.add("the scoped key reads its granted scope (contacts:read)",
               allowed.status == 200, observed=f"status={allowed.status} body={allowed.text[:120]!r}",
               expected="200", surface="api:GET /v1/contacts")
    denied = ctx.http.get("/v1/campaigns?limit=1", headers={"X-API-Key": key})
    denied_named = denied.status in (401, 403) and "scope" in denied.text.lower()
    checks.add("the scoped key is refused outside its scope with a named error",
               denied_named, observed=f"status={denied.status} body={denied.text[:140]!r}",
               expected="403 naming the missing scope", surface="api:GET /v1/campaigns")
    if key_id:
        revoke = owner.session.delete(f"/v1/auth/api-keys/{key_id}")
        checks.add("revoking the key answers 2xx", 200 <= revoke.status < 300,
                   observed=f"status={revoke.status}", surface="api:DELETE /v1/auth/api-keys/:id")
        reused = ctx.http.get("/v1/contacts?limit=1", headers={"X-API-Key": key})
        checks.add("the revoked key is refused", reused.status in (401, 403),
                   observed=f"status={reused.status}", expected="401/403",
                   surface="api:GET /v1/contacts", severity="P1")
    return checks.obs
