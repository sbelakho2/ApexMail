"""Identity provisioning through the PRODUCT'S OWN lifecycle.

Every identity is minted the documented way:
  owner      signup -> Mailpit verification link -> login -> first-login MFA
             setup (TOTP verify)
  member/viewer  own signup + login, then the documented *fixture* step the
             prior campaign used because the invite flow writes an inert
             `invited` row (role/tenant assignment via SQL — recorded as a
             fixture, not a product claim)
  operator   own signup + login, then promoted to tenant `system` / role
             `owner` (the v1 CP recipe), then `POST /web/cp/login` for the
             `apexmail_cp_session` cookie
  api key    minted by the owner through `POST /v1/auth/api-keys`

KiwiCaptcha tokens are minted+solved for every gated auth call.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import struct
import time
import uuid

from .config import PASSWORD
from .kiwi import KiwiError
from .registry import Observation

JSON_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
KIWI_FOR_PATH = (
    ("/v1/auth/login", "login"),
    ("/api/auth/login", "login"),
    ("/web/auth/login", "login"),
    ("/v1/auth/signup", "signup"),
    ("/v1/auth/register", "signup"),
    ("/web/auth/signup", "signup"),
    ("/v1/auth/mfa/verify", "mfa-verify"),
    ("/web/auth/mfa/verify", "mfa-verify"),
    ("/v1/auth/forgot-password", "forgot-password"),
    ("/web/auth/forgot-password", "forgot-password"),
    ("/v1/auth/reset-password", "reset-password"),
    ("/web/auth/reset-password", "reset-password"),
    ("/web/cp/login", "cp-login"),
    ("/web/auth/resend-verification", "resend-verification"),
)


def totp(secret: str) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def fresh_totp(secret: str, min_remaining: int = 3) -> str:
    """TOTP with at least `min_remaining` seconds of validity left."""
    now = time.time()
    remaining = 30 - (now % 30)
    if remaining < min_remaining:
        time.sleep(remaining + 1)
    return totp(secret)


def fresh_totp_next_window(secret: str, margin: int = 2) -> str:
    """A TOTP for the NEXT time step.

    The server enforces single-use codes per step (`mfa_totp_replay` guard),
    so any verification that follows another verification of the same
    account must wait for a fresh window — otherwise the guard (correctly)
    refuses it as a replay and the probe/identity fails spuriously."""
    remaining = 30 - (time.time() % 30)
    time.sleep(remaining + margin)
    return totp(secret)


def parse_cookies(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for part in headers.get("set-cookie", "").split("\n"):
        pair = part.split(";", 1)[0].strip()
        if "=" in pair:
            key, value = pair.split("=", 1)
            out[key] = value
    return out


class Session:
    """One authenticated (or anonymous) client with its own cookie jar."""

    def __init__(self, ctx, name: str, host: str | None = None, base: str | None = None):
        self.ctx = ctx
        self.name = name
        self.host = host or ctx.cfg.host
        self.base = base or ctx.cfg.base
        self.jar: dict[str, str] = {}
        self.csrf = ""
        self.user_id = ""
        self.tenant_id = ""
        self.email = ""
        self.mfa_secret = ""
        self.role = ""

    # ── cookie/CSRF plumbing ───────────────────────────────────────────
    @property
    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.jar.items())

    def _apply_cookies(self, headers: dict[str, str]) -> None:
        for key, value in parse_cookies(headers).items():
            if value == "":
                self.jar.pop(key, None)
            else:
                self.jar[key] = value

    def handshake(self) -> bool:
        resp = self.ctx.get("/v1/auth/csrf", host=self.host, base=self.base)
        if resp.status != 200:
            # Documented env control: a 429/DDOS-block (public limiter, shared
            # IP) is cleared once and retried so a long battery never dies on
            # its own request volume.
            self.ctx.clear_rate_keys()
            if resp.status == 403 and "DDOS_BLOCKED" in (resp.text or ""):
                recovery = getattr(self.ctx, "ddos_recovery", None)
                if callable(recovery):
                    recovery()
            time.sleep(0.5)
            resp = self.ctx.get("/v1/auth/csrf", host=self.host, base=self.base)
        if resp.status != 200:
            raise RuntimeError(
                f"csrf handshake failed for {self.name}: GET /v1/auth/csrf -> "
                f"status={resp.status} body={resp.text[:200]!r}"
            )
        body = resp.json() or {}
        if isinstance(body.get("data"), dict):
            body = body["data"]
        self.csrf = body.get("token", "")
        self._apply_cookies(resp.headers)
        if not self.csrf:
            raise RuntimeError(
                f"csrf handshake returned no token for {self.name}: {resp.text[:200]!r}"
            )
        return True

    # ── requests ───────────────────────────────────────────────────────
    def req(
        self,
        method: str,
        path: str,
        *,
        body=None,
        raw=None,
        ctype=None,
        headers=None,
        csrf: bool = True,
        kiwi_scope: str | None = None,
        host=None,
        base=None,
        follow: bool = True,
        timeout=None,
        retries: int = 2,
    ):
        hdrs = dict(headers or {})
        if csrf and method in JSON_METHODS and self.csrf:
            hdrs.setdefault("X-CSRF-Token", self.csrf)

        def with_token(scope: str | None):
            """(body, raw, ctype) with a freshly minted token for `scope`."""
            if not scope:
                return body, raw, ctype
            try:
                token = self.ctx.kiwi_solver.token(scope)
            except KiwiError as error:
                raise KiwiError(f"{path}: {error}") from error
            if raw is not None:
                sep = "&" if raw else ""
                return body, f"{raw}{sep}kiwi__token={token}", (
                    ctype or "application/x-www-form-urlencoded"
                )
            merged = dict(body or {})
            merged["kiwi__token"] = token
            return merged, raw, (ctype or "application/json")

        def send(send_body, send_raw, send_ctype):
            return self.ctx.http.call(
                method, path, host=host or self.host, base=base or self.base,
                body=send_body, raw=send_raw, ctype=send_ctype, headers=hdrs,
                cookie_header=self.cookie_header or None,
                follow=follow, timeout=timeout, retries=retries,
            )

        call_body, call_raw, call_ctype = with_token(kiwi_scope)
        resp = send(call_body, call_raw, call_ctype)
        # A token that rode out a long DDoS backoff can expire server-side
        # ("challenge expired or not found"): re-mint and retry — the same
        # refresh the widget performs. Bounded to two refreshes so a genuinely
        # broken captcha flow still surfaces as a failure.
        for _ in range(2):
            stale = (
                kiwi_scope
                and resp.status >= 400
                and "challenge" in (resp.text or "").lower()
                and ("expired" in (resp.text or "") or "not found" in (resp.text or ""))
            )
            if not stale:
                break
            call_body, call_raw, call_ctype = with_token(kiwi_scope)
            resp = send(call_body, call_raw, call_ctype)
        self._apply_cookies(resp.headers)
        return resp

    def get(self, path: str, **kw):
        return self.req("GET", path, **kw)

    def json(self, method: str, path: str, body=None, **kw):
        return self.req(method, path, body=body, **kw)

    def post(self, path: str, body=None, **kw):
        return self.req("POST", path, body=body, **kw)

    def put(self, path: str, body=None, **kw):
        return self.req("PUT", path, body=body, **kw)

    def patch(self, path: str, body=None, **kw):
        return self.req("PATCH", path, body=body, **kw)

    def delete(self, path: str, **kw):
        return self.req("DELETE", path, **kw)

    def form(self, path: str, fields: dict[str, str], **kw):
        fields = dict(fields)
        fields.setdefault("_csrf", self.csrf)
        return self.req(
            "POST", path, raw=self.ctx.http.raw_form(fields),
            ctype="application/x-www-form-urlencoded", **kw,
        )

    def form_kiwi(self, path: str, fields: dict[str, str], scope: str | None = None, **kw):
        """Form post with the zero-JS CSRF field and (optionally) a freshly
        minted+solved captcha token — the shape every live SSR form expects."""
        fields = dict(fields)
        fields.setdefault("_csrf", self.csrf)
        if scope:
            fields["kiwi__token"] = self.ctx.kiwi_solver.token(scope)
        return self.req(
            "POST", path, raw=self.ctx.http.raw_form(fields),
            ctype="application/x-www-form-urlencoded", **kw,
        )

    def logout(self) -> None:
        if self.csrf:
            self.post("/v1/auth/logout", {})

    def alive(self) -> bool:
        return self.get("/v1/auth/me").status == 200


def _kiwi_scope_for(path: str) -> str | None:
    for prefix, scope in KIWI_FOR_PATH:
        if path.startswith(prefix):
            return scope
    return None


# ── provisioning ────────────────────────────────────────────────────────

def _verify_link(ctx, email: str, tries: int = 20) -> str:
    for _ in range(tries):
        links = [l for l in ctx.mail.links(email, "verify") if "/verify-email" in l]
        if links:
            link = links[0]
            # strip scheme+host so the probe re-hits the harness base
            return "/" + link.split("://", 1)[1].split("/", 1)[1]
        time.sleep(1)
    return ""


def signup_only(ctx, email: str, *, company: str = "Dogfood v2", plan: str = "free",
                session: Session | None = None) -> Session:
    """signup -> verification mail -> link exchange. No login yet."""
    s = session or Session(ctx, email)
    if not s.csrf:
        if not s.handshake():
            raise RuntimeError(f"csrf handshake failed for {email}")
    resp = s.post(
        "/v1/auth/signup",
        {"email": email, "password": PASSWORD, "company_name": company, "plan": plan},
        kiwi_scope="signup",
    )
    if resp.status == 429:
        ctx.clear_rate_keys()
        time.sleep(1.0)
        resp = s.post(
            "/v1/auth/signup",
            {"email": email, "password": PASSWORD, "company_name": company, "plan": plan},
            kiwi_scope="signup",
        )
    if resp.status not in (200, 201, 202):
        raise RuntimeError(f"signup failed {resp.status}: {resp.text[:300]}")
    s.email = email
    link = _verify_link(ctx, email)
    if not link:
        raise RuntimeError(f"no verification mail reached the mail plane for {email}")
    vresp = s.get(link)
    if vresp.status not in (200, 302, 303):
        raise RuntimeError(f"verification link failed {vresp.status}: {vresp.text[:200]}")
    return s


def _payload(resp) -> dict:
    body = resp.json() or {}
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]
    return body if isinstance(body, dict) else {}


def login(ctx, session: Session, *, password: str | None = None) -> Session:
    """login -> (first-login MFA setup) -> authenticated session."""
    password = password or PASSWORD
    resp = session.post("/v1/auth/login", {"email": session.email, "password": password},
                        kiwi_scope="login")
    if resp.status == 429:
        ctx.clear_rate_keys()
        time.sleep(1.0)
        resp = session.post("/v1/auth/login", {"email": session.email, "password": password},
                            kiwi_scope="login")
    if resp.status not in (200, 201, 202):
        raise RuntimeError(f"login failed {resp.status}: {resp.text[:300]}")
    if "am_session" not in session.jar:
        payload = _payload(resp)
        if payload.get("status") in ("mfa_setup_required", "mfa_required"):
            secret = payload.get("secret") or session.mfa_secret
            challenge = payload.get("challengeToken") or ""
            session.mfa_secret = secret
            verify = session.post(
                "/v1/auth/mfa/verify",
                {"challenge_token": challenge, "mfaCode": fresh_totp(secret) if secret else ""},
                kiwi_scope="mfa-verify",
            )
            if (verify.status != 200 or "am_session" not in session.jar) and (
                "invalid MFA code" in verify.text
                or "invalid or expired MFA challenge" in verify.text
                or verify.status == 401
            ) and secret:
                # Two single-use guards (correct behaviour) can refuse a login
                # that follows another verification inside the same window:
                # the TOTP step (`mfa_totp_replay`) and the challenge itself
                # (consumed on the first attempt). Retry ONCE as a full
                # re-login — a NEW challenge token plus a code for the NEXT
                # 30 s step — instead of failing the identity.
                relog = session.post(
                    "/v1/auth/login",
                    {"email": session.email, "password": password},
                    kiwi_scope="login",
                )
                payload2 = _payload(relog)
                verify = session.post(
                    "/v1/auth/mfa/verify",
                    {
                        "challenge_token": payload2.get("challengeToken") or "",
                        "mfaCode": fresh_totp_next_window(secret),
                    },
                    kiwi_scope="mfa-verify",
                )
            if verify.status != 200 or "am_session" not in session.jar:
                raise RuntimeError(f"mfa verify failed {verify.status}: {verify.text[:300]}")
        else:
            raise RuntimeError(f"login minted no session: {resp.text[:300]}")
    if session.handshake():
        pass
    return session


def _db_identity(ctx, email: str) -> tuple[str, str, str]:
    if ctx.db is None:
        return "", "", ""
    row = ctx.db.row("users", email=email) or {}
    return str(row.get("id", "")), str(row.get("tenant_id", "")), str(row.get("role", ""))


def provision_owner(ctx, name: str = "owner_a", *, company: str = "Dogfood v2 Alpha") -> "Identity":
    from .context import Identity

    email = f"dgv2-{name}-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = signup_only(ctx, email, company=company)
    login(ctx, session)
    user_id, tenant_id, role = _db_identity(ctx, email)
    identity = Identity(name=name, session=session, email=email, role=role or "owner",
                        tenant_id=tenant_id, user_id=user_id)
    _apply_fixture_plan(ctx, identity)
    ctx.note(f"identity {name}: {email} tenant={tenant_id or '?'}")
    return identity


def _apply_fixture_plan(ctx, identity) -> None:
    """A fresh signup lands on the free plan, which gates paid features
    (custom_templates, advanced_analytics, time-travel). Every probe that uses
    this tenant — including probes that never touch the resource fixtures —
    must see the paid-plan behaviour, so the plan is applied at PROVISIONING
    time (fixtures-first timing left the first template create on free).
    Read-back verified; a failed update is noted, never silent."""
    tenant = identity.tenant_id
    if not tenant:
        return
    marker = ctx.fixtures.setdefault("_plan", {})
    if marker.get(tenant) == "growth":
        return
    try:
        if ctx.cfg.mode == "self-test":
            ctx.fixture_plan(tenant, "growth")
            marker[tenant] = "growth"
            return
        if ctx.db is None or not hasattr(ctx.db, "_run"):
            return
        ctx.db._run(f"UPDATE tenants SET plan = 'growth' WHERE id = '{tenant}'")
        observed = ctx.db.scalar(f"SELECT plan FROM tenants WHERE id = '{tenant}'")
        if observed == "growth":
            marker[tenant] = "growth"
        else:
            marker[tenant] = f"error: plan read-back={observed!r}"
            ctx.note(f"identity {identity.name}: plan fixture did not stick (read-back={observed!r})")
    except Exception as error:  # noqa: BLE001
        marker[tenant] = f"error: {error}"
        ctx.note(f"identity {identity.name}: plan fixture failed: {error}")


def provision_role(ctx, base_identity, role: str, *, name: str | None = None) -> "Identity":
    """Sign a fresh user up, then assign it the base tenant + requested role
    through the documented DB fixture (the invite flow writes an inert row)."""
    from .context import Identity

    name = name or f"role_{role}"
    email = f"dgv2-{role}-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = signup_only(ctx, email, company="Dogfood v2 Role")
    if ctx.cfg.mode in ("live", "mutation"):
        if ctx.db is None or not hasattr(ctx.db, "_run"):
            raise RuntimeError("role fixture needs the SQL data plane")
        tenant = base_identity.tenant_id or _db_identity(ctx, base_identity.email)[1]
        ctx.db._run(
            f"UPDATE users SET tenant_id = '{tenant}', role = '{role}' "
            f"WHERE email = '{email}'"
        )
    else:
        ctx.fixture_assign(email, base_identity.tenant_id, role)
    login(ctx, session)
    user_id, tenant_id, role_db = _db_identity(ctx, email)
    identity = Identity(name=name, session=session, email=email, role=role_db or role,
                        tenant_id=tenant_id or base_identity.tenant_id, user_id=user_id)
    return identity


def provision_operator(ctx, name: str = "operator_cp") -> "Identity":
    from .context import Identity

    email = f"dgv2-cp-{uuid.uuid4().hex[:10]}@dogfood.test"
    session = signup_only(ctx, email, company="Dogfood v2 Operator")
    login(ctx, session)
    secret = session.mfa_secret
    if ctx.cfg.mode in ("live", "mutation"):
        if ctx.db is None or not hasattr(ctx.db, "_run"):
            raise RuntimeError("operator promotion needs the SQL data plane")
        ctx.db._run(f"UPDATE users SET tenant_id = 'system', role = 'owner' WHERE email = '{email}'")
    else:
        ctx.fixture_promote_system(email)
    # Re-login so the session claims carry the system tenant, then the CP
    # flow. The LIVE CP login is a two-step, form-encoded, CSRF+kiwi gated
    # flow: POST /web/cp/login (password) answers a challenge redirect for an
    # MFA-enabled operator, and POST /web/auth/mfa/verify completes it and
    # mints BOTH am_session and apexmail_cp_session.
    relogin = Session(ctx, email)
    relogin.email = email
    relogin.mfa_secret = secret
    # A fresh Session has no CSRF token yet; every JSON POST (including the
    # login below) refuses with 403 "missing X-CSRF-Token header" without it.
    relogin.handshake()
    session = login(ctx, relogin)
    cp = session.form_kiwi(
        "/web/cp/login", {"email": email, "password": PASSWORD},
        scope="cp-login", follow=False,
    )
    if cp.status not in (200, 302, 303, 307):
        raise RuntimeError(f"cp login failed {cp.status}: {cp.text[:200]}")
    if "apexmail_cp_session" not in session.jar:
        mfa = session.form_kiwi(
            "/web/auth/mfa/verify",
            {"email": email, "code": fresh_totp_next_window(secret), "return_to": "/dashboard"},
            scope="mfa-verify", follow=False,
        )
        if mfa.status not in (200, 302, 303, 307) or "apexmail_cp_session" not in session.jar:
            raise RuntimeError(
                f"cp mfa step failed {mfa.status}: {mfa.text[:200]} "
                f"challenge_cookie={'apexmail_login_challenge' in session.jar}"
            )
    user_id, tenant_id, role = _db_identity(ctx, email)
    identity = Identity(name=name, session=session, email=email, role=role or "owner",
                        tenant_id=tenant_id or "system", user_id=user_id)
    ctx.note(f"identity {name}: {email} tenant={identity.tenant_id} cp_cookie={'apexmail_cp_session' in session.jar}")
    return identity


def mint_api_key(ctx, owner, scopes: list[str], name: str = "dogfood-v2") -> str:
    resp = owner.session.post("/v1/auth/api-keys", {"name": name, "scopes": scopes})
    if resp.status not in (200, 201):
        raise RuntimeError(f"api key mint failed {resp.status}: {resp.text[:200]}")
    body = resp.json() or {}
    data = body.get("data") or body
    key = data.get("key") or data.get("api_key") or data.get("secret") or ""
    if not key:
        raise RuntimeError(f"api key response carried no secret: {resp.text[:200]}")
    return key


def ensure_identities(ctx) -> None:
    """Provision the identities the batteries need (idempotent)."""
    if "owner_a" not in ctx.identities:
        ctx.ensure("owner_a", lambda c: provision_owner(c, "owner_a", company="Dogfood v2 Alpha"))
    if "owner_b" not in ctx.identities:
        ctx.ensure("owner_b", lambda c: provision_owner(c, "owner_b", company="Dogfood v2 Beta"))
    owner_a = ctx.identity("owner_a")
    if "member" not in ctx.identities:
        ctx.ensure("member", lambda c: provision_role(c, owner_a, "member", name="member"))
    if "viewer" not in ctx.identities:
        ctx.ensure("viewer", lambda c: provision_role(c, owner_a, "viewer", name="viewer"))


def ensure_operator(ctx) -> None:
    if "operator" not in ctx.identities:
        ctx.ensure("operator", lambda c: provision_operator(c))


def observation(probe_id: str, surface: str, title: str, ok: bool, observed: str = "",
                expected: str = "", severity: str = "P2", evidence: dict | None = None,
                kind: str = "check") -> Observation:
    return Observation(
        probe_id=probe_id, surface=surface, title=title, ok=ok, observed=observed,
        expected=expected, severity=severity, evidence=evidence or {}, kind=kind,
    )


def unreachable(probe_id: str, surface: str, title: str, detail: str) -> Observation:
    return Observation(
        probe_id=probe_id, surface=surface, title=f"UNREACHABLE: {title}", ok=False,
        observed=detail, expected="probe must execute (zero skips)", severity="P1",
        kind="unreachable",
    )
