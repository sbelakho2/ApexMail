"""The self-test fixture server implementation.

This is a test double — NOT product code — that implements the documented
contract subset the probe battery exercises, honestly: named errors,
tenant scoping, single-use artifacts, captcha PoW with scope binding, TOTP
MFA, session rotation (AR-005), logout scope, idempotent sends, campaign
transitions, suppression/consent gates, Mailpit-shaped mailbox, tracking
redirects with abuse handling, and webhook HMAC delivery.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
import urllib.request
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote as urllib_quote, urlparse

from .config import REPO_ROOT, PASSWORD as LIVE_PASSWORD
from .identity import totp

FIXTURE_DIFFICULTY = 8
LOGIN_BUDGET = 20
CHALLENGE_BUDGET = 30
WINDOW = 900.0


class FixtureState:
    def __init__(self):
        self.lock = threading.RLock()
        self.tables: dict[str, list[dict]] = {}
        self.challenges: dict[str, dict] = {}
        self.challenge_rate: dict[str, list[float]] = {}
        self.login_rate: dict[str, list[float]] = {}
        self.sessions: dict[str, dict] = {}
        self.revoked: set[str] = set()
        self.api_keys: dict[str, dict] = {}
        self.verified_domains: set[str] = set()
        self.mailbox: list[dict] = []
        self.click_tokens: dict[str, str] = {}
        self.unsub_tokens: dict[str, str] = {}
        self.pending_mfa: dict[str, dict] = {}
        self.seq = 0

    def table(self, name: str) -> list[dict]:
        with self.lock:
            return self.tables.setdefault(name, [])

    def insert(self, _table: str, **row) -> dict:
        with self.lock:
            self.seq += 1
            row.setdefault("id", str(uuid.uuid4()))
            row.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ"))
            self.tables.setdefault(_table, []).append(row)
            return row

    def find(self, name: str, **eq) -> list[dict]:
        with self.lock:
            rows = self.tables.get(name, [])
            return [r for r in rows if all(_eq(r.get(k), v) for k, v in eq.items())]

    def find_one(self, name: str, **eq):
        found = self.find(name, **eq)
        return found[0] if found else None

    def update(self, _table: str, row_id: str, **values) -> None:
        with self.lock:
            for row in self.tables.get(_table, []):
                if str(row.get("id")) == str(row_id):
                    row.update(values)

    def delete(self, name: str, row_id: str) -> bool:
        with self.lock:
            rows = self.tables.get(name, [])
            before = len(rows)
            self.tables[name] = [r for r in rows if str(r.get("id")) != str(row_id)]
            return len(self.tables[name]) != before


def _eq(value, expected) -> bool:
    return str(value) == str(expected)


def _leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count


def get_state() -> FixtureState:
    global _STATE
    if _STATE is None:
        _STATE = FixtureState()
    return _STATE


_STATE: FixtureState | None = None


def _segments_match(pattern_path: str, request_path: str) -> bool:
    """Segment-wise match where a pattern segment starting with ':' matches
    any single request segment. Normalizing only the PATTERN (the previous
    behaviour) never matched a concrete request path, so parameterized
    /web/admin/* routes fell through to the SSR catch-all."""
    pattern = pattern_path.strip("/").split("/")
    request = request_path.strip("/").split("/")
    if len(pattern) != len(request):
        return False
    for expected, actual in zip(pattern, request):
        if expected.startswith(":"):
            continue
        if expected != actual:
            return False
    return True


def _bucket_has(entries, method: str, path: str) -> bool:
    for entry_method, pattern in entries:
        if entry_method == method and _segments_match(pattern, path):
            return True
    return False


class FixtureHandler(BaseHTTPRequestHandler):
    cfg = None
    ledger = None
    tracking = False
    state = None
    _index = None

    def log_message(self, *args):  # noqa: D102
        pass

    # ── plumbing ───────────────────────────────────────────────────────
    def _read(self) -> bytes:
        if getattr(self, "_raw_cache", None) is not None:
            return self._raw_cache
        length = int(self.headers.get("content-length", "0") or "0")
        data = self.rfile.read(length) if length else b""
        self._raw_cache = data
        return data

    def _json(self, status, payload=None, error=None, cookies=None):
        raw = json.dumps({"data": payload, "error": error, "meta": None}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _ok(self, payload=None, cookies=None, status=200):
        self._json(status, payload, None, cookies)

    def _bare(self, payload, status=200, cookies=None):
        """Unwrapped JSON (the harness-internal control plane + the auth
        endpoints whose live contract is bare: csrf token, captcha challenge)."""
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _err(self, status, code, message, details=None):
        self._json(status, None, {"code": code, "message": message, "details": details})

    def _html(self, status, html, cookies=None, location=None, ctype="text/html; charset=utf-8"):
        raw = html.encode() if isinstance(html, str) else html
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, location, cookies=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        for cookie in cookies or []:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _cookies(self) -> dict:
        out = {}
        for part in (self.headers.get("cookie") or "").split(";"):
            if "=" in part:
                key, value = part.strip().split("=", 1)
                out[key] = value
        return out

    def _session(self):
        token = self._cookies().get("am_session", "")
        if not token or token in self.state.revoked:
            return None
        return self.state.sessions.get(token)

    def _scope_ok(self) -> bool:
        jar = self._cookies()
        return bool(jar.get("csrf_token")) and hmac.compare_digest(
            jar.get("csrf_token", ""), self.headers.get("x-csrf-token", "") or "")

    def _body(self):
        raw = self._read()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return None

    def _form(self) -> dict:
        raw = self._read().decode(errors="replace")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def _auth_ok(self):
        """Session (with CSRF for writes) or an API key."""
        key = self.headers.get("x-api-key", "")
        if key:
            if hmac.compare_digest(key, _env_value("CONTROL_PLANE_API_KEY", "local-dev-control-plane-api-key-32chars")):
                # static control-plane machine credential: admitted ONLY on the
                # control-plane admin surface (mirrors authenticate_api_key's
                # is_control_plane_static_key_request carve-out)
                request_path = urlparse(self.path).path
                if request_path.startswith(("/v1/admin", "/v1/billing/admin", "/web/admin")):
                    return {"kind": "api-key", "tenant_id": "system", "scopes": ["*"]}
                return None
            record = self.state.api_keys.get(key) if hasattr(self.state.api_keys, "get") else None
            if isinstance(self.state.api_keys, dict):
                record = self.state.api_keys.get(key)
            if record and not record.get("revoked"):
                return {"kind": "api-key", "tenant_id": record["tenant_id"], "scopes": record.get("scopes", [])}
            return None
        session = self._session()
        if session is None:
            return None
        return {"kind": "session", "tenant_id": session["tenant_id"], "user_id": session["user_id"],
                "role": session["role"], "scopes": session.get("scopes", ["*"]), "session": session}

    def _require(self, scopes=()):
        auth = self._auth_ok()
        if auth is None:
            self._err(401, "UNAUTHORIZED", "authentication required")
            return None
        if self.command in ("POST", "PUT", "PATCH", "DELETE") and auth["kind"] == "session" and not self._scope_ok():
            self._err(403, "FORBIDDEN", "missing CSRF cookie or invalid CSRF token")
            return None
        if scopes:
            granted = auth.get("scopes", [])
            if "*" not in granted and not any(scope in granted for scope in scopes):
                self._err(403, "FORBIDDEN", f"missing required scope: {scopes[0]}")
                return None
        return auth

    def _is_system(self, auth) -> bool:
        if not auth:
            return False
        if auth.get("tenant_id") == "system":
            return True
        return False

    # ── routing ────────────────────────────────────────────────────────
    def do_GET(self): self._route("GET")       # noqa: E704
    def do_POST(self): self._route("POST")     # noqa: E704
    def do_PUT(self): self._route("PUT")       # noqa: E704
    def do_PATCH(self): self._route("PATCH")   # noqa: E704
    def do_DELETE(self): self._route("DELETE") # noqa: E704

    def _route(self, method):
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        host = (self.headers.get("host") or "").split(":")[0]
        self._raw_cache = None
        try:
            # axum's Json extractor refuses malformed JSON before any handler:
            # mirror it globally so the fixture's contract matches the product.
            content_type = self.headers.get("content-type") or ""
            if (method in ("POST", "PUT", "PATCH")
                    and "application/json" in content_type
                    and not path.startswith("/__fixture/")):
                raw = self._read()
                if raw.strip():
                    try:
                        json.loads(raw)
                    except Exception:  # noqa: BLE001
                        return self._err(400, "VALIDATION_ERROR", "invalid JSON body: expected value at line 1")
            if (method in ("POST", "PUT", "PATCH")
                    and path.startswith("/v1/")
                    and not path.endswith("/import")
                    and "application/json" not in content_type
                    and self.headers.get("content-length", "0") not in ("", "0")):
                return self._err(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json")
            if path.startswith("/__fixture/"):
                return self._control(method, path)
            if self.tracking:
                return self._tracking_route(method, path, host)
            if host in (self.cfg.marketing_host, "marketing.localhost") and not path.startswith(("/v1/", "/api/")):
                return self._marketing(method, path)
            if host in (self.cfg.cp_host, "admin.localhost") and not path.startswith(("/v1/", "/api/", "/health", "/assets")):
                return self._ssr(method, path, control_plane=True)
            if path in ("/web/cp/login", "/web/auth/mfa/verify", "/web/auth/login") and method == "POST":
                # operator/web login forms are console-host form POSTs; the
                # JSON router must not claim them before the SSR handler
                return self._ssr(method, path, control_plane=False)
            if self._api(method, path, query):
                return
            if path == "/assets/globals.css":
                return self._html(200, ":root{--apexmail:red}", ctype="text/css")
            if path.startswith(("/assets/", "/css/", "/fonts/", "/images/", "/js/", "/specs/")):
                return self._html(200, "/* fixture asset */", ctype="application/octet-stream")
            index = self._surface_index()
            # A /web/* path that is also a registered API route (the zero-JS
            # form routes merged into the authenticated/admin chains) must
            # answer its API contract, not the SSR page catch-all: /web/admin/*
            # and /web/contacts/export.csv are auth-gated routes, and the
            # anonymous/foreign-session probes assert the refusal.
            if _bucket_has(index["admin"], method, path) or _bucket_has(index["authenticated"], method, path):
                return self._fallback(method, path)
            if method == "GET" and (path in index["ssr_paths"] or path == "/"
                                    or path.startswith(("/web/", "/assets", "/dashboard", "/campaigns",
                                                        "/contacts", "/lists", "/templates", "/reports",
                                                        "/analytics", "/events", "/domains", "/settings",
                                                        "/assistant", "/inbox-placement", "/verify-email",
                                                        "/login", "/signup", "/forgot-password",
                                                        "/reset-password"))):
                return self._ssr(method, path, control_plane=False)
            return self._fallback(method, path)
        except BrokenPipeError:
            pass
        except Exception as error:  # noqa: BLE001
            self._err(500, "INTERNAL_ERROR", f"fixture error: {type(error).__name__}: {error}")

    def _surface_index(self):
        if FixtureHandler._index is None:
            index = {"public": set(), "authenticated": set(), "admin": set(),
                     "ssr": {}, "ssr_paths": set()}
            for surface in self.ledger.by_kind("api"):
                normalized = re.sub(r":[A-Za-z_][A-Za-z0-9_]*", ":param", surface.path)
                bucket = index.get(surface.mount_class or "public")
                if isinstance(bucket, set):
                    bucket.add((surface.method, normalized))
            for surface in self.ledger.by_kind("ssr"):
                host_kind = surface.meta.get("surface", "web")
                key = "cp" if host_kind == "control-plane" else "web"
                index["ssr"][(key, surface.path)] = surface
                index["ssr_paths"].add(surface.path)
            FixtureHandler._index = index
        return FixtureHandler._index

    def _fallback(self, method, path):
        index = self._surface_index()
        if _bucket_has(index["admin"], method, path):
            auth = self._auth_ok()
            if not auth:
                return self._err(401, "UNAUTHORIZED", "authentication required")
            return self._err(403, "FORBIDDEN", "control-plane access requires system tenant")
        if _bucket_has(index["authenticated"], method, path):
            if not self._auth_ok():
                return self._err(401, "UNAUTHORIZED", "authentication required")
            body = None
            if method in ("POST", "PUT", "PATCH") and self.headers.get("content-type", "").startswith("application/json"):
                body = self._body()
                if body is None:
                    return self._err(400, "VALIDATION_ERROR", "invalid JSON body")
            return self._err(404, "NOT_FOUND", "resource not found")
        if _bucket_has(index["public"], method, path):
            return self._err(400, "VALIDATION_ERROR", "invalid request for this endpoint")
        return self._err(404, "NOT_FOUND", "route not found")

    # ── captcha helpers ────────────────────────────────────────────────
    def _issue_challenge(self, scope: str):
        if scope not in ("login", "signup", "forgot-password", "reset-password", "cp-login",
                         "resend-verification", "mfa-verify"):
            return self._err(400, "VALIDATION_ERROR", "invalid captcha scope")
        client = self.client_address[0]
        now = time.time()
        bucket = [t for t in self.state.challenge_rate.get(client, []) if now - t < WINDOW]
        if len(bucket) >= CHALLENGE_BUDGET:
            return self._err(429, "RATE_LIMIT_EXCEEDED", "too many captcha challenges")
        bucket.append(now)
        self.state.challenge_rate[client] = bucket
        nonce = base64.b64encode(f"n-{uuid.uuid4().hex}".encode()).decode()
        salt = base64.b64encode(uuid.uuid4().bytes).decode()
        prefix = base64.b64encode(f"p-{uuid.uuid4().hex}".encode()).decode()
        with self.state.lock:
            for record in self.state.challenges.values():
                if record["scope"] == scope and not record["used"]:
                    record["superseded"] = True
            self.state.challenges[nonce] = {"scope": scope, "used": False, "superseded": False,
                                            "prefix": prefix, "salt": salt, "created": now}
        self._bare({
            "nonce": nonce, "challenge": prefix + ".fixture", "salt": salt, "algorithm": "sha256",
            "mKib": 0, "t": 3, "p": 1, "targetBits": FIXTURE_DIFFICULTY, "ttlSecs": 120,
            "minDurationMs": 0, "prefix": prefix,
        })

    def _verify_captcha(self, token: str, scope: str) -> bool:
        if not token:
            self._err(400, "VALIDATION_ERROR", "CAPTCHA verification token is required")
            return False
        try:
            plain = base64.b64decode(token).decode()
            nonce, counter, _duration, _telemetry = plain.split(".", 3)
            counter = int(counter)
        except Exception:  # noqa: BLE001
            self._err(400, "VALIDATION_ERROR", "CAPTCHA verification failed")
            return False
        record = self.state.challenges.get(nonce)
        if record is None or record["used"] or record.get("superseded") or record["scope"] != scope:
            self._err(400, "VALIDATION_ERROR",
                      "CAPTCHA verification failed — challenge expired, already used, or wrong scope")
            return False
        digest = hashlib.sha256(
            record["prefix"].encode() + str(counter).encode() + base64.b64decode(record["salt"])
        ).digest()
        if _leading_zero_bits(digest) < FIXTURE_DIFFICULTY:
            self._err(400, "VALIDATION_ERROR", "CAPTCHA verification failed")
            return False
        with self.state.lock:
            record["used"] = True
        return True

    # ── auth API ───────────────────────────────────────────────────────
    def _mint_session(self, user) -> str:
        token = base64.b64encode(f"session-{uuid.uuid4().hex}".encode()).decode()
        scopes = ["*"] if user["role"] in ("owner", "admin") else _ROLE_SCOPES.get(user["role"], [])
        self.state.sessions[token] = {"token": token, "user_id": user["id"], "tenant_id": user["tenant_id"],
                                      "role": user["role"], "scopes": scopes, "email": user["email"]}
        return token

    def _rotate_sessions(self, user_id: str) -> None:
        with self.state.lock:
            for token, session in list(self.state.sessions.items()):
                if session["user_id"] == user_id:
                    self.state.revoked.add(token)
                    self.state.sessions.pop(token, None)

    def _auth_routes(self, method, path) -> bool:
        if path == "/v1/auth/csrf" and method == "GET":
            token = hashlib.sha256(f"csrf-{uuid.uuid4()}".encode()).hexdigest()[:32]
            self._bare({"token": token}, cookies=[f"csrf_token={token}; Path=/; HttpOnly"])
            return True
        if path in ("/v1/auth/signup", "/v1/auth/register") and method == "POST":
            body = self._body() or {}
            if not self._verify_captcha(body.get("kiwi__token", ""), "signup"):
                return True
            email = str(body.get("email", "")).strip()
            password = str(body.get("password", ""))
            if not email or "@" not in email or not password:
                self._err(422, "VALIDATION_ERROR", "email and password are required")
                return True
            with self.state.lock:
                existing = self.state.find_one("users", email=email)
                if not existing:
                    tenant = self.state.insert("tenants", name=body.get("company_name") or "Fixture",
                                               plan=body.get("plan") or "free", status="active")
                    existing = self.state.insert(
                        "users", email=email, password=password, tenant_id=tenant["id"], role="owner",
                        email_verified=False, mfa_enabled=False, mfa_secret="", status="active",
                    )
                    token = base64.b64encode(f"vfy-{uuid.uuid4().hex[:24]}".encode()).decode()
                    self.state.insert("email_verifications", token=token, user_id=existing["id"], used=False)
                    self._send_mail(
                        email, "Verify your email address",
                        f'<p>Verify:</p><a href="http://127.0.0.1:{self.cfg.base.rsplit(":", 1)[1]}/verify-email/{token}">verify</a>',
                        f"verify http://127.0.0.1:{self.cfg.base.rsplit(':', 1)[1]}/verify-email/{token}",
                    )
            self._bare({"success": True}, status=202)
            return True
        if path in ("/v1/auth/verify-email",) and method == "POST":
            body = self._body() or {}
            return self._verify_email_token(str(body.get("token", "")))
        if path.startswith("/v1/auth/verify-email/") and method == "GET":
            return self._verify_email_token(path.rsplit("/", 1)[-1])
        if path == "/v1/auth/login" and method == "POST":
            body = self._body() or {}
            email = str(body.get("email", ""))
            client = self.client_address[0]
            now = time.time()
            bucket = [t for t in self.state.login_rate.get(client, []) if now - t < WINDOW]
            if len(bucket) >= LOGIN_BUDGET:
                self._err(429, "RATE_LIMIT_EXCEEDED", "too many login attempts, try again in a few minutes")
                return True
            bucket.append(now)
            self.state.login_rate[client] = bucket
            if not self._verify_captcha(body.get("kiwi__token", ""), "login"):
                return True
            user = self.state.find_one("users", email=email)
            if not user or user["password"] != str(body.get("password", "")):
                self._err(401, "UNAUTHORIZED", "invalid email or password")
                return True
            if not user.get("email_verified"):
                self._err(403, "FORBIDDEN", "Verify your email address before signing in")
                return True
            challenge = base64.b64encode(f"mfa-{uuid.uuid4().hex[:24]}".encode()).decode()
            self.state.pending_mfa[challenge] = {"user": user["id"], "used": False, "setup": not user.get("mfa_enabled")}
            if user.get("mfa_enabled"):
                self._bare({"status": "mfa_required", "challengeToken": challenge}, status=202)
            else:
                secret = base64.b32encode(uuid.uuid4().bytes[:10]).decode().rstrip("=")
                self.state.update("users", user["id"], mfa_pending_secret=secret)
                self._bare({"status": "mfa_setup_required", "challengeToken": challenge,
                            "secret": secret, "otpauthUrl": f"otpauth://totp/ApexMail:{email}?secret={secret}"}, status=202)
            return True
        if path in ("/v1/auth/mfa/verify", "/v1/auth/mfa/verify-code") and method == "POST":
            body = self._body() or {}
            if not self._verify_captcha(body.get("kiwi__token", ""), "mfa-verify"):
                return True
            challenge = self.state.pending_mfa.get(str(body.get("challenge_token", "")))
            if not challenge or challenge["used"]:
                self._err(401, "UNAUTHORIZED", "invalid or expired MFA challenge")
                return True
            user = self.state.find_one("users", id=challenge["user"])
            secret = user.get("mfa_pending_secret") or user.get("mfa_secret") or ""
            code = str(body.get("mfaCode", ""))
            if not _totp_matches(secret, code):
                # a failed attempt consumes the challenge (single-use)
                with self.state.lock:
                    challenge["used"] = True
                self._err(401, "UNAUTHORIZED", "invalid MFA code")
                return True
            with self.state.lock:
                challenge["used"] = True
            self.state.update("users", user["id"], mfa_enabled=True, mfa_secret=secret, mfa_pending_secret="")
            self._rotate_sessions(user["id"])
            token = self._mint_session(user)
            recovery = [f"rc-{uuid.uuid4().hex[:12]}" for _ in range(10)]
            self._bare(
                {"expires_at": "2030-01-01T00:00:00Z",
                 "user": {"id": user["id"], "email": user["email"], "tenant_id": user["tenant_id"], "role": user["role"]},
                 "recovery_codes": recovery, "recoveryCodes": recovery},
                cookies=[f"am_session={token}; Path=/; HttpOnly"],
            )
            return True
        if path == "/v1/auth/logout" and method == "POST":
            auth = self._auth_ok()
            if not auth or auth["kind"] != "session":
                self._err(401, "UNAUTHORIZED", "authentication required")
                return True
            if not self._scope_ok():
                self._err(403, "FORBIDDEN", "missing CSRF cookie or invalid CSRF token")
                return True
            token = self._cookies().get("am_session", "")
            with self.state.lock:
                self.state.revoked.add(token)
                self.state.sessions.pop(token, None)
            self._json(204, None, None, cookies=["am_session=; Path=/; Max-Age=0"])
            return True
        if path == "/v1/auth/me" and method == "GET":
            auth = self._auth_ok()
            if not auth or auth["kind"] != "session":
                self._err(401, "UNAUTHORIZED", "authentication required")
                return True
            user = self.state.find_one("users", id=auth["user_id"])
            self._ok({"id": user["id"], "email": user["email"], "tenant_id": user["tenant_id"], "role": user["role"]})
            return True
        if path == "/v1/auth/sessions" and method == "GET":
            auth = self._require()
            if not auth:
                return True
            rows = [s for s in self.state.sessions.values() if s["user_id"] == auth["user_id"]]
            self._ok({"sessions": [{"id": s["token"][:12], "current": True, "created_at": "2026-01-01T00:00:00Z"} for s in rows]})
            return True
        if path == "/v1/auth/sessions/revoke" and method == "POST":
            auth = self._require()
            if not auth:
                return True
            body = self._body() or {}
            target = str(body.get("session_id", ""))
            match = next((s for s in self.state.sessions.values()
                          if s["user_id"] == auth["user_id"] and s["token"].startswith(target)), None)
            if not match:
                self._err(404, "NOT_FOUND", "session not found")
                return True
            with self.state.lock:
                self.state.revoked.add(match["token"])
                self.state.sessions.pop(match["token"], None)
            self._ok({"revoked": True})
            return True
        if path in ("/v1/auth/forgot-password",) and method == "POST":
            body = self._body() or {}
            if not self._verify_captcha(body.get("kiwi__token", ""), "forgot-password"):
                return True
            email = str(body.get("email", ""))
            user = self.state.find_one("users", email=email)
            if user:
                token = base64.b64encode(f"rst-{uuid.uuid4().hex[:24]}".encode()).decode()
                self.state.insert("password_resets", token=token, user_id=user["id"], used=False)
                self._send_mail(
                    email, "Reset your password",
                    f'<a href="http://127.0.0.1:{self.cfg.base.rsplit(":", 1)[1]}/reset-password/{token}">reset</a>',
                    f"reset http://127.0.0.1:{self.cfg.base.rsplit(':', 1)[1]}/reset-password/{token}",
                )
            self._ok({"success": True, "message": "If the account exists, a reset link was sent."})
            return True
        if path in ("/v1/auth/reset-password",) and method == "POST":
            body = self._body() or {}
            if not self._verify_captcha(body.get("kiwi__token", ""), "reset-password"):
                return True
            token = str(body.get("token", ""))
            record = self.state.find_one("password_resets", token=token)
            if not record or record.get("used"):
                self._err(400, "VALIDATION_ERROR", "reset token is invalid or already used")
                return True
            user = self.state.find_one("users", id=record["user_id"])
            if not user or str(body.get("email", user["email"])) != user["email"]:
                self._err(400, "VALIDATION_ERROR", "reset token does not match the account")
                return True
            confirm = body.get("confirmPassword", body.get("confirm_password"))
            if confirm is not None and confirm != body.get("password"):
                self._err(422, "VALIDATION_ERROR", "passwords do not match")
                return True
            with self.state.lock:
                record["used"] = True
            self.state.update("users", user["id"], password=str(body.get("password", "")), email_verified=True)
            self._rotate_sessions(user["id"])
            self._ok({"success": True, "message": "Password updated"})
            return True
        if path == "/v1/auth/api-keys" and method == "POST":
            auth = self._require()
            if not auth:
                return True
            body = self._body() or {}
            requested = body.get("scopes") or []
            granted = set(auth.get("scopes", []))
            if "*" not in granted and not set(requested) <= granted:
                self._err(403, "FORBIDDEN", "requested scopes exceed the caller's scopes")
                return True
            key = "am_live_" + uuid.uuid4().hex
            record = {"id": str(uuid.uuid4()), "key": key, "name": body.get("name", ""),
                      "tenant_id": auth["tenant_id"], "user_id": auth.get("user_id"),
                      "scopes": requested}
            self.state.api_keys[key] = record
            self._ok({"id": record["id"], "key": key, "scopes": requested}, status=201)
            return True
        if path == "/v1/auth/api-keys" and method == "GET":
            auth = self._require()
            if not auth:
                return True
            rows = [{"id": r["id"], "name": r["name"], "scopes": r["scopes"]}
                    for r in self.state.api_keys.values() if r["tenant_id"] == auth["tenant_id"]]
            self._ok({"api_keys": rows})
            return True
        if path.startswith("/v1/auth/api-keys/") and method == "DELETE":
            auth = self._require()
            if not auth:
                return True
            key_id = path.rsplit("/", 1)[-1]
            for record in self.state.api_keys.values():
                if record["id"] == key_id and record["tenant_id"] == auth["tenant_id"]:
                    record["revoked"] = True
                    return self._ok({"revoked": True})
            return self._err(404, "NOT_FOUND", "api key not found")
        return False

    def _verify_email_token(self, token: str):
        record = self.state.find_one("email_verifications", token=token)
        if not record:
            self._err(400, "VALIDATION_ERROR", "verification token is invalid")
            return True
        if record.get("used"):
            self._err(400, "VALIDATION_ERROR", "verification token was already used")
            return True
        with self.state.lock:
            record["used"] = True
        self.state.update("users", record["user_id"], email_verified=True)
        self._ok({"verified": True})
        return True

    def _send_mail(self, to: str, subject: str, html: str, text: str, extra_headers=None):
        headers = [{"Key": "MIME-Version", "Value": "1.0"},
                   {"Key": "Content-Type", "Value": 'text/html; charset="utf-8"'}]
        for key, value in (extra_headers or {}).items():
            headers.append({"Key": key, "Value": value})
        self.state.mailbox.append({
            "ID": f"msg-{uuid.uuid4().hex[:12]}", "To": [{"Address": to}], "Subject": subject,
            "HTML": html, "Text": text, "Headers": headers,
            "Raw": (
                f"Subject: {subject}\r\n"
                "MIME-Version: 1.0\r\n"
                'Content-Type: text/html; charset="utf-8"\r\n'
                f"\r\n{html}"
            ),
            "Created": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        })

    # ── resource API ───────────────────────────────────────────────────
    def _api(self, method, path, query) -> bool:
        if path.startswith(("/v1/auth", "/api/auth", "/api/kcaptcha", "/v1/kcaptcha")):
            if path in ("/api/kcaptcha/challenge", "/v1/kcaptcha/challenge") and method == "POST":
                scope = (self._body() or {}).get("scope", "")
                self._issue_challenge(scope)
                return True
            if path == "/v1/auth/csrf" or path.startswith("/api/auth"):
                if self._auth_routes(method, path.replace("/api/auth", "/v1/auth")):
                    return True
            if self._auth_routes(method, path):
                return True
        if path in ("/health", "/health/deep") and method == "GET":
            self._ok({"status": "ok", "db": "connected", "redis": "connected"})
            return True
        if path == "/v1/contacts" and method == "POST":
            auth = self._require(["contacts:write"])
            if not auth:
                return True
            body = self._body()
            if body is None:
                self._err(400, "VALIDATION_ERROR", "invalid JSON body")
                return True
            email = str(body.get("email", ""))
            name = str(body.get("name", ""))
            if not email or "@" not in email:
                self._err(422, "VALIDATION_ERROR", "email is required")
                return True
            if "\x00" in email or "\x00" in name:
                self._err(400, "VALIDATION_ERROR", "control characters are not allowed")
                return True
            if len(name) > 100_000 or len(name) > 512:
                self._err(422, "VALIDATION_ERROR", "name exceeds the 512-character limit")
                return True
            if self.state.find_one("contacts", tenant_id=auth["tenant_id"], email=email):
                self._err(409, "CONFLICT", "contact already exists")
                return True
            row = self.state.insert("contacts", tenant_id=auth["tenant_id"], email=email, name=name,
                                    status="active", tags=body.get("tags") or [], metadata=body.get("metadata"))
            self._json(201, {"id": row["id"], "email": email, "name": name, "status": "active"}, None)
            return True
        if path == "/v1/contacts" and method == "GET":
            auth = self._require(["contacts:read"])
            if not auth:
                return True
            rows = self.state.find("contacts", tenant_id=auth["tenant_id"])[:100]
            self._ok({"contacts": rows, "total": len(rows)})
            return True
        if path == "/v1/contacts/bulk" and method == "POST":
            auth = self._require(["contacts:write"])
            if not auth:
                return True
            body = self._body() or {}
            items = body.get("contacts") or []
            if len(items) > 1000:
                self._err(400, "VALIDATION_ERROR", "bulk import exceeds the 1000-item limit")
                return True
            for item in items:
                if not self.state.find_one("contacts", tenant_id=auth["tenant_id"], email=item.get("email", "")):
                    self.state.insert("contacts", tenant_id=auth["tenant_id"], email=item.get("email", ""),
                                      name=item.get("name", ""), status="active")
            self._ok({"imported": len(items)})
            return True
        if path == "/v1/contacts/import" and method == "POST":
            auth = self._require(["contacts:write"])
            if not auth:
                return True
            raw = self._read().decode(errors="replace")
            rows = [line for line in raw.splitlines() if line.strip()]
            if len(rows) > 10_001:
                self._err(400, "VALIDATION_ERROR", "CSV import exceeds the 10000-row cap")
                return True
            self._ok({"imported": max(0, len(rows) - 1)})
            return True
        if path.startswith("/v1/contacts/") and method == "GET":
            auth = self._require(["contacts:read"])
            if not auth:
                return True
            cid = path.split("/")[3]
            if "/trust-score" in path:
                if not _is_uuid(cid) or not self.state.find_one("contacts", id=cid, tenant_id=auth["tenant_id"]):
                    self._err(404, "NOT_FOUND", "contact not found")
                else:
                    self._ok({"trust_score": 90, "factors": []})
                return True
            if not _is_uuid(cid):
                self._err(400, "VALIDATION_ERROR", f"invalid contact id '{cid}': must be a UUID")
                return True
            row = self.state.find_one("contacts", id=cid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "contact not found")
                return True
            self._ok(row)
            return True
        if path.startswith("/v1/contacts/") and method == "DELETE":
            auth = self._require(["contacts:write"])
            if not auth:
                return True
            cid = path.split("/")[3]
            if not _is_uuid(cid):
                self._err(400, "VALIDATION_ERROR", "invalid contact id")
                return True
            row = self.state.find_one("contacts", id=cid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "contact not found")
                return True
            self.state.delete("contacts", cid)
            self._ok({"deleted": True})
            return True
        if self._lists(method, path):
            return True
        if self._templates(method, path):
            return True
        if self._campaigns(method, path):
            return True
        if self._messages(method, path):
            return True
        if self._other_resources(method, path):
            return True
        return False

    def _lists(self, method, path) -> bool:
        if path == "/v1/lists" and method == "POST":
            auth = self._require(["lists:write"])
            if not auth:
                return True
            body = self._body() or {}
            if not str(body.get("name", "")).strip():
                self._err(422, "VALIDATION_ERROR", "name is required")
                return True
            row = self.state.insert("lists", tenant_id=auth["tenant_id"], name=body["name"],
                                    description=body.get("description", ""))
            self._json(201, {"id": row["id"], "name": row["name"]}, None)
            return True
        if path == "/v1/lists" and method == "GET":
            auth = self._require(["lists:read"])
            if not auth:
                return True
            rows = self.state.find("lists", tenant_id=auth["tenant_id"])[:100]
            self._ok({"lists": rows})
            return True
        if path.startswith("/v1/lists/") and method == "POST" and path.endswith("/subscribers"):
            auth = self._require(["lists:write"])
            if not auth:
                return True
            lid = path.split("/")[3]
            if not self.state.find_one("lists", id=lid, tenant_id=auth["tenant_id"]):
                self._err(404, "NOT_FOUND", "list not found")
                return True
            body = self._body() or {}
            # live contract: {"contact_ids": [uuid]} — the subscriber model is
            # contact-based (lists.rs::AddSubscribersRequest)
            contact_ids = body.get("contact_ids")
            if not isinstance(contact_ids, list) or not contact_ids:
                self._err(422, "VALIDATION_ERROR", "contact_ids is required")
                return True
            added = 0
            for contact_id in contact_ids:
                contact = self.state.find_one("contacts", id=contact_id, tenant_id=auth["tenant_id"])
                if not contact:
                    self._err(404, "NOT_FOUND", f"contact {contact_id} not found")
                    return True
                if not self.state.find_one("list_subscribers", list_id=lid, contact_id=contact_id):
                    self.state.insert("list_subscribers", tenant_id=auth["tenant_id"], list_id=lid,
                                      contact_id=contact_id, email=contact.get("email", ""))
                    added += 1
            self._ok({"added": added})
            return True
        if path.startswith("/v1/lists/") and method == "GET":
            auth = self._require(["lists:read"])
            if not auth:
                return True
            lid = path.split("/")[3]
            row = self.state.find_one("lists", id=lid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "list not found")
                return True
            self._ok(row)
            return True
        if path.startswith("/v1/lists/") and method == "DELETE":
            auth = self._require(["lists:write"])
            if not auth:
                return True
            lid = path.split("/")[3]
            row = self.state.find_one("lists", id=lid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "list not found")
                return True
            self.state.delete("lists", lid)
            self._ok({"deleted": True})
            return True
        return False

    def _templates(self, method, path) -> bool:
        if path == "/v1/templates" and method == "POST":
            auth = self._require(["templates:write"])
            if not auth:
                return True
            plan = (self.state.find_one("tenants", id=auth["tenant_id"]) or {}).get("plan", "free")
            if plan in ("free", ""):
                # mirrors the live require_feature(custom_templates) gate
                self._err(403, "FORBIDDEN",
                          f"plan `{plan}` does not include `custom_templates`")
                return True
            body = self._body() or {}
            name = str(body.get("name", ""))
            subject = str(body.get("subject", ""))
            html_body = str(body.get("html_body", ""))
            if len(name) > 200 or len(subject) > 255:
                self._err(422, "VALIDATION_ERROR", "name (200) or subject (255) exceeds the limit")
                return True
            if "\x00" in html_body or any(ord(c) < 32 and c not in "\n\t" for c in name + subject):
                self._err(400, "VALIDATION_ERROR", "control characters are not allowed")
                return True
            row = self.state.insert("templates", tenant_id=auth["tenant_id"], name=name,
                                    subject=subject, html_body=html_body,
                                    text_body=str(body.get("text_body", "")))
            self._json(201, {"id": row["id"], "name": name}, None)
            return True
        if path == "/v1/templates" and method == "GET":
            auth = self._require(["templates:read"])
            if not auth:
                return True
            self._ok({"templates": self.state.find("templates", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path.startswith("/v1/templates/") and method in ("GET", "DELETE"):
            auth = self._require(["templates:read" if method == "GET" else "templates:write"])
            if not auth:
                return True
            tid = path.split("/")[3]
            row = self.state.find_one("templates", id=tid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "template not found")
                return True
            if method == "DELETE":
                self.state.delete("templates", tid)
                self._ok({"deleted": True})
            else:
                self._ok(row)
            return True
        return False

    def _campaigns(self, method, path) -> bool:
        if path == "/v1/campaigns" and method == "POST":
            auth = self._require(["campaigns:write"])
            if not auth:
                return True
            body = self._body() or {}
            if not str(body.get("name", "")).strip():
                self._err(422, "VALIDATION_ERROR", "name is required")
                return True
            # the create body may carry the payload the send later uses
            row = self.state.insert("campaigns", tenant_id=auth["tenant_id"], name=body.get("name"),
                                    subject=body.get("subject", ""), from_addr=body.get("from", ""),
                                    html=body.get("html", ""), list_ids=body.get("list_ids") or [],
                                    status="draft", sent=False)
            self._json(201, {"id": row["id"], "name": row["name"], "status": "draft"}, None)
            return True
        if path == "/v1/campaigns" and method == "GET":
            auth = self._require(["campaigns:read"])
            if not auth:
                return True
            self._ok({"campaigns": self.state.find("campaigns", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path.startswith("/v1/campaigns/"):
            auth = self._require()
            if not auth:
                return True
            parts = path.split("/")
            cid = parts[3]
            action = parts[4] if len(parts) > 4 else ""
            campaign = self.state.find_one("campaigns", id=cid)
            if not campaign or campaign["tenant_id"] != auth["tenant_id"]:
                self._err(404, "NOT_FOUND", "campaign not found")
                return True
            if method == "GET" and not action:
                self._ok(campaign)
                return True
            if method == "PATCH" and not action:
                if campaign.get("sent"):
                    self._err(409, "CONFLICT", "campaign has already been sent and cannot be edited")
                    return True
                body = self._body() or {}
                self.state.update("campaigns", cid, **{k: v for k, v in body.items() if k in ("name", "subject", "html")})
                self._ok({"updated": True})
                return True
            if method == "POST" and action in ("pause", "resume"):
                if campaign.get("status") != "sending":
                    self._err(409, "CONFLICT", f"only a sending campaign can be {action}d")
                    return True
                self._ok({"status": "paused" if action == "pause" else "sending"})
                return True
            if method == "POST" and action == "send":
                if campaign.get("sent"):
                    self._err(409, "CONFLICT", "campaign was already sent")
                    return True
                subscribers = self._campaign_subscribers(auth["tenant_id"], campaign.get("list_ids") or [])
                if not subscribers:
                    self._err(400, "VALIDATION_ERROR", "campaign has no recipients (empty audience)")
                    return True
                self.state.update("campaigns", cid, sent=True, status="sending")
                delivered = 0
                for email in subscribers:
                    if self.state.find_one("suppressions", tenant_id=auth["tenant_id"], email=email):
                        self.state.insert("campaign_recipients", tenant_id=auth["tenant_id"], campaign_id=cid,
                                          email=email, status="suppressed", error="recipient is suppressed")
                        continue
                    consent = self.state.find_one("consent_records", tenant_id=auth["tenant_id"], email=email,
                                                  consent_type="marketing", granted=True)
                    if not consent:
                        self.state.insert("campaign_recipients", tenant_id=auth["tenant_id"], campaign_id=cid,
                                          email=email, status="suppressed",
                                          error="marketing consent required")
                        continue
                    delivered += 1
                    self._deliver_campaign_mail(auth["tenant_id"], campaign, email)
                self.state.update("campaigns", cid, status="sent")
                self._webhook_fire(auth["tenant_id"], "campaign.completed",
                                   {"campaign_id": cid, "delivered": delivered})
                self._ok({"status": "sent", "delivered": delivered})
                return True
            return self._err(405, "METHOD_NOT_ALLOWED", "unsupported campaign action") or True
        return False

    def _campaign_subscribers(self, tenant_id: str, list_ids: list) -> list[str]:
        emails = []
        for list_id in list_ids:
            for row in self.state.find("list_subscribers", list_id=list_id):
                if row.get("email") and row["email"] not in emails:
                    emails.append(row["email"])
        return emails

    def _deliver_campaign_mail(self, tenant_id: str, campaign: dict, email: str):
        base = self.cfg.tracking
        target = "https://example.com/dgv2-target"
        click = base + "/c/" + uuid.uuid4().hex[:24]
        pixel = base + "/o/" + uuid.uuid4().hex[:24]
        unsub = base + "/u/" + uuid.uuid4().hex[:24]
        self.state.click_tokens[click.rsplit("/", 1)[-1]] = target
        self.state.unsub_tokens[unsub.rsplit("/", 1)[-1]] = email
        html = (campaign.get("html") or "<p>dogfood</p>").replace(
            'href="https://example.com/dgv2-target"', f'href="{click}"')
        html += f'<img src="{pixel}" width="1" height="1">'
        self._send_mail(
            email, campaign.get("subject", "campaign"), html,
            f"campaign {campaign.get('subject')} {click}",
            extra_headers={"List-Unsubscribe": f"<{unsub}>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"},
        )
        message = self.state.insert("messages", tenant_id=tenant_id, subject=campaign.get("subject", ""),
                                    status="sent", to_emails=[email], category="marketing")
        self.state.insert("campaign_recipients", tenant_id=tenant_id, campaign_id=campaign["id"],
                          email=email, status="sent", error=None)
        self.state.insert("events", tenant_id=tenant_id, message_id=message["id"], event_type="delivered",
                          status="delivered")

    def _messages(self, method, path) -> bool:
        if path == "/v1/messages" and method == "POST":
            auth = self._require(["messages:send"])
            if not auth:
                return True
            raw = self._read()
            body = None
            try:
                body = json.loads(raw)
            except Exception:  # noqa: BLE001
                self._err(400, "VALIDATION_ERROR", "invalid JSON body")
                return True
            if not isinstance(body, dict):
                self._err(400, "VALIDATION_ERROR", "body must be a JSON object")
                return True
            from_addr = str(body.get("from", ""))
            recipients = body.get("to") or []
            if isinstance(recipients, str):
                recipients = [recipients]
            if not from_addr or not recipients:
                self._err(422, "VALIDATION_ERROR", "from and to are required")
                return True
            for value in [from_addr] + list(recipients) + [str(body.get("subject", ""))]:
                if "\r" in value or "\n" in value:
                    self._err(400, "VALIDATION_ERROR", "header injection (CRLF) is not allowed")
                    return True
            headers = body.get("headers") or {}
            if isinstance(headers, dict):
                for key, value in headers.items():
                    if "\r" in str(value) or "\n" in str(value):
                        self._err(400, "VALIDATION_ERROR", "header injection (CRLF) is not allowed")
                        return True
            sender_domain = from_addr.split("@")[-1].lower()
            if sender_domain not in {d.lower() for d in self.state.verified_domains}:
                self._err(403, "FORBIDDEN", f"sender domain '{sender_domain}' is not verified")
                return True
            if len(raw) > 41 * 1024 * 1024:
                self._err(413, "PAYLOAD_TOO_LARGE", "request body exceeds the 40 MiB limit")
                return True
            template_id = body.get("template_id")
            template = None
            if template_id:
                template = self.state.find_one("templates", id=template_id, tenant_id=auth["tenant_id"])
                if not template:
                    self._err(404, "NOT_FOUND", "template not found")
                    return True
                data = body.get("template_data") or {}
                text = (template.get("subject", "") + template.get("html_body", ""))
                for variable in set(re.findall(r"\{\{\s*([a-z0-9_]+)\s*\}\}", text)):
                    if variable not in data:
                        self._err(422, "VALIDATION_ERROR",
                                  f"template variable '{variable}' is missing from template_data")
                        return True
            idempotency = self.headers.get("idempotency-key", "")
            if idempotency:
                existing = self.state.find_one("idempotency_keys", tenant_id=auth["tenant_id"], key=idempotency)
                if existing:
                    self._json(existing["status"], {"id": existing["message_id"], "status": "queued"}, None)
                    return True
            for recipient in recipients:
                if self.state.find_one("suppressions", tenant_id=auth["tenant_id"], email=recipient):
                    self._err(400, "VALIDATION_ERROR", f"recipient is suppressed: {recipient}")
                    return True
                if str(body.get("category", "marketing")) != "transactional":
                    consent = self.state.find_one("consent_records", tenant_id=auth["tenant_id"],
                                                  email=recipient, consent_type="marketing", granted=True)
                    if not consent:
                        self._err(400, "VALIDATION_ERROR",
                                  f"marketing consent required for {recipient}: no marketing consent on file")
                        return True
            message = self.state.insert("messages", tenant_id=auth["tenant_id"],
                                        subject=body.get("subject", ""), status="queued",
                                        to_emails=list(recipients), category=body.get("category", "marketing"))
            self.state.insert("email_queue", tenant_id=auth["tenant_id"], message_id=message["id"],
                              status="delivered")
            html = body.get("html") or ""
            if template:
                data = body.get("template_data") or {}
                rendered = template.get("html_body", "")
                for key, value in data.items():
                    rendered = rendered.replace("{{" + key + "}}", str(value)).replace(
                        "{{ " + key + " }}", str(value))
                html = rendered
                subject = body.get("subject") or template.get("subject", "")
            else:
                subject = body.get("subject", "")
            for recipient in recipients:
                self._send_mail(recipient, subject, html or "<p></p>", body.get("text") or "")
            self.state.update("messages", message["id"], status="sent")
            self.state.insert("events", tenant_id=auth["tenant_id"], message_id=message["id"],
                              event_type="sent", status="sent")
            self._webhook_fire(auth["tenant_id"], "message.sent", {"message_id": message["id"]})
            if idempotency:
                self.state.insert("idempotency_keys", tenant_id=auth["tenant_id"], key=idempotency,
                                  message_id=message["id"], status=202)
            self._json(202, {"id": message["id"], "status": "queued"}, None)
            return True
        if path == "/v1/messages" and method == "GET":
            auth = self._require(["messages:read"])
            if not auth:
                return True
            self._ok({"messages": self.state.find("messages", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path.startswith("/v1/messages/") and path.endswith("/timeline") and method == "GET":
            auth = self._require(["messages:read"])
            if not auth:
                return True
            mid = path.split("/")[3]
            if "at" not in parse_qs(urlparse(self.path).query):
                self._err(400, "VALIDATION_ERROR", "the 'at' query parameter is required")
                return True
            row = self.state.find_one("messages", id=mid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "message not found")
                return True
            self._ok({"status": row.get("status", "sent"), "since": row.get("created_at"),
                      "source": "events"})
            return True
        return False

    def _other_resources(self, method, path) -> bool:
        if path == "/v1/events" and method == "GET":
            auth = self._require(["events:read"])
            if not auth:
                return True
            self._ok({"events": self.state.find("events", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path == "/v1/suppressions" and method == "POST":
            auth = self._require(["suppressions:write"])
            if not auth:
                return True
            body = self._body() or {}
            email = str(body.get("email", ""))
            if not email:
                self._err(422, "VALIDATION_ERROR", "email is required")
                return True
            if str(body.get("reason", "manual")) not in ("manual", "bounce", "complaint", "unsubscribe"):
                self._err(422, "VALIDATION_ERROR", "invalid suppression reason")
                return True
            if not self.state.find_one("suppressions", tenant_id=auth["tenant_id"], email=email):
                self.state.insert("suppressions", tenant_id=auth["tenant_id"], email=email,
                                  reason=body.get("reason", "manual"))
            self._json(201, {"email": email}, None)
            return True
        if path == "/v1/suppressions" and method == "GET":
            auth = self._require(["suppressions:read"])
            if not auth:
                return True
            self._ok({"suppressions": self.state.find("suppressions", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path.startswith("/v1/suppressions/") and method == "DELETE":
            auth = self._require(["suppressions:write"])
            if not auth:
                return True
            sid = path.split("/")[3]
            row = self.state.find_one("suppressions", id=sid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "suppression not found")
                return True
            if row.get("reason") in ("complaint", "bounce"):
                self._err(409, "CONFLICT",
                          f"{row['reason']} suppressions cannot be removed (compliance policy)")
                return True
            self.state.delete("suppressions", sid)
            self._ok({"removed": True})
            return True
        if path == "/v1/webhooks" and method == "GET":
            auth = self._require(["webhooks:read"])
            if not auth:
                return True
            self._ok({"webhooks": [{k: v for k, v in row.items() if k != "secret"}
                                   for row in self.state.find("webhooks", tenant_id=auth["tenant_id"])]})
            return True
        if path == "/v1/webhooks" and method == "POST":
            auth = self._require(["webhooks:write"])
            if not auth:
                return True
            body = self._body() or {}
            url = str(body.get("url", ""))
            if not url.startswith("http"):
                self._err(422, "VALIDATION_ERROR", "url must be an absolute http(s) URL")
                return True
            secret = "whsec_" + uuid.uuid4().hex
            row = self.state.insert("webhooks", tenant_id=auth["tenant_id"], url=url,
                                    secret=secret, events=body.get("events") or [])
            self._json(201, {"id": row["id"], "secret": secret, "url": url}, None)
            return True
        if path.startswith("/v1/webhooks/") and path.endswith("/test") and method == "POST":
            auth = self._require(["webhooks:write"])
            if not auth:
                return True
            wid = path.split("/")[3]
            row = self.state.find_one("webhooks", id=wid, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "webhook not found")
                return True
            ok = self._deliver_webhook(row, "test", {"webhook_id": wid})
            self._ok({"success": ok, "response_time_ms": 5, "error": None if ok else "delivery failed"})
            return True
        if path.startswith("/v1/webhooks/") and method == "DELETE":
            auth = self._require(["webhooks:write"])
            if not auth:
                return True
            wid = path.split("/")[3]
            if not self.state.find_one("webhooks", id=wid, tenant_id=auth["tenant_id"]):
                self._err(404, "NOT_FOUND", "webhook not found")
                return True
            self.state.delete("webhooks", wid)
            self._ok({"deleted": True})
            return True
        if path == "/v1/domains" and method == "GET":
            auth = self._require(["domains:read"])
            if not auth:
                return True
            self._ok({"domains": self.state.find("domains", tenant_id=auth["tenant_id"])[:100]})
            return True
        if path == "/v1/domains" and method == "POST":
            auth = self._require(["domains:write"])
            if not auth:
                return True
            body = self._body() or {}
            name = str(body.get("name", "")).lower()
            if not re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", name):
                self._err(400, "VALIDATION_ERROR", "invalid domain name")
                return True
            row = self.state.insert("domains", tenant_id=auth["tenant_id"], name=name, verified=False,
                                    dkim_selector="dgv2", dkim_public_key="MIGfMA0GCSqGSIb3DQEBAQUAA4GN")
            self._json(201, {"id": row["id"], "name": name, "verified": False,
                             "dkim_selector": "dgv2", "dkim_public_key": row["dkim_public_key"]}, None)
            return True
        if path.startswith("/v1/domains/") and path.endswith("/dns-records") and method == "GET":
            auth = self._require(["domains:read"])
            if not auth:
                return True
            did = path.split("/")[3]
            row = self.state.find_one("domains", id=did, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "domain not found")
                return True
            self._ok({"records": [
                {"type": "TXT", "name": f"{row['dkim_selector']}._domainkey.{row['name']}",
                 "value": f"v=DKIM1; k=rsa; p={row['dkim_public_key']}"},
                {"type": "TXT", "name": f"_dmarc.{row['name']}", "value": "v=DMARC1; p=none;"},
            ]})
            return True
        if path.startswith("/v1/domains/") and path.endswith("/verify") and method == "POST":
            auth = self._require(["domains:write"])
            if not auth:
                return True
            did = path.split("/")[3]
            row = self.state.find_one("domains", id=did, tenant_id=auth["tenant_id"])
            if not row:
                self._err(404, "NOT_FOUND", "domain not found")
                return True
            if row["name"] in self.state.verified_domains:
                self.state.update("domains", did, verified=True)
                self._ok({"verified": True, "status": "verified"})
            else:
                self._ok({"verified": False, "status": "pending",
                          "message": "DNS records not published yet"})
            return True
        if path.startswith("/v1/domains/") and method == "DELETE":
            auth = self._require(["domains:write"])
            if not auth:
                return True
            did = path.split("/")[3]
            if not self.state.find_one("domains", id=did, tenant_id=auth["tenant_id"]):
                self._err(404, "NOT_FOUND", "domain not found")
                return True
            self.state.delete("domains", did)
            self._ok({"deleted": True})
            return True
        if path == "/v1/billing/plans" and method == "GET":
            auth = self._require(["billing:read"])
            if not auth:
                return True
            self._ok({"plans": [
                {"id": "free", "priceMonthly": 0, "emailLimit": 3000},
                {"id": "starter", "priceMonthly": 2900, "emailLimit": 50000},
                {"id": "pro", "priceMonthly": 8900, "emailLimit": 200000},
                {"id": "growth", "priceMonthly": 22900, "emailLimit": 1000000},
                {"id": "scale", "priceMonthly": 69900, "emailLimit": 5000000},
            ]})
            return True
        if path == "/v1/billing/quota" and method == "GET":
            auth = self._require(["billing:read"])
            if not auth:
                return True
            plan = (self.state.find_one("tenants", id=auth["tenant_id"]) or {}).get("plan", "free")
            limit = {"free": 3000, "growth": 1000000}.get(plan, 3000)
            used = len(self.state.find("messages", tenant_id=auth["tenant_id"]))
            self._ok({"limit": limit, "used": used, "remaining": max(0, limit - used)})
            return True
        if path == "/v1/billing/entitlements" and method == "GET":
            auth = self._require(["billing:read"])
            if not auth:
                return True
            plan = (self.state.find_one("tenants", id=auth["tenant_id"]) or {}).get("plan", "free")
            features = {"advancedAnalytics": plan != "free", "customTrackingDomain": plan != "free",
                        "auditLogs": plan != "free"}
            self._ok({"plan": plan, "features": features})
            return True
        if path == "/v1/billing/invoices" and method == "GET":
            auth = self._require(["billing:read"])
            if not auth:
                return True
            self._ok({"invoices": []})
            return True
        if path == "/v1/dedicated-ips" and method == "POST":
            auth = self._require()
            if not auth:
                return True
            self._err(503, "SERVICE_UNAVAILABLE", "dedicated IP provisioning not configured")
            return True
        if path == "/v1/dashboard/stats" and method == "GET":
            auth = self._require()
            if not auth:
                return True
            self._ok({"total_messages_sent": len(self.state.find("messages", tenant_id=auth["tenant_id"])),
                      "delivery_rate": 1.0})
            return True
        if path == "/v1/analytics/dashboard" and method == "GET":
            auth = self._require(["analytics:read"])
            if not auth:
                return True
            self._ok({"volume": 0, "engagement": 0, "deliverability": 1.0})
            return True
        if path == "/v1/analytics/volume" and method == "GET":
            auth = self._require(["analytics:read"])
            if not auth:
                return True
            self._ok({"data": []})
            return True
        if path == "/webhooks/stripe" and method == "POST":
            return self._stripe(method, path)
        if path.startswith("/v1/admin/") and method == "GET":
            if self._admin(method, path):
                return True
        if path == "/v1/grader/check" and method == "POST":
            body = self._body() or {}
            domain = str(body.get("domain", ""))
            if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain.lower()):
                self._err(422, "VALIDATION_ERROR", "domain is required and must be a valid name")
                return True
            self._ok({"domain": domain, "score": 92, "checks": []})
            return True
        if path == "/v1/inbox-placement/providers" and method == "GET":
            self._ok({"providers": [{"id": "gmail", "name": "Gmail"}]})
            return True
        if path.startswith("/v1/inbox-placement/tests"):
            auth = self._require()
            if not auth:
                return True
            if method == "GET":
                self._ok({"tests": []})
            else:
                self._ok({"id": str(uuid.uuid4()), "status": "queued"})
            return True
        if path == "/explorer/exec" and method == "POST":
            body = self._body() or {}
            target = str(body.get("path", ""))
            if target.startswith("/v1/admin") or "admin" in target:
                self._err(403, "FORBIDDEN", "control-plane paths are not available in the sandbox")
                return True
            recipients = ((body.get("body") or {}).get("to") or [])
            if isinstance(recipients, str):
                recipients = [recipients]
            for recipient in recipients:
                if not str(recipient).endswith("@example.com"):
                    self._err(400, "VALIDATION_ERROR",
                              "the sandbox only sends to @example.com recipients")
                    return True
            if not target:
                self._err(422, "VALIDATION_ERROR", "path is required")
                return True
            self._ok({"status": 202, "sandbox": True})
            return True
        return False

    def _admin(self, method, path) -> bool:
        auth = self._auth_ok()
        if not auth:
            self._err(401, "UNAUTHORIZED", "authentication required")
            return True
        if not self._is_system(auth):
            self._err(403, "FORBIDDEN", "control-plane access requires system tenant")
            return True
        if auth.get("kind") == "session" and not self._cookies().get("apexmail_cp_session"):
            # require_cp_auth on every /v1/admin route: an am_session alone —
            # even a system-tenant one — is not a control-plane credential.
            # Machine credentials (static CP key / system API keys) pass.
            self._err(403, "FORBIDDEN", "MFA-backed control-plane session required")
            return True
        if path == "/v1/admin/tenants":
            self._ok({"tenants": self.state.table("tenants")[:20]})
        elif path == "/v1/admin/dashboard/stats":
            self._ok({"tenants": len(self.state.table("tenants"))})
        elif path.startswith("/v1/admin/audit"):
            self._ok({"logs": []})
        else:
            self._ok({"ok": True})
        return True

    def _stripe(self, method, path) -> bool:
        signature = self.headers.get("stripe-signature", "")
        raw = self._read()
        secret = _env_value("STRIPE_WEBHOOK_SECRET", "dev-stripe-webhook-secret-local-only-0123456789")
        if not signature:
            self._err(400, "VALIDATION_ERROR", "Missing stripe-signature header")
            return True
        try:
            timestamp, candidate = signature.split(",", 1)
            timestamp = timestamp.split("=", 1)[1]
            candidate = candidate.split("=", 1)[1]
        except Exception:  # noqa: BLE001
            self._err(400, "VALIDATION_ERROR", "malformed stripe-signature header")
            return True
        expected = hmac.new(secret.encode(), f"{timestamp}.".encode() + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, candidate):
            self._err(400, "VALIDATION_ERROR", "Invalid webhook signature")
            return True
        try:
            event = json.loads(raw)
        except Exception:  # noqa: BLE001
            self._err(400, "VALIDATION_ERROR", "Invalid JSON payload")
            return True
        event_id = str(event.get("id", ""))
        if not event_id:
            self._err(400, "VALIDATION_ERROR", "Missing event ID")
            return True
        if not self.state.find_one("stripe_webhook_events", stripe_event_id=event_id):
            self.state.insert("stripe_webhook_events", stripe_event_id=event_id,
                              event_type=event.get("type", ""), status="processed")
        self._ok({"received": True})
        return True

    def _webhook_fire(self, tenant_id: str, event: str, payload: dict) -> None:
        for row in self.state.find("webhooks", tenant_id=tenant_id):
            if event in (row.get("events") or []) or not row.get("events"):
                self._deliver_webhook(row, event, payload)

    def _deliver_webhook(self, row: dict, event: str, payload: dict) -> bool:
        body = json.dumps(payload).encode()
        timestamp = str(int(time.time() * 1000))
        signature = "sha256=" + hmac.new(
            row["secret"].encode(), f"{timestamp}.".encode() + body, hashlib.sha256
        ).hexdigest()
        request = urllib.request.Request(
            row["url"], data=body, method="POST",
            headers={"Content-Type": "application/json", "X-ApexMail-Signature": signature,
                     "X-ApexMail-Timestamp": timestamp, "X-ApexMail-Event": event,
                     "X-ApexMail-Webhook-Id": row["id"]},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                ok = 200 <= response.status < 300
        except Exception:  # noqa: BLE001
            ok = False
        self.state.insert("webhook_deliveries", tenant_id=row["tenant_id"], webhook_id=row["id"],
                          event=event, status_code=200 if ok else 0)
        return ok

    # ── SSR / marketing / tracking ─────────────────────────────────────
    def _ssr(self, method, path, *, control_plane: bool):
        if method == "GET" and path.startswith("/verify-email/"):
            token = path.split("/verify-email/", 1)[1].split("?", 1)[0]
            self._verify_email_token(token)
            return
        if path == "/login":
            nonce = uuid.uuid4().hex
            html = (
                "<!doctype html><html><head><title>Login – ApexMail</title>"
                f'<script nonce="{nonce}">window.__kiwi = true;</script></head><body>'
                '<form method="post" action="/web/auth/login">'
                '<input name="email"><input name="password" type="password">'
                '<input type="hidden" name="kiwi__token" value="">'
                '<input type="hidden" name="_csrf" value="fixture"></form>'
                "<p>Sign in to the ApexMail console (mock).</p></body></html>"
            )
            self._html(200, html)
            return
        if path == "/web/auth/login" and method == "POST":
            form = self._form()
            body = self.state.find_one("users", email=form.get("email", ""))
            if not body or body["password"] != form.get("password", "") or not form.get("kiwi__token"):
                self._redirect("/login")
                return
            self._redirect("/login?mfa=1")
            return
        if path == "/web/team/invite" and method == "POST":
            auth = self._require()
            if not auth:
                return
            if auth.get("role") not in ("owner", "admin"):
                self._redirect("/settings/team")
                return
            form = self._form()
            email = form.get("userName", "")
            if email and not self.state.find_one("users", email=email):
                self.state.insert("users", email=email, password="", tenant_id=auth["tenant_id"],
                                  role=form.get("role", "member"), email_verified=False, mfa_enabled=False,
                                  mfa_secret="", status="invited")
            self._redirect("/settings/team")
            return
        if path == "/web/assistant/message" and method == "POST":
            auth = self._require()
            if not auth:
                return
            form = self._form()
            message = form.get("message", "")
            if not message or len(message) > 20_000:
                self._ok({"refused": True})
                return
            self.state.insert("ai_chat_sessions", tenant_id=auth["tenant_id"], message=message[:200])
            self._redirect("/assistant")
            return
        if path == "/web/cp/login" and method == "POST":
            # The CP login is captcha-gated (scope cp-login) and mints the
            # separate control-plane cookie only for a system-tenant user —
            # the same contract the live operator lifecycle exercises. An
            # MFA-enabled operator gets the challenge redirect instead, and
            # /web/auth/mfa/verify completes the exchange.
            form = self._form()
            if not self._verify_captcha(form.get("kiwi__token", ""), "cp-login"):
                return
            user = self.state.find_one("users", email=form.get("email", ""))
            if (
                not user
                or user["password"] != form.get("password", "")
                or user.get("tenant_id") != "system"
            ):
                self._redirect("/login?error=cp_denied")
                return
            if user.get("mfa_enabled"):
                challenge = base64.b64encode(f"web-mfa-{uuid.uuid4().hex[:24]}".encode()).decode()
                self.state.pending_mfa[challenge] = {"user": user["id"], "used": False, "web": True}
                self._redirect(
                    "/login?mfa=1&email=" + urllib_quote(user["email"]),
                    cookies=[f"apexmail_login_challenge={challenge}; Path=/; HttpOnly"],
                )
                return
            token = base64.b64encode(f"cp-{uuid.uuid4().hex}".encode()).decode()
            self._redirect("/tenants", cookies=[f"apexmail_cp_session={token}; Path=/; HttpOnly"])
            return
        if path == "/web/auth/mfa/verify" and method == "POST":
            form = self._form()
            if not self._verify_captcha(form.get("kiwi__token", ""), "mfa-verify"):
                return
            challenge = self._cookies().get("apexmail_login_challenge", "")
            record = self.state.pending_mfa.get(challenge)
            user = self.state.find_one("users", email=form.get("email", ""))
            secret = (user or {}).get("mfa_secret") or (user or {}).get("mfa_pending_secret") or ""
            if (
                not record
                or record.get("used")
                or not user
                or record["user"] != user["id"]
                or not _totp_matches(secret, str(form.get("code", "")))
            ):
                self._redirect("/login?mfa=1&error=bad_code")
                return
            with self.state.lock:
                record["used"] = True
            self.state.update("users", user["id"], mfa_enabled=True, mfa_secret=secret)
            token = self._mint_session(user)
            cookies = [f"am_session={token}; Path=/; HttpOnly"]
            if user.get("tenant_id") == "system":
                cp_token = base64.b64encode(f"cp-{uuid.uuid4().hex}".encode()).decode()
                cookies.append(f"apexmail_cp_session={cp_token}; Path=/; HttpOnly")
            self._redirect("/dashboard", cookies=cookies)
            return
        if method == "POST":
            return self._err(405, "METHOD_NOT_ALLOWED", "form endpoint not implemented in the fixture")
        # SSR pages (dynamic bodies so the CRUD round-trips can assert content)
        session = self._session()
        if control_plane and session and session.get("tenant_id") != "system":
            self._redirect("/login?next=" + path)
            return
        if control_plane and path != "/login" and not self._cookies().get("apexmail_cp_session"):
            # mirror the live CP gate: the system-tenant session is necessary
            # but not sufficient — the signed CP session cookie is the second
            # factor (middleware/cp_auth.rs require_cp_auth)
            self._redirect("/login?next=" + path)
            return
        index = self._surface_index()
        key = "cp" if control_plane else "web"
        surface = index["ssr"].get((key, path))
        if surface is None and path not in ("/dashboard", "/contacts", "/lists", "/templates", "/campaigns"):
            if path.startswith(("/web/", "/settings", "/lists/", "/campaigns/", "/contacts/", "/templates/",
                                "/domains/", "/events", "/analytics", "/reports", "/assistant",
                                "/inbox-placement", "/messages/")):
                self._html(200, _page(f"Page {path}", "console surface (fixture)"))
                return
            return self._err(404, "NOT_FOUND", "page not found")
        if surface is not None and surface.auth_required and not session:
            self._redirect("/login?next=" + path)
            return
        tenant = session["tenant_id"] if session else ""
        extra = ""
        for table, label in (("contacts", "contacts"), ("lists", "lists"), ("templates", "templates"),
                             ("campaigns", "campaigns")):
            rows = self.state.find(table, tenant_id=tenant)
            if rows:
                extra += f"<section id='{label}'>" + "".join(
                    f"<div>{_esc(str(r.get('name') or r.get('email') or r.get('subject') or ''))}</div>" for r in rows
                ) + "</section>"
        self._html(200, _page(f"Page {path}", extra or "no rows yet"))

    def _marketing(self, method, path):
        if path == "/robots.txt":
            return self._html(200, "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n", ctype="text/plain")
        if path == "/sitemap.xml":
            urls = "".join(f"<url><loc>https://apexmail.ee/page{i}</loc></url>" for i in range(8))
            return self._html(200, f'<?xml version="1.0" encoding="UTF-8"?><urlset>{urls}</urlset>',
                              ctype="application/xml")
        if path == "/.well-known/security.txt":
            return self._html(200, "Contact: mailto:security@apexmail.ee\nExpires: 2030-01-01T00:00:00Z\n",
                              ctype="text/plain")
        if path == "/manifest.json":
            return self._html(200, json.dumps({"name": "ApexMail", "short_name": "ApexMail"}),
                              ctype="application/manifest+json")
        if path.startswith(("/css", "/fonts", "/images", "/js", "/specs", "/giallo.css", "/icon.svg",
                            "/favicon.ico", "/pgp-key", "/mail/", "/.well-known")):
            return self._html(200, "/* fixture asset */", ctype="text/plain")
        markers = {
            "/": "ApexMail", "/pricing": "pricing plans", "/features": "features", "/compare": "compare",
            "/compare/postmark": "Postmark", "/compare/resend": "Resend", "/compare/sendgrid": "SendGrid",
            "/terms": "terms of service", "/privacy": "privacy policy", "/cookies": "cookies",
            "/dpa": "data processing agreement", "/sla": "service level agreement",
            "/acceptable-use": "acceptable use", "/data-locations": "data locations",
            "/docs": "documentation", "/docs/api": "api reference", "/status": "status",
            "/api-console": "api console", "/email-logs": "email logs", "/demo": "demo",
            "/private-cloud": "private cloud", "/compliance": "compliance", "/inbox-placement": "inbox placement",
            "/secure-email-for-regulated-saas": "regulated", "/contact": "contact", "/contact/sales": "sales",
            "/de": "German", "/fr": "French", "/es": "Spanish",
        }
        for prefix, marker in markers.items():
            if path == prefix:
                links = "".join(f'<a href="{p}">link</a>' for p in ("/pricing", "/features", "/docs", "/status"))
                return self._html(200, _page(f"{path} — {marker.title()}", f"{marker}. {links}"))
        if path in ("/de/cookies", "/fr/cookies", "/es/cookies"):
            return self._html(200, _page("Cookies", "cookies policy"))
        if path.startswith("/docs/"):
            return self._html(200, _page("Docs", "documentation"))
        # auth pages on the marketing host fall back to console pages
        return self._html(200, _page(path, "marketing page"))

    def _tracking_route(self, method, path, host):
        if host not in (self.cfg.marketing_host, "127.0.0.1", "localhost", "t.apexmail.ee") and host not in (
                self.cfg.host, "apexmail.ee", "www.apexmail.ee"):
            if not path.startswith(("/health", "/ready")):
                self._json(421, None, {"code": "MISDIRECTED_REQUEST", "message": "unknown host", "details": None})
                return
        if path.startswith("/o/") or path == "/o.gif":
            gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
            self._html(200, gif, ctype="image/gif")
            return
        if path.startswith("/c/"):
            token = path.split("/")[2]
            target = self.state.click_tokens.get(token)
            if target:
                self.state.insert("click_events", token=token, target=target)
                self._redirect(target)
            else:
                self._err(404, "NOT_FOUND", "unknown tracking link")
            return
        if path.startswith("/u/") and path.endswith("/confirm") and method == "POST":
            self._html(200, _page("Unsubscribed", "you are unsubscribed"))
            return
        if path.startswith("/u/") and method == "POST":
            token = path.split("/")[2]
            email = self.state.unsub_tokens.get(token)
            if email:
                if not self.state.find_one("suppressions", email=email):
                    self.state.insert("suppressions", tenant_id="", email=email, reason="unsubscribe")
                self._html(200, _page("Unsubscribed", f"{email} unsubscribed"))
            else:
                self._err(404, "NOT_FOUND", "unknown unsubscribe token")
            return
        if path.startswith("/u/") and method == "GET":
            self._html(200, _page("Confirm unsubscribe", "confirm the unsubscribe (side-effect free GET)"))
            return
        if path.startswith("/p/") and method in ("GET", "POST"):
            self._html(200, _page("Preferences", "email preferences"))
            return
        if path == "/v1/stream":
            self._html(200, "event: ping\ndata: {}\n\n", ctype="text/event-stream")
            return
        if path in ("/health", "/ready"):
            self._ok({"status": "ok"})
            return
        self._err(404, "NOT_FOUND", "tracking route not found")

    # ── fixture control ────────────────────────────────────────────────
    def _control(self, method, path):
        body = self._body() or {}
        if path == "/__fixture/mailbox":
            if method == "DELETE":
                self.state.mailbox.clear()
                self._bare({"cleared": True})
            else:
                self._bare({"messages": self.state.mailbox})
            return
        if path == "/__fixture/state":
            query = parse_qs(urlparse(self.path).query)
            op = (query.get("op") or ["count"])[0]
            table = (query.get("table") or [""])[0]
            eq = {k[3:]: v[0] for k, v in query.items() if k.startswith("eq_")}
            if op == "count":
                self._bare({"count": len(self.state.find(table, **eq))})
            elif op == "row":
                self._bare({"row": self.state.find_one(table, **eq)})
            elif op == "tables":
                from .ledger import migration_tables
                self._bare({"tables": sorted(migration_tables().keys())})
            elif op == "columns":
                rows = self.state.table(table)
                keys = sorted({k for row in rows for k in row}) or ["id", "tenant_id", "created_at"]
                self._bare({"columns": keys})
            else:
                self._err(404, "NOT_FOUND", "unknown op")
            return
        if path == "/__fixture/clear_rates":
            with self.state.lock:
                self.state.challenge_rate.clear()
                self.state.login_rate.clear()
            self._bare({"cleared": True})
            return
        if path == "/__fixture/assign":
            user = self.state.find_one("users", email=body.get("email", ""))
            if user:
                self.state.update("users", user["id"], tenant_id=body.get("tenant", user["tenant_id"]),
                                  role=body.get("role", "member"))
            self._bare({"assigned": bool(user)})
            return
        if path == "/__fixture/promote":
            user = self.state.find_one("users", email=body.get("email", ""))
            if user:
                self.state.update("users", user["id"], tenant_id="system", role="owner")
            self._bare({"promoted": bool(user)})
            return
        if path == "/__fixture/consent":
            self.state.insert("consent_records", tenant_id=body.get("tenant", ""),
                              email=body.get("email", ""), consent_type="marketing", granted=True,
                              subscriber_id=body.get("contact", ""))
            self._bare({"granted": True})
            return
        if path == "/__fixture/domain":
            self.state.verified_domains.add(body.get("name", ""))
            self.state.insert("domains", id=body.get("id"), tenant_id=body.get("tenant", ""),
                              name=body.get("name", ""), verified=True)
            self._bare({"verified": True})
            return
        if path == "/__fixture/plan":
            tenant = self.state.find_one("tenants", id=body.get("tenant", ""))
            if tenant:
                self.state.update("tenants", tenant["id"], plan=body.get("plan", "free"))
            self._bare({"plan": body.get("plan", "free"), "updated": bool(tenant)})
            return
        self._err(404, "NOT_FOUND", "unknown fixture control op")


_ROLE_SCOPES = {
    "owner": ["*"], "admin": ["*"],
    "developer": ["messages:send", "messages:read", "domains:read", "domains:write",
                  "templates:read", "templates:write", "events:read", "analytics:read",
                  "contacts:read", "contacts:write", "lists:read", "lists:write", "logs:read",
                  "webhooks:read", "webhooks:write", "campaigns:read", "campaigns:write",
                  "suppressions:read", "suppressions:write", "billing:read"],
    "viewer": ["messages:read", "domains:read", "templates:read", "events:read", "analytics:read",
               "contacts:read", "lists:read", "logs:read", "webhooks:read", "campaigns:read",
               "suppressions:read", "billing:read"],
    "member": ["messages:read"],
}


def _is_uuid(value: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F-]{32,40}$", value or ""))


def _totp_matches(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    return totp(secret) == code or totp(secret) == code.zfill(6)


def _env_value(key: str, fallback: str) -> str:
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(errors="ignore").splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return fallback


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def _page(title: str, body: str) -> str:
    padding = "ApexMail fixture page content. " * 30
    return f"<!doctype html><html><head><title>{title}</title>" \
           f'<script nonce="{uuid.uuid4().hex}">window.__fixture=true;</script></head>' \
           f"<body><h1>{_esc(title)}</h1><p>{body}</p><p>{padding}</p></body></html>"


def build_handler(cfg, ledger, *, tracking: bool):
    state = get_state()

    class Bound(FixtureHandler):
        pass

    Bound.cfg = cfg
    Bound.ledger = ledger
    Bound.tracking = tracking
    Bound.state = state
    Bound._index = None
    return Bound
