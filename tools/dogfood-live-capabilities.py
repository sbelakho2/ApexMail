#!/usr/bin/env python3
"""Live dogfood harness for the 11 advertised capabilities (brief-live-capabilities.md).

Every probe executes a REAL request against the running compose stack
(api-server :8080, enterprise :3002, tracking :3001, Mailpit :8025) and
verifies the effect in Postgres / Mailpit. Refusal arms (RBAC, cross-tenant,
hostile, concurrent) are first-class probes: they fail when the stack answers
with a 500, a silent success, another tenant's data, or a leak.

usage: tools/dogfood-live-capabilities.py [--only p1,p2] [--run-id xyz]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as hmac_mod
import json
import os
import re
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

API = "http://127.0.0.1:8080"
ENTERPRISE = os.environ.get("DOGFOOD_ENTERPRISE_BASE", "http://127.0.0.1:3002")
TRACKING = os.environ.get("DOGFOOD_TRACKING_BASE", "http://127.0.0.1:3001")
MAILPIT = "http://127.0.0.1:8025"
PG = "postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321@127.0.0.1:5432/apexmail"
API_KEY_HASH_SECRET = "dev-api-key-hash-secret"
TRACKING_SECRET = "dev-tracking-secret-key-minimum-32-chars-long"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RESULTS: list[dict] = []


# ── ordinary output helpers ────────────────────────────────────────────
def section(name: str) -> None:
    print(f"\n===== {name} =====", flush=True)


def cmd(text: str) -> None:
    print(f"CMD  {text}", flush=True)


def obs(text: str) -> None:
    print(f"OBS  {text}", flush=True)


def verdict(probe: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"probe": probe, "ok": ok, "detail": detail})
    print(f"VERDICT {'PASS' if ok else 'FAIL'}  {probe}  {detail}", flush=True)


def note(text: str) -> None:
    print(f"NOTE {text}", flush=True)


# ── HTTP ───────────────────────────────────────────────────────────────
def http(
    method: str,
    url: str,
    body: object | None = None,
    headers: dict | None = None,
    raw: bytes | None = None,
    timeout: float = 60.0,
    retries: int = 12,
) -> tuple[int, object, dict]:
    data = raw
    hdrs = {"Accept": "application/json", **(headers or {})}
    if body is not None and raw is None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    for attempt in range(retries + 1):
        if attempt == 0:
            time.sleep(0.9)  # stay under the adaptive per-IP DDOS limiter (5-min baseline window)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
                text = resp.read().decode(errors="replace")
                return resp.status, _maybe_json(text), dict(resp.headers)
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            parsed = _maybe_json(text)
            # the adaptive per-IP DDOS limiter is real: honour Retry-After
            if e.code == 429 and attempt < retries and isinstance(parsed, dict) \
                    and err_code(parsed) == "DDOS_RATE_LIMITED":
                retry_after = float(e.headers.get("Retry-After") or 5)
                wait = min(60.0, max(5.0, retry_after) * (attempt + 1))
                print(f"     (429 DDOS_RATE_LIMITED — sleeping {wait:.0f}s, attempt {attempt + 1}/{retries})", flush=True)
                time.sleep(wait)
                continue
            return e.code, parsed, dict(e.headers)
        except Exception as e:  # transport — report as status 0
            return 0, {"transport": str(e)}, {}
    return 0, {"transport": "retries exhausted"}, {}


def _maybe_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return text


def api(method: str, path: str, key: str, body=None, headers=None, raw=None, timeout=60.0):
    hdrs = {"X-API-Key": key, **(headers or {})}
    return http(method, f"{API}{path}", body=body, headers=hdrs, raw=raw, timeout=timeout)


def ent(method: str, path: str, token: str, body=None, headers=None):
    hdrs = {"Authorization": f"Bearer {token}", **(headers or {})}
    return http(method, f"{ENTERPRISE}{path}", body=body, headers=hdrs)


def err_msg(payload, default="") -> str:
    if isinstance(payload, dict):
        e = payload.get("error")
        if isinstance(e, dict):
            return str(e.get("message") or e.get("code") or default)
        if isinstance(e, str):
            return e
        if "message" in payload:
            return str(payload["message"])
    return default


def unwrap_id(payload) -> str | None:
    """Message id from either a bare body or the {data:{...}} envelope."""
    if isinstance(payload, dict):
        if isinstance(payload.get("data"), dict):
            return payload["data"].get("id")
        if "id" in payload:
            return payload.get("id")
    return None


def err_code(payload) -> str:
    if isinstance(payload, dict):
        e = payload.get("error")
        if isinstance(e, dict):
            return str(e.get("code") or "")
    return ""


# ── Postgres ───────────────────────────────────────────────────────────
def sql(query: str, tuples_only: bool = True) -> str:
    """Run SQL through psql; returns stdout stripped."""
    args = ["psql", PG, "-X", "-q", "-v", "ON_ERROR_STOP=1"]
    if tuples_only:
        args += ["-A", "-t"]
    args += ["-c", query]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed: {proc.stderr.strip()}\nSQL: {query[:400]}")
    return proc.stdout.strip()


def sql1(query: str, default: str = "") -> str:
    out = sql(query)
    return out.splitlines()[0].strip() if out else default


def q(value) -> str:
    """SQL literal for a Python value."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


# ── provisioning ───────────────────────────────────────────────────────
def gen_id(n: int = 26) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


def api_key_hash(raw: str) -> str:
    return hmac_mod.new(API_KEY_HASH_SECRET.encode(), raw.encode(), hashlib.sha256).hexdigest()


def load_jwt_key():
    env = open(os.path.join(ROOT, ".env"), encoding="utf-8").read()
    m = re.search(r'JWT_PRIVATE_KEY_PEM="(-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----)\s*"', env, re.S)
    if not m:
        raise SystemExit("JWT private key not found in .env")
    return m.group(1)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_jwt(tenant_id: str, user_id: str, scopes=None, admin: bool = False, ttl: int = 3600) -> str:
    """RS256 session JWT identical in shape to the api-server/enterprise minter."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {
        "sub": user_id,
        "tenant_id": tenant_id,
        "scopes": scopes if scopes is not None else ["*"],
        "exp": now + ttl,
        "iat": now,
        "jti": str(uuid.uuid4()),
        "typ": "session",
    }
    if admin:
        payload["admin"] = True
    signing_input = f"{b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    key = serialization.load_pem_private_key(load_jwt_key().encode(), password=None)
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(sig)}"


def provision_tenant(name: str, plan: str) -> dict:
    """Create tenant + owner user + wildcard API key + verified sender domain."""
    tid = gen_id()
    uid = str(uuid.uuid4())
    email = f"{name.replace(' ', '-').lower()}-{tid[:8]}@dogfood.test"
    raw_key = f"am_live_{secrets.token_hex(24)}"
    domain = f"{name.replace(' ', '-').lower()}-{tid[:8]}.dogfood.test"
    slug = f"{name.lower().replace(' ', '-')}-{tid[:8]}"
    sql(
        "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) VALUES "
        f"({q(tid)}, {q(name)}, {q(slug)}, {q(plan)}, 'active', NOW(), NOW())"
    )
    sql(
        "INSERT INTO users (id, tenant_id, email, password_hash, role, status, email_verified, created_at, updated_at) VALUES "
        f"({q(uid)}, {q(tid)}, {q(email)}, 'x', 'owner', 'active', TRUE, NOW(), NOW())"
    )
    sql(
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at, updated_at) VALUES "
        f"(gen_random_uuid(), {q(tid)}, 'dogfood-cap', {q(api_key_hash(raw_key))}, {q(raw_key[:12])}, '[\"*\"]'::jsonb, NOW(), NOW())"
    )
    sql(
        "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified, "
        "dkim_selector, dkim_public_key, dkim_private_key, created_at, updated_at) VALUES "
        f"(gen_random_uuid(), {q(tid)}, {q(domain)}, 'verified', TRUE, TRUE, TRUE, "
        "'test-selector', 'test-public-key', 'dkim:v1:test', NOW(), NOW())"
    )
    return {
        "id": tid, "user_id": uid, "email": email, "key": raw_key,
        "domain": domain, "jwt": mint_jwt(tid, uid),
    }


def mint_key(tenant_id: str, name: str, scopes: list[str]) -> str:
    raw = f"am_live_{secrets.token_hex(24)}"
    scopes_json = json.dumps(scopes)
    sql(
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at, updated_at) VALUES "
        f"(gen_random_uuid(), {q(tenant_id)}, {q(name)}, {q(api_key_hash(raw))}, {q(raw[:12])}, {q(scopes_json)}::jsonb, NOW(), NOW())"
    )
    return raw


def ensure_contact(tenant_id: str, email: str, name: str | None = None) -> str:
    cid = str(uuid.uuid4())
    sql(
        "INSERT INTO contacts (id, tenant_id, email, status, unsubscribe_token, name, tags, created_at, updated_at) VALUES "
        f"({q(cid)}, {q(tenant_id)}, {q(email)}, 'subscribed', {q(secrets.token_hex(16))}, {q(name or email.split('@')[0])}, '[]'::jsonb, NOW(), NOW())"
    )
    return cid


def grant_consent(tenant_id: str, *emails: str) -> str | None:
    """Active marketing consent for each recipient (the send admission gate)."""
    last = None
    for email in emails:
        cid = ensure_contact(tenant_id, email)
        last = cid
        sql(
            "INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source, metadata) "
            f"VALUES (gen_random_uuid(), {q(tenant_id)}, {q(cid)}, {q(email)}, 'marketing', TRUE, NOW(), 'dogfood', '{{}}'::jsonb)"
        )
    return last


# ── Mailpit ────────────────────────────────────────────────────────────
def mailpit_messages(recipient: str | None = None, subject_contains: str | None = None, limit: int = 100):
    status, listing, _ = http("GET", f"{MAILPIT}/api/v1/messages?limit={limit}")
    if status != 200 or not isinstance(listing, dict):
        return []
    out = []
    for m in listing.get("messages", []):
        to = [t.get("Address", "") for t in (m.get("To") or [])]
        if recipient and recipient not in to:
            continue
        if subject_contains and subject_contains.lower() not in (m.get("Subject") or "").lower():
            continue
        out.append(m)
    return out


def mailpit_message(mid: str) -> dict:
    status, body, _ = http("GET", f"{MAILPIT}/api/v1/message/{mid}")
    return body if status == 200 and isinstance(body, dict) else {}


def wait_for_mail(recipient: str, subject_contains: str, tries: int = 40) -> dict | None:
    for _ in range(tries):
        found = mailpit_messages(recipient, subject_contains)
        if found:
            return mailpit_message(found[0]["ID"])
        time.sleep(1)
    return None


# ── tracking token codec (mirror of worker encode_tracking_id) ────────
def derive_enc_key() -> bytes:
    return hmac_mod.new(TRACKING_SECRET.encode(), b"encryption", hashlib.sha256).digest()[:16]


def encode_pixel_token(tenant_id: str, message_id: str, recipient_hash: str = "x") -> str:
    """v2 open-pixel token: base64url_nopad(IV||tag||ciphertext)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def u16(v: int) -> bytes:
        return struct.pack(">H", v)

    plain = bytes([2])
    for field in (tenant_id, message_id, recipient_hash, ""):
        b = field.encode()
        plain += u16(len(b)) + b
    iv = os.urandom(12)
    ct_and_tag = AESGCM(derive_enc_key()).encrypt(iv, plain, None)  # ct || tag(16)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return b64url(iv + tag + ct)


def encode_click_token(tenant_id: str, message_id: str, recipient_hash: str, original_url: str) -> str:
    """v3 click token with originalUrl baked in."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def u16(v: int) -> bytes:
        return struct.pack(">H", v)

    plain = bytes([3])
    for field in (tenant_id, message_id, recipient_hash, ""):
        b = field.encode()
        plain += u16(len(b)) + b
    ub = original_url.encode()
    plain += u16(len(ub)) + ub
    iv = os.urandom(12)
    ct_and_tag = AESGCM(derive_enc_key()).encrypt(iv, plain, None)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    return b64url(iv + tag + ct)


def record_open(message_id: str, tenant_id: str, host: str | None = None):
    """Hit the real pixel endpoint for a message; returns (status, headers)."""
    token = encode_pixel_token(tenant_id, message_id)
    headers = {"Host": host} if host else {}
    return http("GET", f"{TRACKING}/o/{token}", headers=headers)


# ── capability probes ─────────────────────────────────────────────────
def probe_p1(run: str) -> None:
    section("P1 template-based sending")
    ten = provision_tenant(f"CapTpl {run}", "growth")
    key = ten["key"]
    grant_consent(ten["id"], f"p1-{run}@dogfood.test", f"p1-missing-{run}@dogfood.test",
                  f"p1-unknown-{run}@dogfood.test", f"p1-xtenant-{run}@dogfood.test",
                  f"p1-batch1-{run}@dogfood.test", f"p1-batch2-{run}@dogfood.test",
                  f"p1-batch3-{run}@dogfood.test", f"p1-batch4-{run}@dogfood.test",
                  f"p1-idem-{run}@dogfood.test", f"p1-idem-conc-{run}@dogfood.test")

    # 1.1 create template with variables (console/API surface = API here)
    cmd("POST /v1/templates {name, subject:'Hi {{first_name}}', html_body with {{code}}}")
    st, body, _ = api("POST", "/v1/templates", key, {
        "name": f"dogfood-tpl-{run}",
        "subject": "Hi {{first_name}}!",
        "html_body": "<p>Hello {{first_name}}, your code is <b>{{code}}</b>.</p>",
        "text_body": "Hello {{first_name}}, your code is {{code}}.",
    })
    obs(f"{st} {json.dumps(body)[:300]}")
    tpl = body.get("id") if isinstance(body, dict) else None
    verdict("P1.1 template created", st == 201 and tpl, f"id={tpl}")

    # 1.2 send with template_id + template_data → rendered mail in Mailpit
    rcpt = f"p1-{run}@dogfood.test"
    cmd(f"POST /v1/messages template_id={tpl} template_data={{first_name:'Ada',code:'X1'}} to={rcpt}")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [rcpt],
        "template_id": tpl,
        "template_data": {"first_name": "Ada", "code": "X1"},
    })
    obs(f"{st} {json.dumps(body)[:400]}")
    msg = unwrap_id(body)
    verdict("P1.2 template send accepted", st in (200, 201, 202) and msg, f"message_id={msg}")
    if msg:
        row = sql1(f"SELECT status FROM messages WHERE id={q(msg)}::uuid AND tenant_id={q(ten['id'])}")
        queued = sql1(f"SELECT COUNT(*) FROM email_queue WHERE message_id={q(msg)}::uuid AND tenant_id={q(ten['id'])}")
        obs(f"DB messages.status={row!r} email_queue rows={queued}")
        verdict("P1.2 message+queue rows persisted for the tenant", bool(row) and queued == "1",
                f"messages.status={row!r} queue_rows={queued}")

    mail = wait_for_mail(rcpt, "Hi Ada!")
    if mail is None:
        verdict("P1.2 rendered mail in Mailpit", False, "no mail within 40s")
    else:
        html = mail.get("HTML") or ""
        txt = mail.get("Text") or ""
        ok = "Ada" in html and "X1" in html and "code is" in html and (mail.get("Subject") == "Hi Ada!")
        verdict("P1.2 rendered mail in Mailpit", ok,
               f"subject={mail.get('Subject')!r} html_has_Ada/X1={('Ada' in html, 'X1' in html)} text_len={len(txt)}")

    # 1.3 missing variable → 422 naming it, nothing queued
    rcpt2 = f"p1-missing-{run}@dogfood.test"
    before_msgs = int(sql1(f"SELECT COUNT(*) FROM messages WHERE tenant_id={q(ten['id'])}"))
    before_queue = int(sql1(f"SELECT COUNT(*) FROM email_queue WHERE tenant_id={q(ten['id'])}"))
    cmd("POST /v1/messages template_data missing 'code'")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [rcpt2],
        "template_id": tpl,
        "template_data": {"first_name": "Grace"},
    })
    obs(f"{st} {json.dumps(body)[:400]}")
    named = isinstance(body, dict) and "code" in json.dumps(body)
    after_msgs = int(sql1(f"SELECT COUNT(*) FROM messages WHERE tenant_id={q(ten['id'])}"))
    after_queue = int(sql1(f"SELECT COUNT(*) FROM email_queue WHERE tenant_id={q(ten['id'])}"))
    verdict("P1.3 missing variable 422 naming it + nothing queued",
            st == 422 and named and after_msgs == before_msgs and after_queue == before_queue,
            f"status={st} names_code={named} messages {before_msgs}->{after_msgs} queue {before_queue}->{after_queue}")

    # 1.4 unknown template → 404
    cmd("POST /v1/messages template_id='tpl_does_not_exist'")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [f"p1-unknown-{run}@dogfood.test"],
        "template_id": "tpl_does_not_exist_123456",
        "template_data": {"first_name": "X", "code": "Y"},
    })
    obs(f"{st} {json.dumps(body)[:300]}")
    verdict("P1.4 unknown template -> 404", st == 404, f"status={st}")

    # 1.5 cross-tenant template -> 404
    other = provision_tenant(f"CapTplForeign {run}", "growth")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [f"p1-xtenant-{run}@dogfood.test"],
        "template_id": "tpl_foreign_placeholder",
        "template_data": {},
    })
    # create a foreign template then try to use it from the first tenant
    st_f, foreign_tpl_body, _ = api("POST", "/v1/templates", other["key"], {
        "name": f"foreign-{run}", "subject": "F", "html_body": "<p>F</p>",
    })
    foreign_tpl = foreign_tpl_body.get("id")
    cmd(f"POST /v1/messages template_id={foreign_tpl} (owned by tenant B) from tenant A")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [f"p1-xtenant-{run}@dogfood.test"],
        "template_id": foreign_tpl,
        "template_data": {},
    })
    obs(f"{st} {json.dumps(body)[:300]}")
    verdict("P1.5 cross-tenant template -> 404", st == 404, f"status={st} foreign_tpl={foreign_tpl}")

    # 1.6 batch partial semantics
    cmd("POST /v1/messages/batch: [valid, template-missing-var, unknown-template, valid]")
    st, body, _ = api("POST", "/v1/messages/batch", key, {
        "messages": [
            {"from": f"dogfood@{ten['domain']}", "to": [f"p1-batch1-{run}@dogfood.test"],
             "template_id": tpl, "template_data": {"first_name": "One", "code": "1"}},
            {"from": f"dogfood@{ten['domain']}", "to": [f"p1-batch2-{run}@dogfood.test"],
             "template_id": tpl, "template_data": {"first_name": "Two"}},
            {"from": f"dogfood@{ten['domain']}", "to": [f"p1-batch3-{run}@dogfood.test"],
             "template_id": "tpl_nope_0000000000000000", "template_data": {}},
            {"from": f"dogfood@{ten['domain']}", "to": [f"p1-batch4-{run}@dogfood.test"],
             "template_id": tpl, "template_data": {"first_name": "Four", "code": "4"}},
        ]
    })
    obs(f"{st} {json.dumps(body)[:600]}")
    envelope = body.get("data") if isinstance(body, dict) and isinstance(body.get("data"), dict) else body
    results = envelope.get("results") if isinstance(envelope, dict) else None
    ok = isinstance(results, list) and len(results) == 4 and \
        results[0].get("status") in ("queued", "accepted", "sent") and \
        results[1].get("status") == "rejected" and results[2].get("status") == "rejected" and \
        results[3].get("status") in ("queued", "accepted", "sent")
    verdict("P1.6 batch partial semantics (2 ok, 2 refused with reasons)",
            bool(ok), f"results={json.dumps(results)[:500] if results else body}")
    if results:
        # refused entries name the reason
        r1 = json.dumps(results[1])
        r2 = json.dumps(results[2])
        verdict("P1.6 refused rows name the variable / template",
                "code" in r1 and ("not found" in r2.lower() or "template" in r2.lower()),
                f"row2={r1[:200]} row3={r2[:200]}")

    # 1.7 idempotency replay returns the same message
    ikey = f"idem-{run}-{uuid.uuid4().hex[:8]}"
    body_req = {
        "from": f"dogfood@{ten['domain']}",
        "to": [f"p1-idem-{run}@dogfood.test"],
        "template_id": tpl,
        "template_data": {"first_name": "Idem", "code": "9"},
    }
    cmd(f"POST /v1/messages twice with Idempotency-Key: {ikey}")
    st1, b1, _ = api("POST", "/v1/messages", key, body_req, headers={"Idempotency-Key": ikey})
    st2, b2, _ = api("POST", "/v1/messages", key, body_req, headers={"Idempotency-Key": ikey})
    obs(f"first={st1} {json.dumps(b1)[:200]}")
    obs(f"replay={st2} {json.dumps(b2)[:200]}")
    id1 = unwrap_id(b1)
    id2 = unwrap_id(b2)
    same = bool(id1) and id1 == id2
    count = int(sql1(
        f"SELECT COUNT(*) FROM messages WHERE tenant_id={q(ten['id'])} "
        f"AND idempotency_key={q(ikey)}"))
    verdict("P1.7 idempotency replay returns the same message (one row)",
            same and count == 1, f"ids {id1}=={id2} rows={count}")

    # concurrency arm: two parallel first-submits with the same key → one effect
    ikey2 = f"idem-conc-{run}-{uuid.uuid4().hex[:8]}"
    body_req2 = dict(body_req, to=[f"p1-idem-conc-{run}@dogfood.test"])
    import threading
    out = {}

    def _fire(n):
        s, b, _ = api("POST", "/v1/messages", key, body_req2, headers={"Idempotency-Key": ikey2})
        out[n] = (s, b)

    t1, t2 = threading.Thread(target=_fire, args=(1,)), threading.Thread(target=_fire, args=(2,))
    t1.start(); t2.start(); t1.join(); t2.join()
    ids = {out[i][0]: (out[i][1].get("id") if isinstance(out[i][1], dict) else None) for i in out}
    rows = int(sql1(f"SELECT COUNT(*) FROM messages WHERE tenant_id={q(ten['id'])} AND idempotency_key={q(ikey2)}"))
    obs(f"concurrent statuses={[out[i][0] for i in out]} ids={[unwrap_id(out[i][1]) for i in out]}")
    # One effect: exactly one row; the loser is refused (409 in-flight or the
    # same replayed body) — never a second message.
    ok_ids = len({v for v in ids.values() if v}) <= 1
    verdict("P1.7 concurrent identical submits -> one message row",
            rows == 1 and ok_ids, f"rows={rows} statuses={[out[i][0] for i in out]}")

    # cross-tenant probe: tenant B reading tenant A's message
    st, body, _ = api("GET", f"/v1/messages/{msg}", other["key"])
    obs(f"tenant B GET /v1/messages/{msg} -> {st} {json.dumps(body)[:200]}")
    verdict("P1.CROSS cross-tenant message read -> 404", st == 404, f"status={st}")


def probe_p2(run: str) -> None:
    section("P2 A/B experiments")
    ten = provision_tenant(f"CapAb {run}", "growth")
    key = ten["key"]
    other = provision_tenant(f"CapAbOther {run}", "growth")
    free = provision_tenant(f"CapAbFree {run}", "free")

    arms = []
    for i, subj in enumerate([f"Arm A {run}", f"Arm B {run}"]):
        st, body, _ = api("POST", "/v1/templates", key, {
            "name": f"ab-arm-{i}-{run}", "subject": subj,
            "html_body": f"<p>Hello {{{{first_name}}}}, arm {i}.</p>",
        })
        arms.append(body["id"])
    obs(f"arm templates: {arms}")

    n_contacts = 200
    lid = str(uuid.uuid4())
    sql("INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, status, created_at, updated_at) VALUES "
        f"({q(lid)}, {q(ten['id'])}, {q('ab-audience-'+run)}, 'dogfood', 'single', 'active', NOW(), NOW())")
    contact_rows, sub_rows, consent_rows = [], [], []
    for i in range(n_contacts):
        cid = str(uuid.uuid4())
        email = f"p2-{run}-{i}@dogfood.test"
        contact_rows.append(f"({q(cid)},{q(ten['id'])},{q(email)},'subscribed',{q(secrets.token_hex(12))},'[]'::jsonb,NOW(),NOW())")
        sub_rows.append(f"(gen_random_uuid(),{q(lid)},{q(cid)},'active',NOW())")
        consent_rows.append(f"(gen_random_uuid(),{q(ten['id'])},{q(cid)},{q(email)},'marketing',TRUE,NOW(),'dogfood','{{}}'::jsonb)")
    sql("INSERT INTO contacts (id, tenant_id, email, status, unsubscribe_token, tags, created_at, updated_at) VALUES " + ",".join(contact_rows))
    sql("INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) VALUES " + ",".join(sub_rows))
    sql("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source, metadata) VALUES " + ",".join(consent_rows))

    cmd(f"POST /v1/campaigns (abTest 2 arms, testPercentage 0.5, waitMinutes 5, list {lid}, {n_contacts} contacts)")
    st, body, _ = api("POST", "/v1/campaigns", key, {
        "name": f"ab-{run}", "subject": f"AB {run}",
        "from": f"dogfood@{ten['domain']}",
        "list_ids": [lid],
        "ab_test": {
            "arms": [{"templateId": arms[0], "subject": f"Arm A {run}"},
                     {"templateId": arms[1], "subject": f"Arm B {run}"}],
            "testPercentage": 0.5,
            "metric": "open",
            "waitMinutes": 5,
        },
    })
    obs(f"{st} {json.dumps(body)[:300]}")
    cid = unwrap_id(body)
    verdict("P2.1 experiment campaign created", st in (200, 201) and cid, f"campaign={cid}")

    cmd(f"POST /v1/campaigns/{cid}/send")
    st, body, _ = api("POST", f"/v1/campaigns/{cid}/send", key, {})
    obs(f"{st} {json.dumps(body)[:300]}")
    verdict("P2.2 send accepted", st in (200, 201), f"status={st}")

    split = sql(f"SELECT contact_id, email, phase, arm_index, ab_bucket FROM campaign_recipients WHERE campaign_id={q(cid)}::uuid ORDER BY email")
    rows = [line.split("|") for line in split.splitlines()]
    all_phased = rows and all(r[2] in ("test", "holdout") and r[4] for r in rows)
    n_test = sum(1 for r in rows if r[2] == "test")
    n_hold = sum(1 for r in rows if r[2] == "holdout")
    verdict("P2.3 every recipient phased with a persisted bucket",
            bool(all_phased) and n_test + n_hold == n_contacts,
            f"test={n_test} holdout={n_hold} total={len(rows)}")

    mismatches = 0
    for r in rows:
        contact_id, phase, arm, bucket = r[0], r[2], r[3], int(r[4])
        expect_bucket = int(hashlib.md5(f"{cid}:{contact_id}".encode()).hexdigest()[:8], 16)
        expect_phase = "test" if expect_bucket % 10000 < 5000 else "holdout"
        expect_arm = str((expect_bucket // 10000) % 2) if expect_phase == "test" else ""
        if bucket != expect_bucket or phase != expect_phase or arm != expect_arm:
            mismatches += 1
    pct = 100.0 * n_test / max(1, len(rows))
    verdict("P2.4 buckets match the md5(campaign:contact) formula exactly",
            mismatches == 0, f"mismatches={mismatches} test_pct={pct:.1f}%")
    verdict("P2.5 both arms populated", len({r[3] for r in rows if r[2] == "test"}) == 2,
            f"arms={sorted({r[3] for r in rows if r[2] == 'test'})}")

    holdout_queued = int(sql1(
        f"SELECT COUNT(*) FROM email_queue q JOIN campaign_recipients cr ON cr.message_id = q.message_id "
        f"WHERE cr.campaign_id={q(cid)}::uuid AND cr.phase='holdout'"))
    holdout_messages = int(sql1(
        f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(cid)}::uuid AND phase='holdout' AND message_id IS NOT NULL"))
    verdict("P2.6 holdout receives nothing at split",
            holdout_queued == 0 and holdout_messages == 0,
            f"holdout queue rows={holdout_queued} holdout message refs={holdout_messages}")

    cmd("wait for the worker to drain the test sample")
    drained = False
    for _ in range(90):
        inflight = int(sql1(
            f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(cid)}::uuid "
            f"AND phase='test' AND status IN ('queued','sending')"))
        if inflight == 0:
            drained = True
            break
        time.sleep(2)
    sent = int(sql1(f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(cid)}::uuid AND phase='test' AND status='sent'"))
    obs(f"test drained={drained} sent={sent}")
    verdict("P2.7 real worker sent the test sample", drained and sent >= 60, f"sent={sent}")

    st, body, _ = api("GET", f"/v1/campaigns/{cid}/experiment", key)
    obs(f"GET experiment -> {st} {json.dumps(body)[:500]}")
    exp = body.get("data", body) if isinstance(body, dict) else {}
    arms_out = exp.get("arms") or []
    trials = sum(a.get("trials", 0) for a in arms_out)
    verdict("P2.8 GET experiment returns per-arm results",
            st == 200 and len(arms_out) == 2 and trials >= 60,
            f"arms={json.dumps(arms_out)[:300]}")

    # ── small campaign: below MIN_ARM_TRIALS
    small_lid = str(uuid.uuid4())
    sql("INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, status, created_at, updated_at) VALUES "
        f"({q(small_lid)}, {q(ten['id'])}, {q('ab-small-'+run)}, 'dogfood', 'single', 'active', NOW(), NOW())")
    srows_c, srows_s, srows_k = [], [], []
    for i in range(40):
        cidc = str(uuid.uuid4())
        email = f"p2small-{run}-{i}@dogfood.test"
        srows_c.append(f"({q(cidc)},{q(ten['id'])},{q(email)},'subscribed',{q(secrets.token_hex(12))},'[]'::jsonb,NOW(),NOW())")
        srows_s.append(f"(gen_random_uuid(),{q(small_lid)},{q(cidc)},'active',NOW())")
        srows_k.append(f"(gen_random_uuid(),{q(ten['id'])},{q(cidc)},{q(email)},'marketing',TRUE,NOW(),'dogfood','{{}}'::jsonb)")
    sql("INSERT INTO contacts (id, tenant_id, email, status, unsubscribe_token, tags, created_at, updated_at) VALUES " + ",".join(srows_c))
    sql("INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) VALUES " + ",".join(srows_s))
    sql("INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source, metadata) VALUES " + ",".join(srows_k))

    st, sbody, _ = api("POST", "/v1/campaigns", key, {
        "name": f"ab-small-{run}", "subject": f"AB small {run}",
        "from": f"dogfood@{ten['domain']}",
        "list_ids": [small_lid],
        "ab_test": {"arms": [{"templateId": arms[0]}, {"templateId": arms[1]}],
                    "testPercentage": 0.5, "metric": "open", "waitMinutes": 5},
    })
    small_cid = unwrap_id(sbody)
    st, sbody, _ = api("POST", f"/v1/campaigns/{small_cid}/send", key, {})
    obs(f"small campaign {small_cid} send -> {st}")
    for _ in range(90):
        inflight = int(sql1(f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(small_cid)}::uuid AND phase='test' AND status IN ('queued','sending')"))
        if inflight == 0:
            break
        time.sleep(2)
    small_sent = int(sql1(f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(small_cid)}::uuid AND phase='test' AND status='sent'"))
    obs(f"small test sent={small_sent} (MIN_ARM_TRIALS is 30/arm)")

    # ── force opens through the real tracking pixel on the big campaign
    test_msgs = sql(
        f"SELECT cr.arm_index, cr.message_id::text FROM campaign_recipients cr "
        f"WHERE cr.campaign_id={q(cid)}::uuid AND cr.phase='test' AND cr.status='sent' AND cr.message_id IS NOT NULL ORDER BY cr.email")
    per_arm = {0: [], 1: []}
    for line in test_msgs.splitlines():
        arm, mid = line.split("|")
        per_arm[int(arm)].append(mid)
    target = {0: 0.8, 1: 0.2}
    forced = 0
    for arm, mids in per_arm.items():
        want = int(len(mids) * target[arm])
        for idx, mid in enumerate(mids[:want]):
            stp, _, _ = record_open(mid, ten["id"])
            if stp == 200:
                forced += 1
            if idx % 20 == 19:
                time.sleep(1.5)
    obs(f"pixel opens requested={forced} (arm0 target 80%, arm1 20%)")
    for _ in range(60):
        opens = int(sql1(f"SELECT COUNT(DISTINCT message_id) FROM events WHERE campaign_id={q(cid)} AND event_type='opened'"))
        if opens >= forced * 0.9:
            break
        time.sleep(2)
    opens_db = int(sql1(f"SELECT COUNT(DISTINCT message_id) FROM events WHERE campaign_id={q(cid)} AND event_type='opened'"))
    verdict("P2.9 opens from the real pixel landed in events",
            forced > 0 and opens_db >= forced * 0.9, f"forced={forced} distinct_open_events={opens_db}")

    cmd("wait for the 5-minute test windows of BOTH campaigns to elapse")
    for _ in range(80):
        elapsed_pair = sql1(
            f"SELECT EXTRACT(EPOCH FROM (NOW() - (SELECT MIN(updated_at) FROM campaign_ab_arms WHERE campaign_id={q(cid)}::uuid)))::int "
            f"|| '|' || EXTRACT(EPOCH FROM (NOW() - (SELECT MIN(updated_at) FROM campaign_ab_arms WHERE campaign_id={q(small_cid)}::uuid)))::int")
        try:
            e1, e2 = (int(x) for x in elapsed_pair.split("|"))
        except Exception:
            e1 = e2 = 0
        if e1 >= 310 and e2 >= 310:
            break
        time.sleep(10)

    st, body, _ = api("GET", f"/v1/campaigns/{cid}/experiment", key)
    exp = body.get("data", body) if isinstance(body, dict) else {}
    obs(f"big experiment decision={json.dumps(exp.get('decision'))[:400]}")
    big_state = (exp.get("decision") or {}).get("state")
    verdict("P2.10 big experiment decides a winner from forced outcomes",
            st == 200 and big_state == "winner" and (exp.get("decision") or {}).get("winner_arm") is not None,
            f"state={big_state}")

    st, sbody, _ = api("GET", f"/v1/campaigns/{small_cid}/experiment", key)
    sexp = sbody.get("data", sbody) if isinstance(sbody, dict) else {}
    sdec = sexp.get("decision") or {}
    obs(f"small experiment decision={json.dumps(sdec)[:400]}")
    reason = sdec.get("reason", "")
    verdict("P2.11 below MIN_ARM_TRIALS the decision refuses with the documented reason",
            st == 200 and sdec.get("state") == "insufficient_sample" and "30" in reason,
            f"state={sdec.get('state')} reason={reason[:160]!r}")

    cmd(f"POST /v1/campaigns/{small_cid}/experiment/winner {{armIndex:1}}")
    st, wbody, _ = api("POST", f"/v1/campaigns/{small_cid}/experiment/winner", key,
                       {"armIndex": 1, "reason": f"dogfood declaration {run}"})
    obs(f"{st} {json.dumps(wbody)[:400]}")
    promoted = int(sql1(f"SELECT COUNT(*) FROM campaign_recipients WHERE campaign_id={q(small_cid)}::uuid AND phase='winner' AND arm_index=1"))
    ab_cfg = sql1(f"SELECT ab_config::text FROM campaigns WHERE id={q(small_cid)}::uuid")
    audit = int(sql1(f"SELECT COUNT(*) FROM audit_logs WHERE tenant_id={q(ten['id'])} AND action='campaign.experiment.winner_declared' AND resource_id={q(small_cid)}"))
    verdict("P2.12 manual declaration promotes the holdout + audits",
            st == 200 and promoted > 0 and '"winnerSource": "manual"' in ab_cfg and audit >= 1,
            f"promoted_rows={promoted} audit_rows={audit} ab_config={ab_cfg[:200]}")

    st, wbody, _ = api("POST", f"/v1/campaigns/{small_cid}/experiment/winner", key, {"armIndex": 7})
    obs(f"armIndex 7 -> {st} {json.dumps(wbody)[:200]}")
    verdict("P2.13 out-of-range arm refused (named 400)", st in (400, 422) and "armIndex" in json.dumps(wbody),
            f"status={st}")

    st, fbody, _ = api("GET", f"/v1/campaigns/{cid}/experiment", free["key"])
    msg_txt = err_msg(fbody)
    obs(f"free tenant GET experiment -> {st} {json.dumps(fbody)[:250]}")
    verdict("P2.14 non-entitled tenant -> 403 naming ab_testing",
            st == 403 and ("ab_testing" in msg_txt.lower() or "plan" in msg_txt.lower()), f"status={st} msg={msg_txt[:160]!r}")

    st, obody, _ = api("GET", f"/v1/campaigns/{cid}/experiment", other["key"])
    obs(f"cross-tenant GET -> {st} {json.dumps(obody)[:200]}")
    verdict("P2.15 cross-tenant campaign -> 404", st == 404, f"status={st}")

    st, obody, _ = api("POST", f"/v1/campaigns/{cid}/experiment/winner", other["key"], {"armIndex": 0})
    obs(f"cross-tenant declare -> {st} {json.dumps(obody)[:200]}")
    verdict("P2.15 cross-tenant declare -> 404", st == 404, f"status={st}")

    import threading
    outs = {}

    def _declare(n):
        outs[n] = api("POST", f"/v1/campaigns/{cid}/experiment/winner", key,
                      {"armIndex": n, "reason": f"race {n}"})

    t1, t2 = threading.Thread(target=_declare, args=(0,)), threading.Thread(target=_declare, args=(1,))
    t1.start(); t2.start(); t1.join(); t2.join()
    winners = sql1(f"SELECT COUNT(DISTINCT arm_index) FROM campaign_recipients WHERE campaign_id={q(cid)}::uuid AND phase='winner'")
    audit_n = int(sql1(f"SELECT COUNT(*) FROM audit_logs WHERE tenant_id={q(ten['id'])} AND action='campaign.experiment.winner_declared' AND resource_id={q(cid)}"))
    obs(f"racing declares statuses={[outs[i][0] for i in outs]} distinct_winner_arms={winners} audit_rows={audit_n}")
    verdict("P2.16 concurrent declarations leave one winner arm",
            winners in ("0", "1"), f"distinct_winner_arms={winners} audit_rows={audit_n} statuses={[outs[i][0] for i in outs]}")


def probe_p3(run: str) -> None:
    section("P3 time-travel debugging")
    ten = provision_tenant(f"CapTT {run}", "growth")
    key = ten["key"]
    other = provision_tenant(f"CapTTOther {run}", "growth")
    grant_consent(ten["id"], f"p3-sent-{run}@dogfood.test", f"p3-bounce-{run}@dogfood.test")

    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}",
        "to": [f"p3-sent-{run}@dogfood.test"],
        "subject": f"P3 timeline {run}",
        "html": '<p>Hello</p><a href="https://example.com/landing">go</a>',
    })
    msg = unwrap_id(body)
    t_accept = sql1(f"SELECT to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM messages WHERE id={q(msg)}::uuid")
    obs(f"accepted {st} id={msg} created_at={t_accept}")
    verdict("P3.0a real message accepted", bool(msg), f"id={msg}")

    sent_at = ""
    for _ in range(60):
        st_row = sql1(f"SELECT status || '|' || COALESCE(to_char(sent_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),'') FROM messages WHERE id={q(msg)}::uuid")
        if st_row.startswith("sent"):
            sent_at = st_row.split("|", 1)[1]
            break
        time.sleep(1)
    obs(f"worker: messages.status={sql1(f'SELECT status FROM messages WHERE id={q(msg)}::uuid')} sent_at={sent_at}")
    verdict("P3.1 real message reached sent via the worker", bool(sent_at), f"sent_at={sent_at}")

    st, tl, _ = api("GET", f"/v1/messages/{msg}/timeline?at={urllib.parse.quote(t_accept)}", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    state_at_accept = (body_tl.get("state") or {}).get("status")
    kinds_at_accept = [e.get("kind") for e in (body_tl.get("timeline") or [])]
    obs(f"timeline at acceptance -> {st} state={json.dumps(body_tl.get('state'))[:200]} kinds={kinds_at_accept[:4]}")
    verdict("P3.2 at=created_at reconstructs the acceptance edge (accepted/queued; downstream fact wins the identical-timestamp tie-break)",
            st == 200 and state_at_accept in ("accepted", "queued") and "message.accepted" in kinds_at_accept,
            f"state={state_at_accept} entries={kinds_at_accept[:4]}")

    # a provably accepted-only message (row without any queue/event row):
    # the reconstruction must say 'accepted', not invent progress
    accepted_only = str(uuid.uuid4())
    sql("INSERT INTO messages (id, tenant_id, from_address, from_email, to_addresses, to_emails, subject, body, status, created_at, updated_at) VALUES "
        f"({q(accepted_only)}::uuid, {q(ten['id'])}, {q('dogfood@'+ten['domain'])}, {q('dogfood@'+ten['domain'])}, "
        f"ARRAY[{q('accepted-only@dogfood.test')}], '[]'::jsonb, 'accepted-only', 'x', 'queued', NOW(), NOW())")
    st, tl, _ = api("GET", f"/v1/messages/{accepted_only}/timeline?at=2030-01-01T00:00:00Z", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    st_acc = (body_tl.get("state") or {}).get("status")
    obs(f"accepted-only timeline -> {st} state={st_acc} complete={body_tl.get('history_complete')}")
    verdict("P3.2b an accepted-but-unqueued message reconstructs 'accepted'",
            st == 200 and st_acc == "accepted", f"state={st_acc}")

    st, tl, _ = api("GET", f"/v1/messages/{msg}/timeline?at={urllib.parse.quote(sent_at)}", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    state_at_sent = (body_tl.get("state") or {}).get("status")
    obs(f"timeline at sent_at -> {st} state={state_at_sent}")
    verdict("P3.3 at=sent_at reconstructs 'sent'", st == 200 and state_at_sent == "sent", f"state={state_at_sent}")

    # Provider fact: delivered. The SES/SNS webhook is unreachable over the
    # SMTP transport (SNS signature), so the fact is written with the exact
    # production SQL shape of ses_notifications::process_delivery.
    qrow = sql1(f"SELECT q.id::text || '|' || q.to_addresses[1] FROM email_queue q WHERE q.message_id={q(msg)}::uuid LIMIT 1")
    qid, rcpt = qrow.split("|")
    sql("UPDATE email_queue SET delivered_at = NOW(), updated_at = NOW() WHERE id=" + q(qid) + "::uuid")
    sql(f"UPDATE messages m SET status='delivered', delivered_at=NOW(), updated_at=NOW() "
        f"WHERE m.id={q(msg)}::uuid AND NOT EXISTS ("
        f"SELECT 1 FROM email_queue q2 WHERE q2.message_id=m.id AND q2.delivered_at IS NULL)")
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
        f"({q('dogfood-deliv-'+msg)}, {q(ten['id'])}, {q(msg)}, 'delivered', {q(rcpt)}, NOW())")
    delivered_at = sql1(f"SELECT to_char(delivered_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM email_queue WHERE id={q(qid)}::uuid")
    injected_at = sql1("SELECT to_char(NOW() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    obs(f"delivered fact injected at {delivered_at}; reconstruct-at instant {injected_at}")

    st, tl, _ = api("GET", f"/v1/messages/{msg}/timeline?at={urllib.parse.quote(sent_at)}", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    past_state = (body_tl.get("state") or {}).get("status")
    obs(f"timeline at OLD sent_at (delivered events now exist) -> {past_state}")
    verdict("P3.4 past state after later events stays 'sent'", st == 200 and past_state == "sent",
            f"state={past_state}")

    st, tl, _ = api("GET", f"/v1/messages/{msg}/timeline?at={urllib.parse.quote(injected_at)}", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    now_state = (body_tl.get("state") or {}).get("status")
    kinds = [e.get("kind") for e in (body_tl.get("timeline") or [])]
    obs(f"timeline at post-injection instant -> {now_state} entries={kinds}")
    verdict("P3.5 at=post-injection instant reconstructs 'delivered'", st == 200 and now_state == "delivered",
            f"state={now_state}")

    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}", "to": [f"p3-bounce-{run}@dogfood.test"],
        "subject": f"P3 bounce {run}", "html": "<p>bounce probe</p>",
    })
    bmsg = unwrap_id(body)
    b_sent = ""
    for _ in range(60):
        row = sql1(f"SELECT status || '|' || COALESCE(to_char(sent_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),'') FROM messages WHERE id={q(bmsg)}::uuid")
        if row.startswith("sent"):
            b_sent = row.split("|", 1)[1]
            break
        time.sleep(1)
    bq = sql1(f"SELECT id::text FROM email_queue WHERE message_id={q(bmsg)}::uuid LIMIT 1")
    sql(f"UPDATE email_queue SET status='bounced', error_message='550 5.1.1 user unknown', updated_at=NOW() WHERE id={q(bq)}::uuid")
    sql(f"UPDATE messages SET status='bounced', updated_at=NOW() WHERE id={q(bmsg)}::uuid")
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, bounce_type, diagnostic_code, timestamp) VALUES "
        f"({q('dogfood-bounce-'+bmsg)}, {q(ten['id'])}, {q(bmsg)}, 'bounced', {q(f'p3-bounce-{run}@dogfood.test')}, 'permanent', '550 5.1.1 user unknown', NOW())")
    b_bounced_at = sql1("SELECT to_char(NOW() AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')")
    time.sleep(1)
    st, tl, _ = api("GET", f"/v1/messages/{bmsg}/timeline?at={urllib.parse.quote(b_bounced_at)}", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    b_state = (body_tl.get("state") or {}).get("status")
    obs(f"bounce timeline -> {b_state} (sent_at={b_sent})")
    verdict("P3.6 bounced message reconstructs 'bounced'", st == 200 and b_state == "bounced", f"state={b_state}")

    st, tl, _ = api("GET", f"/v1/messages/{msg}/timeline?at=2000-01-01T00:00:00Z", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    pre_state = (body_tl.get("state") or {}).get("status")
    complete = body_tl.get("history_complete")
    obs(f"timeline at 2000 -> {pre_state} history_complete={complete}")
    verdict("P3.7 before acceptance -> not_yet_accepted (provable absence)",
            st == 200 and pre_state == "not_yet_accepted" and complete is True, f"state={pre_state}")

    orphan = str(uuid.uuid4())
    sql("INSERT INTO messages (id, tenant_id, from_address, from_email, to_addresses, to_emails, subject, body, status, sent_at, created_at, updated_at) VALUES "
        f"({q(orphan)}::uuid, {q(ten['id'])}, {q('dogfood@'+ten['domain'])}, {q('dogfood@'+ten['domain'])}, ARRAY[{q('ghost@dogfood.test')}], '[]'::jsonb, 'ghost', 'x', 'sent', NOW(), NOW(), NOW())")
    st, tl, _ = api("GET", f"/v1/messages/{orphan}/timeline?at=2030-01-01T00:00:00Z", key)
    body_tl = tl.get("data", tl) if isinstance(tl, dict) else {}
    inc = body_tl.get("insufficient_history")
    obs(f"orphan timeline -> {st} complete={body_tl.get('history_complete')} insufficient={json.dumps(inc)[:220]}")
    verdict("P3.8 insufficient history answers honestly (history_complete=false)",
            st == 200 and body_tl.get("history_complete") is False and isinstance(inc, dict),
            f"history_complete={body_tl.get('history_complete')}")

    st, rbody, _ = api("GET", f"/v1/messages/{msg}/timeline", key)
    obs(f"timeline without at -> {st} {json.dumps(rbody)[:200]}")
    verdict("P3.9 missing at is refused (400/422)", st in (400, 422), f"status={st}")

    st, rbody, _ = api("GET", f"/v1/messages/{msg}/timeline?at=2030-01-01T00:00:00Z", other["key"])
    obs(f"cross-tenant timeline -> {st} {json.dumps(rbody)[:200]}")
    verdict("P3.10 cross-tenant id -> 404", st == 404, f"status={st}")

    free = provision_tenant(f"CapTTFree {run}", "free")
    grant_consent(free["id"], f"p3-free-{run}@dogfood.test")
    st, fbody, _ = api("POST", "/v1/messages", free["key"], {
        "from": f"dogfood@{free['domain']}", "to": [f"p3-free-{run}@dogfood.test"],
        "subject": f"P3 free {run}", "html": "<p>free</p>"})
    free_msg = unwrap_id(fbody)
    st, rbody, _ = api("GET", f"/v1/messages/{free_msg}/timeline?at=2030-01-01T00:00:00Z", free["key"])
    msg_txt = err_msg(rbody)
    obs(f"free tenant's OWN message timeline -> {st} {json.dumps(rbody)[:220]}")
    verdict("P3.11 non-entitled tenant -> 403 naming time_travel_debugging",
            st == 403 and "time_travel" in msg_txt.lower(), f"status={st}")

    cookie = f"am_session={ten['jwt']}"
    st, html, _ = http("GET", f"{API}/messages/{msg}/timeline?at={urllib.parse.quote(injected_at)}",
                       headers={"Cookie": cookie, "Accept": "text/html"})
    html_str = html if isinstance(html, str) else json.dumps(html)
    links = re.findall(r'href="([^"]+)"', html_str)
    obs(f"console page -> {st} bytes={len(html_str)} carries_delivered={'delivered' in html_str.lower()}")
    verdict("P3.12 console timeline page renders the same reconstructed state",
            st == 200 and "delivered" in html_str.lower() and "timeline" in html_str.lower(),
            f"status={st} links={links[:6]}")

    events_link = 'href="/events"' in html_str
    verdict("P3.13 the timeline page links to the delivery-events surface",
            st == 200 and events_link, f"href /events present={events_link}")


def compose_api_server_with_hosts(extra_hosts: dict[str, str] | None) -> None:
    """Recreate the api-server container with (or without) extra_hosts.

    The customer's DNS step for the custom-tracking-domain probe is modelled
    by publishing the CNAME name in the api-server container's resolver view
    (`extra_hosts`), because /etc/hosts is read-only in a running container.
    No image is built: the container is recreated from the existing image.
    """
    override = "/tmp/dogfood-hosts-override.yml"
    if extra_hosts:
        lines = ["services:", "  api-server:", "    extra_hosts:"]
        for host, ip in extra_hosts.items():
            lines.append(f'      - "{host}:{ip}"')
        with open(override, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        files = ["-f", "docker-compose.yml", "-f", "docker-compose.override.yml", "-f", override]
    else:
        files = ["-f", "docker-compose.yml", "-f", "docker-compose.override.yml"]
    subprocess.run(["docker", "compose", *files, "up", "-d", "--no-deps", "--force-recreate", "api-server"],
                   cwd=ROOT, capture_output=True, text=True, timeout=300)
    for _ in range(90):
        st, _, _ = http("GET", f"{API}/health", retries=1)
        if st == 200:
            return
        time.sleep(2)
    raise RuntimeError("api-server did not return healthy after container recreate")


# ── P4 custom tracking domains ─────────────────────────────────────────
def probe_p4(run: str) -> None:
    section("P4 custom tracking domains")
    ten = provision_tenant(f"CapTd {run}", "growth")
    key = ten["key"]
    other = provision_tenant(f"CapTdOther {run}", "growth")
    free = provision_tenant(f"CapTdFree {run}", "free")
    # deterministic parent domains so the resolver-view publish is expressible
    ten["domain"] = f"captd-{run}-a.dogfood.test"
    other["domain"] = f"captd-{run}-b.dogfood.test"
    sql(f"UPDATE domains SET name={q(ten['domain'])} WHERE tenant_id={q(ten['id'])}")
    sql(f"UPDATE domains SET name={q(other['domain'])} WHERE tenant_id={q(other['id'])}")
    custom_host = f"track.{ten['domain']}"

    cmd(f"POST /v1/tracking-domains {{domain:'{custom_host}'}}")
    st, body, _ = api("POST", "/v1/tracking-domains", key, {"domain": custom_host})
    obs(f"{st} {json.dumps(body)[:300]}")
    td = body.get("id") if isinstance(body, dict) else None
    verdict("P4.1 tracking domain created (pending, named reason)",
            st == 201 and td and body.get("status") == "pending" and body.get("status_reason"),
            f"id={td} status={body.get('status') if isinstance(body, dict) else None}")

    cmd(f"GET /v1/tracking-domains/{td}/dns-records")
    st, recs, _ = api("GET", f"/v1/tracking-domains/{td}/dns-records", key)
    obs(f"{st} {json.dumps(recs)[:300]}")
    records = (recs or {}).get("records") or []
    cname = records[0] if records else {}
    verdict("P4.2 exact CNAME shown",
            st == 200 and cname.get("record_type") == "CNAME" and cname.get("hostname") == custom_host
            and cname.get("value", "").startswith("track."),
            f"cname={json.dumps(cname)}")

    # pending arm: no DNS yet → 503 (state unchanged), never a false failure
    cmd(f"POST /v1/tracking-domains/{td}/verify (before DNS exists)")
    st, body, _ = api("POST", f"/v1/tracking-domains/{td}/verify", key, {})
    msg = err_msg(body)
    obs(f"{st} {json.dumps(body)[:250]}")
    db_status = sql1(f"SELECT status FROM tracking_domains WHERE id={q(td)}::uuid")
    verdict("P4.3 verify before DNS -> named 503, state stays pending",
            st == 503 and "DNS" in msg and db_status == "pending", f"status={st} db={db_status}")

    # verify reached live: publish the CNAME in the api-server's resolver view
    # (the customer's DNS step) by pointing the custom host at the CNAME
    # target's real address in the container's /etc/hosts.
    target_ips = subprocess.run(["docker", "exec", "apexmail-api-server-1", "getent", "ahostsv4", cname.get("value", "track.apexmail.ee")],
                                capture_output=True, text=True).stdout.split()
    target_ip = target_ips[0] if target_ips else "95.216.226.51"
    other_host = f"track2.{other['domain']}"
    note(f"publishing {custom_host} -> {target_ip} and {other_host} -> 127.0.0.1 (resolver-view recreate, no image build)")
    compose_api_server_with_hosts({custom_host: target_ip, other_host: "127.0.0.1"})
    cmd(f"POST /v1/tracking-domains/{td}/verify (after CNAME published)")
    st, body, _ = api("POST", f"/v1/tracking-domains/{td}/verify", key, {})
    obs(f"{st} {json.dumps(body)[:300]}")
    verdict("P4.4 verify with the CNAME live -> verified",
            st == 200 and body.get("status") == "verified" and body.get("verified_at"),
            f"status={body.get('status') if isinstance(body, dict) else None}")

    # failed arm: a host that resolves but to the wrong address
    st, body2, _ = api("POST", "/v1/tracking-domains", other["key"], {"domain": other_host})
    td2 = body2.get("id") if isinstance(body2, dict) else None
    st, body2, _ = api("POST", f"/v1/tracking-domains/{td2}/verify", other["key"], {})
    reason2 = (body2 or {}).get("status_reason") or ""
    obs(f"mismatching CNAME verify -> {st} status={body2.get('status') if isinstance(body2, dict) else None} reason={reason2[:200]!r}")
    verdict("P4.5 mismatching CNAME -> failed with the named reason",
            st == 200 and body2.get("status") == "failed" and "does not include" in reason2,
            f"status={body2.get('status') if isinstance(body2, dict) else None}")

    # serving: owner token on the custom host
    msg_id = str(uuid.uuid4())
    owner_token = encode_pixel_token(ten["id"], msg_id)
    st, body, _ = http("GET", f"{TRACKING}/o/{owner_token}", headers={"Host": custom_host})
    obs(f"owner token on {custom_host} -> {st} {str(body)[:40]}")
    verdict("P4.6 tracking link serves on the custom host for the owner", st == 200,
            f"status={st}")

    # foreign token on the owner's custom host → refused by name
    foreign_token = encode_pixel_token(other["id"], str(uuid.uuid4()))
    st, body, _ = http("GET", f"{TRACKING}/o/{foreign_token}", headers={"Host": custom_host})
    text = body if isinstance(body, str) else json.dumps(body)
    obs(f"foreign token on {custom_host} -> {st} {text[:220]!r}")
    verdict("P4.7 foreign token refused on the custom host",
            st in (403, 404, 400) and ("workspace" in text.lower() or "token" in text.lower() or "denied" in text.lower()),
            f"status={st}")

    # click refusal arm on a custom host that is NOT verified
    st, body, _ = http("GET", f"{TRACKING}/o/{owner_token}", headers={"Host": f"track.unverified-{run}.dogfood.test"})
    text = body if isinstance(body, str) else json.dumps(body)
    obs(f"token on unverified host -> {st} {text[:200]!r}")
    verdict("P4.8 unverified host is refused (never silently served)",
            st in (403, 404, 400), f"status={st}")

    # one-per-parent
    st, body, _ = api("POST", "/v1/tracking-domains", key, {"domain": f"email.{ten['domain']}"})
    msg = err_msg(body) or json.dumps(body)
    obs(f"second domain under the same parent -> {st} {msg[:220]}")
    verdict("P4.9 one-per-parent refusal named",
            st in (400, 409, 422) and "already has the tracking domain" in msg, f"status={st}")

    # reserved label
    st, body, _ = api("POST", "/v1/tracking-domains", key, {"domain": f"www.{ten['domain']}"})
    msg = json.dumps(body)
    obs(f"reserved label -> {st} {msg[:300]}")
    verdict("P4.10 reserved-label refusal named",
            st in (400, 422) and "reserved" in msg, f"status={st}")

    # unverified parent (entitled tenant, parent row not verified)
    unverified_parent = f"unverified-{run}.dogfood.test"
    sql("INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, created_at, updated_at) VALUES "
        f"(gen_random_uuid(), {q(ten['id'])}, {q(unverified_parent)}, 'pending', FALSE, FALSE, NOW(), NOW())")
    st, body, _ = api("POST", "/v1/tracking-domains", key, {"domain": f"track.{unverified_parent}"})
    msg = err_msg(body) or json.dumps(body)
    obs(f"unverified parent -> {st} {msg[:220]}")
    verdict("P4.11 unverified parent refused (verified parent required)",
            st in (400, 403, 422) and ("verified" in msg or "parent" in msg), f"status={st}")

    # delete → serving stops
    cmd(f"DELETE /v1/tracking-domains/{td}")
    st, body, _ = api("DELETE", f"/v1/tracking-domains/{td}", key, {})
    obs(f"{st} {json.dumps(body)[:120]}")
    st2, body2, _ = http("GET", f"{TRACKING}/o/{owner_token}", headers={"Host": custom_host})
    text = body2 if isinstance(body2, str) else json.dumps(body2)
    obs(f"after delete, owner token on {custom_host} -> {st2} {text[:180]!r}")
    verdict("P4.12 delete stops serving on the custom host",
            st in (200, 204) and st2 in (403, 404, 400), f"delete={st} serve_after={st2}")

    # cross-tenant read/delete (the other tenant's real row, id from P4.5)
    otd = td2
    st, body, _ = api("GET", f"/v1/tracking-domains/{otd}", key)
    obs(f"cross-tenant GET -> {st} {json.dumps(body)[:160]}")
    verdict("P4.13 cross-tenant GET -> 404", st == 404, f"status={st}")
    st, body, _ = api("DELETE", f"/v1/tracking-domains/{otd}", key, {})
    obs(f"cross-tenant DELETE -> {st}")
    verdict("P4.13 cross-tenant DELETE -> 404", st == 404, f"status={st}")
    still = sql1(f"SELECT status FROM tracking_domains WHERE id={q(otd)}::uuid")
    verdict("P4.13 cross-tenant DELETE left the row intact", bool(still), f"row_status={still}")

    # non-entitled tenant → named 403 on create
    st, body, _ = api("POST", "/v1/tracking-domains", free["key"], {"domain": f"track.{free['domain']}"})
    msg = err_msg(body)
    obs(f"free tenant create -> {st} {msg[:200]!r}")
    verdict("P4.14 non-entitled create -> 403 naming custom_tracking_domain",
            st == 403 and "custom_tracking_domain" in msg, f"status={st}")

    # concurrent create of the same host → one row (unique constraint)
    import threading
    res = {}

    def _create(n):
        res[n] = api("POST", "/v1/tracking-domains", key, {"domain": f"click.{ten['domain']}"})

    t1, t2 = threading.Thread(target=_create, args=(1,)), threading.Thread(target=_create, args=(2,))
    t1.start(); t2.start(); t1.join(); t2.join()
    rows = int(sql1(f"SELECT COUNT(*) FROM tracking_domains WHERE tenant_id={q(ten['id'])} AND domain={q('click.'+ten['domain'])}"))
    obs(f"concurrent create statuses={[res[i][0] for i in res]} rows={rows}")
    verdict("P4.15 concurrent identical creates -> one row",
            rows == 1 and sorted(res[i][0] for i in res) == [201, 409], f"rows={rows} statuses={[res[i][0] for i in res]}")

    note("restoring the api-server container without the resolver-view hosts entries")
    compose_api_server_with_hosts(None)


# ── P5 custom retention ────────────────────────────────────────────────
def restart_compliance_and_wait(timeout=180) -> None:
    subprocess.run(["docker", "restart", "apexmail-compliance-1"], check=True, capture_output=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(["docker", "logs", "--since", "3m", "apexmail-compliance-1"],
                             capture_output=True, text=True).stdout + subprocess.run(
                                ["docker", "logs", "--since", "3m", "apexmail-compliance-1"],
                                capture_output=True, text=True).stderr
        if "Retention sweep completed" in out:
            return
        time.sleep(5)
    note("compliance sweep log not observed within timeout")


def probe_p5(run: str) -> None:
    section("P5 custom retention")
    ten = provision_tenant(f"CapRet {run}", "growth")
    key = ten["key"]
    free = provision_tenant(f"CapRetFree {run}", "free")

    st, body, _ = api("GET", "/v1/retention", key)
    obs(f"GET /v1/retention -> {st} {json.dumps(body)[:250]}")
    verdict("P5.1 growth read shows the plan ceiling and the grant",
            st == 200 and body.get("plan") == "growth" and body.get("plan_max_retention_days") == 90
            and body.get("custom_retention_granted") is True,
            f"plan={body.get('plan')} ceiling={body.get('plan_max_retention_days')}")

    cmd("PUT /v1/retention {retention_days: 30}")
    st, body, _ = api("PUT", "/v1/retention", key, {"retention_days": 30})
    obs(f"{st} {json.dumps(body)[:250]}")
    stored = sql1(f"SELECT retention_days FROM tenants WHERE id={q(ten['id'])}")
    verdict("P5.2 within-ceiling write stored (+audit)",
            st == 200 and body.get("configured_retention_days") == 30 and stored == "30",
            f"stored={stored}")

    st, body, _ = api("PUT", "/v1/retention", key, {"retention_days": 120})
    msg = err_msg(body)
    obs(f"over-ceiling -> {st} {msg[:200]!r}")
    verdict("P5.3 over-ceiling -> named 403", st == 403 and "90" in msg, f"status={st}")

    st, body, _ = api("PUT", "/v1/retention", key, {"retention_days": 0})
    obs(f"below minimum -> {st} {json.dumps(body)[:200]}")
    verdict("P5.4 below legal minimum -> 400", st == 400, f"status={st}")

    # free tenant write refused
    st, body, _ = api("PUT", "/v1/retention", free["key"], {"retention_days": 5})
    msg = err_msg(body)
    obs(f"free tenant PUT -> {st} {msg[:180]!r}")
    verdict("P5.5 non-entitled write -> 403 naming custom_retention",
            st == 403 and "custom_retention" in msg, f"status={st}")

    # seed rows older than 30 days for the tenant + a recent control row
    old_event = f"dogfood-ret-old-{run}"
    new_event = f"dogfood-ret-new-{run}"
    old_msg_id = str(uuid.uuid4())
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
        f"({q(old_event)}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'opened', 'old@dogfood.test', NOW() - INTERVAL '40 days'), "
        f"({q(new_event)}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'opened', 'new@dogfood.test', NOW())")
    sql("INSERT INTO messages (id, tenant_id, from_address, from_email, to_addresses, to_emails, subject, body, status, created_at, updated_at) VALUES "
        f"({q(old_msg_id)}::uuid, {q(ten['id'])}, {q('a@'+ten['domain'])}, {q('a@'+ten['domain'])}, ARRAY['old@dogfood.test'], '[]'::jsonb, 'old-msg', 'x', 'sent', NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days')")
    before = int(sql1(f"SELECT COUNT(*) FROM events WHERE id IN ({q(old_event)},{q(new_event)})"))
    before_msg = int(sql1(f"SELECT COUNT(*) FROM messages WHERE id={q(old_msg_id)}::uuid"))
    obs(f"seeded: events present={before} old message present={before_msg}")
    cmd("docker restart apexmail-compliance-1 (the sweep tick runs on start)")
    restart_compliance_and_wait()
    after_old = int(sql1(f"SELECT COUNT(*) FROM events WHERE id={q(old_event)}"))
    after_new = int(sql1(f"SELECT COUNT(*) FROM events WHERE id={q(new_event)}"))
    after_msg = int(sql1(f"SELECT COUNT(*) FROM messages WHERE id={q(old_msg_id)}::uuid"))
    obs(f"after sweep: old event={after_old} new event={after_new} old message={after_msg}")
    verdict("P5.6 sweep deletes rows older than the tenant value, keeps newer",
            after_old == 0 and after_new == 1, f"old={after_old} new={after_new}")
    verdict("P5.7 sweep deletes the old message content", after_msg == 0, f"old_message={after_msg}")
    report = sql1("SELECT COUNT(*) FROM retention_report")
    obs(f"retention_report rows={report}")
    audit = int(sql1(f"SELECT COUNT(*) FROM audit_logs WHERE tenant_id={q(ten['id'])} AND action IN ('retention.updated','retention.reset')"))
    verdict("P5.8 the override write is audited", audit >= 1, f"audit_rows={audit}")

    # legal hold wins
    sql(f"UPDATE tenants SET legal_hold = TRUE WHERE id={q(ten['id'])}")
    hold_ev = f"dogfood-ret-hold-{run}"
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
        f"({q(hold_ev)}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'opened', 'hold@dogfood.test', NOW() - INTERVAL '40 days')")
    restart_compliance_and_wait()
    hold_after = int(sql1(f"SELECT COUNT(*) FROM events WHERE id={q(hold_ev)}"))
    verdict("P5.9 legal hold wins (held tenant's old rows survive)", hold_after == 1, f"hold_row={hold_after}")
    sql(f"UPDATE tenants SET legal_hold = FALSE WHERE id={q(ten['id'])}")

    # lowering the plan ceiling clamps the stored override
    sql(f"UPDATE tenants SET plan='starter' WHERE id={q(ten['id'])}")
    clamp_ev = f"dogfood-ret-clamp-{run}"
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
        f"({q(clamp_ev)}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'opened', 'clamp@dogfood.test', NOW() - INTERVAL '40 days')")
    restart_compliance_and_wait()
    clamp_after = int(sql1(f"SELECT COUNT(*) FROM events WHERE id={q(clamp_ev)}"))
    stored_override = sql1(f"SELECT COALESCE(retention_days::text,'NULL') FROM tenants WHERE id={q(ten['id'])}")
    verdict("P5.10 lowering the plan ceiling clamps the stored override (40d row deleted at 30d ceiling)",
            clamp_after == 0, f"clamp_row={clamp_after} stored_override_kept={stored_override}")

    # reset (ungated) returns to plan defaults
    sql(f"UPDATE tenants SET plan='growth' WHERE id={q(ten['id'])}")
    st, body, _ = api("DELETE", "/v1/retention", key, {})
    reset = sql1(f"SELECT COALESCE(retention_days::text,'NULL') FROM tenants WHERE id={q(ten['id'])}")
    obs(f"DELETE /v1/retention -> {st} stored={reset}")
    verdict("P5.11 reset clears the override", st == 200 and reset == "NULL", f"stored={reset}")


# ── P6 subaccounts (enterprise) ────────────────────────────────────────
def probe_p6(run: str) -> None:
    section("P6 subaccounts")
    biz = provision_tenant(f"CapSub {run}", "scale")
    free = provision_tenant(f"CapSubFree {run}", "free")
    other = provision_tenant(f"CapSubOther {run}", "scale")
    jwt = biz["jwt"]

    st, body, _ = ent("POST", "/sub-accounts", jwt, {
        "parent_id": biz["id"], "name": f"sub-1-{run}", "email": f"sub1-{run}@dogfood.test"})
    obs(f"first create -> {st} {json.dumps(body)[:300]}")
    live_cap = sql1(f"SELECT features->>'max_subaccounts' FROM plans WHERE name='scale'")
    verdict("P6.1 Business can create a subaccount",
            st in (200, 201) and (body.get("success") is True),
            f"status={st} live_plan_max_subaccounts={live_cap}")

    first_id = ((body.get("data") or {}) if isinstance(body, dict) else {}).get("id")
    created_ok = st in (200, 201)
    if created_ok:
        for i in range(2, 11):
            st, body, _ = ent("POST", "/sub-accounts", jwt, {
                "parent_id": biz["id"], "name": f"sub-{i}-{run}"})
            if st not in (200, 201):
                obs(f"create #{i} failed early: {st} {json.dumps(body)[:250]}")
                break
        total = int(sql1(f"SELECT COUNT(*) FROM ent_sub_accounts WHERE parent_id={q(biz['id'])}"))
        verdict("P6.2 ten subaccounts created (Business cap)", total == 10, f"total={total}")
        st, body, _ = ent("POST", "/sub-accounts", jwt, {"parent_id": biz["id"], "name": f"sub-11-{run}"})
        msg = json.dumps(body)
        obs(f"11th create -> {st} {msg[:300]}")
        verdict("P6.3 11th refused naming max_subaccounts (403)",
                st == 403 and "max_subaccounts" in msg and "10" in msg, f"status={st} msg={msg[:160]!r}")
    else:
        verdict("P6.2 ten subaccounts created (Business cap)", False,
                f"blocked at first create: {st} {json.dumps(body)[:200]}")
        verdict("P6.3 11th refused naming max_subaccounts", False, "blocked at first create")

    if created_ok:
        # per-key revoke
        st, kb, _ = ent("POST", f"/sub-accounts/{first_id}/api-keys", jwt,
                        {"name": f"key-{run}", "permissions": ["send"], "rate_limit": 100})
        obs(f"mint key -> {st} {json.dumps(kb)[:250]}")
        key_id = ((kb.get("data") or {}) if isinstance(kb, dict) else {}).get("id")
        if not key_id and isinstance(kb, dict):
            key_id = (kb.get("data") or {}).get("key_id")
        st, rb, _ = ent("POST", f"/sub-accounts/{first_id}/api-keys/{key_id}/revoke", jwt, {})
        obs(f"revoke -> {st} {json.dumps(rb)[:200]}")
        st, lb, _ = ent("GET", f"/sub-accounts/{first_id}/api-keys", jwt)
        listed_after = (lb.get("data") or []) if isinstance(lb, dict) else []
        target_after = [k for k in listed_after if k.get("id") == key_id]
        revoked = bool(target_after) and bool(target_after[0].get("revoked"))
        verdict("P6.4 per-key revoke works", st == 200 and revoked,
                f"key={key_id} revoked_after={revoked}")

        # concurrent creates at the cap edge: delete one, race two creates →
        # exactly 10 (the advisory lock serialises the quota check)
        sql(f"DELETE FROM ent_sub_accounts WHERE id={q(first_id)}::uuid")
        done_before = int(sql1(f"SELECT COUNT(*) FROM ent_sub_accounts WHERE parent_id={q(biz['id'])}"))
        import threading
        res = {}

        def _c(n):
            res[n] = ent("POST", "/sub-accounts", jwt, {"parent_id": biz["id"], "name": f"race-{n}-{run}"})

        t1, t2 = threading.Thread(target=_c, args=(1,)), threading.Thread(target=_c, args=(2,))
        t1.start(); t2.start(); t1.join(); t2.join()
        total = int(sql1(f"SELECT COUNT(*) FROM ent_sub_accounts WHERE parent_id={q(biz['id'])}"))
        obs(f"concurrent creates at cap: before={done_before} statuses={[res[i][0] for i in res]} total={total}")
        verdict("P6.5 concurrent creates at the cap -> exactly 10 rows",
                total == 10, f"total={total} statuses={[res[i][0] for i in res]}")

    # non-entitled tenant refused
    st, body, _ = ent("POST", "/sub-accounts", free["jwt"], {"parent_id": free["id"], "name": f"nope-{run}"})
    msg = json.dumps(body)
    obs(f"free tenant create -> {st} {msg[:250]}")
    verdict("P6.6 non-entitled tenant -> 403 naming subaccounts",
            st == 403 and ("subaccounts" in msg.lower() or "plan" in msg.lower()), f"status={st}")

    # cross-tenant access refused
    st, body, _ = ent("GET", f"/sub-accounts/parent/{biz['id']}", other["jwt"])
    obs(f"cross-tenant list -> {st} {json.dumps(body)[:180]}")
    verdict("P6.7 cross-tenant list refused (403)",
            st in (403, 404), f"status={st}")
    if created_ok:
        sid = sql1(f"SELECT id::text FROM ent_sub_accounts WHERE parent_id={q(biz['id'])} LIMIT 1")
        st, body, _ = ent("GET", f"/sub-accounts/{sid}", other["jwt"])
        obs(f"cross-tenant get {sid} -> {st} {json.dumps(body)[:180]}")
        verdict("P6.7 cross-tenant get refused", st in (403, 404), f"status={st}")


# ── P7 template approval workflow ──────────────────────────────────────
def probe_p7(run: str) -> None:
    section("P7 template approval workflow")
    biz = provision_tenant(f"CapApr {run}", "scale")
    grow = provision_tenant(f"CapAprGrow {run}", "growth")
    other = provision_tenant(f"CapAprOther {run}", "scale")
    jwt = biz["jwt"]
    submitter = str(uuid.uuid4())
    approver = str(uuid.uuid4())

    st, body, _ = ent("POST", "/templates/submit", jwt, {
        "tenant_id": biz["id"], "name": f"promo-{run}", "subject": f"Hello {run}",
        "html_content": "<p>Body</p>", "submitted_by": submitter})
    obs(f"submit -> {st} {json.dumps(body)[:300]}")
    sub = (body.get("data") or {}) if isinstance(body, dict) else {}
    sub_id = sub.get("id")
    verdict("P7.1 Business submits a template (pending)",
            st in (200, 201) and sub.get("status") == "pending", f"status={st} submission={sub_id}")

    # maker-checker probe: approve with a JWT whose subject IS the submitter
    maker_jwt = mint_jwt(biz["id"], submitter, scopes=["*"])
    st, body, _ = ent("POST", f"/templates/{sub_id}/approve", maker_jwt, {"reviewed_by": submitter, "notes": "self"})
    obs(f"submitter self-approve -> {st} {json.dumps(body)[:220]}")
    self_ok = st in (200, 201)
    note("service does NOT enforce submitter != approver" if self_ok else "service refuses self-approval")
    if self_ok:
        # reset to pending via a fresh submission for the clean checker cycle
        st, body, _ = ent("POST", "/templates/submit", jwt, {
            "tenant_id": biz["id"], "name": f"promo2-{run}", "subject": f"Hello2 {run}",
            "html_content": "<p>Body2</p>", "submitted_by": submitter})
        sub_id = ((body.get("data") or {}) if isinstance(body, dict) else {}).get("id")

    checker_jwt = mint_jwt(biz["id"], approver, scopes=["*"])
    st, body, _ = ent("POST", f"/templates/{sub_id}/approve", checker_jwt, {"reviewed_by": approver, "notes": "looks good"})
    approved = (body.get("data") or {}) if isinstance(body, dict) else {}
    db_status = sql1(f"SELECT status || '|' || reviewed_by FROM ent_template_submissions WHERE id={q(sub_id)}::uuid")
    obs(f"checker approve -> {st} {json.dumps(body)[:220]}")
    verdict("P7.2 approve cycle with maker-checker identity recorded",
            st in (200, 201) and approved.get("status") == "approved" and approver in db_status,
            f"db={db_status}")

    # reject cycle
    st, body, _ = ent("POST", "/templates/submit", jwt, {
        "tenant_id": biz["id"], "name": f"bad-{run}", "subject": "Bad", "html_content": "<p>x</p>",
        "submitted_by": submitter})
    sub2 = ((body.get("data") or {}) if isinstance(body, dict) else {}).get("id")
    st, body, _ = ent("POST", f"/templates/{sub2}/reject", checker_jwt, {"reviewed_by": approver, "reason": "off-brand"})
    obs(f"reject -> {st} {json.dumps(body)[:220]}")
    rej = sql1(f"SELECT status FROM ent_template_submissions WHERE id={q(sub2)}::uuid")
    verdict("P7.3 reject cycle", st in (200, 201) and rej == "rejected", f"db_status={rej}")

    # stats endpoint real
    st, body, _ = ent("GET", f"/templates/stats/{biz['id']}", jwt)
    obs(f"stats -> {st} {json.dumps(body)[:300]}")
    stats = (body.get("data") or {}) if isinstance(body, dict) else {}
    db_total = int(sql1(f"SELECT COUNT(*) FROM ent_template_submissions WHERE tenant_id={q(biz['id'])}"))
    stat_total = stats.get("total") or stats.get("total_submissions") or stats.get("count")
    verdict("P7.4 stats endpoint returns real numbers",
            st == 200 and stat_total == db_total, f"stats={stats} db_total={db_total}")

    # non-entitled tenant refused
    st, body, _ = ent("POST", "/templates/submit", grow["jwt"], {
        "tenant_id": grow["id"], "name": f"x-{run}", "subject": "x", "html_content": "<p>x</p>",
        "submitted_by": submitter})
    msg = json.dumps(body)
    obs(f"growth tenant submit -> {st} {msg[:250]}")
    verdict("P7.5 non-entitled tenant -> 403 naming template_approval_workflow",
            st == 403 and "template_approval_workflow" in msg, f"status={st}")

    # cross-tenant refused
    st, body, _ = ent("GET", f"/templates/{sub_id}", other["jwt"])
    obs(f"cross-tenant get -> {st} {json.dumps(body)[:180]}")
    verdict("P7.6 cross-tenant get refused", st in (403, 404), f"status={st}")
    st, body, _ = ent("GET", f"/templates/tenant/{biz['id']}", other["jwt"])
    obs(f"cross-tenant list -> {st} {json.dumps(body)[:180]}")
    verdict("P7.6 cross-tenant list refused", st in (403, 404), f"status={st}")
    st, body, _ = ent("POST", f"/templates/{sub_id}/approve", other["jwt"], {"reviewed_by": "other", "notes": "x"})
    obs(f"cross-tenant approve -> {st} {json.dumps(body)[:180]}")
    verdict("P7.6 cross-tenant approve refused", st in (403, 404), f"status={st}")

    # concurrency: two racing approves -> one reviewer recorded, no duplicate
    st, body, _ = ent("POST", "/templates/submit", jwt, {
        "tenant_id": biz["id"], "name": f"race-{run}", "subject": "Race", "html_content": "<p>x</p>",
        "submitted_by": submitter})
    race_id = ((body.get("data") or {}) if isinstance(body, dict) else {}).get("id")
    import threading
    res = {}
    jwts = {"a": mint_jwt(biz["id"], str(uuid.uuid4()), scopes=["*"]),
            "b": mint_jwt(biz["id"], str(uuid.uuid4()), scopes=["*"])}

    def _ap(n):
        res[n] = ent("POST", f"/templates/{race_id}/approve", jwts[n], {"reviewed_by": n, "notes": n})

    t1, t2 = threading.Thread(target=_ap, args=("a",)), threading.Thread(target=_ap, args=("b",))
    t1.start(); t2.start(); t1.join(); t2.join()
    state = sql1(f"SELECT status || '|' || COALESCE(reviewed_by::text,'') FROM ent_template_submissions WHERE id={q(race_id)}::uuid")
    obs(f"racing approves statuses={[res[i][0] for i in res]} row={state}")
    verdict("P7.7 concurrent approves leave one review identity",
            state.startswith("approved") and len({res[i][0] for i in res} & {200, 201}) >= 1,
            f"row={state} statuses={[res[i][0] for i in res]}")


# ── P8 audit logs ──────────────────────────────────────────────────────
def probe_p8(run: str) -> None:
    section("P8 audit logs")
    ten = provision_tenant(f"CapAud {run}", "growth")
    key = ten["key"]
    other = provision_tenant(f"CapAudOther {run}", "growth")
    free = provision_tenant(f"CapAudFree {run}", "free")
    scoped = mint_key(ten["id"], f"narrow-{run}", ["messages:read"])

    head_before = sql1("SELECT head_seq FROM audit_chain_head WHERE chain_id='global'")
    # generate actions: template create + send + retention update (audited)
    st, body, _ = api("POST", "/v1/templates", key, {"name": f"aud-{run}", "subject": "s", "html_body": "<p>x</p>"})
    tpl = body.get("id")
    grant_consent(ten["id"], f"p8-{run}@dogfood.test")
    st, body, _ = api("POST", "/v1/messages", key, {
        "from": f"dogfood@{ten['domain']}", "to": [f"p8-{run}@dogfood.test"],
        "subject": f"P8 {run}", "html": "<p>audit</p>"})
    msg = unwrap_id(body)
    st, _, _ = api("PUT", "/v1/retention", key, {"retention_days": 20})
    time.sleep(1)

    cmd("GET /v1/audit?limit=5")
    st, rows, hdrs = api("GET", "/v1/audit?limit=5", key)
    obs(f"{st} rows={json.dumps(rows)[:400]}")
    obs(f"headers x-has-more={hdrs.get('x-has-more')} x-next-cursor={str(hdrs.get('x-next-cursor'))[:60]}")
    is_list = isinstance(rows, list)
    verdict("P8.1 audit trail lists real actions", st == 200 and is_list and len(rows or []) > 0,
            f"status={st} rows={len(rows) if is_list else 'n/a'}")
    actions = [r.get("action") for r in (rows or [])]
    has_actions = any("template" in (a or "") for a in actions) and any("message" in (a or "") or "message.sent" in (a or "") or "sent" in (a or "") for a in actions)
    verdict("P8.2 generated actions appear (template + send)", has_actions, f"actions={actions[:8]}")

    # keyset pagination: page1 cursor → page2 disjoint
    page1 = rows or []
    cursor = hdrs.get("x-next-cursor") or hdrs.get("X-Next-Cursor")
    if cursor:
        st2, page2, _ = api("GET", f"/v1/audit?limit=5&cursor={urllib.parse.quote(str(cursor))}", key)
        ids1 = {r.get("id") for r in page1}
        ids2 = {r.get("id") for r in (page2 or [])}
        obs(f"page2 rows={len(page2 or [])} overlap={len(ids1 & ids2)}")
        verdict("P8.3 keyset pagination continues without overlap",
                st2 == 200 and len(ids1 & ids2) == 0, f"page2={len(page2 or [])} overlap={len(ids1 & ids2)}")
    else:
        verdict("P8.3 keyset pagination continues without overlap", False, "no x-next-cursor returned")

    # exports
    st, csv_body, _ = api("GET", "/v1/audit/export?format=csv", key)
    csv_text = csv_body if isinstance(csv_body, str) else json.dumps(csv_body)
    st2, jsonl_body, _ = api("GET", "/v1/audit/export?format=jsonl", key)
    jsonl_text = jsonl_body if isinstance(jsonl_body, str) else json.dumps(jsonl_body)
    csv_lines = [l for l in csv_text.splitlines() if l.strip()]
    jsonl_lines = [l for l in jsonl_text.splitlines() if l.strip()]
    obs(f"csv status={st} lines={len(csv_lines)} header={csv_lines[0][:120] if csv_lines else ''!r}")
    obs(f"jsonl status={st2} lines={len(jsonl_lines)} first={jsonl_lines[0][:160] if jsonl_lines else ''!r}")
    jsonl_ok = True
    try:
        for line in jsonl_lines:
            json.loads(line)
    except Exception as e:
        jsonl_ok = False
        obs(f"jsonl parse error: {e}")
    verdict("P8.4 export csv + jsonl readable and non-empty",
            st == 200 and st2 == 200 and len(csv_lines) >= 2 and len(jsonl_lines) >= 1 and jsonl_ok,
            f"csv_lines={len(csv_lines)} jsonl_lines={len(jsonl_lines)} jsonl_ok={jsonl_ok}")

    # export writes its own audit row
    st, rows_after, _ = api("GET", "/v1/audit?limit=5", key)
    acts = [r.get("action") for r in (rows_after or [])]
    export_audited = any("export" in (a or "") for a in acts)
    verdict("P8.5 the export itself is audited", export_audited, f"recent_actions={acts[:6]}")

    # scope audit:read enforced
    st, body, _ = api("GET", "/v1/audit", scoped)
    msg = err_msg(body)
    obs(f"messages:read-only key -> {st} {msg[:180]!r}")
    verdict("P8.6 scope audit:read enforced (403)", st == 403 and "audit:read" in msg, f"status={st}")

    # non-entitled tenant
    st, body, _ = api("GET", "/v1/audit", free["key"])
    msg = err_msg(body)
    obs(f"free tenant -> {st} {msg[:180]!r}")
    verdict("P8.7 non-entitled tenant -> 403 naming audit_logs",
            st == 403 and ("audit_logs" in msg or "plan" in msg), f"status={st}")

    # cross-tenant: tenant B sees only its own rows (no tenantId filter exists)
    st, rows_b, _ = api("GET", "/v1/audit?limit=200", other["key"])
    a_ids = {r.get("id") for r in (rows_after or [])}
    b_ids = {r.get("id") for r in (rows_b or [])}
    b_tenants = {r.get("tenant_id") for r in (rows_b or []) if isinstance(r, dict)}
    obs(f"tenant B rows={len(rows_b or [])} tenants_seen={b_tenants} leaked={len(a_ids & b_ids)}")
    verdict("P8.8 cross-tenant read leaked nothing",
            st == 200 and len(a_ids & b_ids) == 0 and b_tenants <= {other["id"]},
            f"status={st} leaked={len(a_ids & b_ids)}")

    head_after = sql1("SELECT head_seq FROM audit_chain_head WHERE chain_id='global'")
    verdict("P8.9 audit chain head advanced",
            int(head_after or 0) > int(head_before or 0), f"seq {head_before} -> {head_after}")


# ── P9 alert rules ─────────────────────────────────────────────────────
def probe_p9(run: str) -> None:
    section("P9 alert rules")
    # mint a fresh system-tenant wildcard key we can use
    sys_raw = mint_key("system_internal_tenant01", f"dogfood-alerts-{run}", ["*"])
    alert_tenant = provision_tenant(f"CapAlert {run}", "free")

    cmd("POST /v1/admin/alert-rules {metricType:'emails', thresholdPercent:50}")
    st, body, _ = api("POST", "/v1/admin/alerts/rules", sys_raw, {
        "tenantId": alert_tenant["id"], "name": f"dogfood-emails-{run}",
        "metricType": "emails", "thresholdPercent": 50,
        "notificationChannel": "email", "severity": "warning", "enabled": True})
    obs(f"{st} {json.dumps(body)[:300]}")
    rule_id = body.get("id") if isinstance(body, dict) else None
    verdict("P9.1 rule created on the evaluated store",
            st in (200, 201) and rule_id and body.get("metricType") == "emails",
            f"id={rule_id} status={st}")

    st, body, _ = api("POST", "/v1/admin/alerts/rules", sys_raw, {
        "tenantId": alert_tenant["id"], "name": f"dogfood-storage-{run}",
        "metricType": "storage", "thresholdPercent": 50,
        "notificationChannel": "email", "severity": "warning", "enabled": True})
    msg = err_msg(body)
    obs(f"storage metric -> {st} {msg[:250]!r}")
    verdict("P9.2 storage metric refused with the reason",
            st == 400 and "storage" in msg and "emails" in msg, f"status={st}")

    # Force usage past the threshold. A FREE tenant inside its 30-day launch
    # window has the 30,000-email allowance (billing_service::usage::
    # free_launch_allowance_applies), so 20,000 is 67% of the effective limit.
    sql("INSERT INTO metering_events (id, tenant_id, event_type, timestamp, quantity, metadata) VALUES "
        f"(gen_random_uuid(), {q(alert_tenant['id'])}, 'emails_sent', NOW(), 20000, '{{}}'::jsonb)")
    obs("forced usage=20000 (67% of the free-plan launch-window limit 30000; threshold 50%)")

    cmd("wait for the billing maintenance usage-alert sweep (5-minute interval)")
    incident = None
    for _ in range(240):
        incident = sql1(f"SELECT id::text || '|' || severity || '|' || COALESCE(message,'') FROM system_alerts "
                        f"WHERE tenant_id={q(alert_tenant['id'])} AND source='usage_alert' ORDER BY created_at DESC LIMIT 1")
        if incident:
            break
        time.sleep(5)
    obs(f"incident={incident[:300] if incident else None}")
    verdict("P9.3 the sweep fired an incident into system_alerts",
            bool(incident) and "warning" in incident, f"incident={incident[:200] if incident else None}")

    # the CP page and JSON API agree
    st, rules_json, _ = api("GET", "/v1/admin/alerts/rules", sys_raw)
    rules = rules_json if isinstance(rules_json, list) else (rules_json or {}).get("data") or (rules_json or {}).get("rules") or []
    mine = [r for r in rules if r.get("id") == rule_id]
    obs(f"JSON rules -> {st} mine={json.dumps(mine)[:220]}")
    sys_uid = sql1("SELECT id::text FROM users WHERE tenant_id='system_internal_tenant01' AND status='active' LIMIT 1")
    sys_jwt = mint_jwt("system_internal_tenant01", sys_uid, scopes=["*"])
    st_page, page, _ = http("GET", f"{API}/alerts",
                            headers={"Cookie": f"am_session={sys_jwt}", "Host": "admin.localhost", "Accept": "text/html"})
    page_text = page if isinstance(page, str) else json.dumps(page)
    is_cp_shell = "Control Plane" in page_text
    obs(f"CP /alerts (admin.localhost) -> {st_page} control_plane_shell={is_cp_shell} bytes={len(page_text)}")
    verdict("P9.4 CP page (Control Plane shell) and the JSON API agree on the rule store",
            st == 200 and len(mine) == 1 and is_cp_shell,
            f"json_mine={len(mine)} page_status={st_page} cp_shell={is_cp_shell}")

    # disable → no new incident
    last_before = sql1(f"SELECT COALESCE(to_char(MAX(created_at),'YYYY-MM-DD\"T\"HH24:MI:SS'),'none') FROM system_alerts WHERE tenant_id={q(alert_tenant['id'])}")
    st, body, _ = api("POST", f"/v1/admin/alerts/rules/{rule_id}/disable", sys_raw, {})
    obs(f"disable -> {st} {json.dumps(body)[:160]}")
    enabled = sql1(f"SELECT enabled FROM usage_alert_configs WHERE id={q(rule_id)}::uuid")
    verdict("P9.5 disable persists", st in (200, 201) and enabled == "f", f"enabled={enabled}")
    # clear cooldown so a still-enabled rule WOULD fire again; disabled must not
    redis_clear = subprocess.run(["docker", "exec", "apexmail-redis", "redis-cli", "-a", "dev-redis-password-minimum-32-chars", "--no-auth-warning", "DEL",
                                  f"alert:cooldown:{alert_tenant['id']}:emails:50"], capture_output=True, text=True)
    note(f"cooldown key cleared ({redis_clear.stdout.strip()}); waiting one sweep interval")
    time.sleep(340)
    after = sql1(f"SELECT COALESCE(to_char(MAX(created_at),'YYYY-MM-DD\"T\"HH24:MI:SS'),'none') FROM system_alerts WHERE tenant_id={q(alert_tenant['id'])}")
    obs(f"last incident before={last_before} after={after}")
    verdict("P9.6 disabled rule fires no new incident", after == last_before, f"before={last_before} after={after}")

    # update
    st, body, _ = api("PATCH", f"/v1/admin/alerts/rules/{rule_id}", sys_raw, {
        "thresholdPercent": 90, "severity": "critical"})
    obs(f"update -> {st} {json.dumps(body)[:220]}")
    row = sql1(f"SELECT threshold_percent || '|' || severity FROM usage_alert_configs WHERE id={q(rule_id)}::uuid")
    verdict("P9.7 update persists", st == 200 and row == "90|critical", f"row={row}")

    # delete
    st, body, _ = api("DELETE", f"/v1/admin/alerts/rules/{rule_id}", sys_raw, {})
    gone = sql1(f"SELECT COUNT(*) FROM usage_alert_configs WHERE id={q(rule_id)}::uuid")
    verdict("P9.8 delete removes the rule", st in (200, 204) and gone == "0", f"status={st} rows={gone}")

    # non-system tenant refused
    st, body, _ = api("GET", "/v1/admin/alerts/rules", alert_tenant["key"])
    obs(f"non-system tenant list -> {st} {json.dumps(body)[:180]}")
    verdict("P9.9 non-system tenant refused", st in (403, 404), f"status={st}")


# ── P10 wave G ─────────────────────────────────────────────────────────
def next_window_utc(now, hour: int, weekday: int, offset_minutes: int):
    """Mirror analytics::send_time_optimizer::next_occurrence_utc."""
    from datetime import timedelta
    local = now + timedelta(minutes=offset_minutes)
    target_day = min(weekday, 6)
    target_hour = min(hour, 23)
    days_ahead = (target_day - local.weekday()) % 7
    candidate = local.replace(hour=target_hour, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)
    while candidate <= local:
        candidate += timedelta(days=7)
    return candidate - timedelta(minutes=offset_minutes)


def probe_p10(run: str) -> None:
    section("P10 wave G (trust score, placement analytics, send-time optimization)")
    ten = provision_tenant(f"CapG {run}", "growth")
    key = ten["key"]
    other = provision_tenant(f"CapGOther {run}", "growth")

    # ── trust score
    cid = ensure_contact(ten["id"], f"p10-trust-{run}@dogfood.test", "Trusty")
    mid = str(uuid.uuid4())
    sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
        f"({q('g1-'+run)}, {q(ten['id'])}, {q(mid)}, 'opened', {q('p10-trust-'+run+'@dogfood.test')}, NOW()), "
        f"({q('g2-'+run)}, {q(ten['id'])}, {q(mid)}, 'clicked', {q('p10-trust-'+run+'@dogfood.test')}, NOW()), "
        f"({q('g3-'+run)}, {q(ten['id'])}, {q(mid)}, 'sent', {q('p10-trust-'+run+'@dogfood.test')}, NOW() - INTERVAL '1 day'), "
        f"({q('g4-'+run)}, {q(ten['id'])}, {q(mid)}, 'replied', {q('p10-trust-'+run+'@dogfood.test')}, NOW())")
    st, owner_body, _ = api("GET", f"/v1/contacts/{cid}/trust-score", key)
    obs(f"trust-score -> {st} {json.dumps(owner_body)[:300]}")
    comp = (owner_body or {}).get("components") or {}
    verdict("P10.1 trust score returns real scores",
            st == 200 and isinstance(owner_body, dict) and 0 <= owner_body.get("overall", -1) <= 100 and comp,
            f"overall={owner_body.get('overall') if isinstance(owner_body, dict) else None} grade={owner_body.get('grade') if isinstance(owner_body, dict) else None}")

    st, body, _ = api("GET", f"/v1/contacts/{cid}/trust-score", other["key"])
    obs(f"cross-tenant trust-score -> {st} {json.dumps(body)[:160]}")
    verdict("P10.2 trust score tenant-scoped (cross-tenant 404)", st == 404, f"status={st}")

    # same address under another tenant has no engagement → lower score
    ocid = ensure_contact(other["id"], f"p10-trust-{run}@dogfood.test", "Foreign twin")
    st, obody, _ = api("GET", f"/v1/contacts/{ocid}/trust-score", other["key"])
    obs(f"twin tenant score -> {st} overall={obody.get('overall') if isinstance(obody, dict) else None}")
    verdict("P10.2 twin tenant's score does not see the other tenant's events",
            st == 200 and obody.get("overall", 100) < owner_body.get("overall", 0),
            f"owner={owner_body.get('overall')} twin={obody.get('overall') if isinstance(obody, dict) else None}")

    # ── placement report analytics block
    test_id = str(uuid.uuid4())
    provider_id = str(uuid.uuid4())
    seed_id = str(uuid.uuid4())
    has_tables = sql1("SELECT to_regclass('placement_tests') IS NOT NULL")
    if has_tables == "t":
        sql(f"INSERT INTO seed_providers (id, name, display_name, inbox_types, created_at) "
            f"VALUES ({q(provider_id)}::uuid, {q('dogfood-'+run)}, {q('Dogfood ISP')}, ARRAY['inbox','spam'], NOW())")
        sql(f"INSERT INTO seed_accounts (id, provider_id, email, imap_host, imap_port, imap_username, is_active, health_status, created_at, updated_at) "
            f"VALUES ({q(seed_id)}::uuid, {q(provider_id)}::uuid, {q('seed-'+run+'@dogfood.test')}, 'imap.dogfood.test', 993, 'seed', TRUE, 'healthy', NOW(), NOW())")
        sql(f"INSERT INTO placement_tests (id, tenant_id, name, status, from_email, subject, total_accounts, completed_accounts, created_at) "
            f"VALUES ({q(test_id)}::uuid, {q(ten['id'])}, {q('dogfood-placement-'+run)}, 'completed', "
            f"{q('dogfood@'+ten['domain'])}, 'place', 4, 4, NOW())")
        for folder in ("inbox", "inbox", "spam", "promotions"):
            sql(f"INSERT INTO placement_results (id, test_id, seed_account_id, inbox_type, delivery_time_ms, checked_at) "
                f"VALUES (gen_random_uuid(), {q(test_id)}::uuid, {q(seed_id)}::uuid, {q(folder)}, 812, NOW())")
        sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
            f"({q('plac-d-'+run)}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'delivered', {q('p10-place-'+run+'@gmail.com')}, NOW())")
        st, body, _ = api("GET", f"/v1/inbox-placement/tests/{test_id}", key)
        obs(f"placement report -> {st} {json.dumps(body)[:500]}")
        analytics = (body or {}).get("analytics") if isinstance(body, dict) else None
        measured = (analytics or {}).get("measured") if isinstance(analytics, dict) else None
        delivery = (analytics or {}).get("delivery") if isinstance(analytics, dict) else None
        verdict("P10.3 placement report carries the analytics block with the real measured numbers",
                st == 200 and isinstance(analytics, dict)
                and (measured or {}).get("measured_total") == 4
                and (measured or {}).get("inbox") == 2
                and (measured or {}).get("spam") == 1
                and (delivery or {}).get("delivered") == 1,
                f"status={st} measured={json.dumps(measured)[:160] if measured else None} delivery={json.dumps(delivery)[:120] if delivery else None}")
    else:
        verdict("P10.3 placement report carries the analytics block", False, "placement_tests table missing")

    # ── send-time optimization
    tz = "Europe/Tallinn"
    rcpt = f"p10-sto-{run}@dogfood.test"
    cid2 = grant_consent(ten["id"], rcpt)
    lid = str(uuid.uuid4())
    sql("INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, status, created_at, updated_at) VALUES "
        f"({q(lid)}, {q(ten['id'])}, {q('sto-'+run)}, 'dogfood', 'single', 'active', NOW(), NOW())")
    sql(f"INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) VALUES (gen_random_uuid(), {q(lid)}, {q(cid2)}, 'active', NOW())")

    st, body, _ = api("POST", "/v1/campaigns", key, {
        "name": f"sto-{run}", "subject": f"STO {run}", "from": f"dogfood@{ten['domain']}",
        "html": "<p>scheduled</p>", "list_ids": [lid],
        "settings": {"sendTimeOptimization": True, "timezone": tz},
    })
    camp = unwrap_id(body)
    obs(f"STO campaign -> {st} {camp}")
    st, body, _ = api("POST", f"/v1/campaigns/{camp}/send", key, {})
    obs(f"STO send -> {st} status={body.get('status') if isinstance(body, dict) else None}")

    scheduled = ""
    for _ in range(90):
        scheduled = sql1("SELECT COALESCE(to_char(scheduled_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'') "
                         f"FROM email_queue WHERE campaign_id={q(camp)}::uuid AND scheduled_at IS NOT NULL LIMIT 1")
        if scheduled:
            break
        time.sleep(1)
    qstatus = sql1(f"SELECT status || '|' || COALESCE(to_char(scheduled_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'immediate') FROM email_queue WHERE campaign_id={q(camp)}::uuid LIMIT 1")
    obs(f"queue row status|scheduled_at={qstatus!r}")

    # Documented cold start (analytics::send_time_optimizer): the absolute
    # anchor is Tuesday 10:00 UTC, rendered in the tenant's local time
    # (`local_cold_start_hour` shifts the stored LOCAL hour; the UTC instant
    # stays 10:00Z). A cold-start recipient therefore lands on the next
    # Tuesday 10:00 UTC regardless of the tenant zone.
    from datetime import datetime, timezone, timedelta
    now = datetime.now(timezone.utc)
    expected = next_window_utc(now, 10, 2, 0)
    if scheduled:
        try:
            got = datetime.fromisoformat(scheduled)
            if got.tzinfo is None:
                got = got.replace(tzinfo=timezone.utc)
            same = abs((got - expected).total_seconds()) < 120
        except Exception as e:
            same = False
            obs(f"scheduled parse error: {e}")
    else:
        same = False
    verdict("P10.4 STO cold-start recipient lands on the next documented window (Tue 10:00 UTC anchor)",
            bool(scheduled) and same, f"scheduled={scheduled!r} expected~{expected.isoformat()}")
    delta_note = ""
    if scheduled:
        try:
            got = datetime.fromisoformat(scheduled)
            if got.tzinfo is None:
                got = got.replace(tzinfo=timezone.utc)
            delta_note = f"delta_vs_now={round((got - now).total_seconds() / 60, 1)}min"
        except Exception:
            pass
    obs(f"immediate-send comparison: {delta_note or 'scheduled_at differs from immediate by construction'}")
    verdict("P10.5 STO scheduled_at differs from immediate",
            bool(scheduled) and delta_note != "" and abs(float(delta_note.split('=')[1].rstrip('min'))) > 5,
            delta_note)

    # ── warm profile: engagement at 08:00 UTC (= 11:00 Tallinn, a local
    #    peak) must schedule the next occurrence of that LOCAL window, i.e.
    #    the offset is applied for data-driven windows.
    warm_email = f"p10-sto-warm-{run}@dogfood.test"
    warm_cid = grant_consent(ten["id"], warm_email)
    warm_lid = str(uuid.uuid4())
    sql("INSERT INTO lists (id, tenant_id, name, description, opt_in_mode, status, created_at, updated_at) VALUES "
        f"({q(warm_lid)}, {q(ten['id'])}, {q('sto-warm-'+run)}, 'dogfood', 'single', 'active', NOW(), NOW())")
    sql(f"INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) VALUES (gen_random_uuid(), {q(warm_lid)}, {q(warm_cid)}, 'active', NOW())")
    # six opens on the most recent matching weekday at 08:00 UTC
    anchor = (now - timedelta(days=2)).replace(hour=8, minute=0, second=0, microsecond=0)
    for i in range(6):
        sql("INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp) VALUES "
            f"({q(f'warm-{run}-{i}')}, {q(ten['id'])}, {q(str(uuid.uuid4()))}, 'opened', {q(warm_email)}, "
            f"{q(anchor.strftime('%Y-%m-%dT%H:%M:%SZ'))})")
    st, wbody, _ = api("POST", "/v1/campaigns", key, {
        "name": f"sto-warm-{run}", "subject": f"STO warm {run}", "from": f"dogfood@{ten['domain']}",
        "html": "<p>scheduled</p>", "list_ids": [warm_lid],
        "settings": {"sendTimeOptimization": True, "timezone": tz},
    })
    wcamp = unwrap_id(wbody)
    st, wbody, _ = api("POST", f"/v1/campaigns/{wcamp}/send", key, {})
    warm_scheduled = ""
    for _ in range(90):
        warm_scheduled = sql1("SELECT COALESCE(to_char(scheduled_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),'') "
                              f"FROM email_queue WHERE campaign_id={q(wcamp)}::uuid AND scheduled_at IS NOT NULL LIMIT 1")
        if warm_scheduled:
            break
        time.sleep(1)
    # the peak's LOCAL hour (offset +180) is 11:00; expected UTC instant =
    # next occurrence of that weekday at 08:00Z
    local_anchor = anchor + timedelta(minutes=180)
    expected_warm = next_window_utc(now, local_anchor.hour, local_anchor.weekday(), 180)
    got_ok = False
    try:
        got = datetime.fromisoformat(warm_scheduled)
        if got.tzinfo is None:
            got = got.replace(tzinfo=timezone.utc)
        got_ok = abs((got - expected_warm).total_seconds()) < 120
    except Exception:
        got_ok = False
    obs(f"warm scheduled_at={warm_scheduled!r} expected~{expected_warm.isoformat()} (local hour {local_anchor.hour} Tue-anchor={anchor.isoformat()})")
    verdict("P10.6 STO applies the campaign timezone to a data-driven window",
            bool(warm_scheduled) and got_ok, f"scheduled={warm_scheduled!r} expected~{expected_warm.isoformat()}")


PROBES = {"p1": probe_p1, "p2": probe_p2, "p3": probe_p3, "p4": probe_p4, "p5": probe_p5, "p6": probe_p6, "p7": probe_p7, "p8": probe_p8, "p9": probe_p9, "p10": probe_p10}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--run-id", default=f"{int(time.time())}")
    args = ap.parse_args()
    selected = [s.strip().lower() for s in args.only.split(",") if s.strip()] or list(PROBES)
    for name in selected:
        if name not in PROBES:
            print(f"unknown probe group {name}", file=sys.stderr)
            return 2
        PROBES[name](args.run_id)

    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n===== SUMMARY run={args.run_id}: {len(RESULTS) - len(failed)}/{len(RESULTS)} PASS =====")
    for r in failed:
        print(f"FAIL {r['probe']} :: {r['detail']}")
    with open(f"/tmp/dogfood-cap-{args.run_id}.json", "w") as fh:
        json.dump({"run": args.run_id, "results": RESULTS}, fh, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
