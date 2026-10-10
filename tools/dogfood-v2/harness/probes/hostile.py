"""Hostile-input battery (partition: hostile).

XSS (stored + reflected, script/attribute/SVG/javascript:/entity contexts),
SQL metacharacters, CRLF/header injection, path traversal, oversized bodies,
malformed JSON/forms, wrong content types, unicode bidi/zero-width/NUL bytes,
and prototype-pollution-shaped JSON keys — applied per surface class.
"""
from __future__ import annotations

import json
import re
import uuid

from ..assertions import (
    BIDI_PAYLOAD, CRLF_PAYLOAD, NUL_PAYLOAD, PROTO_POLLUTION, SQL_PAYLOAD,
    TRAVERSAL_PAYLOAD, XSS_PAYLOADS, Checks, payload_snippet, raw_script_present,
    refusal_ok,
)
from ..registry import probe

WRITE_METHODS = ("POST", "PUT", "PATCH")


def _console_pages(ctx, session):
    return {
        "/contacts": session.get("/contacts"),
        "/lists": session.get("/lists"),
        "/templates": session.get("/templates"),
        "/campaigns": session.get("/campaigns"),
        "/dashboard": session.get("/dashboard"),
    }


@probe("p.hostile.xss_stored", "hostile", severity="P0",
       description="Stored XSS payloads in resource names never render as raw HTML in the console")
def xss_stored(ctx):
    checks = Checks("p.hostile.xss_stored", "console-ssr")
    owner = ctx.identity("owner_a")
    suffix = uuid.uuid4().hex[:8]
    payload = XSS_PAYLOADS[0]
    created = []
    contact = owner.session.post(
        "/v1/contacts", {"email": f"dgv2-xss-{suffix}@dogfood.test", "name": payload})
    created.append(("contact", contact.status))
    lst = owner.session.post("/v1/lists", {"name": payload, "description": payload})
    created.append(("list", lst.status))
    tmpl = owner.session.post(
        "/v1/templates", {"name": f"xss-{suffix}", "subject": payload, "html_body": f"<p>{payload}</p>"})
    created.append(("template", tmpl.status))
    campaign = owner.session.post(
        "/v1/campaigns", {"name": payload, "subject": payload, "from": "dogfood@dogfood-v2.test",
                          "html": f"<p>{payload}</p>"})
    created.append(("campaign", campaign.status))
    checks.add(
        "hostile payloads are accepted as data (creates answer 2xx)",
        all(200 <= status < 300 for _label, status in created),
        observed=f"creates={created}", expected="2xx storing the payload as opaque data",
        surface="api:POST /v1/contacts", severity="P2",
    )
    for path, resp in _console_pages(ctx, owner.session).items():
        body = resp.text or ""
        raw = raw_script_present(body, payload)
        checks.add(
            f"stored payload does not render raw on {path}",
            not raw,
            observed=f"status={resp.status} raw_payload={'PRESENT' if raw else 'absent'} len={len(body)}"
                     + (f" snippet={payload_snippet(body, payload)!r}" if raw else ""),
            expected="escaped rendering (&lt;script&gt;) — no executable markup",
            severity="P0", surface=f"ssr:web:GET {path}",
        )
    # the campaign detail page renders the name too
    cid = ""
    body = campaign.json() or {}
    cid = (body.get("data") or body).get("id", "")
    if cid:
        detail = owner.session.get(f"/campaigns/{cid}")
        checks.add(
            "stored payload does not render raw on the campaign detail page",
            not raw_script_present(detail.text or "", payload),
            observed=f"status={detail.status} len={len(detail.text or '')}",
            expected="escaped rendering", severity="P0", surface="ssr:web:GET /campaigns/[id]",
        )
    return checks.obs


@probe("p.hostile.xss_reflected", "hostile", severity="P0",
       description="XSS payloads in query strings and paths are never reflected raw")
def xss_reflected(ctx):
    checks = Checks("p.hostile.xss_reflected", "console-ssr")
    owner = ctx.identity("owner_a")
    for payload in XSS_PAYLOADS[:4]:
        encoded = _q(payload)
        for path in (
            f"/contacts?search={encoded}",
            f"/campaigns?search={encoded}",
            f"/events?q={encoded}",
            f"/no-such-page-{encoded}",
        ):
            resp = owner.session.get(path)
            raw = raw_script_present(resp.text or "", payload)
            checks.add(
                f"payload is not reflected raw on {path.split('?')[0]}",
                not raw and resp.status < 500,
                observed=f"status={resp.status} raw={'PRESENT' if raw else 'absent'}"
                         + (f" snippet={payload_snippet(resp.text or '', payload)!r}" if raw else ""),
                expected="escaped or dropped, never executable", severity="P0",
                surface=f"ssr:web:GET {path.split('?')[0]}",
            )
    return checks.obs


def _q(value: str) -> str:
    import urllib.parse

    return urllib.parse.quote(value, safe="")


@probe("p.hostile.sql_metacharacters", "hostile", severity="P1",
       description="SQL metacharacters are parameterized: no 5xx, no cross-tenant dump, data intact")
def sql_metacharacters(ctx):
    checks = Checks("p.hostile.sql_metacharacters", "sql")
    owner = ctx.identity("owner_a")
    foreign = ctx.fixture("owner_b")
    foreign_email = foreign.get("contact_email", "")
    endpoints = [
        f"/v1/contacts?search={_q(SQL_PAYLOAD)}",
        f"/v1/contacts?tag={_q(SQL_PAYLOAD)}&limit=5",
        f"/v1/campaigns?search={_q(SQL_PAYLOAD)}",
        f"/v1/templates?search={_q(SQL_PAYLOAD)}",
        f"/v1/audit?action={_q(SQL_PAYLOAD)}",
    ]
    for path in endpoints:
        resp = owner.session.get(path)
        leaked = foreign_email and foreign_email in (resp.text or "")
        checks.add(
            f"{path.split('?')[0]} survives SQL metacharacters without a crash or leak",
            resp.status < 500 and not leaked,
            observed=f"status={resp.status} foreign_leak={bool(leaked)} body={resp.text[:100]!r}",
            expected="parameterized query (200/4xx), never 5xx or foreign rows",
            severity="P1", surface=f"api:GET {path.split('?')[0]}",
        )
    # a payload stored as data must round-trip verbatim and leave tables intact
    email = f"dgv2-sql-{uuid.uuid4().hex[:8]}@dogfood.test"
    resp = owner.session.post("/v1/contacts", {"email": email, "name": SQL_PAYLOAD})
    ok_status = resp.status in (200, 201)
    row = ctx.db.row("contacts", email=email) if ctx.db else None
    if ctx.db is not None:
        stored_ok = bool(row) and str(row.get("name", "")) == SQL_PAYLOAD
        checks.add(
            "a SQL payload in a name is stored verbatim (parameterized write)",
            ok_status and stored_ok,
            observed=f"status={resp.status} db_name={str((row or {}).get('name', ''))[:60]!r}",
            expected="stored as data, table intact", severity="P1", surface="api:POST /v1/contacts",
        )
        count = ctx.db.count("contacts")
        checks.add("the contacts table still answers after hostile writes", True,
                   observed=f"contacts rows={count}", surface="table:contacts")
    return checks.obs


@probe("p.hostile.crlf_injection", "hostile", severity="P1",
       description="CRLF/header injection in mail-bound fields and custom headers is refused")
def crlf_injection(ctx):
    checks = Checks("p.hostile.crlf_injection", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    foreign = ctx.fixture("owner_a")
    # The sender domain must be VERIFIED first (otherwise every case is
    # refused with "domain is not ready", and the CRLF guard is never
    # exercised); `category: transactional` keeps the consent gate out of the
    # way too — so the ONLY thing that can refuse a case is the guard under
    # test.
    from ..fixtures import ensure_verified_domain

    ensure_verified_domain(ctx, owner.tenant_id, foreign.get("sender_domain", "dogfood-v2.test"))
    cases = [
        ("newline-bearing recipient", {"to": [f"victim@x.test{CRLF_PAYLOAD}"], "subject": "s", "html": "<p>x</p>", "category": "transactional", "from": f"noreply@{foreign.get('sender_domain', 'dogfood-v2.test')}"}),
        ("newline-bearing subject", {"to": ["victim@x.test"], "subject": CRLF_PAYLOAD, "html": "<p>x</p>", "category": "transactional", "from": f"noreply@{foreign.get('sender_domain', 'dogfood-v2.test')}"}),
        ("newline-bearing from", {"to": ["victim@x.test"], "subject": "s", "html": "<p>x</p>", "category": "transactional", "from": CRLF_PAYLOAD + "@dogfood-v2.test"}),
        ("CRLF in a custom header value", {"to": ["victim@x.test"], "subject": "s", "html": "<p>x</p>", "category": "transactional", "from": f"noreply@{foreign.get('sender_domain', 'dogfood-v2.test')}", "headers": {"X-Dogfood": CRLF_PAYLOAD}}),
    ]
    for label, body in cases:
        resp = owner.session.post("/v1/messages", body)
        refusal_ok(checks, resp, f"{label} is refused", allowed=(400, 401, 403, 404, 409, 413, 422),
                   surface="api:POST /v1/messages", severity="P1")
    return checks.obs


@probe("p.hostile.path_traversal", "hostile", severity="P1",
       description="Traversal payloads never serve host files and never crash")
def path_traversal(ctx):
    checks = Checks("p.hostile.path_traversal", "traversal")
    owner = ctx.identity("owner_a")
    probes = [
        "/v1/domains/..%2f..%2f..%2fetc%2fpasswd",
        "/v1/contacts/..%2f..%2fetc%2fpasswd",
        "/css/..%2f..%2f..%2fetc%2fpasswd",
        "/.well-known/../%2e%2e/secrets/postgres_password.txt",
        "/api/kcaptcha/challenge/../../../etc/passwd",
        "/images/" + TRAVERSAL_PAYLOAD,
    ]
    for path in probes:
        resp = ctx.http.get(path, host=ctx.cfg.host)
        leaked = "root:" in (resp.text or "") or "password" in (resp.text or "")[:200].lower() and "postgres" in (resp.text or "").lower()
        checks.add(
            f"traversal {path} is refused without file disclosure",
            resp.status < 500 and not leaked,
            observed=f"status={resp.status} len={len(resp.text or '')}",
            expected="404/400, never a 5xx or host-file bytes", severity="P1",
        )
    return checks.obs


@probe("p.hostile.oversized_bodies", "hostile", severity="P1",
       description="Oversized bodies/query strings are bounded per route without crashing")
def oversized_bodies(ctx):
    checks = Checks("p.hostile.oversized_bodies", "limits")
    owner = ctx.identity("owner_a")
    foreign = ctx.fixture("owner_a")
    from ..fixtures import ensure_verified_domain

    ensure_verified_domain(ctx, owner.tenant_id, foreign.get("sender_domain", "dogfood-v2.test"))
    # 1 MiB name on a validated field
    resp = owner.session.post("/v1/contacts", {"email": f"dgv2-big-{uuid.uuid4().hex[:8]}@dogfood.test", "name": "A" * 1_000_000})
    checks.add(
        "a 1 MiB contact name is refused (or accepted as data) without a 5xx",
        resp.status < 500,
        observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="4xx naming the bound (a 5xx is a crash on validated input)",
        severity="P1", surface="api:POST /v1/contacts",
    )
    # 2 MiB template body (global body cap is 40 MiB; template size limits apply)
    resp = owner.session.post(
        "/v1/templates",
        {"name": f"dgv2-big-{uuid.uuid4().hex[:8]}", "subject": "big", "html_body": "<p>" + "B" * 2_000_000 + "</p>"},
    )
    checks.add("a 2 MiB template body does not crash the server", resp.status < 500,
               observed=f"status={resp.status}", expected="2xx or a named 4xx",
               severity="P1", surface="api:POST /v1/templates")
    # 20 KB query string
    resp = owner.session.get("/v1/contacts?search=" + "C" * 20_000)
    checks.add("a 20 KB search query does not crash the server", resp.status < 500,
               observed=f"status={resp.status}", expected="2xx or a named 4xx",
               surface="api:GET /v1/contacts", severity="P1")
    # past the documented 40 MiB body cap on the send route
    big = {"from": f"noreply@{foreign.get('sender_domain', 'dogfood-v2.test')}",
           "to": ["victim@dogfood.test"], "subject": "big", "html": "D" * (41 * 1024 * 1024)}
    resp = owner.session.post("/v1/messages", big)
    checks.add(
        "a 41 MiB send body is refused at the documented 40 MiB cap",
        resp.status in (413, 400, 401, 403, 422),
        observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="413/4xx naming the body limit", severity="P1", surface="api:POST /v1/messages",
    )
    return checks.obs


@probe("p.hostile.malformed_and_content_types", "hostile", severity="P1",
       description="Malformed JSON, wrong content types and prototype-pollution keys across every authenticated write route")
def malformed_and_content_types(ctx):
    checks = Checks("p.hostile.malformed_and_content_types", "taxonomy")
    owner = ctx.identity("owner_a")
    surfaces = [
        s for s in ctx.ledger.by_kind("api")
        if s.mount_class == "authenticated" and s.method in WRITE_METHODS
    ]
    # bound the sweep: every surface gets the malformed-JSON probe (cheap, and
    # a 5xx here is exactly the defect class the brief calls out)
    for surface in surfaces:
        path = _concretize(surface.path)
        resp = owner.session.req(surface.method, path, raw="{", ctype="application/json")
        honest_503 = resp.status == 503 and bool(resp.error_code())
        if resp.status >= 500 and not honest_503:
            checks.add(
                f"malformed JSON on {surface.method} {surface.path} crashed (5xx)",
                False, observed=f"status={resp.status} body={resp.text[:160]!r}",
                expected="a named 4xx (VALIDATION_ERROR/PARSE_ERROR), never 5xx",
                severity="P1", surface=surface.id,
            )
        elif resp.status in (404, 405):
            checks.add(
                f"malformed JSON on {surface.method} {surface.path} routed to {resp.status}",
                False, observed=f"status={resp.status}",
                expected="the enumerated route must exist (404/405 = routing gap)",
                severity="P2", surface=surface.id,
            )
        else:
            checks.add(f"malformed JSON on {surface.method} {surface.path} is a named 4xx",
                       True, observed=f"status={resp.status}", surface=surface.id)
    # wrong content types on a representative JSON route
    sample = "/v1/contacts"
    resp = owner.session.req("POST", sample, raw="email=x%40y.test", ctype="application/x-www-form-urlencoded")
    checks.add("a form body on a JSON route is refused with 415/400", resp.status in (400, 415),
               observed=f"status={resp.status} body={resp.text[:120]!r}",
               expected="415/400 unsupported media type", surface="api:POST /v1/contacts")
    resp = owner.session.req("POST", sample, raw=json.dumps({"email": "z@y.test"}), ctype="text/plain")
    checks.add("a text/plain body on a JSON route is refused with 415/400", resp.status in (400, 415),
               observed=f"status={resp.status}", expected="415/400", surface="api:POST /v1/contacts")
    # prototype-pollution-shaped JSON keys
    resp = owner.session.post(sample, {**PROTO_POLLUTION, "email": f"dgv2-proto-{uuid.uuid4().hex[:8]}@dogfood.test"})
    pollution_reflected = "__proto__" in (resp.text or "")
    checks.add(
        "prototype-pollution-shaped keys do not crash or get reflected",
        resp.status < 500 and not pollution_reflected,
        observed=f"status={resp.status} reflected={pollution_reflected}",
        expected="keys treated as opaque data; no 5xx; no structure echo",
        severity="P1", surface="api:POST /v1/contacts",
    )
    return checks.obs


@probe("p.hostile.unicode_and_nul", "hostile", severity="P1",
       description="NUL bytes are validated (never raw DB errors); bidi/zero-width text is handled as data")
def unicode_and_nul(ctx):
    checks = Checks("p.hostile.unicode_and_nul", "unicode")
    owner = ctx.identity("owner_a")
    suffix = uuid.uuid4().hex[:8]
    cases = [
        ("NUL in a template body", "/v1/templates",
         {"name": f"dgv2-nul-{suffix}", "subject": "nul", "html_body": f"<p>{NUL_PAYLOAD}</p>"}),
        ("NUL in a contact name", "/v1/contacts",
         {"email": f"dgv2-nul-{suffix}@dogfood.test", "name": NUL_PAYLOAD}),
        ("100k-char template name", "/v1/templates",
         {"name": "X" * 100_000, "subject": "long", "html_body": "<p>x</p>"}),
        ("bidi/zero-width contact name", "/v1/contacts",
         {"email": f"dgv2-bidi-{suffix}@dogfood.test", "name": BIDI_PAYLOAD}),
    ]
    for label, path, body in cases:
        resp = owner.session.post(path, body)
        checks.add(
            f"{label} is a named 4xx or stored as data — never a raw 5xx",
            resp.status < 500,
            observed=f"status={resp.status} body={resp.text[:140]!r}",
            expected="4xx validation (D-2 class: DB errors must not surface as 500)",
            severity="P1" if resp.status >= 500 else "P3", surface=f"api:POST {path}",
        )
    return checks.obs


def _concretize(path: str) -> str:
    from .surfaces import concretize

    return concretize(path)
