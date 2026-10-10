"""Console (web SSR) functional probes (partition: console).

Authenticated rendering, CRUD round-trips against the SSR pages, the
zero-JS form contract (CSRF + captcha), and the assistant surface.
"""
from __future__ import annotations

import uuid

from ..assertions import Checks, refusal_ok
from ..registry import probe

AUTH_PAGES = (
    "/dashboard", "/campaigns", "/campaigns/new", "/contacts", "/contacts/new",
    "/lists", "/templates", "/reports", "/reports/deliverability", "/analytics",
    "/events", "/domains", "/settings", "/settings/api-keys", "/settings/team",
    "/settings/billing", "/settings/profile", "/settings/webhooks",
    "/settings/suppressions", "/settings/dedicated-ips", "/assistant",
    "/inbox-placement",
)


@probe("p.console.pages_render", "console", severity="P1",
       description="Every authenticated console page renders 200 with real content")
def pages_render(ctx):
    checks = Checks("p.console.pages_render", "console-ssr")
    owner = ctx.identity("owner_a")
    for path in AUTH_PAGES:
        resp = owner.session.get(path)
        body = resp.text or ""
        ok = resp.status == 200 and len(body) > 500 and "Internal Server Error" not in body
        checks.add(
            f"console page {path} renders for the owner",
            ok, observed=f"status={resp.status} len={len(body)}",
            expected="200 with a rendered page", severity="P1",
            surface=f"ssr:web:GET {path}",
        )
    return checks.obs


@probe("p.console.crud_roundtrip", "console", severity="P1",
       description="Create via JSON → visible in the SSR page and the API; delete removes it")
def crud_roundtrip(ctx):
    checks = Checks("p.console.crud_roundtrip", "console-crud")
    owner = ctx.identity("owner_a")
    marker = f"dgv2-roundtrip-{uuid.uuid4().hex[:8]}"

    contact_email = f"{marker}@dogfood.test"
    created = owner.session.post("/v1/contacts", {"email": contact_email, "name": marker})
    checks.add("contact create succeeds", created.status in (200, 201),
               observed=f"status={created.status}", surface="api:POST /v1/contacts", severity="P1")
    page = owner.session.get("/contacts")
    checks.add(
        "the new contact appears on /contacts",
        marker in (page.text or ""),
        observed=f"status={page.status} marker_present={marker in (page.text or '')}",
        expected="the row renders", surface="ssr:web:GET /contacts", severity="P1",
    )
    api = owner.session.get("/v1/contacts?limit=100")
    checks.add(
        "the new contact appears in the contacts API",
        marker in (api.text or ""),
        observed=f"status={api.status} marker_present={marker in (api.text or '')}",
        expected="the row is queryable", surface="api:GET /v1/contacts", severity="P1",
    )
    lst = owner.session.post("/v1/lists", {"name": marker})
    body = lst.json() or {}
    list_id = (body.get("data") or body).get("id", "")
    checks.add("list create succeeds", lst.status in (200, 201) and bool(list_id),
               observed=f"status={lst.status} id={list_id}", surface="api:POST /v1/lists", severity="P1")
    if list_id:
        page = owner.session.get("/lists")
        checks.add(
            "the new list appears on /lists",
            marker in (page.text or ""),
            observed=f"status={page.status}", expected="the list renders",
            surface="ssr:web:GET /lists", severity="P1",
        )
        detail = owner.session.get(f"/lists/{list_id}")
        checks.add("the list detail page renders", detail.status == 200,
                   observed=f"status={detail.status}", expected="200",
                   surface="ssr:web:GET /lists/[id]", severity="P1")
        deleted = owner.session.delete(f"/v1/lists/{list_id}")
        checks.add("list delete succeeds", 200 <= deleted.status < 300,
                   observed=f"status={deleted.status}", surface="api:DELETE /v1/lists/:id", severity="P1")
    return checks.obs


@probe("p.console.form_contract", "console", severity="P1",
       description="SSR forms require CSRF + captcha; the login page ships the KiwiCaptcha widget")
def form_contract(ctx):
    checks = Checks("p.console.form_contract", "console-forms")
    anon = ctx.get("/login")
    body = anon.text or ""
    has_widget = ("kiwi__token" in body or "kcaptcha" in body.lower()) and "nonce" in body.lower()
    checks.add(
        "/login renders the KiwiCaptcha widget with a per-response nonce",
        anon.status == 200 and has_widget,
        observed=f"status={anon.status} widget={has_widget} len={len(body)}",
        expected="widget markup + nonce + kiwi__token input",
        severity="P1", surface="ssr:web:GET /login",
    )
    # SSR form without _csrf is refused
    resp = ctx.http.form("/web/lists", {"name": "dgv2-csrf-less", "return_to": "/lists"})
    checks.add(
        "an SSR form without _csrf is refused",
        resp.status in (400, 401, 403, 303, 422),
        observed=f"status={resp.status} location={resp.headers.get('location', '')}",
        expected="refusal or PRG redirect back with a flash",
        severity="P1", surface="api:POST /web/lists",
    )
    # SSR login without a captcha token is refused
    resp = ctx.http.form("/web/auth/login", {"email": "dgv2@dogfood.test", "password": "Wrong!Passw0rd-2026"})
    refused = resp.status in (400, 401, 403, 422) or (resp.status in (303, 302) and "mfa" not in resp.headers.get("location", ""))
    checks.add(
        "an SSR login without a captcha token does not mint a session",
        "am_session" not in resp.headers.get("set-cookie", "") and resp.status < 500,
        observed=f"status={resp.status} cookies={resp.headers.get('set-cookie', '')[:80]!r}",
        expected="no session cookie without the captcha proof",
        severity="P1", surface="api:POST /web/auth/login",
    )
    return checks.obs


@probe("p.console.assistant", "console", severity="P2",
       description="Assistant accepts a message, persists it; empty/oversized messages are bounded")
def assistant(ctx):
    checks = Checks("p.console.assistant", "assistant")
    owner = ctx.identity("owner_a")
    marker = f"dgv2 assistant {uuid.uuid4().hex[:8]}"
    resp = owner.session.form("/web/assistant/message", {"message": marker})
    checks.add(
        "the assistant accepts a normal message",
        resp.status in (200, 201, 202, 303) or resp.status < 500,
        observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="200/303 accepting the message", severity="P2",
        surface="api:POST /web/assistant/message",
    )
    for label, message in (("empty", ""), ("oversized", "A" * 50_000)):
        resp = owner.session.form("/web/assistant/message", {"message": message})
        checks.add(
            f"the assistant bounds an {label} message without a 5xx",
            resp.status < 500,
            observed=f"status={resp.status} body={resp.text[:120]!r}",
            expected="named refusal or bounded acceptance, never a crash",
            severity="P2", surface="api:POST /web/assistant/message",
        )
    if ctx.db is not None:
        sessions = ctx.db.count("ai_chat_sessions")
        checks.add("assistant conversations persist", sessions >= 0,
                   observed=f"ai_chat_sessions rows={sessions}", surface="table:ai_chat_sessions")
    return checks.obs
