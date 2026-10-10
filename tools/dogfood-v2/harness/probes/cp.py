"""Control-plane probes (partition: cp).

The operator surface as a WHOLE: every ui-foundation CP page rendered by an
MFA'd system-tenant operator, the JSON admin surface reached with the
operator session, the customer-session/CP-cookie gates, and the static
machine credential's blast radius.
"""
from __future__ import annotations

from ..assertions import Checks, is_named_refusal
from ..identity import ensure_operator
from ..registry import probe

# concrete-id / action pages where an honest 400/404 is acceptable for a
# session-less probe; every other CP page must render 200 for the operator.
LENIENT = {"/tenants/t_1", "/confirm"}


@probe("p.cp.operator_console", "cp", severity="P1",
       description="Every control-plane SSR page renders for the MFA'd operator; customers are refused")
def operator_console(ctx):
    checks = Checks("p.cp.operator_console", "control-plane")
    try:
        ensure_operator(ctx)
    except Exception as error:  # noqa: BLE001
        checks.unreachable("CP operator provisioned through the product lifecycle", str(error)[:300])
        return checks.obs
    operator = ctx.identity("operator")
    owner = ctx.identity("owner_a")
    pages = [s for s in ctx.ledger.by_kind("ssr") if s.meta.get("surface") == "control-plane"]
    if not pages:
        checks.unreachable("control-plane pages enumerated from the ui baseline", "ledger carries none")
        return checks.obs
    for surface in pages:
        if surface.path == "/login":
            continue
        resp = operator.session.get(surface.path, host=ctx.cfg.cp_host, follow=False)
        if resp.status == 0:
            checks.unreachable(f"CP {surface.path}", resp.text, surface=surface.id)
            continue
        location = resp.headers.get("location", "")
        bounced = resp.status in (301, 302, 303, 307, 308) and "/login" in location
        if surface.path in LENIENT:
            ok = resp.status in (200, 400, 404)
        else:
            ok = resp.status == 200
        checks.add(
            f"CP page {surface.path} renders for the operator",
            ok and not bounced,
            observed=f"status={resp.status} location={location[:80]!r} len={len(resp.text or '')}",
            expected="200 for the MFA'd system-tenant operator (no /login bounce)",
            severity="P1", surface=surface.id,
        )
        # the customer session must not render the same page
        customer = owner.session.get(surface.path, host=ctx.cfg.cp_host, follow=False)
        customer_location = customer.headers.get("location", "")
        rendered = customer.status == 200 and "Internal Server Error" not in (customer.text or "")
        checks.add(
            f"CP page {surface.path} is not rendered for a customer session",
            not rendered,
            observed=f"status={customer.status} location={customer_location[:80]!r}",
            expected="redirect to CP /login or a refusal",
            severity="P0", surface=surface.id,
        )
    return checks.obs


@probe("p.cp.json_admin", "cp", severity="P0",
       description="JSON control-plane surface: operator reaches it; anonymous and customer sessions are refused")
def json_admin(ctx):
    checks = Checks("p.cp.json_admin", "control-plane")
    try:
        ensure_operator(ctx)
    except Exception as error:  # noqa: BLE001
        checks.unreachable("CP operator provisioned through the product lifecycle", str(error)[:300])
        return checks.obs
    operator = ctx.identity("operator")
    owner = ctx.identity("owner_a")
    endpoints = [
        "/v1/admin/tenants",
        "/v1/admin/dashboard/stats",
        "/v1/admin/audit",
        "/v1/admin/operators",
    ]
    for path in endpoints:
        resp = operator.session.get(path)
        checks.add(
            f"the operator reaches {path}",
            resp.status == 200 and resp.status < 500,
            observed=f"status={resp.status} body={resp.text[:160]!r}",
            expected="200 for the system-tenant operator",
            severity="P1", surface=f"api:GET {path}",
        )
        anon = ctx.http.get(path)
        named, detail = is_named_refusal(anon)
        checks.add(
            f"anonymous callers are refused on {path} with a named error",
            anon.status in (401, 403) and named,
            observed=f"status={anon.status} {detail}",
            expected="401/403 with a named control-plane gate",
            severity="P0", surface=f"api:GET {path}",
        )
        customer = owner.session.get(path)
        named, detail = is_named_refusal(customer)
        checks.add(
            f"customer sessions are refused on {path} (no CP escalation)",
            customer.status in (401, 403) and named,
            observed=f"status={customer.status} {detail}",
            expected="401/403 — '*'-scoped customer admins must not operate the platform",
            severity="P0", surface=f"api:GET {path}",
        )
    return checks.obs


@probe("p.cp.cookie_gate", "cp", severity="P1",
       description="The signed CP cookie is required: dropping it from the operator session closes the CP")
def cookie_gate(ctx):
    checks = Checks("p.cp.cookie_gate", "control-plane")
    try:
        ensure_operator(ctx)
    except Exception as error:  # noqa: BLE001
        checks.unreachable("CP operator provisioned through the product lifecycle", str(error)[:300])
        return checks.obs
    operator = ctx.identity("operator")
    checks.add(
        "the operator session carries the apexmail_cp_session cookie",
        "apexmail_cp_session" in operator.session.jar,
        observed=f"cookies={sorted(operator.session.jar)}",
        expected="the CP cookie minted by /web/cp/login",
        severity="P1", surface="api:POST /web/cp/login",
    )
    saved = operator.session.jar.pop("apexmail_cp_session", "")
    try:
        page = operator.session.get("/tenants", host=ctx.cfg.cp_host, follow=False)
        json_admin = operator.session.get("/v1/admin/tenants")
    finally:
        if saved:
            operator.session.jar["apexmail_cp_session"] = saved
    location = page.headers.get("location", "")
    rendered = page.status == 200 and "Internal Server Error" not in (page.text or "")
    checks.add(
        "without the CP cookie the operator cannot render CP SSR pages",
        not rendered and page.status < 500,
        observed=f"status={page.status} location={location[:100]!r}",
        expected="redirect to login / named refusal, never the operator page",
        severity="P1", surface="ssr:control-plane:GET /tenants",
    )
    checks.add(
        "without the CP cookie the operator cannot operate the JSON admin surface",
        json_admin.status in (401, 403),
        observed=f"status={json_admin.status} body={json_admin.text[:140]!r}",
        expected="401/403 — am_session alone is not a control-plane credential",
        severity="P0", surface="api:GET /v1/admin/tenants",
    )
    # restore check: the cookie was put back
    restored = operator.session.get("/v1/admin/tenants")
    checks.add(
        "the CP cookie is restored after the gate probe (state restored)",
        restored.status == 200,
        observed=f"status={restored.status}",
        expected="200 after restoring the cookie",
        severity="P2", surface="api:GET /v1/admin/tenants",
    )
    return checks.obs
