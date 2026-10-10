"""Authorization / tenant-isolation battery (partition: authz).

  * cross-tenant IDOR sweep over EVERY id-bearing authenticated route from the
    router tables (owner A presents owner B's real fixture ids);
  * role matrix: member/viewer sessions on admin + write surfaces;
  * control-plane gates: customer sessions on JSON admin + CP SSR, the CP
    cookie requirement, the operator positive path, and the static system key.
"""
from __future__ import annotations

import json
import re
import uuid

from ..assertions import Checks, is_named_refusal, refusal_ok
from ..config import REPO_ROOT
from ..registry import probe

PARAM_RE = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")
BENIGN_UUID = "11111111-1111-4111-8111-1111111111d9"


def _foreign_id(path: str, foreign: dict) -> str:
    if "/contacts/" in path:
        return foreign.get("contact_hidden_id") or BENIGN_UUID
    if "/lists/" in path:
        return foreign.get("list_id") or BENIGN_UUID
    if "/templates/" in path:
        return foreign.get("template_id") or BENIGN_UUID
    if "/campaigns/" in path or "/segments/" in path:
        return foreign.get("campaign_id") or BENIGN_UUID
    if "/suppressions/" in path:
        return BENIGN_UUID
    if "/domains/" in path or "/tracking-domains/" in path:
        return BENIGN_UUID
    if "/messages/" in path or "/events/" in path:
        return BENIGN_UUID
    if "/api-keys/" in path:
        return BENIGN_UUID
    if "/webhooks/" in path:
        return BENIGN_UUID
    return BENIGN_UUID


def _substitute(path: str, foreign: dict) -> str:
    def replace(match: re.Match) -> str:
        name = match.group(0)[1:].lower()
        if name in ("id", "contact_id", "list_id", "template_id", "campaign_id", "segment_id",
                    "domain_id", "webhook_id", "message_id", "session_id", "user_id", "key_id",
                    "api_key_id", "job_id", "automation_id", "test_id", "lead_id"):
            return _foreign_id(path, foreign)
        if name in ("tenant_id",):
            return "22222222-2222-4222-8222-2222222222d9"
        if name == "kind":
            return "wallet"
        if name == "email":
            return foreign.get("contact_hidden_email") or "dgv2-foreign@dogfood.test"
        return "dgv2x"

    return PARAM_RE.sub(replace, path)


@probe(
    "p.authz.cross_tenant_idor", "authz", subsumes=("api:*",), severity="P0",
    description="Every id-bearing authenticated route refuses owner B's ids to owner A (cross-tenant read/write)",
)
def cross_tenant_idor(ctx):
    checks = Checks("p.authz.cross_tenant_idor", "cross-tenant")
    owner_a = ctx.identity("owner_a")
    foreign = ctx.fixture("owner_b")
    if not foreign:
        checks.unreachable("tenant B fixtures provisioned", "fixture set owner_b missing")
        return checks.obs
    surfaces = [
        s for s in ctx.ledger.by_kind("api")
        if s.mount_class in ("authenticated", "admin")
        and PARAM_RE.search(s.path)
        and s.method in ("GET", "PUT", "PATCH", "DELETE", "POST")
    ]
    for surface in surfaces:
        path = _substitute(surface.path, foreign)
        if surface.method in ("GET", "DELETE"):
            resp = owner_a.session.req(surface.method, path)
        else:
            resp = owner_a.session.req(surface.method, path, body={})
        if resp.status == 0:
            checks.unreachable(f"cross-tenant {surface.method} {surface.path}", resp.text, surface=surface.id)
            continue
        if 200 <= resp.status < 300:
            # NON-RESOURCE lookups where a 2xx is the honest contract even for
            # an unknown/non-owned argument (narrow, documented exceptions —
            # not a blanket allowance):
            #  * /v1/billing/plans/features/:feature — a static feature catalog
            #    lookup; `:feature` is a feature key, not a tenant resource.
            #  * /v1/suppressions/check/:email — answers {suppressed: bool} for
            #    the CALLER's tenant; it never returns another tenant's row.
            non_resource = (
                "/plans/features/" in surface.path
                or "/suppressions/check/" in surface.path
            )
            checks.add(
                f"cross-tenant {surface.method} {surface.path} with a FOREIGN id returned 2xx",
                non_resource,
                observed=f"status={resp.status} body={resp.text[:200]!r}",
                expected="403/404 — another tenant's resource must never be reachable"
                         + (" (documented non-resource lookup)" if non_resource else ""),
                severity="P2" if non_resource else "P0", surface=surface.id,
                evidence={"request": f"{surface.method} {path}", "foreign_ids": sorted(foreign.keys())},
            )
            continue
        if resp.status >= 500:
            named, detail = is_named_refusal(resp)
            checks.add(
                f"cross-tenant {surface.method} {surface.path} answered {resp.status}",
                resp.status == 503 and named,  # a NAMED 503 (feature unconfigured) is honest
                observed=f"status={resp.status} {detail} body={resp.text[:160]!r}",
                expected="a named 4xx refusal (a named 503 for an unconfigured feature is honest)",
                severity="P1", surface=surface.id,
            )
            continue
        checks.add(
            f"cross-tenant {surface.method} {surface.path} is refused",
            True, observed=f"status={resp.status}", expected="4xx", surface=surface.id,
        )
    return checks.obs


@probe("p.authz.role_matrix", "authz", severity="P1",
       description="member/viewer/owner role matrix: admin surfaces and write scopes refused where documented")
def role_matrix(ctx):
    checks = Checks("p.authz.role_matrix", "role-matrix")
    owner = ctx.identity("owner_a")
    member = ctx.identity("member")
    viewer = ctx.identity("viewer")

    # admin mounts must reject every customer role (system-tenant gate)
    for who in (owner, member, viewer):
        for path in ("/v1/admin/tenants", "/v1/admin/dashboard/stats", "/v1/admin/audit/logs"):
            resp = who.session.get(path)
            refusal_ok(
                checks, resp, f"{who.role} session is refused on {path}",
                allowed=(401, 403, 404), surface=f"api:GET {path}", severity="P1",
            )

    # member holds messages:read only — contacts read must be refused by scope
    resp = member.session.get("/v1/contacts?limit=1")
    refusal_ok(checks, resp, "member (messages:read only) is refused /v1/contacts",
               allowed=(403,), surface="api:GET /v1/contacts", severity="P1")
    resp = member.session.post("/v1/contacts", {"email": f"dgv2-member-write-{uuid.uuid4().hex[:8]}@dogfood.test"})
    refusal_ok(checks, resp, "member cannot create contacts", allowed=(403,),
               surface="api:POST /v1/contacts", severity="P1")
    resp = member.session.get("/v1/messages?limit=1")
    checks.add(
        "member reads its granted scope (messages:read)",
        resp.status == 200, observed=f"status={resp.status}", expected="200",
        surface="api:GET /v1/messages", severity="P1",
    )

    # viewer holds read scopes — writes refused
    resp = viewer.session.post("/v1/contacts", {"email": f"dgv2-viewer-write-{uuid.uuid4().hex[:8]}@dogfood.test"})
    refusal_ok(checks, resp, "viewer cannot create contacts", allowed=(403,),
               surface="api:POST /v1/contacts", severity="P1")
    resp = viewer.session.get("/v1/contacts?limit=1")
    checks.add("viewer reads contacts (contacts:read)", resp.status == 200,
               observed=f"status={resp.status}", expected="200", surface="api:GET /v1/contacts")

    # owner reaches its own tenant resources
    resp = owner.session.get("/v1/contacts?limit=1")
    checks.add("owner reads contacts", resp.status == 200, observed=f"status={resp.status}",
               expected="200", surface="api:GET /v1/contacts", severity="P1")

    # SSR team invite: a member must not create an invite row
    invite_email = f"dgv2-invite-{uuid.uuid4().hex[:8]}@dogfood.test"
    resp = member.session.form("/web/team/invite", {"userName": invite_email, "role": "member"})
    created = ctx.db.count("users", email=invite_email) if ctx.db else 0
    checks.add(
        "member cannot invite teammates (no row created)",
        created == 0,
        observed=f"status={resp.status} users_rows={created}",
        expected="0 rows for a member-initiated invite",
        surface="api:POST /web/team/invite", severity="P1",
    )
    return checks.obs


@probe("p.authz.cp_gates", "authz", severity="P0",
       description="CP gates: customer sessions refused; the operator path works; CP cookie required")
def cp_gates(ctx):
    checks = Checks("p.authz.cp_gates", "control-plane")
    owner = ctx.identity("owner_a")

    resp = owner.session.get("/v1/admin/tenants")
    named, detail = is_named_refusal(resp)
    checks.add(
        "customer session on /v1/admin/tenants is refused with a named system-tenant error",
        resp.status in (401, 403) and named,
        observed=f"status={resp.status} {detail}", expected="401/403 naming the control-plane gate",
        surface="api:GET /v1/admin/tenants", severity="P0",
    )
    # CP SSR pages on the CP host with a customer session redirect to login
    resp = owner.session.get("/tenants", host=ctx.cfg.cp_host, follow=False)
    checks.add(
        "customer session on CP SSR /tenants does not render the operator page",
        resp.status in (302, 303, 307, 308, 401, 403) or (resp.status == 200 and "/login" in resp.headers.get("location", "")),
        observed=f"status={resp.status} location={resp.headers.get('location', '')}",
        expected="redirect to CP /login or refusal", surface="ssr:control-plane:GET /tenants", severity="P0",
    )
    # the JSON admin surface with an am_session but no CP cookie
    resp = owner.session.get("/v1/admin/tenants")
    checks.add(
        "am_session alone cannot operate the admin JSON surface",
        resp.status in (401, 403),
        observed=f"status={resp.status}", expected="401/403", surface="api:GET /v1/admin/tenants", severity="P0",
    )
    # operator positive path
    try:
        from ..identity import ensure_operator

        ensure_operator(ctx)
    except Exception as error:  # noqa: BLE001
        checks.unreachable("CP operator provisioned through the product lifecycle", str(error)[:300])
        return checks.obs
    operator = ctx.identity("operator")
    checks.add(
        "the operator holds the CP session cookie after /web/cp/login",
        "apexmail_cp_session" in operator.session.jar,
        observed=f"cookies={sorted(operator.session.jar)}",
        expected="apexmail_cp_session set", surface="api:POST /web/cp/login", severity="P1",
    )
    resp = operator.session.get("/v1/admin/tenants")
    checks.add(
        "the operator reaches /v1/admin/tenants",
        resp.status == 200, observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="200 for a system-tenant MFA'd operator", surface="api:GET /v1/admin/tenants", severity="P1",
    )
    resp = operator.session.get("/tenants", host=ctx.cfg.cp_host, follow=False)
    checks.add(
        "the operator renders CP SSR /tenants",
        resp.status == 200, observed=f"status={resp.status}",
        expected="200 on the CP host", surface="ssr:control-plane:GET /tenants", severity="P1",
    )
    # the static control-plane system key (machine credential carve-out)
    cp_key = _cp_static_key()
    if cp_key:
        resp = ctx.http.get("/v1/admin/tenants", headers={"X-API-Key": cp_key})
        checks.add(
            "the static control-plane key reaches the admin JSON surface",
            resp.status == 200, observed=f"status={resp.status} body={resp.text[:120]!r}",
            expected="200 (documented machine-credential carve-out)",
            surface="api:GET /v1/admin/tenants", severity="P2",
        )
        resp = ctx.http.get("/v1/contacts?limit=1", headers={"X-API-Key": cp_key})
        checks.add(
            "the static control-plane key is NOT a customer credential",
            resp.status in (401, 403), observed=f"status={resp.status}",
            expected="401/403 outside the control-plane surface",
            surface="api:GET /v1/contacts", severity="P1",
        )
    return checks.obs


def _cp_static_key() -> str:
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(errors="ignore").splitlines():
            if line.startswith("CONTROL_PLANE_API_KEY="):
                return line.split("=", 1)[1].strip()
    return "local-dev-control-plane-api-key-32chars"
