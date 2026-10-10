"""Money/billing probes (partition: money).

Catalog math, quota honesty, entitlement snapshots (including the documented
plan-override mechanism), invoices, dedicated IPs and checkout refusals.
"""
from __future__ import annotations

from ..assertions import Checks
from ..registry import probe


@probe("p.money.plan_catalog", "money", severity="P1",
       description="Plans catalog answers with coherent ids/prices/limits")
def plan_catalog(ctx):
    checks = Checks("p.money.plan_catalog", "api:GET /v1/billing/plans")
    owner = ctx.identity("owner_a")
    resp = owner.session.get("/v1/billing/plans")
    body = resp.json() or {}
    plans = body.get("plans") or (body.get("data") or {}).get("plans") or body.get("data") or []
    if isinstance(plans, dict):
        plans = plans.get("plans") or []
    checks.add("GET /v1/billing/plans answers a plan list",
               resp.status == 200 and isinstance(plans, list) and len(plans) >= 3,
               observed=f"status={resp.status} plans={len(plans) if isinstance(plans, list) else '?'} body={resp.text[:160]!r}",
               expected="200 with the catalog tiers", severity="P1",
               surface="api:GET /v1/billing/plans")
    price_ok = True
    detail = []
    for plan in plans if isinstance(plans, list) else []:
        if not isinstance(plan, dict):
            continue
        monthly = plan.get("priceMonthly") or plan.get("monthlyPrice") or plan.get("price_monthly") or plan.get("price")
        identifier = plan.get("id") or plan.get("planId") or plan.get("name")
        # `free` and `payg` carry a deliberate €0 base by design (the catalog
        # documents PAYG as per-email billing); every OTHER rung must carry a
        # positive monthly price. Match by NAME (the ids are DB-generated).
        name = str(plan.get("name") or "").lower()
        detail.append(f"{identifier}:{monthly}")
        if identifier and name not in ("free", "payg"):
            if not isinstance(monthly, (int, float)) or monthly <= 0:
                price_ok = False
    checks.add("every paid plan carries a positive price",
               price_ok, observed=f"plans={detail[:8]}",
               expected="positive numeric prices for paid tiers", severity="P1",
               surface="api:GET /v1/billing/plans")
    return checks.obs


@probe("p.money.quota_and_entitlements", "money", severity="P1",
       description="Quota/entitlements are honest; the documented plan override flips features and is restored")
def quota_and_entitlements(ctx):
    checks = Checks("p.money.quota_and_entitlements", "api:GET /v1/billing/quota")
    owner = ctx.identity("owner_a")
    quota = owner.session.get("/v1/billing/quota")
    body = quota.json() or {}
    data = body.get("data") or body
    limit = data.get("limit") or data.get("emailLimit")
    # The shipped quota shape carries `current` (with allowed/limit/
    # percent_used) — the probe previously looked only for `used` and read
    # None on a perfectly coherent snapshot.
    used = (
        data.get("used")
        or data.get("usedEmails")
        or data.get("emailsUsed")
        or data.get("current")
    )
    checks.add(
        "GET /v1/billing/quota answers a coherent snapshot",
        quota.status == 200 and isinstance(limit, (int, float)) and limit > 0 and isinstance(used, (int, float)) and used >= 0,
        observed=f"status={quota.status} limit={limit} used={used} body={quota.text[:160]!r}",
        expected="positive limit, non-negative usage", severity="P1",
        surface="api:GET /v1/billing/quota",
    )
    ent = owner.session.get("/v1/billing/entitlements")
    checks.add("GET /v1/billing/entitlements answers", ent.status == 200,
               observed=f"status={ent.status} body={ent.text[:160]!r}",
               expected="200 feature snapshot", severity="P1",
               surface="api:GET /v1/billing/entitlements")
    # documented override mechanism (the billing-admin path, applied as a DB
    # fixture) — exercised against a DIFFERENT plan, then restored to the
    # tenant's original plan (the fixture tenant runs on a paid plan; the
    # free-plan entitlement gates are asserted below).
    if ctx.db is not None and ctx.live_like() and owner.tenant_id:
        tenant = owner.tenant_id
        original = None
        try:
            original = ctx.db.scalar(f"SELECT plan FROM tenants WHERE id='{tenant}'") or "free"
        except Exception:  # noqa: BLE001
            original = None
        target = "scale" if original == "growth" else "growth"
        try:
            ctx.db._run(
                "INSERT INTO plan_overrides (tenant_id, plan, overridden_by, reason, active) "
                f"VALUES ('{tenant}', '{target}', 'dogfood-v2', 'lane D1 entitlement probe', true) "
                "ON CONFLICT DO NOTHING"
            )
            ctx.db._run(f"UPDATE tenants SET plan='{target}' WHERE id='{tenant}'")
            upgraded = owner.session.get("/v1/billing/entitlements")
            upgraded_text = upgraded.text.lower()
            checks.add(
                "the documented plan override is reflected in the entitlement snapshot",
                upgraded.status == 200 and target in upgraded_text,
                observed=f"status={upgraded.status} body={upgraded.text[:220]!r}",
                expected=f"the overridden plan ({target}) visible in the snapshot",
                severity="P1", surface="api:GET /v1/billing/entitlements",
            )
        finally:
            ctx.db._run(f"DELETE FROM plan_overrides WHERE tenant_id='{tenant}' AND overridden_by='dogfood-v2'")
            if original:
                ctx.db._run(f"UPDATE tenants SET plan='{original}' WHERE id='{tenant}'")
        restored = owner.session.get("/v1/billing/entitlements")
        checks.add("the override is restored after the probe",
                   restored.status == 200 and (not original or original in restored.text.lower()),
                   observed=f"restored={restored.status} body={restored.text[:160]!r}",
                   expected=f"200 back on the original plan ({original})",
                   surface="api:GET /v1/billing/entitlements", severity="P2")
        # the free-plan gate itself: custom_templates is a paid feature and the
        # gate must be a NAMED refusal, not a silent success.
        try:
            ctx.db._run(f"UPDATE tenants SET plan='free' WHERE id='{tenant}'")
            gated = owner.session.post("/v1/templates", {
                "name": f"dgv2-gate-{tenant[:8]}", "subject": "gate", "html_body": "<p>gate</p>",
            })
            named = gated.status == 403 and "custom_templates" in gated.text.lower()
            checks.add(
                "the free plan's custom_templates gate is a named 403",
                named,
                observed=f"status={gated.status} body={gated.text[:180]!r}",
                expected="403 naming custom_templates on the free plan",
                severity="P2", surface="api:POST /v1/templates",
            )
        finally:
            if original:
                ctx.db._run(f"UPDATE tenants SET plan='{original}' WHERE id='{tenant}'")
        final = owner.session.get("/v1/billing/entitlements")
        checks.add("the tenant plan is restored after the gate probe",
                   final.status == 200 and (not original or original in final.text.lower()),
                   observed=f"restored={final.status}",
                   expected="the fixture plan restored",
                   surface="api:GET /v1/billing/entitlements", severity="P2")
    return checks.obs


@probe("p.money.invoices_and_dedicated_ips", "money", severity="P2",
       description="Invoices are honest (empty for a fresh tenant); dedicated IPs refuse honestly when unconfigured")
def invoices_and_dedicated_ips(ctx):
    checks = Checks("p.money.invoices_and_dedicated_ips", "api:GET /v1/billing/invoices")
    owner = ctx.identity("owner_a")
    invoices = owner.session.get("/v1/billing/invoices")
    checks.add("GET /v1/billing/invoices answers 200", invoices.status == 200,
               observed=f"status={invoices.status} body={invoices.text[:160]!r}",
               expected="200 with an honest (possibly empty) list", severity="P2",
               surface="api:GET /v1/billing/invoices")
    ips = owner.session.post("/v1/dedicated-ips", {"region": "eu-central-1", "count": 1})
    honest_503 = ips.status == 503 and bool(ips.error_code())
    honest = ips.status in (200, 201, 202, 400, 403, 404, 409, 422) or honest_503
    checks.add(
        "a dedicated-IP request is an honest success or a named refusal (503 when unconfigured)",
        honest,
        observed=f"status={ips.status} body={ips.text[:180]!r}",
        expected="named refusal when provisioning is not configured",
        severity="P2", surface="api:POST /v1/dedicated-ips",
    )
    page = owner.session.get("/settings/dedicated-ips")
    checks.add("the dedicated IPs settings page renders", page.status == 200,
               observed=f"status={page.status}", expected="200",
               surface="ssr:web:GET /settings/dedicated-ips", severity="P2")
    return checks.obs
