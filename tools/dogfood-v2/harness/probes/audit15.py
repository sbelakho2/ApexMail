"""External audit (15 Oct 2026) alignment probes.

The audit's three launch blockers, made executable:

  * H1 — a paid customer can cancel from the product and the next renewal is
    no longer charged (the old endpoints told the caller to use a billing
    portal that does not exist).
  * H2 — Adyen's legal facts (Adyen N.V., Netherlands/EU) on every legal
    surface in all four languages; no Stripe-era US/India claims.
  * H3 — the production compose + env can actually run an Adyen checkout
    (api-server holds the key/merchant/base URL; placeholders are not Stripe's).

The static arms call the same tools the validate stage runs, so CI and
dogfooding can never disagree about the facts.
"""
from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

from ..assertions import Checks
from ..config import REPO_ROOT
from ..registry import probe

# Stripe-era phrases the audit found on the legal pages (localized variants).
FORBIDDEN_LEGAL_PHRASES = (
    "us (primary)",
    "usa (primär)",
    "us (primair)",
    "india (support)",
    "indien (support)",
    "inde (support)",
    "india (soporte)",
    "inde (assistance)",
    "états-unis (principal)",
    "ee. uu. (principal)",
    "estados unidos (principal)",
    "us/india",
    "us/indien",
    "ee. uu./india",
    "états-unis/inde",
)
EU_FACT = ("netherlands", "niederlande", "países bajos", "pays-bas", "amsterdam")


def _load_tool(name: str):
    path = REPO_ROOT / "tools" / name
    spec = importlib.util.spec_from_file_location(f"audit15_{name[:-3]}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@probe(
    "p.marketing.processor_facts",
    "marketing",
    severity="P0",
    description="Adyen is described as the Dutch entity on every legal surface, all languages (audit 15 Oct H2)",
)
def processor_facts(ctx):
    checks = Checks("p.marketing.processor_facts", "marketing-legal-facts")
    tool = _load_tool("check_processor_facts.py")
    violations = []
    for surface in tool.SURFACES:
        path = REPO_ROOT / surface.relative_to(REPO_ROOT)
        if not path.exists():
            violations.append(f"missing {surface}")
            continue
        violations.extend(tool.check_text(path.read_text(encoding="utf-8")))
    checks.add(
        "every legal surface carries the canonical Adyen fact (NL/EU, no US/India)",
        not violations,
        observed=f"violations={violations[:4]}",
        expected="Adyen N.V., Netherlands (EU) on subprocessors/DPA/privacy/data-locations in all languages",
        severity="P0",
        surface="repo:legal-processor-facts",
    )

    # Live arms: the rendered pages must carry the same facts. Localized trees
    # live under /de/, /es/, /fr/ (Zola default language is en).
    for prefix in ("", "/de", "/es", "/fr"):
        for page in ("/subprocessors/", "/dpa/", "/privacy/", "/data-locations/"):
            path = f"{prefix}{page}" if prefix else page
            resp = ctx.http.get(path, host=ctx.cfg.marketing_host)
            body = (resp.text or "").lower()
            clean = resp.status == 200 and not any(
                phrase in body for phrase in FORBIDDEN_LEGAL_PHRASES
            )
            checks.add(
                f"rendered {path} contains no Stripe-era Adyen location",
                clean,
                observed=f"status={resp.status} len={len(resp.text or '')}",
                expected="200 and no US/India Adyen claims",
                severity="P0" if prefix == "" else "P1",
                surface=f"ssr:marketing:GET {path}",
            )
            if resp.status == 200 and "adyen" in body:
                checks.add(
                    f"rendered {path} states the EU entity for Adyen",
                    any(token in body for token in EU_FACT),
                    observed="EU fact present" if any(t in body for t in EU_FACT) else "EU fact absent",
                    expected="Netherlands/Amsterdam on the Adyen row",
                    severity="P1",
                    surface=f"ssr:marketing:GET {path}",
                )
    return checks.obs


@probe(
    "p.infra.prod_billing_wiring",
    "infra",
    severity="P0",
    description="Production compose/env can run an Adyen checkout (audit 15 Oct H3)",
)
def prod_billing_wiring(ctx):
    checks = Checks("p.infra.prod_billing_wiring", "infra-prod-billing")
    tool = _load_tool("check_prod_billing_wiring.py")
    compose = (REPO_ROOT / "docker-compose.prod.yml").read_text(encoding="utf-8")
    env = (REPO_ROOT / ".env.production.example").read_text(encoding="utf-8")
    problems = tool.check_compose(compose) + tool.check_env(env)
    checks.add(
        "api-server + billing-service + production env carry the Adyen checkout wiring",
        not problems,
        observed=f"problems={problems[:4]}",
        expected="ADYEN_API_KEY_FILE / ADYEN_MERCHANT_ACCOUNT / ADYEN_API_BASE_URL on api-server; no Stripe placeholders",
        severity="P0",
        surface="repo:prod-billing-wiring",
    )
    return checks.obs


@probe(
    "p.money.cancellation_self_service",
    "money",
    severity="P0",
    description="A paid customer can cancel from the product; the next renewal stops (audit 15 Oct H1)",
)
def cancellation_self_service(ctx):
    checks = Checks("p.money.cancellation_self_service", "api:POST /v1/billing/cancel")
    owner = ctx.identity("owner_a")
    tenant = owner.tenant_id or ""

    # The old contract told every caller to use a non-existent Adyen portal
    # (409 BILLING_PORTAL_REQUIRED). That response must be gone in every mode.
    response = owner.session.post(
        "/v1/billing/cancel",
        {"reason": "dogfood-v2 audit-15 probe", "cancelImmediately": False},
    )
    body = response.text or ""
    portal_lie = (
        response.status == 409
        or "BILLING_PORTAL_REQUIRED" in body
        or "billing portal" in body.lower()
    )
    checks.add(
        "POST /v1/billing/cancel does not require a non-existent billing portal",
        not portal_lie,
        observed=f"status={response.status} body={body[:200]!r}",
        expected="a local cancellation (200) or a coherent no-subscription refusal",
        severity="P0",
        surface="api:POST /v1/billing/cancel",
    )

    # The self-test fixture data plane is read-mostly and has no SQL runner;
    # the DB arms run in live/mutation modes (real Postgres). The no-portal-lie
    # check above still runs in every mode.
    if ctx.db is None or not tenant or not hasattr(ctx.db, "rows"):
        return checks.obs

    # Seed (or reuse) a subscription for the fixture tenant so the state
    # transition is real, then restore everything this probe touched.
    escaped = tenant.replace("'", "''")
    preexisting = ctx.db.rows(
        f"SELECT id, status, cancel_at_period_end, canceled_at::text "
        f"FROM adyen_subscriptions WHERE tenant_id = '{escaped}' "
        f"ORDER BY created_at DESC LIMIT 1"
    )
    created_id = None
    try:
        if not preexisting:
            # The fixture tenant is normally free; a paid plan is not needed
            # for the cancellation STATE CONTRACT (the row is what renewals
            # read), so seed a minimal active row.
            created_id = f"dgv2_{uuid.uuid4().simple()}"
            ctx.db._run(
                "INSERT INTO adyen_subscriptions "
                "(tenant_id, adyen_subscription_id, plan, status, billing_cycle_start, "
                " billing_cycle_end, adyen_shopper_reference) VALUES "
                f"('{escaped}', '{created_id}', 'growth', 'active', NOW(), "
                f"NOW() + INTERVAL '30 days', '{escaped}')"
            )
            subscription_id = created_id
        else:
            subscription_id = preexisting[0][0]
            sid = subscription_id.replace("'", "''")
            ctx.db._run(
                "UPDATE adyen_subscriptions SET status='active', cancel_at_period_end=false, "
                f"canceled_at=NULL WHERE id='{sid}'"
            )

        sid = subscription_id.replace("'", "''")
        response = owner.session.post(
            "/v1/billing/cancel",
            {"reason": "dogfood-v2 audit-15 probe", "cancelImmediately": False},
        )
        state = ctx.db.rows(
            "SELECT status, cancel_at_period_end, canceled_at::text "
            f"FROM adyen_subscriptions WHERE id='{sid}'"
        )
        row = state[0] if state else None
        checks.add(
            "cancellation records a period-end stop (cancel_at_period_end + canceled_at)",
            response.status == 200
            and row is not None
            and str(row[1]).lower() in ("t", "true")
            and row[2] is not None
            and row[0] == "active",
            observed=f"status={response.status} row={row} body={body[:200]!r}",
            expected="200; status active, cancel_at_period_end true, canceled_at set",
            severity="P0",
            surface="api:POST /v1/billing/cancel",
        )

        # A replay is idempotent and keeps the original cancellation instant.
        first_canceled_at = row[2] if row else None
        replay = owner.session.post(
            "/v1/billing/cancel",
            {"reason": "dogfood-v2 audit-15 probe", "cancelImmediately": False},
        )
        replay_state = ctx.db.rows(
            "SELECT cancel_at_period_end, canceled_at::text "
            f"FROM adyen_subscriptions WHERE id='{sid}'"
        )
        checks.add(
            "a cancellation replay is idempotent",
            replay.status == 200
            and replay_state
            and str(replay_state[0][0]).lower() in ("t", "true")
            and replay_state[0][1] == first_canceled_at,
            observed=f"status={replay.status} state={replay_state}",
            expected="200 and the same canceled_at",
            severity="P1",
            surface="api:POST /v1/billing/cancel",
        )
    finally:
        if created_id is not None:
            ctx.db._run(
                "DELETE FROM adyen_subscriptions "
                f"WHERE adyen_subscription_id = '{created_id}'"
            )
        elif preexisting:
            old = preexisting[0]
            old_id = old[0].replace("'", "''")
            old_status = (old[1] or "active").replace("'", "''")
            old_period_end = "true" if str(old[2]).lower() in ("t", "true") else "false"
            old_canceled = "NULL" if old[3] is None else "'" + old[3].replace("'", "''") + "'"
            ctx.db._run(
                "UPDATE adyen_subscriptions SET "
                f"status='{old_status}', cancel_at_period_end={old_period_end}, "
                f"canceled_at={old_canceled} WHERE id='{old_id}'"
            )
    return checks.obs
