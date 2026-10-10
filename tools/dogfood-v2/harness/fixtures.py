"""Disposable resource fixtures — one unique set per tenant per run.

Every mutating probe works against these (unique ids, unique emails) so runs
are repeatable and never collide with other agents. State the probes change
is either restored or disposable by construction.
"""
from __future__ import annotations

import re
import time
import uuid

from .identity import Session
from .registry import Observation


def _suffix() -> str:
    return uuid.uuid4().hex[:10]


def _unwrap(resp) -> dict:
    body = resp.json() or {}
    if isinstance(body, dict) and isinstance(body.get("data"), dict):
        return body["data"]
    return body if isinstance(body, dict) else {}


def create_contact(ctx, session: Session, email: str, name: str = "Dogfood v2") -> dict:
    resp = session.post("/v1/contacts", {"email": email, "name": name, "tags": ["dogfood-v2"]})
    return {"status": resp.status, "body": _unwrap(resp), "ok": resp.status in (200, 201)}


def create_list(ctx, session: Session, name: str) -> dict:
    resp = session.post("/v1/lists", {"name": name, "description": "dogfood-v2 disposable"})
    body = _unwrap(resp)
    return {"status": resp.status, "id": body.get("id", ""), "ok": resp.status in (200, 201), "body": body}


def create_template(ctx, session: Session, name: str) -> dict:
    resp = session.post(
        "/v1/templates",
        {"name": name, "subject": "Dogfood {{name}}", "html_body": "<p>Hello {{name}}</p>",
         "text_body": "Hello {{name}}"},
    )
    body = _unwrap(resp)
    return {"status": resp.status, "id": body.get("id", ""), "ok": resp.status in (200, 201), "body": body}


def create_campaign(ctx, session: Session, name: str, **extra) -> dict:
    payload = {
        "name": name, "subject": "Dogfood v2 subject",
        "from": "dogfood@dogfood-v2.test", "html": "<p>dogfood v2</p>",
    }
    payload.update(extra)
    resp = session.post("/v1/campaigns", payload)
    body = _unwrap(resp)
    return {"status": resp.status, "id": body.get("id", ""), "ok": resp.status in (200, 201), "body": body}


def create_suppression(ctx, session: Session, email: str) -> dict:
    resp = session.post("/v1/suppressions", {"email": email, "reason": "manual"})
    return {"status": resp.status, "ok": resp.status in (200, 201, 204), "body": _unwrap(resp)}


def create_webhook(ctx, session: Session, url: str) -> dict:
    resp = session.post("/v1/webhooks", {"url": url, "events": ["campaign.completed"]})
    body = _unwrap(resp)
    return {"status": resp.status, "id": body.get("id", ""), "secret": body.get("secret", ""),
            "ok": resp.status in (200, 201), "body": body}


def create_api_key_full(ctx, session: Session, name: str) -> dict:
    resp = session.post("/v1/auth/api-keys", {"name": name, "scopes": ["*"]})
    body = _unwrap(resp)
    key = body.get("key") or body.get("api_key") or body.get("secret") or ""
    return {"status": resp.status, "key": key, "ok": resp.status in (200, 201) and bool(key), "body": body}


def ensure_verified_domain(ctx, tenant_id: str, name: str) -> str:
    """A verified sending domain for the pipeline probes (idempotent per run:
    `domains.name` is globally unique, so a second probe calling this for the
    same fixture name must NOT re-insert).

    Live: the product's OWN test-blessed DB fixture shape
    (`routes/messages.rs::insert_verified_domain`). Self-test: the fixture
    server's domain table.
    """
    marker = ctx.fixtures.setdefault("_domains", {})
    if name in marker:
        return marker[name]
    domain_id = str(uuid.uuid4())
    if ctx.cfg.mode == "self-test":
        ctx.fixture_verified_domain(tenant_id, name, domain_id)
        marker[name] = domain_id
        return domain_id
    if ctx.db is not None and hasattr(ctx.db, "_run"):
        safe = name.replace("'", "''")
        try:
            existing = ctx.db.scalar(f"SELECT id FROM domains WHERE name = '{safe}'")
        except Exception:  # noqa: BLE001
            existing = ""
        if existing:
            marker[name] = existing
            return existing
        ctx.db._run(
            "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified, "
            "dkim_selector, dkim_public_key, dkim_private_key) VALUES "
            f"('{domain_id}', '{tenant_id}', '{name}', 'verified', true, true, true, "
            "'dogfood-v2', 'dogfood-public', 'dkim:v1:test') ON CONFLICT (name) DO NOTHING"
        )
        marker[name] = domain_id
    return domain_id


def mail_for_recipient(ctx, recipient: str, subject_contains: str = "", tries: int = 20):
    return ctx.mail.wait(recipient, subject_contains, tries=tries)


def ensure_tenant_plan(ctx, identity_name: str, plan: str = "growth") -> None:
    """Put the fixture tenant on the paid plan the batteries exercise.

    A fresh signup lands on `free`, which does NOT include `custom_templates`,
    `advanced_analytics` or time-travel debugging — the functional probes for
    those surfaces need a plan that does. The plan change uses the same
    `tenants.plan` update the billing-admin path performs; the tenant is a
    disposable per-run signup, and the free-plan GATES themselves are asserted
    by the money partition (`p.money.quota_and_entitlements`)."""
    identity = ctx.identity(identity_name)
    marker = ctx.fixtures.setdefault("_plan", {})
    if marker.get(identity.tenant_id) == plan:
        return
    try:
        if ctx.cfg.mode == "self-test":
            ctx.fixture_plan(identity.tenant_id, plan)
        elif ctx.db is not None and hasattr(ctx.db, "_run"):
            ctx.db._run(f"UPDATE tenants SET plan = '{plan}' WHERE id = '{identity.tenant_id}'")
        marker[identity.tenant_id] = plan
    except Exception as error:  # noqa: BLE001
        marker[identity.tenant_id] = f"error: {error}"


def ensure_tenant_fixtures(ctx, identity_name: str, prefix: str) -> dict:
    """Create one disposable resource set for a tenant."""
    existing = ctx.fixtures.get(identity_name)
    if existing:
        return existing
    identity = ctx.identity(identity_name)
    ensure_tenant_plan(ctx, identity_name)
    session = identity.session
    suffix = _suffix()
    data: dict = {"suffix": suffix, "errors": []}

    def attempt(label: str, fn, *args):
        try:
            result = fn(*args)
        except Exception as error:  # noqa: BLE001
            data["errors"].append(f"{label}: {error}")
            return {"ok": False, "status": 0, "error": str(error)}
        if not result.get("ok"):
            data["errors"].append(f"{label}: status={result.get('status')}")
        return result

    contact = attempt("contact", create_contact, ctx, session, f"{prefix}-{suffix}@dogfood.test", f"{prefix} contact")
    contact2 = attempt("contact2", create_contact, ctx, session, f"{prefix}-2-{suffix}@dogfood.test", f"{prefix} contact 2")
    contact_hidden = attempt("contact_hidden", create_contact, ctx, session, f"{prefix}-hidden-{suffix}@dogfood.test", f"{prefix} hidden")
    lst = attempt("list", create_list, ctx, session, f"Dogfood v2 {prefix} {suffix}")
    template = attempt("template", create_template, ctx, session, f"Dogfood v2 {prefix} {suffix}")
    campaign = attempt("campaign", create_campaign, ctx, session, f"Dogfood v2 {prefix} campaign {suffix}")
    suppression = attempt(
        "suppression", create_suppression, ctx, session, f"suppressed-{prefix}-{suffix}@dogfood.test"
    )
    data.update(
        {
            "contact_id": contact.get("body", {}).get("id", ""),
            "contact_email": f"{prefix}-{suffix}@dogfood.test",
            "contact2_id": contact2.get("body", {}).get("id", ""),
            "contact2_email": f"{prefix}-2-{suffix}@dogfood.test",
            "contact_hidden_id": contact_hidden.get("body", {}).get("id", ""),
            "contact_hidden_email": f"{prefix}-hidden-{suffix}@dogfood.test",
            "list_id": lst.get("id", ""),
            "template_id": template.get("id", ""),
            "campaign_id": campaign.get("id", ""),
            "suppression_email": f"suppressed-{prefix}-{suffix}@dogfood.test",
            # hostname labels allow no underscores: identity names like
            # `owner_a` must be hyphenated or the sender address is invalid
            "sender_domain": f"dogfood-{prefix.replace('_', '-')}-{suffix}.test",
        }
    )
    if lst.get("id") and data.get("contact_id"):
        def _add_member():
            # live contract: POST /v1/lists/:id/subscribers {"contact_ids": [uuid]}
            response = session.post(
                f"/v1/lists/{lst['id']}/subscribers",
                {"contact_ids": [data["contact_id"]]},
            )
            return {"ok": response.status in (200, 201, 204), "status": response.status,
                    "body": response.text[:160]}

        attempt("list_member", _add_member)
    ctx.fixtures[identity_name] = data
    if data["errors"]:
        ctx.note(f"fixtures {identity_name}: {len(data['errors'])} create errors: {data['errors'][:3]}")
    return data


def fixtures_observation(probe_id: str, ctx, identity_name: str, surface: str) -> Observation:
    data = ctx.fixtures.get(identity_name, {})
    errors = data.get("errors", [])
    return Observation(
        probe_id=probe_id, surface=surface,
        title=f"fixture set for {identity_name} provisioned",
        ok=not errors,
        observed="; ".join(errors[:4]) or "all fixture creates succeeded",
        expected="every disposable fixture create succeeds through the product API",
        severity="P1", kind="unreachable" if errors else "check",
    )


def ensure_consent(ctx, tenant_id: str, contact_id: str, email: str) -> None:
    """Grant marketing consent for a fixture contact (the product's own
    consent gate needs an active consent_records row for campaign sends)."""
    marker = ctx.fixtures.setdefault("_consent", {})
    if marker.get(f"{email}:{tenant_id}") == "done":
        return
    marker[f"{email}:{tenant_id}"] = "pending"
    try:
        if ctx.cfg.mode == "self-test":
            ctx.fixture_consent(tenant_id, contact_id, email)
        elif ctx.db is not None and hasattr(ctx.db, "_run"):
            ctx.db._run(
                "INSERT INTO consent_records (id, tenant_id, subscriber_id, email, consent_type, "
                "granted, granted_at, source) VALUES "
                f"('{uuid.uuid4()}', '{tenant_id}', '{contact_id}', '{email}', 'marketing', true, "
                "now(), 'dogfood-v2 fixture') ON CONFLICT DO NOTHING"
            )
        marker[f"{email}:{tenant_id}"] = "done"
    except Exception as error:  # noqa: BLE001
        marker[f"{email}:{tenant_id}"] = f"error: {error}"


def ensure_campaign_delivery(ctx, identity_name: str = "owner_a") -> dict:
    """Drive a real campaign send to the fixture recipient and return the
    delivered mail plus the extracted tracking/unsubscribe links. Idempotent
    per run (cached under fixtures['_delivery'])."""
    cached = ctx.fixtures.get("_delivery")
    if cached:
        return cached
    data = ensure_tenant_fixtures(ctx, identity_name, identity_name)
    identity = ctx.identity(identity_name)
    session = identity.session
    ensure_verified_domain(ctx, identity.tenant_id, data.get("sender_domain", "dogfood-v2.test"))
    ensure_consent(ctx, identity.tenant_id, data.get("contact_id", ""), data.get("contact_email", ""))

    suffix = data.get("suffix", uuid.uuid4().hex[:8])
    subject = f"dgv2 campaign {suffix}"
    create = session.post("/v1/campaigns", {
        "name": f"dgv2 delivery {suffix}",
        "subject": subject,
        "from": f"noreply@{data.get('sender_domain', 'dogfood-v2.test')}",
        "html": '<p>dogfood v2 campaign</p><a href="https://example.com/dgv2-target">target</a>',
        "list_ids": [data.get("list_id")] if data.get("list_id") else [],
        "track_clicks": True, "track_opens": True,
    })
    body = create.json() or {}
    campaign_id = (body.get("data") or body).get("id", "")
    result = {"campaign_id": campaign_id, "subject": subject, "create_status": create.status,
              "messages": [], "click": "", "unsubscribe": "", "errors": []}
    if not campaign_id:
        result["errors"].append(f"campaign create failed: {create.status} {create.text[:200]}")
        ctx.fixtures["_delivery"] = result
        return result
    send = session.post(f"/v1/campaigns/{campaign_id}/send", {})
    result["send_status"] = send.status
    if send.status >= 400:
        result["errors"].append(f"campaign send refused: {send.status} {send.text[:200]}")
    messages = ctx.mail.wait(data.get("contact_email", ""), subject, tries=30)
    result["messages"] = messages
    if not messages and send.status < 300:
        # let the worker finish (workers poll)
        time.sleep(3)
        messages = ctx.mail.wait(data.get("contact_email", ""), subject, tries=15)
        result["messages"] = messages
    for message in messages:
        detail = ctx.mail.message(message["ID"])
        text = (detail.get("HTML") or "") + "\n" + (detail.get("Text") or "")
        links = re.findall(r"https?://[^\s\"'<>]+", text)
        for link in links:
            if "/c/" in link and not result["click"]:
                result["click"] = link
            if "/u/" in link and not result["unsubscribe"]:
                result["unsubscribe"] = link
        result["raw"] = ctx.mail.raw_message(message["ID"])[:4000]
        headers = {h.get("Key", "").lower(): h.get("Value", "") for h in detail.get("Headers", [])}
        result["list_unsubscribe"] = headers.get("list-unsubscribe", "")
        for link in re.findall(r"https?://[^\s\"'<>]+", result["list_unsubscribe"]):
            if "/u/" in link and not result["unsubscribe"]:
                result["unsubscribe"] = link
    ctx.fixtures["_delivery"] = result
    return result
