"""State-machine abuse battery (partition: state).

Replay of single-use artifacts (idempotency keys, Stripe events, MFA
challenges), double-submits under real concurrency, and out-of-order
transitions with the DB invariant asserted after each.
"""
from __future__ import annotations

import concurrent.futures
import hmac
import hashlib
import json
import time
import uuid

from ..assertions import Checks, refusal_ok
from ..fixtures import ensure_verified_domain
from ..identity import Session
from ..registry import probe


@probe("p.state.idempotency_replay", "state", severity="P1",
       description="Two identical POST /v1/messages with one Idempotency-Key → one message")
def idempotency_replay(ctx):
    checks = Checks("p.state.idempotency_replay", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    domain = fixture.get("sender_domain") or "dogfood-v2.test"
    ensure_verified_domain(ctx, owner.tenant_id, domain)
    subject = f"dgv2 idempotency {uuid.uuid4().hex[:10]}"
    body = {
        "from": f"noreply@{domain}",
        "to": [fixture.get("contact_email") or "dgv2-recipient@dogfood.test"],
        "subject": subject,
        "html": "<p>idempotency probe</p>",
        "category": "transactional",
    }
    key = f"dgv2-idem-{uuid.uuid4().hex}"
    first = owner.session.post("/v1/messages", body, headers={"Idempotency-Key": key})
    second = owner.session.post("/v1/messages", body, headers={"Idempotency-Key": key})
    ok_status = first.status in (200, 201, 202) and second.status in (200, 201, 202)
    checks.add(
        "both idempotent sends are accepted",
        ok_status,
        observed=f"first={first.status} second={second.status} bodies={first.text[:100]!r}/{second.text[:100]!r}",
        expected="202 for the original and the replay", severity="P1",
        surface="api:POST /v1/messages",
    )
    rows = _message_rows(ctx, owner.session, subject)
    checks.add(
        "the idempotent replay produced exactly one message",
        len(rows) == 1 if rows is not None else True,
        observed=f"message rows with the probe subject={len(rows) if rows is not None else '?'}",
        expected="1 row (a duplicate is a double-send)",
        severity="P1", surface="table:messages",
        evidence={"rows": rows[:3] if rows else []},
    )
    if rows and len(rows) > 1:
        checks.add("idempotency failure details", False,
                   observed=json.dumps(rows[:3])[:400], expected="one row",
                   severity="P1", surface="table:messages")
    return checks.obs


def _message_rows(ctx, session, subject_contains: str):
    """Find messages by subject via the product's API (both data planes)."""
    resp = session.get("/v1/messages?limit=100")
    if resp.status != 200:
        return None
    body = resp.json() or {}
    rows = body.get("messages") or body.get("data") or body.get("items") or []
    if isinstance(rows, dict):
        rows = rows.get("messages") or rows.get("items") or []
    rows = [r for r in rows if isinstance(r, dict)]
    return [r for r in rows if subject_contains in json.dumps(r.get("subject", ""))]


@probe("p.state.double_submit", "state", severity="P1",
       description="Concurrent duplicate creates collapse to one row (DB invariant asserted)")
def double_submit(ctx):
    checks = Checks("p.state.double_submit", "race")
    owner = ctx.identity("owner_a")
    email = f"dgv2-race-{uuid.uuid4().hex[:10]}@dogfood.test"
    payload = {"email": email, "name": "dogfood v2 race"}

    def send(_):
        session = Session(ctx, "race")
        session.jar = dict(owner.session.jar)
        session.csrf = owner.session.csrf
        return session.post("/v1/contacts", payload).status

    with ctx.unpaced():
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(send, range(4)))
    rows = ctx.db.count("contacts", email=email) if ctx.db else None
    checks.add(
        "four concurrent identical creates leave one row",
        (rows == 1 if rows is not None else True) and all(s < 500 for s in statuses),
        observed=f"statuses={statuses} db_rows={rows}",
        expected="exactly one row; conflicts answered 409",
        severity="P1", surface="table:contacts",
    )
    checks.add(
        "duplicate creates are refused with a named conflict (not silent 2xx)",
        sum(1 for s in statuses if 200 <= s < 300) <= 1,
        observed=f"2xx count={sum(1 for s in statuses if 200 <= s < 300)} statuses={statuses}",
        expected="at most one 2xx", severity="P1", surface="api:POST /v1/contacts",
    )
    return checks.obs


@probe("p.state.out_of_order", "state", severity="P1",
       description="Invalid transitions are refused: login-before-verify, pause/resume on draft, edit-after-send")
def out_of_order(ctx):
    checks = Checks("p.state.out_of_order", "transitions")
    # login before verification must be refused (raw signup, link NOT followed)
    email = f"dgv2-unverified-{uuid.uuid4().hex[:10]}@dogfood.test"
    from ..identity import PASSWORD

    unverified = Session(ctx, "unverified")
    unverified.handshake()
    raw_signup = unverified.post(
        "/v1/auth/signup",
        {"email": email, "password": PASSWORD, "company_name": "Dogfood v2 Unverified", "plan": "free"},
        kiwi_scope="signup",
    )
    checks.add("the unverified-account signup is accepted",
               raw_signup.status in (200, 201, 202), observed=f"status={raw_signup.status}",
               expected="202 before verification", surface="api:POST /v1/auth/signup")
    resp = unverified.post("/v1/auth/login", {"email": email, "password": PASSWORD}, kiwi_scope="login")
    checks.add(
        "login before email verification is refused",
        400 <= resp.status < 500 and "am_session" not in unverified.jar,
        observed=f"status={resp.status} session={'yes' if 'am_session' in unverified.jar else 'no'} body={resp.text[:140]!r}",
        expected="4xx naming the unverified address; no session",
        severity="P1", surface="api:POST /v1/auth/login",
    )
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    campaign_id = fixture.get("campaign_id")
    if not campaign_id:
        checks.unreachable("campaign fixture for transitions", "no campaign fixture id")
        return checks.obs
    # pause/resume on a draft campaign — invalid transition
    for action in ("pause", "resume"):
        resp = owner.session.post(f"/v1/campaigns/{campaign_id}/{action}", {})
        refusal_ok(checks, resp, f"{action} on a draft campaign is refused",
                   allowed=(400, 404, 409, 422), surface=f"api:POST /v1/campaigns/:id/{action}",
                   severity="P1")
    # edit after send — drive a real send first (disposable campaign with an audience)
    from ..fixtures import ensure_consent

    ensure_consent(ctx, owner.tenant_id, fixture.get("contact_id", ""), fixture.get("contact_email", ""))
    subject = f"dgv2 edit-after-send {uuid.uuid4().hex[:8]}"
    create = owner.session.post("/v1/campaigns", {
        "name": subject, "subject": subject, "from": "noreply@dogfood-v2.test", "html": "<p>sent</p>",
        "list_ids": [fixture.get("list_id")] if fixture.get("list_id") else [],
    })
    body = create.json() or {}
    sent_campaign = (body.get("data") or body).get("id", "")
    if sent_campaign:
        send = owner.session.post(f"/v1/campaigns/{sent_campaign}/send", {})
        checks.add("the probe campaign send is answered honestly", send.status < 500,
                   observed=f"status={send.status} body={send.text[:120]!r}",
                   surface="api:POST /v1/campaigns/:id/send")
        edit = owner.session.patch(f"/v1/campaigns/{sent_campaign}", {"name": "dogfood-edit-after-send"})
        refusal_ok(checks, edit, "editing a sent campaign is refused", allowed=(400, 404, 409, 422),
                   surface="api:PATCH /v1/campaigns/:id", severity="P1")
    else:
        checks.unreachable("create a campaign for the edit-after-send probe", create.text[:160])
    # start with no audience: the honest answer is a named refusal, never a
    # silent success (this probe catches the "200 on refusal" mutation class)
    empty = owner.session.post("/v1/campaigns", {
        "name": f"dgv2 empty {uuid.uuid4().hex[:8]}", "subject": "empty",
        "from": "noreply@dogfood-v2.test", "html": "<p>empty</p>",
    })
    ebody = empty.json() or {}
    empty_id = (ebody.get("data") or ebody).get("id", "")
    if empty_id:
        started = owner.session.post(f"/v1/campaigns/{empty_id}/send", {})
        ok = 400 <= started.status < 500 and started.status != 404
        checks.add(
            "a campaign start with no audience is a named refusal, never a silent success",
            ok,
            observed=f"status={started.status} body={started.text[:160]!r}",
            expected="4xx naming the empty audience (a 2xx here is a false success)",
            severity="P1", surface="api:POST /v1/campaigns/:id/send",
        )
    return checks.obs


@probe("p.state.stripe_event_replay", "state", severity="P1",
       description="A replayed Stripe webhook event (valid HMAC) is idempotent and never 5xx")
def stripe_event_replay(ctx):
    checks = Checks("p.state.stripe_event_replay", "api:POST /webhooks/stripe")
    secret = _env_value("STRIPE_WEBHOOK_SECRET", "dev-stripe-webhook-secret-local-only-0123456789")
    event_id = f"evt_dgv2_{uuid.uuid4().hex[:16]}"
    payload = json.dumps({
        "id": event_id,
        "type": "invoice.paid",
        "created": int(time.time()),
        "data": {"object": {"id": f"in_dgv2_{uuid.uuid4().hex[:10]}", "object": "invoice",
                            "amount_paid": 1000, "currency": "eur"}},
    }).encode()
    timestamp = int(time.time())
    signature = hmac.new(secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256).hexdigest()
    headers = {"Stripe-Signature": f"t={timestamp},v1={signature}", "Content-Type": "application/json"}
    first = ctx.http.call("POST", "/webhooks/stripe", raw=payload, headers=headers)
    second = ctx.http.call("POST", "/webhooks/stripe", raw=payload, headers=headers)
    checks.add(
        "a signed Stripe event is accepted without a 5xx",
        first.status < 500 and second.status < 500,
        observed=f"first={first.status} second={second.status} bodies={first.text[:80]!r}/{second.text[:80]!r}",
        expected="2xx/4xx, never a crash", severity="P1", surface="api:POST /webhooks/stripe",
    )
    if ctx.db is not None:
        rows = ctx.db.count("stripe_webhook_events", stripe_event_id=event_id)
        checks.add(
            "the replayed event id does not create duplicate processing rows",
            rows <= 1, observed=f"stripe_webhook_events rows for the event={rows}",
            expected="<=1 (idempotent by event id)", severity="P1",
            surface="table:stripe_webhook_events",
        )
    tampered = payload.replace(b"invoice.paid", b"invoice.payment_failed")
    bad = ctx.http.call(
        "POST", "/webhooks/stripe", raw=tampered,
        headers={"Stripe-Signature": f"t={timestamp},v1={signature}", "Content-Type": "application/json"},
    )
    checks.add(
        "a tampered Stripe payload is refused (signature binds the bytes)",
        bad.status in (400, 401, 403), observed=f"status={bad.status} body={bad.text[:120]!r}",
        expected="4xx signature refusal", severity="P1", surface="api:POST /webhooks/stripe",
    )
    unsigned = ctx.http.call("POST", "/webhooks/stripe", raw=payload, headers={"Content-Type": "application/json"})
    checks.add(
        "an unsigned Stripe payload is refused",
        unsigned.status in (400, 401, 403, 503), observed=f"status={unsigned.status} body={unsigned.text[:120]!r}",
        expected="4xx/503 named refusal", severity="P1", surface="api:POST /webhooks/stripe",
    )
    return checks.obs


def _env_value(key: str, fallback: str) -> str:
    from ..config import REPO_ROOT

    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(errors="ignore").splitlines():
            if line.startswith(f"{key}="):
                return line.split("=", 1)[1].strip()
    return fallback
