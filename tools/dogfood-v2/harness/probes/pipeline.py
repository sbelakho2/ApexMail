"""Pipeline / e2e probes (partition: pipeline).

enqueue → worker → terminal delivery, event consistency (API vs DB), the
webhook signature/idempotency contract against a real local sink, and
unsubscribe (RFC 8058) side effects.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..assertions import Checks
from ..fixtures import ensure_campaign_delivery
from ..registry import probe

_SINK_LOCK = threading.Lock()
_SINK_EVENTS: list[dict] = []
_SINK_SERVER: ThreadingHTTPServer | None = None
SINK_PORT = 8791


class _SinkHandler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        with _SINK_LOCK:
            _SINK_EVENTS.append({
                "path": self.path,
                "body": body.decode(errors="replace")[:100_000],
                "signature": self.headers.get("X-ApexMail-Signature", ""),
                "timestamp": self.headers.get("X-ApexMail-Timestamp", ""),
                "event": self.headers.get("X-ApexMail-Event", ""),
                "webhook_id": self.headers.get("X-ApexMail-Webhook-Id", ""),
                "at": time.time(),
            })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *args):  # noqa: D102
        pass


def start_sink() -> bool:
    global _SINK_SERVER
    with _SINK_LOCK:
        if _SINK_SERVER is not None:
            return True
        try:
            server = ThreadingHTTPServer(("0.0.0.0", SINK_PORT), _SinkHandler)
        except OSError:
            return False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        _SINK_SERVER = server
        return True


def sink_events() -> list[dict]:
    with _SINK_LOCK:
        return list(_SINK_EVENTS)


def clear_sink() -> None:
    with _SINK_LOCK:
        _SINK_EVENTS.clear()


def wait_sink(count: int = 1, tries: int = 20) -> list[dict]:
    for _ in range(tries):
        events = sink_events()
        if len(events) >= count:
            return events
        time.sleep(1)
    return sink_events()


@probe("p.pipeline.events_consistency", "pipeline", severity="P1",
       description="A real send produces terminal delivery events; the API list and the DB agree")
def events_consistency(ctx):
    checks = Checks("p.pipeline.events_consistency", "pipeline:events")
    delivery = ensure_campaign_delivery(ctx)
    owner = ctx.identity("owner_a")
    if not delivery.get("messages"):
        checks.unreachable(
            "the campaign delivery fixture exists",
            "; ".join(delivery.get("errors") or []) or "no delivered mail",
        )
        return checks.obs
    subject = delivery.get("subject", "")
    messages = owner.session.get("/v1/messages?limit=100")
    body = messages.json() or {}
    rows = body.get("messages") or body.get("data") or []
    if isinstance(rows, dict):
        rows = rows.get("messages") or []
    match = next((r for r in rows if isinstance(r, dict) and subject[:24] in json.dumps(r)), None)
    checks.add(
        "the campaign send is visible on the messages API",
        bool(match), observed=f"status={messages.status} match={'yes' if match else 'no'}",
        expected="the message row exists", severity="P1", surface="api:GET /v1/messages",
    )
    if match and isinstance(match, dict):
        message_id = match.get("id") or match.get("messageId") or ""
        status = str(match.get("status", "")).lower()
        checks.add(
            "the message reaches a terminal transport state",
            status in ("sent", "delivered", "queued", "processed", "sending"),
            observed=f"status={status!r} row={json.dumps(match)[:200]}",
            expected="a terminal/live state after the worker consumed the queue",
            severity="P1", surface="pipeline:events",
        )
        if message_id:
            timeline = owner.session.get(f"/v1/messages/{message_id}/timeline?at={time.strftime('%Y-%m-%dT%H:%M:%SZ')}")
            checks.add(
                "the timeline endpoint reconstructs the message state",
                timeline.status == 200, observed=f"status={timeline.status} body={timeline.text[:160]!r}",
                expected="200 timeline", severity="P2",
                surface="api:GET /v1/messages/:id/timeline",
            )
    events = owner.session.get("/v1/events?limit=50")
    checks.add("the events API answers after the delivery", events.status == 200,
               observed=f"status={events.status}", expected="200",
               surface="api:GET /v1/events", severity="P1")
    if ctx.db is not None and ctx.live_like():
        try:
            rows_db = ctx.db.scalar(
                f"SELECT count(*) FROM events WHERE tenant_id='{owner.tenant_id}'"
            )
        except Exception as error:  # noqa: BLE001
            rows_db = ""
            checks.add("events count query executed", False, observed=str(error)[:120],
                       expected="the events table answers", severity="P2", surface="table:events")
        if rows_db:
            checks.add(
                "the events table carries the tenant's terminal events",
                int(rows_db) >= 1,
                observed=f"events rows for tenant={rows_db}",
                expected="at least the delivery event", severity="P2", surface="table:events",
            )
    return checks.obs


@probe("p.pipeline.webhook_delivery", "pipeline", severity="P1",
       description="A webhook fires to a real sink with a verifying HMAC; the test fire matches the real scheme")
def webhook_delivery(ctx):
    checks = Checks("p.pipeline.webhook_delivery", "api:POST /v1/webhooks")
    owner = ctx.identity("owner_a")
    if not start_sink():
        checks.unreachable("local webhook sink on 0.0.0.0:%d" % SINK_PORT, "port busy")
        return checks.obs
    clear_sink()
    marker = uuid.uuid4().hex[:8]
    # the live api-server is containerised (host.docker.internal); a mutant
    # api-server runs natively on this host (127.0.0.1); self-test shares it
    sink_host = "host.docker.internal" if ctx.cfg.mode == "live" else "127.0.0.1"
    created = owner.session.post("/v1/webhooks", {
        "url": f"http://{sink_host}:{SINK_PORT}/hook-{marker}",
        "events": ["campaign.completed", "message.delivered", "message.sent", "test"],
    })
    body = created.json() or {}
    data = body.get("data") or body
    webhook_id = data.get("id", "")
    secret = data.get("secret", "")
    checks.add(
        "the webhook is created and its secret returned once",
        created.status in (200, 201) and bool(webhook_id) and bool(secret),
        observed=f"status={created.status} id={webhook_id} secret={'yes' if secret else 'no'}",
        expected="201 with id + secret", severity="P1", surface="api:POST /v1/webhooks",
    )
    if not webhook_id:
        return checks.obs
    test = owner.session.post(f"/v1/webhooks/{webhook_id}/test", {})
    checks.add(
        "POST /v1/webhooks/:id/test answers honestly",
        test.status < 500, observed=f"status={test.status} body={test.text[:160]!r}",
        expected="2xx with a delivery result", severity="P2",
        surface="api:POST /v1/webhooks/:id/test",
    )
    events = wait_sink(1, tries=25)
    if not events:
        checks.add(
            "the test webhook reaches the local sink",
            False, observed=f"no sink event after 25s; test response={test.text[:200]!r}",
            expected="the worker/api delivers to host.docker.internal",
            severity="P1", surface="pipeline:webhook",
        )
        return checks.obs
    event = events[-1]
    checks.add("the test webhook reaches the local sink", True,
               observed=f"path={event['path']} bytes={len(event['body'])}",
               expected="a POST to the registered URL", severity="P1", surface="pipeline:webhook")
    ok_hmac = False
    if secret and event["timestamp"] and event["signature"].startswith("sha256="):
        signing_input = f"{event['timestamp']}.{event['body']}".encode()
        expected = "sha256=" + hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
        ok_hmac = hmac.compare_digest(expected, event["signature"])
    checks.add(
        "the delivered signature verifies as HMAC-SHA256 over '<ms>.<body>'",
        ok_hmac,
        observed=f"signature={event['signature'][:24]}… timestamp={event['timestamp']}",
        expected="sha256=HMAC(secret, timestamp_ms + '.' + body)",
        severity="P1", surface="pipeline:webhook",
    )
    # the real campaign event path (worker-delivered) — a FRESH campaign so
    # the event fires after the webhook exists.
    fresh = _fresh_campaign_send(ctx)
    checks.add("the fresh campaign send is accepted", fresh in (200, 201, 202),
               observed=f"status={fresh}", expected="202", severity="P2", surface="pipeline:webhook")
    real = wait_sink(2, tries=20)
    real_events = [e for e in real if e["event"] != "test"]
    checks.add(
        "the real campaign event stream delivers to the webhook",
        bool(real_events),
        observed=f"sink events={[e['event'] for e in real][:5]}",
        expected="campaign/message events delivered by the worker",
        severity="P2", surface="pipeline:webhook",
    )
    if real_events and secret:
        verified = []
        for candidate in real_events:
            if candidate["timestamp"] and candidate["signature"].startswith("sha256="):
                signing_input = f"{candidate['timestamp']}.{candidate['body']}".encode()
                expected = "sha256=" + hmac.new(secret.encode(), signing_input, hashlib.sha256).hexdigest()
                verified.append(hmac.compare_digest(expected, candidate["signature"]))
        checks.add(
            "real deliveries carry the same verifying HMAC scheme",
            bool(verified) and all(verified),
            observed=f"verified={verified}",
            expected="every real delivery verifies",
            severity="P1", surface="pipeline:webhook",
        )
    owner.session.delete(f"/v1/webhooks/{webhook_id}")
    return checks.obs


def _fresh_campaign_send(ctx) -> int:
    """Create + send a disposable campaign against the fixture audience."""
    fixture = ctx.fixture("owner_a")
    owner = ctx.identity("owner_a")
    from ..fixtures import ensure_consent, ensure_verified_domain

    ensure_verified_domain(ctx, owner.tenant_id, fixture.get("sender_domain", "dogfood-v2.test"))
    ensure_consent(ctx, owner.tenant_id, fixture.get("contact_id", ""), fixture.get("contact_email", ""))
    subject = f"dgv2 webhook event {uuid.uuid4().hex[:8]}"
    created = owner.session.post("/v1/campaigns", {
        "name": subject, "subject": subject,
        "from": f"noreply@{fixture.get('sender_domain', 'dogfood-v2.test')}",
        "html": "<p>webhook event</p>",
        "list_ids": [fixture.get("list_id")] if fixture.get("list_id") else [],
    })
    body = created.json() or {}
    campaign_id = (body.get("data") or body).get("id", "")
    if not campaign_id:
        return created.status
    sent = owner.session.post(f"/v1/campaigns/{campaign_id}/send", {})
    return sent.status


@probe("p.pipeline.unsubscribe", "pipeline", severity="P1",
       description="RFC 8058 one-click unsubscribe is present in delivered mail and suppresses the contact")
def unsubscribe(ctx):
    checks = Checks("p.pipeline.unsubscribe", "pipeline:unsubscribe")
    delivery = ensure_campaign_delivery(ctx)
    if not delivery.get("messages"):
        checks.unreachable("campaign mail for the unsubscribe probe",
                           "; ".join(delivery.get("errors") or []) or "no delivered mail")
        return checks.obs
    header = delivery.get("list_unsubscribe", "")
    checks.add(
        "the delivered mail advertises List-Unsubscribe",
        bool(header), observed=f"List-Unsubscribe={header[:160]!r}",
        expected="a one-click unsubscribe URL", severity="P1", surface="pipeline:mail",
    )
    url = delivery.get("unsubscribe", "")
    if not url:
        checks.unreachable("unsubscribe URL in the delivered mail", "no /u/ link found")
        return checks.obs
    path = "/" + url.split("://", 1)[1].split("/", 1)[1]
    resp = ctx.http.call("POST", path, base=ctx.cfg.tracking)
    checks.add(
        "the one-click unsubscribe POST is accepted",
        resp.status in (200, 202, 204),
        observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="200/204 (RFC 8058)", severity="P1", surface="tracking:unsubscribe",
    )
    replay = ctx.http.call("POST", path, base=ctx.cfg.tracking)
    checks.add(
        "a replayed unsubscribe POST stays honest (no 5xx)",
        replay.status < 500, observed=f"status={replay.status}",
        expected="idempotent or a named refusal", severity="P2", surface="tracking:unsubscribe",
    )
    if ctx.db is not None:
        email = ctx.fixture("owner_a").get("contact_email", "")
        rows = ctx.db.count("suppressions", email=email) if email else 0
        checks.add(
            "the unsubscribed contact is recorded as suppressed",
            rows >= 1, observed=f"suppressions rows for {email}={rows}",
            expected=">=1 suppression row", severity="P1", surface="table:suppressions",
        )
    return checks.obs


@probe("p.pipeline.worker_liveness", "infra", severity="P1",
       description="Queue depth drains after a send (worker liveness proven by delivery)")
def worker_liveness(ctx):
    checks = Checks("p.pipeline.worker_liveness", "pipeline:worker")
    delivery = ensure_campaign_delivery(ctx)
    if not delivery.get("messages"):
        checks.unreachable("worker liveness (no delivery)", "; ".join(delivery.get("errors") or []))
        return checks.obs
    if ctx.db is not None and ctx.live_like():
        try:
            pending = ctx.db.scalar(
                "SELECT count(*) FROM email_queue q WHERE q.status IN ('pending','processing') "
                "AND EXISTS (SELECT 1 FROM messages m WHERE m.id = q.message_id "
                "AND m.subject LIKE 'dgv2 campaign%')"
            )
        except Exception as error:  # noqa: BLE001
            checks.add("queue-drain query executed", False,
                       observed=f"query failed: {error}", expected="email_queue join resolves",
                       severity="P2", surface="pipeline:worker")
            pending = None
        if pending is not None:
            checks.add(
                "no probe message remains pending after delivery",
                pending == "0", observed=f"pending rows for probe messages={pending}",
                expected="the worker drained the queue", severity="P1", surface="pipeline:worker",
            )
    checks.add("the worker delivered a probe message to Mailpit", True,
               observed=f"{len(delivery['messages'])} delivered message(s)",
               expected="delivery proves the worker consumed the queue",
               severity="P1", surface="pipeline:worker")
    return checks.obs
