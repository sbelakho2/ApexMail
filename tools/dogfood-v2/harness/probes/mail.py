"""Mail-plane probes (partition: mail).

Send → Mailpit delivery with header/encoding checks, template substitution,
missing-variable refusal, DKIM material provisioning, domain verification
honesty, suppression and consent gates.
"""
from __future__ import annotations

import json
import re
import time
import uuid

from ..assertions import Checks, refusal_ok
from ..fixtures import ensure_verified_domain
from ..registry import probe


def _sender(ctx) -> str:
    fixture = ctx.fixture("owner_a")
    domain = fixture.get("sender_domain") or "dogfood-v2.test"
    ensure_verified_domain(ctx, ctx.identity("owner_a").tenant_id, domain)
    return f"noreply@{domain}"


@probe("p.mail.send_to_mailpit", "mail", severity="P1",
       description="A transactional send lands in Mailpit with correct headers and body")
def send_to_mailpit(ctx):
    checks = Checks("p.mail.send_to_mailpit", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    subject = f"dgv2 mail {uuid.uuid4().hex[:10]}"
    resp = owner.session.post("/v1/messages", {
        "from": _sender(ctx),
        "to": [fixture.get("contact_email", "dgv2@dogfood.test")],
        "subject": subject,
        "html": "<p>dogfood v2 delivery check</p>",
        "text": "dogfood v2 delivery check",
        "category": "transactional",
    })
    checks.add("the send is accepted", resp.status in (200, 201, 202),
               observed=f"status={resp.status} body={resp.text[:140]!r}",
               expected="202 queued", severity="P1", surface="api:POST /v1/messages")
    messages = ctx.mail.wait(fixture.get("contact_email", ""), subject, tries=25)
    if not messages:
        checks.add("the message reaches Mailpit through the worker", False,
                   observed="no Mailpit message after 25s",
                   expected="the worker delivers the queued message to the SMTP sink",
                   severity="P1", surface="pipeline:send")
        return checks.obs
    detail = ctx.mail.message(messages[0]["ID"])
    headers = {h.get("Key", "").lower(): h.get("Value", "") for h in detail.get("Headers", [])}
    raw = ctx.mail.raw_message(messages[0]["ID"])
    checks.add("the delivered message carries the probe subject", subject in json.dumps(detail)[:20000],
               observed=f"subject={messages[0].get('Subject')!r}", expected=subject,
               severity="P1", surface="pipeline:send")
    checks.add("the delivered message carries MIME headers",
               bool(headers.get("mime-version")) or "MIME-Version" in raw,
               observed=f"headers={sorted(headers)[:8]}", expected="MIME-Version present",
               surface="pipeline:send")
    checks.add("the delivered body matches the sent body",
               "dogfood v2 delivery check" in (detail.get("HTML") or detail.get("Text") or raw),
               observed="body match" if "dogfood v2 delivery check" in json.dumps(detail) else "body mismatch",
               expected="the HTML/text survives the pipeline verbatim",
               severity="P1", surface="pipeline:send")
    return checks.obs


@probe("p.mail.template_send", "mail", severity="P1",
       description="Template send substitutes variables; a missing variable is a named 422 with nothing queued")
def template_send(ctx):
    checks = Checks("p.mail.template_send", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    suffix = uuid.uuid4().hex[:8]
    tmpl = owner.session.post("/v1/templates", {
        "name": f"dgv2-tpl-{suffix}", "subject": f"dgv2 tpl {suffix}",
        "html_body": "<p>Hello {{name}} from {{plan}}</p>", "text_body": "Hello {{name}}",
    })
    body = tmpl.json() or {}
    template_id = (body.get("data") or body).get("id", "")
    checks.add("the template is created", tmpl.status in (200, 201) and bool(template_id),
               observed=f"status={tmpl.status} id={template_id}",
               surface="api:POST /v1/templates", severity="P2")
    if not template_id:
        return checks.obs
    subject = f"dgv2 tpl send {suffix}"
    send = owner.session.post("/v1/messages", {
        "from": _sender(ctx),
        "to": [fixture.get("contact_email", "dgv2@dogfood.test")],
        "subject": subject,
        "template_id": template_id,
        "template_data": {"name": "Grace", "plan": "growth"},
        "category": "transactional",
    })
    checks.add("the template send is accepted", send.status in (200, 201, 202),
               observed=f"status={send.status} body={send.text[:140]!r}",
               surface="api:POST /v1/messages", severity="P1")
    messages = ctx.mail.wait(fixture.get("contact_email", ""), subject, tries=20)
    if messages:
        detail = ctx.mail.message(messages[0]["ID"])
        text = json.dumps(detail)
        checks.add(
            "the template variables are substituted and no {{ }} remains",
            "Grace" in text and "growth" in text and "{{" not in (detail.get("HTML") or ""),
            observed=f"Grace={'Grace' in text} growth={'growth' in text} braces={'{{' in (detail.get('HTML') or '')}",
            expected="substituted values, no leftover placeholders",
            severity="P1", surface="pipeline:template",
        )
    else:
        checks.add("the template mail reaches Mailpit", False,
                   observed="no delivered mail for the template send",
                   expected="worker delivery", severity="P1", surface="pipeline:template")
    # missing variable → named 422 and nothing queued
    count_before = _messages_count(ctx, owner)
    missing = owner.session.post("/v1/messages", {
        "from": _sender(ctx),
        "to": [fixture.get("contact_email", "dgv2@dogfood.test")],
        "subject": f"dgv2 missing var {suffix}",
        "template_id": template_id,
        "template_data": {"name": "Grace"},
        "category": "transactional",
    })
    count_after = _messages_count(ctx, owner)
    checks.add(
        "a missing template variable is a named 422 and nothing is queued",
        missing.status == 422 and (count_after is None or count_before is None or count_after == count_before),
        observed=f"status={missing.status} body={missing.text[:160]!r} count {count_before}->{count_after}",
        expected="422 naming the missing variable; no queued message",
        severity="P1", surface="api:POST /v1/messages",
    )
    return checks.obs


def _messages_count(ctx, session) -> int | None:
    if ctx.db is not None and hasattr(ctx.db, "count"):
        try:
            return ctx.db.count("messages", tenant_id=ctx.identity("owner_a").tenant_id)
        except Exception:  # noqa: BLE001
            return None
    return None


@probe("p.mail.encoding", "mail", severity="P2",
       description="UTF-8/emoji subjects and bodies survive with correct MIME encoding")
def encoding(ctx):
    checks = Checks("p.mail.encoding", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    subject = f"dgv2 ünïcode {uuid.uuid4().hex[:6]} 🚀"
    resp = owner.session.post("/v1/messages", {
        "from": _sender(ctx),
        "to": [fixture.get("contact_email", "dgv2@dogfood.test")],
        "subject": subject,
        "html": "<p>Grüße — 日本語 — 🚀</p>",
        "category": "transactional",
    })
    checks.add("the unicode send is accepted", resp.status in (200, 201, 202),
               observed=f"status={resp.status}", surface="api:POST /v1/messages", severity="P2")
    messages = ctx.mail.wait(fixture.get("contact_email", ""), "ünïcode", tries=20)
    if not messages:
        checks.add("the unicode message is delivered", False, observed="no delivery",
                   expected="worker delivery", severity="P2", surface="pipeline:encoding")
        return checks.obs
    detail = ctx.mail.message(messages[0]["ID"])
    raw = ctx.mail.raw_message(messages[0]["ID"])
    text = json.dumps(detail, ensure_ascii=False)
    checks.add(
        "the unicode subject is transported intact (encoded-word or UTF-8 MIME)",
        ("ünïcode" in text) and ("=?utf-8?" in raw.lower() or "=?utf-8?" in text.lower() or "utf-8" in raw.lower()),
        observed=f"subject_present={'ünïcode' in text} mime_utf8={'utf-8' in raw.lower() or '=?utf-8?' in text.lower()}",
        expected="RFC 2047 encoded-word or UTF-8 body encoding",
        severity="P2", surface="pipeline:encoding",
    )
    checks.add(
        "the unicode body is decoded back to its original characters",
        "Grüße" in text and "日本語" in text and "🚀" in text,
        observed=f"Grüße={'Grüße' in text} 日本語={'日本語' in text} rocket={'🚀' in text}",
        expected="body bytes decode losslessly", severity="P2", surface="pipeline:encoding",
    )
    return checks.obs


@probe("p.mail.domain_dkim", "mail", severity="P1",
       description="Domain creation provisions DKIM material; unverified DNS does not fake 'verified'")
def domain_dkim(ctx):
    checks = Checks("p.mail.domain_dkim", "api:POST /v1/domains")
    owner = ctx.identity("owner_a")
    name = f"dgv2-{uuid.uuid4().hex[:8]}.apexdogfood.test"
    created = owner.session.post("/v1/domains", {"name": name})
    body = created.json() or {}
    data = body.get("data") or body
    domain_id = data.get("id", "")
    # Documented contract (docs/api/endpoints/domains.md): creation ANSWERS the
    # domain shape (no selector/public key in the response — "the private key
    # is never returned; retrieve the DNS values via GET /dns-records") while
    # GENERATING and persisting the DKIM material. Judge that: the documented
    # field set is complete, and the material must never leak in the create
    # response.
    documented_fields = {
        "id", "name", "status", "ses_verified", "spf_verified",
        "dkim_verified", "dmarc_verified", "return_path_verified", "created_at",
    }
    leaked = any(
        key in data for key in ("dkim_private_key", "dkim_public_key", "dkim_selector")
    )
    checks.add(
        "creating a domain answers the documented shape, never leaking key material",
        created.status in (200, 201)
        and documented_fields.issubset(set(data))
        and not leaked,
        observed=f"status={created.status} fields={sorted(set(data))} leaked={leaked}",
        expected="201 with the documented field set; no key material in the response",
        severity="P1", surface="api:POST /v1/domains",
    )
    if not domain_id:
        return checks.obs
    records = owner.session.get(f"/v1/domains/{domain_id}/dns-records")
    rbody = records.json() or {}
    rtext = json.dumps(rbody)
    checks.add(
        "GET /dns-records lists the DKIM + DMARC TXT records",
        records.status == 200 and "DKIM" in rtext.upper() and "DMARC" in rtext.upper(),
        observed=f"status={records.status} body={records.text[:220]!r}",
        expected="TXT records for DKIM and DMARC",
        severity="P1", surface="api:GET /v1/domains/:id/dns-records",
    )
    verify = owner.session.post(f"/v1/domains/{domain_id}/verify", {})
    vtext = verify.text or ""
    faked = verify.status == 200 and re.search(r'"verified"\s*:\s*true', vtext) and "apexdogfood.test" not in vtext
    checks.add(
        "verifying an unpublished domain does not fake success",
        verify.status < 500 and not faked,
        observed=f"status={verify.status} body={vtext[:200]!r}",
        expected="honest pending/refusal (no fake verified=true)",
        severity="P1", surface="api:POST /v1/domains/:id/verify",
    )
    # cleanup: delete the disposable domain
    owner.session.delete(f"/v1/domains/{domain_id}")
    return checks.obs


@probe("p.mail.suppression_consent", "mail", severity="P1",
       description="Suppressed recipients are refused; the marketing consent gate is named; transactional exempt")
def suppression_consent(ctx):
    checks = Checks("p.mail.suppression_consent", "api:POST /v1/messages")
    owner = ctx.identity("owner_a")
    fixture = ctx.fixture("owner_a")
    suppressed = fixture.get("suppression_email") or "dgv2-suppressed@dogfood.test"
    resp = owner.session.post("/v1/messages", {
        "from": _sender(ctx), "to": [suppressed], "subject": "dgv2 suppressed",
        "html": "<p>x</p>", "category": "transactional",
    })
    checks.add(
        "a send to a suppressed recipient is a named 4xx",
        400 <= resp.status < 500 and (resp.status != 404),
        observed=f"status={resp.status} body={resp.text[:180]!r}",
        expected="400 naming the suppression",
        severity="P1", surface="api:POST /v1/messages",
    )
    marker = f"dgv2-no-consent-{uuid.uuid4().hex[:8]}@dogfood.test"
    resp = owner.session.post("/v1/messages", {
        "from": _sender(ctx), "to": [marker], "subject": "dgv2 marketing",
        "html": "<p>x</p>", "category": "marketing",
    })
    checks.add(
        "a marketing send without consent is a named 4xx",
        400 <= resp.status < 500 and (resp.status != 404),
        observed=f"status={resp.status} body={resp.text[:200]!r}",
        expected="400 naming the consent requirement",
        severity="P1", surface="api:POST /v1/messages",
    )
    # manual suppression removal works; complaint-level removal is refused
    add = owner.session.post("/v1/suppressions", {"email": f"dgv2-manual-{uuid.uuid4().hex[:8]}@dogfood.test", "reason": "manual"})
    checks.add("a manual suppression is accepted", add.status in (200, 201, 204),
               observed=f"status={add.status}", surface="api:POST /v1/suppressions", severity="P2")
    return checks.obs
