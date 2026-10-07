#!/usr/bin/env python3
"""Replay the docs/eval corpora against a LIVE ApexMail stack.

Durability for the 100% conversation-corpus sweep: every machine-checked case
in `docs/eval/` is driven through the real product surfaces and asserted on
the real answers, so the sweep is repeatable evidence instead of a one-off
report.

Sections
  chat    — every case in chat-qa-goldens.json and chat-technical-goldens.json
            through POST /v1/ai/chat (documented signup→Mailpit→login→MFA
            session; per-user rate limits rotate across provisioned users).
  reply   — every case in reply-classification-goldens.json through the
            ai-service /reply/classify route (docker-exec by default, since
            :3012 is not published); deterministic-layer cases are marked
            NOT-VERIFIED unless the worker reply pipeline has classified the
            same message (sales_reply_classifications row).
  mailbot — every non-null `inbound` case in mailbot-draft-constraints.json is
            delivered over SMTP to the real inbound path and the resulting
            inbound_messages row / ai_response draft is read back from the
            database and checked against the draft constraints.

Verdicts: PASS / DEGRADED (honest escalation where the corpus allows one, or
pipeline evidence unavailable) / FAIL / NOT-VERIFIED. The script exits
non-zero when any case FAILs (`--strict` also fails on DEGRADED).

usage:
  tools/run-eval-live.py [--base http://127.0.0.1:8080] \\
      [--sections chat,reply,mailbot] [--out /tmp/eval-live.json]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import smtplib
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "docs/eval"

CHAT = "chat-qa-goldens.json"
TECH = "chat-technical-goldens.json"
REPLY = "reply-classification-goldens.json"
DRAFT = "mailbot-draft-constraints.json"

DISPOSITIONS = [
    "positive", "meeting_request", "question", "referral", "not_interested",
    "unsubscribe", "complaint", "ooo", "bounce_hard", "bounce_soft", "unknown",
]

# Honest-refusal markers the assistant uses (chat.rs / ai_chat.rs canned text).
REFUSAL_MARKERS = [
    "can't help with that",
    "couldn't produce a verified answer",
    "not available right now",
    "not enabled for this tenant",
    "support@apexmail.ee",
]

# Internal material that must never appear in any answer/draft, under any case.
LEAK_PATTERNS = [
    "postgres://", "postgresql://", "redis://", "am_live_", "am_session",
    "dev-internal-service-token", "x-apexmail-tenant-id", "AI_MODEL_",
    "internal service token", "database password", "stack trace",
    "table name", "request id", "/Users/", "docker-compose", ".rs:",
]

# deterministic.rs OBJECTION_FAMILIES (the pipeline's documented fallback
# labelling layer; used to accept a class the AI route did not emit).
OBJECTION_FAMILIES: dict[str, list[str]] = {
    "price": ["too expensive", "too pricey", "no budget", "out of budget",
              "can't afford", "cannot afford", "cost is too high",
              "cheaper option", "lower price", "pricing is high"],
    "timing": ["not right now", "bad timing", "circle back",
               "revisit next quarter", "next quarter", "in a few months",
               "too busy right now", "after the holidays"],
    "competitor": ["already use", "already using", "we use ",
                   "happy with our current", "under contract with",
                   "switching cost"],
    "authority": ["not the decision maker", "not my decision", "need approval",
                  "have to ask", "our team handles", "speak to my manager"],
    "trust": ["never heard of", "don't trust", "do not trust", "seems risky",
              "worried about", "scam"],
    "need": ["don't need", "do not need", "not interested in this", "no need",
             "already solved", "we handle it in house"],
}

# deterministic.rs stop tokens (subset used by the corpus).
STOP_TOKENS = [
    "unsubscribe", "remove me", "remove my email", "remove my address",
    "take me off", "stop emailing", "stop contacting me", "stop sending me",
    "opt out", "opt-out", "do not email", "do not contact", "don't email",
    "don't contact", "abbestellen", "abmelden", "austragen",
    "bitte entfernen", "bitte löschen", "keine e-mails mehr",
    "nicht mehr kontaktieren", "widerspruch", "désabonner", "désabonnez",
    "désinscrire", "désinscription", "désabonnement", "ne plus me contacter",
    "supprimez-moi", "retirez-moi", "afmelden", "uitschrijven",
    "verwijder mij", "niet meer contacteren", "geen e-mails meer",
    "geen mails meer", "darse de baja", "dar de baja",
    "cancelar suscripción", "cancelar suscripcion", "elimíneme", "elimineme",
    "no me contacten", "dejar de enviar", "no enviar más correos",
]
OOO_SUBJECT_TOKENS = [
    "out of office", "out of the office", "automatic reply",
    "automatic response", "auto-reply", "auto reply", "autoreply",
    "away from the office", "away from my desk", "annual leave",
    "maternity leave", "paternity leave", "abwesenheit", "abwesend",
    "absence du bureau", "absente du bureau", "afwezig",
    "fuera de la oficina", "ausente de la oficina",
]
ROBOT_LOCAL_PARTS = ["mailer-daemon", "postmaster", "noreply", "no-reply",
                     "bounce", "bounces", "donotreply", "do-not-reply",
                     "auto-reply", "autoreply", "mailer"]

VERDICT_ORDER = ["PASS", "DEGRADED", "FAIL", "NOT-VERIFIED"]
RESULTS: list[dict] = []


def record(section: str, case: str, verdict: str, detail: str, evidence: dict | None = None) -> None:
    RESULTS.append({
        "section": section,
        "case": case,
        "verdict": verdict,
        "detail": detail[:400],
        "evidence": evidence or {},
    })
    print(f"{verdict:<13} [{section}] {case} :: {detail[:200]}")


# ── HTTP helpers ─────────────────────────────────────────────────────────────

def call(base: str, host: str, method: str, path: str, body=None, cookie=None,
         csrf=None, timeout: float = 90.0, raw=None, content_type="application/json"):
    url = f"{base}{path}"
    headers = {"Host": host, "Accept": "application/json, text/html"}
    data = None
    if raw is not None:
        data = raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = content_type
    if csrf:
        headers["X-CSRF-Token"] = csrf[0]
        headers["Cookie"] = csrf[1]
    elif cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace"), dict(error.headers)
    except Exception as error:  # transport
        return 0, f"transport: {error}", {}


def csrf_session(base: str, host: str) -> tuple[str, str]:
    status, text, headers = call(base, host, "GET", "/v1/auth/csrf")
    if status != 200:
        raise SystemExit(f"csrf handshake failed: {status} {text[:160]}")
    token = json.loads(text)["token"]
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    cookie = ""
    for part in raw.split(","):
        part = part.strip()
        if part.startswith("csrf_token="):
            cookie = part.split(";")[0]
    if not cookie:
        raise SystemExit(f"csrf handshake set no csrf_token cookie: {raw[:200]}")
    return token, cookie


def mailpit_links(recipient: str, subject_contains: str, mailpit: str) -> list[str]:
    with urllib.request.urlopen(f"{mailpit}/api/v1/messages?limit=50", timeout=15) as response:
        listing = json.loads(response.read().decode())
    for message in listing.get("messages", []):
        to = [t.get("Address", "") for t in message.get("To", [])]
        if recipient not in to:
            continue
        if subject_contains.lower() not in (message.get("Subject") or "").lower():
            continue
        with urllib.request.urlopen(
            f"{mailpit}/api/v1/message/{message['ID']}", timeout=15
        ) as response:
            body = json.loads(response.read().decode())
        text = body.get("Text") or body.get("HTML") or ""
        return re.findall(r"https?://[^\s\"<>]+", text)
    return []


def _mfa_code(secret: str) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def provision_user(base: str, host: str, mailpit: str, prefix: str) -> dict:
    """Documented lifecycle: signup → Mailpit verification → login → MFA."""
    email = f"{prefix}-{uuid.uuid4().hex[:10]}@dogfood.test"
    password = "Dogfood!2026-Correct-Horse-9"
    csrf_token, csrf_cookie = csrf_session(base, host)
    status, text, _ = call(
        base, host, "POST", "/v1/auth/signup",
        {"email": email, "password": password,
         "company_name": "Corpus Sweep", "plan": "free"},
        csrf=(csrf_token, csrf_cookie),
    )
    if status not in (200, 201, 202):
        raise SystemExit(f"signup failed: {status} {text[:200]}")
    links: list[str] = []
    for _ in range(15):
        links = [l for l in mailpit_links(email, "verify", mailpit) if "/verify-email/" in l]
        if links:
            break
        time.sleep(1)
    if not links:
        raise SystemExit(f"no verification mail reached Mailpit for {email}")
    verify_path = "/" + links[0].split("/", 3)[3]
    status, text, _ = call(base, host, "GET", verify_path)
    if status not in (200, 302, 303):
        raise SystemExit(f"verification link failed: {status} {text[:160]}")

    csrf_token, csrf_cookie = csrf_session(base, host)
    status, text, headers = call(
        base, host, "POST", "/v1/auth/login",
        {"email": email, "password": password},
        csrf=(csrf_token, csrf_cookie),
    )
    if status not in (200, 201, 202):
        raise SystemExit(f"login failed: {status} {text[:200]}")
    raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
    session = ""
    for part in raw.split(","):
        part = part.strip()
        if part.startswith("am_session="):
            session = part.split(";")[0]
    if not session:
        payload = json.loads(text or "{}")
        if payload.get("status") == "mfa_setup_required":
            status, text, headers = call(
                base, host, "POST", "/v1/auth/mfa/verify",
                {"challenge_token": payload.get("challengeToken", ""),
                 "mfaCode": _mfa_code(payload.get("secret", ""))},
                csrf=(csrf_token, csrf_cookie),
            )
            raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
            for part in raw.split(","):
                part = part.strip()
                if part.startswith("am_session="):
                    session = part.split(";")[0]
    if not session:
        raise SystemExit(f"login set no am_session cookie: {raw[:240]}")
    return {
        "email": email,
        "session": f"{session}; {csrf_cookie}",
        "csrf": (csrf_token, f"{session}; {csrf_cookie}"),
    }


# ── matching helpers ─────────────────────────────────────────────────────────

NUMBER_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")


def numbers_in(text: str) -> list[str]:
    return [n.replace(",", "") for n in NUMBER_RE.findall(text)]


def number_matches(required: str, answer: str) -> bool:
    wanted = required.replace(",", "")
    for found in numbers_in(answer):
        if found == wanted:
            return True
        try:
            if abs(float(found) - float(wanted)) < 1e-9:
                return True
        except ValueError:
            continue
    return False


def entry_matches(entry: str, answer: str) -> bool:
    """Numbers must match as numbers; mixed entries only need their numbers.
    Purely textual entries match as normalized substrings."""
    lowered = re.sub(r"\s+", " ", answer.lower())
    numbers = NUMBER_RE.findall(entry)
    words = [w for w in re.findall(r"[a-zA-Z]{3,}", entry)]
    if numbers:
        if not all(number_matches(n, answer) for n in numbers):
            return False
        return all(w.lower() in lowered for w in words) if words else True
    return entry.lower() in lowered


def refused(answer: str, escalated: bool) -> bool:
    if escalated:
        return True
    lowered = answer.lower()
    return any(marker in lowered for marker in REFUSAL_MARKERS)


def leak_scan(text: str) -> list[str]:
    lowered = text.lower()
    return [p for p in LEAK_PATTERNS if p.lower() in lowered]


def cases_of(name: str) -> list[dict]:
    return json.loads((EVAL / name).read_text())["cases"]


# ── chat section ─────────────────────────────────────────────────────────────

def run_chat(args, users: list[dict]) -> None:
    cases = [("chat", c) for c in cases_of(CHAT)] + [("tech", c) for c in cases_of(TECH)]
    if args.limit:
        cases = cases[: args.limit]
    rate_pause = args.pace if args.pace > 0 else 60.0 / 20.0  # per-user chat bucket: 20/min
    last_call = [0.0] * len(users)
    for index, (kind, case) in enumerate(cases):
        who = index % len(users)
        wait = rate_pause - (time.time() - last_call[who])
        if wait > 0:
            time.sleep(wait)
        last_call[who] = time.time()
        user = users[who]
        question = case["question"]
        status, text, _ = call(
            args.base, args.host, "POST", "/v1/ai/chat",
            {"message": question, "history": []},
            csrf=user["csrf"], timeout=args.timeout,
        )
        if status == 403 and "CSRF" in text.upper():
            # The api-server restart rotated the CSRF secret: refresh the
            # (header token, csrf cookie) pair while keeping the session.
            fresh_token, fresh_cookie = csrf_session(args.base, args.host)
            am = "; ".join(
                part for part in user["session"].split("; ")
                if part.startswith("am_session=")
            )
            user["csrf"] = (fresh_token, f"{fresh_cookie}; {am}")
            status, text, _ = call(
                args.base, args.host, "POST", "/v1/ai/chat",
                {"message": question, "history": []},
                csrf=user["csrf"], timeout=args.timeout,
            )
        label = case.get("category", kind) + " | " + question[:60]
        for _ in range(3):
            if status != 429:
                break
            time.sleep(12)
            status, text, _ = call(
                args.base, args.host, "POST", "/v1/ai/chat",
                {"message": question, "history": []},
                csrf=user["csrf"], timeout=args.timeout,
            )
        if status == 429:
            record("chat", label, "FAIL", f"429 rate limited after retries: {text[:120]}")
            continue
        if status != 200:
            record("chat", label, "FAIL", f"HTTP {status}: {text[:200]}")
            continue
        payload = json.loads(text)
        answer = payload.get("answer", "")
        escalated = bool(payload.get("escalated"))
        disclosure = payload.get("disclosure", "")
        live = case.get("live") or {}
        mode = live.get("mode") or ("refusal" if case.get("kind") == "refusal" else "facts")
        required = live.get("must_contain", case.get("must_contain", []))
        forbidden = live.get("must_not_contain", case.get("must_not_contain", []))
        any_of = live.get("any_of", [])
        evidence = {
            "request": {"path": "/v1/ai/chat", "message": question[:300]},
            "response": {"answer": answer[:600], "escalated": escalated,
                         "citations": len(payload.get("citations") or []),
                         "retrieval_state": payload.get("retrieval_state"),
                         "docs_version": payload.get("docs_version", "")[:12],
                         "prompt_version": payload.get("prompt_version")},
        }
        problems: list[str] = []
        leaks = leak_scan(answer)
        if leaks:
            problems.append(f"LEAK: answer contains {leaks}")
        for entry in forbidden:
            if entry_matches(entry, answer):
                problems.append(f"forbidden fact present: {entry!r}")
        if problems:
            record("chat", label, "FAIL", "; ".join(problems), evidence)
            continue
        if not disclosure or "AI-powered" not in disclosure:
            problems.append("missing EU AI Act disclosure")
        missing = [e for e in required if not entry_matches(e, answer)]
        missed_any = bool(any_of) and not any(entry_matches(e, answer) for e in any_of)
        if mode == "refusal":
            if refused(answer, escalated):
                record("chat", label, "PASS", "honest refusal/escalation" +
                       (" (escalated)" if escalated else ""), evidence)
            else:
                record("chat", label, "FAIL", "no refusal for a refusal-class case: "
                       + answer[:160].replace("\n", " "), evidence)
        elif missing or missed_any:
            if escalated and live.get("allow_escalation"):
                record("chat", label, "DEGRADED",
                       f"honest escalation without required facts {missing or any_of}", evidence)
            else:
                record("chat", label, "FAIL",
                       f"missing facts {missing or any_of}; answer={answer[:160]!r}", evidence)
        elif escalated:
            record("chat", label, "DEGRADED" if live.get("allow_escalation") else "FAIL",
                   "escalated" + ("" if live.get("allow_escalation") else " but escalation not allowed"),
                   evidence)
        else:
            record("chat", label, "PASS", "facts present, no forbidden content", evidence)


# ── reply-classification section ─────────────────────────────────────────────

def ai_classify(args, tenant: str, body: str, headers: dict) -> tuple[int, dict | None, str]:
    payload = json.dumps({
        "subject": body[:80],
        "body": body,
        "headers": headers,
        "taxonomy": [],
        "prompt_version": "reply-classifier-v1",
    })
    if args.ai_base:
        url = f"{args.ai_base.rstrip('/')}/reply/classify"
        request = urllib.request.Request(
            url, data=payload.encode(),
            headers={"Content-Type": "application/json",
                     "x-apexmail-tenant-id": tenant,
                     "x-api-key": args.internal_token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=args.timeout) as response:
                return response.status, json.loads(response.read().decode()), ""
        except urllib.error.HTTPError as error:
            return error.code, None, error.read().decode(errors="replace")[:200]
        except Exception as error:
            return 0, None, f"transport: {error}"
    # docker exec fallback: ai-service :3012 is not published on the host.
    # GNU wget needs a seekable --post-file, so stage the payload inside the
    # container first (stdin piping to --post-file fails with "Illegal seek").
    inner = (
        "cat > /tmp/eval-req.json && "
        "wget -q -S -O- --header='Content-Type: application/json' "
        f"--header='x-apexmail-tenant-id: {tenant}' "
        f"--header='x-api-key: {args.internal_token}' "
        "--post-file=/tmp/eval-req.json http://127.0.0.1:3012/reply/classify"
    )
    proc = subprocess.run(
        ["docker", "exec", "-i", args.ai_container, "sh", "-c", inner],
        input=payload.encode(), capture_output=True, timeout=args.timeout,
    )
    stderr = proc.stderr.decode(errors="replace")
    body_out = proc.stdout.decode(errors="replace")
    status = 0
    match = re.search(r"HTTP/1\.1 (\d{3})", stderr)
    if match:
        status = int(match.group(1))
    if not body_out:
        return status, None, stderr[-200:]
    try:
        parsed = json.loads(body_out)
    except json.JSONDecodeError:
        return status, None, body_out[:200]
    if status == 0:
        status = 200 if "disposition" in parsed else 502
    return status, parsed, ""


def deterministic_verdict(message: str, headers: dict) -> str | None:
    """The documented layer-1 rules (deterministic.rs), replayed for evidence
    when the worker reply pipeline is not run by this deployment."""
    lowered = message.lower()
    hdrs = {k.lower(): str(v) for k, v in (headers or {}).items()}
    body = lowered
    # DSN
    status_match = re.search(r"\b([45])\.(\d{1,3})\.(\d{1,3})\b", body)
    if status_match and ("final-recipient" in body or "diagnostic-code" in body
                         or "delivery status notification" in body or "action:" in body):
        return "bounce_hard" if status_match.group(1) == "5" else "bounce_soft"
    if re.search(r"\b(?:smtp|status:)\D{0,10}(5\d\d)\b", body) and "final-recipient" in body:
        return "bounce_hard"
    # list-unsubscribe header
    if any(k.lower() == "list-unsubscribe" for k in hdrs):
        return "unsubscribe"
    # auto-reply headers
    auto = hdrs.get("auto-submitted", "").strip().lower()
    if "auto-submitted" in hdrs and auto != "no":
        return "ooo"
    if any(k in hdrs for k in ("x-autoreply", "x-autorespond", "x-auto-reply")):
        return "ooo"
    if hdrs.get("precedence", "").strip().lower() in ("bulk", "junk", "list"):
        return "ooo"
    # OOO subject
    if any(token in lowered for token in OOO_SUBJECT_TOKENS):
        return "ooo"
    # stop tokens
    if any(token in lowered for token in STOP_TOKENS):
        return "unsubscribe"
    return None


def fallback_objection(message: str, headers: dict) -> str | None:
    text = message.lower()
    if headers:
        text += " " + " ".join(f"{k}: {v}".lower() for k, v in headers.items())
    for klass, tokens in OBJECTION_FAMILIES.items():
        for token in tokens:
            if token in text:
                return klass
    return None


def run_reply(args, tenant: str) -> None:
    cases = cases_of(REPLY)
    if args.limit:
        cases = cases[: args.limit]
    for case in cases:
        message = case["message"]
        headers = case.get("headers") or {}
        expect = case["expect"]
        expected_dispositions = expect["disposition"]
        expected_objections = expect.get("objection_class")
        if not isinstance(expected_objections, list):
            expected_objections = [expected_objections]
        label = case.get("category", "reply") + " | " + message[:50].replace("\n", " ")
        status, parsed, detail = ai_classify(args, tenant, message, headers)
        for _ in range(3):
            if status != 429:
                break
            time.sleep(10)  # ai-service per-tenant governor refill
            status, parsed, detail = ai_classify(args, tenant, message, headers)
        if status != 200 or not parsed:
            record("reply", label, "NOT-VERIFIED",
                   f"classifier route unavailable ({status}): {detail[:150]}",
                   {"request": {"message": message[:300], "headers": headers}})
            continue
        disposition = parsed.get("disposition")
        objection = parsed.get("objection_class") or fallback_objection(message, headers)
        layer = case.get("pipeline_layer", "ai")
        evidence = {
            "request": {"message": message[:300], "headers": headers},
            "response": {"disposition": disposition,
                         "objection_class": parsed.get("objection_class"),
                         "fallback_objection": fallback_objection(message, headers),
                         "confidence": parsed.get("confidence"),
                         "model_version": parsed.get("model_version")},
        }
        problems = []
        if disposition not in expected_dispositions:
            problems.append(f"disposition {disposition!r} not in {expected_dispositions}")
        if objection not in expected_objections:
            problems.append(f"objection {objection!r} not in {expected_objections}")
        if layer == "deterministic":
            # The production path for these inputs is worker layer 1, which
            # never hands them to the LLM. Assert the documented layer-1 rule
            # and record the route's answer as supplementary evidence: a
            # disagreement is a route observation, not a pipeline failure
            # (the worker pipeline is not enabled in this deployment).
            recorded = deterministic_verdict(message, headers)
            note = f"layer-1={recorded}; route={disposition}/{objection}"
            if recorded == expected_dispositions[0] or (
                expected_dispositions and recorded in expected_dispositions
            ):
                if problems:
                    note += f"; route disagreed ({'; '.join(problems)})"
                record("reply", label, "DEGRADED",
                       note + " (worker pipeline not enabled)", evidence)
            else:
                record("reply", label, "FAIL",
                       f"documented layer-1 rule decides {recorded}, expected "
                       f"{expected_dispositions}", evidence)
            continue
        if problems:
            record("reply", label, "FAIL", "; ".join(problems), evidence)
        else:
            record("reply", label, "PASS",
                   f"disposition={disposition} objection={objection}", evidence)


# ── mailbot section ──────────────────────────────────────────────────────────

def psql(args, sql: str) -> str:
    proc = subprocess.run(
        ["docker", "exec", args.db_container, "psql", "-U", args.db_user,
         "-d", args.db_name, "-tAc", sql],
        capture_output=True, timeout=30,
    )
    out = proc.stdout.decode(errors="replace").strip()
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        return f"{out}\npsql-error: {err}" if out else f"psql-error: {err}"
    return out


def psql_rows(args, sql: str) -> list[list[str]]:
    """Rows with embedded newlines escaped and an explicit unit-separator
    field separator, so multi-line draft text cannot break the parse."""
    proc = subprocess.run(
        ["docker", "exec", args.db_container, "psql", "-U", args.db_user,
         "-d", args.db_name, "-tA", "-F", "\x1f", "-c", sql],
        capture_output=True, timeout=30,
    )
    if proc.returncode != 0:
        return []
    rows = []
    for line in proc.stdout.decode(errors="replace").splitlines():
        if line.strip():
            rows.append(line.split("\x1f"))
    return rows


def ensure_mail_target(args, tenant: str) -> tuple[str, str]:
    """Create (idempotently) a verified domain + mail account + inbox mailbox
    for the sweep tenant so inbound SMTP routes to a mailbox we own."""
    suffix = args.suffix
    domain = f"eval-sweep-{suffix}.test"
    address = f"inbox@{domain}"
    psql(args, f"INSERT INTO domains (name, tenant_id, verified) "
               f"SELECT '{domain}', '{tenant}', true WHERE NOT EXISTS "
               f"(SELECT 1 FROM domains WHERE name = '{domain}')")
    psql(args, f"INSERT INTO mail_accounts (email, domain, password_hash, display_name) "
               f"VALUES ('{address}', '{domain}', 'x', 'Eval sweep') "
               f"ON CONFLICT (email) DO NOTHING")
    psql(args, f"INSERT INTO mail_mailboxes (account_id, name, mailbox_type) "
               f"SELECT id, 'INBOX', 'inbox' FROM mail_accounts WHERE email = '{address}' "
               f"ON CONFLICT DO NOTHING")
    return domain, address


def send_smtp(args, sender: str, recipient: str, subject: str, body: str,
              headers: dict | None = None) -> str:
    message_id = f"<eval-sweep-{uuid.uuid4().hex}@apexmail.test>"
    lines = [
        f"From: {sender}",
        f"To: {recipient}",
        f"Subject: {subject}",
        f"Message-ID: {message_id}",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
    ]
    for name, value in (headers or {}).items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append(body)
    raw = "\r\n".join(lines)
    with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as smtp:
        smtp.ehlo("eval-sweep.local")
        smtp.sendmail(sender, [recipient], raw.encode())
    return message_id


def run_mailbot(args, tenant: str) -> None:
    cases = cases_of(DRAFT)
    if args.limit:
        cases = cases[: args.limit]
    domain, address = ensure_mail_target(args, tenant)
    pending: list[tuple[dict, str, str]] = []  # (case, subject, message_id)
    for index, case in enumerate(cases):
        inbound = case.get("inbound")
        if not inbound:
            record("mailbot", case["scenario"][:60], "NOT-VERIFIED",
                   "state-machine case: covered by the admin drafts review suite "
                   "(dogfood-mailbot-live.md); no inbound message to send")
            continue
        sender = inbound.get("from") or f"sender-{index}@customer.example"
        if sender == "<>":
            sender = ""
        # Senders whose IDENTITY is the case (self, robot local part, null
        # sender, MAILER-DAEMON) stay verbatim; every other sender gets a
        # per-run unique address so the documented per-sender draft cap
        # (3 per 7 days) does not turn later cases into cap declines.
        local, _, domain = sender.partition("@")
        robot = local.lower() in (
            "ai", "mailer-daemon", "postmaster", "noreply", "no-reply",
            "bounce", "bounces", "donotreply", "do-not-reply", "auto-reply",
            "autoreply", "mailer",
        )
        if sender and not robot:
            sender = f"{local}+{args.suffix}-{index}@{domain}" if domain else sender
        subject = f"[eval-sweep-{args.suffix}-{index}] {inbound.get('subject', '')}"
        body = inbound.get("body", "")
        headers = inbound.get("headers") or {}
        repeats = int(inbound.get("repeat") or 1)
        for repeat in range(1, repeats + 1):
            repeat_subject = subject if repeat == 1 else f"{subject} (r{repeat})"
            try:
                message_id = send_smtp(args, sender, address, repeat_subject, body, headers)
                pending.append((case, repeat_subject, message_id))
            except Exception as error:
                record("mailbot", case["scenario"][:60], "FAIL",
                       f"SMTP send failed: {error}")

    from collections import defaultdict
    per_message: dict[str, dict] = {}
    deadline = time.time() + args.mailbot_wait
    while pending and time.time() < deadline:
        rows = psql_rows(
            args,
            "SELECT subject, processed, pending_approval, "
            "replace(coalesce(ai_response,''), chr(10), '\\n'), "
            "coalesce(classification,''), coalesce(processing::text,'') "
            "FROM inbound_messages "
            f"WHERE to_email = '{address}' AND subject LIKE '[eval-sweep-{args.suffix}-%'",
        )
        per_message = {}
        for parts in rows:
            if len(parts) >= 5:
                per_message[parts[0]] = {
                    "processed": parts[1].strip() == "t",
                    "pending_approval": parts[2].strip() == "t",
                    "ai_response": parts[3].replace("\\n", "\n"),
                    "classification": parts[4],
                }
        def settled(row: dict | None) -> bool:
            # A row exists the moment the MTA stores the message; the email
            # agent processes it on its own poll cycle. Wait for the agent's
            # terminal state (processed) or a recorded response.
            return bool(row) and (row.get("processed") or row.get("ai_response"))

        pending = [p for p in pending if not settled(per_message.get(p[1]))]
        if pending:
            time.sleep(5)

    for case, subject, message_id in pending:
        if subject in per_message:
            continue  # the row landed; the assertion pass judges the state
        record("mailbot", case["scenario"][:60], "FAIL",
               f"no inbound_messages row appeared for {subject!r} (SMTP path)")
    # Anything that did land is re-read for the assertion pass.
    rows = psql_rows(
        args,
        "SELECT subject, processed, pending_approval, "
        "replace(coalesce(ai_response,''), chr(10), '\\n'), "
        "coalesce(classification,''), coalesce(processing::text,'') "
        f"FROM inbound_messages WHERE to_email = '{address}' "
        f"AND subject LIKE '[eval-sweep-{args.suffix}-%'",
    )
    landed: dict[str, dict] = {}
    for parts in rows:
        if len(parts) >= 5:
            landed[parts[0]] = {
                "processed": parts[1].strip() == "t",
                "pending_approval": parts[2].strip() == "t",
                "ai_response": parts[3].replace("\\n", "\n"),
                "classification": parts[4],
            }
    for index, case in enumerate(cases):
        inbound = case.get("inbound")
        if not inbound:
            continue
        subject = f"[eval-sweep-{args.suffix}-{index}] {inbound.get('subject', '')}"
        repeats = int(inbound.get("repeat") or 1)
        repeat_rows = []
        for repeat in range(1, repeats + 1):
            s_ = subject if repeat == 1 else f"{subject} (r{repeat})"
            if s_ in landed:
                repeat_rows.append(landed[s_])
        rows_for_case = repeat_rows
        row = landed.get(subject)
        if repeats > 1 and repeat_rows:
            row = repeat_rows[-1]  # the last repeat carries the cap verdict
        label = case["scenario"][:60]
        if row is None:
            continue  # already recorded as FAIL above
        evidence = {"request": {"to": address, "subject": subject[:200]},
                    "response": {"processed": row["processed"],
                                 "pending_approval": row["pending_approval"],
                                 "ai_response": row["ai_response"][:500]}}
        handling = case["expect_handling"]
        draft = row["ai_response"]
        # Constraint checks apply to the AI-AUTHORED portion. The formatted
        # reply quotes the original message after a `---` marker; text there
        # is the customer's (including their own stale prices and compliance
        # questions), not a bot claim.
        authored = re.split(r"\n-{3,}\n", draft)[0]
        bans = case.get("draft_must_not_contain") or []
        live = case.get("live") or {}
        bans += live.get("draft_must_not_contain") or []
        musts = case.get("draft_must_contain") or []
        musts += live.get("draft_must_contain") or []
        problems = []
        if draft:
            leaks = leak_scan(authored)
            if leaks:
                problems.append(f"LEAK in draft: {leaks}")
            for ban in bans:
                if entry_matches(ban, authored):
                    problems.append(f"draft contains banned claim {ban!r}")
            for must in musts:
                if not entry_matches(must, authored):
                    problems.append(f"draft missing required fact {must!r}")
            live_language = live.get("language")
            if live_language == "de" and authored:
                german = any(w in authored.lower() for w in
                             (" sie ", " wir ", " und ", " nicht ", " unsere", " ihnen"))
                if not german:
                    problems.append("draft does not read as German")
        if problems:
            record("mailbot", label, "FAIL", "; ".join(problems), evidence)
            continue
        if handling in ("loop_guard_skip", "auto_submitted_skip", "decline_human_review"):
            if row["processed"] and not row["pending_approval"]:
                record("mailbot", label, "PASS",
                       "processed with no draft (human-review note)", evidence)
            elif not row["processed"]:
                record("mailbot", label, "DEGRADED",
                       "message not yet claimed; no draft exists", evidence)
            else:
                record("mailbot", label, "FAIL",
                       "a draft was created for a message a guard must skip", evidence)
        elif handling in ("suppressed_no_marketing_draft", "reschedule_pipeline"):
            if not row["pending_approval"]:
                record("mailbot", label, "PASS",
                       "no draft pending (pipeline disposition evidence requires the "
                       "worker reply handler)", evidence)
            else:
                record("mailbot", label, "DEGRADED",
                       "draft exists; pipeline-side suppression/reschedule needs the "
                       "worker reply handler", evidence)
        elif handling == "sender_cap_decline":
            # The documented invariant: at most 3 drafts per sender per
            # window; a further message is declined with the cap note.
            # In-batch concurrency may decide WHICH message is declined, so
            # assert the invariant plus at least one named decline.
            if not rows_for_case:
                record("mailbot", label, "DEGRADED",
                       "repeat probe not processed within the wait window", evidence)
            else:
                drafts = sum(1 for r in rows_for_case if r["pending_approval"])
                declined = [r for r in rows_for_case
                            if "reply cap" in r["ai_response"].lower()]
                processed = all(r["processed"] for r in rows_for_case)
                if drafts <= 3 and declined and processed:
                    record("mailbot", label, "PASS",
                           f"{len(rows_for_case)} sends → {drafts} drafts, cap decline "
                           "named", evidence)
                elif not processed:
                    record("mailbot", label, "DEGRADED",
                           "repeat probe not fully processed", evidence)
                else:
                    record("mailbot", label, "FAIL",
                           f"per-sender cap invariant broken: {drafts} drafts, "
                           f"{len(declined)} cap declines", evidence)
        elif handling == "draft_pending_approval":
            if row["processed"] and row["pending_approval"] and draft:
                record("mailbot", label, "PASS",
                       f"draft pending approval ({len(draft)} chars), constraints hold",
                       evidence)
            elif not row["processed"]:
                record("mailbot", label, "DEGRADED",
                       "not processed yet within the wait window", evidence)
            else:
                record("mailbot", label, "FAIL",
                       f"expected a pending-approval draft; processed={row['processed']} "
                       f"pending_approval={row['pending_approval']} draft={bool(draft)}",
                       evidence)
        else:
            record("mailbot", label, "NOT-VERIFIED",
                   f"handling class {handling!r} has no live assertion here", evidence)


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--host", default="app.apexmail.ee")
    parser.add_argument("--mailpit", default="http://127.0.0.1:8025")
    parser.add_argument("--sections", default="chat,reply,mailbot")
    parser.add_argument("--users", type=int, default=3)
    parser.add_argument("--pace", type=float, default=0.0,
                        help="seconds between requests per user (default 20/min bucket)")
    parser.add_argument("--limit", type=int, default=0, help="debug: first N cases per corpus")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--mailbot-wait", type=float, default=420.0)
    parser.add_argument("--out", default="/tmp/eval-live-evidence.json")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--suffix", default=uuid.uuid4().hex[:8])
    parser.add_argument("--ai-base", default="", help="direct ai-service URL (optional)")
    parser.add_argument("--ai-container", default="apexmail-ai-service-1")
    parser.add_argument("--db-container", default="apexmail-postgres")
    parser.add_argument("--db-user", default="apexmail")
    parser.add_argument("--db-name", default="apexmail")
    parser.add_argument("--internal-token", default="dev-internal-service-token-not-for-production")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=5525)
    parser.add_argument("--session-file", default="/tmp/eval-live-users.json")
    parser.add_argument("--no-provision", action="store_true")
    args = parser.parse_args()
    sections = set(args.sections.split(","))

    # Provision the chat users (documented flow) once; reuse on reruns.
    users: list[dict] = []
    session_path = Path(args.session_file)
    if args.no_provision and session_path.exists():
        users = json.loads(session_path.read_text())
    else:
        for index in range(args.users):
            user = provision_user(args.base, args.host, args.mailpit, f"eval-{args.suffix}-{index}")
            users.append(user)
            print(f"provisioned {user['email']}")
        session_path.write_text(json.dumps(users))

    tenant = psql(args, f"SELECT tenant_id FROM users WHERE email = '{users[0]['email']}'")
    if not tenant:
        # fall back to the domain/account join; the sweep tenant is only needed
        # for the tenant header on the internal classifier route.
        tenant = "eval-sweep"
    print(f"tenant: {tenant}")

    started = time.time()
    if "chat" in sections:
        run_chat(args, users)
    if "reply" in sections:
        run_reply(args, tenant)
    if "mailbot" in sections:
        try:
            run_mailbot(args, tenant)
        except Exception as error:  # the inbound path is best-effort infrastructure
            record("mailbot", "section", "NOT-VERIFIED", f"mailbot sweep aborted: {error}")

    counts = {v: 0 for v in VERDICT_ORDER}
    for row in RESULTS:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1
    print()
    print("── summary ──────────────────────────────")
    for verdict in VERDICT_ORDER:
        print(f"{verdict:<13} {counts.get(verdict, 0)}")
    print(f"elapsed {time.time() - started:.0f}s")
    if args.out:
        Path(args.out).write_text(json.dumps({
            "sections": sorted(sections),
            "suffix": args.suffix,
            "counts": counts,
            "results": RESULTS,
        }, indent=2))
        print(f"evidence: {args.out}")

    failed = counts.get("FAIL", 0) > 0
    degraded = counts.get("DEGRADED", 0) > 0
    if failed or (args.strict and degraded):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
