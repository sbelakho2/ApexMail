#!/usr/bin/env python3
"""Deterministic OpenAI-compatible mock for the ApexMail AI surfaces.

The compose stack configures `ai-service` with
`AI_MODEL_ENDPOINT=http://mock-llm:8099/v1` (or a host-reachable equivalent).
This server is that runtime: it speaks `POST /v1/chat/completions` and answers
from the CANONICAL sources only, so live dogfooding exercises the real
sanitize -> retrieve -> prompt -> verify -> persist pipeline without a real
model.

Answer policy (grounding-first):
  * Chat prompts (system prompt carries the Canonical Facts block): answers
    are composed exclusively from canonical fact text (plan table rows, the
    PAYG/overage paragraph, the compliance/security/deliverability/SDK fact
    blocks) and from caller-supplied account context. When the question is
    about something the canonical facts do not cover, the docs passages are
    searched for the best-matching sentences and quoted verbatim with their
    [n] marker. Everything else is an honest "not covered" + human route.
  * Classification prompts (system prompt asks for a disposition) return a
    schema-valid classification.
  * All other prompts get a conservative, entity-free sentence that will not
    fabricate facts.

Nothing here is a product surface: it exists so the live stack has a model
runtime. Numbers are never hard-coded — they are parsed out of the prompt's
own Canonical Facts block so the mock cannot drift from the catalog.

usage: python3 tools/mock-llm/mock_llm.py [--port 8099] [--host 0.0.0.0]
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ── canonical-facts parsing ────────────────────────────────────────────────

TABLE_ROW_RE = re.compile(
    r"^\|\s*(?P<name>[^|]+?)\s*\|\s*€(?P<price>[\d,]+)\s*\|\s*"
    r"(?P<emails>[^|]+?)\s*\|\s*(?P<api>[^|]+?)\s*\|\s*(?P<team>[^|]+?)\s*\|\s*"
    r"(?P<retention>[^|]+?)\s*\|\s*$",
    re.MULTILINE,
)


def parse_plans(system: str) -> dict[str, dict[str, str]]:
    plans: dict[str, dict[str, str]] = {}
    for match in TABLE_ROW_RE.finditer(system):
        name = match.group("name").strip()
        if name.lower() in {"plan", "---"}:
            continue
        plans[name.lower()] = {
            "name": name,
            "price": match.group("price").strip(),
            "emails": match.group("emails").strip(),
            "api": match.group("api").strip(),
            "team": match.group("team").strip(),
            "retention": match.group("retention").strip(),
        }
    return plans


def facts_sentence(system: str, needle: str) -> str | None:
    """The canonical fact block that starts with `needle`, up to a blank line."""
    idx = system.find(needle)
    if idx == -1:
        return None
    return system[idx:].split("\n\n")[0].strip()


def normalize_number(raw: str) -> str:
    raw = raw.strip().lower().replace(",", "").replace("€", "")
    mult = 1
    if raw.endswith("k"):
        mult, raw = 1_000, raw[:-1]
    elif raw.endswith("m"):
        mult, raw = 1_000_000, raw[:-1]
    try:
        value = float(raw) * mult
    except ValueError:
        return raw
    if value == int(value):
        return str(int(value))
    return f"{value:g}"


# ── chat answer composition ────────────────────────────────────────────────

PLAN_ALIASES = {
    "free": "free",
    "developer": "developer",
    "starter": "developer",
    "pro": "pro",
    "growth": "growth",
    "business": "business",
    "scale": "business",
    "enterprise cloud": "enterprise cloud",
    "enterprise": "enterprise cloud",
    "pay as you go": "pay as you go",
    "payg": "pay as you go",
}

TOPIC_INTENTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(hipaa|soc ?2|certifi|compliance|gdpr|dpa|encrypt|data location|subprocessor)\b"), "compliance"),
    (re.compile(r"\b(security|mfa|totp|captcha|kiwicaptcha|api key|hashed|backup|rate limit)\b"), "security"),
    (re.compile(r"\b(spf|dkim|dmarc|dns record|deliverab|domain verify|verify (my|a) domain|sender)\b"), "deliverability"),
    (re.compile(r"\b(sdk|library|python|golang|php|ruby|java|client)\b"), "sdk"),
    (re.compile(r"\b(payg|pay as you go|tier|per email|overage|allowance|invoic|vat|refund|billing)\b"), "rates"),
    (re.compile(r"\b(features?|include|difference|compare|retention|team members?|api calls?)\b"), "table"),
]


def plan_sentence(plan: dict[str, str]) -> str:
    return (
        f"The {plan['name']} plan costs €{plan['price']} per month and includes "
        f"{plan['emails']} emails per month, {plan['api']} API calls per month, "
        f"a team of {plan['team']} and {plan['retention']} of event retention."
    )


def all_plans_sentence(plans: dict[str, dict[str, str]]) -> str:
    parts = [
        f"{p['name']} is €{p['price']} per month with {p['emails']} emails per month"
        for p in plans.values()
    ]
    return "The published plans are: " + "; ".join(parts) + "."


def rates_sentence(system: str) -> str:
    block = facts_sentence(system, "PAYG per-email tiers:")
    if not block:
        return "The published rates are on the pricing page."
    text = block.replace("\n", " ")
    return text


def compliance_sentence(system: str) -> str:
    return facts_sentence(system, "GDPR:") or (
        "Compliance details are published on the ApexMail site."
    )


def security_sentence(system: str) -> str:
    return facts_sentence(system, "Security:") or (
        "Security controls are described in the published documentation."
    )


def deliverability_sentence(system: str) -> str:
    return facts_sentence(system, "Deliverability:") or (
        "DNS records are generated per domain in the workspace."
    )


def sdk_sentence(system: str) -> str:
    return facts_sentence(system, "SDKs exist for") or (
        "The REST API and SMTP submission are available today."
    )


def passages_of(user: str) -> list[tuple[str, str]]:
    """[(marker, text)] for the numbered documentation passages in the prompt."""
    block_start = user.find("## Documentation passages")
    if block_start == -1:
        return []
    block_end = user.find("## ", block_start + 10)
    block = user[block_start : block_end if block_end != -1 else len(user)]
    found: list[tuple[str, str]] = []
    for match in re.finditer(r"\[(\d+)\]\s*(.*?)\s*\(([^)]*)\)\s*\n(.*?)(?=\n\n\[|\Z)", block, re.S):
        body = match.group(4).strip()
        if body:
            found.append((match.group(1), body))
    return found


def keywords(text: str) -> set[str]:
    return {
        word
        for word in re.findall(r"[a-z][a-z0-9]{2,}", text.lower())
        if word
        not in {
            "the", "and", "for", "with", "you", "your", "how", "what", "does",
            "can", "are", "was", "were", "have", "has", "that", "this", "from",
            "when", "why", "which", "about", "into", "not", "but", "all", "any",
            "get", "use", "using", "need", "want", "please", "help", "there",
        }
    }


def best_passage_answer(question: str, passages: list[tuple[str, str]]) -> str | None:
    question_words = keywords(question)
    if not question_words or not passages:
        return None
    best: tuple[float, str] | None = None
    for marker, body in passages:
        for sentence in re.split(r"(?<=[.!?])\s+|\n+", body):
            sentence = sentence.strip()
            if len(sentence) < 30:
                continue
            words = keywords(sentence)
            if not words:
                continue
            overlap = question_words & words
            if len(overlap) < 2:
                continue
            score = len(overlap) / max(1, len(question_words))
            if best is None or score > best[0]:
                best = (score, f"{sentence} [{marker}]")
    if best is None or best[0] < 0.34:
        return None
    return best[1]


NOT_COVERED = (
    "The documentation I can cite does not cover that. "
    "Please contact support@apexmail.ee and a human will follow up."
)


def account_context(line_json: str) -> dict:
    try:
        value = json.loads(line_json)
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError):
        return {}


def chat_answer(system: str, user: str) -> str:
    plans = parse_plans(system)
    question_match = re.search(r"## Question\s*\n(.*?)(?:\n\nAnswer|\Z)", user, re.S)
    question = (question_match.group(1) if question_match else user).strip()
    lower = question.lower()
    passages = passages_of(user)

    # Contractual terms the assistant must never invent (the verifier forbids
    # uptime percentages). Answer with the honest human route instead.
    if re.search(r"\b(uptime|sla|guarantee|availability)\b", lower):
        if not re.search(r"\b(gdpr|hipaa|soc ?2|deliverab)\b", lower):
            return (
                "I cannot state uptime or SLA percentages from the published "
                "documentation I can cite. Contractual service terms are confirmed by the "
                "sales team — please contact support@apexmail.ee."
            )

    # Account-context questions answer from the caller-supplied context only.
    if re.search(r"\b(my|our|current) (plan|usage|quota|limit)|how many emails (have|did)", lower):
        ctx_match = re.search(
            r"## Authenticated account context \(display only\)\s*\n(\{.*?\n\})", user, re.S
        )
        ctx = account_context(ctx_match.group(1)) if ctx_match else {}
        parts = []
        if ctx.get("plan"):
            parts.append(f"Your workspace is on the {ctx['plan']} plan.")
        if ctx.get("emails_sent_this_month") is not None:
            parts.append(
                f"It has sent {ctx['emails_sent_this_month']} emails so far this month."
            )
        if ctx.get("monthly_email_limit") is not None:
            parts.append(f"The included monthly volume is {ctx['monthly_email_limit']} emails.")
        if ctx.get("verified_domains") is not None:
            parts.append(f"The workspace has {ctx['verified_domains']} verified domains.")
        if parts:
            return " ".join(parts)

    # A named plan wins over topic words: "Pro plan cost" is a plan question —
    # but "dedicated IP cost" is not, so the plan match also needs plan-ish
    # context beyond the bare word "cost".
    named = None
    for alias, key in PLAN_ALIASES.items():
        if re.search(rf"\b{re.escape(alias)}\b", lower) and key in plans:
            named = plans[key]
            break
    if named and re.search(
        r"\b(cost|price|pricing|plan|include|limit|feature|emails|api calls?|team|retention)\b",
        lower,
    ):
        return plan_sentence(named)

    if re.search(r"\b(plans?|pricing|how much)\b", lower) and plans:
        return all_plans_sentence(plans)

    for pattern, kind in TOPIC_INTENTS:
        if not pattern.search(lower):
            continue
        if kind == "compliance":
            return compliance_sentence(system)
        if kind == "security":
            return security_sentence(system)
        if kind == "deliverability":
            return deliverability_sentence(system)
        if kind == "sdk":
            return sdk_sentence(system)
        if kind == "rates":
            return rates_sentence(system)
        if kind == "table" and plans:
            return all_plans_sentence(plans)

    # Troubleshooting / operational topics (dedicated IPs, feature gates,
    # billing, campaigns, webhooks, migration…): answer from the retrieved
    # docs verbatim when a passage covers the question; otherwise refuse
    # honestly.
    quoted = best_passage_answer(question, passages)
    if quoted:
        return quoted
    return NOT_COVERED


def classification_answer(system: str) -> str:
    return json.dumps({"disposition": "unknown", "confidence": 0.4, "objection_class": None})


def generic_answer(system: str) -> str:
    if "disposition" in system.lower():
        return classification_answer(system)
    if "You are the ApexMail assistant" in system:
        return ""
    return (
        "The documentation I can cite does not cover that. "
        "Please contact support@apexmail.ee and a human will follow up."
    )


# ── HTTP surface ───────────────────────────────────────────────────────────


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "apexmail-mock-llm/1.0"

    def log_message(self, fmt: str, *args) -> None:  # quiet by default
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.rstrip("/") in ("/health", "/v1/models", "/models"):
            if "models" in self.path:
                self._send(200, {"data": [{"id": "apexmail-assistant", "object": "model"}]})
            else:
                self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.endswith("/chat/completions"):
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except ValueError:
            self._send(400, {"error": "invalid json"})
            return
        messages = request.get("messages") or []
        system = next(
            (m.get("content", "") for m in messages if m.get("role") == "system"), ""
        )
        user = next(
            (m.get("content", "") for m in messages if m.get("role") == "user"), ""
        )
        if "You are the ApexMail assistant" in system:
            content = chat_answer(system, user)
            if not content:
                content = NOT_COVERED
        else:
            content = generic_answer(system)
        self._send(
            200,
            {
                "id": "chatcmpl-mock",
                "object": "chat.completion",
                "model": request.get("model", "apexmail-assistant"),
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    server.verbose = args.verbose  # type: ignore[attr-defined]
    print(f"mock-llm listening on {args.host}:{args.port}", flush=True)
    threading.current_thread().name = "main"
    server.serve_forever()


if __name__ == "__main__":
    main()
