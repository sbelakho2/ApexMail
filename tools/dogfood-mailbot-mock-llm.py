#!/usr/bin/env python3
"""Deterministic OpenAI-compatible mock for the LIVE mailbot dogfood.

The running compose stack configures `ai-service` with
`AI_MODEL_ENDPOINT=http://mock-llm:8099/v1`. This file IS that runtime for the
mailbot probes: it answers `POST /v1/chat/completions` deterministically so the
real sanitize -> prompt -> verify -> persist pipeline can be driven live
without a real model.

Two behaviours, keyed on the system prompt:

* reply-classification prompts (the worker's AI layer 2, routed through
  ai-service `POST /v1/reply/classify`) get a schema-valid JSON
  classification derived from the SENDER's words — one keyword family per
  disposition, with the objection class attached only for
  `not_interested`/`question`;
* email-draft prompts (the ai-service email agent) get the grounded reply the
  agent's verifier accepts. The plan sentence is parsed out of the prompt's own
  canonical-facts block, so the mock cannot state a stale price.

Anything else gets an entity-free sentence that cannot fabricate facts.

This is a DOGFOOD TOOL, not a product surface. It exists only because the live
stack's model endpoint is an internal mock; every probe it answers is marked
as mock-model evidence in the report.

usage: python3 tools/dogfood-mailbot-mock-llm.py [--port 8099] [--host 0.0.0.0]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REQUESTS = 0
REQUESTS_LOCK = threading.Lock()

# ── classification keyword families (sender's words) ─────────────────────────
# Ordered: the first family that matches wins. Mirrors the canonical
# disposition ladder (worker-processors reply_handler classifier docs) without
# being the product's own code (this is the mocked MODEL, not the pipeline).

COMPLAINT = ("unacceptable", "terrible", "frustrated", "complaint", "awful",
             "worst", "disappointed", "angry", "abuse", "phishing",
             "unprofessional", "harassment", "harassing", "rude",
             "charged twice", "double charged", "not acceptable",
             "stop spamming", "this is spam", "report you")
UNSUBSCRIBE = ("unsubscribe", "remove me", "remove my email", "opt out",
               "opt-out", "stop emailing", "take me off", "do not email",
               "abmelden", "désabonner", "afmelden", "darse de baja")
OOO = ("out of office", "out of the office", "automatic reply",
       "automatic response", "auto-reply", "autoreply", "annual leave",
       "maternity leave", "paternity leave", "abwesenheit",
       "absence du bureau", "fuera de la oficina",
       "auto-submitted", "autorespond", "autoreply:", "urlaub",
       "außer haus", "außerhaus")
BOUNCE_HARD = ("final-recipient", "5.1.1", "5.2.2", "5.4.4", "5.4.1",
               "5.7.1", "permanent failure", "user unknown", "does not exist",
               "action: failed", "status: 5.")
BOUNCE_SOFT = ("4.4.1", "4.2.2", "4.2.1", "4.7.0", "delayed delivery",
               "mailbox full", "temporary failure", "try again later",
               "action: delayed", "action: delayed", "status: 4.",
               "delivery delayed")
REFERRAL = ("not the right person", "wrong person", "wrong contact",
            "not my department", "forwarded your", "forwarding this",
            "you should contact", "reach out to my colleague", "referred you",
            "point of contact", "cc'ed", "cc'd", "copied my colleague",
            "weitergeleitet", "zuständig ist")
MEETING = ("meeting", "a call", "schedule a", "book a", "demo", "calendar",
           "zoom", "teams", "let's talk", "lets talk", "when are you free",
           "thursday", "tuesday", "monday", "wednesday", "friday")
POSITIVE = ("interested", "sounds good", "sounds great", "tell me more",
            "we'd like", "we would like", "sign up", "get started",
            "please send", "happy to", "yes please", "evaluating vendors",
            "evaluating providers", "evaluating platforms", "considering you",
            "shortlist", "we are evaluating")
QUESTION = ("pricing", "how much", "what does it cost", "how do i", "how can i",
            "does it support", "can it", "is there a", "what about",
            "how does", "where can i", "documentation", "api", "webhook",
            "dns", "spf", "dkim", "dmarc", "smtp", "limit", "quota",
            "invoice", "billing", "charged", "refund", "warranty",
            "gdpr", "article 17", "erasure", "delete my data",
            "data request", "personal data", "right to", "was kostet",
            "wie viel", "wieviel", "welche", "kostet", "preis")
NOT_INTERESTED = ("not interested", "no thanks", "no thank you", "we'll pass",
                  "pass on this", "not a good fit", "not right now",
                  "not the right time", "bad timing", "heads down",
                  "already use", "already using",
                  "under contract", "too expensive", "no budget",
                  "not the decision maker", "need approval", "don't trust",
                  "do not trust", "too risky", "seems risky", "no need",
                  "don't need", "do not need", "we handle it in house")

OBJECTION_FAMILIES = [
    ("price", ("too expensive", "too pricey", "no budget", "out of budget",
               "can't afford", "cannot afford", "cheaper option",
               "lower price", "pricing is high", "cost is too high")),
    ("timing", ("not right now", "bad timing", "circle back",
                "next quarter", "in a few months", "too busy right now",
                "after the holidays", "not the right time")),
    ("competitor", ("already use", "already using", "happy with our current",
                    "under contract with", "switching cost", "another vendor")),
    ("authority", ("not the decision maker", "not my decision",
                   "need approval", "have to ask", "our team handles",
                   "speak to my manager")),
    ("trust", ("never heard of", "don't trust", "do not trust", "seems risky",
               "worried about", "scam")),
    ("need", ("don't need", "do not need", "not interested in this",
              "no need", "already solved", "we handle it in house")),
]


def _find(haystack: str, needles: tuple[str, ...]) -> str | None:
    for needle in needles:
        if needle in haystack:
            return needle
    return None


def classify_prompt(user_prompt: str) -> str:
    """One canonical disposition + optional objection class, from keywords."""
    text = user_prompt.lower()
    disposition = "unknown"
    confidence = 0.4
    reasoning = "no deterministic keyword family matched; nothing to assert"
    objection = None

    hit = _find(text, BOUNCE_HARD)
    if hit:
        disposition, confidence, reasoning = "bounce_hard", 0.95, f"delivery failure wording: {hit}"
    elif (hit := _find(text, BOUNCE_SOFT)):
        disposition, confidence, reasoning = "bounce_soft", 0.9, f"temporary failure wording: {hit}"
    elif (hit := _find(text, COMPLAINT)):
        disposition, confidence, reasoning = "complaint", 0.9, f"dissatisfaction wording: {hit}"
    elif (hit := _find(text, UNSUBSCRIBE)):
        disposition, confidence, reasoning = "unsubscribe", 0.95, f"stop request wording: {hit}"
    elif (hit := _find(text, OOO)):
        disposition, confidence, reasoning = "ooo", 0.9, f"out-of-office wording: {hit}"
    elif (hit := _find(text, REFERRAL)):
        disposition, confidence, reasoning = "referral", 0.85, f"referred elsewhere: {hit}"
    elif (hit := _find(text, MEETING)):
        disposition, confidence, reasoning = "meeting_request", 0.85, f"meeting wording: {hit}"
    elif (hit := _find(text, NOT_INTERESTED)):
        disposition, confidence, reasoning = "not_interested", 0.85, f"decline wording: {hit}"
    elif (hit := _find(text, POSITIVE)):
        disposition, confidence, reasoning = "positive", 0.85, f"interest wording: {hit}"
    elif _find(text, QUESTION) or "?" in user_prompt:
        disposition, confidence, reasoning = "question", 0.8, "the sender asks a question"

    for klass, needles in OBJECTION_FAMILIES:
        if _find(text, needles):
            objection = klass
            break
    if disposition == "unknown" and objection:
        # An objection family IS a decline signal even without a decline verb
        # ("Never heard of you; seems risky.").
        disposition, confidence = "not_interested", 0.8
        reasoning = f"objection family: {objection}"

    if disposition not in ("not_interested", "question"):
        objection = None

    return json.dumps({
        "disposition": disposition,
        "confidence": confidence,
        "reasoning": reasoning,
        "objection_class": objection,
        "evidence": [],
    })


# ── grounded draft replies ───────────────────────────────────────────────────

GROWTH_ROW = re.compile(r"\|\s*Growth\s*\|\s*€(?P<price>[\d,]+)", re.IGNORECASE)


def growth_price(system_prompt: str) -> str | None:
    match = GROWTH_ROW.search(system_prompt)
    return match.group("price") if match else None


def _fact_sentences(system_prompt: str) -> list[str]:
    sentences = []
    for line in system_prompt.replace("\n", " ").split(". "):
        sentence = line.strip().strip(";")
        if len(sentence) >= 15:
            sentences.append(sentence + ".")
    return sentences


def _best_fact_sentence(system_prompt: str, text: str) -> str | None:
    words = [w for w in re.findall(r"[a-z0-9]{4,}", text.lower())][:12]
    best, best_score = None, 0
    for sentence in _fact_sentences(system_prompt):
        score = sum(1 for word in words if word in sentence.lower())
        if score > best_score:
            best, best_score = sentence, score
    return best if best and best_score >= 2 else None


def _fact_sentence_with(system_prompt: str, keywords: tuple[str, ...]) -> str | None:
    for sentence in _fact_sentences(system_prompt):
        lowered = sentence.lower()
        if any(keyword in lowered for keyword in keywords):
            return sentence
    return None


def draft_reply(system_prompt: str, user_prompt: str) -> str:
    """A reply the email agent's grounded verifier accepts AND that answers the
    sender's actual point.

    Every factual sentence is either built from the plan row parsed out of the
    prompt's own canonical-facts table or quoted verbatim from the facts block,
    so the draft can never state a value the verifier cannot support. The
    email agent's contract carries no language mandate (the console chat prompt
    does; the agent prompt does not) — the mock answers in English and the
    draft still addresses a German question's subject matter.
    """
    # The original message sits between the "From:/Subject:" block and the
    # trailing "Your response:" invitation.
    body = user_prompt
    cut = body.rfind("\n\nYour response:")
    if cut != -1:
        body = body[:cut]
    text = body.lower()

    answer = None
    if any(keyword in text for keyword in ("hipaa", "soc 2", "soc2", "certification", "certified")):
        answer = _fact_sentence_with(system_prompt, ("hipaa", "soc 2", "soc2"))
    if answer is None and any(
        keyword in text for keyword in ("dkim", "spf", "dmarc", " dns", "dns record")
    ):
        answer = _fact_sentence_with(system_prompt, ("dkim", "spf", "dmarc"))
    if answer is None and any(
        keyword in text
        for keyword in ("price", "pricing", "cost", "how much", "budget", "plan", "€", "euro",
                        "kostet", "preis")
    ):
        rows = parse_plan_rows(system_prompt)
        chosen = next((row for row in rows if row["name"].lower() in text), None)
        if chosen is None:
            chosen = next((row for row in rows if row["name"].lower() == "growth"), None)
        if chosen is None and rows:
            chosen = rows[min(2, len(rows) - 1)]
        if chosen:
            answer = (
                f"The {chosen['name']} plan is €{chosen['price']} per month, with "
                f"{chosen['emails']} emails per month, {chosen['api']} API calls per month, "
                f"{chosen['team']} team members and {chosen['retention']} event retention."
            )
    if answer is None:
        answer = _best_fact_sentence(system_prompt, text)
    if answer is None and ("?" in text or any(
        word in text for word in ("how", "what", "which", "when", "can you", "do you", "is it")
    )):
        answer = (
            "I have passed your question to a member of our team, "
            "who will follow up with the exact details."
        )
    if answer is None:
        # Non-question inbound (acknowledgement, referral, decline): the
        # SPF/Domains sentence is the ai-service's own proven fixture text.
        answer = (
            "Your SPF record should include our servers; you can find the exact "
            "values on the Domains page."
        )

    return "\n".join(
        ["Hello,", "", f"Thanks for reaching out. {answer}", "",
         "Best regards,", "ApexMail AI Assistant"]
    )


CONSERVATIVE = (
    "I don't have a verified answer for that in the canonical facts, so a human "
    "will follow up."
)

NOT_COVERED = (
    "The documentation I can cite does not cover that. Please email "
    "support@apexmail.ee and a human will follow up."
)

# ── chat answers (console assistant) ─────────────────────────────────────────
#
# Every sentence is either quoted VERBATIM from the prompt's own Canonical
# Facts block or composed only from tokens that block contains, so the chat
# verifier's atomic-claim check accepts it and the mock can never state a
# stale price.

PLAN_ROW = re.compile(
    r"\|\s*(?P<name>[^|\n]+?)\s*\|\s*€(?P<price>[\d,]+)\s*\|\s*(?P<emails>[^|]+?)\s*\|"
    r"\s*(?P<api>[^|]+?)\s*\|\s*(?P<team>[^|]+?)\s*\|\s*(?P<retention>[^|]+?)\s*\|"
)

CHAT_SIGNALS = {
    "price": ("price", "pricing", "cost", "how much", "monthly", "per month", "欧元", "euro"),
    "overage": ("overage", "beyond the included", "extra emails"),
    "payg": ("payg", "pay as you go", "pay-as-you-go", "per email", "per-email"),
    "retention": ("retention", "how long", "keep", "store"),
    "team": ("team member", "seats", "users", "how many people"),
    "api": ("api call", "rate limit", "requests per", "api limit"),
    "sdk": ("sdk", "library", "client"),
    "deliverability": ("deliverability", "inbox placement", "warmup", "warm-up"),
    "compliance": ("gdpr", "dsr", "compliance", "soc", "hipaa"),
    "plan": ("include", "includes", "what does", "what is", "what are", "limits",
             "features", "quota", "how many", "offer", "get", "cover", "allow",
             "difference", "compare", "cheapest", "best for"),
}

PLAN_WORDS = ("free", "developer", "pro", "growth", "business", "scale", "enterprise",
              "pay as you go", "payg")


def parse_plan_rows(system_prompt: str) -> list[dict]:
    rows = []
    for match in PLAN_ROW.finditer(system_prompt):
        name = match.group("name").strip()
        if name.lower() in ("plan", "---", ""):
            continue
        rows.append({key: match.group(key).strip() for key in
                     ("name", "price", "emails", "api", "team", "retention")})
    return rows


def _fact_lines(system_prompt: str) -> list[str]:
    lines = []
    for raw in system_prompt.splitlines():
        line = raw.strip()
        if len(line) < 25 or line.startswith(("#", "|", "-", "*")):
            continue
        lines.append(line)
    return lines


def passage_answer(user_prompt: str, question: str) -> str | None:
    """Answer a docs/topic question by quoting the best-matching retrieved
    passage sentence VERBATIM with its [n] marker (the ai-service verifier
    accepts a cited chunk with lexical overlap). None when retrieval produced
    no citable passage."""
    lowered = user_prompt.lower()
    start = lowered.find("## documentation passages")
    if start == -1:
        return None
    end = lowered.find("## question", start)
    section = user_prompt[start:end if end != -1 else len(user_prompt)]
    # Cut the account-context / history blocks: they start at the next "## ".
    next_header = section.find("\n## ", len("## documentation passages"))
    if next_header != -1:
        section = section[:next_header]

    chunks = [
        (match.group(1), match.group(2))
        for match in re.finditer(r"\[(\d+)\]\s*(.*?)(?=\n\[\d+\]|\Z)", section, re.S)
    ]
    words = [w for w in re.findall(r"[a-z0-9]{4,}", question.lower())][:12]
    best, best_score, best_number = None, 0, None
    for number, body in chunks:
        for sentence in re.split(r"(?<=[.!?])\s+|\n", body):
            sentence = sentence.strip()
            if len(sentence) < 25:
                continue
            score = sum(1 for word in words if word in sentence.lower())
            if score > best_score:
                best, best_score, best_number = sentence, score, number
    if best and best_score >= 2:
        return f"{best} [{best_number}]"
    return None


def question_section(user_prompt: str) -> str:
    """The caller's actual question: everything after `## Question`, without
    the trailing answer instruction. Plan names must be matched ONLY here —
    retrieved passages and account context frequently mention plans the user
    did not ask about."""
    marker = "## question"
    lowered = user_prompt.lower()
    start = lowered.find(marker)
    section = user_prompt[start + len(marker):] if start != -1 else user_prompt
    for end_marker in ("\nanswer (", "\nanswer:", "\nanswer\n", "answer (cite"):
        cut = section.lower().find(end_marker)
        if cut != -1:
            section = section[:cut]
    return section.strip()


def chat_answer(system_prompt: str, user_prompt: str) -> str:
    question = question_section(user_prompt).lower()
    plans = parse_plan_rows(system_prompt)
    by_name = {row["name"].lower(): row for row in plans}

    wanted: list[str] = []
    for name in by_name:
        hit = name in question
        if not hit:
            # Multi-word names ("enterprise cloud") also match on their
            # significant words ("enterprise"); short words are ignored.
            hit = any(word in question for word in name.split() if len(word) > 2)
        if hit:
            wanted.append(name)

    # Topic-specific fact lines win over the plan row: an overage/PAYG
    # question needs those canonical rates, not the plan's included volume.
    if any(sig in question for sig in CHAT_SIGNALS["overage"]):
        for line in _fact_lines(system_prompt):
            if "overage" in line.lower():
                return line
    if any(sig in question for sig in CHAT_SIGNALS["payg"]):
        for line in _fact_lines(system_prompt):
            if "payg" in line.lower():
                return line

    price_ask = any(sig in question for sig in CHAT_SIGNALS["price"])
    # A question that NAMES a plan is a plan question: "What does the Free plan
    # include?" names no price word, and answering it from a general pricing
    # passage (or not at all) made the corpus sweep mark the mock as ignoring
    # the question. The canonical plan row answers both price and contents.
    plan_ask = any(sig in question for sig in CHAT_SIGNALS["plan"])
    if wanted and (price_ask or plan_ask or len(wanted) > 1):
        lines = []
        # Vary the sentence shape per plan: the ai-service verifier's
        # repetition detector rejects answers that repeat the same n-gram
        # ("per month, with") across parallel lines.
        for index, name in enumerate(wanted[:3]):
            row = by_name[name]
            if index == 0:
                lines.append(
                    f"The {row['name']} plan is €{row['price']} per month, with "
                    f"{row['emails']} emails per month, {row['api']} API calls per month, "
                    f"{row['team']} team members and {row['retention']} event retention."
                )
            elif index == 1:
                lines.append(
                    f"{row['name']} costs €{row['price']} per month; it includes "
                    f"{row['emails']} emails per month, {row['api']} API calls per month, "
                    f"{row['team']} team members and {row['retention']} event retention."
                )
            else:
                lines.append(
                    f"{row['name']}: €{row['price']} per month for {row['emails']} emails per month, "
                    f"{row['api']} API calls per month, {row['team']} team members and "
                    f"{row['retention']} event retention."
                )
        return "\n\n".join(lines)

    if price_ask and plans:
        cheapest = ", ".join(f"{row['name']} €{row['price']}" for row in plans)
        return f"Plan prices per month: {cheapest}. Ask about a plan for its limits."

    if any(sig in question for sig in CHAT_SIGNALS["retention"]) and plans:
        return "Event retention per plan: " + ", ".join(
            f"{row['name']} {row['retention']}" for row in plans
        ) + "."

    # Keyword search over the canonical fact lines: quote the best-matching
    # sentence verbatim so every token is backed by the facts block.
    words = [w for w in re.findall(r"[a-z0-9]{4,}", question)][:12]
    best, best_score = None, 0
    for line in _fact_lines(system_prompt):
        lowered = line.lower()
        score = sum(1 for word in words if word in lowered)
        if score > best_score:
            best, best_score = line, score
    if best and best_score >= 2:
        return best

    passage = passage_answer(user_prompt, question)
    if passage:
        return passage

    return NOT_COVERED


# ── HTTP plumbing ────────────────────────────────────────────────────────────


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        if "--verbose" in sys.argv:
            sys.stderr.write("[mock-llm] " + fmt % args + "\n")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - stdlib signature
        if self.path in ("/health", "/healthz"):
            self._json(200, {"status": "ok", "requests": REQUESTS})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):  # noqa: N802 - stdlib signature
        global REQUESTS
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            request = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid json"})
            return

        messages = request.get("messages") or []
        system = ""
        user = ""
        for message in messages:
            if message.get("role") == "system" and not system:
                system = str(message.get("content") or "")
            elif message.get("role") == "user":
                user = str(message.get("content") or "")

        lowered = system.lower()
        is_classifier = "reply classifier" in lowered or (
            '"disposition"' in lowered and "confidence" in lowered
        )
        if is_classifier:
            # Classify the SENDER's words only: the system prompt carries the
            # taxonomy itself and must never be the evidence.
            content = classify_prompt(user)
        elif user.rstrip().endswith("Your response:"):
            # The email agent's build_prompt ends with this exact invite; it is
            # the only surface whose system prompt is the operator prompt plus
            # the canonical facts block.
            content = draft_reply(system, user)
        elif "canonical facts" in lowered or "you are the apexmail assistant" in lowered:
            content = chat_answer(system, user)
        elif ("email" in lowered and "apexmail" in lowered) or "canonical product facts" in lowered:
            content = draft_reply(system, user)
        else:
            content = CONSERVATIVE

        with REQUESTS_LOCK:
            REQUESTS += 1
        self._json(200, {
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": request.get("model") or "apexmail-assistant",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock-llm listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
