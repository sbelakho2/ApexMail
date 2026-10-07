#!/usr/bin/env python3
"""Eval-corpus gate — the goldens must assert the CANONICAL facts.

`docs/eval/` carries the corpora the AI surfaces are scored against (plan §6).
A corpus is only evidence while it speaks the truth: a chat golden that
requires a stale price (or forbids a canonical one) would bless a regression
instead of catching it. This gate checks each corpus against the canonical
sources, so a price change fails here until the corpus follows it.

Checks:
  1. chat goldens: every numeric token in `must_contain` is a canonical value
     (catalog price, plan limit, rate, or launch allowance); every numeric
     token in `must_not_contain` is NOT one. Non-numeric tokens must appear in
     the canonical facts text. Categories are validated and must ALL be
     covered, and every plan price / plan limit / rate in the catalog must be
     required by at least one case (the corpus is the coverage proof).
  2. reply-classification goldens: every expected disposition is one of the
     canonical eleven and every `objection_class` is one of the six (or null).
     Every disposition and every objection class must have at least one case.
  3. objection-rebuttal goldens: classes are canonical; every forbidden claim
     is a non-empty phrase, must not appear in the canonical facts (a ban may
     never forbid a truth), and must come from the shared banned-claims
     vocabulary declared in `mailbot-draft-constraints.json`. All six classes
     must be covered.
  4. chat-technical goldens: every required entry must appear in the PUBLISHED
     docs tree (the assistant may not invent endpoints, limits, event names or
     error codes); every forbidden numeric token is non-canonical. Categories
     validated and all covered.
  5. mailbot-draft-constraints: handling classes and categories canonical and
     all covered; `draft_must_contain` facts canonical; `draft_must_not_contain`
     drawn from the declared vocabulary, which must itself never contain a
     canonical fact.
  6. structural sanity: no duplicate cases, no empty case, and every corpus
     file is valid JSON with the documented shape.

`--coverage` prints the category → case-count tables for the report.
Self-test (`--self-test`) mutates a copy of the corpora and asserts each
mutation class fails.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "services/mail-server/crates/platform-catalog/src/lib.rs"
PRICING_DOC = ROOT / "docs/pricing.md"
EVAL_DIR = ROOT / "docs/eval"

CHAT = "chat-qa-goldens.json"
REPLY = "reply-classification-goldens.json"
OBJECTION = "objection-rebuttal-goldens.json"
TECH = "chat-technical-goldens.json"
DRAFT = "mailbot-draft-constraints.json"

DISPOSITIONS = [
    "positive",
    "meeting_request",
    "question",
    "referral",
    "not_interested",
    "unsubscribe",
    "complaint",
    "ooo",
    "bounce_hard",
    "bounce_soft",
    "unknown",
]
OBJECTION_CLASSES = ["price", "timing", "competitor", "authority", "trust", "need"]

CHAT_CATEGORIES = [
    "chat-plans",
    "chat-billing",
    "chat-gdpr",
    "chat-abuse",
    "chat-sla",
    "chat-use-cases",
    "chat-problems",
    "chat-mutations",
    "chat-refusals",
]
#: The chatbot agent's live-expansion category names, accepted as aliases of
#: the canonical chat categories (the merged corpus carries both taxonomies).
CHAT_CATEGORY_ALIASES = {
    "plans": "chat-plans",
    "rates": "chat-plans",
    "feature_gates": "chat-plans",
    "dedicated_ips": "chat-plans",
    "billing": "chat-billing",
    "compliance": "chat-gdpr",
    "security": "chat-gdpr",
    "deliverability": "chat-use-cases",
    "sdk": "chat-use-cases",
    "use_cases": "chat-use-cases",
    "sla": "chat-sla",
    "problems": "chat-problems",
    "mutations": "chat-mutations",
    "disclosure": "chat-refusals",
}
TECH_CATEGORIES = [
    "tech-api-endpoints",
    "tech-params",
    "tech-limits",
    "tech-sdks",
    "tech-webhooks",
    "tech-errors",
    "tech-smtp",
]
REPLY_CATEGORIES = [
    "reply-auto-handling",
    "reply-objections",
    "reply-taxonomy",
    "reply-customer-service",
    "reply-hostile",
    "reply-technical",
    "reply-unknown",
]
DRAFT_CATEGORIES = [
    "mailbot-auto-handling",
    "mailbot-customer-service",
    "mailbot-draft-constraints",
    "mailbot-mutations",
    "mailbot-technical",
]
DRAFT_HANDLING_CLASSES = [
    "loop_guard_skip",
    "auto_submitted_skip",
    "suppressed_no_marketing_draft",
    "reschedule_pipeline",
    "decline_human_review",
    "draft_pending_approval",
    "sender_cap_decline",
    "mutation_sequence",
]
FORMAT_ASSERTIONS = [
    "pending_approval_only",
    "never_queues_or_sends",
    "quotes_original_message",
    "single_signature_block",
    "language_matches_sender",
    "bounded_length",
]
REPLY_LAYERS = ["deterministic", "ai"]

#: Canonical values every chat corpus must REQUIRE somewhere — one entry per
#: plan price, email limit, API limit, overage rate, PAYG tier and the
#: compliance/SDK truths. A catalog change fails here until the corpus follows.
REQUIRED_CHAT_FACTS = [
    "29", "89", "229", "699", "1,750",  # monthly prices
    "3,000", "50,000", "150,000", "500,000", "2,000,000", "5,000,000",  # emails
    "30,000", "500,000", "2,000,000", "5,000,000", "20,000,000",  # api calls
    "0.8", "0.6", "0.35",  # overage per 1k
    "0.001", "0.0008", "0.0005", "0.0003",  # PAYG tiers
    "0.10",  # PAYG API overage
    "not currently offered",  # HIPAA / SOC 2
    "not yet published",  # SDKs
]

FAILURES: list[str] = []


def fail(message: str) -> None:
    FAILURES.append(message)


def _int(text: str) -> int:
    return int(text.replace("_", ""))


def canonical_values() -> set[str]:
    """Every numeric value the assistant may legitimately state, as strings.

    Sources: the canonical catalog (prices in whole EUR, yearly prices, plan
    limits, overage rates per 1,000, PAYG tier rates) and `docs/pricing.md`
    (the published surface, matched through the price tables).
    """
    catalog = CATALOG.read_text()
    values: set[str] = set()
    for block in re.findall(r"PlanRow \{(.*?)\n    \}", catalog, re.S):
        monthly = _int(re.search(r"price_monthly_cents: (-?[\d_]+)", block).group(1))
        yearly = _int(re.search(r"price_yearly_cents: (-?[\d_]+)", block).group(1))
        emails = _int(re.search(r"email_limit: (-?[\d_]+)", block).group(1))
        api = _int(re.search(r"api_call_limit: (-?[\d_]+)", block).group(1))
        values.add(str(monthly // 100))
        values.add(str(yearly // 100))
        values.add(f"{emails:,}")
        values.add(f"{api:,}")
        overage = re.search(
            r"overage_millicents_per_email: Some\((-?[\d_]+)\)", block
        )
        if overage:
            values.add(f"{_int(overage.group(1)) / 100:g}")
    for rate, _ in re.findall(r"\(([\d_]+|i64::MAX), ([\d.]+)\)", catalog):
        values.add(rate)
        values.add("0")
        values.add("100")
    free_allowance = re.search(r"FREE_LAUNCH_ALLOWANCE: i64 = ([\d_]+)", catalog)
    if free_allowance:
        values.add(f"{_int(free_allowance.group(1)):,}")
        values.add(str(_int(free_allowance.group(1))))
    values.add("30")  # launch window days
    values.add("90")  # default chat retention days
    values.add("300")  # first-response target seconds
    return values


KNOWLEDGE = (
    ROOT / "services/mail-server/crates/ai-service/src/knowledge.rs"
)
CHAT_MODULE = ROOT / "services/mail-server/crates/ai-service/src/chat.rs"


def _production_only(src: str) -> str:
    for marker in ("\n#[cfg(test)]", "\nmod tests"):
        idx = src.find(marker)
        if idx != -1:
            src = src[:idx]
    return src


def _unfold(src: str) -> str:
    """Rust string-literal line continuations (`\\` + newline + indent) join
    the phrase; normalize them and collapse whitespace so a canonical fact is
    checked as the STRING VALUE, not as source text."""
    src = src.replace("\\\n", " ")
    return re.sub(r"\s+", " ", src)


def canonical_facts_text() -> str:
    """The CANONICAL fact sources — the catalog, the ai-service knowledge
    module (production only), the chat module's public disclosure and the
    pricing reference. A numeric token a golden requires must be findable
    here; the wider docs tree is deliberately NOT included, because prose
    mentioning a number is not the same as the assistant being allowed to
    state it."""
    text = PRICING_DOC.read_text()
    text += _unfold(_production_only(KNOWLEDGE.read_text()))
    text += _unfold(_production_only(CHAT_MODULE.read_text()))
    text += _unfold(_production_only(CATALOG.read_text()))
    return text.lower()


#: The PUBLISHED docs the assistant may cite for technical answers. This is
#: deliberately the customer-facing docs only: audit reports and eval corpora
#: are not answer sources.
PUBLISHED_DOC_GLOBS = [
    "docs/api/**/*.md",
    "docs/sending/**/*.md",
    "docs/user-guide/**/*.md",
    "docs/getting-started/**/*.md",
    "docs/quickstart.md",
    "docs/sla.md",
    "docs/pricing.md",
    "docs/glossary.md",
    "docs/domains/**/*.md",
]


def published_docs_text() -> str:
    parts: list[str] = []
    for pattern in PUBLISHED_DOC_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            try:
                parts.append(path.read_text())
            except OSError:
                continue
    return "\n".join(parts).lower()


NUMERIC_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")


def tokens_of(value: str) -> list[str]:
    return NUMERIC_RE.findall(value)


def appears_as_token(haystack: str, number: str) -> bool:
    """Whole-token containment: "65" must not be "found" inside "365 days"."""
    if re.search(rf"(?<![\d.,]){re.escape(number)}(?![\d.,])", haystack) is not None:
        return True
    # Decimal renderings differ ("0.60" vs canonical "0.6"); compare the
    # numeric value when both sides are plain numbers.
    try:
        wanted = float(number)
    except ValueError:
        return False
    for found in re.findall(r"\d[\d,]*(?:\.\d+)?", haystack):
        try:
            if abs(float(found.replace(",", "")) - wanted) < 1e-12:
                return True
        except ValueError:
            continue
    return False


def is_canonical(number: str, values: set[str]) -> bool:
    """Canonical either as an exact string or by numeric value (0.60 ~ 0.6)."""
    if number in values or number.replace(",", "") in values:
        return True
    try:
        wanted = float(number.replace(",", ""))
    except ValueError:
        return False
    for value in values:
        try:
            if abs(float(value.replace(",", "").replace("_", "")) - wanted) < 1e-12:
                return True
        except ValueError:
            continue
    return False


def check_chat(corpus: dict, values: set[str], facts: str) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{CHAT}: cases must be a non-empty list")
        return
    seen: set[str] = set()
    seen_categories: set[str] = set()
    required_tokens: set[str] = set()
    required_entries: set[str] = set()
    for case in cases:
        question = case.get("question", "")
        if not question.strip():
            fail(f"{CHAT}: a case has no question")
            continue
        if question in seen:
            fail(f"{CHAT}: duplicate case {question!r}")
        seen.add(question)
        category = case.get("category")
        category = CHAT_CATEGORY_ALIASES.get(category, category)
        if category not in CHAT_CATEGORIES:
            fail(f"{CHAT}: {question!r} has unknown category {category!r}")
        else:
            seen_categories.add(category)
        for field, invert in (("must_contain", False), ("must_not_contain", True)):
            entries = case.get(field)
            if not isinstance(entries, list):
                fail(f"{CHAT}: {question!r} has no {field} list")
                continue
            for entry in entries:
                if not isinstance(entry, str) or not entry.strip():
                    fail(f"{CHAT}: {question!r} has an empty {field} entry")
                    continue
                if not tokens_of(entry) and not invert:
                    required_entries.add(entry.lower())
                for number in tokens_of(entry):
                    canonical = is_canonical(number, values)
                    if not invert:
                        required_tokens.add(number)
                    if invert and canonical:
                        fail(
                            f"{CHAT}: {question!r} forbids {number!r} but that IS a "
                            "canonical value — the corpus would forbid the truth"
                        )
                    if not invert and not canonical and not appears_as_token(facts, number):
                        fail(
                            f"{CHAT}: {question!r} requires {number!r}, which is not a "
                            "canonical value (catalog/docs) — the corpus asserts a stale value"
                        )
                if not tokens_of(entry) and not invert and entry.lower() not in facts:
                    fail(
                        f"{CHAT}: {question!r} requires {entry!r}, which appears nowhere in "
                        "the canonical docs"
                    )
    for category in CHAT_CATEGORIES:
        if category not in seen_categories:
            fail(f"{CHAT}: category {category!r} has no case — coverage is incomplete")
    for required in REQUIRED_CHAT_FACTS:
        if (
            required not in required_tokens
            and required.replace(",", "") not in required_tokens
            and required.lower() not in required_entries
        ):
            fail(
                f"{CHAT}: canonical fact {required!r} is not required by any case — "
                "the corpus does not cover the canonical catalog"
            )


def check_reply(corpus: dict) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{REPLY}: cases must be a non-empty list")
        return
    seen: set[str] = set()
    seen_categories: set[str] = set()
    seen_dispositions: set[str] = set()
    seen_objections: set[str] = set()
    for case in cases:
        message = case.get("message", "")
        if not message.strip():
            fail(f"{REPLY}: a case has no message")
            continue
        key = message + json.dumps(case.get("headers") or {}, sort_keys=True)
        if key in seen:
            fail(f"{REPLY}: duplicate case {message!r}")
        seen.add(key)
        category = case.get("category")
        if category not in REPLY_CATEGORIES:
            fail(f"{REPLY}: {message!r} has unknown category {category!r}")
        else:
            seen_categories.add(category)
        layer = case.get("pipeline_layer")
        if layer is not None and layer not in REPLY_LAYERS:
            fail(f"{REPLY}: {message!r} has unknown pipeline_layer {layer!r}")
        expect = case.get("expect")
        if not isinstance(expect, dict):
            fail(f"{REPLY}: {message!r} has no expect object")
            continue
        dispositions = expect.get("disposition")
        if not isinstance(dispositions, list) or not dispositions:
            fail(f"{REPLY}: {message!r} expects no disposition")
            continue
        for disposition in dispositions:
            if disposition not in DISPOSITIONS:
                fail(
                    f"{REPLY}: {message!r} expects unknown disposition {disposition!r}; "
                    f"canonical: {', '.join(DISPOSITIONS)}"
                )
            else:
                seen_dispositions.add(disposition)
        objection = expect.get("objection_class")
        if objection is not None and not isinstance(objection, list):
            objection = [objection]
        if isinstance(objection, list):
            for value in objection:
                if value is not None and value not in OBJECTION_CLASSES:
                    fail(
                        f"{REPLY}: {message!r} expects unknown objection class {value!r}; "
                        f"canonical: {', '.join(OBJECTION_CLASSES)}"
                    )
                elif value:
                    seen_objections.add(value)
    for category in REPLY_CATEGORIES:
        if category not in seen_categories:
            fail(f"{REPLY}: category {category!r} has no case — coverage is incomplete")
    for disposition in DISPOSITIONS:
        if disposition not in seen_dispositions:
            fail(
                f"{REPLY}: disposition {disposition!r} has no case — coverage is incomplete"
            )
    for objection in OBJECTION_CLASSES:
        if objection not in seen_objections:
            fail(
                f"{REPLY}: objection class {objection!r} has no case — coverage is incomplete"
            )


def _banned_claim_problem(claim: str, values: set[str], facts: str) -> str | None:
    """A ban must be a non-empty phrase that never forbids a canonical truth."""
    if not isinstance(claim, str) or not claim.strip():
        return "an empty forbidden claim"
    numbers = tokens_of(claim)
    for number in numbers:
        if is_canonical(number, values):
            return f"bans {number!r}, which IS a canonical value"
    if not numbers and claim.lower() in facts:
        return f"bans {claim!r}, which appears in the canonical facts"
    return None


def check_objection(corpus: dict, values: set[str], facts: str, vocab: set[str]) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{OBJECTION}: cases must be a non-empty list")
        return
    seen_classes: set[str] = set()
    for case in cases:
        objection_class = case.get("objection_class")
        if objection_class not in OBJECTION_CLASSES:
            fail(f"{OBJECTION}: unknown class {objection_class!r}")
            continue
        seen_classes.add(objection_class)
        forbidden = case.get("forbidden_claims")
        if not isinstance(forbidden, list) or not forbidden:
            fail(
                f"{OBJECTION}: {objection_class!r} has no forbidden_claims — an empty "
                "deny-list asserts nothing"
            )
        else:
            for item in forbidden:
                problem = _banned_claim_problem(item, values, facts)
                if problem:
                    fail(f"{OBJECTION}: {objection_class!r} {problem}")
                elif vocab and item not in vocab:
                    fail(
                        f"{OBJECTION}: {objection_class!r} bans {item!r}, which is not in "
                        f"the shared banned-claims vocabulary ({DRAFT})"
                    )
    for objection_class in OBJECTION_CLASSES:
        if objection_class not in seen_classes:
            fail(
                f"{OBJECTION}: class {objection_class!r} has no case — coverage is incomplete"
            )


def _required_fact_problem(entry: str, values: set[str], facts: str) -> str | None:
    """Same canonicality rule as chat `must_contain`."""
    for number in tokens_of(entry):
        canonical = is_canonical(number, values)
        if not canonical and not appears_as_token(facts, number):
            return f"requires {number!r}, which is not a canonical value"
    if not tokens_of(entry) and entry.lower() not in facts:
        return f"requires {entry!r}, which appears nowhere in the canonical docs"
    return None


def _tech_entry_published(entry: str, values: set[str], docs: str) -> bool:
    """An entry with digits must be findable segment-by-segment in the
    published docs: `POST /v9/messages` fails because `v9` appears nowhere,
    even though `post` and `messages` do."""
    lowered = entry.strip().lower().strip("`")
    if lowered in docs:
        return True
    numbers = tokens_of(entry)
    if not numbers:
        return False
    for segment in re.split(r"[\s/]+", lowered):
        segment = segment.strip("`'\"()[]{}.,:;")
        if not segment:
            continue
        if segment in docs:
            continue
        if re.fullmatch(r"[\d,]+(?:\.\d+)?%?", segment) and all(
            n in values
            or n.replace(",", "") in values
            or appears_as_token(docs, n)
            for n in tokens_of(segment)
        ):
            continue
        return False
    return True


def check_tech(corpus: dict, values: set[str], docs: str) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{TECH}: cases must be a non-empty list")
        return
    seen: set[str] = set()
    seen_categories: set[str] = set()
    for case in cases:
        question = case.get("question", "")
        if not question.strip():
            fail(f"{TECH}: a case has no question")
            continue
        if question in seen:
            fail(f"{TECH}: duplicate case {question!r}")
        seen.add(question)
        category = case.get("category")
        if category not in TECH_CATEGORIES:
            fail(f"{TECH}: {question!r} has unknown category {category!r}")
        else:
            seen_categories.add(category)
        for field, invert in (("must_contain", False), ("must_not_contain", True)):
            entries = case.get(field)
            if not isinstance(entries, list):
                fail(f"{TECH}: {question!r} has no {field} list")
                continue
            for entry in entries:
                if not isinstance(entry, str) or not entry.strip():
                    fail(f"{TECH}: {question!r} has an empty {field} entry")
                    continue
                numbers = tokens_of(entry)
                if not invert:
                    if not _tech_entry_published(entry, values, docs):
                        fail(
                            f"{TECH}: {question!r} requires {entry!r}, which does not "
                            "appear in the published docs — the corpus asserts an "
                            "invented endpoint/limit/error code"
                        )
                else:
                    for number in numbers:
                        if is_canonical(number, values):
                            fail(
                                f"{TECH}: {question!r} forbids {number!r} but that IS a "
                                "canonical value"
                            )
    for category in TECH_CATEGORIES:
        if category not in seen_categories:
            fail(f"{TECH}: category {category!r} has no case — coverage is incomplete")


def check_draft(corpus: dict, values: set[str], facts: str) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{DRAFT}: cases must be a non-empty list")
        return
    vocab_list = corpus.get("banned_claims_vocabulary")
    if not isinstance(vocab_list, list) or not vocab_list:
        fail(f"{DRAFT}: banned_claims_vocabulary must be a non-empty list")
        return
    vocab: set[str] = set()
    for claim in vocab_list:
        problem = _banned_claim_problem(claim, values, facts)
        if problem:
            fail(f"{DRAFT}: vocabulary {problem}")
        if claim in vocab:
            fail(f"{DRAFT}: duplicate banned claim {claim!r}")
        vocab.add(claim)
    seen: set[str] = set()
    seen_categories: set[str] = set()
    seen_handling: set[str] = set()
    for case in cases:
        scenario = case.get("scenario", "")
        if not scenario.strip():
            fail(f"{DRAFT}: a case has no scenario")
            continue
        if scenario in seen:
            fail(f"{DRAFT}: duplicate scenario {scenario!r}")
        seen.add(scenario)
        category = case.get("category")
        if category not in DRAFT_CATEGORIES:
            fail(f"{DRAFT}: {scenario!r} has unknown category {category!r}")
        else:
            seen_categories.add(category)
        handling = case.get("expect_handling")
        if handling not in DRAFT_HANDLING_CLASSES:
            fail(f"{DRAFT}: {scenario!r} has unknown handling class {handling!r}")
        else:
            seen_handling.add(handling)
        for assertion in case.get("format_assertions") or []:
            if assertion not in FORMAT_ASSERTIONS:
                fail(f"{DRAFT}: {scenario!r} has unknown format assertion {assertion!r}")
        for entry in case.get("draft_must_contain") or []:
            problem = _required_fact_problem(entry, values, facts)
            if problem:
                fail(f"{DRAFT}: {scenario!r} {problem}")
        for entry in (case.get("live") or {}).get("draft_must_contain") or []:
            problem = _required_fact_problem(entry, values, facts)
            if problem:
                fail(f"{DRAFT}: {scenario!r} live {problem}")
        for entry in case.get("draft_must_not_contain") or []:
            problem = _banned_claim_problem(entry, values, facts)
            if problem:
                fail(f"{DRAFT}: {scenario!r} {problem}")
            elif entry not in vocab:
                fail(
                    f"{DRAFT}: {scenario!r} bans {entry!r}, which is not declared in "
                    "banned_claims_vocabulary"
                )
        for entry in (case.get("live") or {}).get("draft_must_not_contain") or []:
            problem = _banned_claim_problem(entry, values, facts)
            if problem:
                fail(f"{DRAFT}: {scenario!r} live {problem}")
            elif entry not in vocab:
                fail(
                    f"{DRAFT}: {scenario!r} live bans {entry!r}, which is not declared "
                    "in banned_claims_vocabulary"
                )
        pipeline_disposition = (case.get("live") or {}).get("pipeline_disposition")
        if pipeline_disposition is not None and pipeline_disposition not in DISPOSITIONS:
            fail(
                f"{DRAFT}: {scenario!r} asserts unknown pipeline disposition "
                f"{pipeline_disposition!r}"
            )
    for category in DRAFT_CATEGORIES:
        if category not in seen_categories:
            fail(f"{DRAFT}: category {category!r} has no case — coverage is incomplete")
    for handling in DRAFT_HANDLING_CLASSES:
        if handling not in seen_handling:
            fail(
                f"{DRAFT}: handling class {handling!r} has no case — coverage is incomplete"
            )


def load(root: Path, name: str) -> dict | None:
    path = root / "docs/eval" / name
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        fail(f"{name}: cannot read: {error}")
        return None


def run_checks(root: Path) -> list[str]:
    global FAILURES
    saved = FAILURES
    FAILURES = []
    try:
        values = canonical_values()
        facts = canonical_facts_text()
        # `canonical_values`/`facts`/`docs` always come from the real tree: the
        # corpora are the fixture under test, the facts are the authority.
        docs = published_docs_text()

        chat = load(root, CHAT)
        if chat is not None:
            check_chat(chat, values, facts)
        reply = load(root, REPLY)
        if reply is not None:
            check_reply(reply)
        draft = load(root, DRAFT)
        vocab = set((draft or {}).get("banned_claims_vocabulary") or [])
        objection = load(root, OBJECTION)
        if objection is not None:
            check_objection(objection, values, facts, vocab)
        tech = load(root, TECH)
        if tech is not None:
            check_tech(tech, values, docs)
        if draft is not None:
            check_draft(draft, values, facts)
        return sorted(set(FAILURES))
    finally:
        FAILURES = saved


def coverage_table(root: Path) -> list[tuple[str, str, int]]:
    """(corpus, category, count) rows, for the report."""
    rows: list[tuple[str, str, int]] = []
    for corpus_name, key in (
        (CHAT, "question"),
        (TECH, "question"),
        (REPLY, "message"),
        (DRAFT, "scenario"),
    ):
        path = root / "docs/eval" / corpus_name
        try:
            corpus = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        counts: dict[str, int] = {}
        for case in corpus.get("cases", []):
            category = case.get("category", "<none>")
            if corpus_name == CHAT:
                category = CHAT_CATEGORY_ALIASES.get(category, category)
            counts[category] = counts.get(category, 0) + 1
        for category in sorted(counts):
            rows.append((corpus_name, category, counts[category]))
    path = root / "docs/eval" / OBJECTION
    try:
        corpus = json.loads(path.read_text())
        counts = {}
        for case in corpus.get("cases", []):
            counts["objection-rebuttal"] = counts.get("objection-rebuttal", 0) + 1
        for category in sorted(counts):
            rows.append((OBJECTION, category, counts[category]))
    except (OSError, json.JSONDecodeError):
        pass
    return rows


def print_coverage(root: Path) -> None:
    rows = coverage_table(root)
    if not rows:
        print("no corpora found")
        return
    width = max(len(name) for _, name, _ in rows)
    print(f"{'corpus':<28} {'category':<{width}} cases")
    for corpus, category, count in rows:
        print(f"{corpus:<28} {category:<{width}} {count}")
    print(f"{'TOTAL':<28} {'':<{width}} {sum(count for _, _, count in rows)}")


def _self_test() -> int:
    ok = True

    def expect_failure(label: str, filename: str, mutate) -> None:
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs/eval").mkdir(parents=True)
            for name in (CHAT, REPLY, OBJECTION, TECH, DRAFT):
                shutil.copy2(EVAL_DIR / name, root / "docs/eval" / name)
            target = root / "docs/eval" / filename
            corpus = json.loads(target.read_text())
            mutate(corpus)
            target.write_text(json.dumps(corpus))
            problems = run_checks(root)
            if problems:
                print(f"self-test PASS [{label}]: {problems[0][:110]}")
            else:
                print(f"self-test FAIL [{label}]: mutation was not detected")
                ok = False

    def mutate_and_expect(label: str, filename: str, mutate) -> None:
        expect_failure(label, filename, mutate)

    expect_failure(
        "a stale required price fails",
        CHAT,
        lambda c: c["cases"][0].__setitem__("must_contain", ["65"]),
    )
    expect_failure(
        "forbidding a canonical price fails",
        CHAT,
        lambda c: c["cases"][0]["must_not_contain"].append("89"),
    )
    expect_failure(
        "an unknown chat category fails",
        CHAT,
        lambda c: c["cases"][0].__setitem__("category", "vibes"),
    )
    expect_failure(
        "a missing chat category fails coverage",
        CHAT,
        lambda c: [
            case.__setitem__("category", "chat-plans") for case in c["cases"]
        ],
    )
    expect_failure(
        "an uncovered canonical price fails",
        CHAT,
        lambda c: [
            case.__setitem__("must_contain", ["0"])
            for case in c["cases"]
            if case.get("category") == "chat-plans"
        ],
    )
    expect_failure(
        "an unknown disposition fails",
        REPLY,
        lambda c: c["cases"][0]["expect"].__setitem__("disposition", ["vibes"]),
    )
    expect_failure(
        "a missing disposition fails coverage",
        REPLY,
        lambda c: [
            case["expect"].__setitem__("disposition", ["question"])
            for case in c["cases"]
            if "positive" in case["expect"]["disposition"]
        ],
    )
    expect_failure(
        "an invented required endpoint fails the docs check",
        TECH,
        lambda c: c["cases"][0].__setitem__("must_contain", ["POST /v9/messages"]),
    )
    expect_failure(
        "an uncovered technical category fails coverage",
        TECH,
        lambda c: [
            case.__setitem__("category", "tech-api-endpoints")
            for case in c["cases"]
            if case.get("category") == "tech-sdks"
        ],
    )
    expect_failure(
        "an unknown objection class fails",
        OBJECTION,
        lambda c: c["cases"][0].__setitem__("objection_class", "vibes"),
    )
    expect_failure(
        "an empty deny-list fails",
        OBJECTION,
        lambda c: c["cases"][0].__setitem__("forbidden_claims", []),
    )
    expect_failure(
        "banning a canonical fact fails",
        OBJECTION,
        lambda c: c["cases"][0]["forbidden_claims"].append("not currently offered"),
    )
    expect_failure(
        "an undeclared draft ban fails",
        DRAFT,
        lambda c: c["cases"][0].__setitem__(
            "draft_must_not_contain", ["something never declared"]
        ),
    )
    expect_failure(
        "an uncovered handling class fails",
        DRAFT,
        lambda c: [
            case.__setitem__("expect_handling", "draft_pending_approval")
            for case in c["cases"]
            if case.get("expect_handling") == "loop_guard_skip"
        ],
    )
    expect_failure(
        "a banned claim that is a canonical truth fails",
        DRAFT,
        lambda c: c["banned_claims_vocabulary"].append(
            c["banned_claims_vocabulary"][0]
        ),
    )
    mutate_and_expect(
        "a draft requiring a stale fact fails",
        DRAFT,
        lambda c: c["cases"][0].__setitem__("draft_must_contain", ["65"]),
    )
    if not run_checks(ROOT):
        print("self-test PASS [pristine tree]")
    else:
        print(f"self-test FAIL [pristine tree]: {run_checks(ROOT)}")
        ok = False
    print(f"eval-corpus self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main() -> int:
    if "--coverage" in sys.argv[1:]:
        print_coverage(ROOT)
    problems = run_checks(ROOT)
    if problems:
        for problem in problems:
            print(f"FAIL eval-corpus: {problem}")
        print(f"eval-corpus: FAIL ({len(problems)} problem(s))")
        return 1
    print("PASS eval-corpus: goldens assert only canonical facts; categories covered")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test())
    sys.exit(main())
