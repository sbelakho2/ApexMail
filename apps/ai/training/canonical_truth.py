#!/usr/bin/env python3
"""canonical_truth.py — mechanically derived product/compliance truth.

One import for every training-side producer that must not hand-code facts:
the tool authority comes from the assistant's REAL registry (chat.rs
``CHAT_READ_ONLY_TOOLS`` — the list the runtime actually executes), the
capability truth from ``docs/development/capability-registry.json`` (the
single source of truth for what ApexMail's security/compliance capabilities
ARE), and the pricing truth from ``apps/marketing-zola/data/pricing.json``
cross-checked against ``validate_pricing.CANONICAL_PRICING`` (the catalog
restatement). Nothing in this module states a product fact of its own — a
fact that is not derivable from those registries is not stated at all.

Consumers:
  - ``generate_gap_training.py`` refuses to write a corpus whose examples
    violate the derived truth (fail-closed regeneration, audit-6 #9).
  - ``tools/check_eval_corpora.py`` re-derives the same truth for the eval
    goldens (import-free twin of this logic; see its TRUTH section).

Fail-closed by contract: if a registry source is missing or its parse shape
changes (chat.rs registry renamed, capability schema drifted), the loaders
raise — a check that cannot read the truth may never pass silently.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from common_paths import PROJECT_ROOT

# ── Canonical registry sources (NEVER hard-code facts below) ────────────
#: The assistant's executable tool registry — the allowlist the runtime
#: enforces ("a tool_call whose name is not here is NEVER executed").
TOOL_REGISTRY_RS = (
    PROJECT_ROOT
    / "services/mail-server/crates/ai-service/src/chat.rs"
)
#: Security/reliability capability truth — what ApexMail ACTUALLY has.
CAPABILITY_REGISTRY_JSON = PROJECT_ROOT / "docs/development/capability-registry.json"
#: The published pricing surface the marketing site renders from.
MARKETING_PRICING_JSON = (
    PROJECT_ROOT / "apps/marketing-zola/data/pricing.json"
)

_CHAT_TOOL_BLOCK_RE = re.compile(
    r"CHAT_READ_ONLY_TOOLS\s*:\s*&\[\s*\(&str,\s*&str\)\]\s*=\s*&\[(.*?)\n\];",
    re.S,
)
_CHAT_TOOL_NAME_RE = re.compile(r"\(\s*\"([a-z0-9_]+)\"\s*,\s*r?#*\"")

_TOOL_CACHE: list[tuple[str, str]] | None = None

#: ChatML user-turn delimiters — the CUSTOMER may ask for anything ("do you
#: offer HIPAA?", "cancel my subscription"); only the system prompt and the
#: assistant turn ASSERT product truth. Scanners drop user turns first.
_USER_TURN_RE = re.compile(r"<\|im_start\|>user\n.*?<\|im_end\|>", re.S)


def assertable_text(text: str) -> str:
    """``text`` with ChatML user turns removed — the part that must speak
    the truth. Plain (non-ChatML) text passes through unchanged."""
    return _USER_TURN_RE.sub("\n", text)


def _rust_string_literals(block: str) -> list[str]:
    """String literal VALUES (delimiters stripped) from a Rust source block.

    Understands plain ``"…"`` (with backslash escapes) and raw ``r"…"`` /
    ``r#"…"#`` literals — the registry examples are raw literals whose JSON
    bodies contain plenty of ``"`` chars, so a naive first-quote scan fails.
    """
    values: list[str] = []
    i = 0
    n = len(block)
    while i < n:
        ch = block[i]
        if ch == "r" and i + 1 < n and block[i + 1] in ('"', "#"):
            j = i + 1
            hashes = 0
            while j < n and block[j] == "#":
                hashes += 1
                j += 1
            if j < n and block[j] == '"':
                closing = '"' + "#" * hashes
                end = block.find(closing, j + 1)
                if end == -1:
                    break
                values.append(block[j + 1: end])
                i = end + len(closing)
                continue
            i += 1
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if block[j] == "\\":
                    j += 2
                    continue
                if block[j] == '"':
                    break
                j += 1
            values.append(block[i + 1: j])
            i = j + 1
            continue
        i += 1
    return values


def read_only_tools() -> list[tuple[str, str]]:
    """(tool name, tool_call example) pairs from the REAL chat registry.

    Parses ``CHAT_READ_ONLY_TOOLS`` out of chat.rs so the training-side tool
    list can never drift from the executed allowlist. Raises when the block
    is missing — fail-closed, never an empty list.
    """
    global _TOOL_CACHE
    if _TOOL_CACHE is not None:
        return _TOOL_CACHE
    src = TOOL_REGISTRY_RS.read_text()
    block = _CHAT_TOOL_BLOCK_RE.search(src)
    if not block:
        raise RuntimeError(
            f"canonical tool registry not found in {TOOL_REGISTRY_RS} — "
            "CHAT_READ_ONLY_TOOLS moved or was renamed; update "
            f"{__file__} in the same change"
        )
    names = _CHAT_TOOL_NAME_RE.findall(block.group(1))
    if not names:
        raise RuntimeError(
            f"tool registry in {TOOL_REGISTRY_RS} parsed empty — parse shape "
            f"changed; update {__file__}"
        )
    # Example = the first string literal after each name whose JSON body
    # names that tool; tuple order and literal order agree in the registry.
    literals = [
        value for value in _rust_string_literals(block.group(1))
        if "tool" in value
    ]
    pairs: list[tuple[str, str]] = []
    for position, name in enumerate(names):
        example = ""
        for value in literals:
            if f'"tool":"{name}"' in value.replace(" ", ""):
                example = value
                break
        if not example and position < len(literals):
            example = literals[position]
        pairs.append((name, example))
    _TOOL_CACHE = pairs
    return pairs


def tool_names() -> set[str]:
    return {name for name, _ in read_only_tools()}


# ── Compliance truth, derived from the capability registry ──────────────
#: Framework keywords a corpus may only mention in DENIED form — each entry
#: maps the canonical keyword regexes to the human name used in messages.
#: A framework is ASSERTABLE only if the capability registry carries a
#: capability for it; none of these do today (HIPAA/SOC 2/ISO 27001 are not
#: offered — knowledge.rs COMPLIANCE_FACTS is the published restatement).
_COMPLIANCE_KEYWORDS: dict[str, list[re.Pattern[str]]] = {
    "HIPAA": [re.compile(r"hipaa", re.I)],
    "BAA": [re.compile(r"\bbaa\b", re.I)],
    "SOC 2": [re.compile(r"soc[\s_-]?2", re.I)],
    "ISO 27001": [re.compile(r"iso[\s_-]?27001", re.I)],
}
_COMPLIANCE_REGISTRY_HINT = re.compile(r"hipaa|soc[\s_-]?2|iso[\s_-]?27001|\bbaa\b", re.I)

#: Denial markers: text within this window of a framework keyword that
#: DENIES availability instead of asserting it ("not currently offered",
#: "no HIPAA", "we cannot support HIPAA", ...).
_DENIAL_RE = re.compile(
    r"not\s+(?:currently\s+|yet\s+|formally\s+)?[\w\s-]{0,30}?"
    r"(?:offered|available|certified|compliant|supported|signed)"
    r"|no\s+(?:hipaa|baa|soc[\s_-]?2|iso[\s_-]?27001|certification|audit)"
    r"|(?:do(?:es)?n'?t|cannot|can'?t|never|won'?t)\s+(?:offer|support|provide|certify|sign)"
    r"|uncertified|without\s+(?:a\s+)?(?:signed\s+)?(?:hipaa|baa)",
    re.I,
)
#: Sentence splitter for the compliance scan: a framework keyword is only
#: clean when the SAME sentence denies it — a denial one sentence earlier
#: must not bless a bare claim one sentence later. Splits on sentence
#: punctuation, paragraph breaks and list-item starts, but NOT on a soft
#: newline inside a wrapped sentence (prompts wrap at ~80 cols).
_SENTENCE_RE = re.compile(
    r"(?<=[.!?])\s+|\n\s*\n|\n(?=\s*(?:[-*•]\s|\d+\.\s|\|))"
)

#: Tool-assertion shapes. A hit names a tool the text claims to call /
#: execute / offer. JSON-shape regexes capture the tool VALUE only (never
#: the "tool"/"params" keys); prose regexes require a tool-shaped name
#: (snake_case, like every CHAT_READ_ONLY_TOOLS entry) so ordinary words
#: ("Call the appropriate tool") never fire.
_TOOL_JSON_RE = re.compile(r'\\?"tool\\?"\s*:\s*\\?"([A-Za-z0-9_]+)\\?"')
_TOOL_VERB_RE = re.compile(
    r"(?:call|calling|execute|executing|emit|emitting|invoke|invoking"
    r"|run|running|using)\s+(?:the\s+)?`?([A-Za-z][A-Za-z0-9_]{2,})`?\s+tool",
    re.I,
)
_TOOL_BACKTICK_RE = re.compile(r"`([a-z][a-z0-9_]+)`\s+tool")


def _is_tool_shaped(name: str) -> bool:
    """Tool-shaped claim: snake_case like every registry entry. All-caps
    (``TOOL_NAME`` placeholder in the syntax example) and plain words
    ("appropriate") are not tool claims."""
    return "_" in name and not name.isupper()


def offered_compliance_frameworks() -> set[str]:
    """Frameworks the capability registry actually carries an entry for.

    Derived, never asserted: today the registry has no HIPAA / SOC 2 /
    ISO 27001 capability, so none of them may be claimed as offered.
    """
    registry = json.loads(CAPABILITY_REGISTRY_JSON.read_text())
    offered: set[str] = set()
    for capability in registry.get("capabilities", []):
        blob = json.dumps(capability)
        if _COMPLIANCE_REGISTRY_HINT.search(blob):
            for framework, patterns in _COMPLIANCE_KEYWORDS.items():
                if any(p.search(blob) for p in patterns):
                    offered.add(framework)
    return offered


def _tool_assertions(text: str) -> list[tuple[str, str]]:
    """(tool name, match context) for every tool-authority claim in text."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def record(name: str, context: str) -> None:
        if name.isupper():  # TOOL_NAME placeholder in the syntax example
            return
        if name in seen:
            return
        seen.add(name)
        found.append((name, context))

    for match in _TOOL_JSON_RE.finditer(text):
        record(
            match.group(1),
            text[max(0, match.start() - 60): match.end() + 60],
        )
    for pattern in (_TOOL_VERB_RE, _TOOL_BACKTICK_RE):
        for match in pattern.finditer(text):
            if _is_tool_shaped(match.group(1)):
                record(
                    match.group(1),
                    text[max(0, match.start() - 60): match.end() + 60],
                )
    return found


def truth_problems_in_text(text: str, source: str = "<text>") -> list[dict]:
    """Findings for every stale product/compliance fact in ``text``.

    Same finding shape as ``validate_pricing.validate_pricing_in_text``
    (``{"source": ..., "message": ...}``) so producers can merge the two.
    Flags: (1) tool/action authority outside the real chat registry;
    (2) HIPAA/BAA/SOC 2/ISO 27001 availability or certification claims for
    frameworks the capability registry does not offer (denials pass).
    """
    problems: list[dict] = []
    registry = tool_names()

    for name, context in _tool_assertions(text):
        if name not in registry:
            problems.append({
                "source": source,
                "message": (
                    f"asserts tool/action `{name}` which is NOT in the real "
                    "chat registry (CHAT_READ_ONLY_TOOLS in ai-service "
                    f"chat.rs) — context: ...{context.strip()[:100]}..."
                ),
            })

    offered = offered_compliance_frameworks()
    for framework, patterns in _COMPLIANCE_KEYWORDS.items():
        if framework in offered:
            continue  # registry-backed: assertable
        for sentence in _SENTENCE_RE.split(text):
            hit = next(
                (p.search(sentence) for p in patterns if p.search(sentence)),
                None,
            )
            if hit is None:
                continue
            if _DENIAL_RE.search(sentence):
                continue  # denied in the same sentence, not asserted
            problems.append({
                "source": source,
                "message": (
                    f"asserts {framework} availability/certification "
                    f"({hit.group(0)!r}) but the capability registry "
                    "offers no such framework — sentence: "
                    f"{sentence.strip()[:120]!r}"
                ),
            })
    return problems


def pricing_drift_problems() -> list[dict]:
    """Marketing pricing.json vs the canonical catalog restatement.

    The generator must consume BOTH pricing registries; if the published
    surface (marketing-zola data) drifts from ``validate_pricing``'s
    CANONICAL_PRICING, regeneration stops until they agree.
    """
    from validate_pricing import CANONICAL_PRICING  # local: avoids a cycle

    published = json.loads(MARKETING_PRICING_JSON.read_text())
    canonical = {
        plan["name"].lower(): plan["price"] for plan in CANONICAL_PRICING["plans"]
    }
    problems: list[dict] = []
    seen: set[str] = set()
    for row in published.get("plans", []):
        name = str(row.get("name", "")).lower()
        seen.add(name)
        price = str(row.get("price", "")).strip()
        if name in canonical and price and price != canonical[name]:
            problems.append({
                "source": "pricing.json",
                "message": (
                    f"plan {name!r} publishes {price!r} but the canonical "
                    f"catalog says {canonical[name]!r}"
                ),
            })
    for name in canonical:
        if name not in seen:
            problems.append({
                "source": "pricing.json",
                "message": f"canonical plan {name!r} missing from pricing.json",
            })
    return problems


__all__ = [
    "CAPABILITY_REGISTRY_JSON",
    "MARKETING_PRICING_JSON",
    "TOOL_REGISTRY_RS",
    "offered_compliance_frameworks",
    "pricing_drift_problems",
    "read_only_tools",
    "tool_names",
    "truth_problems_in_text",
]
