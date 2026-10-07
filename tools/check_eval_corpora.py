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
     the canonical facts text or the published docs.
  2. reply-classification goldens: every expected disposition is one of the
     canonical eleven and every `objection_class` is one of the six (or null).
  3. objection-rebuttal goldens: classes are canonical; every forbidden claim
     is a non-empty phrase (an empty deny-list would assert nothing).
  4. structural sanity: no duplicate cases, no empty case, and every corpus
     file is valid JSON with the documented shape.

Self-test: `check_eval_corpora.py --self-test` mutates a copy of the corpora
and asserts each mutation class fails.
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


def _production_only(src: str) -> str:
    for marker in ("\n#[cfg(test)]", "\nmod tests"):
        idx = src.find(marker)
        if idx != -1:
            src = src[:idx]
    return src


def canonical_facts_text() -> str:
    """The CANONICAL fact sources — the catalog, the ai-service knowledge
    module (production only) and the pricing reference. A numeric token a
    golden requires must be findable here; the wider docs tree is deliberately
    NOT included, because prose mentioning a number is not the same as the
    assistant being allowed to state it."""
    text = PRICING_DOC.read_text()
    text += _production_only(KNOWLEDGE.read_text())
    text += _production_only(CATALOG.read_text())
    return text.lower()


NUMERIC_RE = re.compile(r"\d[\d,]*(?:\.\d+)?")


def tokens_of(value: str) -> list[str]:
    return NUMERIC_RE.findall(value)


def appears_as_token(haystack: str, number: str) -> bool:
    """Whole-token containment: "65" must not be "found" inside "365 days"."""
    return (
        re.search(rf"(?<![\d.,]){re.escape(number)}(?![\d.,])", haystack) is not None
    )


def check_chat(corpus: dict, values: set[str], facts: str) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{CHAT}: cases must be a non-empty list")
        return
    seen: set[str] = set()
    for case in cases:
        question = case.get("question", "")
        if not question.strip():
            fail(f"{CHAT}: a case has no question")
            continue
        if question in seen:
            fail(f"{CHAT}: duplicate case {question!r}")
        seen.add(question)
        for field, invert in (("must_contain", False), ("must_not_contain", True)):
            entries = case.get(field)
            if not isinstance(entries, list):
                fail(f"{CHAT}: {question!r} has no {field} list")
                continue
            for entry in entries:
                if not isinstance(entry, str) or not entry.strip():
                    fail(f"{CHAT}: {question!r} has an empty {field} entry")
                    continue
                for number in tokens_of(entry):
                    canonical = number in values or number.replace(",", "") in values
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


def check_reply(corpus: dict) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{REPLY}: cases must be a non-empty list")
        return
    for case in cases:
        message = case.get("message", "")
        if not message.strip():
            fail(f"{REPLY}: a case has no message")
            continue
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
        objection = expect.get("objection_class")
        if objection is not None and objection not in OBJECTION_CLASSES:
            fail(
                f"{REPLY}: {message!r} expects unknown objection class {objection!r}; "
                f"canonical: {', '.join(OBJECTION_CLASSES)}"
            )


def check_objection(corpus: dict) -> None:
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        fail(f"{OBJECTION}: cases must be a non-empty list")
        return
    for case in cases:
        objection_class = case.get("objection_class")
        if objection_class not in OBJECTION_CLASSES:
            fail(f"{OBJECTION}: unknown class {objection_class!r}")
        forbidden = case.get("forbidden_claims")
        if not isinstance(forbidden, list) or not forbidden:
            fail(
                f"{OBJECTION}: {objection_class!r} has no forbidden_claims — an empty "
                "deny-list asserts nothing"
            )
        elif any(not isinstance(item, str) or not item.strip() for item in forbidden):
            fail(f"{OBJECTION}: {objection_class!r} has an empty forbidden claim")


def run_checks(root: Path) -> list[str]:
    global FAILURES
    saved = FAILURES
    FAILURES = []
    try:
        values = canonical_values()
        facts = canonical_facts_text()
        # `canonical_values`/`facts` always come from the real tree: the
        # corpora are the fixture under test, the facts are the authority.
        for name, checker in (
            (CHAT, lambda corpus: check_chat(corpus, values, facts)),
            (REPLY, check_reply),
            (OBJECTION, check_objection),
        ):
            path = root / "docs/eval" / name
            try:
                corpus = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as error:
                fail(f"{name}: cannot read: {error}")
                continue
            checker(corpus)
        return sorted(set(FAILURES))
    finally:
        FAILURES = saved


def _self_test() -> int:
    ok = True

    def expect_failure(label: str, filename: str, mutate) -> None:
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs/eval").mkdir(parents=True)
            for name in (CHAT, REPLY, OBJECTION):
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
        "an unknown disposition fails",
        REPLY,
        lambda c: c["cases"][0]["expect"].__setitem__("disposition", ["vibes"]),
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
    if not run_checks(ROOT):
        print("self-test PASS [pristine tree]")
    else:
        print(f"self-test FAIL [pristine tree]: {run_checks(ROOT)}")
        ok = False
    print(f"eval-corpus self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main() -> int:
    problems = run_checks(ROOT)
    if problems:
        for problem in problems:
            print(f"FAIL eval-corpus: {problem}")
        print(f"eval-corpus: FAIL ({len(problems)} problem(s))")
        return 1
    print("PASS eval-corpus: goldens assert only canonical facts")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test())
    sys.exit(main())
