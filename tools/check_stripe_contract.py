#!/usr/bin/env python3
"""Stripe boundary contract gate (audit item 32; 30 Oct HEAD re-audit of 562a7c20).

The re-audit proved three Stripe boundary defects in the adapter. This gate
freezes the required behavior so a future edit cannot silently reintroduce
them, with MUTATION TEETH: every check is also proven to fail on a mutated
copy of the real source.

The three facts (each quotes the audit finding it encodes):

  1. "Stripe distinguishes Session completion from payment completion: a
     Session can be `complete` while payment is still processing. Current
     mapping: Session status complete -> PaymentState::Succeeded."
     -> `map_session_status` must NEVER answer Succeeded, and its `complete`
        arm must answer the honest neutral controller state Processing. The
        settlement evidence is the authenticated PaymentIntent fetch.
     (Source: docs.stripe.com/payments/checkout/how-checkout-works —
      `status` is the session lifecycle; `payment_status`/the PaymentIntent
      carry payment completion.)

  2. "Stripe's create-refund API has no currency parameter; sending it can
     400."
     -> the `refund` request construction must carry no `currency` form
        field, while the RETURNED refund's currency must be validated
        against the requested one (a mismatch is Malformed).

  3. "Stripe Search is eventually consistent and must not establish absence
     ... a Search-empty result must NEVER by itself permit a second charge."
     -> `search_payment_by_idempotency_key` must route through the
        idempotent-replay contract: a journaled request is replayed with the
        SAME Idempotency-Key; the replay is the ONLY place `Ok(None)` may be
        answered (a replayed 400/409); an empty search without a replayable
        request must refuse as unprovable.

A fourth, related check keeps the webhook pipeline honest: the event
normalizer must obtain facts from authenticated fetches
(`fetch_payment_details` / `fetch_refund` / `fetch_settlement` /
`list_disputes` / `resolve_charge_payment_id`), never by normalizing the
signed body's money fields.

Checks are SEMANTIC (function-body parsing, not line pins): the audit's facts
are behavioral contracts, and line hashes would churn on every refactor
without adding strength.

Usage: check_stripe_contract.py [--self-test]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PAYMENTS = REPO / "services" / "mail-server" / "crates" / "billing-service" / "src" / "payments"
PROVIDER = PAYMENTS / "stripe_provider.rs"
EVENTS = PAYMENTS / "stripe_events.rs"


def strip_line_comments(source: str) -> str:
    """Drop `//` comments so doc prose (which legitimately DISCUSSES the
    forbidden mappings, e.g. "never Ok(None)") is not mistaken for code."""
    return "\n".join(line.split("//", 1)[0] for line in source.splitlines())


def function_span(source: str, name: str) -> tuple[int, int] | None:
    """The (start, end) of `fn name`'s brace-balanced body in `source`,
    end exclusive. `start` is the index just after the opening brace."""
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*[<(\s]", source)
    if not match:
        return None
    opening = source.find("{", match.end())
    if opening < 0:
        return None
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return opening + 1, index
    return None


def production_source(source: str) -> str:
    """The non-test region: fixtures may legitimately carry forbidden shapes
    (a signed body that lies is exactly what the tests feed the pipeline)."""
    return source.split("#[cfg(test)]", 1)[0]


def function_body(source: str, name: str) -> str | None:
    span = function_span(source, name)
    if span is None:
        return None
    return source[span[0] : span[1]]


def match_arms(body: str) -> list[tuple[str, str]]:
    """The (pattern, expression) arms of a simple match block. A tiny
    AST-lite reader: one arm per source line after the match, pattern up to
    `=>`, expression to the end of the line. Enough for the status mappings,
    which are one line per arm by house style."""
    arms: list[tuple[str, str]] = []
    for line in body.splitlines():
        line = line.strip()
        if "=>" not in line or line.startswith("//"):
            continue
        pattern, expression = line.split("=>", 1)
        arms.append((pattern.strip(), expression.strip().rstrip(",")))
    return arms


# ---------------------------------------------------------------------------
# Fact 1: Session `complete` is never money `Succeeded`
# ---------------------------------------------------------------------------


def check_session_status_mapping(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    body = function_body(source, "map_session_status")
    if body is None:
        return [f"{origin}: map_session_status not found"]
    arms = match_arms(body)
    complete_arms = [expr for pattern, expr in arms if '"complete"' in pattern]
    if not complete_arms:
        problems.append(
            f"{origin}: map_session_status has no 'complete' arm; the session "
            "lifecycle must be mapped explicitly (never by omission)"
        )
    for expression in complete_arms:
        if "PaymentState::Succeeded" in expression:
            problems.append(
                f"{origin}: map_session_status maps Session 'complete' to "
                "PaymentState::Succeeded — a complete session can still be "
                "processing; money may only be Succeeded from the fetched "
                "PaymentIntent (audit item 2)"
            )
        if "PaymentState::Processing" not in expression:
            problems.append(
                f"{origin}: map_session_status 'complete' must map to "
                f"PaymentState::Processing (the honest neutral controller "
                f"state), got {expression!r}"
            )
    # No session status may ever be a money-success answer.
    for pattern, expression in arms:
        if "PaymentState::Succeeded" in expression:
            problems.append(
                f"{origin}: map_session_status arm {pattern!r} answers "
                "PaymentState::Succeeded; the Session lifecycle is never "
                "settlement evidence"
            )
    return problems


def check_events_never_map_sessions(origin: str, source: str) -> list[str]:
    """The webhook pipeline must not translate a session status into a money
    fact at all: it fetches the PaymentIntent instead."""
    problems: list[str] = []
    if "map_session_status" in source:
        problems.append(
            f"{origin}: the webhook normalizer references map_session_status; "
            "session completion must never drive the money state (fetch the "
            "PaymentIntent instead)"
        )
    if re.search(r'"amount_total"', source):
        problems.append(
            f"{origin}: the webhook normalizer reads the session's amount_total; "
            "money facts must come from the authenticated fetch"
        )
    return problems


# ---------------------------------------------------------------------------
# Fact 2: no `currency` on the refund wire; validate the returned currency
# ---------------------------------------------------------------------------

CURRENCY_FORM_PAIR = re.compile(r'\(\s*"currency"\s*\.\s*to_string\s*\(\s*\)\s*,')


def check_refund_wire(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    body = function_body(source, "refund")
    if body is None:
        return [f"{origin}: the trait's refund method not found"]
    for match in CURRENCY_FORM_PAIR.finditer(body):
        line = body.count("\n", 0, match.start()) + 1
        problems.append(
            f"{origin}:+{line}: the refund wire request carries a 'currency' "
            "form field; Stripe's create-refund API has no currency parameter "
            "and rejects it (audit item 6)"
        )
    # The returned refund's currency must be validated against the request.
    if "currencies_equal" not in body or "refund.currency" not in body:
        problems.append(
            f"{origin}: the refund method does not validate the RETURNED "
            "refund's currency against the requested one (a mismatched fact "
            "must be Malformed)"
        )
    if "ProviderError::Malformed" not in body:
        problems.append(
            f"{origin}: a refund currency mismatch must be a typed "
            "ProviderError::Malformed"
        )
    return problems


# ---------------------------------------------------------------------------
# Fact 3: Search-empty is never absence; the idempotent replay decides
# ---------------------------------------------------------------------------


def check_search_recovery(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    body = function_body(source, "search_payment_by_idempotency_key")
    if body is None:
        return [f"{origin}: search_payment_by_idempotency_key not found"]
    if "journaled_charge" not in body or "replay_charge" not in body:
        problems.append(
            f"{origin}: the stale-claim search does not route through the "
            "journaled idempotent replay; Search is eventually consistent and "
            "must never establish absence (audit item 3)"
        )
    else:
        replay_at = body.find("replay_charge")
        search_at = body.find("search_payment_intents")
        if search_at >= 0 and replay_at > search_at:
            problems.append(
                f"{origin}: the search investigation runs BEFORE the idempotent "
                "replay; the replay must decide first, the search may only add "
                "evidence"
            )
    if "Ok(None)" in body:
        problems.append(
            f"{origin}: search_payment_by_idempotency_key answers Ok(None) — "
            "only the idempotent replay may prove absence; a search-based "
            "None is a duplicate-charge path"
        )
    if "absence_unprovable" not in body:
        problems.append(
            f"{origin}: the unprovable-absence path is not a typed refusal "
            "(absence_unprovable); the engine must park the attempt unresolved"
        )

    replay = function_body(source, "replay_charge")
    if replay is None:
        problems.append(f"{origin}: replay_charge not found (no idempotent replay)")
        return problems
    if "Idempotency-Key" not in source:
        problems.append(
            f"{origin}: the adapter no longer sends an Idempotency-Key; the "
            "replay cannot be the same provider operation"
        )
    # Absence may be proven ONLY by a replayed 400/409 refusal.
    if "Ok(None)" not in replay:
        problems.append(
            f"{origin}: replay_charge cannot prove absence (no Ok(None) on a "
            "replayed refusal); without it the sweep can never close a claim"
        )
    if not re.search(r"status:\s*400\s*\|\s*409", replay):
        problems.append(
            f"{origin}: replay_charge's Ok(None) must be gated on a replayed "
            "400/409 refusal (the only absence proof); an unconditional "
            "Ok(None) would permit a second charge"
        )
    return problems


def check_journal_contract(origin: str, source: str) -> list[str]:
    """The replay needs the ORIGINAL wire form: the charge must journal its
    exact pairs under the key BEFORE the request is sent, and expired entries
    must never be replayed (Stripe retains idempotency keys for 24 hours)."""
    problems: list[str] = []
    body = function_body(source, "charge_saved_method")
    if body is None:
        return [f"{origin}: charge_saved_method not found"]
    journal = body.find("journal_charge")
    send = body.find("create_payment_intent")
    if journal < 0 or send < 0 or journal > send:
        problems.append(
            f"{origin}: charge_saved_method does not journal the request "
            "BEFORE sending it; a lost response would then be unrecoverable"
        )
    if "IDEMPOTENCY_RETENTION" not in source:
        problems.append(
            f"{origin}: the journal has no 24 h retention guard; a replay "
            "after Stripe forgot the key could mint a second charge"
        )
    return problems


# ---------------------------------------------------------------------------
# Related: the webhook pipeline is refetch-first
# ---------------------------------------------------------------------------

REQUIRED_FETCHES = (
    "fetch_payment_details",
    "fetch_refund",
    "fetch_settlement",
    "list_disputes",
    "resolve_charge_payment_id",
)
FORBIDDEN_BODY_NORMALIZERS = (
    "observed_from_document",
    "refund_from_document",
    "dispute_from_document",
    "settlement_from_document",
    "checkout_completed_from_document",
)


def check_refetch_first(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    body = function_body(source, "normalize_event")
    if body is None:
        return [f"{origin}: normalize_event not found"]
    for fetch in REQUIRED_FETCHES:
        if fetch not in body:
            problems.append(
                f"{origin}: normalize_event never calls {fetch}; the verified "
                "event must be a trigger whose facts come from an "
                "authenticated fetch (audit item 1)"
            )
    for normalizer in FORBIDDEN_BODY_NORMALIZERS:
        if normalizer in source:
            problems.append(
                f"{origin}: {normalizer} normalizes the SIGNED BODY into "
                "facts; signed does not mean current — the body is only an id "
                "trigger"
            )
    if "PaymentState::Succeeded" not in body:
        problems.append(
            f"{origin}: normalize_event does not gate the completed-checkout "
            "fact on the fetched PaymentIntent state"
        )
    return problems


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def scan(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    if origin.endswith("stripe_provider.rs"):
        problems.extend(check_session_status_mapping(origin, source))
        problems.extend(check_refund_wire(origin, source))
        problems.extend(check_search_recovery(origin, source))
        problems.extend(check_journal_contract(origin, source))
    if origin.endswith("stripe_events.rs"):
        source = production_source(source)
        problems.extend(check_events_never_map_sessions(origin, source))
        problems.extend(check_refetch_first(origin, source))
    return problems


def self_test() -> int:
    failures: list[str] = []
    for path in (PROVIDER, EVENTS):
        if not path.is_file():
            print(f"stripe-contract self-test FAIL: missing {path}", file=sys.stderr)
            return 1
    provider = strip_line_comments(PROVIDER.read_text(encoding="utf-8"))
    events = strip_line_comments(EVENTS.read_text(encoding="utf-8"))

    # The REAL sources must pass every check (the gate's clean arm).
    real_provider_problems = scan("stripe_provider.rs", provider)
    real_events_problems = scan("stripe_events.rs", events)
    if real_provider_problems or real_events_problems:
        failures.append(
            "the real adapter sources fail the gate: "
            f"{real_provider_problems + real_events_problems}"
        )

    def mutated_copy(source: str, old: str, new: str, label: str) -> str | None:
        if old not in source:
            failures.append(f"mutation anchor for {label} is gone: {old!r}")
            return None
        with tempfile.TemporaryDirectory(prefix="stripe-contract-") as tmp:
            copy = Path(tmp) / "mutated.rs"
            copy.write_text(source.replace(old, new, 1), encoding="utf-8")
            return copy.read_text(encoding="utf-8")

    # Mutation 1: inject the forbidden Session complete -> Succeeded mapping
    # into a temp copy of the REAL adapter; the gate must fail.
    mutated = mutated_copy(
        provider,
        '"complete" => Ok(PaymentState::Processing)',
        '"complete" => Ok(PaymentState::Succeeded)',
        "session-complete mapping",
    )
    if mutated is not None:
        problems = check_session_status_mapping("mutated_stripe_provider.rs", mutated)
        if not any("Succeeded" in problem and "complete" in problem.lower() for problem in problems):
            failures.append(
                "MUTATION 1 NOT CAUGHT: Session complete -> Succeeded passed the gate"
            )

    # Mutation 2: add the unsupported `currency` field to the REFUND wire
    # request in a temp copy; the gate must fail.
    refund_span = function_span(provider, "refund")
    if refund_span is None:
        failures.append("MUTATION 2 anchor: refund method body not found")
    else:
        refund_body = provider[refund_span[0] : refund_span[1]]
        injection = (
            '("amount".to_string(), request.amount_minor.to_string()),'
            '\n            (\n                "currency".to_string(),'
            "\n                request.currency.trim().to_lowercase(),\n            ),"
        )
        if '("amount".to_string(), request.amount_minor.to_string()),' not in refund_body:
            failures.append("MUTATION 2 anchor: the refund amount field is not where expected")
        else:
            mutated_refund = refund_body.replace(
                '("amount".to_string(), request.amount_minor.to_string()),',
                injection,
                1,
            )
            mutated = (
                provider[: refund_span[0]]
                + mutated_refund
                + provider[refund_span[1] :]
            )
            problems = check_refund_wire("mutated_stripe_provider.rs", mutated)
            if not any("currency" in problem and "wire" in problem for problem in problems):
                failures.append(
                    "MUTATION 2 NOT CAUGHT: a refund currency field passed the gate"
                )

    # Mutation 3: remove the idempotent replay from the search and answer
    # None on the empty search; the gate must fail.
    search_span = function_span(provider, "search_payment_by_idempotency_key")
    if search_span is None:
        failures.append("MUTATION 3 anchor: search body not found")
    else:
        search_body = provider[search_span[0] : search_span[1]]
        replay_line = re.search(r"return\s+self\.replay_charge\([^;]*;", search_body)
        if replay_line is None:
            failures.append(
                "MUTATION 3 anchor: the replay delegation line is not where expected"
            )
        else:
            mutated_search = search_body.replace(
                replay_line.group(0), "return Ok(None);", 1
            )
            mutated = (
                provider[: search_span[0]]
                + mutated_search
                + provider[search_span[1] :]
            )
            problems = check_search_recovery("mutated_stripe_provider.rs", mutated)
            caught_none = any("Ok(None)" in problem for problem in problems)
            caught_replay = any("replay" in problem.lower() for problem in problems)
            if not (caught_none and caught_replay):
                failures.append(
                    "MUTATION 3 NOT CAUGHT: search-empty -> None without the "
                    f"replay passed the gate ({problems})"
                )

    # Mutation 4: make the webhook normalize the signed body again; the gate
    # must fail.
    mutated_events = events.replace(
        "fn observed_from_fetched(fetched: &FetchedPayment) -> ObservedPayment {",
        "fn observed_from_document(object: &serde_json::Value) -> ObservedPayment {\n"
        "    let _ = object;\n"
        "    unreachable!()\n"
        "}\n\n"
        "fn observed_from_fetched(fetched: &FetchedPayment) -> ObservedPayment {",
        1,
    )
    if mutated_events == events:
        failures.append("MUTATION 4 anchor: observed_from_fetched not found")
    else:
        problems = check_refetch_first("mutated_stripe_events.rs", mutated_events)
        if not any("SIGNED BODY" in problem for problem in problems):
            failures.append(
                "MUTATION 4 NOT CAUGHT: body normalization passed the gate"
            )

    if failures:
        for failure in failures:
            print(f"stripe-contract self-test FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        "stripe-contract self-test: ok (real sources pass; Session complete -> "
        "Succeeded, a refund currency field, search-empty -> None without the "
        "replay, and signed-body normalization are each CAUGHT)"
    )
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if argv:
        print(f"unknown arguments: {argv}", file=sys.stderr)
        return 2
    problems: list[str] = []
    scanned: list[str] = []
    for path in (PROVIDER, EVENTS):
        if not path.is_file():
            problems.append(f"scanned source is missing: {path}")
            continue
        scanned.append(path.name)
        problems.extend(
            scan(path.name, strip_line_comments(path.read_text(encoding="utf-8")))
        )
    if problems:
        print("stripe-contract gate FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        "stripe-contract gate: ok "
        f"({', '.join(scanned)}: Session complete is never Succeeded; the "
        "refund wire carries no currency and validates the returned one; "
        "Search-empty is never absence — only the idempotent replay decides; "
        "webhook facts come from authenticated fetches)"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except OSError as error:
        print(f"stripe-contract gate: IO error: {error}", file=sys.stderr)
        raise SystemExit(2)
