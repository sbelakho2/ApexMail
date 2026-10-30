#!/usr/bin/env python3
"""Provider fixture gate: Mollie's documented statuses only, real renewal metadata.

The audit that produced this gate (30 Oct, "Tests and enforcement") found two
classes of fixture lies in the billing-service suite:

  1. **Invented Mollie statuses.** The adapter mapped `refunded` and
     `charged_back` as PAYMENT statuses and the fixtures/mocks "taught" the
     same vocabulary. Mollie NEVER sends either on a payment object: a
     refunded payment stays `paid`, and a chargeback is a separate `chb_…`
     object enumerated from `GET /v2/payments/{id}/chargebacks`. A fixture
     using an invented status is a test that cannot fail for the right
     reason.

  2. **A recurring-webhook fixture with empty metadata.** MON-8 shipped
     because the recurring fixture did not carry the metadata the real
     renewal worker sends, so the routing defect (a late renewal payment
     treated as a checkout activation) was invisible. The fixture must be
     built from `renew_subscription_locked`'s actual metadata construction.

What this gate checks (all scanned files are the billing-service sources and
test fixtures):

  * `map_payment_status` (the adapter's payment mapping) matches EXACTLY the
    documented seven statuses and nothing else;
  * `notifications_from_payment` (the webhook normalizer) never reads a
    status outside those seven (refunded/charged_back included);
  * every `"status": "…"` value and every payment/refund fixture-builder
    status argument is inside the documented set for ITS object:
      - payment statuses: open, canceled, pending, authorized, expired,
        failed, paid (source: docs.mollie.com, Payments API `status` field);
      - refund statuses: queued, pending, processing, refunded, failed,
        canceled (source: docs.mollie.com, Refunds API `status` field);
      - chargeback statuses: NONE — the documented chargeback object has no
        `status` field; its state is carried by `reversedAt` and
        `settlementAmount`/`settlementId` (source: docs.mollie.com,
        "Get payment chargebacks"). A status token in a chargeback fixture is
        therefore a violation.
  * every recurring/renewal payment fixture carries the metadata keys the
    worker's `renew_subscription_locked` actually writes (`tenant_id`,
    `plan_name`, `interval`, `reference` — derived from that function's
    source, never hard-coded here).

`--self-test` proves the gate with synthetic fixtures: a `refunded` PAYMENT
status is caught, a chargeback with a `status` is caught, a recurring
fixture with empty metadata is caught, and a correct fixture passes.

Usage: check_provider_fixtures.py [--self-test]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BILLING = REPO / "services" / "mail-server" / "crates" / "billing-service"

# The sources of truth are named with the documentation page each set comes
# from. Do not extend a set without a citation.
PAYMENT_STATUSES = frozenset(
    # docs.mollie.com/reference/create-payment (+ Get payment): the `status`
    # field's seven documented values.
    {"open", "canceled", "pending", "authorized", "expired", "failed", "paid"}
)
REFUND_STATUSES = frozenset(
    # docs.mollie.com/reference/refunds-api (Refund `status`).
    {"queued", "pending", "processing", "refunded", "failed", "canceled"}
)
CHARGEBACK_STATUSES = frozenset()
# docs.mollie.com/reference/list-payment-chargebacks: the chargeback object
# has NO `status` field (reversedAt + settlementAmount carry its state), so
# the allowed set is deliberately EMPTY.
SETTLEMENT_STATUSES = frozenset(
    # docs.mollie.com/reference/settlements-api (Settlement `status`): a
    # payout object is neither a payment nor a refund; its status vocabulary
    # is its own.
    {"open", "pending", "paid", "failed"}
)
SUBSCRIPTION_STATUSES = frozenset(
    # docs.mollie.com/reference/create-subscription (Subscription `status`):
    # the mock's subscription object carries `active`, which is NOT a
    # payment status and must not be read as one.
    {"active", "canceled", "suspended", "completed", "pending"}
)

SCANNED = [
    BILLING / "src" / "mollie_client.rs",
    BILLING / "src" / "mollie_webhooks.rs",
    BILLING / "src" / "payments" / "mollie_provider.rs",
    BILLING / "src" / "payments" / "conformance.rs",
    BILLING / "tests" / "coverage_adversarial.rs",
]
WORKER_SOURCE = BILLING / "src" / "plan_billing.rs"

# A status outside an object literal (a builder-call argument) still has a
# budget for the backwards brace scan.
ANCHOR_WINDOW = 1200

STATUS_JSON = re.compile(r'"status"\s*:\s*"([a-z_]+)"')
PAYMENT_DOCUMENT_CALL = re.compile(
    r'\bpayment_document\s*\(\s*[^,()]*(?:\([^()]*\))?[^,()]*,\s*"([a-z_]+)"', re.S
)
PAYMENT_HELPER_CALL = re.compile(
    r'(?<![\w.])payment\s*\(\s*"[^"]*"\s*,\s*"([a-z_]+)"', re.S
)
REFUND_HELPER_CALL = re.compile(
    r'\brefund\s*\(\s*"[^"]*"\s*,\s*"[^"]*"\s*,\s*"([a-z_]+)"', re.S
)
MATCH_ARM = re.compile(r'^\s*((?:"[a-z_]+"\s*\|\s*)*"[a-z_]+")\s*=>', re.M)
QUOTED = re.compile(r'"([a-z_]+)"')


def strip_line_comments(source: str) -> str:
    """Drop `//` comments (keeping string contents intact is not needed for
    the status shapes this gate reads; no scanned fixture embeds `//` in a
    status literal)."""
    return "\n".join(line.split("//", 1)[0] for line in source.splitlines())


def function_body(source: str, name: str) -> str | None:
    """The brace-balanced body of `fn name`, or None."""
    match = re.search(rf'\bfn\s+{re.escape(name)}\s*[<(\s]', source)
    if not match:
        return None
    start = source.find("{", match.end())
    if start < 0:
        return None
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start + 1 : index]
    return None


def enclosing_objects(
    text: str, position: int, floor: int = 0, limit: int = 6
) -> list[str]:
    """The JSON-object literals enclosing `position`, innermost first (a
    backwards brace scan, string-aware), plus each parent object. The scan
    stops at `floor` (the enclosing Rust function), so a previous fixture's
    object can never be mistaken for a parent."""
    objects: list[str] = []
    cursor = position
    for _ in range(limit):
        depth = 0
        in_string = False
        escaped = False
        index = cursor
        start = None
        while index > floor:
            index -= 1
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "}":
                depth += 1
            elif char == "{":
                if depth == 0:
                    start = index
                    break
                depth -= 1
        if start is None or start < floor:
            break
        objects.append(text[start:cursor])
        # Continue from just before the opening brace to find the parent.
        cursor = start
    return objects


def function_floor(source: str, position: int) -> int:
    """The offset of the `fn` that encloses `position` (0 when none)."""
    floor = 0
    for match in re.finditer(r"\bfn\s+[a-z0-9_]+", source):
        if match.start() > position:
            break
        floor = match.start()
    return floor


def classify_position(source: str, position: int) -> str:
    """The object a status token belongs to, read from the enclosing object
    literals (innermost first). A status nested under `additional` belongs
    to the parent fact's object, so parents are consulted too."""
    objects = enclosing_objects(source, position, floor=function_floor(source, position))
    # Refund/chargeback/settlement identities win over a nested payment-ish
    # key (`additional.sequenceType` sits inside a REFUND fact's object).
    for obj in objects:
        if re.search(r'"event_code"\s*:\s*"REFUND', obj) or '"original_payment_id"' in obj:
            return "refund"
        if re.search(r'"id"\s*:\s*(?:format!\()?"re_', obj):
            return "refund"
        if re.search(r'"id"\s*:\s*(?:format!\()?"chb_', obj) or '"settlementAmount"' in obj:
            return "chargeback"
        if re.search(r'"id"\s*:\s*(?:format!\()?"stl_', obj) or '"settlements"' in obj:
            return "settlement"
    for obj in objects:
        if re.search(r'"id"\s*:\s*"tr_', obj) or '"sequenceType"' in obj:
            return "payment"
    # The mock's subscription-mint response has a VARIABLE id; its nearby
    # `format!("sub_…")` is the only object signal. Payments do not mint
    # subscription ids in these fixtures.
    window = source[max(0, position - 2000) : position]
    if re.search(r'format!\("sub_', window):
        return "subscription"
    return "payment"


def allowed_for(kind: str) -> frozenset[str]:
    if kind == "refund":
        return REFUND_STATUSES
    if kind == "chargeback":
        return CHARGEBACK_STATUSES
    if kind == "settlement":
        return SETTLEMENT_STATUSES
    if kind == "subscription":
        return SUBSCRIPTION_STATUSES
    return PAYMENT_STATUSES


def check_status_values(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    clean = strip_line_comments(source)

    def report(line_no: int, kind: str, token: str, how: str) -> None:
        allowed = ", ".join(sorted(allowed_for(kind))) or "(none)"
        problems.append(
            f"{origin}:{line_no}: {how} uses {token!r} on a {kind} object; "
            f"documented {kind} statuses are: {allowed}"
        )

    for match in STATUS_JSON.finditer(clean):
        token = match.group(1)
        kind = classify_position(clean, match.start())
        if token not in allowed_for(kind):
            line_no = clean.count("\n", 0, match.start()) + 1
            report(line_no, kind, token, '"status"')
    for pattern, kind, how in [
        (PAYMENT_DOCUMENT_CALL, "payment", "payment_document(...)"),
        (PAYMENT_HELPER_CALL, "payment", "payment(...)"),
        (REFUND_HELPER_CALL, "refund", "refund(...)"),
    ]:
        for match in pattern.finditer(clean):
            token = match.group(1)
            if token not in allowed_for(kind):
                line_no = clean.count("\n", 0, match.start()) + 1
                report(line_no, kind, token, how)
    return problems


def match_arm_tokens(source: str, function: str) -> list[str] | None:
    body = function_body(source, function)
    if body is None:
        return None
    tokens: list[str] = []
    for match in MATCH_ARM.finditer(body):
        tokens.extend(QUOTED.findall(match.group(1)))
    return tokens


def check_mapping_functions(origin: str, source: str) -> list[str]:
    problems: list[str] = []
    if "mollie_provider.rs" in origin:
        tokens = match_arm_tokens(source, "map_payment_status")
        if tokens is None:
            problems.append(f"{origin}: map_payment_status not found")
        else:
            found = set(tokens)
            if found != set(PAYMENT_STATUSES):
                missing = sorted(PAYMENT_STATUSES - found)
                extra = sorted(found - PAYMENT_STATUSES)
                problems.append(
                    f"{origin}: map_payment_status must map EXACTLY the documented "
                    f"seven payment statuses; missing={missing} invented={extra}"
                )
    if "mollie_webhooks.rs" in origin:
        tokens = match_arm_tokens(source, "notifications_from_payment")
        if tokens is None:
            problems.append(f"{origin}: notifications_from_payment not found")
        else:
            extra = sorted(set(tokens) - PAYMENT_STATUSES)
            if extra:
                problems.append(
                    f"{origin}: notifications_from_payment reads non-payment statuses "
                    f"{extra} (Mollie never sends them on a payment object)"
                )
            for removed in ("refunded", "charged_back"):
                if removed in tokens:
                    problems.append(
                        f"{origin}: notifications_from_payment must not have a "
                        f"{removed!r} arm (MON-9)"
                    )
    return problems


def worker_metadata_keys(worker_source: str) -> list[str]:
    """The metadata keys `renew_subscription_locked` ACTUALLY sends."""
    body = function_body(worker_source, "renew_subscription_locked")
    if body is None:
        raise ValueError("renew_subscription_locked not found in plan_billing.rs")
    match = re.search(
        r"metadata:\s*serde_json::json!\(\s*\{(.*?)\}\s*\)", body, re.S
    )
    if not match:
        raise ValueError("renew_subscription_locked has no metadata json! construction")
    keys = re.findall(r'"([a-z_]+)"\s*:', match.group(1))
    if not keys:
        raise ValueError("the worker's metadata construction names no keys")
    return keys


FIXTURE_FN = re.compile(
    r"\bfn\s+([a-z0-9_]*(?:recurring|renewal)[a-z0-9_]*)\s*\("
)

# A fixture BUILDER returns a payment document/fact. A TEST named after the
# behavior it proves (e.g. `a_recurring_payment_is_only_an_authorisation`)
# returns `()` and must not be mistaken for one.
FIXTURE_RETURNS = (
    "-> serde_json::Value",
    "-> Payment",
    "-> ProviderNotification",
)


def function_signature(source: str, name: str) -> str | None:
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*[<(\s]", source)
    if not match:
        return None
    brace = source.find("{", match.end())
    if brace < 0:
        return None
    return source[match.end() : brace]


def check_recurring_fixtures(
    origin: str, source: str, keys: list[str]
) -> tuple[list[str], int]:
    problems: list[str] = []
    fixtures = 0
    clean = strip_line_comments(source)
    for match in FIXTURE_FN.finditer(clean):
        name = match.group(1)
        signature = function_signature(clean, name) or ""
        body = function_body(clean, name)
        if body is None:
            continue
        if not any(returns in signature for returns in FIXTURE_RETURNS):
            continue
        # Only wire-payment fixtures: they build a payment document/struct
        # with a `recurring` sequence. Production handlers never do.
        looks_like_fixture = '"recurring"' in body and (
            "payment_document(" in body
            or 'Some("recurring"' in body
            or "serde_json::json!" in body
        )
        if not looks_like_fixture:
            continue
        fixtures += 1
        missing = [key for key in keys if f'"{key}"' not in body]
        if missing:
            problems.append(
                f"{origin}: recurring fixture `{name}` lacks the worker's real "
                f"metadata keys {missing} (renew_subscription_locked sends {keys})"
            )
    return problems, fixtures


def scan(origin: str, source: str, keys: list[str]) -> tuple[list[str], int]:
    problems: list[str] = []
    problems.extend(check_status_values(origin, source))
    problems.extend(check_mapping_functions(origin, source))
    fixture_problems, fixtures = check_recurring_fixtures(origin, source, keys)
    problems.extend(fixture_problems)
    return problems, fixtures


def self_test() -> int:
    worker = """
    async fn renew_subscription_locked() {
        provider.charge_saved_method(SavedMethodCharge {
            metadata: serde_json::json!({
                "tenant_id": tenant_id,
                "plan_name": plan,
                "interval": interval,
                "reference": obligation_ref,
            }),
        })
    }
    """
    keys = worker_metadata_keys(worker)
    if keys != ["tenant_id", "plan_name", "interval", "reference"]:
        print(f"provider-fixtures self-test FAIL: key derivation drift: {keys}", file=sys.stderr)
        return 1

    failures: list[str] = []

    # 1. An invented payment status ('refunded') is caught.
    bad_payment = """
    fn payment(id: &str) -> serde_json::Value {
        serde_json::json!({ "id": id, "status": "refunded" })
    }
    """
    problems, _ = scan("synthetic_payment.rs", bad_payment, keys)
    if not any("refunded" in p and "payment object" in p for p in problems):
        failures.append("an invented payment status ('refunded') was NOT caught")

    # 2. 'charged_back' as a payment status is caught.
    bad_charged = """
    fn payment(id: &str) -> serde_json::Value {
        serde_json::json!({ "id": "tr_1", "status": "charged_back" })
    }
    """
    problems, _ = scan("synthetic_charged.rs", bad_charged, keys)
    if not any("charged_back" in p for p in problems):
        failures.append("'charged_back' used as a payment status was NOT caught")

    # 3. A chargeback object with a status field is caught (the documented
    #    object has none).
    bad_chargeback = """
    fn chargeback() -> serde_json::Value {
        serde_json::json!({ "id": "chb_1", "paymentId": "tr_1", "status": "lost" })
    }
    """
    problems, _ = scan("synthetic_chargeback.rs", bad_chargeback, keys)
    if not any("chargeback object" in p for p in problems):
        failures.append("a chargeback status field was NOT caught")

    # 4. A refund status in a REFUND object is legal.
    good_refund = """
    fn refund() -> serde_json::Value {
        serde_json::json!({ "id": "re_1", "paymentId": "tr_1", "status": "refunded" })
    }
    """
    problems, _ = scan("synthetic_refund.rs", good_refund, keys)
    if problems:
        failures.append(f"a legal refund status was flagged: {problems}")

    # 5. A recurring fixture with EMPTY metadata is caught.
    empty_metadata = """
    fn recurring_payment(invoice_id: Uuid) -> serde_json::Value {
        payment_document(
            "tr_1",
            "paid",
            2_900,
            Some("recurring"),
            "cst_1",
            Some("mdt_1"),
            serde_json::json!({}),
        )
    }
    """
    problems, fixtures = scan("synthetic_empty.rs", empty_metadata, keys)
    if fixtures != 1 or not any("lacks the worker's real metadata" in p for p in problems):
        failures.append("a recurring fixture with empty metadata was NOT caught")

    # 6. The correct recurring fixture (the worker's real keys) passes.
    good_renewal = """
    fn renewal_worker_payment(invoice_id: Uuid) -> serde_json::Value {
        payment_document(
            "tr_1",
            "paid",
            2_900,
            Some("recurring"),
            "cst_1",
            Some("mdt_1"),
            serde_json::json!({
                "tenant_id": "t1",
                "plan_name": "growth",
                "interval": "monthly",
                "reference": format!("invoice:{invoice_id}"),
            }),
        )
    }
    """
    problems, fixtures = scan("synthetic_good.rs", good_renewal, keys)
    if fixtures != 1 or problems:
        failures.append(f"a correct recurring fixture was rejected: {problems}")

    # 7. The adapter mapping must be exactly the documented seven.
    bad_mapping = """
    pub(crate) fn map_payment_status(status: &str) -> Result<PaymentState, ProviderError> {
        match status.trim() {
            "open" => Ok(PaymentState::Pending),
            "pending" | "authorized" => Ok(PaymentState::Processing),
            "paid" | "refunded" => Ok(PaymentState::Succeeded),
            "failed" => Ok(PaymentState::Failed),
            "canceled" | "expired" => Ok(PaymentState::Canceled),
            other => Err(ProviderError::UnmappedStatus { kind: "payment", status: other }),
        }
    }
    """
    problems, _ = scan("synthetic_mapping/mollie_provider.rs", bad_mapping, keys)
    if not any("invented" in p for p in problems):
        failures.append("an invented status in map_payment_status was NOT caught")

    if failures:
        for failure in failures:
            print(f"provider-fixtures self-test FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        "provider-fixtures self-test: ok (invented payment statuses, chargeback "
        "status fields and empty recurring metadata are caught; a correct "
        "fixture and the seven-status mapping pass)"
    )
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if argv:
        print(f"unknown arguments: {argv}", file=sys.stderr)
        return 2
    try:
        worker_source = WORKER_SOURCE.read_text(encoding="utf-8")
        keys = worker_metadata_keys(worker_source)
    except (OSError, ValueError) as error:
        print(f"provider-fixtures gate: {error}", file=sys.stderr)
        return 2

    problems: list[str] = []
    fixtures = 0
    scanned = 0
    for path in SCANNED:
        if not path.is_file():
            problems.append(f"scanned source is missing: {path}")
            continue
        scanned += 1
        origin = path.relative_to(REPO).as_posix()
        file_problems, file_fixtures = scan(
            origin, path.read_text(encoding="utf-8"), keys
        )
        problems.extend(file_problems)
        fixtures += file_fixtures
    if fixtures == 0:
        problems.append(
            "no recurring/renewal payment fixture was found; the MON-8 fixture "
            "gate has nothing to check (the worker metadata keys are "
            f"{keys})"
        )
    if problems:
        print("provider-fixtures gate FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        f"provider-fixtures gate: ok ({scanned} sources, {fixtures} recurring "
        f"fixtures carrying the worker's metadata {keys}, Mollie's seven "
        "payment statuses and the refund set are the only legal tokens)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
