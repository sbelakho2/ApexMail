"""Error-path honesty battery (partition: errors).

Every failure shape must be a NAMED error (status + code + message), with no
silent 200s, no 500s on validated input, and no internal details leaked
(stack traces, SQL, file paths). The taxonomy is asserted, not just the code.
"""
from __future__ import annotations

import re
import uuid

from ..assertions import Checks
from ..registry import probe

INTERNAL_MARKERS = (
    "panicked at", "sqlx::", "postgres", "PostgreSQL", "src/", ".rs:",
    "RUST_BACKTRACE", "tokio::", "Traceback (most recent call last)",
    "argon2", "deadpool", "/opt/apexmail", "/app/",
)


@probe("p.errors.taxonomy", "errors", severity="P1",
       description="Representative failures carry the documented {code,message} taxonomy and leak nothing")
def taxonomy(ctx):
    checks = Checks("p.errors.taxonomy", "error-taxonomy")
    owner = ctx.identity("owner_a")
    member = ctx.identity("member")
    cases = [
        ("unknown JSON route", "GET", "/v1/definitely-not-a-route-dgv2", None, None, (404, 405)),
        ("bad method on a known route", "PUT", "/v1/contacts", {}, None, (404, 405)),
        ("malformed JSON", "POST", "/v1/contacts", "{", "application/json", (400, 422)),
        ("missing required field", "POST", "/v1/contacts", {}, "application/json", (400, 422)),
        ("wrong type for a field", "POST", "/v1/contacts", {"email": 12345}, "application/json", (400, 422)),
        ("invalid email format", "POST", "/v1/contacts", {"email": "not-an-email"}, "application/json", (400, 422)),
        ("empty required email", "POST", "/v1/contacts", {"email": ""}, "application/json", (400, 422)),
        ("invalid UUID in a path", "GET", "/v1/contacts/not-a-uuid", None, None, (400, 404)),
        ("unknown enum value", "POST", "/v1/suppressions", {"email": "a@b.test", "reason": "nonsense"}, "application/json", (400, 422)),
        ("unknown query parameter", "GET", "/v1/events?event_type=no-such-type", None, None, (200, 400, 422)),
    ]
    for label, method, path, body, ctype, allowed in cases:
        if isinstance(body, str):
            resp = owner.session.req(method, path, raw=body, ctype=ctype)
        elif body is None:
            resp = owner.session.req(method, path)
        else:
            resp = owner.session.req(method, path, body=body, ctype=ctype)
        code = resp.error_code()
        message = resp.error_message()
        success = 200 <= resp.status < 300
        has_taxonomy = True if success else (
            bool(code) and bool(message) or resp.status in (404, 405) and bool(resp.text.strip()))
        leaked = _leaks_internal(resp.text)
        checks.add(
            f"{label}: status {resp.status} is a named refusal",
            resp.status in allowed and resp.status < 500 and has_taxonomy and not leaked,
            observed=f"status={resp.status} code={code!r} message={message[:100]!r} leaked={leaked} body={resp.text[:100]!r}",
            expected=f"one of {allowed} with a code+message and no internal details",
            severity="P2", surface=f"api:{method} {path}",
        )
    # 401/403 taxonomy
    resp = ctx.http.get("/v1/contacts")
    checks.add(
        "anonymous refusal uses the 401 UNAUTHORIZED taxonomy",
        resp.status == 401 and bool(resp.error_code() or resp.text.strip()),
        observed=f"status={resp.status} code={resp.error_code()!r} body={resp.text[:120]!r}",
        expected="401 with a named error", severity="P1", surface="api:GET /v1/contacts",
    )
    resp = member.session.get("/v1/contacts?limit=1")
    checks.add(
        "scope refusal uses the 403 taxonomy naming the missing scope",
        resp.status == 403 and "scope" in resp.text.lower(),
        observed=f"status={resp.status} body={resp.text[:140]!r}",
        expected="403 naming the required scope", severity="P1", surface="api:GET /v1/contacts",
    )
    # duplicate creates must be a named conflict, not a silent 2xx
    email = f"dgv2-conflict-{uuid.uuid4().hex[:8]}@dogfood.test"
    first = owner.session.post("/v1/contacts", {"email": email})
    second = owner.session.post("/v1/contacts", {"email": email})
    checks.add(
        "a duplicate contact is a named 409 conflict",
        first.status in (200, 201) and second.status == 409 and bool(second.error_code() or second.text.strip()),
        observed=f"first={first.status} second={second.status} code={second.error_code()!r} body={second.text[:120]!r}",
        expected="409 with a named code (a 2xx here would fork the row)",
        severity="P1", surface="api:POST /v1/contacts",
    )
    # no silent success on a refused operation: unknown id delete
    resp = owner.session.delete(f"/v1/contacts/{uuid.uuid4()}")
    checks.add(
        "deleting an absent contact is a named 404, not a silent 204",
        resp.status == 404 and bool(resp.text.strip()),
        observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="404 NOT_FOUND", severity="P1", surface="api:DELETE /v1/contacts/:id",
    )
    return checks.obs


def _leaks_internal(text: str) -> bool:
    if not text:
        return False
    for marker in INTERNAL_MARKERS:
        if marker in text:
            # "src/" alone could appear in a legitimate message; require a
            # file:line shape for the path markers
            if marker in ("src/", ".rs:", "/app/", "/opt/apexmail"):
                if re.search(r"[\w/.-]+\.rs:\d+", text) or marker in ("/app/", "/opt/apexmail"):
                    return True
                continue
            return True
    return False
