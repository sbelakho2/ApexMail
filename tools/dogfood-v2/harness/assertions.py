"""Shared assertion helpers for probes."""
from __future__ import annotations

import json
import re

from .registry import Observation


class Checks:
    """Collects observations for one probe; the probe returns `checks.obs`."""

    def __init__(self, probe_id: str, default_surface: str = "", default_severity: str = "P2"):
        self.probe_id = probe_id
        self.default_surface = default_surface
        self.default_severity = default_severity
        self.obs: list[Observation] = []

    def add(self, title: str, ok: bool, observed: str = "", expected: str = "",
            *, severity: str | None = None, surface: str | None = None,
            evidence: dict | None = None, kind: str = "check") -> bool:
        self.obs.append(
            Observation(
                probe_id=self.probe_id,
                surface=surface or self.default_surface,
                title=title,
                ok=bool(ok),
                observed=observed[:1200],
                expected=expected[:600],
                severity=severity or self.default_severity,
                evidence=evidence or {},
                kind=kind,
            )
        )
        return bool(ok)

    def unreachable(self, title: str, detail: str, *, surface: str | None = None) -> None:
        self.obs.append(
            Observation(
                probe_id=self.probe_id, surface=surface or self.default_surface,
                title=f"UNREACHABLE: {title}", ok=False, observed=detail[:1200],
                expected="probe executes (zero skips)", severity="P1",
                kind="unreachable",
            )
        )

    @property
    def failures(self) -> int:
        return sum(1 for o in self.obs if not o.ok)


# ── response-shape assertions ───────────────────────────────────────────────

NO_5XX = "a refusal (4xx) or success (2xx); never a 5xx crash"


def is_env_blocked(resp) -> bool:
    """True when the response is the STACK'S OWN protection layer, not a
    product verdict: a transport failure, the in-process DDoS block/limit
    (403 DDOS_BLOCKED / 429 DDOS_*). Such a response must be reported as an
    environment abort, never scored as a product pass/fail — the harness must
    not file its own volume as a defect. A plain 429 from a documented
    per-route rate limit stays a response (probes that prove bounds assert it
    explicitly)."""
    if resp.status == 0:
        return True
    body = (resp.text or "")[:400]
    if resp.status == 403 and "DDOS_BLOCKED" in body:
        return True
    if resp.status == 429 and "DDOS_" in body:
        return True
    return False


def env_block_detail(resp) -> str:
    return f"environment block: status={resp.status} body={resp.text[:160]!r}"


def status_class(resp) -> str:
    if resp.status == 0:
        return "transport"
    if 200 <= resp.status < 300:
        return "2xx"
    if 300 <= resp.status < 400:
        return "3xx"
    if 400 <= resp.status < 500:
        return "4xx"
    return "5xx"


def is_named_refusal(resp) -> tuple[bool, str]:
    """A refusal must be NAMED (status + code/message), never a bare status.
    A NAMED 503 (a documented unconfigured-feature refusal, e.g.
    SERVICE_UNAVAILABLE from the dedicated-IP provisioner) is honest; a bare
    or generic-INternal 5xx is a crash."""
    if resp.status < 400:
        return False, f"status {resp.status} is not a refusal"
    code = resp.error_code()
    message = resp.error_message()
    if resp.status >= 500:
        if resp.status == 503 and code and code not in ("INTERNAL_ERROR", "INTERNAL_SERVER_ERROR") \
                and len(message) >= 4:
            return True, f"{resp.status} {code}: {message[:120]} (named unconfigured-feature refusal)"
        return False, f"status {resp.status} is a crash, not an honest refusal"
    if code and code != "LEGACY_STRING_ERROR" and len(message) >= 4:
        return True, f"{resp.status} {code}: {message[:120]}"
    ctype = resp.headers.get("content-type", "")
    if "text/html" in ctype and len(resp.text.strip()) >= 16:
        return True, f"{resp.status} html({len(resp.text)} bytes)"
    if resp.status in (405, 413, 415, 429) and resp.text.strip():
        return True, f"{resp.status} {resp.text.strip()[:80]}"
    if resp.status in (401, 403, 404) and resp.text.strip():
        return True, f"{resp.status} body={resp.text.strip()[:80]}"
    return False, f"{resp.status} carries no named error (body={resp.text[:80]!r})"


def refusal_ok(checks: Checks, resp, title: str, *, allowed=(400, 401, 403, 404, 405, 409, 410, 413, 415, 422, 429, 503),
               surface: str = "", severity: str = "P2") -> bool:
    ok = resp.status in allowed and resp.status < 500
    return checks.add(
        title, ok,
        observed=f"status={resp.status} body={resp.text[:160]!r}",
        expected=f"one of {allowed}, never 5xx", surface=surface, severity=severity,
    )


def silent_success(resp) -> bool:
    """2xx on an operation the probe expects to be REFUSED."""
    return 200 <= resp.status < 300


# ── escaping / hostile payload helpers ─────────────────────────────────────

# The marker is `dgv2xss`, deliberately distinct from the fixture identity
# prefix `dgv2-` (which appears legitimately in rendered sidebar emails and
# inline JSON, and used to trip the executable-context regexes).
XSS_PAYLOADS = (
    '<script>alert("dgv2xss")</script>',
    '"><img src=x onerror=alert("dgv2xss")>',
    "javascript:alert('dgv2xss')",
    "<svg/onload=alert('dgv2xss')>",
    "&lt;script&gt;dgv2xss&lt;/script&gt;",
    "&#x3c;script&#x3e;dgv2xss&#x3c;/script&#x3e;",
)

BIDI_PAYLOAD = "dgo\u202efv2\u200f\u200b\ufeffx"
NUL_PAYLOAD = "dogfood\u0000v2"
CRLF_PAYLOAD = "dogfood\r\nX-Injected: dgv2"
SQL_PAYLOAD = "'; DROP TABLE dogfood_v2;--"
PROTO_POLLUTION = {"__proto__": {"polluted": "dgv2"}, "constructor": {"prototype": {"polluted": "dgv2"}}}
TRAVERSAL_PAYLOAD = "../../../../etc/passwd%00.png"


def payload_snippet(text: str, payload: str, width: int = 120) -> str:
    """The immediate context around the first payload occurrence — evidence
    the runner lanes can paste into a repro. Falls back to the `dgv2` marker
    for regex-shaped hits (e.g. an event-handler attribute built from the
    payload where the payload itself is not verbatim)."""
    index = text.find(payload)
    needle = payload
    if index == -1:
        index = text.find("dgv2xss")
        needle = "dgv2xss"
    if index == -1:
        return ""
    start = max(0, index - width // 2)
    return text[start:index + len(needle) + width // 2].replace("\n", " ")


def raw_script_present(text: str, payload: str) -> bool:
    """True when a hostile payload survives UNESCAPED in an HTML response.

    Deliberately strict: an unrelated page `<script>` tag plus the marker word
    elsewhere must NOT read as a hit; the marker must sit inside an executable
    context (script body, event handler, javascript: URL), or the payload must
    appear verbatim.
    """
    if not text:
        return False
    if payload in text:
        return True
    if re.search(r"<script\b[^>]*>[^<]{0,300}dgv2xss", text, re.IGNORECASE | re.DOTALL):
        return True
    # A handler/URL-shaped hit only counts when it is NOT inside an
    # entity-escaped construct: `&lt;svg/onload=alert(&#x27;dgv2xss&#x27;)&gt;`
    # is inert, while a raw `<svg onload=...>` is executable.
    for pattern in (
        r"on(?:error|load)\s*=\s*[^>\s]{0,120}dgv2xss",
        r"javascript:[^\"\'\s<>]{0,120}dgv2xss",
    ):
        for match in re.finditer(pattern, text, re.IGNORECASE):
            prefix = text[max(0, match.start() - 40):match.start()]
            if "&lt;" not in prefix and "&#" not in prefix:
                return True
    return False


def payload_present_as_data(text: str, payload: str) -> bool:
    return payload in text or json.dumps(payload)[1:-1] in text
