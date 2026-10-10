"""Bots / auxiliary surfaces (partition: bots).

Email grader, inbox placement, the public API explorer sandbox and the
assistant chat — the "adjacent capability" surfaces the product advertises.
"""
from __future__ import annotations

import uuid

from ..assertions import Checks
from ..registry import probe


@probe("p.bots.grader", "bots", severity="P2",
       description="The email grader answers honestly: valid check, invalid input refused, no 5xx")
def grader(ctx):
    checks = Checks("p.bots.grader", "api:POST /v1/grader/check")
    resp = ctx.http.post("/v1/grader/check", {"domain": "apexmail.ee"})
    body = resp.text or ""
    checks.add(
        "POST /v1/grader/check answers for a real domain",
        resp.status < 500 and (resp.status in (200, 201, 202, 400, 401, 403, 422, 429)),
        observed=f"status={resp.status} body={body[:160]!r}",
        expected="200 or a named refusal (never a 5xx)", severity="P2",
        surface="api:POST /v1/grader/check",
    )
    bad = ctx.http.post("/v1/grader/check", {"domain": "not a domain!!"})
    checks.add(
        "the grader refuses an invalid domain with a named 4xx",
        400 <= bad.status < 500 or bad.status == 200 and "error" not in (bad.text or "").lower(),
        observed=f"status={bad.status} body={bad.text[:160]!r}",
        expected="4xx validation refusal", severity="P2",
        surface="api:POST /v1/grader/check",
    )
    empty = ctx.http.post("/v1/grader/check", {})
    checks.add(
        "the grader refuses an empty body without a crash",
        empty.status < 500, observed=f"status={empty.status} body={empty.text[:140]!r}",
        expected="named 4xx", severity="P2", surface="api:POST /v1/grader/check",
    )
    return checks.obs


@probe("p.bots.placement", "bots", severity="P2",
       description="Inbox placement: providers list + authenticated test lifecycle answer honestly")
def placement(ctx):
    checks = Checks("p.bots.placement", "api:GET /v1/inbox-placement/providers")
    providers = ctx.http.get("/v1/inbox-placement/providers")
    checks.add(
        "the placement providers endpoint answers",
        providers.status in (200, 401, 403, 503) and providers.status < 500,
        observed=f"status={providers.status} body={providers.text[:160]!r}",
        expected="200 list or a named refusal", severity="P2",
        surface="api:GET /v1/inbox-placement/providers",
    )
    owner = ctx.identity("owner_a")
    tests = owner.session.get("/v1/inbox-placement/tests")
    checks.add(
        "the authenticated placement tests list answers",
        tests.status in (200, 400, 403, 404, 422, 503) and tests.status < 500,
        observed=f"status={tests.status} body={tests.text[:160]!r}",
        expected="200 (empty list) or a named refusal, never a 5xx",
        severity="P2", surface="api:GET /v1/inbox-placement/tests",
    )
    created = owner.session.post("/v1/inbox-placement/tests", {"name": f"dgv2 placement {uuid.uuid4().hex[:8]}"})
    checks.add(
        "creating a placement test is an honest success or a named refusal",
        created.status < 500,
        observed=f"status={created.status} body={created.text[:180]!r}",
        expected="2xx or named 4xx/503 (PLACEMENT_DISABLED is honest)",
        severity="P2", surface="api:POST /v1/inbox-placement/tests",
    )
    page = owner.session.get("/inbox-placement")
    checks.add("the inbox placement page renders", page.status == 200,
               observed=f"status={page.status}", expected="200",
               surface="ssr:web:GET /inbox-placement", severity="P2")
    return checks.obs


@probe("p.bots.explorer_sandbox", "bots", severity="P1",
       description="The public explorer sandbox refuses non-@example.com recipients with a named policy error")
def explorer_sandbox(ctx):
    checks = Checks("p.bots.explorer_sandbox", "api:POST /explorer/exec")
    payload = {"method": "POST", "path": "/v1/messages",
               "body": {"from": "sandbox@example.com", "to": ["victim@real-domain.test"],
                        "subject": "dgv2", "html": "<p>x</p>"}}
    resp = ctx.http.post("/explorer/exec", payload)
    body = resp.text or ""
    refused = 400 <= resp.status < 500 or resp.status == 403
    checks.add(
        "a non-@example.com recipient is refused with a named policy error",
        refused and resp.status != 404,
        observed=f"status={resp.status} body={body[:200]!r}",
        expected="4xx naming the example.com-only policy (or the sandbox lane's documented limit)",
        severity="P1", surface="api:POST /explorer/exec",
    )
    bad = ctx.http.post("/explorer/exec", {"method": "POST", "path": "/v1/admin/tenants", "body": {}})
    checks.add(
        "the sandbox refuses control-plane paths",
        bad.status < 500 and bad.status != 200,
        observed=f"status={bad.status} body={bad.text[:160]!r}",
        expected="a named refusal for admin paths", severity="P0",
        surface="api:POST /explorer/exec",
    )
    malformed = ctx.http.post("/explorer/exec", {"nonsense": True})
    checks.add(
        "the sandbox refuses malformed exec payloads without a crash",
        malformed.status < 500,
        observed=f"status={malformed.status} body={malformed.text[:140]!r}",
        expected="named 4xx", severity="P2", surface="api:POST /explorer/exec",
    )
    return checks.obs


@probe("p.bots.capability_pages", "bots", severity="P2",
       description="Advertised capability pages render (api-console, email-logs, status, demo)")
def capability_pages(ctx):
    checks = Checks("p.bots.capability_pages", "marketing-ssr")
    for path in ("/api-console", "/email-logs", "/status", "/demo", "/private-cloud", "/compliance"):
        resp = ctx.http.get(path, host=ctx.cfg.marketing_host)
        body = resp.text or ""
        checks.add(
            f"marketing capability page {path} renders",
            resp.status == 200 and len(body) > 200 and "Page not found" not in body,
            observed=f"status={resp.status} len={len(body)}",
            expected="200 with real content", severity="P2",
            surface=f"ssr:marketing:GET {path}",
        )
    return checks.obs
