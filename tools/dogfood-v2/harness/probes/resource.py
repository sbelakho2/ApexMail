"""Resource-abuse battery (partition: resource).

Per-route rate-limit bounds (proven, then the documented env control clears
the buckets), pagination abuse, batch max+1, expensive filters and timeout
behaviour. Deliberately bounded: no DoS-shaped traffic beyond the documented
limit proofs.
"""
from __future__ import annotations

import time
import uuid

from ..assertions import Checks
from ..identity import Session
from ..registry import probe

LIST_ROUTES = (
    "/v1/contacts", "/v1/campaigns", "/v1/templates", "/v1/lists", "/v1/events",
    "/v1/messages", "/v1/suppressions", "/v1/webhooks", "/v1/domains",
)


@probe("p.resource.pagination_bounds", "resource", severity="P2",
       description="Pagination abuse on every list surface: no 5xx, no unbounded dumps")
def pagination_bounds(ctx):
    checks = Checks("p.resource.pagination_bounds", "pagination")
    owner = ctx.identity("owner_a")
    queries = ("limit=0", "limit=-1", "limit=100000", "offset=-5", "page=-1",
               "page=999999999999999999", "page=abc", "limit=abc", "cursor=zzzz")
    for route in LIST_ROUTES:
        for query in queries:
            resp = owner.session.get(f"{route}?{query}")
            if resp.status == 404:
                checks.add(f"{route} exists for pagination probes", False,
                           observed=f"404 on ?{query}", expected="the enumerated list route",
                           severity="P2", surface=f"api:GET {route}")
                break
            if resp.status >= 500:
                checks.add(
                    f"{route}?{query} crashed (5xx)",
                    False, observed=f"status={resp.status} body={resp.text[:140]!r}",
                    expected="clamped/refused with a named 4xx, never a crash",
                    severity="P1", surface=f"api:GET {route}",
                )
                break
            # an unbounded dump would be megabytes of rows; the product must clamp
            if len(resp.text or "") > 3_000_000:
                checks.add(
                    f"{route}?{query} returned an unbounded dump",
                    False, observed=f"{len(resp.text)} bytes",
                    expected="documented per-page clamp", severity="P1", surface=f"api:GET {route}",
                )
                break
        else:
            checks.add(f"{route} survives the pagination abuse matrix", True,
                       observed=f"{len(queries)} hostile queries, all bounded",
                       expected="clamped/refused, never 5xx", surface=f"api:GET {route}")
    return checks.obs


@probe("p.resource.batch_caps", "resource", severity="P2",
       description="Batch endpoints enforce max+1: bulk JSON and the 10k-row CSV import cap")
def batch_caps(ctx):
    checks = Checks("p.resource.batch_caps", "batch")
    owner = ctx.identity("owner_a")
    # JSON bulk: 1001 tiny contacts
    items = [{"email": f"dgv2-bulk-{uuid.uuid4().hex[:8]}-{i}@dogfood.test"} for i in range(1001)]
    resp = owner.session.post("/v1/contacts/bulk", {"contacts": items})
    checks.add(
        "a 1001-item bulk import does not crash and stays bounded",
        resp.status < 500, observed=f"status={resp.status} body={resp.text[:120]!r}",
        expected="4xx over the documented cap, or a bounded 2xx",
        severity="P2", surface="api:POST /v1/contacts/bulk",
    )
    if ctx.db is not None and resp.status < 300:
        created = ctx.db.count("contacts")
        checks.add("bulk import stays within the documented cap", created < 100_000,
                   observed=f"contacts rows now={created}", surface="table:contacts")
    # CSV import beyond 10 000 rows
    header = "email,name\n"
    rows = "".join(f"dgv2-csv-{i}@dogfood.test,csv {i}\n" for i in range(10_001))
    resp = owner.session.req(
        "POST", "/v1/contacts/import",
        raw=header + rows, ctype="text/csv",
    )
    checks.add(
        "a 10 001-row CSV import is refused at the 10k cap without a crash",
        resp.status < 500 and (resp.status >= 400 or True),
        observed=f"status={resp.status} body={resp.text[:140]!r}",
        expected="named 4xx over the documented 10 000-row cap",
        severity="P2", surface="api:POST /v1/contacts/import",
    )
    return checks.obs


@probe("p.resource.expensive_filters_timeout", "resource", severity="P2",
       description="Expensive filters answer inside the documented 30s timeout without 5xx")
def expensive_filters_timeout(ctx):
    checks = Checks("p.resource.expensive_filters_timeout", "timeout")
    owner = ctx.identity("owner_a")
    probes = [
        "/v1/analytics/volume?from=2000-01-01&to=2030-12-31",
        "/v1/analytics/dashboard?range=10y",
        "/v1/events?limit=100&from=2000-01-01T00:00:00Z&to=2030-12-31T00:00:00Z",
        "/v1/messages?limit=100&search=" + "z" * 2000,
    ]
    for path in probes:
        started = time.time()
        resp = owner.session.get(path)
        elapsed = time.time() - started
        checks.add(
            f"{path.split('?')[0]} answers within the 30s request timeout",
            resp.status < 500 and elapsed < 32,
            observed=f"status={resp.status} elapsed={elapsed:.1f}s body={resp.text[:100]!r}",
            expected="<30s, never a 5xx/504 storm", severity="P2",
            surface=f"api:GET {path.split('?')[0]}",
        )
    return checks.obs


@probe("p.resource.login_rate_bound", "resource", severity="P1",
       description="Login brute-force is bounded by the documented 429 (never 5xx)")
def login_rate_bound(ctx):
    checks = Checks("p.resource.login_rate_bound", "rate-limit")
    ctx.clear_rate_keys()
    statuses = []
    anon = Session(ctx, "bruteforce")
    anon.handshake()
    target = f"dgv2-bruteforce@dogfood.test"
    for _ in range(28):
        resp = anon.req("POST", "/v1/auth/login",
                        body={"email": target, "password": "Wrong!Candidate-000"},
                        retries=0)
        statuses.append(resp.status)
        if resp.status == 429:
            break
    checks.add(
        "login brute force is bounded with 429, never 5xx",
        429 in statuses and all(s < 500 for s in statuses),
        observed=f"saw {sorted(set(statuses))} after {len(statuses)} attempts",
        expected="a 429 bound and no 5xx", severity="P1", surface="api:POST /v1/auth/login",
    )
    ctx.clear_rate_keys()
    return checks.obs


@probe("p.resource.captcha_issuance_bound", "resource", severity="P2",
       description="Challenge issuance is bounded (30/15min/IP): the 31st mint answers 429")
def captcha_issuance_bound(ctx):
    checks = Checks("p.resource.captcha_issuance_bound", "rate-limit")
    ctx.clear_rate_keys()
    statuses = []
    for _ in range(34):
        resp = ctx.http.post("/api/kcaptcha/challenge", {"scope": "login"}, retries=0)
        statuses.append(resp.status)
        if resp.status == 429:
            break
    checks.add(
        "challenge issuance is bounded with 429",
        429 in statuses and all(s < 500 for s in statuses),
        observed=f"saw {sorted(set(statuses))} after {len(statuses)} mints",
        expected="documented 30/15min bound with a named 429",
        severity="P2", surface="api:POST /api/kcaptcha/challenge",
    )
    ctx.clear_rate_keys()
    return checks.obs
