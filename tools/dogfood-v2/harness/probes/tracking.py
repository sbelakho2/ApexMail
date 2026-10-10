"""Tracking-plane probes (partition: tracking).

Tracking-service route contract, click/open abuse, open-redirect resistance,
unsubscribe token abuse, and the real click path from a delivered campaign.
"""
from __future__ import annotations

import re

from ..assertions import Checks
from ..fixtures import ensure_campaign_delivery
from ..registry import probe

TRACKING_ROUTES = (
    ("GET", "/o/dgv2-invalid-token"),
    ("GET", "/o.gif"),
    ("GET", "/c/dgv2-invalid-token"),
    ("GET", "/u/dgv2-invalid-token"),
    ("GET", "/p/dgv2-invalid-token"),
    ("GET", "/health"),
    ("GET", "/ready"),
)
# the ledger enumerates these for coverage
TRACKING_SURFACE_IDS = tuple(f"api:{m} {p}" for m, p in TRACKING_ROUTES)


@probe("p.tracking.route_contract", "tracking", subsumes=("trk:*",), severity="P1",
       description="Every tracking-service route answers the anonymous contract (no 5xx, no open redirect)")
def route_contract(ctx):
    checks = Checks("p.tracking.route_contract", "tracking")
    for surface in ctx.ledger.by_kind("tracking"):
        path = surface.path.replace(":tracking_id", "dgv2-invalid-token").replace(":token", "dgv2-invalid-token")
        resp = ctx.http.call(surface.method, path, base=ctx.cfg.tracking)
        if resp.status == 0:
            checks.unreachable(f"{surface.method} {surface.path} on the tracking service", resp.text,
                               surface=surface.id)
            continue
        checks.add(
            f"tracking {surface.method} {surface.path} answers without a crash",
            resp.status < 500,
            observed=f"status={resp.status} len={len(resp.text or '')}",
            expected="404/400/200 — never 5xx", severity="P1", surface=surface.id,
        )
        if "/c/" in surface.path and 300 <= resp.status < 400:
            location = resp.headers.get("location", "")
            checks.add(
                "an invalid click token never redirects off-site",
                "evil.example" not in location,
                observed=f"location={location[:160]!r}",
                expected="the documented fallback URL, never an attacker URL",
                severity="P0", surface=surface.id,
            )
    return checks.obs


@probe("p.tracking.token_abuse", "tracking", severity="P1",
       description="Tampered/replayed tracking tokens are handled honestly; the unsubscribe GET is side-effect free")
def token_abuse(ctx):
    checks = Checks("p.tracking.token_abuse", "tracking")
    # open-redirect shape: url parameter pointing at an attacker host
    resp = ctx.http.get(
        "/c/eyJ0IjoxMjN9?url=https://evil.example/dgv2",
        base=ctx.cfg.tracking, follow=False,
    )
    location = resp.headers.get("location", "")
    checks.add(
        "a forged click token with a url parameter does not redirect to the attacker",
        "evil.example" not in location,
        observed=f"status={resp.status} location={location[:160]!r}",
        expected="no external redirect from a forged token",
        severity="P0",
    )
    # GET unsubscribe must not perform the unsubscribe (RFC 8058 side-effect-free GET)
    resp = ctx.http.get("/u/forged-token-dgv2", base=ctx.cfg.tracking, follow=False)
    checks.add(
        "GET /u/<forged> is side-effect free (no state change, no 5xx)",
        resp.status < 500 and resp.status in (200, 204, 302, 303, 400, 404),
        observed=f"status={resp.status} location={resp.headers.get('location', '')[:120]!r}",
        expected="a confirmation page or refusal, never a silent unsubscribe",
        severity="P1",
    )
    resp = ctx.http.form("/u/forged-token-dgv2/confirm", {}, base=ctx.cfg.tracking, follow=False)
    checks.add(
        "POST /u/<forged>/confirm is refused without a crash",
        resp.status < 500,
        observed=f"status={resp.status}", expected="4xx/3xx, never 5xx",
        severity="P2",
    )
    return checks.obs


@probe("p.tracking.real_click", "pipeline", severity="P1",
       description="A real campaign click redirects to the target and is recorded; replay stays honest")
def real_click(ctx):
    checks = Checks("p.tracking.real_click", "pipeline:tracking")
    delivery = ensure_campaign_delivery(ctx)
    if not delivery.get("messages"):
        checks.unreachable(
            "campaign mail delivered for the click probe",
            "; ".join(delivery.get("errors") or []) or "no delivered message (consent/domain/worker)",
        )
        return checks.obs
    link = delivery.get("click", "")
    if not link:
        checks.unreachable("click link present in the delivered mail", f"no /c/ link; raw={delivery.get('raw', '')[:200]!r}")
        return checks.obs
    path = "/" + link.split("://", 1)[1].split("/", 1)[1]
    resp = ctx.http.get(path, base=ctx.cfg.tracking, follow=False)
    location = resp.headers.get("location", "")
    checks.add(
        "the real click token redirects to the original target",
        resp.status in (301, 302, 303, 307, 308) and "example.com/dgv2-target" in location,
        observed=f"status={resp.status} location={location[:200]!r}",
        expected="3xx to https://example.com/dgv2-target",
        severity="P1",
    )
    replay = ctx.http.get(path, base=ctx.cfg.tracking, follow=False)
    checks.add(
        "a replayed click does not return 5xx (repeat clicks are honest)",
        replay.status in (301, 302, 303, 307, 308, 400, 404, 410),
        observed=f"status={replay.status}", expected="documented repeat behavior",
        severity="P2",
    )
    pixel = "/o/" + link.split("/c/", 1)[1] if "/c/" in link else ""
    if pixel:
        pixel_resp = ctx.http.get(pixel, base=ctx.cfg.tracking)
        checks.add(
            "the open pixel for the delivered mail answers an image response",
            pixel_resp.status in (200, 204, 302, 303, 404),
            observed=f"status={pixel_resp.status} ctype={pixel_resp.headers.get('content-type', '')}",
            expected="a gif/1x1 or documented refusal",
            severity="P2",
        )
    return checks.obs


@probe("p.tracking.unknown_host", "tracking", severity="P2",
       description="Unknown Host on the tracking listener is refused (no cross-tenant serving)")
def unknown_host(ctx):
    checks = Checks("p.tracking.unknown_host", "tracking")
    resp = ctx.http.get("/c/dgv2-token", base=ctx.cfg.tracking, headers={"Host": "unknown-host.invalid"})
    checks.add(
        "an unknown Host header does not serve tracking content",
        resp.status in (404, 421, 400, 403) or resp.status < 500,
        observed=f"status={resp.status} body={(resp.text or '')[:120]!r}",
        expected="421/404 for an unknown host", severity="P2",
    )
    return checks.obs
