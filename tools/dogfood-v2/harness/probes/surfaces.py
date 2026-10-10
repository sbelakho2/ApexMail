"""Mechanical surface-reach probes (partition: surface).

One probe per mount class, each exercising every enumerated (method, path)
from the router tables with an anonymous session and asserting the honest
anonymous contract:
  * never a 5xx on an empty request (crash on validated input);
  * a non-parameterized path must not 404 (an enumerated route that is not
    registered = the coverage ledger is lying or the route vanished);
  * authenticated/admin mounts must refuse anonymous callers (401/403) —
    a 2xx is an anonymous auth bypass (P0);
  * parameterized paths may 404 (resource-not-found is honest).
"""
from __future__ import annotations

import re
import uuid

from ..registry import probe

PARAM_RE = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")

BENIGN_UUID = "00000000-0000-4000-8000-00000000d9f2"


def concretize(path: str) -> str:
    def replace(match: re.Match) -> str:
        name = match.group(0)[1:].lower()
        if name in ("id", "campaign_id", "list_id", "contact_id", "template_id", "tenant_id",
                    "user_id", "domain_id", "webhook_id", "session_id", "message_id", "job_id"):
            return BENIGN_UUID
        if name == "token":
            return "dgv2-invalid-token"
        if name in ("email",):
            return "dgv2-absent@dogfood.test"
        return "dgv2x"

    return PARAM_RE.sub(replace, path)


def _has_params(path: str) -> bool:
    return bool(PARAM_RE.search(path))


def _anonymous_call(ctx, surface):
    path = concretize(surface.path)
    method = surface.method
    kw = {"host": ctx.cfg.host}
    if method in ("POST", "PUT", "PATCH"):
        if surface.path.startswith("/web/") or surface.mount_class == "ssr":
            return ctx.http.form(path, {}, **kw)
        return ctx.http.call(method, path, body={}, **kw)
    if method == "DELETE":
        return ctx.http.call(method, path, **kw)
    return ctx.http.get(path, **kw)


PHANTOM_404 = "the requested endpoint does not exist"


def _is_phantom_404(resp) -> bool:
    """A 404 means the ledger enumerated an UNMOUNTED route only when the
    response is the generic fallback: axum's route-not-found envelope
    (`the requested endpoint does not exist`), an empty body, or the SSR
    catch-all HTML page. A mounted handler may legitimately answer 404 for
    an unconfigured optional feature (e.g. `/v1/auth/sso/github` ->
    `{"code":"NOT_FOUND","message":"GitHub SSO is not configured"}`): that is
    a named refusal from a real route, not a phantom surface."""
    body = (resp.text or "").strip()
    if not body:
        return True
    if PHANTOM_404 in body:
        return True
    if "text/html" in (resp.headers.get("content-type", "") or ""):
        return True
    return False


def _check_routes(ctx, surfaces, checks, label: str):
    from ..assertions import env_block_detail, is_env_blocked

    for surface in surfaces:
        resp = _anonymous_call(ctx, surface)
        observed = f"status={resp.status} body={resp.text[:100]!r}"
        if resp.status == 0:
            checks.unreachable(f"{label} {surface.method} {surface.path}", resp.text, surface=surface.id)
            continue
        if is_env_blocked(resp):
            # the stack's own protection layer answered, not the product: the
            # surface could not be assessed. Recorded as a named environment
            # abort (the httpc recovery usually lifts this before it surfaces).
            checks.unreachable(
                f"{label} {surface.method} {surface.path}", env_block_detail(resp), surface=surface.id
            )
            continue
        if resp.status >= 500:
            checks.add(
                f"{label} {surface.method} {surface.path} must not 5xx on an empty request",
                False, observed=observed,
                expected="4xx/2xx without a server crash on an empty/benign request",
                severity="P1", surface=surface.id,
            )
            continue
        if resp.status == 404 and not _has_params(surface.path):
            if _is_phantom_404(resp):
                checks.add(
                    f"{label} {surface.method} {surface.path} is enumerated but answers 404",
                    False, observed=observed,
                    expected="a registered route (404 = the ledger enumerates a surface that is not mounted)",
                    severity="P2", surface=surface.id,
                )
            else:
                checks.add(
                    f"{label} {surface.method} {surface.path} is mounted and refuses with a named 404",
                    True, observed=observed,
                    expected="a mounted handler (a named unconfigured-feature 404 is a real route)",
                    surface=surface.id,
                )
            continue
        if surface.mount_class in ("authenticated", "admin") and 200 <= resp.status < 300:
            checks.add(
                f"{label} {surface.method} {surface.path} answered anonymous 2xx",
                False, observed=observed,
                expected="401/403 for an anonymous caller on an auth-gated mount",
                severity="P0", surface=surface.id,
            )
            continue
        checks.add(
            f"{label} {surface.method} {surface.path} answers the anonymous contract",
            True, observed=observed,
            expected="not 5xx; not 404 without params; auth mounts refuse anonymous",
            surface=surface.id,
        )


@probe(
    "p.surface.api_public_reach", "surface", subsumes=("api:*",), severity="P2",
    description="Anonymous reachability of every public JSON/API route from the router tables",
)
def api_public_reach(ctx):
    from ..assertions import Checks

    checks = Checks("p.surface.api_public_reach", "ledger")
    surfaces = [s for s in ctx.ledger.by_kind("api") if s.mount_class == "public"]
    _check_routes(ctx, surfaces, checks, "public")
    return checks.obs


@probe(
    "p.surface.api_authenticated_reach", "surface", subsumes=("api:*",), severity="P2",
    description="Anonymous refusal of every authenticated JSON route (401/403, never 5xx)",
)
def api_authenticated_reach(ctx):
    from ..assertions import Checks

    checks = Checks("p.surface.api_authenticated_reach", "ledger")
    surfaces = [s for s in ctx.ledger.by_kind("api") if s.mount_class == "authenticated"]
    _check_routes(ctx, surfaces, checks, "authenticated")
    return checks.obs


@probe(
    "p.surface.api_admin_reach", "surface", subsumes=("api:*",), severity="P2",
    description="Anonymous refusal of every control-plane (/v1/admin + /web/admin) route",
)
def api_admin_reach(ctx):
    from ..assertions import Checks

    checks = Checks("p.surface.api_admin_reach", "ledger")
    surfaces = [s for s in ctx.ledger.by_kind("api") if s.mount_class == "admin"]
    _check_routes(ctx, surfaces, checks, "admin")
    return checks.obs


@probe(
    "p.surface.ssr_reach", "surface", subsumes=("ssr:*",), severity="P2",
    description="Every ui-foundation baseline page on its host: public renders, gated redirects",
)
def ssr_reach(ctx):
    from ..assertions import Checks, env_block_detail, is_env_blocked

    checks = Checks("p.surface.ssr_reach", "ledger")
    for surface in ctx.ledger.by_kind("ssr"):
        host = ctx.cfg.host_for(surface.meta.get("surface", "web"))
        resp = ctx.http.get(surface.path, host=host, follow=False)
        observed = f"status={resp.status} host={host} len={len(resp.text)}"
        if resp.status == 0:
            checks.unreachable(f"SSR {surface.path} ({host})", resp.text, surface=surface.id)
            continue
        if is_env_blocked(resp):
            checks.unreachable(f"SSR {surface.path} ({host})", env_block_detail(resp), surface=surface.id)
            continue
        if resp.status >= 500:
            checks.add(
                f"SSR {surface.path} on {host} must not 5xx",
                False, observed=observed, expected="200 for public, 3xx/401/403 for gated",
                severity="P1", surface=surface.id,
            )
            continue
        if surface.auth_required:
            ok = resp.status in (302, 303, 307, 308, 401, 403)
            checks.add(
                f"gated SSR {surface.path} redirects/refuses anonymous visitors",
                ok, observed=observed, expected="3xx to /login, or 401/403", surface=surface.id,
            )
        else:
            ok = resp.status in (200, 301, 302, 303, 307, 308)
            checks.add(
                f"public SSR {surface.path} renders",
                ok, observed=observed, expected="200 (or a documented redirect)", surface=surface.id,
            )
    return checks.obs


STATIC_PREFIXES = ("/css", "/fonts", "/images", "/js", "/specs", "/giallo.css", "/manifest.json",
                   "/icon.svg", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/.well-known",
                   "/mail/config-v1.1.xml", "/pgp-key")


@probe(
    "p.surface.static_assets", "marketing", subsumes=("api:*",), severity="P3",
    description="Marketing static asset routes served on the marketing host (404 = broken asset path)",
)
def static_assets(ctx):
    from ..assertions import Checks, env_block_detail, is_env_blocked

    checks = Checks("p.surface.static_assets", "ledger")
    seen = set()
    for surface in ctx.ledger.by_kind("api"):
        if not surface.path.startswith(STATIC_PREFIXES) or surface.path in seen:
            continue
        seen.add(surface.path)
        if surface.method not in ("GET", "HEAD"):
            continue
        resp = ctx.http.get(surface.path, host=ctx.cfg.marketing_host)
        if is_env_blocked(resp):
            checks.unreachable(
                f"static asset {surface.path}", env_block_detail(resp), surface=surface.id
            )
            continue
        ok = resp.status in (200, 301, 302, 304)
        checks.add(
            f"static asset {surface.path} is served",
            ok, observed=f"status={resp.status} len={len(resp.text)}",
            expected="200/3xx/304 on the marketing host (a 404 is a broken asset reference)",
            severity="P3" if ok else "P2", surface=surface.id,
        )
    return checks.obs
