"""Self-test orchestration — `--self-test`.

Starts the disposable fixture server (harness/fixture.py) on two free ports
(web + tracking), points a fixture-mode Context at it, and runs the ENTIRE
probe battery. Every dynamic probe must pass against the honest fixture; any
failure here is a harness bug, caught before the harness is aimed at the live
stack. Repo-static probes (env surface, compose definition notes) are reported
separately because they describe the real repository, not the fixture.
"""
from __future__ import annotations

import socket
import threading
import time
from http.server import ThreadingHTTPServer

from .config import Config
from .context import Context
from .dataplane import FixtureDataPlane
from .fixture import build_handler
from .httpc import HttpClient
from .kiwi import KiwiSolver
from .mail import FixtureMailSource

STATIC_PROBES = {"p.infra.env_surface", "p.infra.services", "p.inv.schema_orphans"}


def coverage_rule_selfcheck() -> tuple[bool, list[str]]:
    """Prove the fail-if-unprobed rule and the allowlist justification rules
    with synthetic surfaces (no live stack needed). Returns (ok, lines)."""
    import json
    import tempfile
    from pathlib import Path

    from .coverage import compute_coverage
    from .ledger import Ledger, Surface
    from .registry import Probe

    lines: list[str] = []
    ok = True
    covered_id = "api:GET /selftest-probed"
    unprobed_id = "api:GET /selftest-unprobed"
    probe = Probe(id="p.selftest.synthetic", partition="surface", fn=lambda ctx: [], surfaces=(covered_id,))
    covered_ledger = Ledger(surfaces=[
        Surface(id=covered_id, kind="api", method="GET", path="/selftest-probed"),
    ])
    unprobed_ledger = Ledger(surfaces=[
        Surface(id=unprobed_id, kind="api", method="GET", path="/selftest-unprobed"),
    ])

    class _Registry:
        def all(self):
            return [probe]

    with tempfile.TemporaryDirectory() as tmp:
        empty = Path(tmp) / "empty.json"
        empty.write_text('{"entries": []}')
        bare = compute_coverage(unprobed_ledger, _Registry(), empty)
        if bare.ok or not bare.unprobed:
            ok = False
            lines.append("FAIL: an unprobed surface did NOT fail the coverage rule")
        else:
            lines.append("ok: unprobed surface → coverage.ok=False (fail-if-unprobed)")
        covered = compute_coverage(covered_ledger, _Registry(), empty)
        if not covered.ok:
            ok = False
            lines.append("FAIL: a declared probe did not cover its surface id")
        else:
            lines.append("ok: a declared probe covers its surface id")
        justified = Path(tmp) / "justified.json"
        justified.write_text(json.dumps({"entries": [{
            "id": unprobed_id, "owner": "lane-d1",
            "reason": "synthetic surface used only by the coverage-rule self-check",
        }]}))
        allowed = compute_coverage(unprobed_ledger, _Registry(), justified)
        if not allowed.ok or not allowed.allowlisted:
            ok = False
            lines.append("FAIL: a justified allowlist entry did not clear the unprobed list")
        else:
            lines.append("ok: justified allowlist entry clears the surface (owner+reason recorded)")
        invalid = Path(tmp) / "invalid.json"
        invalid.write_text(json.dumps({"entries": [{"id": unprobed_id, "owner": "lane-d1", "reason": "short"}]}))
        rejected = compute_coverage(unprobed_ledger, _Registry(), invalid)
        if rejected.ok or not rejected.invalid_allowlist:
            ok = False
            lines.append("FAIL: a blanket/under-justified allowlist entry was accepted")
        else:
            lines.append("ok: under-justified allowlist entry rejected (no blanket allowances)")
    return ok, lines


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run_self_test(cfg: Config, ledger) -> int:
    from .registry import REGISTRY
    from .runner import finalize, run_probes

    rule_ok, rule_lines = coverage_rule_selfcheck()
    for line in rule_lines:
        print(f"[dogfood-v2] ledger self-check: {line}", flush=True)

    web_port = _free_port()
    tracking_port = _free_port()
    fixture_cfg = Config()
    fixture_cfg.__dict__.update(cfg.__dict__)
    fixture_cfg.mode = "self-test"
    fixture_cfg.base = f"http://127.0.0.1:{web_port}"
    fixture_cfg.host = "127.0.0.1"
    fixture_cfg.marketing_host = "marketing.localhost"
    fixture_cfg.tracking = f"http://127.0.0.1:{tracking_port}"
    fixture_cfg.mailpit = fixture_cfg.base
    fixture_cfg.pace_seconds = 0.0
    fixture_cfg.max_requests = 200_000
    fixture_cfg.json_out = cfg.out_dir / "selftest-findings.json"
    fixture_cfg.coverage_out = cfg.out_dir / "selftest-coverage.json"

    handlers = {
        "web": build_handler(fixture_cfg, ledger, tracking=False),
        "tracking": build_handler(fixture_cfg, ledger, tracking=True),
    }
    server = ThreadingHTTPServer(("127.0.0.1", web_port), handlers["web"])
    tracking_server = ThreadingHTTPServer(("127.0.0.1", tracking_port), handlers["tracking"])
    servers = (server, tracking_server)
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    http = HttpClient(fixture_cfg)
    solver = KiwiSolver(http, base="", host="")
    ctx = Context(
        cfg=fixture_cfg, http=http, kiwi_solver=solver,
        mail=FixtureMailSource(fixture_cfg.base), db=FixtureDataPlane(fixture_cfg.base),
        ledger=ledger,
    )
    solver.reset_hook = ctx.clear_rate_keys
    ctx.fixture_assign = lambda email, tenant, role: _fixture_post(
        fixture_cfg, "/__fixture/assign", {"email": email, "tenant": tenant, "role": role})
    ctx.fixture_promote_system = lambda email: _fixture_post(
        fixture_cfg, "/__fixture/promote", {"email": email})
    ctx.fixture_consent = lambda tenant, cid, email: _fixture_post(
        fixture_cfg, "/__fixture/consent", {"tenant": tenant, "contact": cid, "email": email})
    ctx.fixture_verified_domain = lambda tenant, name, did: _fixture_post(
        fixture_cfg, "/__fixture/domain", {"tenant": tenant, "name": name, "id": did})
    ctx.fixture_plan = lambda tenant, plan: _fixture_post(
        fixture_cfg, "/__fixture/plan", {"tenant": tenant, "plan": plan})

    ctx.note(f"self-test fixture on {fixture_cfg.base} (tracking {fixture_cfg.tracking})")
    try:
        observations, probe_started = run_probes(ctx, REGISTRY, partitions=cfg.partitions)
        result = finalize(ctx, observations, probe_started)
    finally:
        for srv in servers:
            srv.shutdown()

    dynamic_failures = [o for o in result.observations if not o.ok and o.probe_id not in STATIC_PROBES]
    static_failures = [o for o in result.observations if not o.ok and o.probe_id in STATIC_PROBES]
    ctx.note(
        f"self-test: {len(result.observations)} checks, {len(dynamic_failures)} dynamic failures, "
        f"{len(static_failures)} repo-static notes"
    )
    if dynamic_failures or not rule_ok:
        print("SELF-TEST FAILED — the harness disagrees with its own honest fixture:")
        if not rule_ok:
            print("  - ledger self-check failed (fail-if-unprobed rule or allowlist justification)")
        for obs in dynamic_failures[:60]:
            print(f"  - {obs.probe_id} :: {obs.title} :: {obs.observed[:200]}")
        return 1
    if static_failures:
        print("self-test: repo-static notes (recorded; not fixture-contract failures):")
        for obs in static_failures[:20]:
            print(f"  note: {obs.probe_id} :: {obs.title}")
    print("SELF-TEST GREEN — every dynamic probe matches the honest fixture contract")
    return 0


def _fixture_post(cfg: Config, path: str, body: dict) -> None:
    import json
    import urllib.request

    request = urllib.request.Request(
        cfg.base + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=10).read() # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
    except Exception as error:  # noqa: BLE001
        raise RuntimeError(f"fixture call {path} failed: {error}") from error
