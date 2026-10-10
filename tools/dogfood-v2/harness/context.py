"""Execution context shared by all probes.

Holds the runtime config, the paced HTTP client, the KiwiCaptcha solver, the
mail source, the data plane and lazily-provisioned identities/fixtures. Also
tracks the run transcript and the evidence used by findings.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from . import HARNESS_VERSION
from .config import Config
from .dataplane import DataPlane
from .httpc import HttpClient, Response
from .kiwi import KiwiSolver
from .mail import MailSource


@dataclass
class Identity:
    name: str
    session: object = None          # identity.Session
    email: str = ""
    role: str = ""
    tenant_id: str = ""
    user_id: str = ""


@dataclass
class Context:
    cfg: Config
    http: HttpClient
    kiwi_solver: KiwiSolver
    mail: MailSource
    db: DataPlane
    identities: dict[str, Identity] = field(default_factory=dict)
    fixtures: dict[str, dict] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    ledger: object = None
    findings_meta: dict = field(default_factory=dict)
    mutation_targets: dict = field(default_factory=dict)
    # optional callable restarting the api-server under test (mutation mode
    # restarts the native mutant process; live uses the documented container
    # restart). Set by the mutation runner / used only on self-inflicted
    # DDOS_RATE_LIMITED episodes.
    restart_hook: object = None
    _ddos_recoveries: int = 0
    max_ddos_recoveries: int = 20

    # ── transcript ─────────────────────────────────────────────────────
    def note(self, message: str) -> None:
        line = f"[dogfood-v2] {message}"
        print(line, flush=True)
        try:
            with open(self.cfg.transcript, "a") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    # ── identity / fixture helpers (populated by identity.py, fixtures.py) ─
    def identity(self, name: str) -> Identity:
        if name == "operator":
            from .identity import ensure_operator

            ensure_operator(self)
        elif name not in self.identities:
            from .identity import ensure_identities

            ensure_identities(self)
        identity = self.identities.get(name)
        if identity is None:
            raise KeyError(f"identity {name!r} not provisioned")
        return identity

    def ensure(self, name: str, provisioner) -> Identity:
        identity = self.identities.get(name)
        if identity is None:
            identity = provisioner(self)
            self.identities[name] = identity
        return identity

    def fixture(self, name: str) -> dict:
        if name in ("owner_a", "owner_b") and name not in self.fixtures:
            from .fixtures import ensure_tenant_fixtures

            ensure_tenant_fixtures(self, name, name)
        return self.fixtures.get(name, {})

    # ── request helpers used across probes ─────────────────────────────
    def call(self, method: str, path: str, **kw) -> Response:
        return self.http.call(method, path, **kw)

    def unpaced(self):
        """Context manager: suspend the global pacer for a bounded window so a
        genuine concurrency race can be attempted (used only by the
        double-submit race with <=4 requests)."""
        return _Unpaced(self)

    def get(self, path: str, **kw) -> Response:
        return self.http.get(path, **kw)

    def post(self, path: str, body=None, **kw) -> Response:
        return self.http.post(path, body=body, **kw)

    def form(self, path: str, fields: dict[str, str], **kw) -> Response:
        return self.http.form(path, fields, **kw)

    # ── environment controls (documented) ──────────────────────────────
    def clear_rate_keys(self) -> None:
        """Documented env control: clear the shared limiter buckets. Live runs
        clear the live Redis; mutation runs clear the dedicated test Redis the
        mutant talks to; self-test clears the fixture's counters."""
        if self.cfg.mode == "self-test":
            try:
                import urllib.request
                request = urllib.request.Request(
                    self.cfg.base + "/__fixture/clear_rates", data=b"{}",
                    headers={"Content-Type": "application/json"}, method="POST")
                urllib.request.urlopen(request, timeout=5).read() # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            except Exception:  # noqa: BLE001
                pass
            return
        if self.cfg.mode == "mutation":
            from .dbctl import clear_redis_patterns

            clear_redis_patterns(self.cfg, host=self.cfg.mutation_redis[0],
                                 port=self.cfg.mutation_redis[1])
            return
        from .dbctl import clear_redis_patterns

        clear_redis_patterns(self.cfg)

    def live_like(self) -> bool:
        """True when the run targets a real stack (live or the mutated
        scratch build) where SQL/Redis/Docker evidence is available."""
        return self.cfg.mode in ("live", "mutation")

    def restart_api(self) -> bool:
        """Restart the api-server under test (clears the in-memory adaptive
        DDoS limiter). Documented environment control; used sparingly."""
        if self.restart_hook is not None:
            restarted = bool(self.restart_hook())
        elif not self.live_like():
            return False
        else:
            from .dbctl import compose_restart

            restarted = compose_restart(self.cfg, "api-server")
        if restarted:
            self._wait_for_api()
            # The dev stack's session-signing secret is boot-ephemeral, so
            # every restart invalidates the sessions minted before it. Drop
            # the cached identities (and the operator) so the next
            # ctx.identity(...) RE-ESTABLISHES them through the product
            # lifecycle — otherwise every probe after a DDoS-recovery restart
            # fails on a dead session and reports phantom findings
            # (dogfood 2026-10-10 post-restart cluster).
            self.identities.clear()
            self.note("ddos recovery: identities dropped for re-provisioning after restart")
        return restarted

    def _wait_for_api(self, timeout: float = 90.0) -> bool:
        """Poll /health until the restarted api-server answers (bounded)."""
        import urllib.request

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                request = urllib.request.Request(
                    self.cfg.base + "/health", headers={"Host": self.cfg.host}, method="GET"
                )
                with urllib.request.urlopen(request, timeout=5) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
                    if response.status == 200:
                        return True
            except Exception:  # noqa: BLE001
                pass
            time.sleep(2.0)
        return False

    def ddos_recovery(self) -> bool:
        """The documented environment control for a self-inflicted DDoS block:
        clear the shared limiter buckets and, bounded, restart the api-server
        so the in-process adaptive protector starts from a clean state.
        Every invocation is recorded in the transcript (never hidden)."""
        try:
            self.clear_rate_keys()
        except Exception as error:  # noqa: BLE001
            self.note(f"ddos recovery: limiter bucket clear failed: {error}")
        if not self.live_like():
            return False
        if self._ddos_recoveries >= self.max_ddos_recoveries:
            self.note(
                f"ddos recovery: budget exhausted ({self._ddos_recoveries}/"
                f"{self.max_ddos_recoveries}); not restarting again"
            )
            return False
        self._ddos_recoveries += 1
        self.note(
            f"ddos recovery {self._ddos_recoveries}/{self.max_ddos_recoveries}: "
            f"restarting the api-server under test to clear the in-memory DDoS blocklist"
        )
        return self.restart_api()

    # ── self-test fixture hooks (implemented by selftest.py) ───────────
    def fixture_assign(self, email: str, tenant_id: str, role: str) -> None:
        raise RuntimeError("fixture_assign is only available in --self-test mode")

    def fixture_promote_system(self, email: str) -> None:
        raise RuntimeError("fixture_promote_system is only available in --self-test mode")

    def fixture_verified_domain(self, tenant_id: str, name: str, domain_id: str) -> None:
        raise RuntimeError("fixture_verified_domain is only available in --self-test mode")

    def fixture_plan(self, tenant_id: str, plan: str) -> None:
        raise RuntimeError("fixture_plan is only available in --self-test mode")


def build_context(cfg: Config, *, ledger=None) -> Context:
    from .dataplane import PsqlDataPlane
    from .mail import MailpitSource

    http = HttpClient(cfg)
    solver = KiwiSolver(http, base="", host="")
    mail = MailpitSource(cfg.mailpit)
    db = PsqlDataPlane(cfg)
    ctx = Context(cfg=cfg, http=http, kiwi_solver=solver, mail=mail, db=db, ledger=ledger)
    # On a 429 the solver flushes the documented limiter buckets once and
    # retries — the same recovery the identity layer uses.
    solver.reset_hook = ctx.clear_rate_keys
    # A persistent 403 DDOS_BLOCKED triggers the documented limiter recovery
    # (bucket clear + bounded api-server restart) from inside the HTTP client.
    http.recovery_hook = ctx.ddos_recovery
    return ctx


class _Unpaced:
    """Context manager suspending the global pacer (bounded race windows only)."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.saved = ctx.cfg.pace_seconds

    def __enter__(self):
        self.ctx.cfg.pace_seconds = 0.0
        return self.ctx

    def __exit__(self, *exc):
        self.ctx.cfg.pace_seconds = self.saved
        return False
