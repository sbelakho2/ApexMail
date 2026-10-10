"""Probe registry, observations and partitions.

A probe is a named unit of adversarial work. It declares:
  * id            stable, dot-namespaced (`p.auth.signup_no_session`)
  * partition     exactly one (parallel-safe disjoint subsets)
  * surfaces      explicit ledger surface ids it exercises
  * fn            `fn(ctx) -> list[Observation]`
  * severity      default severity of a failed observation (P0..P3)
  * live_only     True for probes needing the real stack's SQL/daemon access
                  (the self-test fixture must answer their named checks, so a
                  probe is only live_only when it truly needs Docker).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Canonical partition list — coherent disjoint subsets for parallel runners.
PARTITIONS = (
    "surface",    # mechanical route reachability + coverage ledger
    "auth",       # auth lifecycle, captcha, sessions, CSRF
    "authz",      # cross-tenant IDOR, role matrix, CP gates
    "console",    # console SSR flows (dashboard, contacts, lists, campaigns, settings)
    "cp",         # control plane (operators, tenants, admin JSON, CP session gate)
    "marketing",  # marketing pages, assets, links, status
    "money",      # billing, quotas, entitlements, invoices, PAYG math
    "mail",       # send pipeline → Mailpit, headers, templates, domains/DKIM
    "tracking",   # tracking clicks/opens/pixels, tracking domains
    "bots",       # grader, inbox placement, explorer, assistant, demos
    "hostile",    # XSS/SQL/CRLF/traversal/oversize/unicode/ctype/proto
    "state",      # replay, double-submit, out-of-order, races
    "errors",     # error taxonomy honesty
    "resource",   # rate limits, pagination, batch caps, timeouts
    "invariants", # DB invariants, schema orphans, data scoping
    "infra",      # compose services, env surface, health/deep
    "pipeline",   # e2e enqueue→worker→terminal, webhooks, events
    "mutation",   # targeted probes used by --mutation-test
)


@dataclass
class Observation:
    probe_id: str
    surface: str
    title: str
    ok: bool
    observed: str = ""
    expected: str = ""
    severity: str = "P2"
    evidence: dict = field(default_factory=dict)
    # `unreachable` observations still FAIL the probe (no silent skips): they
    # are recorded as findings with severity P1 (harness-unreachable) unless a
    # documented reason downgrades them.
    kind: str = "check"          # check | unreachable | ledger | mutation

    def as_finding(self, index: int) -> dict:
        return {
            "id": f"F-{index:03d}",
            "probe_id": self.probe_id,
            "surface": self.surface,
            "severity": self.severity,
            "kind": self.kind,
            "title": self.title,
            "observed": self.observed,
            "expected": self.expected,
            "evidence": self.evidence,
        }


@dataclass
class Probe:
    id: str
    partition: str
    fn: object
    surfaces: tuple[str, ...] = ()
    severity: str = "P2"
    live_only: bool = False
    description: str = ""
    subsumes: tuple[str, ...] = ()   # surface prefixes/patterns this probe covers


class Registry:
    def __init__(self):
        self.probes: dict[str, Probe] = {}

    def register(self, probe: Probe) -> None:
        if probe.id in self.probes:
            raise ValueError(f"duplicate probe id {probe.id}")
        if probe.partition not in PARTITIONS:
            raise ValueError(f"probe {probe.id}: unknown partition {probe.partition}")
        self.probes[probe.id] = probe

    def all(self) -> list[Probe]:
        return list(self.probes.values())

    def selected(self, partitions: list[str]) -> list[Probe]:
        if not partitions:
            return self.all()
        unknown = [p for p in partitions if p not in PARTITIONS]
        if unknown:
            raise ValueError(f"unknown partitions: {unknown}; known: {list(PARTITIONS)}")
        return [p for p in self.probes.values() if p.partition in partitions]


REGISTRY = Registry()


def probe(id: str, partition: str, *, surfaces=(), severity="P2", live_only=False,
          description="", subsumes=()):
    """Decorator registering a probe function."""
    def wrap(fn):
        REGISTRY.register(
            Probe(
                id=id, partition=partition, fn=fn, surfaces=tuple(surfaces),
                severity=severity, live_only=live_only, description=description,
                subsumes=tuple(subsumes),
            )
        )
        return fn
    return wrap
