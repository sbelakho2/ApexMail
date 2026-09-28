#!/usr/bin/env python3
"""Capability-claims vs production-wiring gate.

Executable honesty: what the product ADVERTISES (marketing security page,
architecture page, compliance templates) must equal what is DEPLOYED, and
both directions are driven from one machine-readable source — the per-capability
scan_aliases + stage ladder in docs/development/capability-registry.json.

Checks (each prints PASS/FAIL/WARN; any FAIL exits 1):
  1. Registry sanity: every entry has a known lifecycle stage; entries at
     stage >= runtime-wired prove their deploy surface:
       - evidence.docker_target is a `FROM runtime-base AS <target>` stage in
         services/mail-server/Dockerfile AND declared in
         docs/development/topology-manifest.json;
       - evidence.compose_service exists in docker-compose.yml /
         docker-compose.prod.yml;
       - evidence.env_gate.name is greppable in the wiring crate's Rust
         sources (null env_gate = always-on wiring, allowed).
  2. Claim surfaces: an alias of a capability whose stage is BELOW
     runtime-wired may appear only inside explicit [roadmap]-marked context;
     a bare mention on a marketing/compliance surface is a claim, and claims
     require runtime-wiring — otherwise FAIL. (Direction: advertised ->
     deployed.)
  3. README wiring-status lines match the registry: stage >= runtime-wired
     forbids a 'NOT WIRED INTO PRODUCTION' banner (unless a
     stale_marker_exceptions needle still proves the banner stale) and
     requires the env-gate name in the README when a gate is declared;
     stage < runtime-wired requires the banner or an explicit
     'wiring in flight' statement.
  4. Advertised-stage entries with aliases must actually be claimed somewhere
     (registry -> surface direction); drift is a WARN.

Strictness (the wiring-wave contract): in-flight items — an env gate not yet
greppable in the tree, a README not yet updated to the new status — print as
WARN and exit 0 by default. Set CAPABILITY_GATE_STRICT=1 to fail on them
(flip this in ci/stages/validate.sh once the in-flight wiring has landed).
Structural failures (missing docker target for a claimed-deployed entry,
sub-advertised naming outside [roadmap], broken needles) fail in BOTH modes.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "docs/development/capability-registry.json"
MANIFEST_PATH = ROOT / "docs/development/topology-manifest.json"
DOCKERFILE_PATH = ROOT / "services/mail-server/Dockerfile"
COMPOSE_DEV_PATH = ROOT / "docker-compose.yml"
COMPOSE_PROD_PATH = ROOT / "docker-compose.prod.yml"
CRATES_DIR = ROOT / "services/mail-server/crates"

STRICT = os.environ.get("CAPABILITY_GATE_STRICT", "0") == "1"

failures: list[str] = []
warnings: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail and not ok else ""
    print(f"{status} {name}{suffix}")
    if not ok:
        failures.append(name)


def soft(name: str, ok: bool, detail: str = "") -> None:
    """In-flight item: WARN (default) or FAIL (CAPABILITY_GATE_STRICT=1)."""
    if ok:
        print(f"PASS {name}")
        return
    if STRICT:
        print(f"FAIL {name} — {detail}")
        failures.append(name)
    else:
        print(f"WARN {name} — {detail} (in-flight wiring; CAPABILITY_GATE_STRICT=1 would fail)")
        warnings.append(name)


REGISTRY = json.loads(REGISTRY_PATH.read_text())
MANIFEST = json.loads(MANIFEST_PATH.read_text())
DOCKERFILE = DOCKERFILE_PATH.read_text()
COMPOSE_DEV = COMPOSE_DEV_PATH.read_text()
COMPOSE_PROD = COMPOSE_PROD_PATH.read_text()

LADDER = REGISTRY["lifecycle_ladder"]
STAGE_INDEX = {stage: i for i, stage in enumerate(LADDER)}
RUNTIME_WIRED = STAGE_INDEX["runtime-wired"]
CAPABILITIES = REGISTRY["capabilities"]

manifest_targets = {s.get("docker_target") for s in MANIFEST["services"] if s.get("docker_target")}
manifest_names = {s["name"] for s in MANIFEST["services"]}


def compose_has_service(name: str) -> bool:
    if not re.fullmatch(r"[a-z0-9-]+", name or ""):
        return True  # prose value ("all prod daemons") — not checkable, allowed
    pattern = re.compile(rf"^\s+{re.escape(name)}:", re.M)
    return bool(pattern.search(COMPOSE_DEV) or pattern.search(COMPOSE_PROD))


def rust_sources_mention(needle: str) -> list[Path]:
    hits = []
    if CRATES_DIR.is_dir():
        for path in CRATES_DIR.rglob("*.rs"):
            try:
                if needle in path.read_text():
                    hits.append(path)
            except OSError:
                continue
    return hits


# ── 1. Per-entry evidence ────────────────────────────────────────────────────
for entry in CAPABILITIES:
    cap = entry.get("capability", "<unnamed>")
    stage = entry.get("stage")
    if stage not in STAGE_INDEX:
        check(f"registry-stage:{cap}", False, f"unknown stage {stage!r} (ladder: {LADDER})")
        continue
    if STAGE_INDEX[stage] < RUNTIME_WIRED:
        continue  # sub-runtime-wired entries carry no deploy-surface duty

    ev = entry.get("evidence") or {}

    target = ev.get("docker_target")
    if target:
        check(
            f"docker-target:{cap}:{target}",
            re.search(rf"FROM runtime-base AS {re.escape(target)}\b", DOCKERFILE) is not None,
            f"stage {stage} but the Dockerfile has no `FROM runtime-base AS {target}` stage",
        )
        check(
            f"manifest-entry:{cap}:{target}",
            target in manifest_targets,
            f"docker target `{target}` is not declared in topology-manifest.json",
        )
    else:
        # null docker_target is legitimate for INFRA-backed capabilities (the
        # compose service runs a stock image, a service-external Dockerfile,
        # or the capability is a compose-level property) — but then the
        # compose service becomes mandatory and a prose value must be
        # justified in the explanation.
        explanation = ev.get("explanation") or ""
        justified_prose = compose_service and not compose_has_service(compose_service) and "docker-compose" in explanation
        check(
            f"deploy-surface:{cap}",
            bool(compose_service) and (compose_has_service(compose_service) or justified_prose),
            "stage {} without docker_target needs a resolvable compose_service "
            "(or a compose-level property justified in the explanation)".format(stage),
        )

    compose_service = ev.get("compose_service")
    if compose_service:
        check(
            f"compose-service:{cap}:{compose_service}",
            compose_has_service(compose_service),
            f"compose service `{compose_service}` not found in docker-compose.yml / docker-compose.prod.yml",
        )
    else:
        check(
            f"compose-service:{cap}",
            False,
            f"stage {stage} requires a compose_service in evidence",
        )

    gate = ev.get("env_gate") or {}
    gate_name = gate.get("name") if isinstance(gate, dict) else None
    if gate_name:
        hits = rust_sources_mention(gate_name)
        check(
            f"env-gate:{cap}:{gate_name}",
            bool(hits),
            "env gate not found in any Rust source under services/mail-server/crates — "
            f"the wiring this stage claims has not landed ({gate_name})",
        )

# ── 2. Claim surfaces: advertised implies runtime-wired ─────────────────────
MARKER = REGISTRY["scan"]["marker"]
MARKER_CLOSE = REGISTRY["scan"]["marker_close"]


def alias_pattern(alias: str) -> re.Pattern:
    """Short tokens and all-caps acronyms match with word boundaries (acronyms
    case-sensitively); phrase aliases match as case-insensitive substrings."""
    if alias.isupper() or len(alias) < 5:
        flags = 0 if alias.isupper() else re.IGNORECASE
        return re.compile(rf"\b{re.escape(alias)}\b", flags)
    return re.compile(re.escape(alias), re.IGNORECASE)


def surface_findings(text: str) -> list[tuple[int, str, bool]]:
    """Yield (line_number, line, in_roadmap_context) for scannable lines."""
    findings = []
    in_roadmap = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#"):  # ATX headings organize; they do not claim
            in_roadmap = False
            continue
        has_marker = MARKER in line
        has_close = MARKER_CLOSE in line
        if has_marker:
            # A marker line is itself roadmap context; an inline close ends it.
            in_roadmap = not has_close
            findings.append((lineno, line, True))
            continue
        if in_roadmap:
            findings.append((lineno, line, True))
            continue
        findings.append((lineno, line, False))
    return findings


alias_hits: dict[str, int] = {}  # capability -> bare-line hit count
compiled: list[tuple[dict, list[re.Pattern]]] = []
for entry in CAPABILITIES:
    aliases = entry.get("scan_aliases") or []
    if aliases:
        compiled.append((entry, [alias_pattern(a) for a in aliases]))

surfaces = REGISTRY["scan"]["surfaces"]
for rel in surfaces:
    path = ROOT / rel
    if not path.is_file():
        check(f"surface-exists:{rel}", False, "claim surface missing from the tree")
        continue
    for lineno, line, in_roadmap in surface_findings(path.read_text()):
        for entry, patterns in compiled:
            stage = entry.get("stage")
            if stage not in STAGE_INDEX:
                continue  # already reported by the sanity check above
            matched = any(p.search(line) for p in patterns)
            if not matched:
                continue
            cap = entry["capability"]
            if not in_roadmap:
                alias_hits[cap] = alias_hits.get(cap, 0) + 1
                if STAGE_INDEX[stage] < RUNTIME_WIRED:
                    check(
                        f"claim-vs-stage:{cap}:{path.name}:{lineno}",
                        False,
                        f"claim surface names `{entry['scan_aliases']}` outside [roadmap] context "
                        f"but the registry stage is `{stage}` — implement and promote the entry, "
                        "or move the claim into [roadmap] context",
                    )

# ── 3. README wiring-status lines match the registry stages ─────────────────
def readme_path(crate: str) -> Path | None:
    crate = crate.strip()
    if not crate.startswith("crates/"):
        return None
    head = crate.split()[0].rstrip("/")
    path = CRATES_DIR / head[len("crates/"):] / "README.md"
    return path if path.is_file() else None


def exception_holds(name: str, exc: str) -> bool:
    """A stale-marker exception holds only while every `<path>:<needle>` pair
    still matches — the checker names files as 'path must contain needle'.
    Paths are resolved against the repo root, then against
    services/mail-server/ (registry prose uses crate-relative shorthand)."""
    for m in re.finditer(r"([A-Za-z0-9_./-]+\.(?:rs|toml|md)) must contain '([^']+)'", exc):
        rel, needle = m.group(1), m.group(2)
        fpath = ROOT / rel
        if not fpath.is_file():
            fpath = ROOT / "services/mail-server" / rel
        if not fpath.is_file() or needle not in fpath.read_text():
            return False
    return True


exceptions = REGISTRY.get("stale_marker_exceptions") or {}
for entry in CAPABILITIES:
    cap = entry.get("capability")
    stage = entry.get("stage")
    if stage not in STAGE_INDEX:
        continue
    if entry.get("readme_status_exemption"):
        # The README banner is not the truthful surface for this entry (the
        # exemption string says why, and where the status actually lives).
        print(f"SKIP readme-status:{cap} — {entry['readme_status_exemption']}")
        continue
    rpath = readme_path(entry.get("crate") or "")
    if rpath is None:
        continue
    text = rpath.read_text()
    gate = entry.get("evidence", {}).get("env_gate") or {}
    gate_name = gate.get("name") if isinstance(gate, dict) else None

    if STAGE_INDEX[stage] >= RUNTIME_WIRED:
        marker_absent = "NOT WIRED INTO PRODUCTION" not in text
        if marker_absent:
            check(f"readme-status:{cap}", True)
        else:
            exc = exceptions.get(rpath.parent.name)
            holds = bool(exc) and exception_holds(rpath.parent.name, exc)
            soft(
                f"readme-status:{cap}",
                holds,
                "README still carries the NOT-WIRED banner and the stale_marker_exception "
                + ("needle no longer matches — re-triage the registry entry"
                   if exc else "has no exception — re-triage the registry entry"),
            )
        if gate_name and gate_name not in text:
            soft(
                f"readme-gate-name:{cap}",
                False,
                f"registry declares env gate {gate_name} but {rpath.relative_to(ROOT)} "
                "never names it — the README wiring-status line and the registry disagree",
            )
    else:
        admitted = "NOT WIRED INTO PRODUCTION" in text or "wiring in flight" in text.lower()
        soft(
            f"readme-status:{cap}",
            admitted,
            f"stage `{stage}` but {rpath.relative_to(ROOT)} carries neither the NOT-WIRED "
            "banner nor a 'wiring in flight' statement — update the status line",
        )

# ── 4. Registry -> surface direction (advisory drift) ───────────────────────
for entry in CAPABILITIES:
    cap = entry.get("capability")
    aliases = entry.get("scan_aliases") or []
    if entry.get("stage") == "advertised" and aliases and alias_hits.get(cap, 0) == 0:
        warnings.append(
            f"registry-stage-drift:{cap}: stage `advertised` with aliases {aliases} but no "
            "claim surface names it outside [roadmap] context (advisory drift)"
        )
for w in [w for w in warnings if w.startswith("registry-stage-drift")]:
    print(f"WARN {w}")

# ── In-flight wiring notice ─────────────────────────────────────────────────
in_flight = (REGISTRY.get("in_flight_wiring") or {}).get("items") or []
for item in in_flight:
    gate_name = item.get("env_gate")
    landed = bool(rust_sources_mention(gate_name)) if gate_name else False
    state = "LANDED (re-triage the registry stage)" if landed else "not landed yet"
    print(f"INFO in-flight wiring: {item.get('capability')} via {gate_name} — {state}")

print()
if failures:
    print(f"CAPABILITY CLAIM FAILURES: {len(failures)}" + (" (strict mode)" if STRICT else ""))
    for name in failures:
        print(f"  - {name}")
    sys.exit(1)
print(
    "capability claims: all green "
    f"({len(warnings)} in-flight warning(s), CAPABILITY_GATE_STRICT={'1' if STRICT else '0'})"
)
