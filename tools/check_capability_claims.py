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
  5. Registry self-consistency: every entry carries exactly ONE lifecycle
     state — its `stage`. Retired-state language ("not landed", "unlanded",
     "wiring in flight", "not wired", "no caller") anywhere in an entry's own
     text FAILS, as does wording contradicting the stage (library-only /
     unwired language on a stage >= runtime-wired entry; "not landed" on an
     `implemented` entry, which asserts the code IS in the tree).
  6. in_flight_wiring items stay honest: an item whose env gate is already
     greppable in the wiring crate's Rust sources has LANDED and FAILS in
     both modes — remove it and raise the entry's stage in the same change.

Self-test: `check_capability_claims.py --self-test` builds a hermetic
fixture tree in a temp dir, copies this checker into it, and proves the
gate FAILS when its evidence disappears (nonexistent docker target, a
demoted advertised stage still named on a claim surface, retired-state
text, a landed in-flight item) and passes on the unmutated fixture. The
real registry is never touched.

Strictness (the wiring-wave contract): genuinely-unlanded in-flight items
print as WARN and exit 0 by default; CAPABILITY_GATE_STRICT=1 fails on
them. Structural failures (missing docker target for a claimed-deployed
entry, sub-advertised naming outside [roadmap], broken needles,
self-consistency violations) fail in BOTH modes.
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


def _self_test() -> int:
    """Meta-test: prove this gate FAILS when its evidence disappears.

    Builds a hermetic fixture tree in a temp dir (minimal registry, topology
    manifest, Dockerfile, compose files, wiring crate, claim surfaces), copies
    THIS script into it so ROOT resolves inside the sandbox, and runs the
    gate against mutated copies of the fixture registry. The real registry
    and tree are never touched.
    """
    import subprocess
    import tempfile

    runner = Path(__file__).resolve()
    ok = True

    def fixture_registry() -> dict:
        return {
            "$comment": "hermetic self-test fixture for check_capability_claims.py",
            "lifecycle_ladder": [
                "implemented",
                "integration-tested",
                "runtime-wired",
                "deployed",
                "monitored",
                "advertised",
            ],
            "scan": {
                "surfaces": [
                    "apps/marketing-zola/content/security/index.md",
                    "templates/compliance/trust-center.md",
                ],
                "marker": "[roadmap]",
                "marker_close": "[/roadmap]",
            },
            "in_flight_wiring": {"items": []},
            "capabilities": [
                {
                    "capability": "fixture-cap",
                    "crate": "crates/fixture",
                    "stage": "advertised",
                    "evidence": {
                        "docker_target": "mta",
                        "compose_service": "mta",
                        "env_gate": {
                            "name": "FIXTURE_GATE_ENABLED",
                            "crate": "crates/fixture",
                        },
                        "call_path": "crates/fixture/src/lib.rs mounts the widget "
                        "in the live request path",
                        "metrics": None,
                        "explanation": "Stage advertised: the fixture widget is "
                        "wired, deployed and truthfully claimed.",
                    },
                    "scan_aliases": ["fixture widget"],
                }
            ],
        }

    def build_sandbox(root: Path) -> Path:
        (root / "tools").mkdir(parents=True)
        (root / "tools" / "check_capability_claims.py").write_text(runner.read_text())
        for rel in (
            "docs/development",
            "services/mail-server/crates/fixture/src",
            "apps/marketing-zola/content/security",
            "templates/compliance",
        ):
            (root / rel).mkdir(parents=True, exist_ok=True)
        (root / "docs/development/topology-manifest.json").write_text(
            json.dumps({"services": [{"name": "mta", "docker_target": "mta"}]})
        )
        (root / "services/mail-server/Dockerfile").write_text(
            "FROM scratch AS runtime-base\nFROM runtime-base AS mta\n"
        )
        (root / "services/mail-server/crates/fixture/src/lib.rs").write_text(
            'pub const WIRING_GATE: &str = "FIXTURE_GATE_ENABLED";\n'
        )
        (root / "docker-compose.yml").write_text("services:\n  mta:\n    image: fixture\n")
        (root / "docker-compose.prod.yml").write_text("services:\n  mta:\n    image: fixture\n")
        (root / "apps/marketing-zola/content/security/index.md").write_text(
            "# Security\n\n[roadmap] future plans only [/roadmap]\n"
            "The fixture widget ships in the running product.\n"
        )
        (root / "templates/compliance/trust-center.md").write_text("# Trust Center\n")
        return root / "docs/development/capability-registry.json"

    # (label, mutation or None, expected exit code, expected needle in output)
    cases = [
        ("unmutated fixture passes", None, 0, None),
        (
            "nonexistent docker target fails the gate",
            lambda reg: reg["capabilities"][0]["evidence"].__setitem__(
                "docker_target", "ghost-target"
            ),
            1,
            "docker-target:fixture-cap:ghost-target",
        ),
        (
            "advertised demoted to implemented while still claimed fails",
            lambda reg: reg["capabilities"][0].__setitem__("stage", "implemented"),
            1,
            "claim-vs-stage:fixture-cap",
        ),
        (
            "retired-state language in entry text fails",
            lambda reg: reg["capabilities"][0]["evidence"].__setitem__(
                "explanation",
                reg["capabilities"][0]["evidence"]["explanation"]
                + " The remaining work has not yet landed.",
            ),
            1,
            "registry-lifecycle-language:fixture-cap",
        ),
        (
            "implemented entry carrying not-landed text fails",
            lambda reg: (
                reg["capabilities"][0].__setitem__("stage", "implemented"),
                reg["capabilities"][0]["evidence"].__setitem__(
                    "explanation",
                    "Stage implemented: the code exists in the crate; the wiring "
                    "has not landed.",
                ),
            ),
            1,
            "registry-stage-contradiction:fixture-cap",
        ),
        (
            "in-flight item whose env gate already landed fails",
            lambda reg: reg["in_flight_wiring"]["items"].append(
                {
                    "capability": "fixture-cap",
                    "wiring_target": "crates/fixture",
                    "env_gate": "FIXTURE_GATE_ENABLED",
                    "status": "self-test fixture contract",
                }
            ),
            1,
            "in-flight-unlanded:fixture-cap",
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="capability-gate-selftest-") as tmp:
        registry_path = build_sandbox(Path(tmp))
        env = dict(os.environ, CAPABILITY_GATE_STRICT="0")
        for label, mutate, expected, needle in cases:
            reg = fixture_registry()
            if mutate is not None:
                mutate(reg)
            registry_path.write_text(json.dumps(reg, indent=2))
            proc = subprocess.run(
                [sys.executable, str(registry_path.parent.parent.parent / "tools" / "check_capability_claims.py")],
                capture_output=True,
                text=True,
                env=env,
            )
            output = proc.stdout + proc.stderr
            passed = proc.returncode == expected and (needle is None or needle in output)
            if passed:
                print(f"SELF-TEST PASS {label}")
            else:
                ok = False
                print(
                    f"SELF-TEST FAIL {label}: exit={proc.returncode} "
                    f"(expected {expected}), needle={needle!r}"
                )
                print("\n".join(output.strip().splitlines()[-10:]))
    print(f"capability-gate self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if "--self-test" in sys.argv[1:]:
    sys.exit(_self_test())

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
    compose_service = ev.get("compose_service")

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

# ── 3b. Registry self-consistency: exactly ONE lifecycle state per entry ────
#
# The registry is the truth surface; history belongs to git. Retired-state
# language from a past audit wave must never survive in an entry's own text:
# the entry's `stage` is its single lifecycle statement, and wording that
# contradicts that stage is a claim-surface lie in the source of truth itself.
RETIRED_STATE_RE = re.compile(
    r"not\s+wired|not\s+(?:yet\s+)?landed|unlanded|wiring\s+in\s+flight|no\s+caller",
    re.IGNORECASE,
)
# Wording that contradicts a stage >= runtime-wired entry (the wiring EXISTS).
WIRED_CONTRADICTION_RE = re.compile(
    r"not\s+wired|unwired|not\s+(?:yet\s+)?landed|unlanded|wiring\s+in\s+flight"
    r"|no\s+caller|do\s+not\s+represent\s+it\s+as\s+an\s+active\s+control",
    re.IGNORECASE,
)
# `implemented` asserts the code IS in the tree — "not landed" contradicts it.
LANDED_CONTRADICTION_RE = re.compile(r"not\s+(?:yet\s+)?landed|unlanded", re.IGNORECASE)

for entry in CAPABILITIES:
    cap = entry.get("capability", "<unnamed>")
    stage = entry.get("stage")
    if stage not in STAGE_INDEX:
        continue  # already reported by the sanity check in section 1
    blob = json.dumps(entry, ensure_ascii=False)
    retired = RETIRED_STATE_RE.search(blob)
    if retired is None:
        check(f"registry-lifecycle-language:{cap}", True)
    else:
        check(
            f"registry-lifecycle-language:{cap}",
            False,
            f"retired-state language {retired.group(0)!r} — the entry's single lifecycle "
            f"statement is its stage (`{stage}`); rewrite the text to match it "
            "(history belongs to git, not the registry)",
        )
    if STAGE_INDEX[stage] >= RUNTIME_WIRED:
        contradiction = WIRED_CONTRADICTION_RE.search(blob)
        if contradiction is None:
            check(f"registry-stage-contradiction:{cap}", True)
        else:
            check(
                f"registry-stage-contradiction:{cap}",
                False,
                f"stage `{stage}` but the entry text says {contradiction.group(0)!r} — "
                "the wiring exists in the tree; rewrite the wording to the lifecycle "
                "statement matching the stage",
            )
    else:
        contradiction = LANDED_CONTRADICTION_RE.search(blob)
        if contradiction is None:
            check(f"registry-stage-contradiction:{cap}", True)
        else:
            check(
                f"registry-stage-contradiction:{cap}",
                False,
                f"stage `{stage}` asserts the code IS in the tree, but the entry text "
                f"says {contradiction.group(0)!r} — drop the contradiction or move the "
                "stage to the truth",
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

# ── In-flight wiring contract ───────────────────────────────────────────────
in_flight = (REGISTRY.get("in_flight_wiring") or {}).get("items") or []
known_capabilities = {e.get("capability") for e in CAPABILITIES}
for item in in_flight:
    cap = item.get("capability", "<unnamed>")
    gate_name = item.get("env_gate")
    check(
        f"in-flight-known-capability:{cap}",
        cap in known_capabilities,
        "in_flight_wiring item names a capability that has no registry entry",
    )
    landed = bool(rust_sources_mention(gate_name)) if gate_name else False
    if landed:
        check(
            f"in-flight-unlanded:{cap}",
            False,
            f"env gate {gate_name} is already greppable in the tree — the item has "
            "LANDED: remove it from in_flight_wiring in the same change that keeps "
            "the capability entry's raised stage (one lifecycle state per capability)",
        )
    else:
        soft(
            f"in-flight-unlanded:{cap}",
            False,
            f"wiring contract for {gate_name} has not arrived in the tree yet"
            if gate_name
            else "in-flight item declares no env gate to verify against",
        )

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
