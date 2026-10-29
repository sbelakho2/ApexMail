#!/usr/bin/env python3
"""Standby env-forwarding contract gate (eighth-audit DR + control plane).

The audit finding: "the STANDBY_* mechanism exists more strongly in the
scripts than in the deployment topology" — the standby scripts consume a
set of environment knobs, and nothing proved the compose overlays actually
forward them. A knob documented in the script header but never forwarded in
the overlay renders as the script's silent default in production, which is
exactly the divergence this gate refuses.

What it checks, mechanically:

  1. CONSUMED — every `STANDBY_*` variable referenced by
     `pg-standby-promote.sh` / `pg-standby-bootstrap.sh` and every
     `HEARTBEAT_*` variable referenced by `pg-replication-heartbeat.sh`
     (grep of the sources; the same list an operator reads in the headers).
  2. FORWARDED — `docker compose -f docker-compose.yml -f <overlay> config`
     rendered for BOTH standby overlays (same-host + remote), the standby
     service's rendered environment must carry every consumed variable —
     or the variable must be on the explicit "intentionally default-only"
     ALLOWLIST (vars documented as optional with sane defaults). The
     wal-archive overlay's `postgres-heartbeat` runner must forward the
     heartbeat knobs the same way.
  3. TOPOLOGY — the same-host overlay attaches the standby to the primary's
     data network ONLY (no external stanza), while the remote overlay joins
     the external replication network and references NO local `postgres`
     service (no depends_on / volumes_from: a remote host has none).

Rendering uses the same synthetic dummy-env technique as the compose render
contract in ci/stages/validate.sh: every `${VAR:?}` guard of the files in
each stack is satisfied with a dummy value, everything else resolves
through its committed default.

Usage: check_standby_contract.py [--self-test]
Exit codes: 0 = clean, 1 = violations, 2 = usage/IO error.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BASE_COMPOSE = ROOT / "docker-compose.yml"
PROD_COMPOSE = ROOT / "docker-compose.prod.yml"
WAL_ARCHIVE_COMPOSE = ROOT / "deploy" / "docker-compose.wal-archive.yml"
SAME_HOST_COMPOSE = ROOT / "deploy" / "docker-compose.standby.yml"
REMOTE_COMPOSE = ROOT / "deploy" / "docker-compose.standby-remote.yml"

PROMOTE_SCRIPT = ROOT / "deploy/hardening/scripts/pg-standby-promote.sh"
BOOTSTRAP_SCRIPT = ROOT / "deploy/hardening/scripts/pg-standby-bootstrap.sh"
HEARTBEAT_SCRIPT = ROOT / "deploy/hardening/scripts/pg-replication-heartbeat.sh"

STANDBY_SERVICE = "postgres-standby"
HEARTBEAT_SERVICE = "postgres-heartbeat"
DATA_NETWORK = "apexmail_data_internal"
REPLICATION_NETWORK = "apexmail_replication"

STANDBY_VAR = re.compile(r"\bSTANDBY_[A-Z0-9_]+\b")
HEARTBEAT_VAR = re.compile(r"\bHEARTBEAT_[A-Z0-9_]+\b")
GUARD_VAR = re.compile(r"\$\{([A-Z0-9_]+):\?")

# "Intentionally default-only": variables the scripts consume but the
# overlays deliberately do NOT forward, each with the documented reason.
# Anything not listed here AND not forwarded is a violation.
ALLOWLIST: dict[str, dict[str, str]] = {
    "pg-standby-promote.sh": {
        "STANDBY_PSQL_HOST": (
            "unix-socket directory inside the standby container "
            "(/var/run/postgresql, the image's own tmpfs) — a container-internal "
            "path, not an operator knob"
        ),
    },
    "pg-standby-bootstrap.sh": {
        "STANDBY_BOOTSTRAP_POLL_SECS": (
            "credential-retry poll interval, documented optional with the "
            "sane default 5s; the timeout knob (STANDBY_BOOTSTRAP_TIMEOUT_SECS) "
            "IS forwarded"
        ),
    },
    "pg-replication-heartbeat.sh": {
        "HEARTBEAT_DB_USER": (
            "derived from the standard libpq POSTGRES_USER fallback chain "
            "inside the script — the overlay forwards POSTGRES_USER, not a "
            "second name for it"
        ),
        "HEARTBEAT_PRUNE_KEEP_HOURS": (
            "heartbeat-row retention, documented optional with the sane "
            "default 24h (hygiene, not a freshness knob — the freshness knob "
            "is STANDBY_MAX_HEARTBEAT_AGE_SECONDS on the promote side)"
        ),
        "HEARTBEAT_PRUNE_EVERY_TICKS": (
            "prune cadence in ticks, documented optional with the sane "
            "default 240 (~1/hour at the 15s interval)"
        ),
    },
}


def consumed_vars(script: Path, pattern: re.Pattern[str]) -> set[str]:
    """Every env-var name of the given family the script references."""
    return set(pattern.findall(script.read_text(errors="replace")))


def missing_forwardings(
    consumed_by_script: dict[str, set[str]],
    forwarded: set[str],
    allowlist: dict[str, str],
    overlay: str,
) -> list[str]:
    """The pure core: consumed-but-not-forwarded-and-not-allowlisted pairs.

    Returns one human-readable violation per missing variable so a failure
    names the exact pairs (variable, script, overlay).
    """
    problems: list[str] = []
    for script, variables in sorted(consumed_by_script.items()):
        for variable in sorted(variables):
            if variable in forwarded:
                continue
            if variable in allowlist:
                continue
            problems.append(
                f"{variable} (consumed by {script}) is not forwarded in "
                f"{overlay}'s {STANDBY_SERVICE} environment and is not allowlisted"
            )
    return problems


def remote_dependency_problems(service: dict) -> list[str]:
    """The remote overlay must not reference a local postgres service."""
    problems: list[str] = []
    depends_on = service.get("depends_on") or {}
    if "postgres" in depends_on:
        problems.append(
            f"{REMOTE_COMPOSE.name}: {STANDBY_SERVICE} depends_on a local "
            "'postgres' service — a remote host has none; the bootstrap's "
            "retry loop is the ordering mechanism"
        )
    if service.get("volumes_from"):
        problems.append(
            f"{REMOTE_COMPOSE.name}: {STANDBY_SERVICE} uses volumes_from — "
            "a remote host has no local service to inherit volumes from"
        )
    return problems


def service_networks(service: dict) -> list[str]:
    networks = service.get("networks") or {}
    if isinstance(networks, list):  # short syntax
        return list(networks)
    return list(networks.keys())


def dummy_env_for(files: list[Path]) -> dict[str, str]:
    """Synthetic env satisfying every ${VAR:?} guard of the given compose
    files (the ci/stages/validate.sh render-contract technique): _FILE
    guards point at an existing temp file, everything else gets a dummy
    string."""
    env: dict[str, str] = {}
    guard_files: list[Path] = []
    for file in files:
        if file.exists():
            guard_files.append(file)
    with tempfile.TemporaryDirectory() as tmp:
        secret = Path(tmp) / "secret"
        secret.touch()
        for file in guard_files:
            for variable in GUARD_VAR.findall(file.read_text(errors="replace")):
                if variable in env:
                    continue
                env[variable] = str(secret) if variable.endswith("_FILE") else "ci-dummy-value"
    return env


def render_services(files: list[Path], env: dict[str, str]) -> dict[str, dict]:
    """`docker compose config --format json` for the given stack → services."""
    argv = ["docker", "compose"]
    for file in files:
        argv += ["-f", str(file)]
    # `config` first: --format is a flag OF the config subcommand.
    argv += ["config", "--format", "json"]
    result = subprocess.run(
        argv, cwd=ROOT, capture_output=True, text=True,
        env={**os.environ, **env},
    )
    if result.returncode != 0:
        raise RuntimeError(
            "docker compose config failed for "
            f"{[f.name for f in files]}: {(result.stderr or result.stdout).strip()}"
        )
    config = json.loads(result.stdout)
    services = config.get("services")
    if not isinstance(services, dict):
        raise RuntimeError(f"rendered config carries no services: {[f.name for f in files]}")
    return services


def check() -> list[str]:
    problems: list[str] = []

    for path in (PROMOTE_SCRIPT, BOOTSTRAP_SCRIPT, HEARTBEAT_SCRIPT,
                 SAME_HOST_COMPOSE, REMOTE_COMPOSE, WAL_ARCHIVE_COMPOSE,
                 BASE_COMPOSE, PROD_COMPOSE):
        if not path.is_file():
            return [f"required input missing: {path.relative_to(ROOT)}"]

    consumed_standby = {
        "deploy/hardening/scripts/pg-standby-promote.sh": consumed_vars(PROMOTE_SCRIPT, STANDBY_VAR),
        "deploy/hardening/scripts/pg-standby-bootstrap.sh": consumed_vars(BOOTSTRAP_SCRIPT, STANDBY_VAR),
    }
    consumed_heartbeat = {
        "deploy/hardening/scripts/pg-replication-heartbeat.sh": consumed_vars(HEARTBEAT_SCRIPT, HEARTBEAT_VAR),
    }

    # ── Render the two standby stacks (dummy env, like the render contract).
    stacks = {
        SAME_HOST_COMPOSE: [BASE_COMPOSE, SAME_HOST_COMPOSE],
        REMOTE_COMPOSE: [BASE_COMPOSE, REMOTE_COMPOSE],
    }
    rendered: dict[Path, dict[str, dict]] = {}
    for overlay, files in stacks.items():
        env = dummy_env_for(files)
        rendered[overlay] = render_services(files, env)
        service = rendered[overlay].get(STANDBY_SERVICE)
        if not isinstance(service, dict):
            problems.append(f"{overlay.name}: no {STANDBY_SERVICE} service renders")
            continue
        environment = service.get("environment") or {}
        if not isinstance(environment, dict):
            environment = {}
        problems += missing_forwardings(
            consumed_standby, set(environment),
            ALLOWLIST.get("pg-standby-promote.sh", {}) | ALLOWLIST.get("pg-standby-bootstrap.sh", {}),
            str(overlay.relative_to(ROOT)),
        )

    # ── Topology: same-host attaches ONLY the primary's data network.
    same_host = rendered[SAME_HOST_COMPOSE].get(STANDBY_SERVICE, {})
    networks = service_networks(same_host)
    if DATA_NETWORK not in networks:
        problems.append(
            f"{SAME_HOST_COMPOSE.name}: {STANDBY_SERVICE} must join {DATA_NETWORK} "
            "(the primary's compose network)"
        )
    if REPLICATION_NETWORK in networks:
        problems.append(
            f"{SAME_HOST_COMPOSE.name}: {STANDBY_SERVICE} joins {REPLICATION_NETWORK} — "
            "the same-host overlay attaches ONLY the data network; the external "
            f"{REPLICATION_NETWORK} stanza belongs to the remote overlay"
        )

    # ── Topology: remote joins the external replication network and no
    # local postgres service.
    remote = rendered[REMOTE_COMPOSE].get(STANDBY_SERVICE, {})
    remote_networks = service_networks(remote)
    if REPLICATION_NETWORK not in remote_networks:
        problems.append(
            f"{REMOTE_COMPOSE.name}: {STANDBY_SERVICE} must join the external "
            f"{REPLICATION_NETWORK} (the restricted replication transport)"
        )
    problems += remote_dependency_problems(remote)

    # ── The heartbeat runner must forward the heartbeat knobs.
    wal_services = render_services(
        [BASE_COMPOSE, PROD_COMPOSE, WAL_ARCHIVE_COMPOSE],
        dummy_env_for([BASE_COMPOSE, PROD_COMPOSE, WAL_ARCHIVE_COMPOSE]),
    )
    heartbeat = wal_services.get(HEARTBEAT_SERVICE)
    if not isinstance(heartbeat, dict):
        problems.append(
            f"{WAL_ARCHIVE_COMPOSE.name}: no {HEARTBEAT_SERVICE} service renders "
            "(the replicated-heartbeat runner is missing)"
        )
    else:
        heartbeat_env = heartbeat.get("environment") or {}
        if not isinstance(heartbeat_env, dict):
            heartbeat_env = {}
        problems += missing_forwardings(
            consumed_heartbeat, set(heartbeat_env),
            ALLOWLIST.get("pg-replication-heartbeat.sh", {}),
            f"{WAL_ARCHIVE_COMPOSE.relative_to(ROOT)}'s {HEARTBEAT_SERVICE}",
        )

    return sorted(set(problems))


def self_test() -> int:
    failures = 0

    # 1. The forwarding core: a missing variable is caught, an allowlisted
    #    one passes — proved on a SYNTHETIC script fixture, no docker.
    fixture = Path(tempfile.mkdtemp(prefix="apexmail-standby-contract-test.")) / "fake-standby.sh"
    fixture.write_text(
        "#!/bin/sh\n"
        "STANDBY_REQUIRED_VAR=\"${STANDBY_REQUIRED_VAR:-x}\"\n"
        "STANDBY_DEFAULT_ONLY_VAR=\"${STANDBY_DEFAULT_ONLY_VAR:-y}\"\n"
    )
    consumed = {"fake-standby.sh": consumed_vars(fixture, STANDBY_VAR)}
    if consumed["fake-standby.sh"] != {"STANDBY_REQUIRED_VAR", "STANDBY_DEFAULT_ONLY_VAR"}:
        print(f"self-test FAIL: fixture scan got {consumed}", file=sys.stderr)
        failures += 1

    # Allowlisted default-only var passes; the required one is forwarded.
    clean = missing_forwardings(
        consumed, {"STANDBY_REQUIRED_VAR"},
        {"STANDBY_DEFAULT_ONLY_VAR": "documented optional default"},
        "fake-overlay.yml",
    )
    if clean:
        print(f"self-test FAIL: forwarded+allowlisted fixture rejected: {clean}", file=sys.stderr)
        failures += 1

    # The same fixture WITHOUT the allowlist entry catches the missing pair.
    caught = missing_forwardings(consumed, {"STANDBY_REQUIRED_VAR"}, {}, "fake-overlay.yml")
    if not any("STANDBY_DEFAULT_ONLY_VAR" in p and "not forwarded" in p for p in caught):
        print(f"self-test FAIL: a missing (non-allowlisted) var was not caught: {caught}", file=sys.stderr)
        failures += 1

    # A missing REQUIRED var is caught even when another var is forwarded.
    caught = missing_forwardings(consumed, set(), {"STANDBY_DEFAULT_ONLY_VAR": "ok"}, "fake-overlay.yml")
    if not any("STANDBY_REQUIRED_VAR" in p for p in caught):
        print(f"self-test FAIL: a missing forwarded var was not caught: {caught}", file=sys.stderr)
        failures += 1

    # 2. The remote-topology predicate: a depends_on postgres is refused.
    if not remote_dependency_problems({"depends_on": {"postgres": {"condition": "service_healthy"}}}):
        print("self-test FAIL: a remote depends_on postgres was not caught", file=sys.stderr)
        failures += 1
    if remote_dependency_problems({"depends_on": {}}):
        print("self-test FAIL: a clean remote service was flagged", file=sys.stderr)
        failures += 1

    # 3. The real scripts must scan to the documented families at all.
    if not consumed_vars(PROMOTE_SCRIPT, STANDBY_VAR):
        print("self-test FAIL: no STANDBY_* consumed by the promote script", file=sys.stderr)
        failures += 1
    if not consumed_vars(HEARTBEAT_SCRIPT, HEARTBEAT_VAR):
        print("self-test FAIL: no HEARTBEAT_* consumed by the heartbeat script", file=sys.stderr)
        failures += 1

    import shutil
    shutil.rmtree(fixture.parent, ignore_errors=True)

    if failures:
        print(f"self-test FAIL: {failures} direction(s) escaped", file=sys.stderr)
        return 1
    print("check_standby_contract self-test: ok (synthetic fixture: missing var caught, "
          "allowlisted var passes, forwarded var passes; remote depends_on postgres caught; "
          "real scripts scan to their variable families)")
    return 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if [a for a in argv if not a.startswith("--")]:
        print("usage: check_standby_contract.py [--self-test]", file=sys.stderr)
        return 2
    try:
        problems = check()
    except RuntimeError as exc:
        print(f"standby contract gate could not run: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("standby contract gate FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(
        "standby contract gate: clean (same-host + remote overlays forward every "
        "consumed STANDBY_* var or name it default-only; heartbeat runner forwards "
        "the heartbeat knobs; remote overlay carries no local postgres dependency)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
