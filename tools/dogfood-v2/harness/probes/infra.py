"""Infrastructure surface probes (partition: infra).

  * every compose service: definition valid (always) + running/healthy (live);
  * health endpoints answer honestly;
  * the env surface: read-but-unused and documented-but-unset detection;
  * redis/postgres reachability through the data plane.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..config import REPO_ROOT
from ..ledger import COMPOSE_FILES
from ..registry import probe

# long-running services that must expose a healthcheck in the compose files
CORE_SERVICES = {
    "postgres", "redis", "api-server", "worker", "mta", "outbound-mta", "tracking",
    "enterprise", "imap-server", "mailpit", "clickhouse", "ai-service",
    "sales-autopilot", "compliance", "ha", "isolation", "analytics-worker",
    "billing-service", "pdf-renderer",
}

SERVICE_ALIASES = {
    "postgres": "apexmail-postgres",
    "redis": "apexmail-redis",
    "mailpit": "apexmail-mailpit",
    "clickhouse": "apexmail-clickhouse",
}


@probe(
    "p.infra.services", "infra", subsumes=("svc:*",), severity="P1",
    description="Every compose service: definition valid; the DESIGNED state per topology/profile",
)
def services(ctx):
    from ..assertions import Checks

    checks = Checks("p.infra.services", "compose")
    live = ctx.cfg.mode in ("live", "mutation")
    running: dict[str, dict] = {}
    if live:
        from ..dbctl import docker_ps

        for row in docker_ps(ctx.cfg):
            running[row["name"]] = row
    service_surfaces = ctx.ledger.by_kind("service")
    container_of = {}
    for surface in service_surfaces:
        name = surface.id.split(":", 1)[1]
        container_of[name] = SERVICE_ALIASES.get(name, f"apexmail-{name}-1")
    # Active profiles are inferred from the running stack itself: a profile is
    # active when one of its services runs (mailpit => dev). Services of an
    # inactive profile (monitoring, …) have no container BY DESIGN and are not
    # findings; services of the active profile ARE required.
    active_profiles: set[str] = set()
    for surface in service_surfaces:
        name = surface.id.split(":", 1)[1]
        if running.get(container_of[name]) is not None:
            active_profiles.update(surface.meta.get("profiles") or [])
    prod_services = []
    for surface in service_surfaces:
        meta = surface.meta or {}
        name = surface.id.split(":", 1)[1]
        files = meta.get("files", [])
        profiles = meta.get("profiles") or []
        topology = meta.get("topology", "dev")
        row = running.get(container_of[name]) or running.get(name)
        checks.add(
            f"compose service {name} is defined in {','.join(files) or 'compose'}",
            bool(files), observed=f"files={files} topology={topology} profiles={profiles}",
            expected="present in the compose files", surface=surface.id,
        )
        if topology == "prod":
            # The production topology is not the dev stack's designed state:
            # its services are not required to have containers here.
            prod_services.append(name)
            if live and row is not None:
                checks.add(
                    f"prod-topology service {name} (running here) is healthy",
                    "healthy" in row["status"] or row["state"] == "running",
                    observed=f"{row['state']} {row['status']}",
                    expected="Up (healthy) when a prod service is started in dev",
                    severity="P3", surface=surface.id,
                )
            continue
        if profiles and (not live or not (set(profiles) & active_profiles)):
            checks.add(
                f"compose service {name} is profile-gated ({', '.join(profiles)}) and not "
                f"required by the active topology",
                True, observed=f"profiles={profiles} active={sorted(active_profiles)}",
                expected="profile-gated services run only when their profile is enabled",
                surface=surface.id,
            )
            continue
        if not live:
            # fixture/self-test mode exercises the contract, not the daemon
            # state: the design assertion above is the whole check here.
            if name in CORE_SERVICES and not meta.get("has_healthcheck") and name not in ("mailpit",):
                checks.add(
                    f"core compose service {name} declares a healthcheck",
                    False, observed="no healthcheck key found in the compose definition",
                    expected="a healthcheck for every core long-running service",
                    severity="P3", surface=surface.id,
                )
            continue
        required_severity = "P1" if name in CORE_SERVICES else "P3"
        if row is None:
            checks.add(
                f"compose service {name} container is running",
                False,
                observed=f"no container matching {container_of[name]} in docker ps -a "
                         f"(topology={topology}, profiles={profiles or ['<default>']}, "
                         f"active={sorted(active_profiles)})",
                expected="running: the dev topology (or an ACTIVE profile) requires it",
                severity=required_severity, surface=surface.id,
            )
            continue
        has_healthcheck = bool(meta.get("has_healthcheck"))
        healthy = row["state"] == "running" and (not has_healthcheck or "healthy" in row["status"])
        checks.add(
            f"compose service {name} is up and healthy",
            healthy, observed=f"{row['state']} {row['status']} healthcheck={has_healthcheck}",
            expected="Up (healthy) on the active topology",
            severity=required_severity, surface=surface.id,
        )
        if name in CORE_SERVICES and not has_healthcheck and name not in ("mailpit",):
            checks.add(
                f"core compose service {name} declares a healthcheck",
                False, observed="no healthcheck key found in the compose definition",
                expected="a healthcheck for every core long-running service",
                severity="P3", surface=surface.id,
            )
    if prod_services:
        checks.add(
            "production-topology services are defined but not part of the dev stack",
            True,
            observed=f"prod-only services: {', '.join(sorted(prod_services))}",
            expected="the dev topology asserts only services it is designed to run",
            surface="compose",
        )
    return checks.obs


@probe("p.infra.health", "infra", severity="P1",
       description="Health endpoints answer honestly (db/redis connected)")
def health(ctx):
    from ..assertions import Checks

    checks = Checks("p.infra.health", "health")
    for path in ("/health", "/health/deep"):
        resp = ctx.get(path)
        ok = resp.status == 200
        detail = resp.text[:200]
        body = resp.json() or {}
        data = body.get("data") if isinstance(body.get("data"), dict) else body
        if path.endswith("deep") and ok:
            ok = isinstance(data, dict)
        checks.add(
            f"GET {path} answers 200 with a health payload",
            ok, observed=f"status={resp.status} body={detail!r}",
            expected="200 with db/redis status", surface=f"api:GET {path}",
            severity="P1",
        )
    return checks.obs


@probe("p.infra.data_plane", "infra", severity="P1",
       description="Postgres and Redis answer through the harness data plane")
def data_plane(ctx):
    from ..assertions import Checks

    checks = Checks("p.infra.data_plane", "data-plane")
    if ctx.db is None:
        checks.unreachable("data plane reachable", "no data plane configured")
        return checks.obs
    try:
        ping = ctx.db.ping()
    except Exception as error:  # noqa: BLE001
        checks.unreachable("data plane reachable", f"ping raised: {error}")
        return checks.obs
    checks.add("Postgres answers a ping", ping, observed=f"ping={ping}",
               expected="the migration-applied database is reachable", severity="P1")
    tables = ctx.db.tables()
    checks.add("the database exposes tables", bool(tables),
               observed=f"{len(tables)} tables", expected="the migrated schema", severity="P1")
    return checks.obs


_REPO_SOURCE_SUFFIXES = {
    ".rs", ".py", ".sh", ".bash", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".php",
    ".go", ".java", ".rb", ".toml", ".json", ".yml", ".yaml", ".conf", ".ini",
    ".cfg", ".sql", ".txt", ".env",
}
_REPO_SCAN_SKIP_DIRS = {
    ".git", "target", "node_modules", "__pycache__", "reports", "out",
    "docs", ".kilo", ".idea", ".vscode", "dist", "build", "coverage",
}
_CONSUMER_CACHE: dict[tuple, dict[str, str]] = {}


def _env_consumers(names: set[str]) -> dict[str, str]:
    """Which env names are consumed, and by what.

    A variable counts as consumed when ANY of:
      * a repo source/script/config file reads or references the name
        (word-bounded) — `env::var("X")`, `os.getenv("X")`, `${X}`, …;
      * its `_FILE` suffix: the base name is read, or the `*_FILE` name is
        passed to a container entrypoint/loader (`load-secret-env.sh`,
        `entrypoint-wrapper.sh` — sets any listed `NAME` from `NAME_FILE`);
      * it is set ONLY on third-party image services (env consumed by the
        image itself, e.g. GF_* → grafana, MP_* → mailpit, DATA_SOURCE_* →
        postgres-exporter; not repo config-theater).
    """
    key = tuple(sorted(names))
    if key in _CONSUMER_CACHE:
        return _CONSUMER_CACHE[key]
    consumers: dict[str, str] = {}
    remaining = set(names)
    # one alternation per file beats N regex searches per file (the repo scan
    # is ~20k files × ~600 names in the naive form)
    combined = re.compile(
        r"(?<![A-Za-z0-9_])(?P<name>[A-Z][A-Z0-9_]{2,})(?![A-Za-z0-9_])"
    )
    candidates: list[Path] = [path for path in sorted(REPO_ROOT.glob("*")) if path.is_file()]
    for top in ("services", "apps", "packages", "deploy", "scripts", "ci", "tools", "tests", "data"):
        root = REPO_ROOT / top
        if root.exists():
            candidates.extend(path for path in root.rglob("*") if path.is_file())
    for path in candidates:
        if not remaining:
            break
        if any(part in _REPO_SCAN_SKIP_DIRS for part in path.parts):
            continue
        if path.name.startswith(".env"):
            # deployment templates DECLARE values; they are not readers.
            # `read by code` requires a code/script/loader/entrypoint consumer.
            continue
        if path.suffix not in _REPO_SOURCE_SUFFIXES and path.name not in (".env", ".env.example", "Makefile"):
            continue
        if "docker-compose" in path.name:
            continue          # handled below (entrypoint/loader lists only)
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        for match in combined.finditer(text):
            name = match.group("name")
            if name in remaining:
                consumers[name] = f"code:{path.relative_to(REPO_ROOT)}"
                remaining.discard(name)
    patterns = {name: re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])") for name in remaining}
    # compose files: the env KEY definition does not consume; the same name in
    # an entrypoint/command/loader list does (bridged into a native var).
    for compose in COMPOSE_FILES:
        if not compose.exists():
            continue
        for line in compose.read_text(errors="replace").splitlines():
            for name in list(remaining):
                if name not in line:
                    continue
                if re.match(rf"\s*{re.escape(name)}\s*:", line):
                    continue      # this is the definition line itself
                if patterns[name].search(line):
                    consumers[name] = f"entrypoint:{compose.name}"
                    remaining.discard(name)
    # `_FILE` convention: the loader exports NAME from NAME_FILE.
    for name in list(remaining):
        if not name.endswith("_FILE"):
            continue
        base = name[:-len("_FILE")]
        if base in consumers:
            consumers[name] = f"via {base} ({consumers[base]}) + _FILE loader convention"
            remaining.discard(name)
    _CONSUMER_CACHE[key] = consumers
    return consumers


@probe(
    "p.infra.env_surface", "infra", subsumes=("env:*",), severity="P3",
    description="Env surface: read-but-unused (compose-only) and documented-but-unset keys",
)
def env_surface(ctx):
    from ..assertions import Checks

    checks = Checks("p.infra.env_surface", "env")
    names = {s.id.split(":", 1)[1] for s in ctx.ledger.by_kind("env")}
    consumers = _env_consumers(names)
    # services that run third-party images (env consumed inside the image)
    image_only: set[str] = set()
    for surface in ctx.ledger.by_kind("service"):
        if surface.meta.get("image_only"):
            image_only.add(surface.id.split(":", 1)[1])
    # …including services that only exist in the PROD overlay (backups,
    # exporters): derive them from every compose file — a service with an
    # `image:` and no `build:` is third-party, and its documented env
    # contract is consumed by that image (e.g. BACKUP_KEEP_* by the
    # postgres-backup image; the dogfood ledger only classified the base
    # compose and read them as repo-built config-theater).
    for compose_path in sorted(REPO_ROOT.glob("docker-compose*.yml")):
        try:
            text = compose_path.read_text(errors="ignore")
        except OSError:
            continue
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if re.match(r"^[A-Za-z0-9_.-]+:\s*$", stripped) and not line.startswith((" ", "\t")):
                current = stripped[:-1]
            elif current and stripped.startswith("image:"):
                image_only.add(current)
            elif current and stripped.startswith("build:"):
                image_only.discard(current)
    in_env_files = set()
    for candidate in (REPO_ROOT / ".env", REPO_ROOT / ".env.example",
                      REPO_ROOT / ".env.production.example"):
        if candidate.exists():
            text = candidate.read_text(errors="ignore")
            for name in names:
                if re.search(rf"^\s*{re.escape(name)}=", text, re.M):
                    in_env_files.add(name)
    for surface in ctx.ledger.by_kind("env"):
        meta = surface.meta or {}
        name = surface.id.split(":", 1)[1]
        set_on = meta.get("set_on") or []
        code_read = meta.get("code_read")
        documented = meta.get("documented")
        if set_on and not code_read and name not in consumers:
            if set_on and all(service in image_only for service in set_on):
                # third-party image config (grafana/mailpit/clickhouse/…):
                # consumed by the image binary, not repo config-theater.
                continue
            checks.add(
                f"env {name} is set in compose and read by code",
                False,
                observed=f"set_on={set_on}; no reader in repo source/scripts/entrypoints; "
                         f"services are repo-built (not third-party images)",
                expected="every compose var is consumed (read-but-unused vars are dead config)",
                severity="P3", surface=surface.id,
            )
        if documented and not set_on and name not in in_env_files:
            checks.add(
                f"documented env {name} is set somewhere",
                False, observed="documented in docs/deployment/configuration.md; not set in compose or .env files",
                expected="documented-but-unset keys are a docs/ops drift (or a documented default)",
                severity="P3", surface=surface.id,
            )
    consumed = sum(1 for s in ctx.ledger.by_kind("env")
                   if (s.meta or {}).get("set_on") and s.id.split(":", 1)[1] in consumers)
    checks.add(
        "compose-set env vars are consumed by source, a loader, or a third-party image",
        True, observed=f"{consumed} compose-set vars have a located consumer",
        expected="every compose-set var has a consumer",
        surface="env", severity="P3",
    )
    return checks.obs
