#!/usr/bin/env python3
"""Topology / documentation-contract gate.

Executable architecture: the facts the docs and the deployment claim are
checked against the tree, so implementation can no longer outrun the
topology silently (the outbound-mta lesson: the daemon existed in source
for weeks with no runtime consuming it).

Checks (each prints PASS/FAIL; any FAIL exits 1):
  1. every manifest service proves its declared Dockerfile target, compose
     services and alerts — and the manifest provably covers EVERY Dockerfile
     runtime target and EVERY non-infra prod compose service;
  2. the alerting rules reference the deployed jobs that exist;
  3. the architecture docs no longer claim the outbound relay is absent;
  4. the sales owner gate is mounted on exactly the sales routers;
  5. stale TODO markers that name retired gaps are gone.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    status = "PASS" if ok else "FAIL"
    suffix = f" — {detail}" if detail and not ok else ""
    print(f"{status} {name}{suffix}")
    if not ok:
        failures.append(name)


DOCKERFILE = (ROOT / "services/mail-server/Dockerfile").read_text()
COMPOSE_DEV = (ROOT / "docker-compose.yml").read_text()
COMPOSE_PROD = (ROOT / "docker-compose.prod.yml").read_text()
ALERTS = (ROOT / "deploy/alerting-rules.yml").read_text()

# 1. Manifest-driven: every declared service proves its deploy surface.
#    The inventory lives in docs/development/topology-manifest.json; this
#    gate derives from it AND proves exhaustiveness in both directions (no
#    silent new Dockerfile runtime target; no silent new compose service —
#    the "important seven" lesson).
import json

MANIFEST = json.loads(
    (ROOT / "docs/development/topology-manifest.json").read_text()
)
SERVICES = MANIFEST["services"]

for svc in SERVICES:
    name = svc["name"]
    target = svc.get("docker_target")
    if target:
        check(
            f"docker-target:{target}",
            re.search(rf"FROM runtime-base AS {re.escape(target)}\b", DOCKERFILE) is not None,
            f"manifest declares docker target `{target}` but the Dockerfile has no such stage",
        )
    if svc.get("compose_dev"):
        check(
            f"compose-dev:{name}",
            re.search(rf"^\s+{re.escape(svc['compose_dev'])}:", COMPOSE_DEV, re.M) is not None,
            f"manifest declares a dev compose service but docker-compose.yml has none",
        )
    if svc.get("compose_prod"):
        check(
            f"compose-prod:{name}",
            re.search(rf"^\s+{re.escape(svc['compose_prod'])}:", COMPOSE_PROD, re.M) is not None,
            f"manifest declares a prod compose service but docker-compose.prod.yml has none",
        )
    for alert in svc.get("alerts", []):
        check(
            f"alert-exists:{alert}",
            f"alert: {alert}" in ALERTS,
            f"manifest declares alert `{alert}` but deploy/alerting-rules.yml has none",
        )

# 1b. Exhaustiveness, both directions.
docker_targets = set(re.findall(r"FROM runtime-base AS ([a-z0-9-]+)", DOCKERFILE))
manifest_targets = {s["docker_target"] for s in SERVICES if s.get("docker_target")}
for missing in sorted(docker_targets - manifest_targets):
    check(
        f"manifest-covers-docker-target:{missing}",
        False,
        "a Dockerfile runtime target is missing from topology-manifest.json "
        "— declare it (class build-only is allowed)",
    )

infra = set(MANIFEST.get("infrastructure_compose_services", []))
prod_services = {
    m.group(1)
    for m in re.finditer(r"^  ([a-z0-9-]+):", COMPOSE_PROD, re.M)
    if m.group(1) not in {"driver", "options"}
}
manifest_names = {s["name"] for s in SERVICES} | infra
for orphan in sorted(prod_services - manifest_names):
    check(
        f"manifest-covers-compose-service:{orphan}",
        False,
        "a prod compose service is missing from topology-manifest.json — "
        "declare it or add it to infrastructure_compose_services",
    )

# 2. Alert `up{job=...}` selectors resolve to manifest or infra services.
ALERT_JOB_TO_SERVICE = {
    "apexmail-api": "api-server",
    "apexmail-worker": "worker",
}
known_services = manifest_names | docker_targets
for job in re.findall(r'up\{job="([a-z0-9-]+)"\}', ALERTS):
    normalized = ALERT_JOB_TO_SERVICE.get(job, job.removeprefix("apexmail-"))
    check(
        f"alert-job-has-service:{job}",
        normalized in known_services
        and re.search(rf"^\s+{re.escape(normalized)}:", COMPOSE_DEV, re.M) is not None,
        f"alerting rule references job `{job}` but no manifest entry or compose service matches",
    )
# 3. Docs must not claim the outbound relay is absent.
DOC = (ROOT / "docs/architecture/delivery-transport.md").read_text()
check(
    "docs:outbound-relay-not-absent",
    "not implemented in this repository" not in DOC
    and "no recipient-facing outbound connector exists" not in DOC,
    "delivery-transport.md still claims the outbound relay is absent",
)
check(
    "docs:outbound-mta-documented",
    "outbound-mta" in DOC,
    "delivery-transport.md does not mention the outbound-mta crate/daemon",
)

# 4. The owner gate is mounted on exactly the owner-run routers: the sales
# brain (sales + autopilot) and — since the SalesCloser plan §5.6 — the demo
# presenter API, which executes real machinery and mints viewer links. A new
# mount is a deliberate security-surface decision, so the count is pinned.
APP = (ROOT / "services/mail-server/crates/api-server/src/app.rs").read_text()
production = APP.split("#[cfg(test)]")[0]
check(
    "owner-gate:exactly-three-mounts",
    production.count("require_sales_owner") == 3,
    "expected 3 mounts (sales + autopilot + demos), "
    f"found {production.count('require_sales_owner')}",
)

# 5. Retired gap markers are gone from live source.
TRANSPORT = (
    ROOT / "services/mail-server/crates/worker-processors/src/email/transport.rs"
).read_text()
check(
    "no-stale-todo:mta-owner",
    "TODO(mta-owner)" not in TRANSPORT,
    "transport.rs still carries the retired TODO(mta-owner) gap marker",
)

print()
if failures:
    print(f"TOPOLOGY CONTRACT FAILURES: {len(failures)}")
    for name in failures:
        print(f"  - {name}")
    sys.exit(1)
print("topology contracts: all green")
