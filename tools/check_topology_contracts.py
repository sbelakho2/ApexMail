#!/usr/bin/env python3
"""Topology / documentation-contract gate.

Executable architecture: the facts the docs and the deployment claim are
checked against the tree, so implementation can no longer outrun the
topology silently (the outbound-mta lesson: the daemon existed in source
for weeks with no runtime consuming it).

Checks (each prints PASS/FAIL; any FAIL exits 1):
  1. every canonical stateful daemon binary has a Dockerfile runtime target
     AND a compose service (dev + prod overlay);
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

# 1. Stateful daemons that own durable work → image target + services.
DAEMONS = {
    "mta": "mta-server",
    "worker": "worker",
    "api-server": "api-server",
    "imap-server": "imap-server",
    "billing-service": "billing-service",
    "sales-autopilot": "sales-autopilot",
    "outbound-mta": "outbound-mta",
}
for target, binary in DAEMONS.items():
    check(
        f"docker-target:{target}",
        re.search(rf"FROM runtime-base AS {target}\b", DOCKERFILE) is not None,
        f"no `FROM runtime-base AS {target}` stage",
    )
    check(
        f"compose-dev:{target}",
        re.search(rf"^\s+{re.escape(target)}:", COMPOSE_DEV, re.M) is not None,
        f"docker-compose.yml has no `{target}:` service",
    )
    check(
        f"compose-prod:{target}",
        re.search(rf"^\s+{re.escape(target)}:", COMPOSE_PROD, re.M) is not None,
        f"docker-compose.prod.yml has no `{target}:` service",
    )
    check(
        f"dockerfile-copies-binary:{binary}",
        f"/{binary}" in DOCKERFILE or f" {binary}" in DOCKERFILE,
        f"the Dockerfile never copies the {binary} binary",
    )

# 2. Alert jobs that exist as compose services.
ALERT_JOB_TO_SERVICE = {
    "apexmail-api": "api-server",
    "apexmail-worker": "worker",
}
for job in re.findall(r"up\{job=\"([a-z0-9-]+)\"\}", ALERTS):
    normalized = ALERT_JOB_TO_SERVICE.get(job, job.removeprefix("apexmail-"))
    check(
        f"alert-job-has-service:{job}",
        re.search(rf"^\s+{re.escape(normalized)}:", COMPOSE_DEV, re.M) is not None,
        f"alerting rule references job `{job}` but no compose service matches",
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

# 4. The sales owner gate is mounted on exactly the sales routers.
APP = (ROOT / "services/mail-server/crates/api-server/src/app.rs").read_text()
production = APP.split("#[cfg(test)]")[0]
check(
    "sales-owner-gate:exactly-two-mounts",
    production.count("require_sales_owner") == 2,
    f"expected 2 mounts (sales + autopilot), found {production.count('require_sales_owner')}",
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
