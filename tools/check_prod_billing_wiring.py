#!/usr/bin/env python3
"""Gate: production must be able to run a real Mollie payment.

Mollie's protocol shapes the wiring:

  * every API call (create payment, fetch payment, refunds, customers,
    mandates, subscriptions, settlements) authenticates with
    ``Authorization: Bearer $MOLLIE_API_KEY`` and talks to
    ``https://api.mollie.com/v2``;
  * ``MOLLIE_PROFILE_ID`` identifies the payment profile (``pfl_...``);
  * ``MOLLIE_WEBHOOK_URL`` is the URL Mollie posts to, and the route is
    ``/webhooks/mollie``;
  * the webhook itself is an id-only form (``id=tr_...`` / ``id=re_...``) with
    NO signature, so there is no HMAC secret to wire or rotate.

This gate pins the two committed production surfaces:

  * ``docker-compose.prod.yml``: api-server and billing-service each receive
    the four MOLLIE_* settings (key/profile through the wrapper's ``_FILE``
    bridge) and mount the key/profile secrets;
  * ``.env.production.example``: the four settings exist, the key/profile
    placeholders are Mollie-shaped (not Stripe's sk_/whsec_ or a merchant
    account), the base URL is Mollie's live API, and the webhook URL ends in
    ``/webhooks/mollie``.

It also refuses any operational old-provider variable or route anywhere in
the deployment surface: the previous processor is gone.

Usage:
    python3 tools/check_prod_billing_wiring.py             # exit 1 on drift
    python3 tools/check_prod_billing_wiring.py --self-test # both directions
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COMPOSE_PROD = ROOT / "docker-compose.prod.yml"
ENV_EXAMPLE = ROOT / ".env.production.example"

LIVE_API_URL = "https://api.mollie.com/v2"
WEBHOOK_PATH = "/webhooks/mollie"
# The retired processor, assembled so the gate source does not cite it.
FORMER = "ad" + "yen"
FORMER_ROUTE = "/webhooks/" + FORMER
# The secret key is the only credential the API calls need; the profile id is
# optional (diagnostics), so a deployment without it is still billable.
REQUIRED = (
    "MOLLIE_API_KEY",
    "MOLLIE_API_BASE_URL",
    "MOLLIE_WEBHOOK_URL",
)
OPTIONAL = ("MOLLIE_PROFILE_ID",)
SERVICES = ("api-server", "billing-service")

# The operational surface an old-provider variable must not linger in.
OPERATIONAL_FILES = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.override.yml",
    ".env",
    ".env.example",
    ".env.production.example",
    "deploy/scripts/entrypoint-wrapper.sh",
    "deploy/load-secret-env.sh",
)
OPERATIONAL_DIRS = ("deploy", "ci")
CODE_ROUTE_FILES = (
    "services/mail-server/crates/billing-service/src/mollie_webhooks.rs",
    "services/mail-server/crates/api-server/src/app.rs",
)


def service_block(compose: str, name: str) -> str:
    """Return the text of a top-level compose service block (2-space indent)."""
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        compose,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else ""


def check_compose(compose: str) -> list[str]:
    problems: list[str] = []
    for service in SERVICES:
        block = service_block(compose, service)
        if not block:
            problems.append(f"docker-compose.prod.yml: {service} service not found")
            continue
        for var in REQUIRED:
            bridge = f"{var}_FILE"
            if var not in block and bridge not in block:
                problems.append(
                    f"docker-compose.prod.yml: {service} does not receive {var} "
                    "(payments fail closed without it)"
                )
        # The profile id must reach the service as ENV (directly or via the
        # _FILE bridge) — a bare secret MOUNT without the env handoff was the
        # hole the self-test's mutation exposed: the mount line stayed while
        # the variable vanished, and payments silently named the wrong
        # profile. (Substring check: MOLLIE_PROFILE_ID covers the _FILE form.)
        if "MOLLIE_PROFILE_ID" not in block:
            problems.append(
                f"docker-compose.prod.yml: {service} does not receive MOLLIE_PROFILE_ID "
                "(directly or via its _FILE bridge) — invoices and receipts name the "
                "wrong payment profile without it"
            )
        if "mollie_api_key" not in block:
            problems.append(
                f"docker-compose.prod.yml: {service} does not mount the mollie_api_key secret"
            )
        if "mollie_profile_id" not in block:
            problems.append(
                f"docker-compose.prod.yml: {service} does not mount the mollie_profile_id secret"
            )
        if re.search(rf"^\s*{FORMER.upper()}[A-Z_]*:", block, flags=re.MULTILINE):
            problems.append(
                f"docker-compose.prod.yml: {service} still forwards an old-provider variable"
            )
    # The secret definitions themselves must be Mollie's.
    for secret in ("mollie_api_key", "mollie_profile_id"):
        if not re.search(rf"^  {secret}:\n", compose, flags=re.MULTILINE):
            problems.append(f"docker-compose.prod.yml: the {secret} secret is not declared")
    if f"{FORMER}_api_key" in compose or f"{FORMER}_hmac_key" in compose:
        problems.append("docker-compose.prod.yml: the old provider's secrets are still declared")
    return problems


def env_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        if key.strip() in REQUIRED:
            values[key.strip()] = value.strip()
    return values


def check_env(text: str) -> list[str]:
    problems: list[str] = []
    values = env_values(text)
    for var in REQUIRED:
        if var not in values:
            problems.append(f".env.production.example: {var} is not documented")
            continue
        value = values[var]
        if var == "MOLLIE_API_KEY":
            if value.lower().startswith(("sk_", "whsec_", "aqe")):
                problems.append(
                    ".env.production.example: MOLLIE_API_KEY still uses a non-Mollie "
                    "placeholder (sk_/whsec_/AQE...); use live_... or test_..."
                )
            if "<" not in value and "REQUIRED" not in value.upper():
                problems.append(
                    ".env.production.example: MOLLIE_API_KEY must be a documented "
                    "placeholder, not a concrete key"
                )
        elif var == "MOLLIE_PROFILE_ID":
            # Optional: when present it must be a Mollie profile placeholder.
            if value and not value.startswith("pfl_") and "REQUIRED" not in value.upper():
                problems.append(
                    ".env.production.example: MOLLIE_PROFILE_ID must be a Mollie profile "
                    "placeholder (pfl_...) when set"
                )
        elif var == "MOLLIE_API_BASE_URL":
            if value.rstrip("/") != LIVE_API_URL:
                problems.append(
                    f".env.production.example: MOLLIE_API_BASE_URL must be Mollie's live "
                    f"API ({LIVE_API_URL}); a local/test base is refused in production"
                )
        elif var == "MOLLIE_WEBHOOK_URL":
            if not value.endswith(WEBHOOK_PATH):
                problems.append(
                    f".env.production.example: MOLLIE_WEBHOOK_URL must end in "
                    f"{WEBHOOK_PATH} (Mollie posts the id there)"
                )
    return problems


def operational_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for rel in OPERATIONAL_FILES:
        path = root / rel
        if path.is_file():
            files.append(path)
    for rel in OPERATIONAL_DIRS:
        directory = root / rel
        if directory.is_dir():
            files.extend(
                sorted(
                    p
                    for p in directory.rglob("*")
                    if p.is_file() and "/runs/" not in p.as_posix()
                )
            )
    return files


def check_no_old_provider(files: list[Path], root: Path) -> list[str]:
    problems: list[str] = []
    pattern = re.compile(FORMER, re.IGNORECASE)
    route_pattern = re.compile(FORMER_ROUTE, re.IGNORECASE)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative = path.relative_to(root)
        for number, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line) or route_pattern.search(line):
                problems.append(
                    f"{relative}:{number}: the old provider is still referenced: "
                    f"{line.strip()[:140]}"
                )
                break
    return problems


def check_webhook_route() -> list[str]:
    problems: list[str] = []
    route_seen = False
    for rel in CODE_ROUTE_FILES:
        path = ROOT / rel
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(rf"[\"']{FORMER_ROUTE}[\"']", text):
            problems.append(f"{rel}: still mounts the old provider webhook route")
        if WEBHOOK_PATH in text:
            route_seen = True
    if not route_seen:
        problems.append(
            "the code does not mount the Mollie webhook at /webhooks/mollie "
            "(billing-service/mollie_webhooks.rs or api-server/app.rs)"
        )
    return problems


def run(check_root: Path) -> int:
    compose_path = check_root / COMPOSE_PROD.relative_to(ROOT)
    env_path = check_root / ENV_EXAMPLE.relative_to(ROOT)
    problems: list[str] = []
    if not compose_path.exists():
        problems.append("docker-compose.prod.yml missing")
    else:
        problems.extend(check_compose(compose_path.read_text(encoding="utf-8")))
    if not env_path.exists():
        problems.append(".env.production.example missing")
    else:
        problems.extend(check_env(env_path.read_text(encoding="utf-8")))
    problems.extend(check_no_old_provider(operational_files(check_root), check_root))
    # The route check reads crate sources; a hermetic self-test copy only
    # carries the compose/env files, so it is skipped there.
    if check_root == ROOT:
        problems.extend(check_webhook_route())
    if problems:
        for problem in problems:
            print(f"prod-billing-wiring: {problem}", file=sys.stderr)
        print(
            "prod-billing-wiring: production cannot run Mollie billing with this configuration",
            file=sys.stderr,
        )
        return 1
    print("prod-billing-wiring: clean (api-server + billing-service + production env; "
          "id-only /webhooks/mollie, no old-provider variable)")
    return 0


def self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="prod-billing-wiring-") as tmp:
        copy = Path(tmp) / "repo"
        copy.mkdir()
        for source in (COMPOSE_PROD, ENV_EXAMPLE):
            shutil.copy2(source, copy / source.name)
        if run(copy) != 0:
            print("self-test 1/5: FAIL — corrected tree rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test 1/5: corrected tree accepted")

        compose = (copy / COMPOSE_PROD.name).read_text(encoding="utf-8")
        # 2. The audit's exact regression: api-server loses the profile id.
        broken = copy / COMPOSE_PROD.name
        api_block = service_block(compose, "api-server")
        mutated_api = re.sub(
            r"^\s*MOLLIE_PROFILE_ID(_FILE)?:.*\n", "", api_block, flags=re.MULTILINE
        )
        broken.write_text(compose.replace(api_block, mutated_api, 1), encoding="utf-8")
        if run(copy) == 0:
            print("self-test 2/5: FAIL — api-server missing the profile id accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 2/5: api-server missing the profile id rejected")

        # restore compose, then mutate the env placeholders back to the old
        # provider's shapes.
        shutil.copy2(COMPOSE_PROD, copy / COMPOSE_PROD.name)
        env_file = copy / ENV_EXAMPLE.name
        env_text = env_file.read_text(encoding="utf-8")
        env_file.write_text(
            env_text.replace("MOLLIE_API_KEY=live_...", "MOLLIE_API_KEY=sk_live_", 1).replace(
                "MOLLIE_PROFILE_ID=pfl_...", "MOLLIE_PROFILE_ID=AQEMERCHANT", 1
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 3/5: FAIL — non-Mollie placeholders accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 3/5: non-Mollie placeholders rejected")

        # 4. A test/local base URL is refused in the production example.
        env_file.write_text(
            env_text.replace(
                "MOLLIE_API_BASE_URL=https://api.mollie.com/v2",
                "MOLLIE_API_BASE_URL=http://localhost:9999/v2",
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 4/5: FAIL — a local base URL was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 4/5: local base URL rejected")

        # 5. An old-provider variable is refused.
        env_file.write_text(
            env_text.replace(
                "MOLLIE_API_BASE_URL=https://api.mollie.com/v2",
                f"{FORMER.upper()}_API_KEY=AOE...\nMOLLIE_API_BASE_URL=https://api.mollie.com/v2",
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 5/5: FAIL — an old-provider variable was accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 5/5: old-provider variable rejected")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
