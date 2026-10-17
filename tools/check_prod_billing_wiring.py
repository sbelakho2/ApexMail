#!/usr/bin/env python3
"""Gate: production must be able to run an Adyen checkout (audit 15 Oct, H3).

The 2026-10-15 audit found the checkout client needs ADYEN_API_KEY,
ADYEN_MERCHANT_ACCOUNT and a live ADYEN_API_BASE_URL, but
docker-compose.prod.yml passed none of them to api-server (only billing-service
got the key + HMAC secret), and .env.production.example documented neither the
merchant account nor the base URL — and still showed Stripe-shaped placeholder
values (sk_live_, whsec_). Paid checkout could therefore never work in
production.

This gate pins the wiring in the two committed production surfaces:

  * docker-compose.prod.yml: the api-server service carries
    ADYEN_API_KEY_FILE, ADYEN_MERCHANT_ACCOUNT and ADYEN_API_BASE_URL, and
    mounts the adyen_api_key secret; billing-service keeps its key + HMAC.
  * .env.production.example: all four ADYEN_* settings exist, the API-key and
    HMAC placeholders are Adyen-shaped (not sk_/whsec_), the merchant account
    is a non-empty placeholder, and the base URL is Adyen's LIVE endpoint.

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

LIVE_CHECKOUT_URL = "https://checkout-live.adyen.com/v71"
API_SERVER_REQUIRED = ("ADYEN_API_KEY_FILE", "ADYEN_MERCHANT_ACCOUNT", "ADYEN_API_BASE_URL")
BILLING_REQUIRED = ("ADYEN_API_KEY_FILE", "ADYEN_HMAC_KEY_FILE", "ADYEN_MERCHANT_ACCOUNT", "ADYEN_API_BASE_URL")
ENV_REQUIRED = (
    "ADYEN_API_KEY",
    "ADYEN_HMAC_KEY",
    "ADYEN_MERCHANT_ACCOUNT",
    "ADYEN_API_BASE_URL",
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
    api = service_block(compose, "api-server")
    if not api:
        return ["docker-compose.prod.yml: api-server service not found"]
    for var in API_SERVER_REQUIRED:
        if var not in api:
            problems.append(
                f"docker-compose.prod.yml: api-server does not receive {var} "
                "(the checkout client fails closed without it)"
            )
    # The entrypoint wrapper maps *_FILE to the native env var; the secret
    # itself must be mounted on the service.
    if "adyen_api_key" not in api:
        problems.append(
            "docker-compose.prod.yml: api-server does not mount the adyen_api_key secret"
        )
    billing = service_block(compose, "billing-service")
    if not billing:
        problems.append("docker-compose.prod.yml: billing-service service not found")
    else:
        for var in BILLING_REQUIRED:
            if var not in billing:
                problems.append(f"docker-compose.prod.yml: billing-service is missing {var}")
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
        if key.strip() in ENV_REQUIRED:
            values[key.strip()] = value.strip()
    return values


def check_env(text: str) -> list[str]:
    problems: list[str] = []
    values = env_values(text)
    for var in ENV_REQUIRED:
        if var not in values:
            problems.append(f".env.production.example: {var} is not documented")
            continue
        value = values[var]
        if var == "ADYEN_API_KEY":
            if value.lower().startswith("sk_"):
                problems.append(
                    ".env.production.example: ADYEN_API_KEY still uses a Stripe-shaped "
                    "placeholder (sk_...); use an Adyen key placeholder (AQE...)"
                )
            if "<" not in value and "REQUIRED" not in value.upper():
                problems.append(
                    ".env.production.example: ADYEN_API_KEY must be a documented placeholder, "
                    "not a concrete key"
                )
        elif var == "ADYEN_HMAC_KEY":
            if value.lower().startswith("whsec_"):
                problems.append(
                    ".env.production.example: ADYEN_HMAC_KEY still uses a Stripe-shaped "
                    "placeholder (whsec_...); Adyen HMAC keys are hex"
                )
        elif var == "ADYEN_MERCHANT_ACCOUNT":
            if "<" not in value and "REQUIRED" not in value.upper():
                problems.append(
                    ".env.production.example: ADYEN_MERCHANT_ACCOUNT must be a documented "
                    "placeholder (the live merchant account name)"
                )
        elif var == "ADYEN_API_BASE_URL":
            if LIVE_CHECKOUT_URL not in value:
                problems.append(
                    f".env.production.example: ADYEN_API_BASE_URL must be the live endpoint "
                    f"({LIVE_CHECKOUT_URL}); the checkout client refuses the test endpoint in production"
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
    if problems:
        for problem in problems:
            print(f"prod-billing-wiring: {problem}", file=sys.stderr)
        print(
            "prod-billing-wiring: production cannot start a checkout with this configuration"
            " (audit 15 Oct, H3)",
            file=sys.stderr,
        )
        return 1
    print("prod-billing-wiring: clean (api-server + billing-service + production env)")
    return 0


def self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="prod-billing-wiring-") as tmp:
        copy = Path(tmp) / "repo"
        copy.mkdir()
        for source in (COMPOSE_PROD, ENV_EXAMPLE):
            shutil.copy2(source, copy / source.name)
        if run(copy) != 0:
            print("self-test 1/4: FAIL — corrected tree rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test 1/4: corrected tree accepted")

        compose = (copy / COMPOSE_PROD.name).read_text(encoding="utf-8")
        # 2. The audit's exact regression: api-server loses the merchant account.
        broken = copy / COMPOSE_PROD.name
        api_block = service_block(compose, "api-server")
        mutated_api = re.sub(
            r"^\s*ADYEN_MERCHANT_ACCOUNT:.*\n", "", api_block, flags=re.MULTILINE
        )
        broken.write_text(compose.replace(api_block, mutated_api, 1), encoding="utf-8")
        if run(copy) == 0:
            print("self-test 2/4: FAIL — api-server missing merchant account accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 2/4: api-server missing merchant account rejected")

        # restore compose, then mutate the env placeholder back to Stripe's.
        shutil.copy2(COMPOSE_PROD, copy / COMPOSE_PROD.name)
        env_file = copy / ENV_EXAMPLE.name
        env_text = env_file.read_text(encoding="utf-8")
        env_file.write_text(
            env_text.replace(
                "ADYEN_API_KEY=", "ADYEN_API_KEY=sk_live_", 1
            ).replace(
                "ADYEN_HMAC_KEY=", "ADYEN_HMAC_KEY=whsec_", 1
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 3/4: FAIL — Stripe-shaped placeholders accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 3/4: Stripe-shaped placeholders rejected")

        # 4. A test-endpoint base URL is refused in the production example.
        env_file.write_text(
            env_text.replace(
                "ADYEN_API_BASE_URL=https://checkout-live.adyen.com/v71",
                "ADYEN_API_BASE_URL=https://checkout-test.adyen.com/v71",
            ),
            encoding="utf-8",
        )
        if run(copy) == 0:
            print("self-test 4/4: FAIL — test-endpoint base URL accepted", file=sys.stderr)
            failures += 1
        else:
            print("self-test 4/4: test-endpoint base URL rejected")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
