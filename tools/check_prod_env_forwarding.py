#!/usr/bin/env python3
"""Gate: production env keys read by the binaries must actually be forwarded.

The F1 feature-inventory audit found a class of silent production failures:
``.env.production.example`` documented a capability key, a Rust binary read it
(``env::var("KEY")`` or a clap ``env = "KEY"``), but ``docker-compose.prod.yml``
never passed it into the container. The feature then answered 503 / fell back
to a dev default in production (dedicated IP, MFA/webhook encryption, tracking
host, SNS callbacks, SSO secret encryption, mailstore encryption-at-rest, AI
flags, invoice auto-pay).

This gate closes the class mechanically:

  * parse every ``KEY=`` name from ``.env.production.example`` (duplicates
    collapse; commented lines are ignored);
  * determine which keys the repo's Rust sources read: direct
    ``env::var("KEY")`` / ``env::var_os("KEY")``, clap ``env = "KEY"``, and
    ``const NAME: &str = "KEY"; ... env::var(NAME)`` indirection (the MFA key
    is read this way);
  * treat ``export_from_file X`` in ``deploy/scripts/entrypoint-wrapper.sh``
    as a bridge for ``X`` (so ``X: ""`` + ``X_FILE: /run/secrets/...`` is a
    valid forwarding shape);
  * require every such key to be referenced by ``docker-compose.prod.yml``
    (an env key, a ``${KEY...}`` interpolation, a load-secret-env.sh
    argument, or an entrypoint ``export KEY=`` bridge), directly or through
    the ``_FILE`` bridge;
  * require an explicit allowlist entry, with a one-line reason, for every
    remaining key (image-only variables, third-party service config, values
    consumed by deploy scripts, or services not deployed by any compose
    stack). An env key with no disposition fails the gate.

``--self-test`` proves both directions on a temporary copy:
  1. the corrected tree is accepted;
  2. removing a forwarded capability key from the compose overlay is rejected;
  3. un-listing an allowlisted-only key is rejected (an allowlist that silently
     swallows anything is not a gate).

Usage:
    python3 tools/check_prod_env_forwarding.py             # exit 1 on drift
    python3 tools/check_prod_env_forwarding.py --self-test
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = ROOT / ".env.production.example"
COMPOSE_PROD = ROOT / "docker-compose.prod.yml"
WRAPPER = ROOT / "deploy/scripts/entrypoint-wrapper.sh"
RUST_ROOT = ROOT / "services/mail-server"

# Capability wiring that the F1 audit called out explicitly. The per-key check
# below is global; these service→key pairs pin the capability to the service
# that actually reads it, so a key forwarded to the wrong container still
# fails.
CAPABILITY_WIRING: dict[str, tuple[str, ...]] = {
    "api-server": (
        "HETZNER_API_TOKEN",
        "HETZNER_MTA_SERVER_ID",
        "HETZNER_DEFAULT_LOCATION",
        "MFA_SECRET_ENCRYPTION_KEY",
        "TRACKING_BASE_URL",
        "TRACKING_PUBLIC_HOST",
        "SNS_ALLOWED_TOPIC_ARNS",
    ),
    "worker": (
        "MFA_SECRET_ENCRYPTION_KEY",
        "TRACKING_BASE_URL",
        "TRACKING_PUBLIC_HOST",
        "WORKER_REPLY_CLASSIFIER_AI_ENABLED",
        "WORKER_REPLY_CLASSIFIER_AI_URL",
    ),
    "tracking": (
        "TRACKING_BASE_URL",
        "TRACKING_PUBLIC_HOST",
    ),
    "enterprise": (
        "SSO_ENCRYPTION_KEY",
        "SSO_ENCRYPTION_KEY_FILE",
    ),
    "mailstore": ("ENCRYPTION_KEY_FILE",),
    "ai-service": (
        "AI_MODEL_ENABLED",
        "AI_EMAIL_AGENT_ENABLED",
        "AI_EMAIL_REQUIRE_APPROVAL",
    ),
    "billing-service": ("AUTO_PAY_OPEN_INVOICES",),
}

# Docker secrets that must be defined AND mounted by the capability services.
CAPABILITY_SECRETS: dict[str, tuple[str, ...]] = {
    "api-server": ("mfa_secret_encryption_key",),
    "worker": ("mfa_secret_encryption_key",),
    "enterprise": ("sso_encryption_key",),
    "mailstore": ("mailstore_encryption_key",),
}

# Every env-example key that is NOT read by Rust and NOT forwarded by the
# production overlay needs a disposition here. Reasons are one line and say
# WHO consumes the value, so an entry cannot silently hide a production
# capability regression.
ALLOWLIST: dict[str, str] = {
    # ── Third-party / base-image configuration ──────────────────────────────
    "POSTGRES_PORT": "only the base compose host-port mapping reads it; production clears ports",
    "POSTGRES_PASSWORD": "rendered to the postgres_password Docker secret (PROD_POSTGRES_PASSWORD_FILE); never a plain env var",
    "GF_SECURITY_ADMIN_USER": "Grafana image var; the prod overlay forwards GF_SECURITY_ADMIN_PASSWORD from GRAFANA_ADMIN_PASSWORD",
    "RUST_BACKTRACE": "Rust runtime logging knob; the production overlay pins RUST_LOG=info and leaves backtraces off",
    "APP_BASE_URL": "consumed by the marketing/links tooling, not by a Rust service env read",
    # ── Host-port mappings used only by the base (dev) compose ──────────────
    "API_PORT": "dev-only host-port mapping; production clears api-server ports and uses the internal :3000",
    "TRACKING_PORT": "dev-only host-port mapping; production clears tracking ports and uses the internal :3001",
    "TRACKING_METRICS_PORT": "dev-only host-port mapping; production scrapes the internal :9092 listener",
    "ENTERPRISE_PORT": "dev-only host-port mapping; production clears enterprise ports and uses the internal :3008",
    "OBSERVABILITY_PORT": "dev-only host-port mapping; production scrapes the internal observability listener",
    # ── Values consumed by deploy-time scripts, not containers ──────────────
    "PAGERDUTY_ROUTING_KEY": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "OPSGENIE_API_KEY": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "SLACK_WEBHOOK_PATH": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "SLACK_WEBHOOK_PATH_LOW": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "ALERT_EMAIL_CRITICAL": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "ALERT_EMAIL_WARNING": "rendered into alertmanager.yml by deploy/scripts/render-alertmanager-config.sh",
    "SYNTHETIC_TARGETS": "consumed by deploy/synthetic-monitor/synthetic_probe.py (host cron, not a compose service)",
    "SYNTHETIC_INTERVAL_SECONDS": "consumed by deploy/synthetic-monitor/synthetic_probe.py (host cron, not a compose service)",
    "SYNTHETIC_TIMEOUT_SECONDS": "consumed by deploy/synthetic-monitor/synthetic_probe.py (host cron, not a compose service)",
    "OTEL_GRPC_PORT": "base compose host-port mapping for the collector; production publishes no collector port",
    "OTEL_HTTP_PORT": "base compose host-port mapping for the collector; production publishes no collector port",
    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "base compose collector config; production exporters use OTEL_EXPORTER_OTLP_ENDPOINT",
    # ── Secret values rendered to files (never plain container env) ─────────
    "COMPLIANCE_SECRETS_ENCRYPTION_KEY": "rendered to the compliance_secrets_encryption_key Docker secret (PROD_COMPLIANCE_SECRETS_ENCRYPTION_KEY_FILE)",
    "COMPLIANCE_SECRETS_KDF_SALT": "rendered to the compliance_secrets_kdf_salt Docker secret (PROD_COMPLIANCE_SECRETS_KDF_SALT_FILE)",
    "COMPLIANCE_CONSENT_SIGNING_KEY": "rendered to the compliance_consent_signing_key Docker secret (PROD_COMPLIANCE_CONSENT_SIGNING_KEY_FILE)",
    "MAILSTORE_ENCRYPTION_KEY": "rendered to the mailstore_encryption_key Docker secret (PROD_MAILSTORE_ENCRYPTION_KEY_FILE); the container reads ENCRYPTION_KEY_FILE",
    # ── Services / credentials not deployed by any compose stack today ──────
    "TEMPLATE_RENDERER_AUTH_TOKEN": "reserved credential; no template-renderer service exists in any compose stack",
    "DEVEX_AUTH_TOKEN": "reserved credential; no devex service exists in any compose stack",
    "AI_EMBEDDINGS_AUTH_TOKEN": "reserved credential; no ai-embeddings service exists in any compose stack",
    "AI_EMBEDDINGS_PORT": "reserved port; no ai-embeddings service exists in any compose stack",
    # ── Documented as intentionally unused ──────────────────────────────────
    "SES_DEFAULT_WARMUP_DAYS": "documented as NOT USED (Hetzner floating IPs provide dedicated-IP warmup)",
    "SES_IP_POOL_PREFIX": "documented as NOT USED (dedicated IPs are Hetzner floating IPs, not an SES pool)",
}

ENV_LINE_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
DIRECT_READ_RE = re.compile(
    r"""(?:env::var|env::var_os)\s*\(\s*"([A-Z][A-Z0-9_]*)"|env\s*=\s*"([A-Z][A-Z0-9_]*)\""""
)
CONST_RE = re.compile(
    r"""(?:const|static)\s+([A-Z][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*"([A-Z][A-Z0-9_]*)\""""
)
BRIDGE_RE = re.compile(r"^\s*export_from_file\s+([A-Z][A-Z0-9_]*)\b", re.MULTILINE)


def env_keys(text: str) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        match = ENV_LINE_RE.match(line)
        if not match:
            continue
        key = match.group(1)
        if key not in seen:
            seen.add(key)
            keys.append(key)
    return keys


def rust_read_keys(rust_root: Path) -> set[str]:
    """Keys read by Rust: direct env reads, clap env attrs, const indirection."""
    keys: set[str] = set()
    for path in rust_root.rglob("*.rs"):
        parts = set(path.parts)
        if "target" in parts or "node_modules" in parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in DIRECT_READ_RE.finditer(text):
            keys.add(match.group(1) or match.group(2))
        # const ENV_VAR: &str = "KEY"; ... env::var(ENV_VAR)
        for match in CONST_RE.finditer(text):
            const_name, literal = match.group(1), match.group(2)
            if re.search(rf"env::var(?:_os)?\s*\(\s*{re.escape(const_name)}\b", text):
                keys.add(literal)
    return keys


def bridged_keys(wrapper: Path) -> set[str]:
    text = wrapper.read_text(encoding="utf-8")
    return {match.group(1) for match in BRIDGE_RE.finditer(text)}


def compose_referenced(compose: str, key: str, bridged: set[str]) -> bool:
    """True when the prod overlay forwards KEY directly or via its _FILE bridge."""

    def referenced(name: str) -> bool:
        patterns = (
            rf"(?m)^\s+{re.escape(name)}\s*:",
            rf"\$\{{{re.escape(name)}(?::[-?+]|[}}])",
            rf"(?m)^\s*-\s*{re.escape(name)}\s*$",
            # Entrypoint bridges export the native env var directly (e.g. the
            # HA 32-byte derivation from the backup secret).
            rf"(?m)^\s*(?:export\s+)?{re.escape(name)}=",
        )
        return any(re.search(pattern, compose) for pattern in patterns)

    if referenced(key):
        return True
    if key in bridged and referenced(f"{key}_FILE"):
        return True
    return False


def service_block(compose: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_.-]+:\s*$|\Z)",
        compose,
        re.MULTILINE | re.DOTALL,
    )
    return match.group(1) if match else ""


def check(root: Path, rust_root: Path | None = None, allowlist: dict[str, str] | None = None) -> list[str]:
    allowlist = ALLOWLIST if allowlist is None else allowlist
    env_path = root / ENV_EXAMPLE.relative_to(ROOT)
    compose_path = root / COMPOSE_PROD.relative_to(ROOT)
    wrapper_path = root / WRAPPER.relative_to(ROOT)
    scan_root = rust_root if rust_root is not None else root / RUST_ROOT.relative_to(ROOT)

    problems: list[str] = []
    for path, label in ((env_path, ".env.production.example"), (compose_path, "docker-compose.prod.yml")):
        if not path.exists():
            problems.append(f"{label} missing")
    if problems:
        return problems
    if not wrapper_path.exists():
        problems.append("deploy/scripts/entrypoint-wrapper.sh missing")
        return problems
    if not scan_root.is_dir():
        problems.append(f"Rust source root missing: {scan_root}")
        return problems

    keys = env_keys(env_path.read_text(encoding="utf-8"))
    read = rust_read_keys(scan_root)
    bridged = bridged_keys(wrapper_path)
    compose = compose_path.read_text(encoding="utf-8")

    for key in keys:
        forwarded = compose_referenced(compose, key, bridged)
        if key in read:
            if not forwarded and key not in allowlist:
                problems.append(
                    f"{key} is read by Rust but docker-compose.prod.yml never forwards it "
                    "(directly or through its _FILE bridge) — the capability silently "
                    "fails/503s in production"
                )
        elif not forwarded and key not in allowlist:
            problems.append(
                f"{key} is documented in .env.production.example but is neither read by "
                "Rust nor forwarded by docker-compose.prod.yml — add the wiring or an "
                "explicit allowlist entry with a reason"
            )

    # The allowlist must stay honest: a dead entry (not in the example) or a
    # stale entry for a key the overlay now forwards would mask a future
    # forwarding regression, so both fail.
    for key, reason in allowlist.items():
        if not reason.strip():
            problems.append(f"allowlist entry {key} has no reason")
        if key not in keys:
            problems.append(
                f"allowlist entry {key} is not present in .env.production.example (stale)"
            )
        elif compose_referenced(compose, key, bridged):
            problems.append(
                f"allowlist entry {key} is stale — docker-compose.prod.yml forwards it; "
                "remove the entry so a future regression is caught"
            )

    # Capability-level checks: correct container, and companion secret mounted.
    for service, required_keys in CAPABILITY_WIRING.items():
        block = service_block(compose, service)
        if not block:
            problems.append(f"docker-compose.prod.yml: service '{service}' not found")
            continue
        for key in required_keys:
            if key not in block:
                problems.append(
                    f"docker-compose.prod.yml: {service} does not receive {key} "
                    f"(capability wiring regression)"
                )
    for service, secret_names in CAPABILITY_SECRETS.items():
        block = service_block(compose, service)
        for secret in secret_names:
            if f"- {secret}" not in block:
                problems.append(
                    f"docker-compose.prod.yml: {service} does not mount the '{secret}' secret"
                )
    for secret in ("mfa_secret_encryption_key", "sso_encryption_key", "mailstore_encryption_key"):
        if not re.search(
            rf"(?m)^  {re.escape(secret)}:\n\s+file:", compose
        ):
            problems.append(
                f"docker-compose.prod.yml: secret '{secret}' is not defined with a file source"
            )
    return problems


def run(root: Path, rust_root: Path | None = None, allowlist: dict[str, str] | None = None) -> int:
    problems = check(root, rust_root=rust_root, allowlist=allowlist)
    if problems:
        for problem in problems:
            print(f"prod-env-forwarding: {problem}", file=sys.stderr)
        print(
            "prod-env-forwarding: production env contract drift (F1 feature-inventory audit)",
            file=sys.stderr,
        )
        return 1
    print("prod-env-forwarding: clean (documented env keys are forwarded or allowlisted)")
    return 0


def self_test() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="prod-env-forwarding-") as tmp:
        copy = Path(tmp) / "repo"
        (copy / "deploy/scripts").mkdir(parents=True)
        for source in (COMPOSE_PROD, ENV_EXAMPLE):
            shutil.copy2(source, copy / source.name)
        shutil.copy2(WRAPPER, copy / WRAPPER.relative_to(ROOT))

        if run(copy, rust_root=RUST_ROOT) != 0:
            print("self-test 1/3: FAIL — corrected tree rejected", file=sys.stderr)
            failures += 1
        else:
            print("self-test 1/3: corrected tree accepted")

        # 2. Remove a forwarded capability key entirely from the overlay.
        compose_path = copy / COMPOSE_PROD.name
        original = compose_path.read_text(encoding="utf-8")
        broken = re.sub(
            r"(?m)^\s+HETZNER_API_TOKEN:.*\n",
            "",
            original,
        )
        compose_path.write_text(broken, encoding="utf-8")
        if run(copy, rust_root=RUST_ROOT) == 0:
            print(
                "self-test 2/3: FAIL — missing HETZNER_API_TOKEN forwarding accepted",
                file=sys.stderr,
            )
            failures += 1
        else:
            print("self-test 2/3: removed forwarded key rejected")

        # 3. Un-list an allowlisted-only key (POSTGRES_PORT is neither read by
        #    Rust nor forwarded by the production overlay).
        compose_path.write_text(original, encoding="utf-8")
        reduced = {key: reason for key, reason in ALLOWLIST.items() if key != "POSTGRES_PORT"}
        if run(copy, rust_root=RUST_ROOT, allowlist=reduced) == 0:
            print(
                "self-test 3/3: FAIL — allowlisted-only key POSTGRES_PORT accepted after un-listing",
                file=sys.stderr,
            )
            failures += 1
        else:
            print("self-test 3/3: un-listed allowlisted-only key rejected")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    return self_test() if args.self_test else run(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
