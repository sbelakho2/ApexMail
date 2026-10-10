"""Runtime configuration for dogfood-v2.

Everything the harness needs to reach the stack, the DB, Redis and Mailpit is
derived here. Defaults are the documented dogfood recipes
(docs/audit/dogfood-2026-10-06/dogfood-live-console.md §1/§10).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

TOOL_DIR = Path(__file__).resolve().parent.parent            # tools/dogfood-v2
REPO_ROOT = TOOL_DIR.parent.parent                            # repo root
DEFAULT_ALLOWLIST = TOOL_DIR / "allowlist.json"
DEFAULT_OUT = TOOL_DIR / "out"

# Live-stack recipes (all read-only or documented environment controls).
DEFAULT_BASE = "http://127.0.0.1:8080"
DEFAULT_HOST = "127.0.0.1"          # web console host (UI_WEB_HOSTS includes it)
DEFAULT_CP_HOST = "admin.localhost"
DEFAULT_MARKETING_HOST = "marketing.localhost"
DEFAULT_MAILPIT = "http://127.0.0.1:8025"
DEFAULT_TRACKING = "http://127.0.0.1:3001"
DEFAULT_ENTERPRISE = "http://127.0.0.1:3002"
DEFAULT_MTA_SMTP = ("127.0.0.1", 5525)
DEFAULT_IMAPS = ("127.0.0.1", 993)
DEFAULT_CLICKHOUSE = "http://127.0.0.1:8123"
DEFAULT_POSTGRES = ("127.0.0.1", 5432)
DEFAULT_REDIS = ("127.0.0.1", 6379)
DEFAULT_DOCKER_CONTEXT = "colima-local"

PASSWORD = "Dogfood!2026-Correct-Horse-9"

# Documented environment controls (cleared between phases; the limiters are
# themselves deliberately exercised by the resource-abuse battery).
RATE_KEYS = (
    "apexmail:login_rate*",
    "apexmail:forgot_password_rate*",
    "apexmail:kiwi_challenge_rate*",
    "apexmail:ddos*",
    "apexmail:rate_limit*",
    # the public (IP-scoped) auth limiter writes apexmail:ratelimit:public:…
    "apexmail:ratelimit*",
    # TOTP failure counters are per-user state, cleared with the limiters
    "apexmail:mfa_verify_failures*",
)


def _read_secret(name: str, fallback: str = "") -> str:
    path = REPO_ROOT / "secrets" / name
    try:
        value = path.read_text().strip()
        return value or fallback
    except OSError:
        return fallback


@dataclass
class Config:
    # targets
    base: str = DEFAULT_BASE
    host: str = DEFAULT_HOST
    cp_host: str = DEFAULT_CP_HOST
    marketing_host: str = DEFAULT_MARKETING_HOST
    mailpit: str = DEFAULT_MAILPIT
    tracking: str = DEFAULT_TRACKING
    enterprise: str = DEFAULT_ENTERPRISE
    # infrastructure
    docker_context: str = DEFAULT_DOCKER_CONTEXT
    postgres: tuple[str, int] = DEFAULT_POSTGRES
    redis: tuple[str, int] = DEFAULT_REDIS
    clickhouse: str = DEFAULT_CLICKHOUSE
    psql_bin: str = "/opt/homebrew/bin/psql"
    postgres_password: str = field(default_factory=lambda: _read_secret("postgres_password.txt"))
    redis_password: str = field(default_factory=lambda: _read_secret("redis_password.txt", "dev-redis-password-minimum-32-chars"))
    # harness behaviour
    mode: str = "live"                    # live | self-test | mutation
    partitions: list[str] = field(default_factory=list)   # empty = all
    json_out: Path = DEFAULT_OUT / "findings.json"
    coverage_out: Path = DEFAULT_OUT / "coverage.json"
    allowlist: Path = DEFAULT_ALLOWLIST
    out_dir: Path = DEFAULT_OUT
    pace_seconds: float = 0.18            # sustained ~5 req/s; adaptive backoff on 429
    timeout: int = 40
    concurrency: int = 1                  # HTTP probes are paced globally
    verbose: bool = False
    max_requests: int = 12000             # hard budget: refuse to look like a DoS
    # self-test / mutation plumbing
    fixture_port: int = 0                 # 0 = pick free port
    mutation_worktree: Path = REPO_ROOT.parent / "ApexMail-scratch-v2"
    mutation_manifest: Path = TOOL_DIR / "mutations" / "manifest.json"
    mutation_build_jobs: int = 8
    # the dedicated test Redis (documented 16379): mutant runs must not share
    # the live dev Redis's limiter/session state
    mutation_redis: tuple[str, int] = ("127.0.0.1", 16379)
    # evidence
    transcript: Path = DEFAULT_OUT / "transcript.log"

    # ── derived helpers ──────────────────────────────────────────────────
    @property
    def db_url(self) -> str:
        host, port = self.postgres
        return f"postgresql://apexmail:{self.postgres_password}@{host}:{port}/apexmail"

    def host_for(self, surface: str) -> str:
        if surface == "control-plane":
            return self.cp_host
        if surface in ("marketing", "marketing-zola"):
            return self.marketing_host
        return self.host

    def is_live(self) -> bool:
        return self.mode == "live"

    def is_fixture(self) -> bool:
        return self.mode == "self-test"


def from_args(args) -> Config:
    cfg = Config()
    for key in (
        "base", "host", "cp_host", "marketing_host", "mailpit", "tracking", "enterprise",
        "docker_context", "psql_bin", "pace_seconds", "timeout", "concurrency",
    ):
        value = getattr(args, key, None)
        if value is not None:
            setattr(cfg, key, value)
    if getattr(args, "json", None):
        cfg.json_out = Path(args.json)
    if getattr(args, "allowlist", None):
        cfg.allowlist = Path(args.allowlist)
    if getattr(args, "partitions", None):
        cfg.partitions = [p.strip() for p in args.partitions.split(",") if p.strip()]
    if getattr(args, "out_dir", None):
        cfg.out_dir = Path(args.out_dir)
        cfg.json_out = cfg.out_dir / cfg.json_out.name
        cfg.coverage_out = cfg.out_dir / cfg.coverage_out.name
        cfg.transcript = cfg.out_dir / cfg.transcript.name
    cfg.verbose = bool(getattr(args, "verbose", False))
    if os.environ.get("DOGFOOD_V2_PACE"):
        cfg.pace_seconds = float(os.environ["DOGFOOD_V2_PACE"])
    if os.environ.get("DOGFOOD_V2_MAX_REQUESTS"):
        cfg.max_requests = int(os.environ["DOGFOOD_V2_MAX_REQUESTS"])
    return cfg
