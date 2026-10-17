"""Docker/Redis/Postgres control-plane helpers (live runs only).

These are the DOCUMENTED environment controls from the v1 dogfood campaign:
rate-limit bucket clearing between phases and (sparingly) an api-server
restart to clear the in-memory adaptive DDoS limiter. Nothing here mutates
product code or data beyond disposable fixtures.
"""
from __future__ import annotations

import subprocess


def docker(cfg, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "--context", cfg.docker_context, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def compose_restart(cfg, service: str) -> bool:
    result = docker(cfg, "restart", f"apexmail-{service}-1", timeout=120)
    return result.returncode == 0


def redis_cli(cfg, *args: str, host: str | None = None, port: int | None = None) -> str:
    if host is not None:
        result = subprocess.run(
            ["redis-cli", "-h", host, "-p", str(port or 6379), "-a", cfg.redis_password,
             "--no-auth-warning", *args],
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout
    result = docker(
        cfg, "exec", "apexmail-redis", "redis-cli", "-a", cfg.redis_password,
        "--no-auth-warning", *args,
    )
    return result.stdout


# Redis DEL accepts many keys per call; batching keeps the control-plane
# cost at O(scans + keys/chunk) subprocesses instead of O(scans + keys).
DEL_CHUNK = 200


def _chunks(items: list[str], size: int):
    for start in range(0, len(items), size):
        yield items[start:start + size]


def clear_redis_patterns(cfg, patterns: tuple[str, ...] | None = None,
                         host: str | None = None, port: int | None = None) -> int:
    from .config import RATE_KEYS

    cleared = 0
    keys: list[str] = []
    for pattern in patterns or RATE_KEYS:
        for key in redis_cli(cfg, "--scan", "--pattern", pattern, host=host, port=port).splitlines():
            key = key.strip()
            if key:
                keys.append(key)
                cleared += 1
    for chunk in _chunks(keys, DEL_CHUNK):
        redis_cli(cfg, "del", *chunk, host=host, port=port)
    return cleared


def docker_ps(cfg) -> list[dict]:
    """Running containers: name, service, status, health."""
    result = docker(cfg, "ps", "-a", "--format", "{{.Names}}\t{{.State}}\t{{.Status}}")
    out = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            out.append({"name": parts[0], "state": parts[1], "status": parts[2]})
    return out


def container_env(cfg, name: str) -> dict[str, str]:
    result = docker(cfg, "exec", name, "env")
    out = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key] = value
    return out
