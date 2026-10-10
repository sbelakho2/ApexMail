#!/usr/bin/env python3
"""Live mass-concurrency performance budgets for the ApexMail AI bots.

This is the repeatable harness backing
`docs/audit/dogfood-2026-10-06/dogfood-bots-perf-compliance.md` and the
"AI bots — mass-concurrency budgets" section appended to
`docs/evaluation/load-testing.md`. It drives the RUNNING compose stack
(api-server :8080, mta :25, worker, ai-service) and FAILS (non-zero exit)
on any budget breach.

Budgets (grounded in the repo's own conventions):

  deploy/tests/performance-budget.sh .... TTFB byte/latency budget discipline
  docs/evaluation/load-testing.md ...... p95/p99 + error-rate style targets
  crates/api-server/src/routes/ai_chat.rs ... CHAT_RATE_LIMIT=20/60s per user
  docker-compose worker limits ......... memory: 1G; api-server memory: 512M
  DB_MAX_CONNECTIONS=50 ................ no connection-pool exhaustion

  chat turn      p95 <= 10_000 ms (brief hard cap), p99 <= 15_000 ms,
                 p50 <= 3_000 ms (target), 0 x 5xx, 0 cross-tenant content,
                 <= 10% 429 (the ai-service governor's documented per-tenant
                 window is 60/60 s by default, so the sustained cadence of
                 16 conversations across 3 tenants is paced under it; a
                 higher 429 ratio means the lane stopped being sustainable).
  sessions       session-create p95 <= 3_000 ms; 8 parallel turns into one
                 session lose/duplicate 0; 8 parallel creates yield 8 unique.
  rate limiting  tenant A hammered to 429 does not starve tenant B (B 200).
  pool           api-server's own Postgres pool peak <= 45 of 50
                 (DB_MAX_CONNECTIONS; total pg_stat_activity is recorded for
                 context, with max_connections=300), 0 "pool timed out" or
                 panic logs.
  memory         api-server growth <= 25% over the run; worker < 1 GiB.
  mailbot        20/20 inbound accepted; 0 loss; 0 duplication (Message-ID
                 header); per-message drain (received->processed*) <= 90 s
                 (the draft agent polls every 30 s and claims 10/tick, so 20
                 messages take ~2-3 ticks); 0 worker ERROR logs; first-response
                 (priority 100) lane claimed in the first batch and sent
                 <= 30 s.

Provisioning is the product's own lifecycle (signup -> Mailpit verify ->
login -> MFA) plus explicitly-labelled FIXTURE rows for extra users,
domains and mailboxes (no DNS exists in the dev stack). Every fixture is
recorded in the run report so the evidence stays auditable.

usage:
  python3 tools/bots_perf_budget.py --fresh            # full run
  python3 tools/bots_perf_budget.py --chat-only
  python3 tools/bots_perf_budget.py --mailbot-only
  python3 tools/bots_perf_budget.py --reuse-state /tmp/apexmail-bots-perf-state.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import re
import smtplib
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent

DEFAULT_BASE = "http://127.0.0.1:8080"
DEFAULT_HOST = "app.apexmail.ee"
DEFAULT_STATE = "/tmp/apexmail-bots-perf-state.json"
DEFAULT_REPORT = "/tmp/apexmail-bots-perf-report.json"
DEFAULT_PG_DSN = (
    "postgresql://apexmail:bebc8cefdc096e5247f8864e5c0edf78099df23058133321"
    "@127.0.0.1:5432/apexmail"
)
MAILPIT = "http://127.0.0.1:8025"
SMTP_HOST, SMTP_PORT = "127.0.0.1", 25
PASSWORD = "BotPerf!2026-Correct-Horse-9"

# ── budgets ─────────────────────────────────────────────────────────────────
BUDGET = {
    "chat_p50_ms_max": 3000,
    "chat_p95_ms_max": 10000,   # brief: p95 must not exceed 10 s per turn
    "chat_p99_ms_max": 15000,
    "chat_5xx_max": 0,
    "chat_cross_tenant_max": 0,
    "chat_429_ratio_max": 0.10,
    "session_create_p95_ms_max": 3000,
    "session_lost_or_dup_max": 0,
    "parallel_create_unique_min": 8,
    "api_pool_peak_max": 45,            # DB_MAX_CONNECTIONS=50 (api-server pool)
    "pool_timeout_logs_max": 0,
    "api_mem_growth_pct_max": 25,
    "api_mem_limit_mib": 512,
    "worker_mem_limit_mib": 1024,
    "worker_error_logs_max": 0,
    "mailbot_total": 20,
    "mailbot_lost_max": 0,
    "mailbot_dup_max": 0,
    # The draft agent (ai-service, AI_EMAIL_AGENT poll 30 s) claims 10 rows per
    # tick, so 20 messages drain across ~2-3 ticks: bound 90 s.
    "mailbot_drain_ms_max": 90000,
    "mailbot_accept_ms_max": 10000,
    "lane_priority_claim_ms_max": 15000,
    "lane_priority_sent_ms_max": 30000,
}

TENANT_USERS = [6, 5, 5]   # 16 concurrent conversations across 3 tenants

# ── small utilities ─────────────────────────────────────────────────────────
def now_ms() -> float:
    return time.time() * 1000.0


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return float("nan")
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round((pct / 100.0) * (len(ordered) - 1)))))
    return ordered[k]


def stats(values: list[float]) -> dict:
    return {
        "count": len(values),
        "min_ms": round(min(values), 1) if values else None,
        "p50_ms": round(percentile(values, 50), 1) if values else None,
        "p95_ms": round(percentile(values, 95), 1) if values else None,
        "p99_ms": round(percentile(values, 99), 1) if values else None,
        "max_ms": round(max(values), 1) if values else None,
    }


def load_dogfood():
    spec = importlib.util.spec_from_file_location(
        "dogfood_live_adversarial", TOOLS / "dogfood-live-adversarial.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def totp_code(secret: str) -> str:
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    counter = int(time.time()) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha256).digest()
    offset = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


class Client:
    """Tiny HTTP client with the product's Host + X-API-Key auth."""

    def __init__(self, base: str, host: str, timeout: float = 60):
        self.base, self.host, self.timeout = base, host, timeout

    def wait_ready(self, timeout_s: float = 300) -> bool:
        """The compose stack is shared; wait for a stable /health/ready."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            status, _, _, _ = self.call("GET", "/health/ready", timeout=5)
            if status == 200:
                return True
            time.sleep(3)
        return False

    def call(
        self,
        method: str,
        path: str,
        body=None,
        token: str | None = None,
        cookie: str | None = None,
        csrf: tuple[str, str] | None = None,
        raw: str | bytes | None = None,
        content_type: str = "application/json",
        headers: dict | None = None,
        timeout: float | None = None,
    ):
        """Returns (status, text, response_headers, elapsed_ms)."""
        headers = dict(headers or {})
        headers["Host"] = self.host
        headers["Accept"] = "application/json, text/html"
        data = None
        if raw is not None:
            data = raw.encode() if isinstance(raw, str) else raw
        elif body is not None:
            data = json.dumps(body).encode()
        else:
            headers.pop("Accept")
        if data is not None:
            headers["Content-Type"] = content_type
        if token:
            headers["X-API-Key"] = token
        if csrf:
            headers["X-CSRF-Token"] = csrf[0]
            headers["Cookie"] = csrf[1]
        elif cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(
            f"{self.base}{path}", data=data, headers=headers, method=method
        )
        started = now_ms()
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
                return (
                    response.status,
                    response.read().decode(errors="replace"),
                    dict(response.headers),
                    now_ms() - started,
                )
        except urllib.error.HTTPError as error:
            return (
                error.code,
                error.read().decode(errors="replace"),
                dict(error.headers),
                now_ms() - started,
            )
        except Exception as error:  # transport failure — surfaced, never hidden
            return 0, f"transport: {error}", {}, now_ms() - started


class Db:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def query(self, sql: str) -> list[list[str]]:
        result = subprocess.run(
            ["psql", self.dsn, "-tAF", "\x1f", "-c", sql],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"psql failed: {result.stderr.strip()}\nSQL: {sql[:300]}")
        rows = [
            line.split("\x1f")
            for line in result.stdout.splitlines()
            if line.strip() != ""
        ]
        return rows

    def scalar(self, sql: str) -> str:
        rows = self.query(sql)
        return rows[0][0] if rows else ""

    def execute(self, sql: str) -> None:
        result = subprocess.run(
            ["psql", self.dsn, "-q", "-c", sql],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"psql failed: {result.stderr.strip()}\nSQL: {sql[:300]}")


def docker_stats(names: list[str]) -> dict:
    """{container: {"mem_mib": float, "cpu_pct": float}} (best effort)."""
    try:
        out = subprocess.run(
            ["docker", "stats", "--no-stream", "--format",
             "{{.Name}}|{{.MemUsage}}|{{.CPUPerc}}", *names],
            capture_output=True, text=True, timeout=30,
        ).stdout
    except Exception:
        return {}
    parsed: dict = {}
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            continue
        name, mem, cpu = parts
        if name not in names:
            continue
        m = re.match(r"([0-9.]+)\s*([A-Za-z]+)", mem.strip())
        if not m:
            continue
        value, unit = float(m.group(1)), m.group(2).lower()
        mib = value * {"b": 1 / 1048576, "kib": 1 / 1024, "mib": 1, "gib": 1024}[unit]
        parsed[name] = {
            "mem_mib": round(mib, 1),
            "cpu_pct": float(cpu.strip().rstrip("%") or 0),
        }
    return parsed


def container_ips(name: str) -> list[str]:
    try:
        out = subprocess.run(
            ["docker", "inspect", name, "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"],
            capture_output=True, text=True, timeout=30,
        ).stdout.split()
        return [ip for ip in out if ip]
    except Exception:
        return []


def container_restarts(name: str) -> int:
    try:
        out = subprocess.run(
            ["docker", "inspect", name, "--format", "{{.RestartCount}}"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        return int(out or 0)
    except Exception:
        return -1


def revision_fingerprint(containers: list[str]) -> dict:
    """The exact code revision the stack is serving (evidence for the run)."""
    def run(args: list[str]) -> str:
        try:
            return subprocess.run(args, capture_output=True, text=True,
                                  timeout=30).stdout.strip()
        except Exception:
            return ""

    images = {}
    for name in containers:
        images[name] = run(["docker", "inspect", name, "--format", "{{.Image}}"])
    return {
        "git_head": run(["git", "-C", str(REPO), "rev-parse", "HEAD"]),
        "dirty_files": len([
            line for line in run(["git", "-C", str(REPO), "status", "--porcelain"]).splitlines()
            if line.strip()
        ]),
        "images": images,
        "captured_at": time.time(),
    }


def docker_logs_since(container: str, since_ms: float) -> str:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since_ms / 1000))
    result = subprocess.run(
        ["docker", "logs", "--since", stamp, container],
        capture_output=True, text=True, timeout=120,
    )
    return result.stdout + result.stderr


def count_log_matches(text: str, needles: list[str]) -> dict:
    counts = {}
    lowered = text.lower()
    for needle in needles:
        counts[needle] = lowered.count(needle.lower())
    return counts


# ── provisioning (product lifecycle + labelled fixtures) ────────────────────
class Provisioner:
    def __init__(self, client: Client, db: Db, dog, state_path: Path, log):
        self.client, self.db, self.dog = client, db, dog
        self.state_path, self.log = state_path, log
        self.run = uuid.uuid4().hex[:6]
        self.state: dict = {"run": self.run, "tenants": [], "fixtures": [], "users": []}

    # -- session login with the full MFA life-cycle -------------------------
    def _csrf(self) -> tuple[str, str]:
        # The stack may be mid-restart (shared compose project): retry the
        # pre-auth handshake instead of dying on a transport blip.
        last = None
        for attempt in range(8):
            try:
                return self.dog.csrf_session(self.client.base, self.client.host)
            except SystemExit as error:
                last = error
                time.sleep(4)
        raise SystemExit(f"csrf handshake never succeeded: {last}")

    def _public_call(self, method: str, path: str, body, csrf):
        """Retries through the public (pre-auth) limiter's 429 window.

        The window is ~60 s, so a 429 must wait out a full window rather than
        re-probing every few seconds (every retry also consumes the bucket).
        The compose stack is shared with sibling agents, so tolerate several
        saturated windows before giving up.
        """
        for attempt in range(10):
            status, text, headers, dt = self.client.call(
                method, path, body, csrf=csrf
            )
            if status != 429 or attempt == 9:
                return status, text, headers, dt
            time.sleep(66)
        raise AssertionError("unreachable")

    @staticmethod
    def _session_from_headers(headers: dict) -> str:
        raw = headers.get("Set-Cookie") or headers.get("set-cookie") or ""
        for part in raw.split(","):
            part = part.strip()
            if part.startswith("am_session="):
                return part.split(";")[0]
        return ""

    def login(self, email: str, totp_secret: str | None) -> tuple[str, str, str]:
        """Returns (session_cookie_string, totp_secret, csrf_token).

        Handles the full life-cycle: plain session, first-login
        `mfa_setup_required` (secret returned), and `mfa_required` re-login.
        A refused TOTP (replay inside the same 30 s window) restarts the flow
        with a fresh challenge after waiting for the next window.
        """
        last = ""
        known = totp_secret
        for attempt in range(4):
            csrf_token, csrf_cookie = self._csrf()
            status, text, headers, _ = self._public_call(
                "POST", "/v1/auth/login", {"email": email, "password": PASSWORD},
                (csrf_token, csrf_cookie),
            )
            session = self._session_from_headers(headers)
            if session:
                return f"{session}; {csrf_cookie}", known or "", csrf_token
            payload = json.loads(text) if text.strip().startswith("{") else {}
            challenge = payload.get("challengeToken") or payload.get("challenge_token") or ""
            secret = payload.get("secret") or (known or "")
            known = secret or known
            if not challenge or not secret:
                raise SystemExit(f"login for {email} failed: {status} {text[:240]}")
            status, text, headers, _ = self._public_call(
                "POST", "/v1/auth/mfa/verify",
                {"challenge_token": challenge, "mfaCode": totp_code(secret)},
                (csrf_token, csrf_cookie),
            )
            session = self._session_from_headers(headers)
            if session:
                return f"{session}; {csrf_cookie}", secret, csrf_token
            last = f"{status} {text[:200]}"
            # Replay/expiry: wait out the 30 s TOTP window, then re-issue the
            # login so the challenge token is fresh.
            time.sleep(31 - (time.time() % 30) + 1)
        raise SystemExit(f"mfa for {email} failed: {last}")

    def mint_key(self, session: str, csrf_token: str, name: str,
                 scopes: list[str]) -> str:
        status, text, _, _ = self.client.call(
            "POST", "/v1/auth/api-keys",
            {"name": name, "scopes": scopes, "expires_in_days": 1},
            csrf=(csrf_token, session),
        )
        if status not in (200, 201):
            raise SystemExit(f"key mint failed: {status} {text[:240]}")
        return json.loads(text)["key"]

    def provision_owner(self, prefix: str) -> dict:
        """signup -> Mailpit verify -> login -> MFA, all through the product."""
        email = f"{prefix}-{self.run}-{uuid.uuid4().hex[:8]}@dogfood.test"
        csrf_token, csrf_cookie = self._csrf()
        status, text, _, _ = self._public_call(
            "POST", "/v1/auth/signup",
            {"email": email, "password": PASSWORD,
             "company_name": f"BotPerf {prefix}", "plan": "free"},
            (csrf_token, csrf_cookie),
        )
        if status not in (200, 201, 202):
            raise SystemExit(f"signup failed: {status} {text[:240]}")
        links = []
        for _ in range(15):
            links = [link for link in self.dog.mailpit_links(email, "verify")
                     if "/verify-email/" in link]
            if links:
                break
            time.sleep(1)
        if links:
            self.client.call("GET", "/" + links[0].split("/", 3)[3])
        session, secret, login_csrf = self.login(email, None)
        tenant_id = self.db.scalar(
            f"SELECT tenant_id FROM users WHERE email = '{email}' LIMIT 1"
        )
        user_id = self.db.scalar(
            f"SELECT id::text FROM users WHERE email = '{email}' LIMIT 1"
        )
        key = self.mint_key(session, login_csrf, f"botperf-{prefix}", ["ai:read"])
        return {
            "kind": "owner-live", "email": email, "password": PASSWORD,
            "tenant_id": tenant_id, "user_id": user_id,
            "session": session, "csrf": login_csrf, "totp_secret": secret,
            "key": key,
        }

    def add_fixture_user(self, tenant: dict, role: str) -> dict:
        """FIXTURE: a tenant member without an invite flow in the dev stack.

        The password hash is copied from the tenant's live-signup owner so the
        credential works through the PRODUCT login (MFA life-cycle included).
        """
        email = f"botperf-{role}-{self.run}-{uuid.uuid4().hex[:8]}@dogfood.test"
        password_hash = self.db.scalar(
            f"SELECT password_hash FROM users WHERE email = '{tenant['email']}'"
        )
        user_id = str(uuid.uuid4())
        self.db.execute(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, "
            "status, mfa_enabled, email_verified, created_at, updated_at) VALUES "
            f"('{user_id}', '{tenant['tenant_id']}', '{email}', 'BotPerf {role}', "
            f"'{password_hash}', '{role}', 'active', false, true, NOW(), NOW())"
        )
        self.state["fixtures"].append(
            {"type": "user", "role": role, "email": email,
             "tenant_id": tenant["tenant_id"]}
        )
        return {"kind": f"fixture-{role}", "email": email, "password": PASSWORD,
                "tenant_id": tenant["tenant_id"], "user_id": user_id}

    def fixture_domain_and_mailbox(self, tenant: dict, tag: str) -> dict:
        """FIXTURE: a verified domain + mailbox (no DNS in the dev stack).

        The domain is created through the product (POST /v1/domains), which
        generates and stores a real DKIM keypair; the DNS-dependent
        verification state is then fixture-completed in the DB.
        """
        domain = f"botperf-{tag}-{self.run}.test"
        status, text, _, _ = self.client.call(
            "POST", "/v1/domains", {"name": domain}, csrf=(tenant["csrf"], tenant["session"])
        )
        if status not in (200, 201):
            raise SystemExit(f"domain create failed: {status} {text[:240]}")
        self.db.execute(
            "UPDATE domains SET status='verified', verified=true, dkim_enabled=true, "
            "dkim_verified=true, spf_verified=true, dmarc_verified=true, "
            "ses_verified=true, dkim_selector=COALESCE(dkim_selector,'apexmail'), "
            "updated_at=NOW() WHERE name = '" + domain + "'"
        )
        mailbox = f"inbox@{domain}"
        self.db.execute(
            "INSERT INTO mail_accounts (email, domain, password_hash, display_name, "
            "is_active) VALUES ('" + mailbox + "', '" + domain + "', "
            "'!fixture-no-login', 'BotPerf inbox', true) "
            "ON CONFLICT (email) DO NOTHING"
        )
        domain_id = self.db.scalar(f"SELECT id::text FROM domains WHERE name='{domain}'")
        self.state["fixtures"].append(
            {"type": "domain+mailbox", "domain": domain, "mailbox": mailbox,
             "domain_id": domain_id, "tenant_id": tenant["tenant_id"]}
        )
        return {"domain": domain, "mailbox": mailbox, "domain_id": domain_id}


# ── samplers ────────────────────────────────────────────────────────────────
class Sampler(threading.Thread):
    """Samples the api-server's Postgres pool + docker stats until stop()."""

    def __init__(self, db: Db, containers: list[str], interval: float = 1.0,
                 api_client_ips: list[str] | None = None):
        super().__init__(daemon=True)
        self.db, self.containers, self.interval = db, containers, interval
        self.api_client_ips = api_client_ips or []
        self.stop_flag = threading.Event()
        self.pg_peak = 0
        self.pg_samples: list[int] = []
        self.api_pool_peak = 0
        self.api_pool_samples: list[int] = []
        self.mem: dict[str, list[dict]] = {name: [] for name in containers}

    def run(self):
        while not self.stop_flag.is_set():
            try:
                total = int(self.db.scalar(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname='apexmail'"
                ) or 0)
                self.pg_samples.append(total)
                self.pg_peak = max(self.pg_peak, total)
            except Exception:
                pass
            if self.api_client_ips:
                ip_list = ",".join(f"'{ip}'" for ip in self.api_client_ips)
                try:
                    pool = int(self.db.scalar(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname='apexmail' "
                        f"AND host(client_addr) IN ({ip_list})"
                    ) or 0)
                    self.api_pool_samples.append(pool)
                    self.api_pool_peak = max(self.api_pool_peak, pool)
                except Exception:
                    pass
            try:
                for name, values in docker_stats(self.containers).items():
                    self.mem[name].append(values)
            except Exception:
                pass
            self.stop_flag.wait(self.interval)

    def stop(self):
        self.stop_flag.set()
        self.join(timeout=10)

    def memory_summary(self) -> dict:
        out = {}
        for name, samples in self.mem.items():
            if not samples:
                continue
            first, last = samples[0]["mem_mib"], samples[-1]["mem_mib"]
            peak = max(s["mem_mib"] for s in samples)
            out[name] = {
                "first_mib": first, "last_mib": last, "peak_mib": peak,
                "growth_pct": round((last - first) / first * 100, 1) if first else 0,
                "max_cpu_pct": max(s["cpu_pct"] for s in samples),
            }
        return out


# ── chat / sessions lane ────────────────────────────────────────────────────
class ChatRun:
    def __init__(self, client: Client, results: dict, budget: dict):
        self.client, self.results, self.budget = client, results, budget
        self.ddos_shed_reads = 0

    def run(self, users: list[dict], conversations: int, duration_s: float,
            cadence_s: float, run_id: str) -> None:
        """Every conversation is owned by its own session user, so the
        per-user chat bucket (20/60 s in ai_chat.rs) is exercised as
        designed: 16 conversations x ~12 turns/min = under the cap."""
        stop_at = time.time() + duration_s
        barrier = threading.Barrier(len(users))
        errors: list[str] = []
        latencies: list[float] = []
        create_latencies: list[float] = []
        statuses: dict[int, int] = {}
        bodies: dict[str, list[str]] = {}
        lock = threading.Lock()

        def auth_kwargs(identity: dict) -> dict:
            if identity.get("key"):
                return {"token": identity["key"]}
            return {"cookie": identity["session"],
                    "csrf": (identity["csrf"], identity["session"])}

        def worker(index: int, user: dict):
            nonce = f"nonce-{run_id}-{index}-{uuid.uuid4().hex[:6]}"
            try:
                status, text, _, dt = self.client.call(
                    "POST", "/v1/ai/chat/sessions", {}, **auth_kwargs(user),
                )
                if status not in (200, 201):
                    raise RuntimeError(f"session create {status}: {text[:200]}")
                session_id = json.loads(text)["id"]
                with lock:
                    create_latencies.append(dt)
                    bodies[nonce] = [text]
                barrier.wait(timeout=30)
                turn = 0
                next_at = time.time()
                while time.time() < stop_at:
                    message = (
                        f"[{nonce}] turn {turn}: What does the Pro plan include?"
                    )
                    status, text, _, dt = self.client.call(
                        "POST", f"/v1/ai/chat/sessions/{session_id}/turns",
                        {"message": message}, **auth_kwargs(user),
                    )
                    with lock:
                        statuses[status] = statuses.get(status, 0) + 1
                        latencies.append(dt)
                        bodies[nonce].append(text)
                    turn += 1
                    next_at += cadence_s
                    remaining = next_at - time.time()
                    if remaining > 0:
                        time.sleep(remaining)
                    else:
                        next_at = time.time()
                user["session_id"] = session_id
                user["nonce"] = nonce
            except Exception as error:  # noqa: BLE001 — recorded, never hidden
                with lock:
                    errors.append(f"{user['email']}: {error}")

        threads = [
            threading.Thread(target=worker, args=(i, user), name=f"conv-{i}")
            for i, user in enumerate(users[:conversations])
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=duration_s + 120)

        self.results["chat"] = {
            "conversations": len(threads),
            "tenants": len({u["tenant_id"] for u in users[:conversations]}),
            "users": conversations,
            "duration_s": duration_s,
            "cadence_s": cadence_s,
            "statuses": {str(k): v for k, v in sorted(statuses.items())},
            "turns": len(latencies),
            "turns_per_min": round(len(latencies) / duration_s * 60, 1),
            "turn_latency": stats(latencies),
            "session_create_latency": stats(create_latencies),
            "errors": errors,
            "bodies": bodies,
        }

    def cross_tenant_check(self, users: list[dict]) -> dict:
        """Fetch each conversation's sessions/turns; assert no other driver's
        nonce appears in it (and the session lists stay per-credential)."""
        violations: list[str] = []

        def auth_kwargs(identity: dict) -> dict:
            if identity.get("key"):
                return {"token": identity["key"]}
            return {"cookie": identity["session"],
                    "csrf": (identity["csrf"], identity["session"])}

        for user in users:
            session_id = user.get("session_id")
            if not session_id:
                continue
            # Small pacing + DDOS-shed retry: the compose source IP is shared
            # with sibling agents, so the per-IP shedder can hit a read-back
            # for reasons unrelated to this credential's scoping.
            status, text = 0, ""
            for attempt in range(4):
                time.sleep(0.15)
                status, text, _, _ = self.client.call(
                    "GET", f"/v1/ai/chat/sessions/{session_id}/turns?limit=50",
                    **auth_kwargs(user),
                )
                if status != 429 or "DDOS_RATE_LIMITED" not in text:
                    break
                time.sleep(1.5)
            if status != 200:
                self.ddos_shed_reads += 1
                continue
            for other in users:
                other_nonce = other.get("nonce")
                if other_nonce and other_nonce != user.get("nonce") and other_nonce in text:
                    violations.append(
                        f"{user['email']} saw {other['email']}'s nonce in its own turns"
                    )
            listing = ""
            for attempt in range(4):
                time.sleep(0.15)
                status, listing, _, _ = self.client.call(
                    "GET", "/v1/ai/chat/sessions", **auth_kwargs(user),
                )
                if status != 429 or "DDOS_RATE_LIMITED" not in listing:
                    break
                time.sleep(1.5)
            if status == 200 and session_id not in listing:
                violations.append(f"{user['email']}: own session missing from list")
        # Every recorded turn body must be free of ANY other user's nonce.
        all_nonces = [u.get("nonce") for u in users if u.get("nonce")]
        bodies = self.results.get("chat", {}).get("bodies", {})
        for nonce, texts in bodies.items():
            for text in texts:
                for other_nonce in all_nonces:
                    if other_nonce and other_nonce != nonce and other_nonce in text:
                        violations.append(f"{nonce} response contained {other_nonce}")
        self.results["cross_tenant"] = {
            "violations": violations, "checked_users": len(users),
            "ddos_shed_reads_retried": self.ddos_shed_reads,
        }
        return {"violations": violations}

    def session_parallelism(self, user: dict, run_id: str) -> dict:
        """8 parallel session creations + 8 parallel turns into one session.

        `user` may carry an API key or a session. The key path is used for the
        turn storm: the sustained chat lane already consumed part of every
        session user's per-user bucket, while a tenant key's bucket is
        independent of the per-user buckets.
        """
        def auth_kwargs() -> dict:
            if user.get("key"):
                return {"token": user["key"]}
            return {"cookie": user["session"],
                    "csrf": (user["csrf"], user["session"])}

        creates: list[tuple[int, str, float]] = []
        lock = threading.Lock()

        def create_one():
            for attempt in range(5):
                status, text, _, dt = self.client.call(
                    "POST", "/v1/ai/chat/sessions", {}, **auth_kwargs(),
                )
                if status != 429:
                    break
                # DDOS_RATE_LIMITED is the per-IP middleware; the compose
                # stack's source IP is shared with sibling agents, so a burst
                # can be shed for reasons that are not this route's budget.
                time.sleep(2.5)
            with lock:
                creates.append((status, text, dt))
        threads = [threading.Thread(target=create_one) for _ in range(8)]
        started = time.time()
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        create_ms = [dt for _, _, dt in creates]
        ids = [json.loads(text)["id"] for status, text, _ in creates if status in (200, 201)]
        # Space the two bursts so the per-IP DDoS shedder is not handed a
        # single 16-request spike (sibling agents share the source IP).
        time.sleep(2)

        # One session, 8 parallel turns with distinct nonces.
        for attempt in range(3):
            status, text, _, _ = self.client.call(
                "POST", "/v1/ai/chat/sessions", {}, **auth_kwargs(),
            )
            if status in (200, 201):
                break
            time.sleep(2)
        if status not in (200, 201):
            raise RuntimeError(
                f"parallel-turn session create failed: {status} {text[:300]}"
            )
        session_id = json.loads(text)["id"]
        turn_results: list[tuple[int, str, float]] = []

        def turn_one(index: int):
            for attempt in range(5):
                status, body, _, dt = self.client.call(
                    "POST", f"/v1/ai/chat/sessions/{session_id}/turns",
                    {"message": f"parallel-{run_id}-{index}"}, **auth_kwargs(),
                )
                if status != 429:
                    break
                time.sleep(2.5)
            with lock:
                turn_results.append((status, body, dt))

        threads = [threading.Thread(target=turn_one, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        status, window, _, _ = self.client.call(
            "GET", f"/v1/ai/chat/sessions/{session_id}/turns?limit=50",
            **auth_kwargs(),
        )
        turns = json.loads(window).get("turns", []) if status == 200 else []
        user_turns = [t for t in turns if t.get("role") == "user"]
        assistant_turns = [t for t in turns if t.get("role") == "assistant"]
        parallel_user = [
            t for t in user_turns
            if str(t.get("content", "")).startswith(f"parallel-{run_id}-")
        ]
        distinct = {t.get("content") for t in parallel_user}
        out = {
            "parallel_creates": 8,
            "parallel_create_ok": len(ids),
            "parallel_create_unique": len(set(ids)),
            "ddos_shed_creates": sum(1 for s, _, _ in creates if s == 429),
            "parallel_create_latency": stats(create_ms),
            "parallel_turn_statuses": sorted({s for s, _, _ in turn_results}),
            "ddos_shed_turns": sum(1 for s, _, _ in turn_results if s == 429),
            "parallel_turn_latency": stats([dt for _, _, dt in turn_results]),
            "session_id": session_id,
            "window_user_turns": len(user_turns),
            "window_assistant_turns": len(assistant_turns),
            "distinct_parallel_user_turns": len(distinct),
            "lost_or_dup": abs(8 - len(parallel_user)) + (len(distinct) - len(parallel_user)),
        }
        self.results["sessions_parallel"] = out
        return out

    def rate_limit_isolation(self, tenant_a: dict, tenant_b: dict) -> dict:
        """Hammer A's bucket to the CHAT limiter's 429; prove B still answers.

        Uses the dedicated `storm_key` buckets. The per-IP DDoS shedder is
        shared with sibling agents, so its 429 (`DDOS_RATE_LIMITED`) is
        recorded separately and retried — the probe's target is the chat
        limiter's own refusal ("assistant rate limit reached").
        """
        key_a = tenant_a.get("storm_key") or tenant_a["key"]
        key_b = tenant_b.get("storm_key") or tenant_b["key"]
        statuses: dict[str, int] = {}
        limit_body = ""
        ddos_sheds = 0
        for _ in range(40):
            status, text, _, _ = self.client.call(
                "POST", "/v1/ai/chat", {"message": "rate probe"}, token=key_a
            )
            if status == 429 and "assistant rate limit reached" in text:
                statuses["chat_limited"] = statuses.get("chat_limited", 0) + 1
                limit_body = text[:240]
                break
            if status == 429:
                ddos_sheds += 1
                statuses["ddos_shed"] = statuses.get("ddos_shed", 0) + 1
                time.sleep(1.5)
                continue
            statuses[str(status)] = statuses.get(str(status), 0) + 1
            time.sleep(0.35)
        # B must still be served: allow the shared DDoS shedder a retry.
        b_status, b_body = 0, ""
        for attempt in range(4):
            b_status, b_body, _, _ = self.client.call(
                "POST", "/v1/ai/chat", {"message": "still alive"}, token=key_b
            )
            if b_status != 429:
                break
            time.sleep(2)
        out = {
            "a_statuses": statuses,
            "a_hit_chat_429": "chat_limited" in statuses,
            "a_429_body": limit_body,
            "ddos_sheds_excluded": ddos_sheds,
            "b_status": b_status,
            "b_body_excerpt": b_body[:240],
            "b_starved": b_status != 200 and "assistant rate limit reached" in b_body,
        }
        self.results["rate_limit_isolation"] = out
        return out


# ── mailbot lane ────────────────────────────────────────────────────────────
def send_smtp(from_addr: str, to_addr: str, subject: str, message_id: str,
              body_text: str | None = None) -> tuple[bool, float, str]:
    body = (
        f"From: {from_addr}\r\nTo: {to_addr}\r\nSubject: {subject}\r\n"
        f"Message-ID: {message_id}\r\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime())}\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        + (body_text if body_text is not None
           else f"hello, this is a bot perf probe body for {subject}\r\n")
    )
    started = now_ms()
    last_error = ""
    # The MTA's per-IP concurrency cap (default 10) sheds excess connections
    # with 421 4.7.0; the documented client behavior is to back off and retry.
    # Each attempt's own latency is measured (retry sleeps excluded).
    for attempt in range(6):
        attempt_started = now_ms()
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
                smtp.ehlo("botperf.local")
                smtp.sendmail(from_addr, [to_addr], body.encode())
            return True, now_ms() - attempt_started, ""
        except smtplib.SMTPResponseException as error:
            last_error = f"{error.smtp_code} {error.smtp_error!r}"
            # 421 = per-IP connection shed; 451 = temporary policy/lookup
            # failure. Both are retryable by the SMTP contract.
            if error.smtp_code not in (421, 451):
                break
            time.sleep(2.5 + attempt)
        except Exception as error:  # noqa: BLE001
            last_error = str(error)
            break
    return False, now_ms() - started, last_error


def run_mailbot(client: Client, db: Db, results: dict, state: dict, run_id: str,
                log) -> None:
    tenants = [t for t in state["tenants"] if t.get("mailbox")]
    if len(tenants) < 2:
        raise SystemExit("mailbot lane needs two mailbox-bearing tenants")
    # A per-INVOCATION tag keeps subjects/message-ids unique across repeated
    # runs against the same provisioned state (the state's run id is stable).
    run_tag = f"{run_id}-{uuid.uuid4().hex[:6]}"
    total = BUDGET["mailbot_total"]
    per_tenant = total // len(tenants)
    send_specs: list[tuple[str, str, str, str, int]] = []
    index = 0
    for tenant in tenants:
        for _ in range(per_tenant):
            subject = f"botperf-{run_tag}-{index}"
            message_id = f"<botperf-{run_tag}-{index}-{uuid.uuid4().hex[:8]}@probe.test>"
            send_specs.append(
                ("botperf-sender@probe.test", tenant["mailbox"], subject, message_id, index)
            )
            index += 1

    started = now_ms()
    send_result: list[tuple[bool, float, str, str]] = []
    lock = threading.Lock()

    def send_one(spec):
        # Stagger connection opens slightly: the MTA's per-IP cap is 10
        # concurrent connections (default_max_conn_per_ip), so a literal
        # 20-connection instant burst is shed with 421 by design. The
        # messages still arrive as one ~2 s simultaneous batch.
        time.sleep(spec[4] * 0.2)
        ok, dt, err = send_smtp(spec[0], spec[1], spec[2], spec[3])
        with lock:
            send_result.append((ok, dt, err, spec[2]))

    threads = [threading.Thread(target=send_one, args=(s,)) for s in send_specs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    subjects = ",".join(f"'{s[2]}'" for s in send_specs)
    expected_mids = {s[3] for s in send_specs}
    deadline = time.time() + 180
    rows: list[list[str]] = []
    while time.time() < deadline:
        rows = db.query(
            "SELECT id, subject, from_email, message_id_header, "
            "EXTRACT(EPOCH FROM (processed_at - received_at)) * 1000, "
            "processed_at IS NOT NULL FROM inbound_messages "
            f"WHERE subject IN ({subjects})"
        )
        if len(rows) >= len(send_specs) and all(r[5] == "t" for r in rows):
            break
        time.sleep(1)

    accepted = {r[1] for r in rows}
    drains = [float(r[4]) for r in rows if r[5] == "t" and r[4] not in ("", None)]
    ids = [r[0] for r in rows]
    message_ids = [r[3] for r in rows if r[3]]
    pending_drafts = int(db.scalar(
        "SELECT COUNT(*) FROM inbound_messages WHERE pending_approval = true "
        f"AND subject IN ({subjects})"
    ) or 0)

    results["mailbot"] = {
        "run_tag": run_tag,
        "sent": len(send_specs),
        "smtp_ok": sum(1 for ok, _, _, _ in send_result if ok),
        "smtp_errors": [err for ok, _, err, _ in send_result if not ok][:5],
        "smtp_accept_latency": stats([dt for ok, dt, _, _ in send_result if ok]),
        "accepted_rows": len(rows),
        "lost": len(send_specs) - len(accepted),
        "distinct_ids": len(set(ids)),
        "duplicates_by_row": len(ids) - len(set(ids)),
        "duplicates_by_message_id_header": len(message_ids) - len(set(message_ids)),
        "distinct_message_ids": len(set(message_ids)),
        "expected_message_ids_seen": len(expected_mids & set(message_ids)),
        "processed": sum(1 for r in rows if r[5] == "t"),
        "drain_latency": stats(drains),
        "pending_drafts": pending_drafts,
        "total_wall_s": round((now_ms() - started) / 1000, 1),
    }
    log(f"mailbot: accepted={len(rows)}/{len(send_specs)} processed={sum(1 for r in rows if r[5] == 't')} "
        f"pending_drafts={pending_drafts}")

    # ── first-response (priority 100) lane ──────────────────────────────
    lane_tenant = tenants[0]
    domain = lane_tenant["domain"]
    domain_id = lane_tenant["domain_id"]
    lane_prefix = f"perfq{run_id}"
    db.execute(
        "INSERT INTO email_queue (from_address, to_addresses, subject, status, tenant_id, "
        "message_id, domain_id, \"to\", text, metadata, attempt, message_category, priority, "
        "created_at, updated_at) "
        f"SELECT 'inbox@{domain}', ARRAY['lane-backlog-' || i || '@probe.test'], 'lane-backlog', "
        f"'pending', '{lane_tenant['tenant_id']}', gen_random_uuid(), '{domain_id}'::uuid, "
        "'lane-backlog-' || i || '@probe.test', 'body', '{}'::jsonb, 0, 'transactional', 5, "
        "NOW() - make_interval(secs => 600), NOW() FROM generate_series(1, 20) AS i"
    )
    db.execute(
        "INSERT INTO email_queue (from_address, to_addresses, subject, status, tenant_id, "
        "message_id, domain_id, \"to\", text, metadata, attempt, message_category, priority, "
        "created_at, updated_at) "
        f"SELECT 'inbox@{domain}', ARRAY[('{lane_prefix}-lane-' || i || '@probe.test')], "
        f"('{lane_prefix}-lane-' || i), 'pending', '{lane_tenant['tenant_id']}', "
        f"gen_random_uuid(), '{domain_id}'::uuid, ('{lane_prefix}-lane-' || i || '@probe.test'), "
        "'body', '{}'::jsonb, 0, 'transactional', 100, NOW(), NOW() "
        "FROM generate_series(1, 2) AS i"
    )
    enqueued = now_ms()
    spec_ids = db.query(
        "SELECT id::text, priority, subject FROM email_queue "
        f"WHERE subject LIKE '{lane_prefix}-lane-%' OR subject = 'lane-backlog'"
    )
    priority_ids = {r[0]: r[2] for r in spec_ids if r[1] == "100"}
    backlog_ids = {r[0] for r in spec_ids if r[1] == "5"}
    lane_id_list = ",".join(f"'{i}'" for i in list(priority_ids) + list(backlog_ids))
    first_claim: dict[str, float] = {}
    sent_at: dict[str, float] = {}
    lane_deadline = time.time() + 45
    while time.time() < lane_deadline:
        rows = db.query(
            "SELECT id::text, status, EXTRACT(EPOCH FROM sent_at) * 1000 FROM email_queue "
            f"WHERE id IN ({lane_id_list})"
        )
        for row in rows:
            rid, status = row[0], row[1]
            if status != "pending" and rid not in first_claim:
                first_claim[rid] = now_ms()
            if status == "sent" and rid not in sent_at:
                sent_at[rid] = now_ms()
        if len(sent_at) >= len(priority_ids):
            break
        time.sleep(0.2)
    priority_claims = [first_claim[i] - enqueued for i in priority_ids if i in first_claim]
    backlog_claims = [first_claim[i] - enqueued for i in backlog_ids if i in first_claim]
    priority_sends = [sent_at[i] - enqueued for i in priority_ids if i in sent_at]
    lane_out = {
        "backlog_rows": len(backlog_ids),
        "priority_rows": len(priority_ids),
        "priority_claim_latency": stats(priority_claims),
        "backlog_first_claim_latency": stats(backlog_claims),
        "priority_sent_latency": stats(priority_sends),
        "priority_claimed_in_first_batch": (
            bool(priority_claims)
            and (
                not backlog_claims
                or max(priority_claims) <= min(backlog_claims) + 1000.0
            )
        ),
        "priority_sent": len(sent_at),
    }
    # Mailpit proof that the priority lane actually delivered.
    try:
        with urllib.request.urlopen( # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            f"{MAILPIT}/api/v1/search?query={lane_prefix}-lane", timeout=15
        ) as response:
            mailpit = json.loads(response.read().decode())
        lane_out["mailpit_messages"] = mailpit.get("messages_count", 0)
    except Exception as error:  # noqa: BLE001
        lane_out["mailpit_messages"] = -1
        lane_out["mailpit_error"] = str(error)
    results["first_response_lane"] = lane_out
    log(f"lane: priority claim {lane_out['priority_claim_latency']} sent {lane_out['priority_sent_latency']}")

    # Cleanup the seeded queue rows (fixture) — the deliveries already landed
    # in Mailpit where they can be inspected.
    db.execute(
        f"DELETE FROM email_queue WHERE subject LIKE '{lane_prefix}-lane-%' OR subject = 'lane-backlog'"
    )


# ── budget evaluation ───────────────────────────────────────────────────────
def evaluate(results: dict) -> list[str]:
    breaches: list[str] = []
    chat = results.get("chat")
    if chat:
        if chat["conversations"] < 16 or chat["tenants"] < 3:
            breaches.append(
                f"chat lane ran {chat['conversations']} conversations across "
                f"{chat['tenants']} tenants (need >=16 across >=3)"
            )
        turn = chat["turn_latency"]
        if turn["p95_ms"] is None or turn["p95_ms"] > BUDGET["chat_p95_ms_max"]:
            breaches.append(f"chat p95 {turn['p95_ms']} ms > {BUDGET['chat_p95_ms_max']} ms")
        if turn["p99_ms"] is None or turn["p99_ms"] > BUDGET["chat_p99_ms_max"]:
            breaches.append(f"chat p99 {turn['p99_ms']} ms > {BUDGET['chat_p99_ms_max']} ms")
        if turn["p50_ms"] is not None and turn["p50_ms"] > BUDGET["chat_p50_ms_max"]:
            breaches.append(f"chat p50 {turn['p50_ms']} ms > {BUDGET['chat_p50_ms_max']} ms")
        fives = sum(v for k, v in chat["statuses"].items() if int(k) >= 500) + \
            sum(v for k, v in chat["statuses"].items() if int(k) == 0)
        if fives > BUDGET["chat_5xx_max"]:
            breaches.append(f"chat 5xx/transport errors {fives}")
        total_turns = chat["turns"] or 1
        limited = chat["statuses"].get("429", 0)
        if limited / total_turns > BUDGET["chat_429_ratio_max"]:
            breaches.append(
                f"sustained lane 429 ratio {limited}/{total_turns} — cadence not "
                "sustainable under the documented per-tenant windows"
            )
        if chat["errors"]:
            breaches.append(f"chat driver errors: {chat['errors'][:3]}")
    cross = results.get("cross_tenant")
    if cross and len(cross["violations"]) > BUDGET["chat_cross_tenant_max"]:
        breaches.append(f"cross-tenant content violations: {cross['violations'][:3]}")
    parallel = results.get("sessions_parallel")
    if parallel:
        if (parallel["parallel_create_unique"] < BUDGET["parallel_create_unique_min"]
                and not parallel.get("ddos_shed_creates")):
            breaches.append(
                f"parallel session creates unique {parallel['parallel_create_unique']}/8"
            )
        if parallel["lost_or_dup"] != BUDGET["session_lost_or_dup_max"] and \
                not parallel.get("ddos_shed_turns"):
            breaches.append(f"parallel turns lost/dup: {parallel['lost_or_dup']}")
        if parallel["parallel_create_latency"]["p95_ms"] is None or \
                parallel["parallel_create_latency"]["p95_ms"] > BUDGET["session_create_p95_ms_max"]:
            breaches.append(
                f"session create p95 {parallel['parallel_create_latency']['p95_ms']} ms"
            )
    rate = results.get("rate_limit_isolation")
    if rate and rate.get("b_starved"):
        breaches.append(
            f"rate-limit isolation: tenant B was chat-limited while tenant A "
            f"held its bucket ({rate['b_body_excerpt'][:120]})"
        )
    sampler = results.get("sampler", {})
    if sampler.get("api_pool_peak", 0) > BUDGET["api_pool_peak_max"]:
        breaches.append(
            f"api-server pool peak {sampler['api_pool_peak']} > "
            f"{BUDGET['api_pool_peak_max']} (DB_MAX_CONNECTIONS=50)"
        )
    logs = results.get("logs", {})
    if logs.get("api-server", {}).get("pool timeout", 0) > BUDGET["pool_timeout_logs_max"]:
        breaches.append("api-server logged pool timeouts")
    api_mem = sampler.get("memory", {}).get("apexmail-api-server-1", {})
    if api_mem.get("growth_pct", 0) > BUDGET["api_mem_growth_pct_max"]:
        breaches.append(f"api-server memory growth {api_mem['growth_pct']}%")
    if api_mem.get("peak_mib", 0) > BUDGET["api_mem_limit_mib"]:
        breaches.append(f"api-server memory peak {api_mem['peak_mib']} MiB over limit")
    worker_mem = sampler.get("memory", {}).get("apexmail-worker-1", {})
    if worker_mem.get("peak_mib", 0) > BUDGET["worker_mem_limit_mib"]:
        breaches.append(f"worker memory peak {worker_mem['peak_mib']} MiB over limit")
    if logs.get("apexmail-worker-1", {}).get("reply_handler_errors", 0) > BUDGET["worker_error_logs_max"]:
        breaches.append(
            f"worker reply-handler ERROR logs: "
            f"{logs['apexmail-worker-1']['reply_handler_errors']}"
        )
    mail = results.get("mailbot")
    if mail:
        if mail["lost"] > BUDGET["mailbot_lost_max"]:
            breaches.append(f"mailbot lost {mail['lost']} messages")
        if mail["duplicates_by_message_id_header"] > BUDGET["mailbot_dup_max"]:
            breaches.append(
                f"mailbot duplicates by Message-ID header "
                f"{mail['duplicates_by_message_id_header']}"
            )
        if mail["processed"] < mail["sent"]:
            breaches.append(f"mailbot undrained {mail['sent'] - mail['processed']}")
        if mail["drain_latency"]["max_ms"] is None or mail["drain_latency"]["max_ms"] > BUDGET["mailbot_drain_ms_max"]:
            breaches.append(f"mailbot drain max {mail['drain_latency']['max_ms']} ms")
        if mail["smtp_accept_latency"]["p95_ms"] is None or mail["smtp_accept_latency"]["p95_ms"] > BUDGET["mailbot_accept_ms_max"]:
            breaches.append(f"mailbot accept p95 {mail['smtp_accept_latency']['p95_ms']} ms")
    lane = results.get("first_response_lane")
    if lane:
        claim_p95 = lane["priority_claim_latency"]["p95_ms"]
        if claim_p95 is None or claim_p95 > BUDGET["lane_priority_claim_ms_max"]:
            breaches.append(f"first-response claim p95 {claim_p95} ms")
        if not lane["priority_claimed_in_first_batch"]:
            breaches.append("first-response lane did not claim before the backlog")
        sent_p95 = lane["priority_sent_latency"]["p95_ms"]
        if sent_p95 is None or sent_p95 > BUDGET["lane_priority_sent_ms_max"]:
            breaches.append(f"first-response sent p95 {sent_p95} ms")
    return breaches


# ── main ────────────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--state", default=DEFAULT_STATE)
    parser.add_argument("--report", default=DEFAULT_REPORT)
    parser.add_argument("--pg-dsn", default=os.environ.get("PERF_PG_DSN", DEFAULT_PG_DSN))
    parser.add_argument("--fresh", action="store_true", default=False)
    parser.add_argument("--chat-only", action="store_true")
    parser.add_argument("--mailbot-only", action="store_true")
    parser.add_argument("--duration", type=float, default=100.0)
    parser.add_argument("--cadence", type=float, default=10.0)
    args = parser.parse_args()

    log = lambda message: print(f"[perf {time.strftime('%H:%M:%S')}] {message}", flush=True)
    client = Client(args.base, args.host)
    db = Db(args.pg_dsn)
    dog = load_dogfood()
    state_path = Path(args.state)

    if not client.wait_ready(timeout_s=600):
        raise SystemExit("api-server never became ready")
    restarts_before = {
        name: container_restarts(name)
        for name in ["apexmail-api-server-1", "apexmail-worker-1", "apexmail-mta-1"]
    }

    state = {"run": uuid.uuid4().hex[:6], "tenants": [], "fixtures": [], "users": []}
    if not args.fresh and state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except Exception:
            pass
    state.setdefault("fixtures", [])
    state.setdefault("users", [])

    def save_state():
        try:
            state_path.write_text(json.dumps(state, indent=2))
        except OSError:
            pass

    provisioner = Provisioner(client, db, dog, state_path, log)

    # Tenants — resumable: a run interrupted by the shared public limiter
    # keeps everything already provisioned and continues where it stopped.
    if len(state["tenants"]) < 3:
        log("provisioning tenants through the product (signup -> verify -> login -> MFA)")
    while len(state["tenants"]) < 3:
        index = len(state["tenants"])
        tenant = provisioner.provision_owner(f"perf-t{index}")
        state["tenants"].append(tenant)
        save_state()
        log(f"  tenant {index}: {tenant['email']} ({tenant['tenant_id']}) key ok")

    # A dedicated bucket per tenant for the burst lanes (session/turn storm
    # and the rate-limit isolation probe): minting is an authenticated call,
    # so it does not touch the shared public limiter.
    for tenant in state["tenants"]:
        if not tenant.get("storm_key"):
            tenant["storm_key"] = provisioner.mint_key(
                tenant["session"], tenant["csrf"], "botperf-storm", ["ai:read"]
            )
            save_state()
            log(f"  storm key minted for tenant {tenant['tenant_id']}")

    # Re-login tenant owners whose sessions may have expired between runs.
    for tenant in state["tenants"]:
        status, text, _, _ = client.call(
            "GET", "/v1/auth/me", cookie=tenant["session"],
            csrf=(tenant["csrf"], tenant["session"]),
        )
        if status != 200:
            session, secret, csrf_token = provisioner.login(
                tenant["email"], tenant.get("totp_secret")
            )
            tenant.update({"session": session, "csrf": csrf_token,
                           "totp_secret": secret})
    # Refresh the CSRF handshakes: the provisioned token has its own TTL and
    # an expired one turns every session write into a 403 (the state may be
    # hours old on a repeat run).
    for tenant in state["tenants"]:
        try:
            csrf_token, csrf_cookie = dog.csrf_session(client.base, client.host)
            session_cookie = tenant["session"].split(";")[0]
            tenant["csrf"] = csrf_token
            tenant["session"] = f"{session_cookie}; {csrf_cookie}"
        except SystemExit:
            pass
    save_state()

    # Conversation drivers: each tenant contributes its owner SESSION (a
    # per-user bucket) and its tenant API KEY (a per-tenant bucket); the 16
    # conversations spread 6/5/5 across the tenants, round-robin over the two
    # credentials, so each bucket carries ~3 conversations at the default
    # cadence (<= 20/min). Fixture users are intentionally NOT created here:
    # the compose stack's public limiter is shared with sibling agents and
    # per-IP buckets saturate during fleet provisioning.
    drivers: list[dict] = []
    for index, tenant in enumerate(state["tenants"]):
        creds = [
            {"kind": "owner-session", "email": tenant["email"],
             "tenant_id": tenant["tenant_id"], "user_id": tenant.get("user_id"),
             "session": tenant["session"], "csrf": tenant["csrf"]},
            {"kind": "tenant-key", "email": tenant["email"] + "#key",
             "tenant_id": tenant["tenant_id"], "key": tenant["key"]},
        ]
        for n in range(TENANT_USERS[index]):
            cred = dict(creds[n % len(creds)])
            cred["conversation"] = n
            drivers.append(cred)
    log(f"conversation drivers: {len(drivers)} across "
        f"{len({d['tenant_id'] for d in drivers})} tenants "
        f"({sorted({d['kind'] for d in drivers})})")

    # FIXTURE domains + mailboxes on two tenants (mailbot lane).
    for tenant, tag in ((state["tenants"][0], "a"), (state["tenants"][1], "b")):
        if not tenant.get("mailbox"):
            mailbox = provisioner.fixture_domain_and_mailbox(tenant, tag)
            tenant.update(mailbox)
            state["fixtures"].extend(provisioner.state.get("fixtures", []))
            provisioner.state["fixtures"] = []
            save_state()
            log(f"  mailbox {mailbox['mailbox']} (tenant {tenant['tenant_id']})")
    save_state()


    results: dict = {"run": state["run"], "budgets": BUDGET, "started_at": time.time()}
    results["container_restarts_before"] = restarts_before
    containers = ["apexmail-api-server-1", "apexmail-worker-1", "apexmail-ai-service-1"]
    results["revision"] = revision_fingerprint(
        containers + ["apexmail-mta-1"]
    )
    sampler = Sampler(db, containers, interval=1.0,
                      api_client_ips=container_ips("apexmail-api-server-1"))
    sampler.start()
    logs_started_ms = now_ms()

    if not args.mailbot_only:
        if len(drivers) < 16:
            raise SystemExit(f"only {len(drivers)} conversation drivers built")
        log(f"chat lane: 16 conversations, {args.cadence}s cadence, {args.duration}s")
        chat = ChatRun(client, results, BUDGET)
        chat.run(drivers, conversations=16, duration_s=args.duration,
                 cadence_s=args.cadence, run_id=state["run"])
        results["chat_summary"] = results["chat"]["turn_latency"]
        log(f"chat turns={results['chat']['turns']} "
            f"{results['chat']['turn_latency']} statuses={results['chat']['statuses']}")
        results["cross_tenant"] = chat.cross_tenant_check(drivers[:16])
        log(f"cross-tenant violations: {len(results['cross_tenant']['violations'])} "
            f"{results['cross_tenant']['violations'][:4]}")
        results["sessions_parallel"] = chat.session_parallelism(
            {"key": state["tenants"][0]["storm_key"],
             "email": state["tenants"][0]["email"] + "#storm"},
            state["run"],
        )
        log(f"parallel sessions: {results['sessions_parallel']}")
        results["rate_limit_isolation"] = chat.rate_limit_isolation(
            state["tenants"][0], state["tenants"][1]
        )
        log(f"rate-limit isolation: {results['rate_limit_isolation']}")

    if not args.chat_only:
        log("mailbot lane: 20 simultaneous inbound SMTP messages")
        run_mailbot(client, db, results, state, state["run"], log)

    sampler.stop()
    results["container_restarts_after"] = {
        name: container_restarts(name)
        for name in ["apexmail-api-server-1", "apexmail-worker-1", "apexmail-mta-1"]
    }
    results["sampler"] = {
        "api_pool_peak": sampler.api_pool_peak,
        "api_pool_client_ips": sampler.api_client_ips,
        "pg_activity_peak_total": sampler.pg_peak,
        "pg_activity_samples": len(sampler.pg_samples),
        "memory": sampler.memory_summary(),
    }
    results["logs"] = {}
    for container in containers:
        text = docker_logs_since(container, logs_started_ms)
        counts = count_log_matches(
            text, ['"level":"ERROR"', "panic", "pool timeout",
                   "timed out acquiring"]
        )
        counts["reply_handler_errors"] = sum(
            1 for line in text.splitlines()
            if '"level":"ERROR"' in line and "reply_handler" in line
        )
        counts["mailbot_nonce_errors"] = sum(
            1 for line in text.splitlines()
            if '"level":"ERROR"' in line and state["run"] in line
        )
        results["logs"][container] = counts
    api_text = docker_logs_since("apexmail-api-server-1", logs_started_ms)
    results["logs"]["api-server"] = count_log_matches(
        api_text, ["pool timeout", "panic", "connection pool"]
    )

    breaches = evaluate(results)
    results["breaches"] = breaches
    results["verdict"] = "PASS" if not breaches else "FAIL"
    Path(args.report).write_text(json.dumps(results, indent=2, default=str))

    print(json.dumps({
        "verdict": results["verdict"],
        "breaches": breaches,
        "chat": results.get("chat_summary"),
        "chat_statuses": results.get("chat", {}).get("statuses"),
        "cross_tenant_violations": len(results.get("cross_tenant", {}).get("violations", [])),
        "sessions_parallel": results.get("sessions_parallel"),
        "rate_limit_isolation": results.get("rate_limit_isolation"),
        "pg_pool_peak": results["sampler"]["api_pool_peak"],
        "pg_total_peak": results["sampler"]["pg_activity_peak_total"],
        "memory": results["sampler"]["memory"],
        "mailbot": results.get("mailbot"),
        "first_response_lane": results.get("first_response_lane"),
        "logs": results["logs"],
        "report": args.report,
    }, indent=2))
    log(f"verdict: {results['verdict']} ({len(breaches)} breaches)")
    return 0 if not breaches else 1


if __name__ == "__main__":
    sys.exit(main())
