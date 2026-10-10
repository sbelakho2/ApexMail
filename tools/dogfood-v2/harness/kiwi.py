"""KiwiCaptcha challenge minting + legitimate proof-of-work solving.

The live dev stack runs KiwiCaptcha ENABLED with the real server-side
verification (docs/security/kiwicaptcha-login.md). Every JSON auth probe must
therefore mint + solve a challenge for the target scope and submit the
solution as `kiwi__token`. This module performs exactly the work the browser
widget performs (SHA-256 grind), never a bypass.

Contract (routes/kiwicaptcha.rs + packages/kiwicaptcha):
  POST /api/kcaptcha/challenge {"scope": "..."} ->
      {nonce, challenge, salt, algorithm, targetBits, ttlSecs, minDurationMs, prefix}
  solve: find counter c with leading_zero_bits(sha256(prefix || c || salt)) >= targetBits
  token = base64_std(nonce || "." || counter || "." || duration_ms || "." || telemetry_json)
  submitted as body field kiwi__token (form: kiwi__token).
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time

CHALLENGE_PATH = "/api/kcaptcha/challenge"
VALID_SCOPES = (
    "login", "signup", "forgot-password", "reset-password",
    "cp-login", "resend-verification", "mfa-verify",
)


class KiwiError(RuntimeError):
    pass


def _leading_zero_bits(digest: bytes) -> int:
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
        else:
            count += 8 - byte.bit_length()
            break
    return count


class KiwiSolver:
    """Mints and solves challenges for one base URL. Thread-safe."""

    # The server enforces 30 issuances / 15 min per IP (Redis-backed:
    # apexmail:kiwi_challenge_rate:hmac:<ip>). A full battery mints far more;
    # the documented control is clearing the bucket, which is done between
    # probes AND proactively every RESET_EVERY mints so the harness never
    # trips the issuance bound it is not currently proving.
    RESET_EVERY = 18

    def __init__(self, http, base: str = "", host: str = ""):
        self.http = http
        self.base = base
        self.host = host
        self._lock = threading.Lock()
        self._last_mint: dict[str, float] = {}
        self._mints_since_reset = 0
        self.minted = 0
        self.solved = 0
        self.solve_ms_total = 0
        self.reset_hook = None      # optional callable clearing limiter buckets

    def _paced_reset(self) -> None:
        if self.reset_hook is None:
            return
        self._mints_since_reset += 1
        if self._mints_since_reset >= self.RESET_EVERY:
            self._mints_since_reset = 0
            try:
                self.reset_hook()
            except Exception:  # noqa: BLE001 — recovery is best-effort
                pass

    def challenge(self, scope: str) -> dict:
        if scope not in VALID_SCOPES:
            raise KiwiError(f"invalid captcha scope {scope!r}")
        with self._lock:
            # The server caches one challenge per (IP, scope) for ~1s; after
            # a token is consumed the cached record is dead, so wait out the
            # cache window before minting the next one for the same scope.
            last = self._last_mint.get(scope, 0.0)
            wait = last + 1.05 - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last_mint[scope] = time.monotonic()
        resp = self.http.post(
            CHALLENGE_PATH, {"scope": scope},
            base=self.base or None, host=self.host or None,
        )
        attempts = 0
        while resp.status == 429 and self.reset_hook is not None and attempts < 2:
            # Documented environment control: clear the limiter buckets, wait
            # out the window, retry (bounded) instead of failing provisioning.
            attempts += 1
            self.reset_hook()
            time.sleep(2.0 if attempts == 1 else 5.0)
            resp = self.http.post(
                CHALLENGE_PATH, {"scope": scope},
                base=self.base or None, host=self.host or None,
            )
        if resp.status == 429:
            raise KiwiError(
                f"challenge issuance rate-limited (429) for scope {scope} :: {resp.text[:200]}"
            )
        if resp.status >= 500:
            # one bounded retry for a transient issuance failure
            time.sleep(1.0)
            resp = self.http.post(
                CHALLENGE_PATH, {"scope": scope},
                base=self.base or None, host=self.host or None,
            )
        if resp.status != 200:
            raise KiwiError(f"challenge issuance failed: {resp.status} {resp.text[:200]}")
        body = resp.json() or {}
        if isinstance(body.get("data"), dict):
            body = body["data"]
        if not body.get("nonce") or body.get("algorithm") != "sha256":
            raise KiwiError(f"unexpected challenge shape: {resp.text[:200]}")
        self.minted += 1
        self._paced_reset()
        return body

    def solve(self, challenge: dict) -> str:
        prefix = challenge["prefix"]
        salt = base64.b64decode(challenge["salt"])
        target = int(challenge.get("targetBits") or 20)
        min_duration = int(challenge.get("minDurationMs") or 0)
        started = time.monotonic()
        counter = 0
        pre = prefix.encode()
        while counter < 20_000_000:
            digest = hashlib.sha256(pre + str(counter).encode() + salt).digest()
            if _leading_zero_bits(digest) >= target:
                break
            counter += 1
        else:
            raise KiwiError("no counter within the solver cap; re-mint the challenge")
        elapsed_ms = int((time.monotonic() - started) * 1000)
        duration = max(elapsed_ms, min_duration + 2)
        self.solved += 1
        self.solve_ms_total += elapsed_ms
        plain = f"{challenge['nonce']}.{counter}.{duration}.{{}}"
        return base64.b64encode(plain.encode()).decode()

    def token(self, scope: str) -> str:
        """Mint + solve in one call; returns the base64 solution token."""
        return self.solve(self.challenge(scope))
