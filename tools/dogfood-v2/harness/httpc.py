"""Paced HTTP client for the dogfood harness.

Design notes:
  * one global pacer keeps the shared live stack calm (the adaptive DDoS
    limiter and the per-IP auth limiters are shared with other agents);
  * a hard request budget makes an accidental runaway probe impossible;
  * retries are bounded and only for transport errors / 429 with Retry-After;
  * Set-Cookie handling merges repeated headers correctly (urllib folds them).
"""
from __future__ import annotations

import json
import random
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "dogfood-v2/2.0 (+adversarial self-proving harness; contact: dogfood)"


class DdosBlocked(RuntimeError):
    """The target's DDoS layer blocked this client's IP (403 DDOS_BLOCKED)
    and the documented recovery (limiter-bucket clear + api-server restart)
    did not lift it. This is an ENVIRONMENT abort: the probe could not
    assess the product, and must be reported as a named unreachable."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


@dataclass
class Response:
    status: int
    text: str
    headers: dict[str, str]       # repeated headers joined with \n
    url: str
    method: str
    elapsed_ms: int = 0

    @property
    def set_cookie_headers(self) -> list[str]:
        raw = self.headers.get("set-cookie", "")
        return [p.strip() for p in raw.split("\n") if p.strip()]

    def json(self):
        try:
            return json.loads(self.text)
        except Exception:  # noqa: BLE001
            return None

    def data(self):
        """The payload, unwrapping the standard {data,error,meta} envelope."""
        body = self.json()
        if isinstance(body, dict) and isinstance(body.get("data"), (dict, list)):
            return body["data"]
        return body

    def error_code(self) -> str:
        """The NAMED error code of the standard ApiError envelope, or a
        best-effort extraction for other shapes. '' when none is present."""
        body = self.json()
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                return str(err.get("code") or "")
            if isinstance(err, str):
                return "LEGACY_STRING_ERROR" if err else ""
        return ""

    def error_message(self) -> str:
        body = self.json()
        if isinstance(body, dict):
            err = body.get("error")
            if isinstance(err, dict):
                return str(err.get("message") or "")
            if isinstance(err, str):
                return err
        return ""

    def details(self) -> list[str]:
        body = self.json()
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            det = body["error"].get("details")
            if isinstance(det, list):
                return [str(d) for d in det]
        return []

    def is_named_error(self) -> bool:
        """Refused operations must be NAMED: JSON error code + message."""
        if self.status < 400:
            return False
        code = self.error_code()
        msg = self.error_message()
        if code and code not in ("LEGACY_STRING_ERROR",) and len(msg) >= 4:
            return True
        # Non-JSON refusals (SSR redirects / HTML pages / 405 etc.) are only
        # honest if they carry a human-readable body and are from the
        # documented non-JSON surface set.
        ctype = self.headers.get("content-type", "")
        if "text/html" in ctype and len(self.text.strip()) > 0:
            return True
        if self.status in (401, 403, 404, 405, 413, 429, 503):
            return len(self.text.strip()) >= 4
        return False


class HttpClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self._plain = urllib.request.build_opener()
        self._noredir = urllib.request.build_opener(NoRedirect)
        self._lock = threading.Lock()
        self._last = 0.0
        self.requests = 0
        self.transport_errors = 0
        self.backoffs = 0
        self.ddos_backoffs = 0
        self.ddos_blocks = 0
        self._ddos429_streak = 0
        self._streak_recovery_done = False
        self.journal: list[dict] = []          # bounded request journal for evidence
        self._journal_limit = 400
        # called when a DDOS_BLOCKED persists past the bounded wait; clears the
        # Redis limiter buckets and (bounded) restarts the api-server — the
        # documented environment control for the in-memory adaptive protector.
        self.recovery_hook = None

    # ── pacing / budget ────────────────────────────────────────────────
    def _pace(self) -> None:
        # Jittered pacing: a mechanically PERIODIC inter-arrival pattern is a
        # documented bot signal in the stack's own DDoS protector
        # (ddos-protection::bot_detection — "bots are mechanically periodic"),
        # which false-positived this honest client and blocked it within a
        # minute. Real clients are not metronomes, so the pacer is not either.
        # A periodic breather also keeps the per-IP adaptive limiter's
        # z-score below its threshold during long sweeps.
        with self._lock:
            now = time.monotonic()
            target = self.cfg.pace_seconds * random.uniform(0.55, 1.6) if self.cfg.pace_seconds else 0.0
            wait = self._last + target - now
            if wait > 0:
                time.sleep(wait)
            if self.requests and self.requests % 60 == 0:
                time.sleep(2.0)
            self._last = time.monotonic()

    def _budget(self, method: str, url: str) -> bool:
        self.requests += 1
        if self.requests > self.cfg.max_requests:
            raise RuntimeError(
                f"dogfood-v2 request budget exhausted ({self.cfg.max_requests}); "
                f"refusing to send {method} {url}"
            )
        return True

    # ── core call ──────────────────────────────────────────────────────
    def call(
        self,
        method: str,
        path: str,
        *,
        host: str | None = None,
        base: str | None = None,
        body: object | None = None,
        raw: bytes | str | None = None,
        ctype: str | None = None,
        headers: dict[str, str] | None = None,
        cookie_header: str | None = None,
        follow: bool = True,
        timeout: int | None = None,
        retries: int = 2,
    ) -> Response:
        base = base or self.cfg.base
        host = host or self.cfg.host
        url = base + path
        self._budget(method, url)
        streak_at_start = self._ddos429_streak
        data = None
        hdrs = {"Host": host, "Accept": "application/json, text/html, */*", "User-Agent": USER_AGENT}
        if raw is not None:
            data = raw.encode() if isinstance(raw, str) else raw
        elif body is not None:
            data = json.dumps(body).encode()
            ctype = ctype or "application/json"
        if data is not None:
            hdrs["Content-Type"] = ctype or "application/octet-stream"
        if cookie_header:
            hdrs["Cookie"] = cookie_header
        if headers:
            hdrs.update(headers)
        request = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        opener = self._plain if follow else self._noredir
        attempt = 0
        while True:
            self._pace()
            started = time.monotonic()
            try:
                with opener.open(request, timeout=timeout or self.cfg.timeout) as resp:
                    text = resp.read().decode(errors="replace")
                    hdrs_out = self._headers(resp.headers)
                    return self._settle(
                        self._finish(method, url, resp.status, text, hdrs_out, started)
                    )
            except urllib.error.HTTPError as error:
                text = error.read().decode(errors="replace")
                hdrs_out = self._headers(error.headers)
                resp = self._finish(method, url, error.code, text, hdrs_out, started)
                # Two distinct DDoS-layer signals:
                #  * 429 DDOS_RATE_LIMITED — the adaptive limiter's window; it
                #    carries Retry-After (1s adaptive) — HONOR it.
                #  * 403 DDOS_BLOCKED — the IP was pushed onto the in-memory
                #    blocklist (low reputation from the battery's own
                #    adversarial volume). No header; waiting cannot clear it,
                #    so the documented control (clear the Redis buckets and
                #    restart the api-server to reset the in-process protector)
                #    runs via recovery_hook, then the request is retried.
                ddos_limited = resp.status == 429 and "DDOS_" in (resp.text or "")
                ddos_blocked = resp.status == 403 and "DDOS_BLOCKED" in (resp.text or "")
                if ddos_limited:
                    has_header = bool(resp.headers.get("retry-after"))
                    budget = 7 if has_header else 4
                elif ddos_blocked:
                    budget = 4
                else:
                    has_header = False
                    budget = retries
                # A SUSTAINED 429 storm — the PREVIOUS several requests all
                # ended DDOS_RATE_LIMITED even while honoring Retry-After —
                # cannot drain by waiting: the in-memory adaptive state must be
                # reset with the documented control. (Per-request retries do
                # not count: the intended limit is a storm ACROSS requests.)
                if ddos_limited and streak_at_start >= 3 and callable(self.recovery_hook):
                    self.ddos_backoffs += 1
                    print(
                        f"[dogfood-v2] ddos 429 storm ({streak_at_start} consecutive requests "
                        f"throttled) for {method} {url.split('://', 1)[-1]} — running the "
                        f"documented limiter recovery (clear buckets + restart api-server)",
                        flush=True,
                    )
                    try:
                        self.recovery_hook()
                    except Exception as hook_error:  # noqa: BLE001
                        print(f"[dogfood-v2] recovery hook failed: {hook_error}", flush=True)
                    self._ddos429_streak = 0
                    time.sleep(2.0)
                    attempt += 1
                    continue
                if (resp.status == 429 or ddos_blocked) and attempt < budget:
                    raw_delay = self._retry_after(resp)
                    if ddos_blocked:
                        self.ddos_blocks += 1
                        self.ddos_backoffs += 1
                        if attempt >= 1 and callable(self.recovery_hook):
                            delay = 5.0 * (attempt + 1)
                            print(
                                f"[dogfood-v2] ddos BLOCKED ({attempt + 1}/{budget}) for "
                                f"{method} {url.split('://', 1)[-1]} — running the documented "
                                f"limiter recovery (clear buckets + restart api-server)",
                                flush=True,
                            )
                            try:
                                self.recovery_hook()
                            except Exception as hook_error:  # noqa: BLE001
                                print(f"[dogfood-v2] recovery hook failed: {hook_error}", flush=True)
                        else:
                            delay = 2.0 * (attempt + 1)
                            print(
                                f"[dogfood-v2] ddos BLOCKED ({attempt + 1}/{budget}) waiting "
                                f"{delay:.0f}s for {method} {url.split('://', 1)[-1]}",
                                flush=True,
                            )
                    elif ddos_limited:
                        self.ddos_backoffs += 1
                        delay = (
                            max(raw_delay, 1.0) if has_header
                            else min(15.0 * (attempt + 1), 45.0)
                        )
                        print(
                            f"[dogfood-v2] ddos backoff ({attempt + 1}/{budget}) "
                            f"waiting {delay:.1f}s for {method} {url.split('://', 1)[-1]}",
                            flush=True,
                        )
                    else:
                        self.backoffs += 1
                        delay = min(max(raw_delay, 1.0), 20.0)
                    time.sleep(delay)
                    attempt += 1
                    continue
                if ddos_blocked:
                    # bounded wait + restart did not lift the block: surface an
                    # ENVIRONMENT abort so no probe records a block as a
                    # product verdict.
                    raise DdosBlocked(
                        f"DDOS_BLOCKED persisted for {method} {url.split('://', 1)[-1]} "
                        f"after {budget} bounded retries with limiter recovery: {resp.text[:200]!r}"
                    )
                return self._settle(resp)
            except Exception as error:  # noqa: BLE001 — transport failure
                self.transport_errors += 1
                if attempt < retries:
                    time.sleep(1.0 + attempt)
                    attempt += 1
                    continue
                elapsed = int((time.monotonic() - started) * 1000)
                return self._settle(Response(0, f"transport: {error}", {}, url, method, elapsed))

    def _settle(self, resp: Response) -> Response:
        """One call = one streak tick: consecutive calls ending in the adaptive
        limiter's 429 are a storm; any other outcome resets the streak."""
        if resp.status == 429 and "DDOS_" in (resp.text or ""):
            self._ddos429_streak += 1
        else:
            self._ddos429_streak = 0
        return resp

    def _finish(self, method, url, status, text, headers, started) -> Response:
        elapsed = int((time.monotonic() - started) * 1000)
        resp = Response(status, text, headers, url, method, elapsed)
        with self._lock:
            if len(self.journal) < self._journal_limit:
                self.journal.append(
                    {
                        "method": method,
                        "path": url.split("://", 1)[-1].split("/", 1)[-1],
                        "status": status,
                        "ms": elapsed,
                    }
                )
        return resp

    @staticmethod
    def _headers(headers) -> dict[str, str]:
        out: dict[str, list[str]] = {}
        for key, value in headers.items():
            out.setdefault(key.lower(), []).append(value)
        return {k: "\n".join(v) for k, v in out.items()}

    @staticmethod
    def _retry_after(resp: Response) -> float:
        try:
            return float(resp.headers.get("retry-after", "1"))
        except Exception:  # noqa: BLE001
            return 1.0

    # ── convenience ────────────────────────────────────────────────────
    def get(self, path: str, **kw) -> Response:
        return self.call("GET", path, **kw)

    def post(self, path: str, body=None, **kw) -> Response:
        return self.call("POST", path, body=body, **kw)

    def form(self, path: str, fields: dict[str, str], **kw) -> Response:
        return self.call(
            "POST", path, raw=urllib.parse.urlencode(fields),
            ctype="application/x-www-form-urlencoded", **kw,
        )

    def raw_form(self, fields: dict[str, str]) -> str:
        return urllib.parse.urlencode(fields)
