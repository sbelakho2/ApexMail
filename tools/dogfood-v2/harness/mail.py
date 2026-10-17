"""Mail-plane source abstraction.

Live runs read Mailpit (the stack's real delivery sink). Self-test runs read
the fixture server's in-memory mailbox over its own API, so the whole battery
is exercisable without the compose stack.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request


class MailSource:
    # True when list entries already carry the full body (the fixture does);
    # links() then avoids one detail fetch per matched message (N+1).
    summary_has_body = False

    def __init__(self):
        self._detail_cache: dict[str, dict] = {}

    def _cached(self, mid: str) -> dict | None:
        cache = getattr(self, "_detail_cache", None)
        if cache is None:
            cache = self._detail_cache = {}
        return cache.get(mid)

    def _remember(self, mid: str, detail: dict) -> dict:
        if detail:
            cache = getattr(self, "_detail_cache", None)
            if cache is None:
                cache = self._detail_cache = {}
            cache[mid] = detail
        return detail

    def _forget_details(self) -> None:
        getattr(self, "_detail_cache", {}).clear()

    def messages(self, limit: int = 100) -> list[dict]:
        raise NotImplementedError

    def message(self, mid: str) -> dict:
        raise NotImplementedError

    def delete_all(self) -> None:
        raise NotImplementedError

    def for_recipient(self, recipient: str, subject_contains: str = "") -> list[dict]:
        out = []
        for message in self.messages():
            to = [t.get("Address", "") for t in message.get("To", [])]
            if recipient not in to:
                continue
            subject = message.get("Subject") or ""
            if subject_contains and subject_contains.lower() not in subject.lower():
                continue
            out.append(message)
        return out

    def _body_text(self, message: dict, summary_has_body: bool | None = None) -> str:
        use_summary = self.summary_has_body if summary_has_body is None else summary_has_body
        if use_summary:
            text = message.get("Text") or message.get("HTML") or ""
            if text:
                return text
        body = self.message(message["ID"])
        return body.get("Text") or body.get("HTML") or ""

    def links(self, recipient: str, subject_contains: str = "") -> list[str]:
        links: list[str] = []
        for message in self.for_recipient(recipient, subject_contains):
            text = self._body_text(message)
            links.extend(re.findall(r"https?://[^\s\"'<>]+", text))
        return links

    def wait(self, recipient: str, subject_contains: str = "", tries: int = 15, delay: float = 1.0) -> list[dict]:
        for _ in range(tries):
            found = self.for_recipient(recipient, subject_contains)
            if found:
                return found
            time.sleep(delay)
        return []

    def raw_message(self, mid: str) -> str:
        """Full raw RFC822 bytes (Mailpit `?raw=1`-style); fixture synthesizes."""
        body = self.message(mid)
        return body.get("Raw") or body.get("raw") or body.get("HTML") or body.get("Text") or ""


class MailpitSource(MailSource):
    def __init__(self, url: str = "http://127.0.0.1:8025"):
        super().__init__()
        self.url = url

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.url}{path}", timeout=15) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            return json.loads(response.read().decode())

    def messages(self, limit: int = 100) -> list[dict]:
        try:
            return self._get(f"/api/v1/messages?limit={limit}").get("messages", [])
        except Exception:  # noqa: BLE001
            return []

    def message(self, mid: str) -> dict:
        cached = self._cached(mid)
        if cached is not None:
            return cached
        try:
            detail = self._get(f"/api/v1/message/{mid}")
        except Exception:  # noqa: BLE001
            return {}
        return self._remember(mid, detail)

    def delete_all(self) -> None:
        self._forget_details()
        request = urllib.request.Request(f"{self.url}/api/v1/messages", method="DELETE")
        try:
            urllib.request.urlopen(request, timeout=10) # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
        except Exception:  # noqa: BLE001
            pass

    def raw_message(self, mid: str) -> str:
        try:
            with urllib.request.urlopen(f"{self.url}/api/v1/message/{mid}/raw", timeout=15) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
                return response.read().decode(errors="replace")
        except Exception:  # noqa: BLE001
            return ""


class FixtureMailSource(MailSource):
    """Reads the self-test fixture server's mailbox API."""

    # /__fixture/mailbox returns the stored message objects with HTML/Text/Raw.
    summary_has_body = True

    def __init__(self, base: str):
        super().__init__()
        self.base = base
        self._by_id: dict[str, dict] = {}

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base}{path}", timeout=10) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
            return json.loads(response.read().decode())

    def messages(self, limit: int = 100) -> list[dict]:
        messages = self._get("/__fixture/mailbox").get("messages", [])[-limit:]
        # One pass per fetch: message() lookups become O(1) instead of
        # re-fetching and rescanning the mailbox per id (N+1).
        self._by_id = {message["ID"]: message for message in messages if "ID" in message}
        return messages

    def message(self, mid: str) -> dict:
        cached = self._cached(mid)
        if cached is not None:
            return cached
        if mid not in self._by_id:
            self.messages()
        found = self._by_id.get(mid)
        if found is None:
            return {}
        return self._remember(mid, found)

    def delete_all(self) -> None:
        self._forget_details()
        self._by_id = {}
        request = urllib.request.Request(f"{self.base}/__fixture/mailbox", method="DELETE")
        try:
            urllib.request.urlopen(request, timeout=5) # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
        except Exception:  # noqa: BLE001
            pass
