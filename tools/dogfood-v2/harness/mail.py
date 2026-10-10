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

    def links(self, recipient: str, subject_contains: str = "") -> list[str]:
        links: list[str] = []
        for message in self.for_recipient(recipient, subject_contains):
            body = self.message(message["ID"])
            text = body.get("Text") or body.get("HTML") or ""
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
        self.url = url

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.url}{path}", timeout=15) as response:
            return json.loads(response.read().decode())

    def messages(self, limit: int = 100) -> list[dict]:
        try:
            return self._get(f"/api/v1/messages?limit={limit}").get("messages", [])
        except Exception:  # noqa: BLE001
            return []

    def message(self, mid: str) -> dict:
        try:
            return self._get(f"/api/v1/message/{mid}")
        except Exception:  # noqa: BLE001
            return {}

    def delete_all(self) -> None:
        request = urllib.request.Request(f"{self.url}/api/v1/messages", method="DELETE")
        try:
            urllib.request.urlopen(request, timeout=10)
        except Exception:  # noqa: BLE001
            pass

    def raw_message(self, mid: str) -> str:
        try:
            with urllib.request.urlopen(f"{self.url}/api/v1/message/{mid}/raw", timeout=15) as response:
                return response.read().decode(errors="replace")
        except Exception:  # noqa: BLE001
            return ""


class FixtureMailSource(MailSource):
    """Reads the self-test fixture server's mailbox API."""

    def __init__(self, base: str):
        self.base = base

    def _get(self, path: str) -> dict:
        with urllib.request.urlopen(f"{self.base}{path}", timeout=10) as response:
            return json.loads(response.read().decode())

    def messages(self, limit: int = 100) -> list[dict]:
        return self._get("/__fixture/mailbox").get("messages", [])[-limit:]

    def message(self, mid: str) -> dict:
        for message in self.messages():
            if message["ID"] == mid:
                return message
        return {}

    def delete_all(self) -> None:
        request = urllib.request.Request(f"{self.base}/__fixture/mailbox", method="DELETE")
        try:
            urllib.request.urlopen(request, timeout=5)
        except Exception:  # noqa: BLE001
            pass
