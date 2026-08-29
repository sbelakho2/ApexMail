import dataclasses
import importlib.util
import pathlib
import sys
import types
import unittest
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


class ApexMailError(Exception):
    pass


class ValidationError(Exception):
    pass


@dataclasses.dataclass
class SendEmailResponse:
    id: str
    status: str


class Email:
    def __init__(self, **kwargs):
        self.data = kwargs


class EmailListResponse:
    def __init__(self, **kwargs):
        self.data = kwargs


class EmailStatus(str):
    pass


apexmail_pkg = types.ModuleType("apexmail")
apexmail_pkg.__path__ = [str(ROOT)]

resources_pkg = types.ModuleType("apexmail.resources")
resources_pkg.__path__ = [str(ROOT / "resources")]

exceptions_mod = types.ModuleType("apexmail.exceptions")
exceptions_mod.ApexMailError = ApexMailError
exceptions_mod.ValidationError = ValidationError

models_mod = types.ModuleType("apexmail.models")
models_mod.Email = Email
models_mod.EmailListResponse = EmailListResponse
models_mod.EmailStatus = EmailStatus
models_mod.SendEmailResponse = SendEmailResponse

sys.modules["apexmail"] = apexmail_pkg
sys.modules["apexmail.resources"] = resources_pkg
sys.modules["apexmail.exceptions"] = exceptions_mod
sys.modules["apexmail.models"] = models_mod

spec = importlib.util.spec_from_file_location(
    "apexmail.resources.emails",
    ROOT / "resources" / "emails.py",
)
emails_module = importlib.util.module_from_spec(spec)
sys.modules["apexmail.resources.emails"] = emails_module
assert spec.loader is not None
spec.loader.exec_module(emails_module)

AsyncEmailsResource = emails_module.AsyncEmailsResource
EmailsResource = emails_module.EmailsResource


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _request(self, method: str, path: str, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if path == "/v1/messages/batch":
            return {"results": [{"id": "msg_batch", "status": "queued"}]}
        return {"id": "msg_single", "status": "queued"}


class FakeAsyncClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def _request(self, method: str, path: str, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if path == "/v1/messages/batch":
            return {"results": [{"id": "msg_batch", "status": "queued"}]}
        return {"id": "msg_single", "status": "queued"}


class EmailsResourceTests(unittest.TestCase):
    def test_send_serializes_datetime_scheduled_at(self) -> None:
        client = FakeClient()
        resource = EmailsResource(client)
        scheduled_at = datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc)

        response = resource.send(
            from_="sender@example.com",
            to="user@example.com",
            subject="Hello",
            html="<p>Hello</p>",
            scheduled_at=scheduled_at,
        )

        self.assertEqual(response.id, "msg_single")
        self.assertEqual(client.calls[0]["json"]["scheduled_at"], scheduled_at.isoformat())

    def test_batch_threads_idempotency_key(self) -> None:
        client = FakeClient()
        resource = EmailsResource(client)

        responses = resource.batch(
            [{"from_": "sender@example.com", "to": "user@example.com", "subject": "Hello", "html": "<p>Hello</p>"}],
            idempotency_key="batch-key-123",
        )

        self.assertEqual(responses[0].id, "msg_batch")
        self.assertEqual(client.calls[0]["idempotency_key"], "batch-key-123")
        self.assertIn("messages", client.calls[0]["json"])
        self.assertNotIn("emails", client.calls[0]["json"])


class AsyncEmailsResourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_send_serializes_datetime_scheduled_at(self) -> None:
        client = FakeAsyncClient()
        resource = AsyncEmailsResource(client)
        scheduled_at = datetime(2026, 4, 27, 12, 0, tzinfo=timezone.utc)

        response = await resource.send(
            from_="sender@example.com",
            to="user@example.com",
            subject="Hello",
            html="<p>Hello</p>",
            scheduled_at=scheduled_at,
        )

        self.assertEqual(response.id, "msg_single")
        self.assertEqual(client.calls[0]["json"]["scheduled_at"], scheduled_at.isoformat())

    async def test_batch_threads_idempotency_key(self) -> None:
        client = FakeAsyncClient()
        resource = AsyncEmailsResource(client)

        responses = await resource.batch(
            [{"from_": "sender@example.com", "to": "user@example.com", "subject": "Hello", "html": "<p>Hello</p>"}],
            idempotency_key="batch-key-123",
        )

        self.assertEqual(responses[0].id, "msg_batch")
        self.assertEqual(client.calls[0]["idempotency_key"], "batch-key-123")
        self.assertIn("messages", client.calls[0]["json"])
        self.assertNotIn("emails", client.calls[0]["json"])