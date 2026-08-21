"""Tests for the SDK-B/C/D/E/F/G fixes (idempotency keys, batch parsing,
Retry-After handling, 2xx handling, close() hygiene, streaming size cap).

Follows the same importlib/fake-module pattern as the other test files in
this package so tests run without importing the real httpx transport.
"""

import importlib.util
import json
import pathlib
import sys
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


# ── Fake httpx module (built to satisfy client.py's imports and the
#    _buffer_capped/_handle_response/_retry_delay code paths) ─────────────

class FakeResponse:
    """Quacks like httpx.Response."""

    def __init__(self, status_code, *, headers=None, content=b"", request=None, json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._content = content
        self.request = request
        self._json_data = json_data

    @property
    def content(self):
        return self._content

    @property
    def text(self):
        return self._content.decode("utf-8", errors="replace")

    def json(self):
        if self._json_data is not None:
            return self._json_data
        return json.loads(self.text)


class FakeStream:
    """Quacks like the httpx streaming response yielded by Client.stream."""

    def __init__(self, status_code, chunks, headers=None, request=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.request = request
        self._chunks = list(chunks)

    def iter_bytes(self):
        yield from self._chunks


class FakeTimeoutException(Exception):
    pass


class FakeNetworkError(Exception):
    pass


httpx_fake = types.ModuleType("httpx")
httpx_fake.Response = FakeResponse
httpx_fake.Client = object
httpx_fake.AsyncClient = object
httpx_fake.TimeoutException = FakeTimeoutException
httpx_fake.NetworkError = FakeNetworkError

# Our client-module instance must be loaded against our fake httpx, no
# matter what earlier test files installed.
saved_httpx = sys.modules.get("httpx")
saved_client = sys.modules.get("apexmail.client")
sys.modules["httpx"] = httpx_fake


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


apexmail_pkg = types.ModuleType("apexmail")
apexmail_pkg.__path__ = [str(ROOT)]
resources_pkg = types.ModuleType("apexmail.resources")
resources_pkg.__path__ = [str(ROOT / "resources")]
sys.modules["apexmail"] = apexmail_pkg
sys.modules["apexmail.resources"] = resources_pkg

exceptions_module = _load("apexmail.exceptions", ROOT / "exceptions.py")
models_module = _load("apexmail.models", ROOT / "models.py")
emails_resource = _load("apexmail.resources.emails", ROOT / "resources" / "emails.py")
client_module = _load("apexmail.client", ROOT / "client.py")

# Restore whatever the other test files expect.
if saved_httpx is not None:
    sys.modules["httpx"] = saved_httpx
else:
    del sys.modules["httpx"]
if saved_client is not None:
    sys.modules["apexmail.client"] = saved_client

BaseClient = client_module.BaseClient
ApexMailError = exceptions_module.ApexMailError
SendEmailResponse = models_module.SendEmailResponse
EmailsResource = emails_resource.EmailsResource
_parse_batch_results = emails_resource._parse_batch_results


class FakeRecordingClient:
    def __init__(self):
        self.calls = []

    def _request(self, method, path, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if path == "/v1/messages/batch":
            return {
                "accepted": 1,
                "rejected": 0,
                "results": [{"index": 0, "id": "msg_ok", "status": "queued"}],
            }
        return {"id": "msg_ok", "status": "queued"}


def make_base_client(**kwargs):
    return BaseClient(api_key="am_test_1234567890abcdef", base_url="https://api.apexmail.ee", **kwargs)


# ── SDK-D: batch parsing tolerates rejected items ──────────────────────────

class BatchParsingTests(unittest.TestCase):
    def test_rejected_item_without_id_parses(self):
        data = {
            "accepted": 2,
            "rejected": 1,
            "results": [
                {"index": 0, "id": "m1", "status": "queued"},
                {"index": 1, "id": "m2", "status": "queued"},
                {"index": 2, "status": "rejected", "error": "invalid recipient"},
            ],
        }

        results = _parse_batch_results(data)

        self.assertEqual(3, len(results))
        self.assertEqual("m1", results[0].id)
        self.assertEqual("queued", results[0].status)
        self.assertIsNone(results[2].id)
        self.assertEqual("rejected", results[2].status)
        self.assertEqual("invalid recipient", results[2].error)
        self.assertEqual(2, results[2].index)

    def test_single_send_shape_parses_with_created_at(self):
        response = SendEmailResponse(
            **{"id": "msg_1", "status": "queued", "created_at": "2026-08-21T12:00:00Z"}
        )
        self.assertEqual("msg_1", response.id)
        self.assertEqual("queued", response.status)
        self.assertEqual("2026-08-21T12:00:00Z", response.created_at.isoformat().replace("+00:00", "Z"))


# ── SDK-B: automatic idempotency keys ──────────────────────────────────────

class AutoIdempotencyKeyTests(unittest.TestCase):
    def test_send_generates_key_when_missing(self):
        client = FakeRecordingClient()
        resource = EmailsResource(client)

        resource.send(from_="a@example.com", to="b@example.com", subject="Hi", html="<p>x</p>")

        key = client.calls[0]["idempotency_key"]
        self.assertTrue(key)

    def test_send_generates_different_keys_per_logical_send(self):
        client = FakeRecordingClient()
        resource = EmailsResource(client)

        resource.send(from_="a@example.com", to="b@example.com", subject="Hi", html="<p>x</p>")
        resource.send(from_="a@example.com", to="b@example.com", subject="Hi 2", html="<p>x</p>")

        self.assertNotEqual(client.calls[0]["idempotency_key"], client.calls[1]["idempotency_key"])

    def test_send_honors_caller_key(self):
        client = FakeRecordingClient()
        resource = EmailsResource(client)

        resource.send(
            from_="a@example.com", to="b@example.com", subject="Hi",
            html="<p>x</p>", idempotency_key="caller-key",
        )

        self.assertEqual("caller-key", client.calls[0]["idempotency_key"])

    def test_batch_generates_and_forwards_key(self):
        client = FakeRecordingClient()
        resource = EmailsResource(client)

        resource.batch([{"from": "a@example.com", "to": "b@example.com", "subject": "Hi", "html": "<p>x</p>"}])
        first_key = client.calls[0]["idempotency_key"]
        self.assertTrue(first_key)

        resource.batch(
            [{"from": "a@example.com", "to": "b@example.com", "subject": "Hi", "html": "<p>x</p>"}],
            idempotency_key="batch-caller-key",
        )
        self.assertEqual("batch-caller-key", client.calls[1]["idempotency_key"])


# ── SDK-F: Retry-After honored in full, capped at 120s ────────────────────

class RetryDelayTests(unittest.TestCase):
    def setUp(self):
        self.client = make_base_client(max_retries=3)

    def test_retry_after_60_honored(self):
        response = FakeResponse(429, headers={"Retry-After": "60"})
        self.assertEqual(60.0, self.client._retry_delay(response, 0))

    def test_retry_after_300_capped_at_120(self):
        response = FakeResponse(429, headers={"Retry-After": "300"})
        self.assertEqual(120.0, self.client._retry_delay(response, 0))

    def test_retry_after_beats_backoff(self):
        response = FakeResponse(429, headers={"Retry-After": "3"})
        self.assertEqual(3.0, self.client._retry_delay(response, 2))

    def test_no_retry_after_uses_quadratic_backoff(self):
        response = FakeResponse(503)
        self.assertEqual(2.0, self.client._retry_delay(response, 2))

    def test_non_retryable_status_returns_none(self):
        response = FakeResponse(400)
        self.assertIsNone(self.client._retry_delay(response, 0))

    def test_final_attempt_returns_none(self):
        response = FakeResponse(429, headers={"Retry-After": "60"})
        self.assertIsNone(self.client._retry_delay(response, 3))


# ── SDK-G L7: every 2xx status is a success ────────────────────────────────

class TwoXxHandlingTests(unittest.TestCase):
    def setUp(self):
        self.client = make_base_client()

    def test_202_is_success(self):
        response = FakeResponse(202, json_data={"id": "m1", "status": "queued"})
        self.assertEqual({"id": "m1", "status": "queued"}, self.client._handle_response(response))

    def test_204_returns_empty_dict(self):
        self.assertEqual({}, self.client._handle_response(FakeResponse(204)))

    def test_envelope_unwrapped_on_2xx(self):
        response = FakeResponse(200, json_data={"data": {"id": "m1"}, "meta": {"total": 1}})
        self.assertEqual({"id": "m1"}, self.client._handle_response(response))


# ── SDK-G L8: close() clears base headers too ─────────────────────────────

class CloseHygieneTests(unittest.TestCase):
    def test_close_clears_api_key_and_headers(self):
        client = make_base_client()
        self.assertIn("X-API-Key", client._base_headers)

        client.close()

        self.assertEqual("", client.api_key)
        self.assertEqual({}, client._base_headers)


# ── SDK-G: streaming response-size cap ────────────────────────────────────

class StreamingCapTests(unittest.TestCase):
    def test_buffer_capped_returns_body_when_under_limit(self):
        client = make_base_client(max_response_bytes=100)
        stream = FakeStream(200, [b'{"id": "m1"}'], headers={"Content-Type": "application/json"})

        response = client._buffer_capped(stream)

        self.assertEqual(200, response.status_code)
        self.assertEqual({"id": "m1"}, response.json())

    def test_buffer_capped_aborts_as_soon_as_limit_exceeded(self):
        client = make_base_client(max_response_bytes=100)
        stream = FakeStream(200, [b"x" * 60, b"x" * 60])

        with self.assertRaises(ApexMailError) as ctx:
            client._buffer_capped(stream)

        self.assertEqual("RESPONSE_TOO_LARGE", ctx.exception.code)


if __name__ == "__main__":
    unittest.main()
