"""Live-contract regression tests for the 2026-10-06 dogfood SDK fixes.

Covered (all verified against the running api-server, see
docs/audit/dogfood-2026-10-06/fix-sdks.md):

* `Idempotency-Key` (NOT `X-Idempotency-Key`) is the header the server reads
  (middleware/idempotency.rs; docs/api/endpoints/messages.md).
* 422 maps to ValidationError (docs/api/errors.md).
* Paginated /v1/messages list surfaces meta.nextCursor / meta.hasMore.
* `cursor` is rejected client-side on the list endpoints whose server query
  structs use deny_unknown_fields without a cursor (domains, templates,
  suppressions, events, api-keys) instead of emitting a server 400.
* Path params on /v1/auth/api-keys/:id and /v1/suppressions/check/:email are
  URL-escaped (no URL injection).
* The webhook event vocabulary includes the campaign.* events.

Follows the importlib/fake-module pattern used by the other tests in this
package so no real network transport is constructed.
"""

import importlib.util
import json
import pathlib
import sys
import types
import unittest
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


class FakeResponse:
    def __init__(self, status_code, *, headers=None, json_data=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data
        self._content = json.dumps(json_data).encode() if json_data is not None else b""

    @property
    def content(self):
        return self._content

    @property
    def text(self):
        return self._content.decode("utf-8", errors="replace")

    def json(self):
        return json.loads(self._content.decode("utf-8"))


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
client_module = _load("apexmail.client", ROOT / "client.py")

api_keys_module = _load("apexmail.resources.api_keys", ROOT / "resources" / "api_keys.py")
domains_module = _load("apexmail.resources.domains", ROOT / "resources" / "domains.py")
emails_module = _load("apexmail.resources.emails", ROOT / "resources" / "emails.py")
events_module = _load("apexmail.resources.events", ROOT / "resources" / "events.py")
suppressions_module = _load("apexmail.resources.suppressions", ROOT / "resources" / "suppressions.py")
templates_module = _load("apexmail.resources.templates", ROOT / "resources" / "templates.py")
webhooks_module = _load("apexmail.resources.webhooks", ROOT / "resources" / "webhooks.py")

if saved_httpx is not None:
    sys.modules["httpx"] = saved_httpx
else:
    del sys.modules["httpx"]
if saved_client is not None:
    sys.modules["apexmail.client"] = saved_client

BaseClient = client_module.BaseClient
ValidationError = exceptions_module.ValidationError


class FakeRecordingClient:
    """Records every _request call and returns scripted payloads."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def _request(self, method, path, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        for prefix, payload in self.responses.items():
            if path.startswith(prefix):
                return payload
        return {}


def make_base_client():
    return BaseClient(api_key="am_test_1234567890abcdef", base_url="https://api.apexmail.ee")


# ── Idempotency header name ────────────────────────────────────────────────

class IdempotencyHeaderTests(unittest.TestCase):
    def test_uses_the_server_read_header_name(self):
        client = make_base_client()
        headers = client._get_headers("idem-key-1")
        self.assertEqual({"Idempotency-Key": "idem-key-1"}, headers)
        self.assertNotIn("X-Idempotency-Key", headers)

    def test_control_characters_still_stripped(self):
        client = make_base_client()
        headers = client._get_headers("key\r\ninjected")
        self.assertEqual({"Idempotency-Key": "keyinjected"}, headers)

    def test_auto_key_for_post_body_uses_server_header(self):
        client = make_base_client()
        key = client_module.auto_idempotency_key("POST", {"a": 1})
        headers = client._get_headers(key)
        self.assertIn("Idempotency-Key", headers)
        self.assertTrue(headers["Idempotency-Key"])


# ── Error typing ───────────────────────────────────────────────────────────

class ErrorTypingTests(unittest.TestCase):
    def test_422_is_validation_error(self):
        client = make_base_client()
        with self.assertRaises(ValidationError) as ctx:
            client._handle_response(FakeResponse(
                422,
                json_data={"error": {"code": "VALIDATION_ERROR", "message": "missing field"}},
            ))
        self.assertEqual("VALIDATION_ERROR", ctx.exception.code)


# ── Pagination meta ────────────────────────────────────────────────────────

class ListMetaTests(unittest.TestCase):
    def test_email_list_surfaces_next_cursor_and_has_more(self):
        client = FakeRecordingClient(responses={
            "/v1/messages": (
                [{"id": "m1", "status": "queued", "created_at": "2026-08-21T12:00:00Z",
                  "from": "a@example.com", "to": ["b@example.com"], "subject": "Hi",
                  "tags": None, "metadata": None, "scheduled_at": None, "sent_at": None}],
                {"hasMore": True, "nextCursor": "cur_abc123"},
            ),
        })
        resource = emails_module.EmailsResource(client)
        result = resource.list(limit=1)
        self.assertEqual("cur_abc123", result.cursor)
        self.assertTrue(result.has_more)
        self.assertEqual(1, len(result.emails))
        # the call asked for the meta-aware return
        self.assertTrue(client.calls[0].get("with_meta"))

    def test_email_list_last_page_has_no_cursor(self):
        client = FakeRecordingClient(responses={
            "/v1/messages": ([], {"hasMore": False, "nextCursor": None}),
        })
        resource = emails_module.EmailsResource(client)
        result = resource.list()
        self.assertIsNone(result.cursor)
        self.assertFalse(result.has_more)


# ── Unsupported cursor params ──────────────────────────────────────────────

class UnsupportedCursorTests(unittest.TestCase):
    def _assert_rejected(self, callable_):
        with self.assertRaises(ValidationError) as ctx:
            callable_()
        self.assertEqual("UNSUPPORTED_PAGINATION", ctx.exception.code)

    def test_domains_list_rejects_cursor(self):
        resource = domains_module.DomainsResource(FakeRecordingClient())
        self._assert_rejected(lambda: resource.list(cursor="abc"))

    def test_templates_list_rejects_cursor(self):
        resource = templates_module.TemplatesResource(FakeRecordingClient())
        self._assert_rejected(lambda: resource.list(cursor="abc"))

    def test_suppressions_list_rejects_cursor(self):
        resource = suppressions_module.SuppressionsResource(FakeRecordingClient())
        self._assert_rejected(lambda: resource.list(cursor="abc"))

    def test_events_list_rejects_cursor(self):
        resource = events_module.EventsResource(FakeRecordingClient())
        self._assert_rejected(lambda: resource.list(cursor="abc"))

    def test_api_keys_list_rejects_cursor(self):
        resource = api_keys_module.ApiKeysResource(FakeRecordingClient())
        self._assert_rejected(lambda: resource.list(cursor="abc"))

    def test_supported_lists_do_not_send_cursor(self):
        client = FakeRecordingClient()
        resource = templates_module.TemplatesResource(client)
        resource.list(limit=10)
        self.assertNotIn("cursor", client.calls[-1].get("params") or {})


# ── URL escaping of path params ────────────────────────────────────────────

class PathEscapingTests(unittest.TestCase):
    def test_api_key_revoke_escapes_id(self):
        client = FakeRecordingClient()
        resource = api_keys_module.ApiKeysResource(client)
        resource.revoke("../../tenants/other?x=1#frag")
        self.assertEqual(
            "/v1/auth/api-keys/..%2F..%2Ftenants%2Fother%3Fx%3D1%23frag",
            client.calls[0]["path"],
        )

    def test_suppression_check_escapes_email(self):
        client = FakeRecordingClient(responses={
            "/v1/suppressions/check/": {"email": "a@example.com", "suppressed": False},
        })
        resource = suppressions_module.SuppressionsResource(client)
        resource.check("a+b/../c@example.com?x=1")
        self.assertEqual(
            "/v1/suppressions/check/a%2Bb%2F..%2Fc%40example.com%3Fx%3D1",
            client.calls[0]["path"],
        )


# ── Webhook vocabulary ─────────────────────────────────────────────────────

class WebhookVocabularyTests(unittest.TestCase):
    def test_campaign_events_are_known(self):
        for event in ("campaign.started", "campaign.ab_winner_selected", "campaign.completed"):
            self.assertIn(event, webhooks_module.KNOWN_WEBHOOK_EVENTS)

    def test_campaign_event_create_does_not_warn(self):
        client = FakeRecordingClient(responses={
            "/v1/webhooks": {"id": "wh_1", "url": "https://example.com/hook",
                             "events": ["campaign.started"], "status": "active",
                             "created_at": "2026-08-21T12:00:00Z",
                             "updated_at": "2026-08-21T12:00:00Z"},
        })
        resource = webhooks_module.WebhooksResource(client)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            resource.create(url="https://example.com/hook", events=["campaign.started"])
        self.assertEqual([], [w for w in caught if "Unknown webhook event" in str(w.message)])


if __name__ == "__main__":
    unittest.main()
