"""Payload contract tests.

The wire bodies this SDK emits must match the server DTOs in
api-server/src/routes/*.rs exactly — most use serde(deny_unknown_fields),
so any extra key is a 422:

* messages.rs    SendMessageRequest
* webhooks.rs    CreateWebhookRequest / UpdateWebhookRequest
* templates.rs   CreateTemplateRequest
* suppressions.rs CreateSuppressionRequest
* domains.rs     CreateDomainRequest
* auth.rs        CreateApiKeyRequest
"""

from __future__ import annotations

import importlib
import pathlib
import sys
import unittest
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"

# Other test files stub `apexmail.*` entries in sys.modules for isolated
# module loading; these contract tests exercise the REAL package (with the
# real pydantic models), so purge any stubs before importing.
for _name in [m for m in sys.modules if m == "apexmail" or m.startswith("apexmail.")]:
    del sys.modules[_name]
sys.path.insert(0, str(ROOT.parent))

from apexmail.exceptions import ValidationError as _ValidationError  # noqa: E402
from apexmail.resources import analytics as analytics_module  # noqa: E402
from apexmail.resources import webhooks as webhooks_module  # noqa: E402
from apexmail.resources.emails import build_send_payload  # noqa: E402


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _request(self, method: str, path: str, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if path == "/v1/messages":
            return {"id": "msg_1", "status": "queued", "created_at": "2026-08-29T00:00:00Z"}
        if path == "/v1/messages/batch":
            return {
                "accepted": 1,
                "rejected": 0,
                "results": [{"index": 0, "id": "msg_1", "status": "queued"}],
            }
        if path == "/v1/webhooks":
            return {
                "id": "wh_1",
                "url": "https://example.com/hook",
                "events": ["message.delivered"],
                "secret": "whsec_generated_server_side",
                "status": "active",
                "created_at": "2026-08-29T00:00:00Z",
                "updated_at": "2026-08-29T00:00:00Z",
            }
        if path.startswith("/v1/webhooks/"):
            return {
                "id": "wh_1",
                "url": "https://example.com/hook2",
                "events": ["message.opened"],
                "status": "paused",
                "created_at": "2026-08-29T00:00:00Z",
                "updated_at": "2026-08-29T00:00:00Z",
            }
        raise AssertionError(f"unexpected path {path}")


class SendPayloadContract(unittest.TestCase):
    def test_send_payload_matches_send_message_request(self) -> None:
        payload = build_send_payload(
            from_="hello@example.com",
            to=["user@example.com"],
            subject="Hello!",
            html="<h1>Hello World</h1>",
            cc=["cc@example.com"],
            bcc=["bcc@example.com"],
            tags=["welcome"],
            scheduled_at=datetime(2026, 9, 1, 9, tzinfo=timezone.utc),
            metadata={"source": "python-sdk-test"},
        )
        self.assertEqual(
            {
                "from": "hello@example.com",
                "to": ["user@example.com"],
                "subject": "Hello!",
                "html": "<h1>Hello World</h1>",
                "cc": ["cc@example.com"],
                "bcc": ["bcc@example.com"],
                "tags": ["welcome"],
                "scheduled_at": "2026-09-01T09:00:00+00:00",
                "metadata": {"source": "python-sdk-test"},
            },
            payload,
        )

    def test_send_never_serializes_unknown_fields(self) -> None:
        payload = build_send_payload(
            from_="hello@example.com",
            to="user@example.com",
            subject="Hi",
            text="Hello",
        )
        for forbidden in (
            "replyTo", "reply_to", "templateId", "templateData",
            "attachments", "priority", "headers", "scheduledAt", "name",
        ):
            self.assertNotIn(forbidden, payload)

    def test_recipient_dicts_flatten_to_bare_addresses(self) -> None:
        payload = build_send_payload(
            from_="hello@example.com",
            to=[{"email": "user@example.com", "name": "User"}],
            subject="Hi",
            text="Hello",
        )
        self.assertEqual(payload["to"], ["user@example.com"])
        self.assertNotIn("name", payload)

    def test_tags_flatten_to_string_list(self) -> None:
        payload = build_send_payload(
            from_="a@example.com",
            to="b@example.com",
            subject="s",
            text="t",
            tags=["alpha", {"name": "campaign", "value": "spring"}],
        )
        self.assertEqual(payload["tags"], ["alpha", "campaign=spring"])


class BatchCoercionContract(unittest.TestCase):
    def setUp(self) -> None:
        from apexmail.resources.emails import EmailsResource

        self.client = FakeClient()
        self.resource = EmailsResource(self.client)

    def test_batch_coerces_string_to_like_send(self) -> None:
        results = self.resource.batch(
            [{"from": "hello@example.com", "to": "user@example.com", "subject": "Hi", "text": "Hello"}]
        )
        self.assertEqual(results[0].id, "msg_1")
        message = self.client.calls[0]["json"]["messages"][0]
        self.assertEqual(message["to"], ["user@example.com"])
        self.assertEqual(message["from"], "hello@example.com")

    def test_batch_drops_unknown_fields_and_maps_scheduled_at(self) -> None:
        self.resource.batch(
            [
                {
                    "from": "hello@example.com",
                    "to": ["user@example.com"],
                    "subject": "Hi",
                    "text": "Hello",
                    "scheduledAt": "2026-09-01T09:00:00Z",
                    "priority": "high",
                    "reply_to": "r@example.com",
                }
            ]
        )
        message = self.client.calls[0]["json"]["messages"][0]
        self.assertEqual(message["scheduled_at"], "2026-09-01T09:00:00Z")
        self.assertNotIn("scheduledAt", message)
        self.assertNotIn("priority", message)
        self.assertNotIn("replyTo", message)
        self.assertNotIn("reply_to", message)

    def test_batch_from_underscore_alias_accepted(self) -> None:
        self.resource.batch(
            [{"from_": "hello@example.com", "to": "user@example.com", "subject": "Hi", "text": "Hello"}]
        )
        message = self.client.calls[0]["json"]["messages"][0]
        self.assertEqual(message["from"], "hello@example.com")


class WebhookPayloadContract(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.resource = webhooks_module.WebhooksResource(self.client)

    def test_create_sends_exactly_url_and_events(self) -> None:
        webhook = self.resource.create(
            name="legacy name",
            url="https://example.com/hook",
            events=["message.delivered", "email.bounced", "*"],
            description="legacy",
            secret="whsec_legacy",
            enabled=True,
        )
        call = self.client.calls[0]
        self.assertEqual("POST", call["method"])
        self.assertEqual("/v1/webhooks", call["path"])
        self.assertEqual(
            {"url": "https://example.com/hook", "events": ["message.delivered", "email.bounced", "*"]},
            call["json"],
        )
        # Flat response parse, secret only at creation.
        self.assertEqual(webhook.id, "wh_1")
        self.assertEqual(webhook.status, "active")
        self.assertEqual(webhook.secret, "whsec_generated_server_side")

    def test_update_maps_enabled_to_status(self) -> None:
        self.resource.update("wh_1", url="https://example.com/hook2", events=["message.opened"], enabled=False)
        call = self.client.calls[0]
        self.assertEqual("PUT", call["method"])
        self.assertEqual(
            {"url": "https://example.com/hook2", "events": ["message.opened"], "status": "paused"},
            call["json"],
        )

    def test_update_rejects_unknown_status(self) -> None:
        with self.assertRaises(_ValidationError):
            self.resource.update("wh_1", status="enabled")

    def test_known_events_match_server_list(self) -> None:
        # webhooks.rs KNOWN_WEBHOOK_EVENTS
        self.assertEqual(
            (
                "email.delivered", "email.bounced", "email.complained",
                "message.sent", "message.delivered", "message.bounced",
                "message.complained", "message.opened", "message.clicked",
                "recipient.unsubscribed", "placement_test.completed",
                "bounce", "complaint", "inbound", "*",
            ),
            tuple(webhooks_module.KNOWN_WEBHOOK_EVENTS),
        )
        with self.assertRaises(_ValidationError):
            self.resource.create(url="https://example.com/hook", events=["delivered"])


class AnalyticsEndpointContract(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeClient()
        self.resource = analytics_module.AnalyticsResource(self.client)

    def _stub_paths(self) -> None:
        self.client._request = lambda method, path, **kwargs: (  # type: ignore[method-assign]
            self.client.calls.append({"method": method, "path": path, **kwargs}) or {}
        )

    def test_typed_methods_hit_real_subpaths(self) -> None:
        self._stub_paths()
        self.resource.dashboard(from_="2026-01-01", to="2026-02-01")
        self.resource.volume(interval="week")
        self.resource.engagement()
        self.resource.deliverability()
        self.assertEqual(
            [
                ("GET", "/v1/analytics/dashboard", {"from": "2026-01-01", "to": "2026-02-01"}),
                ("GET", "/v1/analytics/volume", {"interval": "week"}),
                ("GET", "/v1/analytics/engagement", None),
                ("GET", "/v1/analytics/deliverability", None),
            ],
            [(c["method"], c["path"], c.get("params")) for c in self.client.calls],
        )

    def test_subject_line_posts_subject_body(self) -> None:
        self._stub_paths()
        self.resource.analyze_subject_line("Open me")
        call = self.client.calls[0]
        self.assertEqual(("POST", "/v1/analytics/subject-line", {"subject": "Open me"}),
                         (call["method"], call["path"], call["json"]))

    def test_interval_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            self.resource.volume(interval="fortnight")


if __name__ == "__main__":
    unittest.main()
