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

    def test_send_serializes_every_accepted_option(self) -> None:
        """F48: options the send() API accepts must reach the wire."""
        payload = build_send_payload(
            from_="hello@example.com",
            to="user@example.com",
            subject="Hi",
            text="Hello",
            reply_to="reply@example.com",
            attachments=[{"filename": "a.txt", "content": "eHg="}],
            headers={"X-Custom": "yes"},
        )
        self.assertEqual(payload["reply_to"], "reply@example.com")
        self.assertEqual(payload["attachments"], [{"filename": "a.txt", "content": "eHg="}])
        self.assertEqual(payload["headers"], {"X-Custom": "yes"})

    def test_omitted_options_stay_absent(self) -> None:
        payload = build_send_payload(
            from_="hello@example.com",
            to="user@example.com",
            subject="Hi",
            text="Hello",
        )
        for absent in ("reply_to", "attachments", "headers", "cc", "bcc", "tags", "metadata"):
            self.assertNotIn(absent, payload)

    def test_recipient_dicts_serialize_display_names(self) -> None:
        """F48: display names survive as "Name <addr>" wire forms."""
        payload = build_send_payload(
            from_={"email": "hello@example.com", "name": "Hello"},
            to=[{"email": "user@example.com", "name": "User"}, "plain@example.com"],
            subject="Hi",
            text="Hello",
            cc=[{"email": "cc@example.com", "name": "CC"}],
        )
        self.assertEqual(payload["from"], "Hello <hello@example.com>")
        self.assertEqual(
            payload["to"], ["User <user@example.com>", "plain@example.com"]
        )
        self.assertEqual(payload["cc"], ["CC <cc@example.com>"])

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

    def test_batch_maps_scheduled_at_and_forwards_options(self) -> None:
        self.resource.batch(
            [
                {
                    "from": "hello@example.com",
                    "to": ["user@example.com"],
                    "subject": "Hi",
                    "text": "Hello",
                    "scheduledAt": "2026-09-01T09:00:00Z",
                    "reply_to": "r@example.com",
                }
            ]
        )
        message = self.client.calls[0]["json"]["messages"][0]
        self.assertEqual(message["scheduled_at"], "2026-09-01T09:00:00Z")
        self.assertNotIn("scheduledAt", message)
        self.assertEqual(message["reply_to"], "r@example.com")

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


# ── F48: shared send contract — packages/contract/send-contract.json ────────
#
# The SAME fixture file drives the api-server contract tests and every SDK
# serialization suite, so the wire forms this SDK emits can never drift
# from what the API deserializer accepts.

import json as _json  # noqa: E402

from apexmail.exceptions import ValidationError as ContractValidationError  # noqa: E402
from apexmail.resources.emails import (  # noqa: E402
    EmailsResource,
    _bare_address,
    _validate_priority,
)

CONTRACT_PATH = pathlib.Path(__file__).resolve().parents[2] / "contract" / "send-contract.json"


class SharedSendContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = _json.loads(CONTRACT_PATH.read_text())

    def _fixture_value(self, case: dict) -> object:
        input_spec = case["input"]
        if input_spec["type"] == "int":
            return int(input_spec["value"])
        return input_spec["value"]

    def test_priority_wire_forms_match_the_fixture(self) -> None:
        for case in self.contract["priority"]["cases"]:
            description = case["description"]
            value = self._fixture_value(case)
            if case["valid"]:
                # The validator returns the exact wire form; the payload
                # builder puts it on the wire unchanged.
                self.assertEqual(case["wire"], _validate_priority(value), description)
                payload = build_send_payload(
                    from_="hello@example.com",
                    to="user@example.com",
                    subject="Hi",
                    text="Hello",
                    priority=value,
                )
                self.assertEqual(case["wire"], payload["priority"], description)
            else:
                with self.assertRaises(ContractValidationError, msg=description):
                    _validate_priority(value)

    def test_named_levels_map_like_the_api(self) -> None:
        for level, queue in self.contract["priority"]["named_levels"].items():
            self.assertEqual(queue, {"high": 7, "normal": 5, "low": 3}[level])
        # Case-insensitive canonicalization to the exact wire spelling.
        self.assertEqual("high", _validate_priority("HIGH"))

    def test_mailbox_extraction_matches_the_fixture(self) -> None:
        for case in self.contract["mailbox"]["cases"]:
            description = case["description"]
            extracted = _bare_address(case["input"])
            if case["valid"]:
                self.assertEqual(case["addr_spec"], extracted, description)
            else:
                self.assertFalse(
                    extracted and extracted == case.get("addr_spec"),
                    f"case '{description}' must not validate",
                )
                with self.assertRaises(ContractValidationError, msg=description):
                    EmailsResource(FakeClient()).send(
                        from_=case["input"],
                        to=["user@example.com"],
                        subject="Hi",
                        text="Hello",
                    )

    def test_sender_dict_and_display_string_validate_the_bare_address(self) -> None:
        # The reported defect: a documented {"email": ..., "name": ...} sender
        # was passed straight to a regex expecting str (TypeError).
        client = FakeClient()
        EmailsResource(client).send(
            from_={"email": "ada@example.com", "name": "Ada Lovelace"},
            to=["Bob <bob@example.com>", "carol@example.com"],
            subject="Hi",
            text="Hello",
            reply_to={"email": "reply@example.com", "name": "Replies"},
            priority="high",
        )
        payload = client.calls[0]["json"]
        self.assertEqual("Ada Lovelace <ada@example.com>", payload["from"])
        self.assertEqual(["Bob <bob@example.com>", "carol@example.com"], payload["to"])
        self.assertEqual("Replies <reply@example.com>", payload["reply_to"])
        self.assertEqual("high", payload["priority"])

        # A display-name STRING sender is validated the same way.
        client = FakeClient()
        EmailsResource(client).send(
            from_="Ada Lovelace <ada@example.com>",
            to="user@example.com",
            subject="Hi",
            text="Hello",
            priority=3,
        )
        payload = client.calls[0]["json"]
        self.assertEqual("Ada Lovelace <ada@example.com>", payload["from"])
        self.assertEqual(3, payload["priority"])

        # ...and an invalid addr-spec inside any form is still rejected.
        for bad in ("Ada <not-an-email>", "not-an-email"):
            with self.assertRaises(ContractValidationError):
                EmailsResource(FakeClient()).send(
                    from_=bad, to="user@example.com", subject="Hi", text="Hello"
                )


if __name__ == "__main__":
    unittest.main()
