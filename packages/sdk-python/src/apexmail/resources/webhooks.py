"""
Webhooks Resource

API operations for webhook management.

The server's CreateWebhookRequest accepts exactly {url, events}
(deny_unknown_fields) and returns the flat WebhookResponse
{id, url, events, secret?, status, created_at, updated_at} — there is no
{"webhook": ...} wrapper and no name/enabled fields.
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from ..exceptions import ValidationError
from ..models import Webhook, WebhookListResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

# FIX-500-291: ID format validation
_ID_REGEX = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')

# Event names the server accepts (api-server/src/routes/webhooks.rs
# KNOWN_WEBHOOK_EVENTS, canonicalized 2026-09-08). Any other name is
# rejected with 422 server-side.
KNOWN_WEBHOOK_EVENTS: tuple[str, ...] = (
    "message.accepted",
    "message.queued",
    "message.attempted",
    "message.deferred",
    "message.delivered",
    "message.bounced",
    "message.complained",
    "message.suppressed",
    "message.opened",
    "message.clicked",
    "message.cancelled",
    "recipient.unsubscribed",
    # Campaign lifecycle (produced by the campaign worker; the server
    # vocabulary carries these three — a stale SDK list warned falsely).
    "campaign.started",
    "campaign.ab_winner_selected",
    "campaign.completed",
    "placement_test.completed",
    "inbound",
    "*",
)


def _validate_id(resource_id: str, resource_name: str) -> None:
    """Validate resource ID format."""
    if not resource_id or not _ID_REGEX.match(resource_id):
        raise ValidationError(
            f'Invalid {resource_name} ID format: "{resource_id}". '
            'IDs must be 1-128 alphanumeric characters, hyphens, or underscores.'
        )


def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL is HTTPS (unless localhost)."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if parsed.scheme != "https":
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValidationError(
                f'Webhook URL must use HTTPS: "{url}". '
                'HTTP is only allowed for localhost development.'
            )


def _validate_events(events: list[str]) -> None:
    """Warn on unknown event names — the server 422s them.

    Deliberately a warning, not a hard error (audit SM15 F1): the server
    owns the vocabulary, and a client-side gate would brick the SDK every
    time the server adds a new event type. This is a convenience
    diagnostic only.
    """
    invalid = [event for event in events if event.strip() not in KNOWN_WEBHOOK_EVENTS]
    if invalid:
        warnings.warn(
            f"Unknown webhook event type(s): {', '.join(invalid)}. "
            f"Known events: {', '.join(KNOWN_WEBHOOK_EVENTS)}",
            stacklevel=3,
        )


def _parse_webhook(data: Any) -> Webhook:
    """Parse the flat WebhookResponse (tolerating a legacy wrapper)."""
    if isinstance(data, dict) and isinstance(data.get("webhook"), dict):
        data = data["webhook"]
    return Webhook(**data)


class WebhooksResource:
    """Synchronous webhooks resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        *,
        name: Optional[str] = None,
        url: str,
        events: list[str],
        description: Optional[str] = None,
        secret: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: bool = True,
    ) -> Webhook:
        """
        Create a new webhook.

        Only {url, events} are transmitted — the API's CreateWebhookRequest
        rejects anything else (the signing secret is generated server-side
        and returned in the response). The legacy name/description/secret/
        headers/enabled arguments are accepted for backwards compatibility
        but ignored on the wire.

        Args:
            name: Unused by the API (ignored).
            url: Webhook URL (must be HTTPS in production)
            events: Event names (KNOWN_WEBHOOK_EVENTS), e.g.
                ["message.delivered", "message.bounced", "*"]
            description: Unused by the API (ignored).
            secret: Unused by the API (server-generated; ignored).
            headers: Unused by the API (ignored).
            enabled: Unused by the API (new webhooks are always "active").

        Returns:
            Created webhook (secret is present only in this response)
        """
        _validate_webhook_url(url)
        _validate_events(events)

        data = self._client._request("POST", "/v1/webhooks", json={"url": url, "events": events})
        return _parse_webhook(data)

    def get(self, webhook_id: str) -> Webhook:
        """
        Get webhook details by ID (flat WebhookResponse).

        Args:
            webhook_id: The webhook ID

        Returns:
            Webhook details
        """
        _validate_id(webhook_id, 'webhook')
        data = self._client._request("GET", f"/v1/webhooks/{webhook_id}")
        return _parse_webhook(data)

    def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> WebhookListResponse:
        """
        List all webhooks.

        Args:
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            WebhookListResponse with webhooks list
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        data = self._client._request("GET", "/v1/webhooks", params=params or None)
        return WebhookListResponse.model_validate(data)

    def update(
        self,
        webhook_id: str,
        *,
        name: Optional[str] = None,
        url: Optional[str] = None,
        events: Optional[list[str]] = None,
        description: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: Optional[bool] = None,
        status: Optional[str] = None,
    ) -> Webhook:
        """
        Update a webhook.

        Transmits only {url, events, status} per the API's
        UpdateWebhookRequest (status one of "active" | "paused" |
        "disabled"); a boolean ``enabled`` is mapped to
        active/paused for backwards compatibility. name/description/headers
        are accepted but ignored.

        Args:
            webhook_id: The webhook ID to update
            name: Unused by the API (ignored).
            url: New URL
            events: New events list
            description: Unused by the API (ignored).
            headers: Unused by the API (ignored).
            enabled: Mapped to status active/paused.
            status: New status ("active" | "paused" | "disabled")

        Returns:
            Updated webhook details
        """
        _validate_id(webhook_id, 'webhook')

        payload: dict[str, Any] = {}

        if url is not None:
            _validate_webhook_url(url)
            payload["url"] = url
        if events is not None:
            _validate_events(events)
            payload["events"] = events
        resolved_status = status
        if resolved_status is None and enabled is not None:
            resolved_status = "active" if enabled else "paused"
        if resolved_status is not None:
            if resolved_status not in {"active", "paused", "disabled"}:
                raise ValidationError(
                    'status must be one of "active", "paused", "disabled" '
                    f"(got {resolved_status!r})"
                )
            payload["status"] = resolved_status

        if not payload:
            raise ValidationError("Update payload must include at least one field")

        data = self._client._request("PUT", f"/v1/webhooks/{webhook_id}", json=payload)
        return _parse_webhook(data)

    def delete(self, webhook_id: str) -> None:
        """
        Delete a webhook.

        Args:
            webhook_id: The webhook ID to delete
        """
        _validate_id(webhook_id, 'webhook')
        self._client._request("DELETE", f"/v1/webhooks/{webhook_id}")

    def test(self, webhook_id: str) -> dict[str, Any]:
        """
        Send a test event to a webhook (the server takes no body).

        Args:
            webhook_id: The webhook ID to test

        Returns:
            Test result: {success, status_code?, response_time_ms, error?}
        """
        _validate_id(webhook_id, 'webhook')
        return self._client._request("POST", f"/v1/webhooks/{webhook_id}/test")

    def rotate_secret(self, webhook_id: str) -> Webhook:
        """
        Rotate the webhook's signing secret.

        ``POST /v1/webhooks/:id/rotate-secret`` (webhooks.rs router). The new
        secret is returned in this response only; the previous secret stops
        verifying deliveries immediately, so update the receiver before
        rotating. Pass the secret verbatim (the full ``whsec_…`` string) to
        :func:`apexmail.webhooks.verify_signature`.

        Args:
            webhook_id: The webhook ID whose secret to rotate

        Returns:
            Webhook details with the new ``secret`` populated
        """
        _validate_id(webhook_id, 'webhook')
        data = self._client._request(
            "POST", f"/v1/webhooks/{webhook_id}/rotate-secret"
        )
        return _parse_webhook(data)


class AsyncWebhooksResource:
    """Asynchronous webhooks resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        *,
        name: Optional[str] = None,
        url: str,
        events: list[str],
        description: Optional[str] = None,
        secret: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: bool = True,
    ) -> Webhook:
        """Create a new webhook asynchronously.

        Only {url, events} are transmitted (see the sync resource)."""
        _validate_webhook_url(url)
        _validate_events(events)

        data = await self._client._request("POST", "/v1/webhooks", json={"url": url, "events": events})
        return _parse_webhook(data)

    async def get(self, webhook_id: str) -> Webhook:
        """Get webhook details by ID asynchronously (flat response)."""
        _validate_id(webhook_id, 'webhook')
        data = await self._client._request("GET", f"/v1/webhooks/{webhook_id}")
        return _parse_webhook(data)

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> WebhookListResponse:
        """List all webhooks asynchronously."""
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        data = await self._client._request("GET", "/v1/webhooks", params=params or None)
        return WebhookListResponse.model_validate(data)

    async def update(
        self,
        webhook_id: str,
        *,
        name: Optional[str] = None,
        url: Optional[str] = None,
        events: Optional[list[str]] = None,
        description: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: Optional[bool] = None,
        status: Optional[str] = None,
    ) -> Webhook:
        """Update a webhook asynchronously ({url, events, status} on the wire)."""
        _validate_id(webhook_id, 'webhook')
        payload: dict[str, Any] = {}

        if url is not None:
            _validate_webhook_url(url)
            payload["url"] = url
        if events is not None:
            _validate_events(events)
            payload["events"] = events
        resolved_status = status
        if resolved_status is None and enabled is not None:
            resolved_status = "active" if enabled else "paused"
        if resolved_status is not None:
            if resolved_status not in {"active", "paused", "disabled"}:
                raise ValidationError(
                    'status must be one of "active", "paused", "disabled" '
                    f"(got {resolved_status!r})"
                )
            payload["status"] = resolved_status

        # FIX-500-293: Reject empty update payload
        if not payload:
            raise ValidationError('At least one field must be provided for update')

        data = await self._client._request("PUT", f"/v1/webhooks/{webhook_id}", json=payload)
        return _parse_webhook(data)

    async def delete(self, webhook_id: str) -> None:
        """Delete a webhook asynchronously."""
        _validate_id(webhook_id, 'webhook')
        await self._client._request("DELETE", f"/v1/webhooks/{webhook_id}")

    async def test(self, webhook_id: str) -> dict[str, Any]:
        """Send a test event to a webhook asynchronously (no body)."""
        _validate_id(webhook_id, 'webhook')
        return await self._client._request("POST", f"/v1/webhooks/{webhook_id}/test")

    async def rotate_secret(self, webhook_id: str) -> Webhook:
        """Rotate the webhook's signing secret asynchronously.

        See the sync resource: the new secret is returned once and the old
        one stops verifying deliveries immediately."""
        _validate_id(webhook_id, 'webhook')
        data = await self._client._request(
            "POST", f"/v1/webhooks/{webhook_id}/rotate-secret"
        )
        return _parse_webhook(data)
