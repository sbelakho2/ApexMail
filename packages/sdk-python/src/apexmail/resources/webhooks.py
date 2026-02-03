"""
Webhooks Resource

API operations for webhook management.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

from ..models import Webhook, WebhookListResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


class WebhooksResource:
    """Synchronous webhooks resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        *,
        name: str,
        url: str,
        events: list[str],
        description: Optional[str] = None,
        secret: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: bool = True,
    ) -> Webhook:
        """
        Create a new webhook.

        Args:
            name: Webhook name
            url: Webhook URL (must be HTTPS in production)
            events: List of events to subscribe to
            description: Optional description
            secret: Optional secret for signature verification
            headers: Optional custom headers
            enabled: Whether webhook is enabled

        Returns:
            Created webhook details
        """
        payload: dict[str, Any] = {
            "name": name,
            "url": url,
            "events": events,
            "enabled": enabled,
        }

        if description:
            payload["description"] = description
        if secret:
            payload["secret"] = secret
        if headers:
            payload["headers"] = headers

        data = self._client._request("POST", "/webhooks", json=payload)
        return Webhook(**data["webhook"])

    def get(self, webhook_id: str) -> Webhook:
        """
        Get webhook details by ID.

        Args:
            webhook_id: The webhook ID

        Returns:
            Webhook details
        """
        data = self._client._request("GET", f"/webhooks/{webhook_id}")
        return Webhook(**data["webhook"])

    def list(self) -> WebhookListResponse:
        """
        List all webhooks.

        Returns:
            WebhookListResponse with webhooks list
        """
        data = self._client._request("GET", "/webhooks")
        return WebhookListResponse(**data)

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
    ) -> Webhook:
        """
        Update a webhook.

        Args:
            webhook_id: The webhook ID to update
            name: New name
            url: New URL
            events: New events list
            description: New description
            headers: New headers
            enabled: New enabled status

        Returns:
            Updated webhook details
        """
        payload: dict[str, Any] = {}

        if name is not None:
            payload["name"] = name
        if url is not None:
            payload["url"] = url
        if events is not None:
            payload["events"] = events
        if description is not None:
            payload["description"] = description
        if headers is not None:
            payload["headers"] = headers
        if enabled is not None:
            payload["enabled"] = enabled

        data = self._client._request("PATCH", f"/webhooks/{webhook_id}", json=payload)
        return Webhook(**data["webhook"])

    def delete(self, webhook_id: str) -> None:
        """
        Delete a webhook.

        Args:
            webhook_id: The webhook ID to delete
        """
        self._client._request("DELETE", f"/webhooks/{webhook_id}")

    def test(self, webhook_id: str, event_type: str = "message.delivered") -> dict[str, Any]:
        """
        Send a test event to a webhook.

        Args:
            webhook_id: The webhook ID to test
            event_type: The event type to simulate

        Returns:
            Test result details
        """
        payload = {"eventType": event_type}
        return self._client._request("POST", f"/webhooks/{webhook_id}/test", json=payload)


class AsyncWebhooksResource:
    """Asynchronous webhooks resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        *,
        name: str,
        url: str,
        events: list[str],
        description: Optional[str] = None,
        secret: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        enabled: bool = True,
    ) -> Webhook:
        """Create a new webhook asynchronously."""
        payload: dict[str, Any] = {
            "name": name,
            "url": url,
            "events": events,
            "enabled": enabled,
        }

        if description:
            payload["description"] = description
        if secret:
            payload["secret"] = secret
        if headers:
            payload["headers"] = headers

        data = await self._client._request("POST", "/webhooks", json=payload)
        return Webhook(**data["webhook"])

    async def get(self, webhook_id: str) -> Webhook:
        """Get webhook details by ID asynchronously."""
        data = await self._client._request("GET", f"/webhooks/{webhook_id}")
        return Webhook(**data["webhook"])

    async def list(self) -> WebhookListResponse:
        """List all webhooks asynchronously."""
        data = await self._client._request("GET", "/webhooks")
        return WebhookListResponse(**data)

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
    ) -> Webhook:
        """Update a webhook asynchronously."""
        payload: dict[str, Any] = {}

        if name is not None:
            payload["name"] = name
        if url is not None:
            payload["url"] = url
        if events is not None:
            payload["events"] = events
        if description is not None:
            payload["description"] = description
        if headers is not None:
            payload["headers"] = headers
        if enabled is not None:
            payload["enabled"] = enabled

        data = await self._client._request("PATCH", f"/webhooks/{webhook_id}", json=payload)
        return Webhook(**data["webhook"])

    async def delete(self, webhook_id: str) -> None:
        """Delete a webhook asynchronously."""
        await self._client._request("DELETE", f"/webhooks/{webhook_id}")

    async def test(
        self, webhook_id: str, event_type: str = "message.delivered"
    ) -> dict[str, Any]:
        """Send a test event to a webhook asynchronously."""
        payload = {"eventType": event_type}
        return await self._client._request("POST", f"/webhooks/{webhook_id}/test", json=payload)
