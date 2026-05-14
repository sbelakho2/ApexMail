"""
Events Resource

API operations for event queries.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from ..exceptions import ValidationError
from ..models import Event, EventStats, EventTimeseriesPoint

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def _validate_id(resource_id: str, resource_name: str) -> None:
    if not resource_id or not _ID_REGEX.match(resource_id):
        raise ValidationError(
            f'Invalid {resource_name} ID format: "{resource_id}". '
            'IDs must be 1-128 alphanumeric characters, hyphens, or underscores.'
        )


def _extract_list(data: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for candidate in (key, "data", "items"):
            value = data.get(candidate)
            if isinstance(value, list):
                return value
    return []


def _extract_item(data: Any, key: str) -> dict[str, Any]:
    if isinstance(data, dict) and key in data and isinstance(data[key], dict):
        return data[key]
    return data if isinstance(data, dict) else {}


class EventsResource:
    """Synchronous events resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
        event_type: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> list[Event]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        if event_type:
            params["event_type"] = event_type
        if message_id:
            params["message_id"] = message_id
        data = self._client._request("GET", "/v1/events", params=params or None)
        return [Event(**item) for item in _extract_list(data, "events")]

    def get_by_message(self, message_id: str) -> list[Event]:
        """Get all events for a specific sent message (max 100 results)."""
        params: dict[str, Any] = {"message_id": message_id, "limit": 100}
        data = self._client._request("GET", "/v1/events", params=params)
        return [Event(**item) for item in _extract_list(data, "events")]

    def get(self, event_id: str) -> Event:
        _validate_id(event_id, "event")
        data = self._client._request("GET", f"/v1/events/{event_id}")
        return Event(**_extract_item(data, "event"))

    def stats(self, *, from_: Optional[str] = None, to: Optional[str] = None) -> EventStats:
        params: dict[str, Any] = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        data = self._client._request("GET", "/v1/events/stats", params=params or None)
        return EventStats(**data)

    def timeseries(self, *, from_: Optional[str] = None, to: Optional[str] = None) -> list[EventTimeseriesPoint]:
        params: dict[str, Any] = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        data = self._client._request("GET", "/v1/events/timeseries", params=params or None)
        return [EventTimeseriesPoint(**item) for item in _extract_list(data, "timeseries")]


class AsyncEventsResource:
    """Asynchronous events resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
        event_type: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> list[Event]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        if event_type:
            params["event_type"] = event_type
        if message_id:
            params["message_id"] = message_id
        data = await self._client._request("GET", "/v1/events", params=params or None)
        return [Event(**item) for item in _extract_list(data, "events")]

    async def get_by_message(self, message_id: str) -> list[Event]:
        """Get all events for a specific sent message (max 100 results) asynchronously."""
        params: dict[str, Any] = {"message_id": message_id, "limit": 100}
        data = await self._client._request("GET", "/v1/events", params=params)
        return [Event(**item) for item in _extract_list(data, "events")]

    async def get(self, event_id: str) -> Event:
        _validate_id(event_id, "event")
        data = await self._client._request("GET", f"/v1/events/{event_id}")
        return Event(**_extract_item(data, "event"))

    async def stats(self, *, from_: Optional[str] = None, to: Optional[str] = None) -> EventStats:
        params: dict[str, Any] = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        data = await self._client._request("GET", "/v1/events/stats", params=params or None)
        return EventStats(**data)

    async def timeseries(self, *, from_: Optional[str] = None, to: Optional[str] = None) -> list[EventTimeseriesPoint]:
        params: dict[str, Any] = {}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        data = await self._client._request("GET", "/v1/events/timeseries", params=params or None)
        return [EventTimeseriesPoint(**item) for item in _extract_list(data, "timeseries")]
