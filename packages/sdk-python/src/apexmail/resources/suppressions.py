"""
Suppressions Resource

API operations for suppression list management.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from ..exceptions import ValidationError
from ..models import BulkSuppressionResponse, Suppression, SuppressionCheckResponse

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


class SuppressionsResource:
    """Synchronous suppressions resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        *,
        email: str,
        reason: str,
        source: Optional[str] = None,
    ) -> Suppression:
        return self.add(email=email, reason=reason, source=source)

    def add(
        self,
        *,
        email: str,
        reason: str,
        source: Optional[str] = None,
    ) -> Suppression:
        payload = {"email": email, "reason": reason, "source": source}
        data = self._client._request("POST", "/v1/suppressions", json=payload)
        return Suppression(**_extract_item(data, "suppression"))

    def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> list[Suppression]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        if reason:
            params["reason"] = reason
        data = self._client._request("GET", "/v1/suppressions", params=params or None)
        return [Suppression(**item) for item in _extract_list(data, "suppressions")]

    def delete(self, suppression_id: str) -> None:
        _validate_id(suppression_id, "suppression")
        self._client._request("DELETE", f"/v1/suppressions/{suppression_id}")

    def check(self, email: str) -> SuppressionCheckResponse:
        data = self._client._request("GET", f"/v1/suppressions/check/{email}")
        return SuppressionCheckResponse(**data)

    def bulk(self, entries: list[dict[str, Any]]) -> BulkSuppressionResponse:
        data = self._client._request("POST", "/v1/suppressions/bulk", json={"entries": entries})
        return BulkSuppressionResponse(**data)


class AsyncSuppressionsResource:
    """Asynchronous suppressions resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        *,
        email: str,
        reason: str,
        source: Optional[str] = None,
    ) -> Suppression:
        return await self.add(email=email, reason=reason, source=source)

    async def add(
        self,
        *,
        email: str,
        reason: str,
        source: Optional[str] = None,
    ) -> Suppression:
        payload = {"email": email, "reason": reason, "source": source}
        data = await self._client._request("POST", "/v1/suppressions", json=payload)
        return Suppression(**_extract_item(data, "suppression"))

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> list[Suppression]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        if reason:
            params["reason"] = reason
        data = await self._client._request("GET", "/v1/suppressions", params=params or None)
        return [Suppression(**item) for item in _extract_list(data, "suppressions")]

    async def delete(self, suppression_id: str) -> None:
        _validate_id(suppression_id, "suppression")
        await self._client._request("DELETE", f"/v1/suppressions/{suppression_id}")

    async def check(self, email: str) -> SuppressionCheckResponse:
        data = await self._client._request("GET", f"/v1/suppressions/check/{email}")
        return SuppressionCheckResponse(**data)

    async def bulk(self, entries: list[dict[str, Any]]) -> BulkSuppressionResponse:
        data = await self._client._request("POST", "/v1/suppressions/bulk", json={"entries": entries})
        return BulkSuppressionResponse(**data)
