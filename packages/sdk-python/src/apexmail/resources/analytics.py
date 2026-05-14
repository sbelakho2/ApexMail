"""Analytics Resource."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


class AnalyticsResource:
    """Synchronous analytics resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def get(
        self,
        *,
        from_: str,
        to: str,
        group_by: Optional[str] = None,
        tag: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "from": from_,
            "to": to,
        }
        if group_by:
            params["groupBy"] = group_by
        if tag:
            params["tag"] = tag
        if domain:
            params["domain"] = domain
        return self._client._request("GET", "/v1/analytics", params=params)


class AsyncAnalyticsResource:
    """Asynchronous analytics resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def get(
        self,
        *,
        from_: str,
        to: str,
        group_by: Optional[str] = None,
        tag: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "from": from_,
            "to": to,
        }
        if group_by:
            params["groupBy"] = group_by
        if tag:
            params["tag"] = tag
        if domain:
            params["domain"] = domain
        return await self._client._request("GET", "/v1/analytics", params=params)