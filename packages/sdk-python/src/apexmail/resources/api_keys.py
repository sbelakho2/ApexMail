"""API Keys Resource."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


class ApiKeysResource:
    """Synchronous API keys resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(self, *, name: str, expires_at: Optional[str] = None) -> dict[str, Any]:
        payload = {"name": name, "expiresAt": expires_at}
        return self._client._request("POST", "/v1/auth/api-keys", json={k: v for k, v in payload.items() if v})

    def list(self, *, limit: int = 50, offset: int = 0, cursor: Optional[int] = None) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        return self._client._request("GET", "/v1/auth/api-keys", params=params)

    def revoke(self, key_id: str) -> None:
        self._client._request("DELETE", f"/v1/auth/api-keys/{key_id}")


class AsyncApiKeysResource:
    """Asynchronous API keys resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(self, *, name: str, expires_at: Optional[str] = None) -> dict[str, Any]:
        payload = {"name": name, "expiresAt": expires_at}
        return await self._client._request("POST", "/v1/auth/api-keys", json={k: v for k, v in payload.items() if v})

    async def list(self, *, limit: int = 50, offset: int = 0, cursor: Optional[int] = None) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        return await self._client._request("GET", "/v1/auth/api-keys", params=params)

    async def revoke(self, key_id: str) -> None:
        await self._client._request("DELETE", f"/v1/auth/api-keys/{key_id}")