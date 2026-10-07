"""API Keys Resource.

The server's CreateApiKeyRequest (auth.rs) accepts exactly
{name, scopes: string[], expires_in_days?} — `scopes` is required (use []
for a key with no scopes) and the legacy ``expiresAt`` field is not part
of the API.
"""

from __future__ import annotations

from urllib.parse import quote
from typing import TYPE_CHECKING, Any, List, Optional

from ..exceptions import ValidationError

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


def _reject_cursor(cursor: Optional[Any]) -> None:
    """ListApiKeysQuery accepts {limit, offset} only (deny_unknown_fields):
    a `cursor` parameter is rejected by the server with HTTP 400, and the
    endpoint returns a plain array with no pagination envelope. Fail fast
    client-side with the honest contract instead of emitting a request the
    server refuses."""
    if cursor is not None:
        raise ValidationError(
            "/v1/auth/api-keys does not support cursor pagination "
            "(the server rejects `cursor` with HTTP 400); use limit/offset",
            code="UNSUPPORTED_PAGINATION",
        )


def _create_payload(name: str, scopes: Optional[List[str]], expires_in_days: Optional[int]) -> dict[str, Any]:
    return {
        "name": name,
        "scopes": list(scopes) if scopes is not None else [],
        **({"expires_in_days": expires_in_days} if expires_in_days is not None else {}),
    }


class ApiKeysResource:
    """Synchronous API keys resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        *,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a new API key ({name, scopes, expires_in_days?} on the wire).

        ``expires_at`` is accepted for backwards compatibility but ignored —
        the API takes a relative ``expires_in_days`` (1..365).
        """
        return self._client._request(
            "POST", "/v1/auth/api-keys", json=_create_payload(name, scopes, expires_in_days)
        )

    def list(self, *, limit: int = 50, offset: int = 0, cursor: Optional[str] = None) -> list[dict[str, Any]]:
        """List API keys. The server returns a plain array (no envelope)."""
        _reject_cursor(cursor)
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        return self._client._request("GET", "/v1/auth/api-keys", params=params)

    def revoke(self, key_id: str) -> None:
        # Path-segment escaping: a raw id containing `/`, `?` or `#` would
        # otherwise rewrite the route (URL injection) rather than address
        # the key.
        self._client._request("DELETE", f"/v1/auth/api-keys/{quote(key_id, safe='')}")


class AsyncApiKeysResource:
    """Asynchronous API keys resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        *,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
        expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a new API key asynchronously ({name, scopes, expires_in_days?})."""
        return await self._client._request(
            "POST", "/v1/auth/api-keys", json=_create_payload(name, scopes, expires_in_days)
        )

    async def list(self, *, limit: int = 50, offset: int = 0, cursor: Optional[str] = None) -> list[dict[str, Any]]:
        """List API keys asynchronously. The server returns a plain array."""
        _reject_cursor(cursor)
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        return await self._client._request("GET", "/v1/auth/api-keys", params=params)

    async def revoke(self, key_id: str) -> None:
        await self._client._request("DELETE", f"/v1/auth/api-keys/{quote(key_id, safe='')}")
