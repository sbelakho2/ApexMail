"""
Domains Resource

API operations for domain management and verification.

The server's CreateDomainRequest accepts exactly {name} (deny_unknown_fields)
and DomainResponse is the flat object {id, name, status, ses_verified,
spf_verified, dkim_verified, dmarc_verified, return_path_verified,
created_at} — there is no {"domain": ...} wrapper.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from ..exceptions import ValidationError
from ..models import Domain, DomainListResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

# FIX-500-291: ID format validation
_ID_REGEX = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')


def _validate_id(resource_id: str, resource_name: str) -> None:
    """Validate resource ID format."""
    if not resource_id or not _ID_REGEX.match(resource_id):
        raise ValidationError(
            f'Invalid {resource_name} ID format: "{resource_id}". '
            'IDs must be 1-128 alphanumeric characters, hyphens, or underscores.'
        )


def _parse_domain(data: Any) -> Domain:
    """Parse the flat DomainResponse (tolerating a legacy wrapper)."""
    if isinstance(data, dict) and isinstance(data.get("domain"), dict):
        data = data["domain"]
    if isinstance(data, dict) and "name" not in data and isinstance(data.get("domain"), str):
        # Older payloads used a `domain` string key for the name.
        data = {**data, "name": data["domain"]}
    return Domain(**data)


class DomainsResource:
    """Synchronous domains resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        domain: str,
        *,
        verification_method: str = "dns_txt",
    ) -> Domain:
        """
        Add a new domain.

        The body sent is exactly {name: domain} per the API's
        CreateDomainRequest; ``verification_method`` is accepted for
        backwards compatibility but the API has no such field (verification
        is always DNS-based).

        Args:
            domain: The domain name to add
            verification_method: Unused by the API (ignored)

        Returns:
            Domain details with verification state
        """
        data = self._client._request("POST", "/v1/domains", json={"name": domain})
        return _parse_domain(data)

    def get(self, domain_id: str) -> Domain:
        """
        Get domain details by ID (flat DomainResponse).

        Args:
            domain_id: The domain ID

        Returns:
            Domain details
        """
        _validate_id(domain_id, 'domain')
        data = self._client._request("GET", f"/v1/domains/{domain_id}")
        return _parse_domain(data)

    def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
    ) -> DomainListResponse:
        """
        List all domains.

        The server's ListDomainsQuery accepts {limit, offset, cursor} only.

        Args:
            limit: Maximum number of results
            offset: Number of results to skip
            cursor: Cursor for pagination

        Returns:
            DomainListResponse with domains list
        """
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor

        data = self._client._request("GET", "/v1/domains", params=params or None)
        return DomainListResponse(**data)

    def verify(self, domain_id: str) -> dict[str, Any]:
        """
        Trigger domain verification.

        Args:
            domain_id: The domain ID to verify

        Returns:
            {domain, spf_verified, dkim_verified, dmarc_verified,
             return_path_verified, status}
        """
        _validate_id(domain_id, 'domain')
        return self._client._request("POST", f"/v1/domains/{domain_id}/verify")

    def delete(self, domain_id: str) -> None:
        """
        Delete a domain.

        Args:
            domain_id: The domain ID to delete
        """
        _validate_id(domain_id, 'domain')
        self._client._request("DELETE", f"/v1/domains/{domain_id}")

    def health(self, domain_id: str) -> Domain:
        """Domain health/verification state.

        The API has no GET /:id/health endpoint — GET /:id itself returns
        the health information (spf/dkim/dmarc/return_path verification
        booleans plus status), so this is a thin alias of get().
        """
        _validate_id(domain_id, 'domain')
        return self.get(domain_id)


class AsyncDomainsResource:
    """Asynchronous domains resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        domain: str,
        *,
        verification_method: str = "dns_txt",
    ) -> Domain:
        """Add a new domain asynchronously (body {name})."""
        data = await self._client._request("POST", "/v1/domains", json={"name": domain})
        return _parse_domain(data)

    async def get(self, domain_id: str) -> Domain:
        """Get domain details by ID asynchronously (flat response)."""
        _validate_id(domain_id, 'domain')
        data = await self._client._request("GET", f"/v1/domains/{domain_id}")
        return _parse_domain(data)

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
    ) -> DomainListResponse:
        """List all domains asynchronously."""
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor

        data = await self._client._request("GET", "/v1/domains", params=params or None)
        return DomainListResponse(**data)

    async def verify(self, domain_id: str) -> dict[str, Any]:
        """Trigger domain verification asynchronously."""
        _validate_id(domain_id, 'domain')
        return await self._client._request("POST", f"/v1/domains/{domain_id}/verify")

    async def delete(self, domain_id: str) -> None:
        """Delete a domain asynchronously."""
        _validate_id(domain_id, 'domain')
        await self._client._request("DELETE", f"/v1/domains/{domain_id}")

    async def health(self, domain_id: str) -> Domain:
        """Domain health/verification state (alias of get(); there is no
        /health endpoint on the API)."""
        _validate_id(domain_id, 'domain')
        return await self.get(domain_id)
