"""
Domains Resource

API operations for domain management and verification.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

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

        Args:
            domain: The domain name to add
            verification_method: Verification method (dns_txt, dns_cname, meta_tag)

        Returns:
            Domain details with verification instructions
        """
        payload = {
            "domain": domain,
            "verificationMethod": verification_method,
        }

        data = self._client._request("POST", "/domains", json=payload)
        return Domain(**data["domain"])

    def get(self, domain_id: str) -> Domain:
        """
        Get domain details by ID.

        Args:
            domain_id: The domain ID

        Returns:
            Domain details
        """
        _validate_id(domain_id, 'domain')
        data = self._client._request("GET", f"/domains/{domain_id}")
        return Domain(**data["domain"])

    def list(
        self,
        *,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> DomainListResponse:
        """
        List all domains.

        Args:
            status: Filter by status (pending, verified, failed, expired)
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            DomainListResponse with domains list
        """
        params = {}
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset

        data = self._client._request("GET", "/domains", params=params or None)
        return DomainListResponse(**data)

    def verify(self, domain_id: str) -> Domain:
        """
        Trigger domain verification.

        Args:
            domain_id: The domain ID to verify

        Returns:
            Updated domain details
        """
        _validate_id(domain_id, 'domain')
        data = self._client._request("POST", f"/domains/{domain_id}/verify")
        return Domain(**data["domain"])

    def delete(self, domain_id: str) -> None:
        """
        Delete a domain.

        Args:
            domain_id: The domain ID to delete
        """
        _validate_id(domain_id, 'domain')
        self._client._request("DELETE", f"/domains/{domain_id}")


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
        """Add a new domain asynchronously."""
        payload = {
            "domain": domain,
            "verificationMethod": verification_method,
        }

        data = await self._client._request("POST", "/domains", json=payload)
        return Domain(**data["domain"])

    async def get(self, domain_id: str) -> Domain:
        """Get domain details by ID asynchronously."""
        _validate_id(domain_id, 'domain')
        data = await self._client._request("GET", f"/domains/{domain_id}")
        return Domain(**data["domain"])

    async def list(
        self,
        *,
        status: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
    ) -> DomainListResponse:
        """List all domains asynchronously."""
        params = {}
        if status:
            params["status"] = status
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset

        data = await self._client._request("GET", "/domains", params=params or None)
        return DomainListResponse(**data)

    async def verify(self, domain_id: str) -> Domain:
        """Trigger domain verification asynchronously."""
        _validate_id(domain_id, 'domain')
        data = await self._client._request("POST", f"/domains/{domain_id}/verify")
        return Domain(**data["domain"])

    async def delete(self, domain_id: str) -> None:
        """Delete a domain asynchronously."""
        _validate_id(domain_id, 'domain')
        await self._client._request("DELETE", f"/domains/{domain_id}")
