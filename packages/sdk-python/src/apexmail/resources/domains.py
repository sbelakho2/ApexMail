"""
Domains Resource

API operations for domain management and verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ..models import Domain, DomainListResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


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
        data = self._client._request("GET", f"/domains/{domain_id}")
        return Domain(**data["domain"])

    def list(
        self,
        *,
        status: Optional[str] = None,
    ) -> DomainListResponse:
        """
        List all domains.

        Args:
            status: Filter by status (pending, verified, failed, expired)

        Returns:
            DomainListResponse with domains list
        """
        params = {}
        if status:
            params["status"] = status

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
        data = self._client._request("POST", f"/domains/{domain_id}/verify")
        return Domain(**data["domain"])

    def delete(self, domain_id: str) -> None:
        """
        Delete a domain.

        Args:
            domain_id: The domain ID to delete
        """
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
        data = await self._client._request("GET", f"/domains/{domain_id}")
        return Domain(**data["domain"])

    async def list(
        self,
        *,
        status: Optional[str] = None,
    ) -> DomainListResponse:
        """List all domains asynchronously."""
        params = {}
        if status:
            params["status"] = status

        data = await self._client._request("GET", "/domains", params=params or None)
        return DomainListResponse(**data)

    async def verify(self, domain_id: str) -> Domain:
        """Trigger domain verification asynchronously."""
        data = await self._client._request("POST", f"/domains/{domain_id}/verify")
        return Domain(**data["domain"])

    async def delete(self, domain_id: str) -> None:
        """Delete a domain asynchronously."""
        await self._client._request("DELETE", f"/domains/{domain_id}")
