"""
ApexMail API Client

Provides both synchronous and asynchronous clients for the ApexMail API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import httpx

from .exceptions import (
    ApexMailError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .resources.domains import AsyncDomainsResource, DomainsResource
from .resources.emails import AsyncEmailsResource, EmailsResource
from .resources.webhooks import AsyncWebhooksResource, WebhooksResource

if TYPE_CHECKING:
    from types import TracebackType


DEFAULT_BASE_URL = "https://api.apexmail.ee/v1"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3


class BaseClient:
    """Base client with shared configuration."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        if not api_key:
            raise ValueError("API key is required")

        if not api_key.startswith(("am_live_", "am_test_")):
            raise ValueError("API key must start with 'am_live_' or 'am_test_'")

        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "apexmail-python/1.0.0",
        }

    def _handle_response(self, response: httpx.Response) -> dict:
        """Handle API response and raise appropriate exceptions."""
        if response.status_code == 200 or response.status_code == 201:
            return response.json()

        try:
            error_data = response.json()
            message = error_data.get("message", "Unknown error")
            code = error_data.get("code", "UNKNOWN")
            errors = error_data.get("errors", [])
        except Exception:
            message = response.text or f"HTTP {response.status_code}"
            code = "UNKNOWN"
            errors = []

        if response.status_code == 400:
            raise ValidationError(message=message, code=code, errors=errors)
        elif response.status_code == 401:
            raise AuthenticationError(message=message, code=code)
        elif response.status_code == 404:
            raise NotFoundError(message=message, code=code)
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                message=message,
                code=code,
                retry_after=int(retry_after) if retry_after else None,
            )
        elif response.status_code >= 500:
            raise ServerError(message=message, code=code)
        else:
            raise ApexMailError(message=message, code=code, status_code=response.status_code)


class ApexMail(BaseClient):
    """
    Synchronous ApexMail API client.

    Usage:
        client = ApexMail(api_key="am_live_xxxx")
        response = client.emails.send(
            from_="hello@example.com",
            to="user@example.com",
            subject="Welcome!",
            html="<h1>Hello!</h1>"
        )
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        super().__init__(api_key, base_url=base_url, timeout=timeout, max_retries=max_retries)

        self._client = httpx.Client(
            base_url=self.base_url,
            headers=self._get_headers(),
            timeout=timeout,
        )

        # Initialize resources
        self.emails = EmailsResource(self)
        self.domains = DomainsResource(self)
        self.webhooks = WebhooksResource(self)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make a synchronous HTTP request."""
        response = self._client.request(
            method=method,
            url=path,
            json=json,
            params=params,
        )
        return self._handle_response(response)

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "ApexMail":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()


class AsyncApexMail(BaseClient):
    """
    Asynchronous ApexMail API client.

    Usage:
        async with AsyncApexMail(api_key="am_live_xxxx") as client:
            response = await client.emails.send(
                from_="hello@example.com",
                to="user@example.com",
                subject="Welcome!",
                html="<h1>Hello!</h1>"
            )
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> None:
        super().__init__(api_key, base_url=base_url, timeout=timeout, max_retries=max_retries)

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._get_headers(),
            timeout=timeout,
        )

        # Initialize resources
        self.emails = AsyncEmailsResource(self)
        self.domains = AsyncDomainsResource(self)
        self.webhooks = AsyncWebhooksResource(self)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> dict:
        """Make an asynchronous HTTP request."""
        response = await self._client.request(
            method=method,
            url=path,
            json=json,
            params=params,
        )
        return self._handle_response(response)

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncApexMail":
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        await self.close()
