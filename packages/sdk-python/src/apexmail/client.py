"""
ApexMail API Client

Provides both synchronous and asynchronous clients for the ApexMail API.

SECURITY: Implements HTTPS enforcement, retry logic, and masked API key repr.
"""

from __future__ import annotations

import asyncio
import random
import re
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Callable, Optional
from urllib.parse import urlparse

import httpx

from .exceptions import (
    ApexMailError,
    AuthenticationError,
    ConflictError,
    ForbiddenError,
    NotFoundError,
    RateLimitError,
    ServerError,
    ValidationError,
)
from .resources.domains import AsyncDomainsResource, DomainsResource
from .resources.emails import AsyncEmailsResource, EmailsResource
from .resources.events import AsyncEventsResource, EventsResource
from .resources.suppressions import AsyncSuppressionsResource, SuppressionsResource
from .resources.templates import AsyncTemplatesResource, TemplatesResource
from .resources.webhooks import AsyncWebhooksResource, WebhooksResource

if TYPE_CHECKING:
    from types import TracebackType


DEFAULT_BASE_URL = "https://api.apexmail.ee"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
# Retry on these status codes
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


class BaseClient:
    """Base client with shared configuration."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        if not api_key:
            raise ValueError("API key is required")

        # SECURITY FIX: Stronger API key validation
        if not re.match(r'^am_(live|test)_[a-zA-Z0-9]{32,}$', api_key):
            raise ValueError(
                "API key must match format 'am_live_<key>' or 'am_test_<key>' "
                "where <key> is at least 32 alphanumeric characters"
            )

        normalized_base_url = base_url.rstrip("/")
        if normalized_base_url.endswith("/v1"):
            normalized_base_url = normalized_base_url[:-3]

        # SECURITY FIX: Enforce HTTPS in production
        parsed_url = urlparse(normalized_base_url)
        if parsed_url.scheme != "https":
            hostname = parsed_url.hostname or ""
            if hostname not in {"localhost", "127.0.0.1"}:
                raise ValueError(
                    "HTTPS is required for production API URLs. "
                    "HTTP is only allowed for localhost."
                )

        self._api_key = api_key  # Private to avoid accidental exposure
        self.base_url = normalized_base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self._sleep = sleep_fn or time.sleep
        self._base_headers = {
            "X-API-Key": self._api_key,
            "Content-Type": "application/json",
            "User-Agent": "apexmail-python/1.0.0",
        }

    # SECURITY FIX: Mask API key in repr to prevent accidental logging
    def __repr__(self) -> str:
        masked_key = f"{self._api_key[:10]}...{self._api_key[-4:]}"
        return f"{self.__class__.__name__}(api_key='{masked_key}', base_url='{self.base_url}')"

    @property
    def api_key(self) -> str:
        """Access API key (use with caution)."""
        return self._api_key

    def _get_headers(self, idempotency_key: Optional[str] = None) -> Optional[dict[str, str]]:
        if idempotency_key:
            return {"X-Idempotency-Key": idempotency_key}
        return None

    def _parse_retry_after(self, retry_after: Optional[str]) -> Optional[float]:
        if not retry_after:
            return None
        try:
            return float(retry_after)
        except ValueError:
            try:
                parsed = parsedate_to_datetime(retry_after)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return max(0.0, parsed.timestamp() - time.time())
            except Exception:
                return None

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff with jitter."""
        base_delay = min(2 ** attempt, 30.0)  # Max 30 seconds
        jitter = random.uniform(0, 0.3 * base_delay)
        return base_delay + jitter

    def _handle_response(self, response: httpx.Response) -> dict:
        """Handle API response and raise appropriate exceptions."""
        # FIX-500-294: Handle 204 No Content (DELETE responses)
        if response.status_code == 204:
            return {}
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
        elif response.status_code == 403:
            raise ForbiddenError(message=message, code=code)
        elif response.status_code == 404:
            raise NotFoundError(message=message, code=code)
        elif response.status_code == 409:
            raise ConflictError(message=message, code=code)
        elif response.status_code == 429:
            retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
            raise RateLimitError(
                message=message,
                code=code,
                retry_after=int(retry_after) if retry_after is not None else None,
            )
        elif response.status_code >= 500:
            raise ServerError(message=message, code=code)
        else:
            raise ApexMailError(message=message, code=code, status_code=response.status_code)


class ApexMail(BaseClient):
    """
    Synchronous ApexMail API client.

    FIX-500-466: The sync and async clients share a common BaseClient for
    initialization, validation, headers, and error handling. The remaining
    duplication (retry loops in _request) is inherent to Python's sync/async
    duality and cannot be easily deduplicated without a code generator
    (e.g. unasync). This is a known acceptable pattern.

    Usage:
        client = ApexMail(api_key="YOUR_API_KEY")
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
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        super().__init__(
            api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            sleep_fn=sleep_fn,
        )

        self._client = httpx.Client(
            base_url=self.base_url,
            headers=self._base_headers,
            timeout=timeout,
        )

        # Initialize resources
        self.emails = EmailsResource(self)
        self.domains = DomainsResource(self)
        self.templates = TemplatesResource(self)
        self.suppressions = SuppressionsResource(self)
        self.events = EventsResource(self)
        self.webhooks = WebhooksResource(self)

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """Make a synchronous HTTP request with retry logic."""
        headers = self._get_headers(idempotency_key)
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                    headers=headers,
                )
                
                # Retry on retryable status codes
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    if response.status_code == 429:
                        # Use Retry-After header if present
                        retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
                        delay = retry_after if retry_after is not None else self._calculate_backoff(attempt)
                    else:
                        delay = self._calculate_backoff(attempt)
                    self._sleep(delay)
                    continue
                    
                return self._handle_response(response)
                
            except httpx.TimeoutException as e:
                last_exception = e
                if attempt < self.max_retries:
                    self._sleep(self._calculate_backoff(attempt))
                    continue
                raise ApexMailError(
                    message="Request timed out",
                    code="TIMEOUT_ERROR",
                    status_code=408,
                ) from e
            except httpx.NetworkError as e:
                last_exception = e
                if attempt < self.max_retries:
                    self._sleep(self._calculate_backoff(attempt))
                    continue
                raise ApexMailError(
                    message=f"Network error: {e}",
                    code="NETWORK_ERROR",
                    status_code=0,
                ) from e
        
        # Should not reach here, but handle edge case
        if last_exception:
            raise last_exception
        raise ApexMailError(message="Request failed", code="UNKNOWN", status_code=0)

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
        async with AsyncApexMail(api_key="YOUR_API_KEY") as client:
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
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        super().__init__(
            api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            sleep_fn=sleep_fn,
        )

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self._base_headers,
            timeout=timeout,
        )

        # Initialize resources
        self.emails = AsyncEmailsResource(self)
        self.domains = AsyncDomainsResource(self)
        self.templates = AsyncTemplatesResource(self)
        self.suppressions = AsyncSuppressionsResource(self)
        self.events = AsyncEventsResource(self)
        self.webhooks = AsyncWebhooksResource(self)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict:
        """Make an asynchronous HTTP request with retry logic."""
        headers = self._get_headers(idempotency_key)
        last_exception: Optional[Exception] = None
        
        for attempt in range(self.max_retries + 1):
            try:
                response = await self._client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                    headers=headers,
                )
                
                # Retry on retryable status codes
                if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    if response.status_code == 429:
                        # Use Retry-After header if present
                        retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
                        delay = retry_after if retry_after is not None else self._calculate_backoff(attempt)
                    else:
                        delay = self._calculate_backoff(attempt)
                    await asyncio.sleep(delay)
                    continue
                    
                return self._handle_response(response)
                
            except httpx.TimeoutException as e:
                last_exception = e
                if attempt < self.max_retries:
                    await asyncio.sleep(self._calculate_backoff(attempt))
                    continue
                raise ApexMailError(
                    message="Request timed out",
                    code="TIMEOUT_ERROR",
                    status_code=408,
                ) from e
            except httpx.NetworkError as e:
                last_exception = e
                if attempt < self.max_retries:
                    await asyncio.sleep(self._calculate_backoff(attempt))
                    continue
                raise ApexMailError(
                    message=f"Network error: {e}",
                    code="NETWORK_ERROR",
                    status_code=0,
                ) from e
        
        # Should not reach here, but handle edge case
        if last_exception:
            raise last_exception
        raise ApexMailError(message="Request failed", code="UNKNOWN", status_code=0)

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
