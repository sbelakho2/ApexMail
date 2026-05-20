"""
ApexMail API Client

Provides both synchronous and asynchronous clients for the ApexMail API.

SECURITY: Implements HTTPS enforcement, retry logic, and masked API key repr.
"""

from __future__ import annotations

import asyncio
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
from .resources.analytics import AnalyticsResource, AsyncAnalyticsResource
from .resources.api_keys import ApiKeysResource, AsyncApiKeysResource
from .resources.suppressions import AsyncSuppressionsResource, SuppressionsResource
from .resources.templates import AsyncTemplatesResource, TemplatesResource
from .resources.webhooks import AsyncWebhooksResource, WebhooksResource

if TYPE_CHECKING:
    from types import TracebackType


DEFAULT_BASE_URL = "https://api.apexmail.ee"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_TOTAL_RETRY_TIMEOUT = 90.0
DEFAULT_MAX_RESPONSE_BYTES = 20 * 1024 * 1024
DEFAULT_INITIAL_BACKOFF = 0.5
DEFAULT_MAX_BACKOFF = 5.0
# Retry on these status codes
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}

API_KEY_PATTERN = re.compile(r'^am_(live|test)_[a-zA-Z0-9]{16,}$')


class BaseClient:
    """Base client with shared configuration."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        if not api_key:
            raise ValueError("API key is required")

        if not API_KEY_PATTERN.match(api_key):
            raise ValueError(
                "API key must match format 'am_live_<key>' or 'am_test_<key>' "
                "where <key> is at least 16 alphanumeric characters"
            )

        normalized_base_url = base_url.rstrip("/")
        if normalized_base_url.endswith("/v1"):
            normalized_base_url = normalized_base_url[:-3]

        # SECURITY FIX: Enforce HTTPS in production
        parsed_url = urlparse(normalized_base_url)
        if parsed_url.scheme != "https":
            hostname = parsed_url.hostname or ""
            if hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError(
                    "HTTPS is required for production API URLs. "
                    "HTTP is only allowed for localhost."
                )

        self._api_key = api_key
        self.base_url = normalized_base_url
        self.timeout = timeout
        self.max_retries = max_retries
        self.max_response_bytes = max_response_bytes
        self.total_retry_timeout = max(timeout, DEFAULT_TOTAL_RETRY_TIMEOUT)
        self._sleep = sleep_fn or time.sleep
        self._base_headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "apexmail-python/1.0.0",
        }

    def close(self) -> None:
        """Clear sensitive API key data from memory."""
        self._api_key = ""

    def __repr__(self) -> str:
        key = self.api_key
        masked_key = f"{key[:4]}\u2026\u2026{key[-4:]}"
        return f"{self.__class__.__name__}(api_key='{masked_key}', base_url='{self.base_url}')"

    @property
    def api_key(self) -> str:
        """Access API key (use with caution)."""
        return self._api_key

    def _get_headers(self, idempotency_key: Optional[str] = None) -> dict[str, str]:
        if idempotency_key:
            return {"X-Idempotency-Key": idempotency_key}
        return {}

    def _parse_retry_after(self, retry_after: Optional[str]) -> Optional[float]:
        """Parse Retry-After header value into seconds.

        Supports both integer/float seconds and HTTP-date format (RFC 2822/1123).
        Returns None if the header is absent or unparseable.
        """
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
            except (TypeError, ValueError, OverflowError):
                return None

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate bounded quadratic backoff: baseDelay * attempt²."""
        return min(DEFAULT_INITIAL_BACKOFF * (attempt * attempt), DEFAULT_MAX_BACKOFF)

    def _ensure_response_size(self, response: httpx.Response) -> None:
        content = response.content
        if len(content) > self.max_response_bytes:
            raise ApexMailError(
                message="Response body exceeds maxResponseBytes",
                code="RESPONSE_TOO_LARGE",
                status_code=0,
            )

    def _handle_response(self, response: httpx.Response) -> dict:
        """Handle API response and raise appropriate exceptions."""
        # FIX-500-294: Handle 204 No Content (DELETE responses)
        if response.status_code == 204:
            return {}
        if response.status_code == 200 or response.status_code == 201:
            self._ensure_response_size(response)
            data = response.json()
            # SDK-111: Unwrap API envelope {"data": ..., "meta": ...}
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            return data

        try:
            error_data = response.json()
            error_obj = error_data.get("error")
            if isinstance(error_obj, dict):
                message = error_obj.get("message") or response.text or "Unknown error"
                code = error_obj.get("code") or "UNKNOWN"
                errors = error_obj.get("details") or error_obj.get("errors") or []
            else:
                message = error_obj or error_data.get("message") or response.text or "Unknown error"
                code = error_data.get("code") or "UNKNOWN"
                errors = error_data.get("errors", [])
        except (ValueError, TypeError):
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

    def _retry_delay(self, response: httpx.Response, attempt: int) -> Optional[float]:
        """Calculate delay if request should be retried, or None if not.

        Returns the delay in seconds if the response status code is retryable
        and the attempt is not the final one, or None to indicate no retry.
        """
        if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
            delay = self._calculate_backoff(attempt)
            if response.status_code == 429:
                retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
                if retry_after is not None:
                    delay = max(delay, retry_after)
            return delay
        return None

    def _check_total_timeout(self, started_at: float) -> None:
        """Raise ApexMailError if the total retry timeout has been exceeded."""
        if (time.monotonic() - started_at) > self.total_retry_timeout:
            raise ApexMailError(
                message="Total retry timeout exceeded",
                code="TOTAL_TIMEOUT",
                status_code=408,
            )

    def _build_timeout_error(self, attempt: int, last_exception: Optional[Exception]) -> None:
        """Raise appropriate error after exhausting retries on timeout/network errors.

        This is a shared helper called only after all retry attempts have been exhausted.
        """
        if last_exception:
            raise last_exception
        raise ApexMailError(message="Request failed", code="UNKNOWN", status_code=0)

    def _build_exception_from_httpx_error(self, e: Exception, attempt: int) -> Exception:
        """Build an ApexMailError from a httpx transport exception."""
        if isinstance(e, httpx.TimeoutException):
            return ApexMailError(
                message="Request timed out",
                code="TIMEOUT_ERROR",
                status_code=408,
            )
        if isinstance(e, httpx.NetworkError):
            return ApexMailError(
                message=f"Network error: {e}",
                code="NETWORK_ERROR",
                status_code=0,
            )
        return ApexMailError(message=f"Request failed: {e}", code="UNKNOWN", status_code=0)


class ApexMail(BaseClient):
    """
    Synchronous ApexMail API client.

    FIX-500-466: The sync and async clients share a common BaseClient for
    initialization, validation, headers, and error handling. Helper methods
    for retry logic (timeout checks, backoff, error building) have been
    extracted to the base class to minimize duplication in the _request methods.

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
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        super().__init__(
            api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
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
        self.analytics = AnalyticsResource(self)
        self.api_keys = ApiKeysResource(self)

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
        started_at = time.monotonic()
        
        for attempt in range(self.max_retries + 1):
            self._check_total_timeout(started_at)
            try:
                response = self._client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                    headers=headers,
                )
                
                delay = self._retry_delay(response, attempt)
                if delay is not None:
                    self._sleep(delay)
                    continue
                    
                return self._handle_response(response)
                
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    self._sleep(self._calculate_backoff(attempt))
                    continue
                raise self._build_exception_from_httpx_error(e, attempt) from e
        
        self._build_timeout_error(attempt, last_exception)

    def close(self) -> None:
        """Close the HTTP client and clear sensitive data from memory."""
        super().close()
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
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        super().__init__(
            api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=max_retries,
            max_response_bytes=max_response_bytes,
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
        self.analytics = AsyncAnalyticsResource(self)
        self.api_keys = AsyncApiKeysResource(self)

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
        started_at = time.monotonic()
        
        for attempt in range(self.max_retries + 1):
            self._check_total_timeout(started_at)
            try:
                response = await self._client.request(
                    method=method,
                    url=path,
                    json=json,
                    params=params,
                    headers=headers,
                )
                
                delay = self._retry_delay(response, attempt)
                if delay is not None:
                    await asyncio.sleep(delay)
                    continue
                    
                return self._handle_response(response)
                
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                last_exception = e
                if attempt < self.max_retries:
                    await asyncio.sleep(self._calculate_backoff(attempt))
                    continue
                raise self._build_exception_from_httpx_error(e, attempt) from e
        
        self._build_timeout_error(attempt, last_exception)

    async def close(self) -> None:
        """Close the HTTP client and clear sensitive data from memory."""
        super().close()
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
