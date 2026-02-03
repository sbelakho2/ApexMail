"""
ApexMail API Exceptions

Custom exception classes for handling API errors.
"""

from __future__ import annotations

from typing import Any, Optional


class ApexMailError(Exception):
    """Base exception for ApexMail API errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "UNKNOWN",
        status_code: Optional[int] = None,
    ) -> None:
        self.message = message
        self.code = code
        self.status_code = status_code
        super().__init__(message)

    def __str__(self) -> str:
        if self.code:
            return f"[{self.code}] {self.message}"
        return self.message


class ValidationError(ApexMailError):
    """Raised when request validation fails (400)."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "VALIDATION_ERROR",
        errors: Optional[list[dict[str, Any]]] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=400)
        self.errors = errors or []


class AuthenticationError(ApexMailError):
    """Raised when authentication fails (401)."""

    def __init__(
        self,
        message: str = "Invalid API key",
        *,
        code: str = "AUTHENTICATION_ERROR",
    ) -> None:
        super().__init__(message, code=code, status_code=401)


class NotFoundError(ApexMailError):
    """Raised when a resource is not found (404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        *,
        code: str = "NOT_FOUND",
    ) -> None:
        super().__init__(message, code=code, status_code=404)


class RateLimitError(ApexMailError):
    """Raised when rate limit is exceeded (429)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        *,
        code: str = "RATE_LIMIT_EXCEEDED",
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(message, code=code, status_code=429)
        self.retry_after = retry_after


class ServerError(ApexMailError):
    """Raised when a server error occurs (5xx)."""

    def __init__(
        self,
        message: str = "Internal server error",
        *,
        code: str = "SERVER_ERROR",
    ) -> None:
        super().__init__(message, code=code, status_code=500)
