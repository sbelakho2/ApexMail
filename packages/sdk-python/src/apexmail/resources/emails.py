"""
Emails Resource

API operations for sending and managing emails.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Union

from ..exceptions import ApexMailError, ValidationError
from ..models import Email, EmailListResponse, EmailStatus, SendEmailResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

# FIX-500-287: Basic email format validation
_EMAIL_REGEX = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._%+\-]{0,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$')
# FIX-500-291: ID format validation
_ID_REGEX = re.compile(r'^[a-zA-Z0-9_-]{1,128}$')

# FIX-500-286: Maximum batch size
_MAX_BATCH_SIZE = 1000


def _validate_email(email: str, field: str) -> None:
    """Validate email format."""
    if not _EMAIL_REGEX.match(email):
        raise ValidationError(f'Invalid "{field}" email format: {email}')


def _validate_id(resource_id: str, resource_name: str) -> None:
    """FIX-500-291: Validate resource ID format."""
    if not resource_id or not _ID_REGEX.match(resource_id):
        raise ValidationError(
            f'Invalid {resource_name} ID format: "{resource_id}". '
            'IDs must be 1-128 alphanumeric characters, hyphens, or underscores.'
        )


def _validate_recipients(value: Any, field: str, *, required: bool = False) -> None:
    if value is None:
        if required:
            raise ValidationError(f'"{field}" is required')
        return
    recipients = value if isinstance(value, list) else [value]
    if not recipients:
        raise ValidationError(f'"{field}" must contain at least one recipient')
    for recipient in recipients:
        if not isinstance(recipient, str):
            raise ValidationError(f'"{field}" must be a string or list of strings')
        _validate_email(recipient, field)


def _validate_batch_email(email: dict[str, Any], index: int) -> None:
    from_value = email.get("from") or email.get("from_")
    if not from_value:
        raise ValidationError(f'Email at index {index}: "from" is required')
    if not isinstance(from_value, str):
        raise ValidationError(f'Email at index {index}: "from" must be a string')
    _validate_email(from_value, "from")

    _validate_recipients(email.get("to"), "to", required=True)
    _validate_recipients(email.get("cc"), "cc")
    _validate_recipients(email.get("bcc"), "bcc")

    subject = email.get("subject")
    if not subject:
        raise ValidationError(f'Email at index {index}: "subject" is required')
    if not isinstance(subject, str):
        raise ValidationError(f'Email at index {index}: "subject" must be a string')

    html = email.get("html")
    text = email.get("text")
    if not html and not text:
        raise ValidationError(f'Email at index {index}: Either "html" or "text" body is required')
    if html and isinstance(html, str) and not html.strip():
        raise ValidationError(f'Email at index {index}: "html" body must not be empty or whitespace-only')
    if text and isinstance(text, str) and not text.strip():
        raise ValidationError(f'Email at index {index}: "text" body must not be empty or whitespace-only')

    reply_to = email.get("reply_to") or email.get("replyTo")
    if reply_to is not None:
        if not isinstance(reply_to, str):
            raise ValidationError(f'Email at index {index}: "reply_to" must be a string')
        _validate_email(reply_to, "reply_to")


def _parse_batch_results(data: Any) -> list[SendEmailResponse]:
    if not isinstance(data, dict):
        raise ApexMailError(
            "Invalid batch response: expected object payload",
            code="INVALID_RESPONSE",
        )

    results = data.get("results")
    if not isinstance(results, list):
        raise ApexMailError(
            "Invalid batch response: expected 'results' list",
            code="INVALID_RESPONSE",
        )

    if not all(isinstance(item, dict) for item in results):
        raise ApexMailError(
            "Invalid batch response: each result must be an object",
            code="INVALID_RESPONSE",
        )

    return [SendEmailResponse(**item) for item in results]


class EmailsResource:
    """Synchronous emails resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def send(
        self,
        *,
        from_: str,
        to: Union[str, list[str]],
        subject: str,
        html: Optional[str] = None,
        text: Optional[str] = None,
        cc: Optional[list[str]] = None,
        bcc: Optional[list[str]] = None,
        reply_to: Optional[str] = None,
        tags: Optional[list[dict[str, str]]] = None,
        attachments: Optional[list[dict[str, Any]]] = None,
        headers: Optional[dict[str, str]] = None,
        scheduled_at: Optional[Union[str, datetime]] = None,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> SendEmailResponse:
        """
        Send an email.

        Args:
            from_: Sender email address
            to: Recipient email address(es)
            subject: Email subject
            html: HTML body content
            text: Plain text body content
            cc: CC recipients
            bcc: BCC recipients
            reply_to: Reply-to address
            tags: Tags for categorization
            attachments: File attachments
            headers: Custom headers
            scheduled_at: ISO 8601 datetime or datetime object for scheduled sending
            metadata: Custom metadata
            idempotency_key: Idempotency key for safe retries

        Returns:
            SendEmailResponse with email ID and status
        """
        payload: dict[str, Any] = {
            "from": from_,
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
        }

        # FIX-500-287: Validate email formats
        _validate_email(from_, "from")
        recipients = to if isinstance(to, list) else [to]
        for r in recipients:
            _validate_email(r, "to")

        # FIX-500-288: Body presence check
        if not html and not text:
            raise ValidationError('Either "html" or "text" body is required')
        if html and not html.strip():
            raise ValidationError('"html" body must not be empty or whitespace-only')
        if text and not text.strip():
            raise ValidationError('"text" body must not be empty or whitespace-only')

        if html:
            payload["html"] = html
        if text:
            payload["text"] = text
        if cc:
            payload["cc"] = cc
        if bcc:
            payload["bcc"] = bcc
        if reply_to:
            payload["replyTo"] = reply_to
        if tags:
            payload["tags"] = tags
        if attachments:
            payload["attachments"] = attachments
        if headers:
            payload["headers"] = headers
        if scheduled_at:
            payload["scheduledAt"] = scheduled_at.isoformat() if isinstance(scheduled_at, datetime) else scheduled_at
        if metadata:
            payload["metadata"] = metadata

        # FIX-500-CRITICAL: Thread idempotency_key to the HTTP client (was silently dropped!)
        data = self._client._request("POST", "/v1/messages", json=payload, idempotency_key=idempotency_key)
        return SendEmailResponse(**data)

    def batch(
        self,
        emails: list[dict[str, Any]],
        *,
        idempotency_key: Optional[str] = None,
    ) -> list[SendEmailResponse]:
        """
        Send multiple emails in a batch (up to 1000).

        Args:
            emails: List of email objects with same fields as send()
            idempotency_key: Idempotency key for safe retries

        Returns:
            List of SendEmailResponse objects
        """
        # FIX-500-286: Validate batch size
        if not emails:
            raise ValidationError('"emails" list must not be empty')
        if len(emails) > _MAX_BATCH_SIZE:
            raise ValidationError(f'Maximum {_MAX_BATCH_SIZE} emails per batch, got {len(emails)}')

        for index, email in enumerate(emails):
            _validate_batch_email(email, index)

        # Convert from_ to from in each email
        processed = []
        for email in emails:
            processed_email = {**email}
            if "from_" in processed_email:
                processed_email["from"] = processed_email.pop("from_")
            processed.append(processed_email)

        data = self._client._request(
            "POST",
            "/v1/messages/batch",
            json={"messages": processed},
            idempotency_key=idempotency_key,
        )
        return _parse_batch_results(data)

    def get(self, email_id: str) -> Email:
        """
        Get email details by ID.

        Args:
            email_id: The email ID

        Returns:
            Email details
        """
        _validate_id(email_id, 'email')
        data = self._client._request("GET", f"/v1/messages/{email_id}")
        return Email(**data["email"])

    def list(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        cursor: Optional[int] = None,
        status: Optional[Union[str, EmailStatus]] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        tag: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> EmailListResponse:
        """
        List emails with optional filters.

        Args:
            limit: Number of results (1-100)
            offset: Number of results to skip
            cursor: Pagination cursor (from previous response's pagination)
            status: Filter by status
            from_: Filter by sender
            to: Filter by recipient
            tag: Filter by tag name
            since: Return emails after this date
            until: Return emails before this date

        Returns:
            EmailListResponse with emails and pagination
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        if status:
            params["status"] = status.value if isinstance(status, EmailStatus) else status
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        if tag:
            params["tag"] = tag
        if since:
            params["since"] = since
        if until:
            params["until"] = until

        data = self._client._request("GET", "/v1/messages", params=params)
        return EmailListResponse(**data)

    def cancel(self, email_id: str) -> Email:
        """
        Cancel a scheduled email.

        Args:
            email_id: The email ID to cancel

        Returns:
            Updated email details
        """
        _validate_id(email_id, 'email')
        data = self._client._request("POST", f"/v1/messages/{email_id}/cancel")
        return Email(**data["email"])


class AsyncEmailsResource:
    """Asynchronous emails resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def send(
        self,
        *,
        from_: str,
        to: Union[str, list[str]],
        subject: str,
        html: Optional[str] = None,
        text: Optional[str] = None,
        cc: Optional[list[str]] = None,
        bcc: Optional[list[str]] = None,
        reply_to: Optional[str] = None,
        tags: Optional[list[dict[str, str]]] = None,
        attachments: Optional[list[dict[str, Any]]] = None,
        headers: Optional[dict[str, str]] = None,
        scheduled_at: Optional[Union[str, datetime]] = None,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> SendEmailResponse:
        """Send an email asynchronously."""
        payload: dict[str, Any] = {
            "from": from_,
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
        }

        # FIX-500-287: Validate email formats
        _validate_email(from_, "from")
        recipients = to if isinstance(to, list) else [to]
        for r in recipients:
            _validate_email(r, "to")

        # FIX-500-288: Body presence check
        if not html and not text:
            raise ValidationError('Either "html" or "text" body is required')
        if html and not html.strip():
            raise ValidationError('"html" body must not be empty or whitespace-only')
        if text and not text.strip():
            raise ValidationError('"text" body must not be empty or whitespace-only')

        if html:
            payload["html"] = html
        if text:
            payload["text"] = text
        if cc:
            payload["cc"] = cc
        if bcc:
            payload["bcc"] = bcc
        if reply_to:
            payload["replyTo"] = reply_to
        if tags:
            payload["tags"] = tags
        if attachments:
            payload["attachments"] = attachments
        if headers:
            payload["headers"] = headers
        if scheduled_at:
            payload["scheduledAt"] = scheduled_at.isoformat() if isinstance(scheduled_at, datetime) else scheduled_at
        if metadata:
            payload["metadata"] = metadata

        # FIX-500-CRITICAL: Thread idempotency_key to the HTTP client (was silently dropped!)
        data = await self._client._request("POST", "/v1/messages", json=payload, idempotency_key=idempotency_key)
        return SendEmailResponse(**data)

    async def batch(
        self,
        emails: list[dict[str, Any]],
        *,
        idempotency_key: Optional[str] = None,
    ) -> list[SendEmailResponse]:
        """Send multiple emails in a batch asynchronously."""
        # FIX-500-286: Validate batch size
        if not emails:
            raise ValidationError('"emails" list must not be empty')
        if len(emails) > _MAX_BATCH_SIZE:
            raise ValidationError(f'Maximum {_MAX_BATCH_SIZE} emails per batch, got {len(emails)}')

        for index, email in enumerate(emails):
            _validate_batch_email(email, index)

        processed = []
        for email in emails:
            processed_email = {**email}
            if "from_" in processed_email:
                processed_email["from"] = processed_email.pop("from_")
            processed.append(processed_email)

        data = await self._client._request(
            "POST",
            "/v1/messages/batch",
            json={"messages": processed},
            idempotency_key=idempotency_key,
        )
        return _parse_batch_results(data)

    async def get(self, email_id: str) -> Email:
        """Get email details by ID asynchronously."""
        _validate_id(email_id, 'email')
        data = await self._client._request("GET", f"/v1/messages/{email_id}")
        return Email(**data["email"])

    async def list(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        cursor: Optional[int] = None,
        status: Optional[Union[str, EmailStatus]] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        tag: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> EmailListResponse:
        """List emails with optional filters asynchronously."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        if status:
            params["status"] = status.value if isinstance(status, EmailStatus) else status
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        if tag:
            params["tag"] = tag
        if since:
            params["since"] = since
        if until:
            params["until"] = until

        data = await self._client._request("GET", "/v1/messages", params=params)
        return EmailListResponse(**data)

    async def cancel(self, email_id: str) -> Email:
        """Cancel a scheduled email asynchronously."""
        _validate_id(email_id, 'email')
        data = await self._client._request("POST", f"/v1/messages/{email_id}/cancel")
        return Email(**data["email"])
