"""
Emails Resource

API operations for sending and managing emails.
"""

from __future__ import annotations

import re
import uuid
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

# FIX-500-286: Maximum batch size (API_MESSAGES_MAX_BATCH_SIZE default on the server)
_MAX_BATCH_SIZE = 100


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


def _normalize_tags(tags: Any) -> Optional[list[str]]:
    """The API requires tags to be Vec<String>. Legacy {name, value} dict
    inputs are still accepted and flattened to "name" or "name=value"."""
    if tags is None:
        return None
    normalized: list[str] = []
    for tag in tags:
        if isinstance(tag, str):
            normalized.append(tag)
        elif isinstance(tag, dict) and tag.get("name"):
            value = tag.get("value")
            normalized.append(f"{tag['name']}={value}" if value is not None else str(tag["name"]))
    return normalized or None


def _coerce_recipient_list(value: Any) -> Optional[list[str]]:
    """Coerce "addr" | ["addr", ...] | {"email": ...} inputs to a list of
    bare address strings — the API's SendMessageRequest takes Vec<String>
    and rejects {email, name} object wrappers with 422."""
    if value is None:
        return None
    if isinstance(value, dict):
        value = [value]
    recipients = value if isinstance(value, list) else [value]
    out: list[str] = []
    for recipient in recipients:
        if isinstance(recipient, dict):
            email = recipient.get("email") or recipient.get("address")
            if email:
                out.append(str(email))
        elif recipient is not None:
            out.append(str(recipient))
    return out or None


def build_send_payload(
    *,
    from_: str,
    to: Any,
    subject: str,
    html: Optional[str] = None,
    text: Optional[str] = None,
    cc: Any = None,
    bcc: Any = None,
    tags: Any = None,
    scheduled_at: Optional[Union[str, datetime]] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Serialize a send body matching the server's SendMessageRequest
    (api-server/src/routes/messages.rs, deny_unknown_fields) exactly.

    Inputs the API does not accept — reply_to, attachments, headers,
    template ids, priority — are deliberately NOT serialized (sending them
    would be a 422). Display names inside address dicts are dropped: the
    API has no name fields.
    """
    payload: dict[str, Any] = {
        "from": from_ if isinstance(from_, str) else str(from_),
        "to": _coerce_recipient_list(to) or [],
        "subject": subject,
    }

    if html:
        payload["html"] = html
    if text:
        payload["text"] = text
    cc_list = _coerce_recipient_list(cc)
    if cc_list:
        payload["cc"] = cc_list
    bcc_list = _coerce_recipient_list(bcc)
    if bcc_list:
        payload["bcc"] = bcc_list
    normalized_tags = _normalize_tags(tags)
    if normalized_tags:
        payload["tags"] = normalized_tags
    if scheduled_at:
        payload["scheduled_at"] = (
            scheduled_at.isoformat() if isinstance(scheduled_at, datetime) else scheduled_at
        )
    if metadata:
        payload["metadata"] = metadata

    return payload


def _validate_batch_email(email: dict[str, Any], index: int) -> None:
    from_value = email.get("from") or email.get("from_")
    if not from_value:
        raise ValidationError(f'Email at index {index}: "from" is required')
    if isinstance(from_value, dict):
        from_value = from_value.get("email")
    if not from_value or not isinstance(from_value, str):
        raise ValidationError(f'Email at index {index}: "from" must be a string')
    _validate_email(from_value, "from")

    _validate_recipients(_coerce_recipient_list(email.get("to")), "to", required=True)
    for optional_field in ("cc", "bcc"):
        if email.get(optional_field) is not None:
            _validate_recipients(_coerce_recipient_list(email.get(optional_field)), optional_field)

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


def _normalize_batch_message(email: dict[str, Any]) -> dict[str, Any]:
    """Build the wire body for one batch message with the same coercion as
    send() — bare-string recipients, snake_case scheduled_at, tags as
    string list, and no API-unknown keys."""
    from_raw = email.get("from") or email.get("from_")
    from_value = from_raw.get("email") if isinstance(from_raw, dict) else from_raw

    payload = build_send_payload(
        from_=str(from_value),
        to=email.get("to"),
        subject=email["subject"],
        html=email.get("html"),
        text=email.get("text"),
        cc=email.get("cc"),
        bcc=email.get("bcc"),
        tags=email.get("tags"),
        scheduled_at=email.get("scheduled_at") or email.get("scheduledAt"),
        metadata=email.get("metadata"),
    )
    return payload


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

    # SDK-D: rejected items lack 'id' and carry {index, status: "rejected",
    # error} — SendEmailResponse models them with an optional id, so this no
    # longer raises ValidationError after the API already accepted siblings.
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
        tags: Optional[list[Any]] = None,
        attachments: Optional[list[dict[str, Any]]] = None,
        headers: Optional[dict[str, str]] = None,
        scheduled_at: Optional[Union[str, datetime]] = None,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> SendEmailResponse:
        """
        Send an email.

        The serialized body matches the server's SendMessageRequest exactly:
        from/to/cc/bcc go out as bare address strings and only API-accepted
        fields are sent. ``reply_to``, ``attachments``, ``headers``,
        ``template`` fields and display names are accepted as arguments for
        backwards compatibility but are NOT transmitted (the API rejects
        them with 422 via deny_unknown_fields).

        Args:
            from_: Sender email address
            to: Recipient email address(es)
            subject: Email subject
            html: HTML body content
            text: Plain text body content
            cc: CC recipients
            bcc: BCC recipients
            reply_to: Unsupported by the API; ignored on the wire
            tags: Tags (strings or {name, value} dicts, flattened)
            attachments: Unsupported by the API; ignored on the wire
            headers: Unsupported by the API; ignored on the wire
            scheduled_at: ISO 8601 datetime or datetime object for scheduled sending
            metadata: Custom metadata
            idempotency_key: Idempotency key for safe retries

        Returns:
            SendEmailResponse with email ID and status
        """
        # FIX-500-287: Validate email formats
        _validate_email(from_, "from")
        recipients = to if isinstance(to, list) else [to]
        for r in recipients:
            if isinstance(r, str):
                _validate_email(r, "to")
            elif isinstance(r, dict):
                _validate_email(str(r.get("email", "")), "to")
            else:
                raise ValidationError('"to" must be a string or list of strings')

        # FIX-500-288: Body presence check
        if not html and not text:
            raise ValidationError('Either "html" or "text" body is required')
        if html and not html.strip():
            raise ValidationError('"html" body must not be empty or whitespace-only')
        if text and not text.strip():
            raise ValidationError('"text" body must not be empty or whitespace-only')

        payload = build_send_payload(
            from_=from_,
            to=to,
            subject=subject,
            html=html,
            text=text,
            cc=cc,
            bcc=bcc,
            tags=tags,
            scheduled_at=scheduled_at,
            metadata=metadata,
        )

        # FIX-500-CRITICAL + SDK-B: thread idempotency_key to the HTTP client
        # (was silently dropped); when not supplied, generate one per logical
        # send so transport-level retries can never cause a duplicate send.
        data = self._client._request(
            "POST", "/v1/messages", json=payload, idempotency_key=idempotency_key or str(uuid.uuid4())
        )
        return SendEmailResponse(**data)

    def batch(
        self,
        emails: list[dict[str, Any]],
        *,
        idempotency_key: Optional[str] = None,
    ) -> list[SendEmailResponse]:
        """
        Send multiple emails in a batch (up to the server's batch limit).

        Each message dict accepts the same inputs as send() (``to`` may be a
        bare string; ``from_``/``from`` both accepted) and is serialized with
        the exact same coercion as send().

        Args:
            emails: List of email objects with same fields as send()
            idempotency_key: Idempotency key for safe retries; a random UUID
                is generated when omitted (SDK-B)

        Returns:
            List of SendEmailResponse objects (one per message; rejected
            items have status "rejected", an `error` message and no `id`)
        """
        # FIX-500-286: Validate batch size
        if not emails:
            raise ValidationError('"emails" list must not be empty')
        if len(emails) > _MAX_BATCH_SIZE:
            raise ValidationError(f'Maximum {_MAX_BATCH_SIZE} emails per batch, got {len(emails)}')

        for index, email in enumerate(emails):
            _validate_batch_email(email, index)

        data = self._client._request(
            "POST",
            "/v1/messages/batch",
            json={"messages": [_normalize_batch_message(email) for email in emails]},
            idempotency_key=idempotency_key or str(uuid.uuid4()),
        )
        return _parse_batch_results(data)

    def get(self, email_id: str) -> Email:
        """
        Get email details by ID.

        Returns the flat MessageDetail payload ({id, from, to, subject,
        status, tags, metadata, scheduled_at, sent_at, created_at}) — the
        API has no {"email": ...} wrapper.
        """
        _validate_id(email_id, 'email')
        data = self._client._request("GET", f"/v1/messages/{email_id}")
        if isinstance(data, dict) and isinstance(data.get("email"), dict):
            # Legacy wrapper shape tolerated defensively.
            data = data["email"]
        return Email(**data)

    def list(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        cursor: Optional[str] = None,
        status: Optional[Union[str, EmailStatus]] = None,
        sort_by: Optional[str] = None,
    ) -> EmailListResponse:
        """
        List emails with optional filters.

        The server's ListMessagesQuery accepts {limit, offset, cursor,
        status, sort_by} only — other filter parameters are rejected.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        if status:
            params["status"] = status.value if isinstance(status, EmailStatus) else status
        if sort_by:
            params["sort_by"] = sort_by

        data = self._client._request("GET", "/v1/messages", params=params)
        return EmailListResponse(**data)

    def cancel(self, email_id: str) -> dict[str, Any]:
        """
        Cancel a scheduled email.

        Returns the flat cancellation payload {id, status, created_at}.
        """
        _validate_id(email_id, 'email')
        data = self._client._request("POST", f"/v1/messages/{email_id}/cancel")
        if isinstance(data, dict) and isinstance(data.get("email"), dict):
            data = data["email"]
        return data


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
        tags: Optional[list[Any]] = None,
        attachments: Optional[list[dict[str, Any]]] = None,
        headers: Optional[dict[str, str]] = None,
        scheduled_at: Optional[Union[str, datetime]] = None,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> SendEmailResponse:
        """Send an email asynchronously.

        See the sync resource's docstring: only fields the API accepts are
        serialized; reply_to/attachments/headers/display names are ignored
        on the wire.
        """
        _validate_email(from_, "from")
        recipients = to if isinstance(to, list) else [to]
        for r in recipients:
            if isinstance(r, str):
                _validate_email(r, "to")
            elif isinstance(r, dict):
                _validate_email(str(r.get("email", "")), "to")
            else:
                raise ValidationError('"to" must be a string or list of strings')

        if not html and not text:
            raise ValidationError('Either "html" or "text" body is required')
        if html and not html.strip():
            raise ValidationError('"html" body must not be empty or whitespace-only')
        if text and not text.strip():
            raise ValidationError('"text" body must not be empty or whitespace-only')

        payload = build_send_payload(
            from_=from_,
            to=to,
            subject=subject,
            html=html,
            text=text,
            cc=cc,
            bcc=bcc,
            tags=tags,
            scheduled_at=scheduled_at,
            metadata=metadata,
        )

        data = await self._client._request(
            "POST", "/v1/messages", json=payload, idempotency_key=idempotency_key or str(uuid.uuid4())
        )
        return SendEmailResponse(**data)

    async def batch(
        self,
        emails: list[dict[str, Any]],
        *,
        idempotency_key: Optional[str] = None,
    ) -> list[SendEmailResponse]:
        """Send multiple emails in a batch asynchronously.

        Rejected items come back with status "rejected", an `error` message
        and no `id` (SDK-D). An idempotency key is generated automatically
        when not supplied (SDK-B). Each message is serialized with the same
        coercion as send().
        """
        if not emails:
            raise ValidationError('"emails" list must not be empty')
        if len(emails) > _MAX_BATCH_SIZE:
            raise ValidationError(f'Maximum {_MAX_BATCH_SIZE} emails per batch, got {len(emails)}')

        for index, email in enumerate(emails):
            _validate_batch_email(email, index)

        data = await self._client._request(
            "POST",
            "/v1/messages/batch",
            json={"messages": [_normalize_batch_message(email) for email in emails]},
            idempotency_key=idempotency_key or str(uuid.uuid4()),
        )
        return _parse_batch_results(data)

    async def get(self, email_id: str) -> Email:
        """Get email details by ID asynchronously (flat MessageDetail)."""
        _validate_id(email_id, 'email')
        data = await self._client._request("GET", f"/v1/messages/{email_id}")
        if isinstance(data, dict) and isinstance(data.get("email"), dict):
            data = data["email"]
        return Email(**data)

    async def list(
        self,
        *,
        limit: int = 25,
        offset: int = 0,
        cursor: Optional[str] = None,
        status: Optional[Union[str, EmailStatus]] = None,
        sort_by: Optional[str] = None,
    ) -> EmailListResponse:
        """List emails with optional filters asynchronously."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if cursor is not None:
            params["cursor"] = cursor
        if status:
            params["status"] = status.value if isinstance(status, EmailStatus) else status
        if sort_by:
            params["sort_by"] = sort_by

        data = await self._client._request("GET", "/v1/messages", params=params)
        return EmailListResponse(**data)

    async def cancel(self, email_id: str) -> dict[str, Any]:
        """Cancel a scheduled email asynchronously ({id, status, created_at})."""
        _validate_id(email_id, 'email')
        data = await self._client._request("POST", f"/v1/messages/{email_id}/cancel")
        if isinstance(data, dict) and isinstance(data.get("email"), dict):
            data = data["email"]
        return data
