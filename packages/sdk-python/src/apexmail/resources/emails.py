"""
Emails Resource

API operations for sending and managing emails.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Union

from ..models import Email, EmailListResponse, EmailStatus, SendEmailResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail


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
        scheduled_at: Optional[str] = None,
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
            scheduled_at: ISO 8601 datetime for scheduled sending
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
            payload["scheduledAt"] = scheduled_at
        if metadata:
            payload["metadata"] = metadata

        data = self._client._request("POST", "/emails", json=payload)
        return SendEmailResponse(**data)

    def batch(
        self,
        emails: list[dict[str, Any]],
    ) -> list[SendEmailResponse]:
        """
        Send multiple emails in a batch (up to 1000).

        Args:
            emails: List of email objects with same fields as send()

        Returns:
            List of SendEmailResponse objects
        """
        # Convert from_ to from in each email
        processed = []
        for email in emails:
            processed_email = {**email}
            if "from_" in processed_email:
                processed_email["from"] = processed_email.pop("from_")
            processed.append(processed_email)

        data = self._client._request("POST", "/emails/batch", json={"emails": processed})
        return [SendEmailResponse(**item) for item in data.get("results", [])]

    def get(self, email_id: str) -> Email:
        """
        Get email details by ID.

        Args:
            email_id: The email ID

        Returns:
            Email details
        """
        data = self._client._request("GET", f"/emails/{email_id}")
        return Email(**data["email"])

    def list(
        self,
        *,
        limit: int = 25,
        cursor: Optional[str] = None,
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
            cursor: Pagination cursor
            status: Filter by status
            from_: Filter by sender
            to: Filter by recipient
            tag: Filter by tag name
            since: Return emails after this date
            until: Return emails before this date

        Returns:
            EmailListResponse with emails and pagination
        """
        params: dict[str, Any] = {"limit": limit}

        if cursor:
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

        data = self._client._request("GET", "/emails", params=params)
        return EmailListResponse(**data)

    def cancel(self, email_id: str) -> Email:
        """
        Cancel a scheduled email.

        Args:
            email_id: The email ID to cancel

        Returns:
            Updated email details
        """
        data = self._client._request("POST", f"/emails/{email_id}/cancel")
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
        scheduled_at: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        idempotency_key: Optional[str] = None,
    ) -> SendEmailResponse:
        """Send an email asynchronously."""
        payload: dict[str, Any] = {
            "from": from_,
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
        }

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
            payload["scheduledAt"] = scheduled_at
        if metadata:
            payload["metadata"] = metadata

        data = await self._client._request("POST", "/emails", json=payload)
        return SendEmailResponse(**data)

    async def batch(self, emails: list[dict[str, Any]]) -> list[SendEmailResponse]:
        """Send multiple emails in a batch asynchronously."""
        processed = []
        for email in emails:
            processed_email = {**email}
            if "from_" in processed_email:
                processed_email["from"] = processed_email.pop("from_")
            processed.append(processed_email)

        data = await self._client._request("POST", "/emails/batch", json={"emails": processed})
        return [SendEmailResponse(**item) for item in data.get("results", [])]

    async def get(self, email_id: str) -> Email:
        """Get email details by ID asynchronously."""
        data = await self._client._request("GET", f"/emails/{email_id}")
        return Email(**data["email"])

    async def list(
        self,
        *,
        limit: int = 25,
        cursor: Optional[str] = None,
        status: Optional[Union[str, EmailStatus]] = None,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        tag: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> EmailListResponse:
        """List emails with optional filters asynchronously."""
        params: dict[str, Any] = {"limit": limit}

        if cursor:
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

        data = await self._client._request("GET", "/emails", params=params)
        return EmailListResponse(**data)

    async def cancel(self, email_id: str) -> Email:
        """Cancel a scheduled email asynchronously."""
        data = await self._client._request("POST", f"/emails/{email_id}/cancel")
        return Email(**data["email"])
