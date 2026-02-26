"""
ApexMail API Models

Pydantic models for request and response data.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class EmailStatus(str, Enum):
    """Email delivery status."""

    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    BOUNCED = "bounced"
    COMPLAINED = "complained"
    FAILED = "failed"


class DomainStatus(str, Enum):
    """Domain verification status."""

    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class WebhookEvent(str, Enum):
    """Webhook event types."""

    MESSAGE_ACCEPTED = "message.accepted"
    MESSAGE_QUEUED = "message.queued"
    MESSAGE_SENDING = "message.sending"
    MESSAGE_SENT = "message.sent"
    MESSAGE_DELIVERED = "message.delivered"
    MESSAGE_BOUNCED = "message.bounced"
    MESSAGE_DEFERRED = "message.deferred"
    MESSAGE_DROPPED = "message.dropped"
    MESSAGE_OPENED = "message.opened"
    MESSAGE_CLICKED = "message.clicked"
    MESSAGE_UNSUBSCRIBED = "message.unsubscribed"
    MESSAGE_COMPLAINED = "message.complained"
    MESSAGE_FAILED = "message.failed"
    DOMAIN_VERIFIED = "domain.verified"
    DOMAIN_FAILED = "domain.failed"
    ALL = "*"


class EmailAddress(BaseModel):
    """Email address with optional display name."""

    model_config = ConfigDict(populate_by_name=True)

    email: EmailStr
    name: Optional[str] = None


class Tag(BaseModel):
    """Email tag for categorization and tracking."""

    name: str = Field(max_length=50)
    value: str = Field(max_length=100)


class Attachment(BaseModel):
    """Email attachment."""

    filename: str
    content: str  # Base64 encoded
    content_type: Optional[str] = Field(default=None, alias="contentType")


class SendEmailRequest(BaseModel):
    """Request body for sending an email."""

    model_config = ConfigDict(populate_by_name=True)

    from_: Union[str, EmailAddress] = Field(alias="from")
    to: Union[str, EmailAddress, list[Union[str, EmailAddress]]]
    cc: Optional[list[Union[str, EmailAddress]]] = None
    bcc: Optional[list[Union[str, EmailAddress]]] = None
    reply_to: Optional[Union[str, EmailAddress]] = Field(default=None, alias="replyTo")
    subject: str = Field(min_length=1, max_length=998)
    html: Optional[str] = None
    text: Optional[str] = None
    attachments: Optional[list[Attachment]] = None
    tags: Optional[list[Tag]] = None
    headers: Optional[dict[str, str]] = None
    scheduled_at: Optional[datetime] = Field(default=None, alias="scheduledAt")
    metadata: Optional[dict[str, Any]] = None

    @model_validator(mode="after")
    def validate_body(self) -> "SendEmailRequest":
        if not self.html and not self.text:
            raise ValueError("Either 'html' or 'text' must be provided")
        return self


class SendEmailResponse(BaseModel):
    """Response from sending an email."""

    id: str
    status: EmailStatus


class Email(BaseModel):
    """Email details."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    from_: EmailAddress = Field(alias="from")
    to: list[EmailAddress]
    cc: Optional[list[EmailAddress]] = None
    bcc: Optional[list[EmailAddress]] = None
    subject: str
    status: EmailStatus
    created_at: datetime = Field(alias="createdAt")
    sent_at: Optional[datetime] = Field(default=None, alias="sentAt")
    delivered_at: Optional[datetime] = Field(default=None, alias="deliveredAt")
    opened_at: Optional[datetime] = Field(default=None, alias="openedAt")
    clicked_at: Optional[datetime] = Field(default=None, alias="clickedAt")
    tags: Optional[list[Tag]] = None
    metadata: Optional[dict[str, Any]] = None


class EmailListResponse(BaseModel):
    """Response from listing emails."""

    emails: list[Email]
    cursor: Optional[str] = None
    has_more: bool = Field(alias="hasMore")


class DNSRecord(BaseModel):
    """DNS record for domain verification."""

    model_config = ConfigDict(populate_by_name=True)

    type: str
    name: str
    value: str
    verified: bool


class Domain(BaseModel):
    """Domain details."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    domain: str
    status: DomainStatus
    verification_token: Optional[str] = Field(default=None, alias="verificationToken")
    dns_records: Optional[dict[str, DNSRecord]] = Field(default=None, alias="dnsRecords")
    verified_at: Optional[datetime] = Field(default=None, alias="verifiedAt")
    created_at: datetime = Field(alias="createdAt")


class DomainListResponse(BaseModel):
    """Response from listing domains."""

    domains: list[Domain]


class Webhook(BaseModel):
    """Webhook details."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    url: str
    events: list[str]
    enabled: bool
    secret: Optional[str] = None
    created_at: datetime = Field(alias="createdAt")


class WebhookListResponse(BaseModel):
    """Response from listing webhooks."""

    webhooks: list[Webhook]


class Template(BaseModel):
    """Template details."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    subject: str
    html_body: str = Field(alias="htmlBody")
    text_body: Optional[str] = Field(default=None, alias="textBody")
    version: int
    status: str
    created_at: datetime = Field(alias="createdAt")
    updated_at: datetime = Field(alias="updatedAt")


class TemplateRenderResponse(BaseModel):
    """Rendered template output."""

    subject: str
    html: str
    text: Optional[str] = None


class TemplateListResponse(BaseModel):
    """Response from listing templates."""

    templates: list[Template]


class Suppression(BaseModel):
    """Suppression entry."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    email: EmailStr
    reason: str
    source: str
    created_at: datetime = Field(alias="createdAt")


class SuppressionCheckResponse(BaseModel):
    """Suppression check response."""

    email: EmailStr
    suppressed: bool
    reason: Optional[str] = None


class SuppressionListResponse(BaseModel):
    """Response from listing suppressions."""

    suppressions: list[Suppression]


class BulkSuppressionResponse(BaseModel):
    """Response from bulk suppression operations."""

    created: int
    duplicates: int
    invalid: int


class Event(BaseModel):
    """Delivery event details."""

    model_config = ConfigDict(populate_by_name=True)

    id: str
    message_id: Optional[str] = Field(default=None, alias="messageId")
    event_type: str = Field(alias="eventType")
    recipient: Optional[EmailStr] = None
    metadata: Optional[dict[str, Any]] = None
    timestamp: datetime


class EventStats(BaseModel):
    """Event stats summary."""

    total: int
    delivered: int
    bounced: int
    complained: int
    opened: int
    clicked: int


class EventTimeseriesPoint(BaseModel):
    """Event timeseries point."""

    timestamp: datetime
    count: int
    event_type: str = Field(alias="eventType")


class EventListResponse(BaseModel):
    """Response from listing events."""

    events: list[Event]
