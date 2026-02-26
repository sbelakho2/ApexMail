"""
ApexMail Python SDK

Official Python SDK for the ApexMail transactional email API.

Usage:
    from apexmail import ApexMail
    
    client = ApexMail(api_key="YOUR_API_KEY")
    response = client.emails.send(
        from_="hello@example.com",
        to="user@example.com",
        subject="Welcome!",
        html="<h1>Hello!</h1>"
    )
"""

from .client import ApexMail, AsyncApexMail
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
from .models import (
    Attachment,
    BulkSuppressionResponse,
    DNSRecord,
    Domain,
    DomainListResponse,
    DomainStatus,
    Email,
    EmailAddress,
    EmailListResponse,
    EmailStatus,
    Event,
    EventListResponse,
    EventStats,
    EventTimeseriesPoint,
    SendEmailRequest,
    SendEmailResponse,
    Suppression,
    SuppressionCheckResponse,
    SuppressionListResponse,
    Tag,
    Template,
    TemplateListResponse,
    TemplateRenderResponse,
    Webhook,
    WebhookEvent,
    WebhookListResponse,
)

__version__ = "1.0.0"
__all__ = [
    # Client
    "ApexMail",
    "AsyncApexMail",
    # Exceptions
    "ApexMailError",
    "AuthenticationError",
    "ConflictError",
    "ForbiddenError",
    "NotFoundError",
    "RateLimitError",
    "ServerError",
    "ValidationError",
    # Models
    "Attachment",
    "BulkSuppressionResponse",
    "DNSRecord",
    "Domain",
    "DomainListResponse",
    "DomainStatus",
    "Email",
    "EmailAddress",
    "EmailListResponse",
    "EmailStatus",
    "Event",
    "EventListResponse",
    "EventStats",
    "EventTimeseriesPoint",
    "SendEmailRequest",
    "SendEmailResponse",
    "Suppression",
    "SuppressionCheckResponse",
    "SuppressionListResponse",
    "Tag",
    "Template",
    "TemplateListResponse",
    "TemplateRenderResponse",
    "Webhook",
    "WebhookEvent",
    "WebhookListResponse",
]
