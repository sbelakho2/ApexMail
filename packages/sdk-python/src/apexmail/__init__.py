"""
ApexMail Python SDK

Official Python SDK for the ApexMail transactional email API.

Usage:
    from apexmail import ApexMail
    
    client = ApexMail(api_key="am_live_xxxx")
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
    Domain,
    DomainStatus,
    Email,
    EmailAddress,
    EmailStatus,
    SendEmailRequest,
    SendEmailResponse,
    Tag,
    Webhook,
    WebhookEvent,
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
    "Domain",
    "DomainStatus",
    "Email",
    "EmailAddress",
    "EmailStatus",
    "SendEmailRequest",
    "SendEmailResponse",
    "Tag",
    "Webhook",
    "WebhookEvent",
]
