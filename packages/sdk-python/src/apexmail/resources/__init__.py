"""ApexMail API Resources."""
from .domains import AsyncDomainsResource, DomainsResource
from .emails import AsyncEmailsResource, EmailsResource
from .webhooks import AsyncWebhooksResource, WebhooksResource

__all__ = [
    "DomainsResource",
    "AsyncDomainsResource",
    "EmailsResource",
    "AsyncEmailsResource",
    "WebhooksResource",
    "AsyncWebhooksResource",
]