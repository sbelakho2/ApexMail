"""ApexMail API Resources."""
from .domains import AsyncDomainsResource, DomainsResource
from .emails import AsyncEmailsResource, EmailsResource
from .events import AsyncEventsResource, EventsResource
from .suppressions import AsyncSuppressionsResource, SuppressionsResource
from .templates import AsyncTemplatesResource, TemplatesResource
from .webhooks import AsyncWebhooksResource, WebhooksResource

__all__ = [
    "DomainsResource",
    "AsyncDomainsResource",
    "EmailsResource",
    "AsyncEmailsResource",
    "EventsResource",
    "AsyncEventsResource",
    "SuppressionsResource",
    "AsyncSuppressionsResource",
    "TemplatesResource",
    "AsyncTemplatesResource",
    "WebhooksResource",
    "AsyncWebhooksResource",
]