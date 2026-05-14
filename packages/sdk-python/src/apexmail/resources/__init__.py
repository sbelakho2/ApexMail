"""ApexMail API Resources."""
from .domains import AsyncDomainsResource, DomainsResource
from .emails import AsyncEmailsResource, EmailsResource
from .events import AsyncEventsResource, EventsResource
from .analytics import AnalyticsResource, AsyncAnalyticsResource
from .api_keys import ApiKeysResource, AsyncApiKeysResource
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
    "AnalyticsResource",
    "AsyncAnalyticsResource",
    "ApiKeysResource",
    "AsyncApiKeysResource",
    "SuppressionsResource",
    "AsyncSuppressionsResource",
    "TemplatesResource",
    "AsyncTemplatesResource",
    "WebhooksResource",
    "AsyncWebhooksResource",
]