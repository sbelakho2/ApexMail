"""Analytics Resource.

The analytics API exposes typed subpaths only (there is no GET /v1/analytics):
/v1/analytics/dashboard, /volume, /engagement, /deliverability,
/subject-line (POST) and /export. Every GET subpath accepts exactly the
query parameters {from, to, interval} (interval: hour | day | week | month).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

_VALID_INTERVALS = ("hour", "day", "week", "month")


def _analytics_query(
    from_: Optional[str] = None,
    to: Optional[str] = None,
    interval: Optional[str] = None,
) -> dict[str, Any]:
    if interval is not None and interval not in _VALID_INTERVALS:
        raise ValueError(
            f"interval must be one of {', '.join(_VALID_INTERVALS)} (got {interval!r})"
        )
    params: dict[str, Any] = {}
    if from_:
        params["from"] = from_
    if to:
        params["to"] = to
    if interval:
        params["interval"] = interval
    return params


class AnalyticsResource:
    """Synchronous analytics resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def dashboard(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Dashboard counters: {total_sent, total_delivered, total_bounced,
        total_opened, total_clicked, delivery_rate, open_rate, click_rate}."""
        return self._client._request(
            "GET", "/v1/analytics/dashboard", params=_analytics_query(from_, to, interval) or None
        )

    def volume(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Volume timeseries: [{date, sent, delivered, bounced}, ...]."""
        return self._client._request(
            "GET", "/v1/analytics/volume", params=_analytics_query(from_, to, interval) or None
        )

    def engagement(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Engagement rates + timeseries: {open_rate, click_rate,
        unsubscribe_rate, timeseries: [{date, opens, clicks}]}."""
        return self._client._request(
            "GET", "/v1/analytics/engagement", params=_analytics_query(from_, to, interval) or None
        )

    def deliverability(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deliverability rates: {delivery_rate, bounce_rate,
        complaint_rate, inbox_rate}."""
        return self._client._request(
            "GET", "/v1/analytics/deliverability", params=_analytics_query(from_, to, interval) or None
        )

    def analyze_subject_line(self, subject: str) -> dict[str, Any]:
        """Analyze a subject line (POST /subject-line with body {subject})."""
        return self._client._request("POST", "/v1/analytics/subject-line", json={"subject": subject})

    def export(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        format: str = "json",
    ) -> dict[str, Any]:
        """Start an analytics export job ({job_id?, download_url?, status})."""
        params: dict[str, Any] = {"format": format}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        return self._client._request("GET", "/v1/analytics/export", params=params)

    def get(
        self,
        *,
        from_: str,
        to: str,
        group_by: Optional[str] = None,
        tag: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deprecated: GET /v1/analytics does not exist on the API.

        Kept as an alias of :meth:`dashboard` for backwards compatibility;
        ``group_by`` is mapped to the API's ``interval`` parameter.
        ``tag``/``domain`` are ignored (the API has no such filters).
        """
        import warnings

        warnings.warn(
            "analytics.get() is deprecated: the API exposes typed subpaths. "
            "Use dashboard()/volume()/engagement()/deliverability().",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.dashboard(from_=from_, to=to, interval=group_by)


class AsyncAnalyticsResource:
    """Asynchronous analytics resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def dashboard(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Dashboard counters (see the sync resource)."""
        return await self._client._request(
            "GET", "/v1/analytics/dashboard", params=_analytics_query(from_, to, interval) or None
        )

    async def volume(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Volume timeseries (see the sync resource)."""
        return await self._client._request(
            "GET", "/v1/analytics/volume", params=_analytics_query(from_, to, interval) or None
        )

    async def engagement(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Engagement rates + timeseries (see the sync resource)."""
        return await self._client._request(
            "GET", "/v1/analytics/engagement", params=_analytics_query(from_, to, interval) or None
        )

    async def deliverability(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        interval: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deliverability rates (see the sync resource)."""
        return await self._client._request(
            "GET", "/v1/analytics/deliverability", params=_analytics_query(from_, to, interval) or None
        )

    async def analyze_subject_line(self, subject: str) -> dict[str, Any]:
        """Analyze a subject line (POST /subject-line)."""
        return await self._client._request("POST", "/v1/analytics/subject-line", json={"subject": subject})

    async def export(
        self,
        *,
        from_: Optional[str] = None,
        to: Optional[str] = None,
        format: str = "json",
    ) -> dict[str, Any]:
        """Start an analytics export job."""
        params: dict[str, Any] = {"format": format}
        if from_:
            params["from"] = from_
        if to:
            params["to"] = to
        return await self._client._request("GET", "/v1/analytics/export", params=params)

    async def get(
        self,
        *,
        from_: str,
        to: str,
        group_by: Optional[str] = None,
        tag: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        """Deprecated alias of dashboard() (see the sync resource)."""
        import warnings

        warnings.warn(
            "analytics.get() is deprecated: the API exposes typed subpaths. "
            "Use dashboard()/volume()/engagement()/deliverability().",
            DeprecationWarning,
            stacklevel=2,
        )
        return await self.dashboard(from_=from_, to=to, interval=group_by)
