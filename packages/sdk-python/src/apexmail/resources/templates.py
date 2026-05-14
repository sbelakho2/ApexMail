"""
Templates Resource

API operations for template management.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Optional

from ..exceptions import ValidationError
from ..models import Template, TemplateRenderResponse

if TYPE_CHECKING:
    from ..client import ApexMail, AsyncApexMail

_ID_REGEX = re.compile(r"^[a-zA-Z0-9_-]{1,128}$")


def _validate_id(resource_id: str, resource_name: str) -> None:
    if not resource_id or not _ID_REGEX.match(resource_id):
        raise ValidationError(
            f'Invalid {resource_name} ID format: "{resource_id}". '
            'IDs must be 1-128 alphanumeric characters, hyphens, or underscores.'
        )


def _extract_list(data: Any, key: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for candidate in (key, "data", "items"):
            value = data.get(candidate)
            if isinstance(value, list):
                return value
    return []


def _extract_item(data: Any, key: str) -> dict[str, Any]:
    if isinstance(data, dict) and key in data and isinstance(data[key], dict):
        return data[key]
    return data if isinstance(data, dict) else {}


class TemplatesResource:
    """Synchronous templates resource."""

    def __init__(self, client: "ApexMail") -> None:
        self._client = client

    def create(
        self,
        *,
        name: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
    ) -> Template:
        payload = {
            "name": name,
            "subject": subject,
            "htmlBody": html_body,
            "textBody": text_body,
        }
        data = self._client._request("POST", "/v1/templates", json=payload)
        return Template(**_extract_item(data, "template"))

    def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
    ) -> list[Template]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        data = self._client._request("GET", "/v1/templates", params=params or None)
        return [Template(**item) for item in _extract_list(data, "templates")]

    def get(self, template_id: str) -> Template:
        _validate_id(template_id, "template")
        data = self._client._request("GET", f"/v1/templates/{template_id}")
        return Template(**_extract_item(data, "template"))

    def get_by_slug(self, slug: str) -> Template:
        _validate_id(slug, "template slug")
        data = self._client._request("GET", f"/v1/templates/slug/{slug}")
        return Template(**_extract_item(data, "template"))

    def update(
        self,
        template_id: str,
        *,
        name: Optional[str] = None,
        subject: Optional[str] = None,
        html_body: Optional[str] = None,
        text_body: Optional[str] = None,
    ) -> Template:
        _validate_id(template_id, "template")
        payload: dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if subject is not None:
            payload["subject"] = subject
        if html_body is not None:
            payload["htmlBody"] = html_body
        if text_body is not None:
            payload["textBody"] = text_body
        if not payload:
            raise ValidationError("Update payload must include at least one field")
        data = self._client._request("PUT", f"/v1/templates/{template_id}", json=payload)
        return Template(**_extract_item(data, "template"))

    def duplicate(self, template_id: str) -> Template:
        _validate_id(template_id, "template")
        data = self._client._request(
            "POST", f"/v1/templates/{template_id}/duplicate"
        )
        return Template(**_extract_item(data, "template"))

    def rollback(self, template_id: str, version: int) -> Template:
        _validate_id(template_id, "template")
        data = self._client._request(
            "POST",
            f"/v1/templates/{template_id}/rollback",
            json={"version": version},
        )
        return Template(**_extract_item(data, "template"))

    def delete(self, template_id: str) -> None:
        _validate_id(template_id, "template")
        self._client._request("DELETE", f"/v1/templates/{template_id}")

    def render(self, template_id: str, variables: dict[str, Any]) -> TemplateRenderResponse:
        _validate_id(template_id, "template")
        data = self._client._request(
            "POST",
            f"/v1/templates/{template_id}/render",
            json={"variables": variables},
        )
        return TemplateRenderResponse(**data)


class AsyncTemplatesResource:
    """Asynchronous templates resource."""

    def __init__(self, client: "AsyncApexMail") -> None:
        self._client = client

    async def create(
        self,
        *,
        name: str,
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
    ) -> Template:
        payload = {
            "name": name,
            "subject": subject,
            "htmlBody": html_body,
            "textBody": text_body,
        }
        data = await self._client._request("POST", "/v1/templates", json=payload)
        return Template(**_extract_item(data, "template"))

    async def list(
        self,
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        cursor: Optional[int] = None,
    ) -> list[Template]:
        params: dict[str, Any] = {}
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        if cursor is not None:
            params["cursor"] = cursor
        data = await self._client._request("GET", "/v1/templates", params=params or None)
        return [Template(**item) for item in _extract_list(data, "templates")]

    async def get(self, template_id: str) -> Template:
        _validate_id(template_id, "template")
        data = await self._client._request("GET", f"/v1/templates/{template_id}")
        return Template(**_extract_item(data, "template"))

    async def get_by_slug(self, slug: str) -> Template:
        _validate_id(slug, "template slug")
        data = await self._client._request("GET", f"/v1/templates/slug/{slug}")
        return Template(**_extract_item(data, "template"))

    async def update(
        self,
        template_id: str,
        *,
        name: Optional[str] = None,
        subject: Optional[str] = None,
        html_body: Optional[str] = None,
        text_body: Optional[str] = None,
    ) -> Template:
        _validate_id(template_id, "template")
        payload: dict[str, Any] = {}
        if name is not None:
            payload["name"] = name
        if subject is not None:
            payload["subject"] = subject
        if html_body is not None:
            payload["htmlBody"] = html_body
        if text_body is not None:
            payload["textBody"] = text_body
        if not payload:
            raise ValidationError("Update payload must include at least one field")
        data = await self._client._request("PUT", f"/v1/templates/{template_id}", json=payload)
        return Template(**_extract_item(data, "template"))

    async def duplicate(self, template_id: str) -> Template:
        _validate_id(template_id, "template")
        data = await self._client._request(
            "POST", f"/v1/templates/{template_id}/duplicate"
        )
        return Template(**_extract_item(data, "template"))

    async def rollback(self, template_id: str, version: int) -> Template:
        _validate_id(template_id, "template")
        data = await self._client._request(
            "POST",
            f"/v1/templates/{template_id}/rollback",
            json={"version": version},
        )
        return Template(**_extract_item(data, "template"))

    async def delete(self, template_id: str) -> None:
        _validate_id(template_id, "template")
        await self._client._request("DELETE", f"/v1/templates/{template_id}")

    async def render(self, template_id: str, variables: dict[str, Any]) -> TemplateRenderResponse:
        _validate_id(template_id, "template")
        data = await self._client._request(
            "POST",
            f"/v1/templates/{template_id}/render",
            json={"variables": variables},
        )
        return TemplateRenderResponse(**data)
