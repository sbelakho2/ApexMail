import dataclasses
import importlib.util
import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


class ValidationError(Exception):
    pass


@dataclasses.dataclass
class Template:
    data: dict | None = None


@dataclasses.dataclass
class TemplateRenderResponse:
    subject: str
    html: str
    text: str | None = None


apexmail_pkg = types.ModuleType("apexmail")
apexmail_pkg.__path__ = [str(ROOT)]

resources_pkg = types.ModuleType("apexmail.resources")
resources_pkg.__path__ = [str(ROOT / "resources")]

exceptions_mod = types.ModuleType("apexmail.exceptions")
exceptions_mod.ValidationError = ValidationError

models_mod = types.ModuleType("apexmail.models")
models_mod.Template = Template
models_mod.TemplateRenderResponse = TemplateRenderResponse

sys.modules["apexmail"] = apexmail_pkg
sys.modules["apexmail.resources"] = resources_pkg
sys.modules["apexmail.exceptions"] = exceptions_mod
sys.modules["apexmail.models"] = models_mod

spec = importlib.util.spec_from_file_location(
    "apexmail.resources.templates",
    ROOT / "resources" / "templates.py",
)
templates_module = importlib.util.module_from_spec(spec)
sys.modules["apexmail.resources.templates"] = templates_module
assert spec.loader is not None
spec.loader.exec_module(templates_module)

AsyncTemplatesResource = templates_module.AsyncTemplatesResource
TemplatesResource = templates_module.TemplatesResource


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def _request(self, method: str, path: str, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if not path.endswith("/render"):
            return {"template": {"data": {"id": "template-123", "name": "Welcome v2"}}}
        return {
            "subject": "Welcome",
            "html": "<p>Hello Alice</p>",
            "text": "Hello Alice",
        }


class FakeAsyncClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def _request(self, method: str, path: str, **kwargs):
        self.calls.append({"method": method, "path": path, **kwargs})
        if not path.endswith("/render"):
            return {"template": {"data": {"id": "template-123", "name": "Welcome v2"}}}
        return {
            "subject": "Welcome",
            "html": "<p>Hello Alice</p>",
            "text": "Hello Alice",
        }


class TemplatesRenderTests(unittest.TestCase):
    def test_render_uses_variables_payload(self) -> None:
        client = FakeClient()
        resource = TemplatesResource(client)

        response = resource.render("template-123", {"first_name": "Alice"})

        self.assertEqual(client.calls[0]["method"], "POST")
        self.assertEqual(client.calls[0]["path"], "/v1/templates/template-123/render")
        self.assertEqual(client.calls[0]["json"], {"variables": {"first_name": "Alice"}})
        self.assertEqual(response.subject, "Welcome")
        self.assertEqual(response.html, "<p>Hello Alice</p>")
        self.assertEqual(response.text, "Hello Alice")

    def test_render_sends_empty_variables_object(self) -> None:
        client = FakeClient()
        resource = TemplatesResource(client)

        resource.render("template-123", {})

        self.assertEqual(client.calls[0]["json"], {"variables": {}})

    def test_update_uses_patch_payload(self) -> None:
        client = FakeClient()
        resource = TemplatesResource(client)

        response = resource.update("template-123", name="Welcome v2", subject="Hello")

        self.assertEqual(client.calls[0]["method"], "PATCH")
        self.assertEqual(client.calls[0]["path"], "/v1/templates/template-123")
        self.assertEqual(client.calls[0]["json"], {"name": "Welcome v2", "subject": "Hello"})
        self.assertEqual(response.data["name"], "Welcome v2")

    def test_update_rejects_empty_payload(self) -> None:
        client = FakeClient()
        resource = TemplatesResource(client)

        with self.assertRaises(ValidationError):
            resource.update("template-123")


class AsyncTemplatesRenderTests(unittest.IsolatedAsyncioTestCase):
    async def test_render_uses_variables_payload(self) -> None:
        client = FakeAsyncClient()
        resource = AsyncTemplatesResource(client)

        response = await resource.render("template-123", {"first_name": "Alice"})

        self.assertEqual(client.calls[0]["method"], "POST")
        self.assertEqual(client.calls[0]["path"], "/v1/templates/template-123/render")
        self.assertEqual(client.calls[0]["json"], {"variables": {"first_name": "Alice"}})
        self.assertEqual(response.subject, "Welcome")
        self.assertEqual(response.html, "<p>Hello Alice</p>")
        self.assertEqual(response.text, "Hello Alice")

    async def test_update_uses_patch_payload(self) -> None:
        client = FakeAsyncClient()
        resource = AsyncTemplatesResource(client)

        response = await resource.update("template-123", name="Welcome v2", subject="Hello")

        self.assertEqual(client.calls[0]["method"], "PATCH")
        self.assertEqual(client.calls[0]["path"], "/v1/templates/template-123")
        self.assertEqual(client.calls[0]["json"], {"name": "Welcome v2", "subject": "Hello"})
        self.assertEqual(response.data["name"], "Welcome v2")

    async def test_update_rejects_empty_payload(self) -> None:
        client = FakeAsyncClient()
        resource = AsyncTemplatesResource(client)

        with self.assertRaises(ValidationError):
            await resource.update("template-123")