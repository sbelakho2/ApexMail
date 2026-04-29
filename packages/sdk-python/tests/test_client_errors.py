import importlib.util
import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


class FakeResponse:
    def __init__(self, status_code: int, *, headers: dict[str, str] | None = None, json_data=None, text: str = "") -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._json_data = json_data
        self.text = text
        self.content = text.encode("utf-8")

    def json(self):
        if self._json_data is None:
            raise ValueError("no json")
        return self._json_data


class FakeSyncHttpClient:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs

    def close(self) -> None:
        return None


class FakeAsyncHttpClient:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs

    async def aclose(self) -> None:
        return None


class FakeTimeoutException(Exception):
    pass


class FakeNetworkError(Exception):
    pass


httpx_mod = types.ModuleType("httpx")
httpx_mod.Response = FakeResponse
httpx_mod.Client = FakeSyncHttpClient
httpx_mod.AsyncClient = FakeAsyncHttpClient
httpx_mod.TimeoutException = FakeTimeoutException
httpx_mod.NetworkError = FakeNetworkError
sys.modules["httpx"] = httpx_mod

apexmail_pkg = types.ModuleType("apexmail")
apexmail_pkg.__path__ = [str(ROOT)]

resources_pkg = types.ModuleType("apexmail.resources")
resources_pkg.__path__ = [str(ROOT / "resources")]

for module_name, class_names in {
    "domains": ["AsyncDomainsResource", "DomainsResource"],
    "emails": ["AsyncEmailsResource", "EmailsResource"],
    "events": ["AsyncEventsResource", "EventsResource"],
    "suppressions": ["AsyncSuppressionsResource", "SuppressionsResource"],
    "templates": ["AsyncTemplatesResource", "TemplatesResource"],
    "webhooks": ["AsyncWebhooksResource", "WebhooksResource"],
}.items():
    module = types.ModuleType(f"apexmail.resources.{module_name}")
    for class_name in class_names:
        setattr(module, class_name, type(class_name, (), {"__init__": lambda self, client: None}))
    sys.modules[f"apexmail.resources.{module_name}"] = module

sys.modules["apexmail"] = apexmail_pkg
sys.modules["apexmail.resources"] = resources_pkg

exceptions_spec = importlib.util.spec_from_file_location("apexmail.exceptions", ROOT / "exceptions.py")
exceptions_module = importlib.util.module_from_spec(exceptions_spec)
sys.modules["apexmail.exceptions"] = exceptions_module
assert exceptions_spec.loader is not None
exceptions_spec.loader.exec_module(exceptions_module)

client_spec = importlib.util.spec_from_file_location("apexmail.client", ROOT / "client.py")
client_module = importlib.util.module_from_spec(client_spec)
sys.modules["apexmail.client"] = client_module
assert client_spec.loader is not None
client_spec.loader.exec_module(client_module)

BaseClient = client_module.BaseClient
RateLimitError = exceptions_module.RateLimitError
ServerError = exceptions_module.ServerError


class ClientErrorHandlingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = BaseClient(api_key="am_test_1234567890abcdef", base_url="https://api.apexmail.ee")

    def test_handle_response_raises_rate_limit_error_with_retry_after(self) -> None:
        response = FakeResponse(
            429,
            headers={"Retry-After": "120"},
            json_data={"error": "Slow down", "code": "RATE_LIMITED"},
        )

        with self.assertRaises(RateLimitError) as context:
            self.client._handle_response(response)

        self.assertEqual(context.exception.code, "RATE_LIMITED")
        self.assertEqual(context.exception.retry_after, 120)
        self.assertEqual(context.exception.status_code, 429)

    def test_handle_response_raises_server_error_for_5xx(self) -> None:
        response = FakeResponse(
            503,
            json_data={"error": "Temporary outage", "code": "SERVICE_UNAVAILABLE"},
        )

        with self.assertRaises(ServerError) as context:
            self.client._handle_response(response)

        self.assertEqual(context.exception.code, "SERVICE_UNAVAILABLE")
        self.assertEqual(context.exception.status_code, 500)


if __name__ == "__main__":
    unittest.main()