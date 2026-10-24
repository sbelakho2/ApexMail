"""A real (in-process) Mollie API double for the dogfood-v2 harness.

Mollie's protocol is not a signed-notification protocol. The contract this
module implements is the provider's:

  * a webhook is ``POST`` with ``Content-Type:
    application/x-www-form-urlencoded`` and a single ``id`` parameter —
    ``id=tr_…`` for a payment, ``id=re_…`` for a refund. There is no
    signature, status or event type in the request;
  * verification is an authenticated fetch: ``GET
    https://api.mollie.com/v2/payments/{id}`` with ``Authorization: Bearer
    <MOLLIE_API_KEY>``;
  * amounts are decimal strings (``{"currency":"EUR","value":"12.34"}``),
    never minor units;
  * payment statuses are ``open | pending | authorized | paid | failed |
    canceled | expired | refunded | charged_back`` — only the settled/negative
    states are facts;
  * refunds are created under a payment and have their own ``re_…`` id;
  * customers are ``cst_…`` objects, mandates ``mdt_…``, subscriptions
    ``sub_…``; settlements reconcile payouts.

``MockMollieServer`` serves that wire protocol on a free port so a probe (or
a local stack configured with ``MOLLIE_API_BASE_URL``) can drive checkout,
refund, customer, subscription and settlement flows without the network.
``post_webhook`` is the companion helper: it posts the id-only body to the
application's ``/webhooks/mollie`` route, exactly as Mollie would.
"""
from __future__ import annotations

import hashlib
import json
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

WEBHOOK_PATH = "/webhooks/mollie"
API_PREFIX = "/v2"

PAYMENT_STATUSES = (
    "open",
    "pending",
    "authorized",
    "paid",
    "failed",
    "canceled",
    "expired",
    "refunded",
    "charged_back",
)
REFUND_STATUSES = ("queued", "pending", "processing", "refunded", "failed", "canceled")


def wire_value(cents: int) -> str:
    """Mollie's amount.value: a decimal string with two decimals."""
    cents = int(cents)
    return f"{cents // 100}.{cents % 100:02d}"


def money(currency: str, cents: int) -> dict:
    return {"currency": currency.upper(), "value": wire_value(cents)}


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())


def webhook_form(object_id: str) -> bytes:
    """The exact body Mollie posts: one urlencoded ``id`` parameter."""
    return f"id={object_id}".encode()


def webhook_headers() -> dict[str, str]:
    return {"Content-Type": "application/x-www-form-urlencoded"}


class MockMollie:
    """The provider's in-memory object store (payments, refunds, …)."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.payments: dict[str, dict] = {}
        self.refunds: dict[str, dict] = {}          # refund id -> refund (with paymentId)
        self.customers: dict[str, dict] = {}
        self.mandates: dict[str, dict] = {}         # mandate id -> mandate (with customerId)
        self.subscriptions: dict[str, dict] = {}    # subscription id -> subscription
        self.settlements: dict[str, dict] = {}

    # ── payments ───────────────────────────────────────────────────────
    def create_payment(self, body: dict | None = None) -> dict:
        body = dict(body or {})
        payment_id = _id("tr")
        amount = body.get("amount") or money("EUR", 0)
        payment = {
            "resource": "payment",
            "id": payment_id,
            "mode": "test",
            "createdAt": _now(),
            "status": body.get("status", "open"),
            "isCancelable": False,
            "amount": amount,
            "amountRefunded": money(amount.get("currency", "EUR"), 0),
            "description": body.get("description", "ApexMail dogfood payment"),
            "method": body.get("method"),
            "metadata": body.get("metadata") or {},
            "locale": body.get("locale", "en_US"),
            "sequenceType": body.get("sequenceType", "oneoff"),
            "customerId": body.get("customerId"),
            "mandateId": body.get("mandateId"),
            "webhookUrl": body.get("webhookUrl") or f"/{WEBHOOK_PATH.lstrip('/')}",
            "redirectUrl": body.get("redirectUrl"),
            "profileId": body.get("profileId", "pfl_dogfood"),
            "_links": {
                "self": {"href": f"https://api.mollie.com/v2/payments/{payment_id}", "type": "application/hal+json"},
                "checkout": {
                    "href": f"https://www.mollie.com/checkout/dogfood/{payment_id}",
                    "type": "text/html",
                },
            },
        }
        with self.lock:
            self.payments[payment_id] = payment
        return payment

    def get_payment(self, payment_id: str) -> dict | None:
        with self.lock:
            return self.payments.get(payment_id)

    def set_payment_status(self, payment_id: str, status: str) -> dict | None:
        if status not in PAYMENT_STATUSES:
            raise ValueError(f"unknown Mollie payment status {status!r}")
        with self.lock:
            payment = self.payments.get(payment_id)
            if payment is None:
                return None
            payment["status"] = status
            if status == "paid":
                payment["paidAt"] = _now()
            if status in ("refunded", "charged_back"):
                payment["amountRefunded"] = dict(payment["amount"])
            return payment

    # ── refunds ────────────────────────────────────────────────────────
    def create_refund(self, payment_id: str, body: dict | None = None) -> dict | None:
        body = dict(body or {})
        with self.lock:
            payment = self.payments.get(payment_id)
            if payment is None:
                return None
            refund_id = _id("re")
            amount = body.get("amount") or payment["amount"]
            refund = {
                "resource": "refund",
                "id": refund_id,
                "paymentId": payment_id,
                "status": body.get("status", "queued"),
                "createdAt": _now(),
                "amount": amount,
                "description": body.get("description", "ApexMail dogfood refund"),
                "metadata": body.get("metadata") or {},
                "_links": {
                    "self": {
                        "href": f"https://api.mollie.com/v2/payments/{payment_id}/refunds/{refund_id}",
                        "type": "application/hal+json",
                    },
                    "payment": {
                        "href": f"https://api.mollie.com/v2/payments/{payment_id}",
                        "type": "application/hal+json",
                    },
                },
            }
            self.refunds[refund_id] = refund
            return refund

    def get_refund(self, payment_id: str, refund_id: str) -> dict | None:
        with self.lock:
            refund = self.refunds.get(refund_id)
            if refund is None or refund["paymentId"] != payment_id:
                return None
            return refund

    def set_refund_status(self, refund_id: str, status: str) -> dict | None:
        if status not in REFUND_STATUSES:
            raise ValueError(f"unknown Mollie refund status {status!r}")
        with self.lock:
            refund = self.refunds.get(refund_id)
            if refund is None:
                return None
            refund["status"] = status
            if status == "refunded":
                payment = self.payments.get(refund["paymentId"])
                if payment is not None:
                    payment["status"] = "refunded"
                    payment["amountRefunded"] = dict(refund["amount"])
            return refund

    # ── customers / mandates / subscriptions ───────────────────────────
    def create_customer(self, body: dict | None = None) -> dict:
        body = dict(body or {})
        customer_id = _id("cst")
        customer = {
            "resource": "customer",
            "id": customer_id,
            "mode": "test",
            "name": body.get("name", "ApexMail dogfood customer"),
            "email": body.get("email", "dogfood@apexmail.test"),
            "locale": body.get("locale", "en_US"),
            "metadata": body.get("metadata") or {},
            "createdAt": _now(),
            "_links": {
                "self": {"href": f"https://api.mollie.com/v2/customers/{customer_id}"},
                "mandates": {"href": f"https://api.mollie.com/v2/customers/{customer_id}/mandates"},
                "subscriptions": {"href": f"https://api.mollie.com/v2/customers/{customer_id}/subscriptions"},
            },
        }
        with self.lock:
            self.customers[customer_id] = customer
        return customer

    def get_customer(self, customer_id: str) -> dict | None:
        with self.lock:
            return self.customers.get(customer_id)

    def create_mandate(self, customer_id: str, body: dict | None = None) -> dict | None:
        """A mandate normally appears with the first payment; the mock can
        mint one directly for settlement/recurring tests."""
        body = dict(body or {})
        with self.lock:
            if customer_id not in self.customers:
                return None
            mandate_id = _id("mdt")
            mandate = {
                "resource": "mandate",
                "id": mandate_id,
                "customerId": customer_id,
                "mode": "test",
                "status": body.get("status", "valid"),
                "method": body.get("method", "directdebit"),
                "details": body.get("details") or {"consumerName": "ApexMail Dogfood"},
                "createdAt": _now(),
            }
            self.mandates[mandate_id] = mandate
            return mandate

    def get_mandate(self, customer_id: str, mandate_id: str) -> dict | None:
        with self.lock:
            mandate = self.mandates.get(mandate_id)
            if mandate is None or mandate["customerId"] != customer_id:
                return None
            return mandate

    def create_subscription(self, customer_id: str, body: dict | None = None) -> dict | None:
        body = dict(body or {})
        with self.lock:
            if customer_id not in self.customers:
                return None
            subscription_id = _id("sub")
            subscription = {
                "resource": "subscription",
                "id": subscription_id,
                "customerId": customer_id,
                "mode": "test",
                "status": body.get("status", "active"),
                "amount": body.get("amount") or money("EUR", 0),
                "times": body.get("times"),
                "interval": body.get("interval", "1 month"),
                "startDate": body.get("startDate", time.strftime("%Y-%m-%d", time.gmtime())),
                "description": body.get("description", "ApexMail dogfood subscription"),
                "method": body.get("method"),
                "webhookUrl": body.get("webhookUrl"),
                "metadata": body.get("metadata") or {},
                "createdAt": _now(),
            }
            self.subscriptions[subscription_id] = subscription
            return subscription

    def get_subscription(self, customer_id: str, subscription_id: str) -> dict | None:
        with self.lock:
            subscription = self.subscriptions.get(subscription_id)
            if subscription is None or subscription["customerId"] != customer_id:
                return None
            return subscription

    def cancel_subscription(self, customer_id: str, subscription_id: str) -> dict | None:
        with self.lock:
            subscription = self.get_subscription(customer_id, subscription_id)
            if subscription is None:
                return None
            subscription["status"] = "canceled"
            subscription["canceledAt"] = _now()
            return subscription

    # ── settlements ────────────────────────────────────────────────────
    def list_settlements(self) -> dict:
        with self.lock:
            return {"count": len(self.settlements), "_embedded": {"settlements": list(self.settlements.values())}}

    def get_settlement(self, settlement_id: str) -> dict | None:
        with self.lock:
            return self.settlements.get(settlement_id)


# A process-wide store the fixture can consult when it emulates the app's
# authenticated fetch. Probes that start a real server get their own store.
MOCK = MockMollie()


class _Handler(BaseHTTPRequestHandler):
    store: MockMollie

    def log_message(self, *args):  # noqa: D102
        pass

    # ── plumbing ───────────────────────────────────────────────────────
    def _body(self) -> dict:
        length = int(self.headers.get("content-length", "0") or "0")
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return {}

    def _json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/hal+json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status: int, title: str, detail: str = "") -> None:
        self._json(status, {"status": status, "title": title, "detail": detail or title})

    def _authorised(self) -> bool:
        header = self.headers.get("authorization", "")
        return header.startswith("Bearer ") and len(header) > len("Bearer ")

    def _not_found(self, what: str, object_id: str) -> None:
        self._json(
            404,
            {
                "status": 404,
                "title": "Not found",
                "detail": f"No {what} exists for id {object_id}",
                "field": "id",
            },
        )

    # ── routing ────────────────────────────────────────────────────────
    def do_GET(self):  # noqa: N802
        self._route("GET")

    def do_POST(self):  # noqa: N802
        self._route("POST")

    def do_DELETE(self):  # noqa: N802
        self._route("DELETE")

    def _route(self, method: str) -> None:
        path = urlparse(self.path).path
        segments = [segment for segment in path.strip("/").split("/") if segment]
        if not segments or segments[0] != API_PREFIX.strip("/"):
            return self._error(404, "Not found", f"No route for {path}")
        # Mollie authenticates every API call with the secret key.
        if not self._authorised():
            return self._json(
                401,
                {
                    "status": 401,
                    "title": "Unauthorized",
                    "detail": "Missing or invalid authentication. Use a Bearer token.",
                },
            )
        parts = segments[1:]
        try:
            if parts == ["payments"] and method == "POST":
                return self._json(201, self.store.create_payment(self._body()))
            if len(parts) == 2 and parts[0] == "payments" and method == "GET":
                payment = self.store.get_payment(parts[1])
                return self._json(200, payment) if payment else self._not_found("payment", parts[1])
            if len(parts) == 3 and parts[0] == "payments" and parts[2] == "refunds" and method == "POST":
                refund = self.store.create_refund(parts[1], self._body())
                return self._json(201, refund) if refund else self._not_found("payment", parts[1])
            if len(parts) == 3 and parts[0] == "payments" and parts[2] == "refunds" and method == "GET":
                with self.store.lock:
                    refunds = [
                        r for r in self.store.refunds.values() if r["paymentId"] == parts[1]
                    ]
                return self._json(
                    200,
                    {"count": len(refunds), "_embedded": {"refunds": refunds}},
                )
            if len(parts) == 4 and parts[0] == "payments" and parts[2] == "refunds" and method == "GET":
                refund = self.store.get_refund(parts[1], parts[3])
                return self._json(200, refund) if refund else self._not_found("refund", parts[3])
            if parts == ["customers"] and method == "POST":
                return self._json(201, self.store.create_customer(self._body()))
            if len(parts) == 2 and parts[0] == "customers" and method == "GET":
                customer = self.store.get_customer(parts[1])
                return self._json(200, customer) if customer else self._not_found("customer", parts[1])
            if len(parts) == 3 and parts[0] == "customers" and parts[2] == "mandates" and method == "POST":
                mandate = self.store.create_mandate(parts[1], self._body())
                return self._json(201, mandate) if mandate else self._not_found("customer", parts[1])
            if len(parts) == 4 and parts[0] == "customers" and parts[2] == "mandates" and method == "GET":
                mandate = self.store.get_mandate(parts[1], parts[3])
                return self._json(200, mandate) if mandate else self._not_found("mandate", parts[3])
            if len(parts) == 3 and parts[0] == "customers" and parts[2] == "subscriptions" and method == "POST":
                subscription = self.store.create_subscription(parts[1], self._body())
                return (
                    self._json(201, subscription)
                    if subscription
                    else self._not_found("customer", parts[1])
                )
            if len(parts) == 3 and parts[0] == "customers" and parts[2] == "subscriptions" and method == "GET":
                with self.store.lock:
                    rows = [
                        s for s in self.store.subscriptions.values() if s["customerId"] == parts[1]
                    ]
                return self._json(200, {"count": len(rows), "_embedded": {"subscriptions": rows}})
            if len(parts) == 4 and parts[0] == "customers" and parts[2] == "subscriptions":
                subscription = self.store.get_subscription(parts[1], parts[3])
                if subscription is None:
                    return self._not_found("subscription", parts[3])
                if method == "GET":
                    return self._json(200, subscription)
                if method == "DELETE":
                    return self._json(200, self.store.cancel_subscription(parts[1], parts[3]))
            if parts == ["settlements"] and method == "GET":
                return self._json(200, self.store.list_settlements())
            if len(parts) == 2 and parts[0] == "settlements" and method == "GET":
                settlement = self.store.get_settlement(parts[1])
                return self._json(200, settlement) if settlement else self._not_found("settlement", parts[1])
            return self._error(404, "Not found", f"No route for {method} {path}")
        except Exception as error:  # noqa: BLE001
            return self._error(500, "Mock Mollie error", f"{type(error).__name__}: {error}")


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class MockMollieServer:
    """A threaded mock of ``https://api.mollie.com/v2``.

    Usage::

        server = MockMollieServer()
        server.start()
        try:
            payment = server.store.create_payment({"amount": money("EUR", 2900)})
            post_webhook(app_base_url, payment["id"])
        finally:
            server.stop()
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, store: MockMollie | None = None):
        self.host = host
        self.port = port or _free_port()
        self.store = store or MockMollie()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/v2"

    def start(self) -> "MockMollieServer":
        handler = type("BoundMockMollie", (_Handler,), {"store": self.store})
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "MockMollieServer":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()


def post_webhook(
    app_base_url: str,
    object_id: str,
    *,
    timeout: int = 10,
    path: str = WEBHOOK_PATH,
) -> tuple[int, str]:
    """Post ``id=<object_id>`` to the application's webhook route.

    Returns ``(status, body)``. Mollie retries anything that is not 200, so a
    probe asserts on the status code and on the app's own body.
    """
    url = app_base_url.rstrip("/") + path
    request = Request(
        url,
        data=webhook_form(object_id),
        headers=webhook_headers(),
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal harness posting to the configured app base URL
            return response.status, response.read().decode(errors="replace")
    except Exception as error:  # noqa: BLE001
        # urllib raises HTTPError for a non-2xx answer; surface its status so
        # the probe can make an honest assertion instead of an exception.
        status = getattr(error, "code", 0)
        body = ""
        try:
            body = error.read().decode(errors="replace")
        except Exception:  # noqa: BLE001
            body = str(error)
        return status, body


def content_digest(object_id: str) -> str:
    """The fixture's content-addressed dedupe key for an id-only webhook.

    The live app re-fetches and derives a digest from the fetched object; the
    fixture has no provider state, so it keys on the object id it was handed.
    """
    return hashlib.sha256(object_id.encode()).hexdigest()


def self_test() -> int:
    """Exercise every mock endpoint once. Returns 0 on success."""
    server = MockMollieServer().start()
    failures: list[str] = []
    try:
        payment = server.store.create_payment(
            {"amount": money("EUR", 2900), "description": "self-test", "sequenceType": "first"}
        )
        refund = server.store.create_refund(payment["id"], {"amount": money("EUR", 1000)})
        customer = server.store.create_customer({"email": "selftest@apexmail.test"})
        mandate = server.store.create_mandate(customer["id"])
        subscription = server.store.create_subscription(customer["id"], {"amount": money("EUR", 2900)})
        server.store.settlements["stl_selftest"] = {"resource": "settlement", "id": "stl_selftest"}

        checks = [
            ("payment id shape", payment["id"].startswith("tr_")),
            ("payment starts open", payment["status"] == "open"),
            ("checkout link present", "checkout" in payment["_links"]),
            ("decimal amount", payment["amount"]["value"] == "29.00"),
            ("refund id shape", refund["id"].startswith("re_")),
            ("refund bound to payment", refund["paymentId"] == payment["id"]),
            ("customer id shape", customer["id"].startswith("cst_")),
            ("mandate id shape", mandate["id"].startswith("mdt_")),
            ("subscription id shape", subscription["id"].startswith("sub_")),
            ("settlement present", server.store.get_settlement("stl_selftest") is not None),
            ("webhook body is id-only", webhook_form("tr_x") == b"id=tr_x"),
        ]
        for name, ok in checks:
            if not ok:
                failures.append(name)
    finally:
        server.stop()
    for failure in failures:
        print(f"mock-mollie self-test FAIL: {failure}")
    if not failures:
        print("mock-mollie self-test: PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(self_test())
