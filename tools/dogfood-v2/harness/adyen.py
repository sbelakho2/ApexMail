"""The Adyen notification contract — shared by the fixture and the probes.

One implementation of the frozen contract (docs/tool-contracts/adyen.md) so
the mock endpoint and the probe battery can never drift apart:

  * body: ``{"notificationItems": [{"NotificationRequestItem": {...}}]}``
  * HMAC lives INSIDE the body at ``additionalData.hmacSignature`` (never a
    header): base64(HMAC-SHA256(key, payload)) where payload is the
    colon-joined ``pspReference:originalReference:merchantAccountCode:
    merchantReference:amount.value:amount.currency:eventCode:success`` with
    every value escaped (``\\`` → ``\\\\``, then ``:`` → ``\\:``), and the key
    is ``ADYEN_HMAC_KEY`` hex-decoded.
  * amounts are minor units (cents), EUR.
  * the success answer is the bare body ``[accepted]``.
  * the ledger's dedupe id is a deterministic digest over the fields Adyen
    retries identically: (eventCode, pspReference, success, eventDate,
    merchantReference) — migration 252's ``adyen_notification_id``.
"""
from __future__ import annotations

import base64
import hashlib
import hmac

SIGNED_FIELDS = (
    "pspReference",
    "originalReference",
    "merchantAccountCode",
    "merchantReference",
    "amount.value",
    "amount.currency",
    "eventCode",
    "success",
)
DEDUPE_FIELDS = ("eventCode", "pspReference", "success", "eventDate", "merchantReference")


def hmac_key_bytes(secret: str) -> bytes:
    """The signing key: ADYEN_HMAC_KEY is hex-encoded key material.

    The local dev fallback (compose default / no .env override) is a readable
    string, not hex; it is kept usable as raw bytes so the fixture, the probes
    and the local stack agree. A real deployed key is hex and takes the
    strict path.
    """
    cleaned = (secret or "").strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return cleaned.encode()


def _stringify(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        # Adyen's signing string uses lowercase true/false for `success`.
        return "true" if value else "false"
    return str(value)


def _field(item: dict, dotted: str) -> str:
    current = item
    for part in dotted.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return _stringify(current)


def escape(value) -> str:
    """Adyen's signing-string escaping: backslashes first, then colons."""
    return _stringify(value).replace("\\", "\\\\").replace(":", "\\:")


def signing_payload(item: dict) -> str:
    return ":".join(escape(_field(item, name)) for name in SIGNED_FIELDS)


def sign_notification(item: dict, secret: str) -> str:
    """base64(HMAC-SHA256(hex-decoded key, colon-joined escaped fields))."""
    digest = hmac.new(
        hmac_key_bytes(secret), signing_payload(item).encode(), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


def verify_notification(item: dict, signature: str, secret: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign_notification(item, secret), signature)


def notification_id(item: dict) -> str:
    """The ``adyen_webhook_events.adyen_notification_id`` dedupe digest."""
    basis = "\x1f".join(_field(item, name) for name in DEDUPE_FIELDS)
    return hashlib.sha256(basis.encode()).hexdigest()


def notification_items(envelope) -> list[dict]:
    """Every ``NotificationRequestItem`` in the documented envelope."""
    if not isinstance(envelope, dict):
        return []
    raw = envelope.get("notificationItems")
    if not isinstance(raw, list):
        return []
    items = []
    for entry in raw:
        item = entry.get("NotificationRequestItem") if isinstance(entry, dict) else None
        if isinstance(item, dict):
            items.append(item)
    return items
