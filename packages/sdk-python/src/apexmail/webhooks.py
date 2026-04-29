"""Webhook verification helpers for inbound ApexMail webhooks."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional, Sequence, Tuple, Union


SignatureHeader = Union[str, Sequence[str]]


def verify_signature(
    payload: Union[str, bytes],
    signature_header: Optional[SignatureHeader],
    secret: str,
    tolerance_seconds: int = 300,
    timestamp: Optional[int] = None,
) -> bool:
    """Validate an ApexMail webhook signature using HMAC-SHA256.

    The canonical signed payload is ``"{timestamp}.{payload}"``. The
    ``signature_header`` may be either the raw hex digest (when ``timestamp`` is
    provided separately) or the combined header form ``"t=<ts>,v1=<hex>"``.
    """

    if signature_header is None or secret == "":
        return False

    if isinstance(signature_header, (list, tuple)):
        signature_header = signature_header[0] if signature_header else None
    if signature_header is None:
        return False

    header_timestamp, signature = _parse_signature_header(str(signature_header))
    if timestamp is None:
        if header_timestamp is None:
            return False
        try:
            timestamp = int(header_timestamp)
        except (TypeError, ValueError):
            return False

    if signature is None or signature == "":
        return False

    if tolerance_seconds > 0 and abs(int(time.time()) - timestamp) > tolerance_seconds:
        return False

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _parse_signature_header(signature_header: str) -> Tuple[Optional[str], Optional[str]]:
    trimmed = signature_header.strip()
    if trimmed == "":
        return None, None

    if "t=" in trimmed and "v1=" in trimmed:
        timestamp = None
        signature = None
        for part in trimmed.split(","):
            key, _, value = part.strip().partition("=")
            if key == "t" and value:
                timestamp = value
            elif key == "v1" and value:
                signature = value
        return timestamp, signature

    if trimmed.startswith("sha256="):
        return None, trimmed[len("sha256="):]

    return None, trimmed