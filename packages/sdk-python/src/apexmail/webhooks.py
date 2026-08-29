"""Webhook verification helpers for inbound ApexMail webhooks.

Platform wire format (worker-processors/src/webhook/processor.rs):

* ``X-ApexMail-Signature: sha256=<hex HMAC-SHA256>``
* ``X-ApexMail-Timestamp: <milliseconds since epoch>``
* signed message: ``"{timestamp_millis}.{payload}"`` — the millisecond
  digits are used verbatim, so the signature input must be built from the
  raw header string, not from a normalized/second-converted timestamp.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional, Sequence, Tuple, Union


SignatureHeader = Union[str, Sequence[str]]

# Timestamps above this value (2001-09-09T01:46:40Z) cannot be epoch
# seconds; below it they cannot be epoch milliseconds.
_MS_CUTOFF = 1_000_000_000_000


def verify_signature(
    payload: Union[str, bytes],
    signature_header: Optional[SignatureHeader],
    secret: str,
    tolerance_seconds: int = 300,
    timestamp: Optional[Union[int, str]] = None,
    timestamp_header: Optional[Union[int, str]] = None,
) -> bool:
    """Validate an ApexMail webhook signature using HMAC-SHA256.

    Pass BOTH platform headers for real deliveries::

        verify_signature(
            body,
            headers.get("X-ApexMail-Signature"),
            secret,
            timestamp_header=headers.get("X-ApexMail-Timestamp"),
        )

    The platform delivers millisecond timestamps; they are auto-detected
    (and compared against ``time.time() * 1000``) while the signed string
    always uses the timestamp digits exactly as delivered. The legacy
    combined header form ``"t=<seconds>,v1=<hex>"`` and an explicit
    ``timestamp`` override remain supported for older integrations.
    """

    if signature_header is None or secret == "":
        return False

    if isinstance(signature_header, (list, tuple)):
        signature_header = signature_header[0] if signature_header else None
    if signature_header is None:
        return False

    header_timestamp, signature = _parse_signature_header(str(signature_header))
    if timestamp is None and timestamp_header is None:
        timestamp = header_timestamp
    elif timestamp is None:
        timestamp = timestamp_header

    if signature is None or signature == "":
        return False
    if timestamp is None:
        return False
    timestamp_text = str(timestamp).strip()
    if not timestamp_text.isdigit():
        return False

    # Auto-detect seconds vs milliseconds: the platform sends milliseconds.
    timestamp_value = int(timestamp_text)
    is_milliseconds = len(timestamp_text) > 11 or timestamp_value > _MS_CUTOFF
    if is_milliseconds:
        now = time.time() * 1000
    else:
        now = time.time()
    tolerance = tolerance_seconds * (1000 if is_milliseconds else 1)
    if tolerance_seconds > 0 and abs(now - timestamp_value) > tolerance:
        return False

    payload_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    # Sign with the timestamp digits EXACTLY as delivered (milliseconds on
    # the platform path) — never a normalized form.
    signed_payload = f"{timestamp_text}.".encode("utf-8") + payload_bytes
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
