"""Platform webhook-signature verification tests.

The platform (worker-processors/src/webhook/processor.rs) delivers:

    X-ApexMail-Signature: sha256=<hex hmac-sha256>
    X-ApexMail-Timestamp: <milliseconds since epoch>

and signs the exact string "{timestamp_millis}.{payload}". These tests pin
that format, including the known vector for
HMAC-SHA256("1750000000000." + '{"test":true}', "whsec_test").
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import pathlib
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"

spec = importlib.util.spec_from_file_location("apexmail.webhooks_platform", ROOT / "webhooks.py")
webhooks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(webhooks)

PAYLOAD = '{"test":true}'
SECRET = "whsec_test"
# Known vector (ms timestamp):
KNOWN_TS_MS = "1750000000000"
KNOWN_VECTOR = "31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2"


def platform_sign(ts_ms: str, payload: str, secret: str) -> str:
    return "sha256=" + hmac.new(
        secret.encode(), f"{ts_ms}.{payload}".encode(), hashlib.sha256
    ).hexdigest()


def fresh_ms() -> str:
    return str(int((time.time() - 1.0) * 1000))


class PlatformSignatureTests(unittest.TestCase):
    def test_known_vector_pins_the_signed_string(self) -> None:
        self.assertEqual(
            KNOWN_VECTOR,
            hmac.new(
                SECRET.encode(), f"{KNOWN_TS_MS}.{PAYLOAD}".encode(), hashlib.sha256
            ).hexdigest(),
        )

    def test_platform_header_pair_verifies(self) -> None:
        ts = fresh_ms()
        self.assertTrue(
            webhooks.verify_signature(
                PAYLOAD,
                platform_sign(ts, PAYLOAD, SECRET),
                SECRET,
                timestamp_header=ts,
            )
        )

    def test_sha256_header_without_timestamp_is_rejected(self) -> None:
        ts = fresh_ms()
        self.assertFalse(
            webhooks.verify_signature(PAYLOAD, platform_sign(ts, PAYLOAD, SECRET), SECRET)
        )

    def test_millisecond_timestamp_not_treated_as_seconds(self) -> None:
        ts = fresh_ms()
        # Correct signature but the seconds-timestamp path would reject a ms
        # timestamp as ~55,000 years stale — auto-detection must accept it.
        self.assertTrue(
            webhooks.verify_signature(
                PAYLOAD,
                platform_sign(ts, PAYLOAD, SECRET),
                SECRET,
                timestamp_header=ts,
            )
        )

    def test_stale_millisecond_timestamp_rejected(self) -> None:
        self.assertFalse(
            webhooks.verify_signature(
                PAYLOAD,
                platform_sign(KNOWN_TS_MS, PAYLOAD, SECRET),
                SECRET,
                timestamp_header=KNOWN_TS_MS,
                tolerance_seconds=300,
            )
        )

    def test_tampered_payload_rejected(self) -> None:
        ts = fresh_ms()
        self.assertFalse(
            webhooks.verify_signature(
                '{"test":false}',
                platform_sign(ts, PAYLOAD, SECRET),
                SECRET,
                timestamp_header=ts,
            )
        )

    def test_wrong_secret_rejected(self) -> None:
        ts = fresh_ms()
        self.assertFalse(
            webhooks.verify_signature(
                PAYLOAD,
                platform_sign(ts, PAYLOAD, SECRET),
                "whsec_other",
                timestamp_header=ts,
            )
        )

    def test_wrong_signing_order_rejected(self) -> None:
        ts = fresh_ms()
        wrong = "sha256=" + hmac.new(
            SECRET.encode(), f"{PAYLOAD}.{ts}".encode(), hashlib.sha256
        ).hexdigest()
        self.assertFalse(
            webhooks.verify_signature(PAYLOAD, wrong, SECRET, timestamp_header=ts)
        )

    def test_legacy_seconds_header_still_verifies(self) -> None:
        ts = str(int(time.time()))
        legacy = f"t={ts},v1=" + hmac.new(
            SECRET.encode(), f"{ts}.{PAYLOAD}".encode(), hashlib.sha256
        ).hexdigest()
        self.assertTrue(webhooks.verify_signature(PAYLOAD, legacy, SECRET))


if __name__ == "__main__":
    unittest.main()
