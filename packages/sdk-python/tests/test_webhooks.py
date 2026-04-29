import hashlib
import hmac
import importlib.util
import pathlib
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1] / "src" / "apexmail"


spec = importlib.util.spec_from_file_location("apexmail.webhooks", ROOT / "webhooks.py")
webhooks = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(webhooks)


def sign(payload: bytes, secret: str, timestamp: int) -> str:
    signed_payload = f"{timestamp}.".encode("utf-8") + payload
    return hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()


class WebhookVerificationTests(unittest.TestCase):
    def test_verify_signature_accepts_structured_header(self) -> None:
        payload = b'{"event":"message.delivered"}'
        secret = "whsec_test_secret"
        timestamp = int(time.time())
        signature = sign(payload, secret, timestamp)

        self.assertTrue(
            webhooks.verify_signature(
                payload,
                f"t={timestamp},v1={signature}",
                secret,
            )
        )

    def test_verify_signature_rejects_expired_signatures(self) -> None:
        payload = b'{"event":"message.delivered"}'
        secret = "whsec_test_secret"
        timestamp = int(time.time()) - 600
        signature = sign(payload, secret, timestamp)

        self.assertFalse(
            webhooks.verify_signature(
                payload,
                f"t={timestamp},v1={signature}",
                secret,
                tolerance_seconds=300,
            )
        )

    def test_verify_signature_accepts_prefixed_signature_header(self) -> None:
        payload = b'{"event":"message.delivered"}'
        secret = "whsec_test_secret"
        timestamp = int(time.time())
        signature = sign(payload, secret, timestamp)

        self.assertTrue(
            webhooks.verify_signature(
                payload,
                f"sha256={signature}",
                secret,
                timestamp=timestamp,
            )
        )

    def test_package_exports_verify_signature(self) -> None:
        init_text = (ROOT / "__init__.py").read_text(encoding="utf-8")
        self.assertIn("from .webhooks import verify_signature", init_text)
        self.assertIn('"verify_signature"', init_text)


if __name__ == "__main__":
    unittest.main()