#!/usr/bin/env python3
"""Local SNS notification signer/Poster for B6 (verify-final-money).

Builds the exact AWS SNS string-to-sign the api-server reconstructs
(Message/MessageId/Timestamp/TopicArn/Type for Notification), signs it with
RSA-SHA256 (SignatureVersion=2) using a local key, and POSTs the envelope to
/v1/ses/notifications.
"""
import base64, json, subprocess, sys, time, urllib.request, urllib.error

KEY = "/tmp/sns_dev_key.pem"
TOPIC = "arn:aws:sns:eu-central-1:000000000000:apexmail-dev-ses-events"
URL = "http://127.0.0.1:8080/v1/ses/notifications"


def ienv(ses_message_id: str, recipient: str, one_click: bool = False) -> dict:
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    if one_click:
        event = {
            "eventType": "Complaint",
            "complaint": {
                "complaintFeedbackType": "abuse",
                "timestamp": ts,
                "complainedRecipients": [{"emailAddress": recipient}],
            },
            "mail": {
                "timestamp": ts,
                "messageId": ses_message_id,
                "source": "bounce@apexmail.ee",
                "destination": [recipient],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": ses_message_id},
                ],
            },
        }
    else:
        event = {
            "eventType": "Bounce",
            "bounce": {
                "bounceType": "Permanent",
                "bounceSubType": "General",
                "timestamp": ts,
                "bouncedRecipients": [
                    {"emailAddress": recipient, "action": "failed", "status": "5.1.1",
                     "diagnosticCode": "smtp; 550 5.1.1 user unknown"}
                ],
            },
            "mail": {
                "timestamp": ts,
                "messageId": ses_message_id,
                "source": "bounce@apexmail.ee",
                "destination": [recipient],
                "headers": [
                    {"name": "X-ApexMail-MessageId", "value": ses_message_id},
                ],
            },
        }
    return event


def main() -> int:
    ses_message_id = sys.argv[1]
    recipient = sys.argv[2]
    kind = sys.argv[3] if len(sys.argv) > 3 else "complaint"  # complaint|bounce|unsigned|badarn
    msg_id = sys.argv[4] if len(sys.argv) > 4 else None
    message = json.dumps(ienv(ses_message_id, recipient, kind == "complaint"))
    message_id = msg_id or f"probe-{int(time.time()*1000)}"
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    topic = TOPIC if kind != "badarn" else "arn:aws:sns:eu-central-1:000000000000:evil-topic"
    if kind == "badarn":
        topic = "arn:aws:sns:eu-central-1:000000000000:some-other-topic"
    string_to_sign = (
        f"Message\n{message}\nMessageId\n{message_id}\nTimestamp\n{timestamp}\n"
        f"TopicArn\n{topic}\nType\nNotification\n"
    )
    signature = ""
    if kind != "unsigned":
        p = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY],
                           input=string_to_sign.encode(), capture_output=True)
        if p.returncode != 0:
            print("SIGN FAILED:", p.stderr.decode()); return 2
        signature = base64.b64encode(p.stdout).decode()
    envelope = {
        "Type": "Notification",
        "MessageId": message_id,
        "TopicArn": topic,
        "Subject": None,
        "Message": message,
        "Timestamp": timestamp,
        "SignatureVersion": "2",
        "Signature": signature,
        "SigningCertURL": "http://127.0.0.1:9/dev-sns.pem",
        "UnsubscribeURL": "http://127.0.0.1:9/unsub",
    }
    body = json.dumps(envelope).encode()
    req = urllib.request.Request(URL, data=body, method="POST",
                                 headers={"Content-Type": "text/plain"})
    try:
        r = urllib.request.urlopen(req, timeout=15)
        print(f"HTTP={r.status} body={r.read().decode()[:400]!r}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"HTTP={e.code} body={e.read().decode()[:400]!r}")
        return 1
    except Exception as e:
        print(f"ERROR {type(e).__name__}: {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
