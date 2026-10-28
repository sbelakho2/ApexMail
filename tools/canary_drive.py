#!/usr/bin/env python3
"""Drive the EXTERNAL qualification runner against the local canary stack.

The runner (tests/qualification/ApexMail_Real_Mail_Tests.py) is the reviewed,
byte-pinned external artifact — this driver NEVER modifies it. It imports it
as a library and runs its real plan→prepare→execute pipeline in the runner's
LOCAL_FIXTURE origin mode, which is exactly the honest scope label for a
loopback canary: real product admission (authenticated POST /v1/messages
with Idempotency-Key), real queue→worker→DKIM-signed SMTP delivery to the
controlled GreenMail receiver, real independent IMAP observation, real
six-case oracles (plain/unicode/html/attachment/idempotency/reserved_header),
and the runner's own evidence chain + summary.

Usage: canary_drive.py --api-base URL --api-key KEY --imap-host H --imap-port P
                        --imap-user U --imap-password PW --from ADDR --out DIR
Exit codes: 0 = PANEL_CHECKS_PASSED, 1 = anything else, 2 = usage/IO.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tests" / "qualification" / "ApexMail_Real_Mail_Tests.py"
RUNNER_SHA = "622d54f343f74a3cba95e7fcd262496950b9d16c9dfef1ca6745b9cb7f28ecc6"  # noqa: E501


def load_runner():
    digest = hashlib.sha256(RUNNER.read_bytes()).hexdigest()
    if digest != RUNNER_SHA:
        print(
            f"canary_drive: runner bytes drifted (sha256 {digest}); the lane pins the "
            f"reviewed artifact {RUNNER_SHA} — vendor the new file consciously and "
            "update RUNNER_SHA in this driver and tools/run_canary_lane.sh",
            file=sys.stderr,
        )
        sys.exit(1)
    spec = importlib.util.spec_from_file_location("amq_runner", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_config(runner, args) -> dict:
    cfg = runner.example_config()
    cfg.update({
        "reviewed_commit": None,
        "from": args.from_addr,
        "allowlist": [args.recipient],
        "routes": {
            "A": {"kind": "api", "url": args.api_base.rstrip("/") + "/v1/messages",
                  "key_env": "CANARY_APEXMAIL_API_KEY"},
            "B": {"kind": "api", "url": args.api_base.rstrip("/") + "/v1/messages",
                  "key_env": "CANARY_APEXMAIL_API_KEY"},
        },
        "mailboxes": [{
            "id": "canary-greenmail",
            "provider": "greenmail-controlled-receiver",
            "address": args.recipient,
            "host": args.imap_host,
            "port": args.imap_port,
            "tls": False,
            "user_env": "CANARY_IMAP_USER",
            "password_env": "CANARY_IMAP_PASSWORD",
            "folders": ["INBOX"],
        }],
        "cases": list(runner.CASES),
        "rounds": 1,
        "max_logical_messages": 64,
        "deadline_s": args.deadline,
        "late_window_s": args.late_window,
        "poll_s": args.poll,
        "pair_gap_s": 0.2,
        "pace_s": 0.2,
        "timeout_s": 20,
        "alpha": 0.05,
        "randomization_assumptions": (
            "A/A apparatus qualification against the local canary stack "
            "(authenticated API admission, DKIM-signed SMTP to the controlled "
            "GreenMail receiver, independent IMAP observation). LOCAL_FIXTURE "
            "origin: no external provider is involved."
        ),
    })
    return cfg


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api-base", required=True)
    ap.add_argument("--api-key", required=True)
    ap.add_argument("--imap-host", default="127.0.0.1")
    ap.add_argument("--imap-port", type=int, required=True)
    ap.add_argument("--imap-user", default="canary@receiver.canary.test")
    ap.add_argument("--imap-password", default="canary-lane")
    ap.add_argument("--from-addr", required=True)
    ap.add_argument("--recipient", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--deadline", type=float, default=120.0)
    ap.add_argument("--late-window", type=float, default=30.0)
    ap.add_argument("--poll", type=float, default=2.0)
    args = ap.parse_args()

    os.environ.setdefault("CANARY_APEXMAIL_API_KEY", args.api_key)
    os.environ.setdefault("CANARY_IMAP_USER", args.imap_user)
    os.environ.setdefault("CANARY_IMAP_PASSWORD", args.imap_password)

    runner = load_runner()
    cfg = build_config(runner, args)
    plan = runner.make_plan(cfg, fixture=True)
    digest = runner.validate_plan(plan)
    Path(args.out).mkdir(parents=True, exist_ok=True)
    print(json.dumps({"phase": "plan", "plan_sha256": digest,
                      "logical_messages": len(plan["probes"])}), flush=True)
    runner.prepare_run(plan, args.out, digest)
    result = runner.execute(plan, args.out, digest, fixture_mode=True)
    print(json.dumps({k: result[k] for k in
                      ("status", "origin", "logical_probes", "problems", "incomplete")}))
    return 0 if result["status"] == "PANEL_CHECKS_PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
