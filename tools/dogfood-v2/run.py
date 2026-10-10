#!/usr/bin/env python3
"""dogfood-v2 entry point (Lane D1).

usage:
  python3 tools/dogfood-v2/run.py [--base URL] [--host HOST] [--partition a,b]
                                  [--self-test] [--mutation-test]
                                  [--json PATH] [--allowlist PATH] [--verbose]
  python3 tools/dogfood-v2/run.py --ledger-only        # enumerate + coverage report
  python3 tools/dogfood-v2/run.py --list-partitions

Exit codes: 0 clean · 2 findings · 3 ledger coverage violation · 1 harness error.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import HARNESS_VERSION  # noqa: E402
from harness.config import Config, from_args  # noqa: E402
from harness.ledger import enumerate as enumerate_ledger  # noqa: E402
from harness.registry import PARTITIONS, REGISTRY  # noqa: E402
from harness.runner import finalize, run_probes  # noqa: E402


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="dogfood-v2", description="wider, adversarial, self-proving dogfood harness")
    ap.add_argument("--base", default=None, help="api-server base URL (default http://127.0.0.1:8080)")
    ap.add_argument("--host", default=None, help="web console Host header (default 127.0.0.1)")
    ap.add_argument("--cp-host", default=None, help="control-plane Host (default admin.localhost)")
    ap.add_argument("--marketing-host", default=None, help="marketing Host (default marketing.localhost)")
    ap.add_argument("--partition", dest="partitions", default=None,
                    help="comma-separated partitions (default: all)")
    ap.add_argument("--self-test", action="store_true", help="run the whole battery against the fixture server")
    ap.add_argument("--mutation-test", action="store_true",
                    help="seed defects into a scratch worktree, build, and require every one to be caught")
    ap.add_argument("--mutation-only", default=None,
                    help="run only the named mutation (development aid; still requires its catch)")
    ap.add_argument("--json", default=None, help="findings.json output path")
    ap.add_argument("--out-dir", default=None, help="output directory for findings/coverage/transcript")
    ap.add_argument("--allowlist", default=None, help="allowlist.json path")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--ledger-only", action="store_true", help="enumerate surfaces + coverage, run no probes")
    ap.add_argument("--list-partitions", action="store_true")
    ap.add_argument("--list-probes", action="store_true")
    ap.add_argument("--pace", type=float, default=None, help="seconds between HTTP requests")
    ap.add_argument("--max-requests", type=int, default=None, help="hard request budget")
    return ap


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.list_partitions:
        for name in PARTITIONS:
            print(name)
        return 0
    if args.list_probes:
        imported = __import__("harness.probes", fromlist=["__all__"])
        _ = imported
        for probe in REGISTRY.all():
            print(f"{probe.partition:12s} {probe.id}")
        return 0

    cfg = from_args(args)
    if args.pace is not None:
        cfg.pace_seconds = args.pace
    if args.max_requests is not None:
        cfg.max_requests = args.max_requests
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    import harness.probes  # noqa: F401 — register every probe before any run

    try:
        ledger = enumerate_ledger()
        if args.ledger_only:
            import harness.probes  # noqa: F401 — register probes for coverage
            from harness.coverage import compute_coverage, write_coverage
            from harness.registry import REGISTRY as reg

            coverage = compute_coverage(ledger, reg, cfg.allowlist)
            write_coverage(cfg.coverage_out, coverage, ledger, reg)
            print(json.dumps(coverage.as_dict()["totals"], indent=1))
            if coverage.unprobed:
                print(f"UNPROBED ({len(coverage.unprobed)}):")
                for surface in coverage.unprobed[:40]:
                    print(" ", surface["id"], surface["kind"], surface.get("source", ""))
            if coverage.invalid_allowlist:
                print("INVALID ALLOWLIST:")
                for problem in coverage.invalid_allowlist:
                    print(" ", problem)
            return 0 if coverage.ok else 3

        if args.mutation_test:
            from harness.mutation import run_mutation_test

            return run_mutation_test(cfg, ledger, args)

        if args.self_test:
            from harness.selftest import run_self_test

            return run_self_test(cfg, ledger)

        # live run
        from harness.context import build_context

        ctx = build_context(cfg, ledger=ledger)
        ctx.note(f"dogfood-v2 {HARNESS_VERSION} live run against {cfg.base}")
        ctx.note(
            f"ledger: {len(ledger.surfaces)} surfaces "
            f"({', '.join(f'{k}={v}' for k, v in sorted(ledger.counts().items()))})"
        )
        observations, started_probes = run_probes(ctx, REGISTRY, partitions=cfg.partitions)
        result = finalize(ctx, observations, started_probes)
        return result.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 1
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
