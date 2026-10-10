"""Probe execution engine.

Sequential execution with a global paced HTTP client (the shared live stack
must not be hammered); per-probe failure isolation (an exception in one probe
becomes an honest P1 unreachable observation, never a silent skip); summary
table + findings.json + coverage.json writers; exit-code contract:

  0  every check honest AND the ledger fully covered
  1  harness internal error
  2  findings present (product defects / violations)
  3  ledger coverage violation (fail-if-unprobed) — a harness-lint failure
"""
from __future__ import annotations

import time
import traceback

from . import HARNESS_VERSION
from .findings import build_findings, summary_table, write_findings
from .registry import Observation, Registry


class Result:
    def __init__(self, observations, coverage, payload, exit_code):
        self.observations = observations
        self.coverage = coverage
        self.payload = payload
        self.exit_code = exit_code


def run_probes(ctx, registry: Registry, *, partitions: list[str] | None = None,
               partitions_override: list[str] | None = None, mutation_filter=None) -> Result:
    """Execute the selected probes; returns a Result (no process exit here)."""
    selected = registry.selected(partitions_override or (partitions or []))
    if mutation_filter is not None:
        selected = [p for p in selected if mutation_filter(p)]
    observations: list[Observation] = []
    ctx.note(f"running {len(selected)} probes (partitions={partitions_override or partitions or ['all']})")
    started = time.time()
    if ctx.cfg.mode in ("live", "mutation"):
        # Run-start hygiene (documented control): start from clean Redis
        # limiter buckets so stale state from a previous campaign cannot look
        # like a product defect.
        try:
            ctx.clear_rate_keys()
        except Exception:  # noqa: BLE001
            pass
    for probe in selected:
        probe_started = time.time()
        ddos_before = getattr(ctx.http, "ddos_backoffs", 0)
        if ctx.cfg.mode in ("live", "mutation"):
            # Probe independence (isolation): every probe starts from a clean
            # limiter state via the documented env control, so one probe's
            # spent buckets can never fail the next one (except the probes
            # that deliberately prove the bounds themselves).
            try:
                ctx.clear_rate_keys()
            except Exception:  # noqa: BLE001
                pass
        try:
            output = probe.fn(ctx)
        except Exception as error:  # noqa: BLE001 — probe isolation
            message = f"{type(error).__name__}: {error}"
            # Recoverable-by-environment aborts: the harness's own bounded
            # volume can trip the in-process adaptive DDoS limiter, and a
            # captcha token that rode out a long backoff can expire before its
            # verification. Both are documented controls away from recovery
            # (restart clears the limiter; a re-minted token is fresh), so the
            # probe is retried — bounded — instead of being reported as an
            # unreachable that proves nothing.
            recoverable = (
                "429" in message
                or "rate-limited" in message
                or "DDOS" in message
                or "challenge expired" in message.lower()
                or "challenge not found" in message.lower()
            )
            for attempt in range(2):
                if error is None or not recoverable or ctx.cfg.mode not in ("live", "mutation"):
                    break
                ctx.note(
                    f"probe {probe.id}: environment-recoverable abort (attempt {attempt + 1}/2); "
                    f"clearing limiters"
                    + (" and restarting the api-server under test" if ctx.cfg.mode == "mutation" else "")
                )
                if ctx.cfg.mode == "mutation":
                    # restarting the NATIVE mutant is cheap and safe; the
                    # live container is shared with other agents and is never
                    # restarted on the harness's own account
                    try:
                        ctx.restart_api()
                    except Exception:  # noqa: BLE001
                        pass
                try:
                    ctx.clear_rate_keys()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(15 if attempt == 0 else 62)
                try:
                    output = probe.fn(ctx)
                    error = None
                except Exception as retry_error:  # noqa: BLE001
                    error = retry_error
                    message = f"{type(retry_error).__name__}: {retry_error}"
                    recoverable = (
                        "429" in message
                        or "rate-limited" in message
                        or "DDOS" in message
                        or "challenge expired" in message.lower()
                        or "challenge not found" in message.lower()
                    )
            if error is not None:
                # A probe that cannot execute is reported as a NAMED
                # environment abort (never a silent skip, never a bare
                # traceback in the finding text): the exact error + the
                # request that failed, plus the traceback as evidence for the
                # runner lanes.
                output = [
                    Observation(
                        probe_id=probe.id, surface="harness", ok=False, severity="P1",
                        title=f"probe could not execute: {str(error)[:160]}",
                        observed=f"{type(error).__name__}: {str(error)[:400]}",
                        expected="the probe completes and reports product verdicts (an "
                                 "environment abort is not a product finding)",
                        evidence={"exception": type(error).__name__, "traceback": traceback.format_exc()[-2000:]},
                        kind="unreachable",
                    )
                ]
            else:
                output = output or []
        if output is None:
            output = []
        if isinstance(output, Observation):
            output = [output]
        for observation in output:
            observation.probe_id = observation.probe_id or probe.id
            observations.append(observation)
        failed = sum(1 for o in output if not o.ok)
        elapsed = time.time() - probe_started
        if ctx.cfg.verbose or failed:
            ctx.note(
                f"probe {probe.id}: {len(output)} checks, {failed} failed "
                f"({elapsed:.1f}s)"
            )
        # A probe that had to ride out DDOS backoffs leaves the target's
        # in-process reputation degraded; restart it (documented control) so
        # the NEXT probe starts from a clean protector state.
        ddos_seen = getattr(ctx.http, "ddos_backoffs", 0)
        if ctx.cfg.mode == "mutation" and ddos_seen > ddos_before:
            ctx.note(
                f"probe {probe.id}: {ddos_seen - ddos_before} ddos backoff(s); "
                f"restarting the native mutant (isolation)"
            )
            try:
                ctx.restart_api()
            except Exception:  # noqa: BLE001
                pass
    return observations, started


def finalize(ctx, observations, started, *, mutation_report=None, exit_on_coverage=True) -> Result:
    from .coverage import compute_coverage, write_coverage

    coverage = compute_coverage(ctx.ledger, REGISTRY_REF[0], ctx.cfg.allowlist)
    write_coverage(ctx.cfg.coverage_out, coverage, ctx.ledger, REGISTRY_REF[0])
    payload = build_findings(
        observations, mode=ctx.cfg.mode, base=ctx.cfg.base,
        partitions=ctx.cfg.partitions, coverage=coverage, ledger=ctx.ledger,
        mutation_report=mutation_report, started=started,
        harness_meta={
            "requests": ctx.http.requests,
            "transport_errors": ctx.http.transport_errors,
            "backoffs": ctx.http.backoffs,
            "ddos_backoffs": ctx.http.ddos_backoffs,
            "ddos_blocks": ctx.http.ddos_blocks,
            "ddos_recoveries": getattr(ctx, "_ddos_recoveries", 0),
            "kiwi_minted": ctx.kiwi_solver.minted,
            "kiwi_solved": ctx.kiwi_solver.solved,
            "identities": {k: v.email for k, v in ctx.identities.items()},
        },
    )
    write_findings(ctx.cfg.json_out, payload)
    table = summary_table(payload)
    print(table, flush=True)
    try:
        with open(ctx.cfg.transcript, "a") as handle:
            handle.write(table + "\n")
    except OSError:
        pass
    findings_count = payload["summary"]["findings"]
    if not coverage.ok and exit_on_coverage:
        exit_code = 3
        print(
            f"LEDGER VIOLATION: {len(coverage.unprobed)} surfaces unprobed and not allowlisted; "
            f"{len(coverage.invalid_allowlist)} invalid allowlist entries",
            flush=True,
        )
    elif findings_count:
        exit_code = 2
    else:
        exit_code = 0
    ctx.note(
        f"run complete: {findings_count} findings, {len(coverage.covered)}/{coverage.totals['surfaces']} "
        f"surfaces covered, exit={exit_code}"
    )
    payload["exit_code"] = exit_code
    return Result(observations, coverage, payload, exit_code)


# the registry is a singleton; kept behind a ref so finalize stays injectable
from .registry import REGISTRY as _REGISTRY  # noqa: E402

REGISTRY_REF = [_REGISTRY]
