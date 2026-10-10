"""Mutation self-test — `--mutation-test`.

Seeds a documented, reversible patch set (tools/dogfood-v2/mutations/) into a
SCRATCH COPY of the product (never the live tree), builds the api-server with
a targeted incremental cargo build, runs the probes that the mutation is
supposed to trip, and requires EVERY seeded defect to be caught.

The scratch is an rsync copy of the WORKING TREE (not `git worktree`/HEAD):
the deployed stack is built from the working tree, which carries uncommitted
product changes — seeding against HEAD would mutate a different product (it
literally lacks the newer `mfa-verify` captcha scope the live server accepts).
Patches are applied with `git apply` inside the copy and reverted by
reverse-apply, with a copy-back-from-the-main-tree fallback; the main tree is
never written.

Attribution rule: a mutation is CAUGHT when at least one targeted probe fails
in the mutant run with a failing CHECK that did not fail in the clean control
run of the same probe set. A check that is already red cleanly (pre-existing
product finding) can never be credited with catching a mutation — that is the
difference between "the harness noticed" and "the harness happened to be red".

Safety rails:
  * patches may only touch services/mail-server/** and must never touch any
    path containing `kiwicaptcha` (the separate KiwiCaptcha product stays a
    black box);
  * the scratch copy is reverted after every mutation and verified
    byte-identical to the main tree for every touched file before continuing;
  * the mutant api-server binds a private port and uses the dedicated test
    Redis (16379), so it cannot disturb the shared live stack's limiter state.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.request
from pathlib import Path

from .config import Config, REPO_ROOT

SCRATCH_MARKER = ".dogfood-v2-scratch"
RSYNC_EXCLUDES = (
    ".git", "services/mail-server/target", "node_modules", ".venv", "output",
    "reports", ".playwright-cli", "data", ".kilo", "ci/runs", "*.rdb",
    "tools/dogfood-v2/out",
)
from .context import Context
from .dataplane import PsqlDataPlane
from .httpc import HttpClient
from .kiwi import KiwiSolver
from .mail import MailpitSource

MUTATION_PORT = 18080

ALLOWED_PREFIXES = ("services/mail-server/",)
FORBIDDEN_SUBSTRINGS = ("kiwicaptcha", "packages/")


# ── scratch-copy plumbing ───────────────────────────────────────────────────

def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=120)


def ensure_scratch_tree(cfg: Config, log=None) -> Path:
    """A marker-tagged rsync copy of the working tree; created on first use."""
    scratch = cfg.mutation_worktree
    if (scratch / SCRATCH_MARKER).exists():
        return scratch
    if scratch.exists():
        shutil.rmtree(scratch)
    if log:
        log(f"creating scratch copy of the working tree at {scratch}")
    scratch.mkdir(parents=True)
    command = ["rsync", "-a", "--delete"]
    command += [f"--exclude={pattern}" for pattern in RSYNC_EXCLUDES]
    command += [f"{REPO_ROOT}/", f"{scratch}/"]
    result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if result.returncode != 0:
        raise RuntimeError(f"scratch copy failed: {result.stderr[-400:]}")
    (scratch / SCRATCH_MARKER).write_text(json.dumps({
        "source": str(REPO_ROOT), "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }, indent=1))
    return scratch


def patch_touched_files(patch_path: Path) -> list[str]:
    touched: list[str] = []
    for line in patch_path.read_text().splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/"):].strip()
            if path not in touched:
                touched.append(path)
    return touched


def apply_patch(scratch: Path, patch_path: Path) -> subprocess.CompletedProcess:
    return _git("apply", str(patch_path), cwd=scratch)


def revert_patch(scratch: Path, patch_path: Path, touched: list[str]) -> list[str]:
    """Reverse-apply; fall back to copying each touched file back from the
    main tree. Returns the files that had to be restored by copy."""
    result = _git("apply", "-R", str(patch_path), cwd=scratch)
    if result.returncode == 0:
        restored: list[str] = []
    else:
        restored = []
        for relative in touched:
            source = REPO_ROOT / relative
            if source.exists():
                shutil.copy2(source, scratch / relative)
                restored.append(relative)
    # verify: every touched file is byte-identical to the main tree again
    for relative in touched:
        source = REPO_ROOT / relative
        target = scratch / relative
        if source.exists() and (not target.exists() or source.read_bytes() != target.read_bytes()):
            raise RuntimeError(f"scratch file {relative} could not be restored")
    return restored


def load_manifest(cfg: Config) -> list[dict]:
    raw = json.loads(cfg.mutation_manifest.read_text())
    mutations = raw["mutations"] if isinstance(raw, dict) else raw
    for mutation in mutations:
        patch_path = cfg.mutation_manifest.parent / mutation["patch"]
        if not patch_path.exists():
            raise RuntimeError(f"mutation {mutation['id']}: missing patch {patch_path}")
        text = patch_path.read_text()
        for line in text.splitlines():
            if line.startswith(("--- ", "+++ ", "diff --git ")):
                for token in line.replace("a/", " ").replace("b/", " ").split():
                    if "/" in token and token.endswith((".rs", ".sql", ".toml")):
                        path = token.strip()
                        if not path.startswith(ALLOWED_PREFIXES):
                            raise RuntimeError(
                                f"mutation {mutation['id']}: patch touches {path} outside "
                                f"{ALLOWED_PREFIXES}"
                            )
                        if any(bad in path.lower() for bad in FORBIDDEN_SUBSTRINGS):
                            raise RuntimeError(
                                f"mutation {mutation['id']}: patch touches a forbidden path {path}"
                            )
    return mutations


# ── build / run the mutant ──────────────────────────────────────────────────

def _build(cfg: Config, scratch: Path, log) -> None:
    target = REPO_ROOT / "services/mail-server/target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    started = time.time()
    log(f"building mutant api-server (incremental, CARGO_TARGET_DIR={target})")
    result = subprocess.run(
        ["cargo", "build", "-p", "api-server"],
        cwd=scratch / "services/mail-server", env=env,
        capture_output=True, text=True, timeout=1800,
    )
    if result.returncode != 0:
        tail = "\n".join(result.stderr.splitlines()[-30:])
        raise RuntimeError(f"cargo build failed:\n{tail}")
    log(f"build ok in {time.time() - started:.0f}s")


def _container_env(cfg: Config) -> dict:
    """The live api-server's own environment (fidelity), plus host overrides:
    private port and the dedicated test Redis so the shared live stack's
    limiter/session state is never touched by a mutant."""
    env: dict[str, str] = {}
    # JSON form: multi-line values (the JWT PEMs) survive, unlike line-split.
    result = subprocess.run(
        ["docker", "--context", cfg.docker_context, "inspect", "apexmail-api-server-1",
         "--format", "{{json .Config.Env}}"],
        capture_output=True, text=True, timeout=60,
    )
    try:
        for entry in json.loads(result.stdout or "[]"):
            if isinstance(entry, str) and "=" in entry:
                key, value = entry.split("=", 1)
                env[key] = value
    except json.JSONDecodeError as error:
        raise RuntimeError(f"could not read the api-server container env: {error}") from error
    env.update({
        "PORT": str(MUTATION_PORT),
        "HOST": "127.0.0.1",
        "BASE_URL": f"http://127.0.0.1:{MUTATION_PORT}",
        "DB_HOST": "127.0.0.1",
        "DB_PORT": "5432",
        "REDIS_HOST": "127.0.0.1",
        "REDIS_PORT": "16379",
        "METRICS_PORT": "19090",
        "PLACEMENT_SMTP_HOST": "127.0.0.1",
        "PLACEMENT_SMTP_PORT": "5525",
        "ENVIRONMENT": "development",
    })
    env.pop("DB_PASSWORD_FILE", None)
    env.pop("REDIS_PASSWORD_FILE", None)
    env["DB_PASSWORD"] = cfg.postgres_password
    env["REDIS_PASSWORD"] = cfg.redis_password
    return env


class Mutant:
    def __init__(self, cfg: Config, scratch: Path, log):
        self.cfg = cfg
        self.scratch = scratch
        self.log = log
        self.process: subprocess.Popen | None = None

    @property
    def binary(self) -> Path:
        return REPO_ROOT / "services/mail-server/target/debug/api-server"

    def start(self) -> None:
        last_error: Exception | None = None
        for attempt in range(3):
            self.stop()
            self._wait_port_free(MUTATION_PORT)
            self._wait_port_free(19090)  # the native metrics listener
            env = _container_env(self.cfg)
            log_path = self.cfg.out_dir / "mutant-server.log"
            self._logfile = open(log_path, "w")
            self.process = subprocess.Popen(
                [str(self.binary)], cwd=self.scratch, env=env,
                stdout=self._logfile, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                self._wait_healthy()
                return
            except RuntimeError as error:
                last_error = error
                self.stop()
                time.sleep(3)
        raise RuntimeError(f"mutant api-server failed to start: {last_error}")

    @staticmethod
    def _wait_port_free(port: int, tries: int = 20) -> None:
        for _ in range(tries):
            with socket.socket() as probe:
                probe.settimeout(0.5)
                if probe.connect_ex(("127.0.0.1", port)) != 0:
                    return
            time.sleep(1)

    def _wait_healthy(self, tries: int = 60) -> None:
        url = f"http://127.0.0.1:{MUTATION_PORT}/health"
        for _ in range(tries):
            if self.process is not None and self.process.poll() is not None:
                tail = ""
                try:
                    tail = (self.cfg.out_dir / "mutant-server.log").read_text()[-800:]
                except OSError:
                    pass
                raise RuntimeError(f"mutant api-server exited early:\n{tail}")
            try:
                with urllib.request.urlopen(url, timeout=2) as response: # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected — internal tooling hitting a configured/constant endpoint, not a user-supplied URL
                    if response.status == 200:
                        return
            except Exception:  # noqa: BLE001
                time.sleep(1)
        raise RuntimeError("mutant api-server did not answer /health within 60s")

    def stop(self) -> None:
        if self.process is None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.process = None
        if getattr(self, "_logfile", None):
            self._logfile.close()
            self._logfile = None


# ── probe execution against the mutant ─────────────────────────────────────

def _mutation_context(cfg: Config, ledger, out_dir: Path) -> Context:
    run_cfg = Config()
    run_cfg.__dict__.update(cfg.__dict__)
    run_cfg.mode = "mutation"
    run_cfg.base = f"http://127.0.0.1:{MUTATION_PORT}"
    run_cfg.host = "127.0.0.1"
    run_cfg.out_dir = out_dir
    run_cfg.json_out = out_dir / "findings.json"
    run_cfg.coverage_out = out_dir / "coverage.json"
    run_cfg.transcript = out_dir / "transcript.log"
    http = HttpClient(run_cfg)
    ctx = Context(
        cfg=run_cfg, http=http, kiwi_solver=KiwiSolver(http, base="", host=""),
        mail=MailpitSource(run_cfg.mailpit), db=PsqlDataPlane(run_cfg), ledger=ledger,
    )
    ctx.kiwi_solver.reset_hook = ctx.clear_rate_keys
    return ctx


def _run_probe_set(cfg: Config, ledger, probe_ids: list[str], out_dir: Path, log,
                   restart_hook=None):
    from .registry import REGISTRY
    from .runner import run_probes

    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = _mutation_context(cfg, ledger, out_dir)
    ctx.restart_hook = restart_hook
    wanted = set(probe_ids)
    observations, started = run_probes(
        ctx, REGISTRY, partitions_override=[], mutation_filter=lambda p: p.id in wanted,
    )
    # failures are keyed at CHECK granularity: a probe may carry a
    # pre-existing red check, and only NEW failing checks attributable to the
    # mutation may be credited (see the module docstring's attribution rule).
    failures: dict[tuple[str, str], dict] = {}
    passed: dict[str, int] = {}
    for obs in observations:
        if obs.ok:
            passed[obs.probe_id] = passed.get(obs.probe_id, 0) + 1
        else:
            failures[(obs.probe_id, obs.title)] = {
                "probe_id": obs.probe_id, "title": obs.title,
                "observed": obs.observed[:300], "expected": obs.expected[:200],
                "severity": obs.severity, "kind": obs.kind,
            }
    try:
        (out_dir / "failures.json").write_text(json.dumps({
            "probes": sorted({o.probe_id for o in observations}),
            "failed_checks": list(failures.values()),
            "passed_checks": sum(passed.values()),
        }, indent=1))
    except OSError:
        pass
    # a probe that could not even execute (exception / honest unreachable)
    # leaves the clean behaviour of its later checks unknown: it can neither
    # credit NOR exonerate a mutation.
    incomplete = {
        obs.probe_id for obs in observations
        if obs.kind == "unreachable"
    }
    return observations, failures, passed, incomplete


# ── orchestration ───────────────────────────────────────────────────────────

def run_mutation_test(cfg: Config, ledger, args) -> int:
    from . import HARNESS_VERSION
    from .findings import write_findings

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    mutations = load_manifest(cfg)
    only = getattr(args, "mutation_only", None)
    if only:
        mutations = [m for m in mutations if m["id"] == only]
        if not mutations:
            print(f"unknown mutation id: {only}", flush=True)
            return 1
    def log(message: str) -> None:
        line = f"[dogfood-v2 mutation] {message}"
        print(line, flush=True)
        with open(cfg.out_dir / "mutation-transcript.log", "a") as handle:
            handle.write(line + "\n")

    union = sorted({p for m in mutations for p in m["probes"]})
    log(f"harness {HARNESS_VERSION}: {len(mutations)} seeded mutations, "
        f"{len(union)} targeted probes, scratch={cfg.mutation_worktree}")

    scratch = ensure_scratch_tree(cfg, log)
    # A previous run killed mid-mutation can leave a patch applied. Restore
    # every file any patch touches to the main-tree bytes BEFORE the control
    # build: a "clean control" must never be built from mutant source.
    restored: list[str] = []
    for mutation in mutations:
        for relative in patch_touched_files(cfg.mutation_manifest.parent / mutation["patch"]):
            source = REPO_ROOT / relative
            target = scratch / relative
            if source.exists() and target.exists() and source.read_bytes() != target.read_bytes():
                shutil.copy2(source, target)
                restored.append(relative)
    if restored:
        log(f"restored {len(restored)} leftover-patched file(s) from the main tree: {restored}")
    mutant = Mutant(cfg, scratch, log)
    report: dict = {"seeded": len(mutations), "caught": 0, "missed": 0, "inconclusive": 0,
                    "passed": False, "port": MUTATION_PORT, "scratch": str(scratch),
                    "mutations": [], "control_failures": {}}
    try:
        # ── clean control: every targeted probe must behave ────────────────
        _build(cfg, scratch, log)
        mutant.start()
        log("clean control: running the targeted probe set against the pristine scratch build")
        restart_hook = lambda: (mutant.start(), True)[1]  # noqa: E731
        observations, control_failures, _passed, control_incomplete = _run_probe_set(
            cfg, ledger, union, cfg.out_dir / "mutation" / "control", log,
            restart_hook=restart_hook,
        )
        control_probes_red = sorted({key[0] for key in control_failures})
        log(f"control: {len(observations)} checks over {len(union)} probes, "
            f"{len(control_failures)} failing checks, "
            f"{len(control_probes_red)} probes already failing clean")
        for key, fail in sorted(control_failures.items()):
            log(f"  control-failure {fail['probe_id']}: {fail['title']} :: {fail['observed'][:120]}")
        report["control_failures"] = {
            probe_id: [fail["title"] for (pid, _t), fail in sorted(control_failures.items()) if pid == probe_id]
            for probe_id in control_probes_red
        }
        report["control_incomplete_probes"] = sorted(control_incomplete)
        if control_incomplete:
            log(f"control-incomplete probes (no attribution possible): {sorted(control_incomplete)}")
        mutant.stop()

        # ── per-mutation mutants ───────────────────────────────────────────
        for mutation in mutations:
            entry = {
                "id": mutation["id"], "family": mutation["family"],
                "patch": mutation["patch"], "description": mutation.get("description", ""),
                "probes": mutation["probes"], "caught": False, "catching_probes": [],
                "evidence": {},
            }
            report["mutations"].append(entry)
            patch_path = cfg.mutation_manifest.parent / mutation["patch"]
            touched = patch_touched_files(patch_path)
            check = _git("apply", "--check", str(patch_path), cwd=scratch)
            if check.returncode != 0:
                entry["evidence"]["apply_error"] = check.stderr[:400]
                log(f"{mutation['id']}: PATCH DOES NOT APPLY — {check.stderr[:200]}")
                continue
            applied = apply_patch(scratch, patch_path)
            if applied.returncode != 0:
                entry["evidence"]["apply_error"] = applied.stderr[:400]
                log(f"{mutation['id']}: PATCH FAILED — {applied.stderr[:200]}")
                continue
            try:
                changed = [rel for rel in touched
                           if (REPO_ROOT / rel).read_bytes() != (scratch / rel).read_bytes()]
                if not changed:
                    entry["evidence"]["apply_error"] = "patch applied but produced no change"
                    continue
                _build(cfg, scratch, log)
                mutant.start()
                _, failures, _p, incomplete = _run_probe_set(
                    cfg, ledger, mutation["probes"],
                    cfg.out_dir / "mutation" / mutation["id"], log,
                    restart_hook=restart_hook,
                )
                attributable_set: set[str] = set()
                for key, fail in sorted(failures.items()):
                    if key in control_failures:
                        continue  # already red clean: not attributable
                    if fail["probe_id"] in control_incomplete:
                        entry["evidence"].setdefault(
                            fail["probe_id"],
                            [],
                        ).append(f"[inconclusive: probe aborted in control] {fail['title']}")
                        continue
                    if fail.get("kind") == "unreachable":
                        # A probe that could not execute proves nothing about
                        # the seeded defect: an abort can NEVER be a catch.
                        entry["evidence"].setdefault(fail["probe_id"], []).append(
                            f"[not credited: probe aborted in the mutant] {fail['title']} :: "
                            f"{fail['observed'][:120]}"
                        )
                        continue
                    attributable_set.add(fail["probe_id"])
                    entry["evidence"].setdefault(fail["probe_id"], []).append(
                        f"{fail['title']} :: {fail['observed'][:160]}"
                    )
                attributable = sorted(attributable_set)
                entry["caught"] = bool(attributable)
                entry["catching_probes"] = attributable
                entry["inconclusive"] = bool(
                    not attributable and incomplete & set(mutation["probes"])
                )
                if entry["caught"]:
                    log(f"{mutation['id']}: CAUGHT by {', '.join(attributable)}")
                elif entry["inconclusive"]:
                    log(f"{mutation['id']}: INCONCLUSIVE — a targeted probe could not execute "
                        f"in the mutant run (an abort proves nothing)")
                else:
                    log(f"{mutation['id']}: MISSED (failures={sorted(failures)}; "
                        f"control-failing={sorted(set(failures) & set(control_failures))})")
            finally:
                mutant.stop()
                restored = revert_patch(scratch, patch_path, touched)
                if restored:
                    log(f"{mutation['id']}: reverted by copy-back ({len(restored)} files)")

        report["caught"] = sum(1 for m in report["mutations"] if m["caught"])
        report["inconclusive"] = sum(1 for m in report["mutations"] if m.get("inconclusive"))
        report["missed"] = len(report["mutations"]) - report["caught"]
        report["passed"] = report["missed"] == 0
    finally:
        mutant.stop()
        log("scratch copy verified clean against the main tree after the run")

    report_path = cfg.out_dir / "mutation-report.json"
    report_path.write_text(json.dumps(report, indent=1))
    print(json.dumps(
        {k: report[k] for k in ("seeded", "caught", "missed", "inconclusive", "passed")}, indent=1,
    ))
    for item in report["mutations"]:
        mark = "CAUGHT" if item["caught"] else "MISSED"
        print(f"  [{mark}] {item['id']} ({item['family']}) <- {', '.join(item['catching_probes']) or '---'}")
    print(f"mutation report: {report_path}", flush=True)

    payload = {
        "harness": {"version": HARNESS_VERSION, "lane": "D1", "mode": "mutation-test"},
        "run": {"base": f"http://127.0.0.1:{MUTATION_PORT}", "partitions": ["mutation"]},
        "summary": {
            "probes_run": len(union), "checks": 0, "checks_failed": 0, "findings": 0,
            "by_severity": {}, "by_partition": {},
        },
        "coverage": {"surfaces": len(ledger.surfaces) if ledger else 0},
        "findings": [],
        "mutation_test": report,
    }
    write_findings(cfg.out_dir / "mutation-findings.json", payload)
    return 0 if report["passed"] else 1
