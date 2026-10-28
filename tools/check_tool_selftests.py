#!/usr/bin/env python3
"""CI-invoked Python tools must prove their own gate (invariant I19).

Every `python3 tools/*.py` that `ci/stages/*.sh` runs must either expose
`--self-test` (a drift-injection proof: a known-bad fixture FAILS, a clean
tree passes) or declare itself in the allowlist below with the reason it is
meta-untestable (a pure formatter or a generator checked by `--check` elsewhere).

This is the fix for "20 of 55 tools have their own meta-test, 22 CI gates have
none": the gate checks itself by calling itself.

Usage: check_tool_selftests.py [--self-test]
Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGES = ROOT / "ci" / "stages"

# Tools whose self-test is redundant with another tool's drift injection.
EXEMPT = {
    "check_pdf_ark.py": "its own --self-test is the only entry; covered by check_invariants anchors",
    "tools/dogfood-v2/run.py": "its --self-test IS the whole adversarial battery (fixture server, "
    "~10 min, mutation gates) — far past the 120 s probe budget; it is separately a "
    "REQUIRED lane (test.dogfood-harness-self-test) whose failure fails the stage",
}

TOOL_REF = re.compile(r"python3\s+(tools/[A-Za-z0-9_\-./]+\.py)")


def ci_invoked_tools() -> list[str]:
    found: set[str] = set()
    for stage in sorted(STAGES.glob("*.sh")):
        text = stage.read_text(errors="replace")
        for match in TOOL_REF.finditer(text):
            found.add(match.group(1))
    return sorted(found)


def _probe(path: Path, flag: str) -> bool:
    if not path.is_file():
        return False
    try:
        proc = subprocess.run(
            [sys.executable, str(path), flag],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = (proc.stdout + proc.stderr).lower()
    return proc.returncode == 0 and ("self-test" in output or "selftest" in output)


def has_self_test_flag(tool_rel: str, candidates: tuple[str, ...] = ("--self-test", "--selftest")) -> bool:
    """Probe each known spelling ONCE, in order; the first proof wins."""
    path = ROOT / tool_rel
    return any(_probe(path, flag) for flag in candidates)


def collect() -> list[str]:
    problems: list[str] = []
    for tool in ci_invoked_tools():
        if Path(tool).name in EXEMPT or tool in EXEMPT:
            continue
        if not has_self_test_flag(tool):
            problems.append(
                f"{tool}: CI invokes it but it exposes no working --self-test "
                "(drift-injection proof of the gate itself)"
            )
    return problems


def self_test() -> int:
    """Hermetic drift-injection proof — NEVER re-probes the real tree (the
    full collect() takes minutes; the self-test must finish in seconds)."""
    # 1. A tool with a working --self-test is NOT flagged (fixture).
    with tempfile_stage() as (stage_dir, fake_tool):
        (ROOT / "tools" / "fake_gate.py").write_text(
            "print('self-test: ok (fixture)')\n", encoding="utf-8")
        problems = collect_from(stage_dir)
        if any(fake_tool in p for p in problems):
            print("self-test FAIL: a tool WITH --self-test was flagged", file=sys.stderr)
            return 1
    # 2. A tool without one IS flagged.
    with tempfile_stage() as (stage_dir, fake_tool):
        problems = collect_from(stage_dir)
        if not any(fake_tool in p for p in problems):
            print("self-test FAIL: a tool WITHOUT --self-test was not flagged", file=sys.stderr)
            return 1
        # 3. A tool whose --self-test exists but FAILS is flagged (probe rc).
        (ROOT / "tools" / "fake_gate.py").write_text(
            "import sys; print('self-test: boom'); sys.exit(1)\n", encoding="utf-8")
        problems = collect_from(stage_dir)
        if not any(fake_tool in p for p in problems):
            print("self-test FAIL: a FAILING --self-test was not flagged", file=sys.stderr)
            return 1
    # 4. The EXEMPT registry names real tools with reasons.
    real_root = Path(__file__).resolve().parents[1]
    for name, reason in EXEMPT.items():
        tool = real_root / "tools" / name
        if not tool.is_file():
            tool = real_root / name
        if not tool.is_file() or len(reason.strip()) < 20:
            print(f"self-test FAIL: EXEMPT entry {name!r} must name a real tool and "
                  "carry a substantive reason", file=sys.stderr)
            return 1
    print("tool-selftests self-test: ok (working self-test accepted; missing and "
          "failing self-tests flagged; exempt registry sound)")
    return 0


class tempfile_stage:
    """Throwaway stage dir + tool pair for the drift-injection self-test."""

    def __enter__(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.stage = base / "stages"
        self.stage.mkdir()
        (self.stage / "fake.sh").write_text("#!/bin/sh\npython3 tools/fake_gate.py\n")
        self.tool_name = "tools/fake_gate.py"
        (base / "tools").mkdir()
        (base / "tools" / "fake_gate.py").write_text("print('no self test here')\n")
        self._orig_root, self._orig_stages = ROOT, STAGES
        globals()["ROOT"], globals()["STAGES"] = base, self.stage
        return self.stage, self.tool_name

    def __exit__(self, *exc):
        globals()["ROOT"], globals()["STAGES"] = self._orig_root, self._orig_stages
        self.tmp.cleanup()
        return False


def collect_from(_stage_dir):
    return collect()


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    if "--inventory" in argv:
        # Informational mode: publish HOW MANY CI tools still owe a
        # self-test. Invariant I19 stays `planned` until this reaches 0.
        tools = ci_invoked_tools()
        missing = collect()
        print(f"tool-selftests inventory: {len(tools)} CI tools, {len(missing)} without a self-test")
        return 0
    problems = collect()
    if problems:
        for problem in problems:
            print(f"tool-selftests: {problem}", file=sys.stderr)
        print(f"tool-selftests: {len(problems)} CI tool(s) without a self-test", file=sys.stderr)
        return 1
    print("tool-selftests: all CI-invoked tools expose a working --self-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
