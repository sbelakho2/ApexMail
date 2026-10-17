"""Performance-invariant tests for the dogfood harness + its gate tools.

Every test here pins a previously blind spot: it fails on the pre-fix code
(the naive scan/copy/fetch pattern) and passes on the indexed/batched
implementation. The checks are wired into `--self-test` through
`perf_selfcheck()` so a regression in these hot paths fails the harness's
own selftest, not only an external pytest run.

Run directly with either:
    python3 tools/dogfood-v2/harness/perf_selftest.py
    python3 -m pytest tools/dogfood-v2/harness/perf_selftest.py -q
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HARNESS_DIR = Path(__file__).resolve().parent
TOOL_DIR = HARNESS_DIR.parent
REPO_ROOT = TOOL_DIR.parent.parent

if str(TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(TOOL_DIR))

from harness import dbctl, fixture, ledger, mail  # noqa: E402
from harness.coverage import _rule_matches, compute_coverage  # noqa: E402
from harness.registry import Probe  # noqa: E402


class RedisBatchTest(unittest.TestCase):
    def test_clear_patterns_batches_del_calls(self):
        calls = []

        def fake_redis_cli(_cfg, *args, host=None, port=None):
            calls.append(args)
            if args and args[0] == "--scan":
                return "k1\nk2\n\nk3\n"
            return ""

        with mock.patch.object(dbctl, "redis_cli", side_effect=fake_redis_cli):
            cleared = dbctl.clear_redis_patterns(None, patterns=("p1", "p2"))

        self.assertEqual(cleared, 6)  # two patterns x three keys, same counter as before
        scans = [call for call in calls if call[0] == "--scan"]
        dels = [call for call in calls if call[0] == "del"]
        self.assertEqual(len(scans), 2)
        # Old code issued one DEL per key (6); batching issues one.
        self.assertEqual(len(dels), 1)
        self.assertEqual(dels[0][1:], ("k1", "k2", "k3", "k1", "k2", "k3"))

    def test_clear_patterns_chunks_large_key_sets(self):
        calls = []
        keys = [f"k{index}" for index in range(450)]

        def fake_redis_cli(_cfg, *args, host=None, port=None):
            calls.append(args)
            if args and args[0] == "--scan":
                return "\n".join(keys) + "\n"
            return ""

        with mock.patch.object(dbctl, "redis_cli", side_effect=fake_redis_cli):
            cleared = dbctl.clear_redis_patterns(None, patterns=("p1",))

        self.assertEqual(cleared, 450)
        dels = [call for call in calls if call[0] == "del"]
        self.assertEqual(len(dels), 3)  # 200 + 200 + 50
        self.assertEqual([len(call) - 1 for call in dels], [200, 200, 50])


class CoverageIndexTest(unittest.TestCase):
    class _Registry:
        def __init__(self, probes):
            self._probes = list(probes)
            self.calls = 0

        def all(self):
            self.calls += 1
            return list(self._probes)

    @staticmethod
    def _surface(surface_id, kind):
        return type("Surface", (), {
            "id": surface_id, "kind": kind,
            "as_dict": lambda self: {"id": self.id, "kind": self.kind},
        })()

    def _probes(self):
        return [
            Probe(id="p.explicit", partition="surface", fn=lambda ctx: [],
                  surfaces=("api:GET /a", "api:GET /a")),
            Probe(id="p.prefix", partition="surface", fn=lambda ctx: [],
                  subsumes=("api:*", "api:GET /exact-prefix-that-also-matches")),
            Probe(id="p.kind", partition="surface", fn=lambda ctx: [],
                  subsumes=("kind:table",)),
            Probe(id="p.exact", partition="surface", fn=lambda ctx: [],
                  subsumes=("ssr:web:GET /exact",)),
            Probe(id="p.unrelated", partition="surface", fn=lambda ctx: [],
                  subsumes=("svc:*",)),
        ]

    def test_registry_scanned_once_not_once_per_surface(self):
        probes = self._probes()
        surfaces = [self._surface(f"api:GET /s{index}", "api") for index in range(50)]
        ledger_like = type("Ledger", (), {"surfaces": surfaces, "warnings": []})()
        registry = self._Registry(probes)
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "allow.json"
            allowlist.write_text('{"entries": []}')
            compute_coverage(ledger_like, registry, allowlist)
        # The old nested loop called registry.all() once per surface (50).
        self.assertEqual(registry.calls, 1)

    def test_exact_coverage_semantics_match_the_naive_scan(self):
        probes = self._probes()
        surfaces = [
            self._surface("api:GET /a", "api"),
            self._surface("api:GET /b", "api"),
            self._surface("table:users", "table"),
            self._surface("ssr:web:GET /exact", "ssr"),
            self._surface("svc:mta", "service"),
            self._surface("unprobed:GET /nothing", "api"),
        ]
        ledger_like = type("Ledger", (), {"surfaces": surfaces, "warnings": []})()
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "allow.json"
            allowlist.write_text('{"entries": [{"id": "unprobed:GET /nothing", '
                                 '"owner": "lane-d1", "reason": "synthetic coverage reference check"}]}')
            result = compute_coverage(ledger_like, self._Registry(probes), allowlist)

        expected = {}
        for surface in surfaces:
            hits = []
            for probe in probes:
                if surface.id in probe.surfaces:
                    hits.append(probe.id)
                    continue
                if any(_rule_matches(rule, surface.id, surface.kind) for rule in probe.subsumes):
                    hits.append(probe.id)
            if hits:
                expected[surface.id] = sorted(set(hits))
        self.assertEqual(result.covered, expected)
        self.assertEqual([entry["id"] for entry in result.allowlisted], ["unprobed:GET /nothing"])
        self.assertEqual(result.unprobed, [])
        self.assertTrue(result.ok)

    def test_ten_times_input_keeps_one_registry_pass(self):
        probes = self._probes() * 20  # 100 probes
        probes = [Probe(id=f"{probe.id}.{index}", partition="surface", fn=lambda ctx: [],
                        surfaces=probe.surfaces, subsumes=probe.subsumes)
                  for index, probe in enumerate(probes)]
        surfaces = [self._surface(f"api:GET /s{index}", "api") for index in range(500)]
        ledger_like = type("Ledger", (), {"surfaces": surfaces, "warnings": []})()
        registry = self._Registry(probes)
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "allow.json"
            allowlist.write_text('{"entries": []}')
            compute_coverage(ledger_like, registry, allowlist)
        self.assertEqual(registry.calls, 1)


class RouteIndexTest(unittest.TestCase):
    def _entries(self):
        entries = []
        for index in range(200):
            entries.append(("GET", f"/v1/static{index}"))
        for index in range(100):
            entries.append(("POST", f"/v1/items/:id/step{index % 7}"))
        entries += [
            ("GET", "/"),
            ("GET", "/v1/items/:item_id"),
            ("DELETE", "/v1/items/:item_id"),
            ("GET", "/web/contacts/export.csv"),
            ("GET", "/v1/items/:id/step"),
        ]
        return entries

    def test_route_table_matches_naive_segment_scan(self):
        entries = self._entries()
        table = fixture._RouteTable(entries)
        requests = [("GET", f"/v1/static{index}") for index in range(0, 200, 3)]
        requests += [(method, f"/v1/items/abc{index}/step{index % 7}")
                     for index in range(100) for method in ("GET", "POST")]
        requests += [("GET", "/"), ("GET", "/v1/items/xyz"), ("DELETE", "/v1/items/xyz"),
                     ("GET", "/web/contacts/export.csv"), ("GET", "/v1/items/xyz/step"),
                     ("GET", "/v1/missing"), ("POST", "/v1/items/xyz/step9")]
        for method, path in requests:
            naive = any(entry_method == method and fixture._segments_match(pattern, path)
                        for entry_method, pattern in entries)
            self.assertEqual(table.has(method, fixture._path_segments(path)), naive,
                             f"{method} {path}")

    def test_compiled_lookup_does_not_rescan_patterns(self):
        entries = self._entries()
        table = fixture._RouteTable(entries)
        with mock.patch.object(fixture, "_segments_match", wraps=fixture._segments_match) as spy:
            for index in range(300):
                fixture._bucket_has(table, "GET", f"/v1/static{index % 200}")
                fixture._bucket_has(table, "GET", f"/v1/items/id{index}/step{index % 7}")
        # The old list scan invoked _segments_match once per pattern per call.
        self.assertEqual(spy.call_count, 0)

    def test_parameterized_and_static_requests(self):
        table = fixture._RouteTable(self._entries())
        self.assertTrue(table.has("GET", fixture._path_segments("/v1/static7")))
        self.assertTrue(table.has("GET", fixture._path_segments("/v1/items/abc")))
        self.assertTrue(table.has("POST", fixture._path_segments("/v1/items/abc/step3")))
        self.assertFalse(table.has("GET", fixture._path_segments("/v1/static9999")))
        self.assertFalse(table.has("POST", fixture._path_segments("/v1/static7")))
        self.assertFalse(table.has("GET", fixture._path_segments("/v1/items/a/b/c")))


class LedgerDedupeTest(unittest.TestCase):
    class _CountingStr(str):
        eq_calls = 0

        def __eq__(self, other):
            type(self).eq_calls += 1
            return str.__eq__(self, other)

        __hash__ = str.__hash__

    def test_dedupe_preserves_first_occurrence_order(self):
        self.assertEqual(ledger._dedupe(["a", "b", "a", "c", "b"]), ["a", "b", "c"])

    def test_dedupe_is_linear_not_quadratic(self):
        self._CountingStr.eq_calls = 0
        items = [self._CountingStr(f"warning-{index:06d}") for index in range(4000)]
        deduped = ledger._dedupe(items)
        self.assertEqual(len(deduped), len(items))
        # The old `item not in out` implementation performed ~n^2/2 string
        # comparisons (8,000,000 here); dict.fromkeys uses hashing.
        self.assertLess(self._CountingStr.eq_calls, 4 * len(items))


class MailReuseTest(unittest.TestCase):
    @staticmethod
    def _messages():
        return [
            {"ID": "m1", "To": [{"Address": "a@example.test"}], "Subject": "verify one",
             "Text": "click https://example.test/verify?id=1", "HTML": ""},
            {"ID": "m2", "To": [{"Address": "a@example.test"}], "Subject": "verify two",
             "Text": "click https://example.test/verify?id=2", "HTML": ""},
            {"ID": "m3", "To": [{"Address": "other@example.test"}], "Subject": "verify three",
             "Text": "click https://example.test/verify?id=3", "HTML": ""},
        ]

    def _fixture_source(self):
        source = mail.FixtureMailSource("http://fixture.invalid")
        calls = {"count": 0}

        def fake_get(_path):
            calls["count"] += 1
            return {"messages": self._messages()}

        source._get = fake_get
        return source, calls

    def test_message_lookup_reuses_the_last_mailbox_fetch(self):
        source, calls = self._fixture_source()
        source.messages()
        self.assertEqual(source.message("m1")["Subject"], "verify one")
        self.assertEqual(source.message("m1")["Subject"], "verify one")
        self.assertEqual(calls["count"], 1)  # old: 1 + one fetch per message() call

    def test_links_never_fetch_details_one_by_one(self):
        source, calls = self._fixture_source()
        links = source.links("a@example.test", "verify")
        self.assertEqual(links, ["https://example.test/verify?id=1",
                                 "https://example.test/verify?id=2"])
        # Old FixtureMailSource: 1 list fetch + one full mailbox fetch per
        # matched message (3); now the list snapshots carry the body.
        self.assertEqual(calls["count"], 1)

    def test_mailpit_detail_is_memoized_per_id(self):
        source = mail.MailpitSource("http://mailpit.invalid")
        calls = {"count": 0}

        def fake_get(_path):
            calls["count"] += 1
            return {"ID": "m1", "Text": "hello"}

        source._get = fake_get
        self.assertEqual(source.message("m1")["Text"], "hello")
        self.assertEqual(source.message("m1")["Text"], "hello")
        self.assertEqual(calls["count"], 1)

    def test_delete_all_clears_the_detail_cache(self):
        source, calls = self._fixture_source()
        source.messages()
        source.message("m1")
        with mock.patch.object(mail.urllib.request, "urlopen", side_effect=OSError("no network")):
            source.delete_all()
        self.assertEqual(source.message("m1")["Subject"], "verify one")
        self.assertEqual(calls["count"], 2)


class CapabilityScanTest(unittest.TestCase):
    """The capability gate must read every Rust source at most once per run
    (the old rust_sources_mention re-globbed and re-read all 969 files for
    every env gate: N+1 file reads)."""

    _WRAPPER = r"""
import json, os, runpy, sys
script, log = sys.argv[1], sys.argv[2]
opened = {}
def hook(event, args):
    if event == "open" and args and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if path.endswith(".rs"):
            opened[path] = opened.get(path, 0) + 1
sys.addaudithook(hook)
sys.argv = [script]
try:
    runpy.run_path(script, run_name="__main__")
except SystemExit:
    pass
json.dump(opened, open(log, "w"))
"""

    def _build_tree(self, root: Path, capabilities: int = 4, rust_files: int = 8) -> None:
        (root / "tools").mkdir(parents=True)
        shutil.copy2(REPO_ROOT / "tools/check_capability_claims.py",
                     root / "tools/check_capability_claims.py")
        (root / "docs/development").mkdir(parents=True)
        (root / "services/mail-server/crates/fixture/src").mkdir(parents=True)
        registry = {
            "lifecycle_ladder": ["implemented", "integration-tested", "runtime-wired",
                                 "deployed", "monitored", "advertised"],
            "scan": {"surfaces": [], "marker": "[roadmap]", "marker_close": "[/roadmap]",
                     "matrix_surfaces": []},
            "in_flight_wiring": {"items": []},
            "capabilities": [
                {
                    "capability": f"cap-{index}",
                    "crate": f"crates/fixture-{index}",
                    "stage": "runtime-wired",
                    "evidence": {
                        "docker_target": "mta",
                        "compose_service": "mta",
                        "env_gate": {"name": f"PERF_GATE_{index}_ENABLED",
                                      "crate": "crates/fixture"},
                    },
                    "scan_aliases": [f"fixture capability {index}"],
                }
                for index in range(capabilities)
            ],
        }
        (root / "docs/development/capability-registry.json").write_text(json.dumps(registry))
        (root / "docs/development/topology-manifest.json").write_text(
            json.dumps({"services": [{"name": "mta", "docker_target": "mta"}]}))
        (root / "docs/deployment-facts.json").write_text(json.dumps({"facts": {
            "fixture_fact": {
                "value": True, "implementation_stage": "runtime-wired",
                "binary_default": None, "managed_cloud_enabled": True,
                "enforcement_mode": "enforced", "monitored": False, "advertised": False,
                "evidence": "perf selftest fixture", "source": "perf selftest fixture",
            }
        }}))
        (root / "services/mail-server/Dockerfile").write_text(
            "FROM scratch AS runtime-base\nFROM runtime-base AS mta\n")
        (root / "docker-compose.yml").write_text("services:\n  mta:\n    image: fixture\n")
        (root / "docker-compose.prod.yml").write_text("services:\n  mta:\n    image: fixture\n")
        for index in range(rust_files):
            body = "\n".join(f"// filler line {line}" for line in range(20))
            if index == 0:
                body += "\n" + "\n".join(
                    f'pub const GATE_{cap}: &str = "PERF_GATE_{cap}_ENABLED";'
                    for cap in range(capabilities))
            (root / f"services/mail-server/crates/fixture/src/file{index}.rs").write_text(body)

    def test_each_rust_source_opened_at_most_once(self):
        with tempfile.TemporaryDirectory(prefix="capability-perf-") as tmp:
            root = Path(tmp)
            self._build_tree(root)
            wrapper = root / "wrapper.py"
            wrapper.write_text(self._WRAPPER)
            log = root / "opens.json"
            proc = subprocess.run([sys.executable, str(wrapper),
                                   str(root / "tools/check_capability_claims.py"), str(log)],
                                  check=False, cwd=root, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0,
                             (proc.stdout + proc.stderr)[-1200:])
            opened = json.loads(log.read_text())
        rust_paths = [path for path in opened if path.endswith(".rs")]
        self.assertEqual(len(rust_paths), 8)
        self.assertEqual(max(opened.values()), 1,
                         f"a Rust source was re-read: {sorted(opened.items(), key=lambda kv: -kv[1])[:3]}")
        self.assertEqual(sum(opened.values()), 8)


class DocsLintSinglePassTest(unittest.TestCase):
    """docs-lint must preprocess/scan each markdown file once; the former
    implementation ran mdprose.awk + checks.awk twice over the same corpus."""

    _SHIM = """#!/bin/sh
printf '%s\\n' "$*" >> "$AWK_LOG"
exec "{real}" "$@"
"""

    def _build_tree(self, root: Path) -> None:
        (root / "docs/guide").mkdir(parents=True)
        # Capital Resources/ is the byte-parity mirror name the script special-
        # cases; a lowercase resources/ tree is excluded by the scan filter.
        (root / "docs/Resources").mkdir(parents=True)
        (root / "README.md").write_text("# ApexMail\n\nProduct docs.\n")
        (root / "docs/guide/a.md").write_text(
            "# A\n\nThe platform is premium and seamless. The platform is premium and seamless.\n\n"
            "A **bold** and **bold** and **bold** paragraph.\n")
        (root / "docs/guide/b.md").write_text(
            "# B\n\nA plain sentence. Another plain sentence with a duplicate.\n\n"
            "A plain sentence. Another plain sentence with a duplicate.\n")
        (root / "docs/Resources/ACCESSIBILITY.md").write_text(
            "# A11y\n\nA plain sentence. Another plain sentence with a duplicate.\n")

    def test_one_prose_and_one_check_pass_per_markdown_file(self):
        shim_dir = Path(tempfile.mkdtemp(prefix="awk-shim-"))
        self.addCleanup(shutil.rmtree, shim_dir, True)
        real_awk = shutil.which("gawk") or shutil.which("awk")
        self.assertIsNotNone(real_awk)
        shim = shim_dir / "gawk"
        shim.write_text(self._SHIM.format(real=real_awk))
        shim.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix="docs-lint-perf-") as tmp:
            root = Path(tmp)
            self._build_tree(root)
            log = root / "awk.log"
            env = dict(os.environ, PATH=f"{shim_dir}:{os.environ.get('PATH', '')}",
                       AWK_LOG=str(log))
            proc = subprocess.run(["sh", str(REPO_ROOT / "tools/docs-lint.sh"), str(root)],
                                  capture_output=True, text=True, env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("TOTAL:", proc.stdout)
            invocations = log.read_text().splitlines()
        prose = [line for line in invocations if "mdprose.awk" in line]
        checks = [line for line in invocations if "checks.awk" in line]
        # 4 scanned markdown files (README + 3 docs). Old code: 8 + 8.
        self.assertEqual(len(prose), 4)
        self.assertEqual(len(checks), 4)


def perf_selfcheck() -> tuple[bool, list[str]]:
    """Run the perf-invariant suite for `--self-test`."""
    import io

    classes = (RedisBatchTest, CoverageIndexTest, RouteIndexTest, LedgerDedupeTest,
               MailReuseTest, CapabilityScanTest, DocsLintSinglePassTest)
    suite = unittest.TestSuite()
    for case in classes:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(case))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    lines = []
    for test, _trace in result.failures + result.errors:
        lines.append(f"FAIL: {test.id()}")
        detail = _trace.strip().splitlines()
        if detail:
            lines.append(f"      {detail[-1][:200]}")
    if result.wasSuccessful():
        lines.append(f"ok: {result.testsRun} performance-invariant tests "
                     "(batched DEL, indexed coverage/routes, linear dedupe, mail reuse, "
                     "one-pass docs-lint, single-read capability scan)")
    return result.wasSuccessful(), lines


if __name__ == "__main__":
    unittest.main(verbosity=2)
