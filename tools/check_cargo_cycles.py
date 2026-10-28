#!/usr/bin/env python3
"""Fail if Cargo workspace package dependencies contain a cycle."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "services" / "mail-server" / "Cargo.toml"


def load_metadata() -> dict:
    output = subprocess.check_output(
        ["cargo", "metadata", "--manifest-path", str(MANIFEST), "--format-version", "1"],
        text=True,
        timeout=120,
    )
    return json.loads(output)


def build_graph(metadata: dict) -> dict[str, list[str]]:
    """workspace-member id -> workspace-member dependency ids (self-edges skipped)."""
    workspace_ids = set(metadata["workspace_members"])
    graph: dict[str, list[str]] = {package_id: [] for package_id in workspace_ids}

    for node in metadata["resolve"]["nodes"]:
        package_id = node["id"]
        if package_id not in workspace_ids:
            continue
        # A crate's self-path dev-dependency (`outbound-mta = { path = ".",
        # features = ["test-support"] }`) is the standard cargo idiom for
        # enabling an own feature in tests — cargo itself accepts it, and a
        # genuine unit cycle is rejected by cargo outright. Skip self-edges
        # so the idiom is not misread as a dependency cycle.
        graph[package_id] = [
            dep
            for dep in node["dependencies"]
            if dep in workspace_ids and dep != package_id
        ]
    return graph


def first_cycle(graph: dict[str, list[str]], names: dict[str, str]) -> list[str] | None:
    """First dependency cycle found (package ids), or None for a DAG."""
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(package_id: str) -> list[str] | None:
        if package_id in visiting:
            start = visiting.index(package_id)
            return visiting[start:] + [package_id]
        if package_id in visited:
            return None
        visiting.append(package_id)
        for dep in graph.get(package_id, []):
            cycle = visit(dep)
            if cycle:
                return cycle
        visiting.pop()
        visited.add(package_id)
        return None

    for package_id in sorted(graph, key=lambda pid: names.get(pid, pid)):
        cycle = visit(package_id)
        if cycle:
            return cycle
    return None


def main(metadata: dict | None = None) -> int:
    if metadata is None:
        metadata = load_metadata()
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    graph = build_graph(metadata)
    cycle = first_cycle(graph, names)
    if cycle:
        readable = " -> ".join(names.get(pid, pid) for pid in cycle)
        print(f"workspace dependency cycle detected: {readable}", file=sys.stderr)
        return 1

    print("workspace dependency cycle check passed")
    return 0


def self_test() -> int:
    """Prove the cycle gate on fixture manifests (cargo is never invoked)."""
    import contextlib
    import io
    import re
    import tempfile

    name_re = re.compile(r'^name\s*=\s*"([^"]+)"', re.M)
    dep_re = re.compile(r'^([A-Za-z0-9_-]+)\s*=\s*\{\s*path\s*=\s*"([^"]+)"', re.M)

    def workspace(manifests: dict[str, list[str]]) -> dict:
        """A cargo-metadata-shaped dict parsed out of fixture manifests."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for crate, deps in manifests.items():
                manifest = root / crate / "Cargo.toml"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(
                    f'[package]\nname = "{crate}"\nversion = "0.1.0"\n\n[dependencies]\n'
                    + "".join(
                        f'{d} = {{ path = "{"" if d == crate else "../" + d}" }}\n'
                        for d in deps
                    )
                )
            files = sorted(root.glob("*/Cargo.toml"))
            names = {f.parent.resolve(): name_re.search(f.read_text()).group(1) for f in files}
            pid = {d: f"path+file://{d}#{n}@0.1.0" for d, n in names.items()}
            return {
                "packages": [{"id": pid[d], "name": n} for d, n in names.items()],
                "workspace_members": list(pid.values()),
                "resolve": {
                    "nodes": [
                        {
                            "id": pid[f.parent.resolve()],
                            "dependencies": [
                                pid[(f.parent.resolve() / m.group(2)).resolve()]
                                for m in dep_re.finditer(f.read_text())
                            ],
                        }
                        for f in files
                    ]
                },
            }

    def run(manifests: dict[str, list[str]]) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = main(workspace(manifests))
        return code, out.getvalue()

    code, out = run({"app": ["lib-a"], "lib-a": ["lib-b"], "lib-b": []})
    if code != 0:
        print(f"self-test FAIL: clean DAG flagged (exit {code}): {out}", file=sys.stderr)
        return 1
    # Real cycle: app -> lib-a -> app.
    code, out = run({"app": ["lib-a"], "lib-a": ["app"], "lib-b": []})
    if code != 1 or "app -> lib-a -> app" not in out:
        print(f"self-test FAIL: dependency cycle not caught (exit {code}): {out}", file=sys.stderr)
        return 1
    # Self-path dev-dependency idiom (`path = "."`) must stay legal.
    code, out = run({"app": ["app"]})
    if code != 0:
        print(f"self-test FAIL: self-path dev-dependency misread as a cycle: {out}", file=sys.stderr)
        return 1

    print("self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    raise SystemExit(main())