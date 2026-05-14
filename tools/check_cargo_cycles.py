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


def main() -> int:
    metadata = load_metadata()
    workspace_ids = set(metadata["workspace_members"])
    names = {package["id"]: package["name"] for package in metadata["packages"]}
    graph: dict[str, list[str]] = {package_id: [] for package_id in workspace_ids}

    for node in metadata["resolve"]["nodes"]:
        package_id = node["id"]
        if package_id not in workspace_ids:
            continue
        graph[package_id] = [dep for dep in node["dependencies"] if dep in workspace_ids]

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
            readable = " -> ".join(names.get(pid, pid) for pid in cycle)
            print(f"workspace dependency cycle detected: {readable}", file=sys.stderr)
            return 1

    print("workspace dependency cycle check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())