#!/usr/bin/env python3
"""KiwiCaptcha mirror advance and parity proof.

ApexMail mirrors the parts of the standalone KiwiCaptcha repository it
actually consumes (owner directive 2026-10-28: the PHP packages and their
browser suite are NOT carried — the product surface is Rust-only):
packages/kiwicaptcha (the Rust crate api-server links, including upstream's
own integrations/ bytes for exact parity), packages/kiwicaptcha-risk and
packages/kiwicaptcha-wasm (Rust satellites with their own gates), and
protocol/ (include_str!-embedded wire contracts). The standalone repo is a
SEPARATE project: this tool reads it (git only, never the worktree, never
writes) and writes only ApexMail-side paths.

--apply walks a per-file diff instead of rsyncing whole trees, so anything
ApexMail owns inside a mirrored path survives every advance. (tests/browser
used to hold 19 ApexMail journey scripts that a whole-tree rsync destroyed
on 2026-10-28 before they were relocated to tests/journeys/.)

Usage:
  python3 tools/kiwi_mirror_advance.py --check [--upstream DIR]
  python3 tools/kiwi_mirror_advance.py --apply OLD_SHA NEW_SHA [--upstream DIR]

--check proves byte parity: every upstream-tracked path under the surface must
exist in the mirror with the identical git blob hash. Exit 1 on any missing or
mismatched path. ApexMail-owned extras are reported but never a failure.

After --apply, the manual repairs that every advance has needed:
  1. touch packages/kiwicaptcha/src and protocol/execution-v1.json — the crate
     include_str!s both, and preserved mtimes can skip the rebuild;
  2. if a lane normalizes packages/kiwicaptcha/Cargo.lock, restore it;
  3. run the scoped battery: cargo nextest run -p kiwicaptcha (the workspace
     suite), the crate's --features redis lane, cargo check -p api-server
     -p integration-tests, and the kiwicaptcha-wasm satellite suite.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SURFACES = (
    "packages/kiwicaptcha",
    "packages/kiwicaptcha-risk",
    "packages/kiwicaptcha-wasm",
    "protocol",
)

# Upstream bytes under a mirrored path that ApexMail does NOT carry (owner
# directive 2026-10-28: no PHP in the mirror). The Symfony bundle lives
# inside the crate's own upstream layout; the Rust crate never reads it at
# build time, so excluding it keeps the mirror PHP-free without forking the
# crate's path. Re-check this list on every advance.
EXCLUDES = (
    "packages/kiwicaptcha/integrations/",
)


def excluded(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in EXCLUDES)


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def upstream_tree(upstream: Path, rev: str) -> dict[str, str]:
    out = git(upstream, "ls-tree", "-r", rev, *SURFACES)
    tree: dict[str, str] = {}
    for line in out.splitlines():
        meta, path = line.split("\t", 1)
        _mode, kind, blob = meta.split()
        if kind == "blob":
            tree[path] = blob
    return tree


def check(apex: Path, upstream: Path, rev: str = "HEAD") -> int:
    tree = {
        path: blob
        for path, blob in upstream_tree(upstream, rev).items()
        if not excluded(path)
    }
    tracked_apex = set(git(apex, "ls-files", *SURFACES).splitlines())
    missing, mismatch, extras, stray = [], [], [], []
    for path, blob in sorted(tree.items()):
        target = apex / path
        if not target.is_file():
            missing.append(path)
            continue
        local = git(apex, "hash-object", "--no-filters", str(target)).strip()
        if local != blob:
            mismatch.append(path)
    extras = sorted(p for p in tracked_apex if p not in tree and not excluded(p))
    stray = sorted(p for p in tracked_apex if excluded(p))
    print(f"upstream paths proved: {len(tree) - len(missing) - len(mismatch)}/{len(tree)}")
    for label, rows in (("MISSING", missing), ("MISMATCH", mismatch)):
        for path in rows:
            print(f"{label}: {path}")
    if extras:
        print(f"ApexMail-owned extras inside the surface ({len(extras)}, preserved by --apply):")
        for path in extras:
            print(f"  extra: {path}")
    if stray:
        print(f"STRAY excluded bytes tracked in the mirror ({len(stray)}) — remove them:", file=sys.stderr)
        for path in stray:
            print(f"  stray: {path}")
    if missing or mismatch or stray:
        print("PARITY FAILED", file=sys.stderr)
        return 1
    print("PARITY OK")
    return 0


def apply(apex: Path, upstream: Path, old: str, new: str) -> int:
    out = git(upstream, "diff", "--name-status", old, new, "--", *SURFACES)
    added = changed = deleted = 0
    for line in out.splitlines():
        status, path = line.split("\t", 1)
        if excluded(path):
            continue
        target = apex / path
        if status.startswith("D"):
            if path in set(git(apex, "ls-files", path).splitlines()):
                git(apex, "rm", "-q", "--", path)
            elif target.exists():
                target.unlink()
            deleted += 1
            continue
        content = subprocess.run(
            ["git", "-C", str(upstream), "show", f"{new}:{path}"],
            check=True,
            capture_output=True,
        ).stdout
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        if path in set(git(apex, "ls-files", path).splitlines()):
            changed += 1
        else:
            added += 1
    print(f"applied: {added} added, {changed} changed, {deleted} deleted")
    return check(apex, upstream, new)


def main() -> int:
    here = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--upstream", default=str(here.parent / "kiwicaptcha-standalone"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="prove byte parity of the mirror surface")
    group.add_argument("--apply", nargs=2, metavar=("OLD_SHA", "NEW_SHA"), help="apply the upstream diff per file")
    args = parser.parse_args()

    upstream = Path(args.upstream).resolve()
    if not (upstream / ".git").exists():
        print(f"upstream repo not found: {upstream}", file=sys.stderr)
        return 2
    if args.check:
        return check(here, upstream)
    old, new = args.apply
    return apply(here, upstream, old, new)


if __name__ == "__main__":
    sys.exit(main())
