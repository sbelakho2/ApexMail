#!/usr/bin/env python3
"""External route census gate (external audit 2026-10-26, exposure lane E16a).

The nginx configurations in this repository ARE the external boundary: every
internet-reachable route exists because a `server`/`location` block declares
it (the compliance service is deliberately NOT internet-routed — it has no
published port and no public vhost proxies to it). This gate keeps a committed
census of every route and fails when the boundary and the census drift:

  1. UNKNOWN route  — a location parsed from an nginx config that the manifest
                      does not classify → the operator must classify it
                      (anonymous / customer / internal / security-review).
  2. STALE entry    — a manifest entry whose (config, listen, server_name,
                      location) no longer parses from the configs, or whose
                      recorded action (proxy target / return / static root)
                      no longer matches → re-census the route.
  3. FORBIDDEN      — the patterns /v1/admin, /cp/, /internal/ and /claims
                      must never appear in a public (anonymous/customer)
                      location path. The /claims endpoints of the compliance
                      service are intentionally not internet-routed; this
                      asserts it mechanically. Loopback/internal locations
                      are exempt (that is where internal routes belong).
  4. COMPLIANCE     — a public (non-loopback) server block whose proxy_pass
                      targets the compliance service port fails: the
                      compliance service must stay off the internet.

Source of truth for discovery: every `*.conf` under deploy/nginx/ and every
`apps/*/nginx.conf` (both current configs live there; a new nginx config
outside those globs must be added to CONFIG_GLOBS below — the discovery
failure direction is loud, never silent).

--self-test proves all four failure directions on fixture configs in a temp
dir. --list prints the parsed census (handy when classifying a new route).

Exit codes: 0 = clean, 1 = violation, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "docs" / "operations" / "route-census.json"

# Where nginx configs live. The brief's boundary inventory: every server/
# location definition in the repo. Keep this list exhaustive; a config added
# anywhere else is invisible to the census until listed here.
CONFIG_GLOBS = (
    "deploy/nginx/*.conf",
    "deploy/nginx/**/*.conf",
    "apps/*/nginx.conf",
)

# Files under those globs that contain no server blocks (shared snippets).
# They are still parsed (harmless) — listed here only for documentation.
SNIPPETS = ("deploy/nginx/proxy-headers.conf",)

FORBIDDEN_PUBLIC_PATTERNS = ("/v1/admin", "/cp/", "/internal/", "/claims")
COMPLIANCE_HOST = "compliance"
COMPLIANCE_PORT = 3011
CLASSES = ("anonymous", "customer", "internal", "security-review")
# Classes that sit on the public internet without a staff gate: the
# forbidden-pattern rule applies to these.
PUBLIC_CLASSES = ("anonymous", "customer")


# ─── nginx parsing ──────────────────────────────────────────────────────────


def strip_comments(text: str) -> str:
    """Remove nginx comments (# to EOL) outside of quoted strings."""
    out = []
    for line in text.splitlines(keepends=True):
        buf = []
        quote = None
        for ch in line:
            if quote:
                buf.append(ch)
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
                buf.append(ch)
            elif ch == "#":
                break  # comment to EOL
            else:
                buf.append(ch)
        out.append("".join(buf))
    return "".join(out)


def tokenize(text: str) -> list[tuple[str, str]]:
    """Tokenize nginx config into ('word', w) / ('{', '') / ('}', '') / (';', '')."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch in "{};":
            tokens.append((ch, ""))
            i += 1
        elif ch in "\"'":
            quote = ch
            j = i + 1
            while j < n and text[j] != quote:
                j += 1
            tokens.append(("word", text[i + 1 : j]))
            i = j + 1
        else:
            j = i
            while j < n and not text[j].isspace() and text[j] not in "{};\"'":
                j += 1
            tokens.append(("word", text[i:j]))
            i = j
    return tokens


def parse_nodes(tokens, i=0):
    """Parse a token stream into nodes: ('directive', words) | ('block', words, kids)."""
    nodes = []
    while i < len(tokens):
        kind, val = tokens[i]
        if kind == "}":
            return nodes, i + 1
        if kind in ("{", ";"):
            i += 1
            continue
        words = []
        while i < len(tokens) and tokens[i][0] == "word":
            words.append(tokens[i][1])
            i += 1
        if i >= len(tokens):
            nodes.append(("directive", words))
            break
        if tokens[i][0] == "{":
            kids, i = parse_nodes(tokens, i + 1)
            nodes.append(("block", words, kids))
        else:  # ';'
            nodes.append(("directive", words))
            i += 1
    return nodes, i


def find_blocks(nodes, name: str):
    """Depth-first yield every block whose head word equals `name`."""
    for node in nodes:
        if node[0] == "block":
            if node[1] and node[1][0] == name:
                yield node
            yield from find_blocks(node[2], name)


def location_spec(words: list[str]) -> str:
    """Normalize a location modifier + path: '= /p', '~ ^/re$', '/prefix'."""
    rest = words[1:]
    if not rest:
        return ""
    if rest[0] in ("=", "~", "~*", "^@"):
        return f"{rest[0]} {' '.join(rest[1:])}"
    return " ".join(rest)


def action_of(kids) -> str:
    """Derive the stable action string for a location/server body."""
    internal = False
    proxy = None
    ret = None
    root = None
    for node in kids:
        if node[0] != "directive":
            continue
        words = node[1]
        if not words:
            continue
        if words[0] == "internal":
            internal = True
        elif words[0] == "proxy_pass" and len(words) > 1:
            proxy = " ".join(words[1:])
        elif words[0] == "return":
            ret = " ".join(words[1:])
        elif words[0] == "root" and len(words) > 1 and root is None:
            root = words[1]
    if internal:
        return "internal"
    if proxy:
        return f"proxy_pass {proxy}"
    if ret:
        return f"return {ret}"
    if root:
        return f"static root {root}"
    return "other"


def is_loopback_listen(args: list[str]) -> bool:
    """True when every listen directive binds loopback only."""
    if not args:
        return False  # no listen → nginx default :80 → public
    loopback = True
    has_listen = False
    for spec in args:
        has_listen = True
        host = spec.split(":", 1)[0] if ":" in spec else ""
        if host in ("127.0.0.1", "::1", "[::1]"):
            continue
        loopback = False
    return has_listen and loopback


def parse_config(text: str) -> list[dict]:
    """Parse one nginx config into its server blocks with locations."""
    nodes, _ = parse_nodes(tokenize(strip_comments(text)))
    servers = []
    for block in find_blocks(nodes, "server"):
        kids = block[2]
        listens = []
        server_names = []
        server_action = None
        locations = []
        for node in kids:
            if node[0] == "block" and node[1] and node[1][0] == "location":
                loc_kids = node[2]
                locations.append(
                    {
                        "location": location_spec(node[1]),
                        "action": action_of(loc_kids),
                    }
                )
            elif node[0] == "directive" and node[1]:
                head = node[1][0]
                if head == "listen":
                    listens.append(" ".join(node[1][1:]))
                elif head == "server_name":
                    server_names.append(" ".join(node[1][1:]))
        server_action = action_of(kids)
        servers.append(
            {
                "listen": " ; ".join(listens),
                "server_name": " ; ".join(server_names) or "(default)",
                "loopback": is_loopback_listen(listens),
                "server_action": server_action,
                "locations": locations,
            }
        )
    return servers


# ─── census ─────────────────────────────────────────────────────────────────


def discover_configs(root: Path, globs: tuple[str, ...] = CONFIG_GLOBS) -> list[str]:
    found: set[str] = set()
    for pattern in globs:
        for path in root.glob(pattern):
            if path.is_file():
                found.add(path.relative_to(root).as_posix())
    return sorted(found)


def census_repo(root: Path) -> dict[tuple, dict]:
    """Parse every discovered config into a keyed census (first-wins on dupes)."""
    census: dict[tuple, dict] = {}
    for rel in discover_configs(root):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for server in parse_config(text):
            for loc in server["locations"]:
                key = (rel, server["listen"], server["server_name"], loc["location"])
                if key in census:
                    continue  # duplicate declaration (e.g. two `location /`)
                census[key] = {
                    "action": loc["action"],
                    "loopback": server["loopback"],
                    "server_action": server["server_action"],
                }
    return census


def entry_key(entry: dict) -> tuple:
    return (
        entry.get("config", ""),
        entry.get("listen", ""),
        entry.get("server_name", ""),
        entry.get("location", ""),
    )


def compliance_leaks(servers: list[dict], port: int, host: str) -> list[str]:
    """Public server blocks proxying to the compliance service."""
    problems = []
    for server in servers:
        if server["loopback"]:
            continue
        targets = []
        if server["server_action"].startswith("proxy_pass "):
            targets.append(server["server_action"][len("proxy_pass ") :])
        for loc in server["locations"]:
            if loc["action"].startswith("proxy_pass "):
                targets.append(loc["action"][len("proxy_pass ") :])
        for target in targets:
            if re.search(rf"[:/]({re.escape(host)})(:\d+)?(/|$)", target) or re.search(
                rf":{port}\b", target
            ):
                problems.append(
                    f"public vhost (listen {server['listen'] or '(default)'}, "
                    f"server_name {server['server_name']}) proxies to the compliance "
                    f"service ({target}) — the compliance service is NOT internet-routed"
                )
    return problems


def run_checks(manifest_path: Path = MANIFEST_PATH, root: Path = REPO_ROOT) -> list[str]:
    problems: list[str] = []
    if not manifest_path.is_file():
        return [f"manifest missing: {manifest_path} (commit the route census)"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"manifest unreadable: {error}"]
    entries = manifest.get("routes")
    if not isinstance(entries, list):
        return ["manifest has no 'routes' array"]

    patterns = tuple(manifest.get("forbidden_public_patterns", FORBIDDEN_PUBLIC_PATTERNS))
    compliance_port = int(manifest.get("compliance_service_port", COMPLIANCE_PORT))

    configs = discover_configs(root)
    if not configs:
        return ["no nginx configs discovered — CONFIG_GLOBS is stale or the tree is empty"]

    # Fresh census from the configs.
    parsed = census_repo(root)
    manifest_keys = set()
    for entry in entries:
        key = entry_key(entry)
        manifest_keys.add(key)
        cls = entry.get("class", "")
        if cls not in CLASSES:
            problems.append(
                f"manifest entry {key} has invalid class {cls!r} "
                f"(expected one of {', '.join(CLASSES)})"
            )
        got = parsed.get(key)
        if got is None:
            problems.append(
                f"STALE manifest entry (config={key[0]}, listen={key[1]!r}, "
                f"server_name={key[2]!r}, location={key[3]!r}) no longer exists in "
                f"the nginx configs — re-census the route"
            )
            continue
        if got["action"] != entry.get("action"):
            problems.append(
                f"STALE manifest action for {key}: recorded {entry.get('action')!r}, "
                f"configs now say {got['action']!r} — re-census the route"
            )

    # 1. Unknown routes + 3. forbidden patterns on public locations.
    for key, got in sorted(parsed.items()):
        if key not in manifest_keys:
            problems.append(
                f"UNKNOWN public route not in the census: config={key[0]}, "
                f"listen={key[1]!r}, server_name={key[2]!r}, location={key[3]!r} "
                f"({got['action']}) — classify it in {manifest_path.name} "
                f"(anonymous/customer/internal/security-review)"
            )
            continue
        entry = next(e for e in entries if entry_key(e) == key)
        if entry.get("class") in PUBLIC_CLASSES and not got["loopback"]:
            for pattern in patterns:
                if pattern in key[3]:
                    problems.append(
                        f"FORBIDDEN pattern {pattern!r} in public location "
                        f"{key[3]!r} (config={key[0]}, server_name={key[2]!r}, "
                        f"class={entry.get('class')})"
                    )

    # 4. Compliance service must stay off every public vhost.
    for rel in configs:
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        for problem in compliance_leaks(parse_config(text), compliance_port, COMPLIANCE_HOST):
            problems.append(f"{rel}: {problem}")

    return problems


def class_counts(manifest_path: Path) -> dict[str, int]:
    counts = {cls: 0 for cls in CLASSES}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest.get("routes", []):
        cls = entry.get("class", "")
        counts[cls] = counts.get(cls, 0) + 1
    return counts


def list_routes(root: Path = REPO_ROOT) -> None:
    census = census_repo(root)
    for key in sorted(census):
        got = census[key]
        print(
            json.dumps(
                {
                    "config": key[0],
                    "listen": key[1],
                    "server_name": key[2],
                    "location": key[3],
                    "action": got["action"],
                    "loopback": got["loopback"],
                }
            )
        )


# ─── self-test ──────────────────────────────────────────────────────────────

FIXTURE_CONF = """
http {
    server {
        listen 127.0.0.1:9000;
        server_name loopback-internal;
        location /internal/metrics { return 200; }
    }
    server {
        listen 443 ssl;
        server_name fixture.example;
        location = / { return 301 https://fixture.example/docs/; }
        location /docs/ { proxy_pass http://docs:8080; }
        location /v1/ { proxy_pass http://api:3000; }
    }
}
"""


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        conf_dir = root / "deploy" / "nginx"
        conf_dir.mkdir(parents=True)
        conf_path = conf_dir / "nginx.conf"

        def manifest_for(conf_text: str, extra_routes=()) -> Path:
            """Write the conf, census IT, and emit a matching manifest."""
            conf_path.write_text(conf_text)
            return emit_manifest(extra_routes)

        def emit_manifest(extra_routes=()) -> Path:
            parsed = census_repo(root)
            routes = [
                {
                    "config": "deploy/nginx/nginx.conf",
                    "listen": key[1],
                    "server_name": key[2],
                    "location": key[3],
                    "action": got["action"],
                    "class": "internal"
                    if got["loopback"]
                    or key[3].startswith("= /404")
                    else ("customer" if key[3].startswith("/v1") else "anonymous"),
                    "note": "fixture",
                }
                for key, got in parsed.items()
            ]
            routes.extend(extra_routes)
            path = root / "manifest.json"
            path.write_text(
                json.dumps(
                    {
                        "forbidden_public_patterns": list(FORBIDDEN_PUBLIC_PATTERNS),
                        "compliance_service_port": COMPLIANCE_PORT,
                        "routes": routes,
                    }
                )
            )
            return path

        # (a) clean fixture passes.
        manifest = manifest_for(FIXTURE_CONF)
        problems = run_checks(manifest, root)
        assert not problems, problems

        # loopback internal location carrying a forbidden pattern is EXEMPT.
        conf = FIXTURE_CONF.replace(
            "location /internal/metrics { return 200; }",
            "location /internal/admin-panel { return 200; }",
        )
        manifest = manifest_for(conf)
        problems = run_checks(manifest, root)
        assert not problems, problems

        # (b) unknown public location fails: manifest from the BASE conf,
        # configs gain a route the census does not know.
        manifest = manifest_for(FIXTURE_CONF)
        conf_path.write_text(
            FIXTURE_CONF.replace(
                "location /v1/ { proxy_pass http://api:3000; }",
                "location /v1/ { proxy_pass http://api:3000; }\n"
                "        location /v1/newly-added { proxy_pass http://api:3000; }",
            )
        )
        problems = run_checks(manifest, root)
        assert any("UNKNOWN" in p for p in problems), problems
        conf_path.write_text(FIXTURE_CONF)

        # (c) stale manifest entry fails (extra entry not in config).
        manifest = manifest_for(
            FIXTURE_CONF,
            extra_routes=[
                {
                    "config": "deploy/nginx/nginx.conf",
                    "listen": "443 ssl",
                    "server_name": "fixture.example",
                    "location": "/retired/",
                    "action": "proxy_pass http://gone:8080",
                    "class": "anonymous",
                    "note": "removed route",
                }
            ],
        )
        problems = run_checks(manifest, root)
        assert any("STALE" in p for p in problems), problems

        # (c2) stale ACTION fails (route re-pointed without re-census).
        conf = FIXTURE_CONF.replace(
            "proxy_pass http://docs:8080", "proxy_pass http://other:9090"
        )
        manifest = manifest_for(FIXTURE_CONF)  # manifest recorded the OLD action
        conf_path.write_text(conf)
        problems = run_checks(manifest, root)
        assert any("STALE manifest action" in p for p in problems), problems
        conf_path.write_text(FIXTURE_CONF)

        # (d) forbidden public location fails once manifested.
        conf = FIXTURE_CONF.replace(
            "location /v1/ { proxy_pass http://api:3000; }",
            "location /v1/ { proxy_pass http://api:3000; }\n"
            "        location /v1/admin { proxy_pass http://api:3000; }",
        )
        manifest = manifest_for(conf)
        problems = run_checks(manifest, root)
        assert any("FORBIDDEN" in p and "/v1/admin" in p for p in problems), problems

        # (e) public vhost proxying to the compliance service fails.
        conf = FIXTURE_CONF.replace(
            "location /v1/ { proxy_pass http://api:3000; }",
            "location /v1/ { proxy_pass http://api:3000; }\n"
            "        location /claims/ { proxy_pass http://compliance:3011/; }",
        )
        manifest = manifest_for(conf)
        problems = run_checks(manifest, root)
        assert any("compliance" in p for p in problems), problems

        # (f) loopback vhost may proxy to compliance (not internet-routed).
        conf = FIXTURE_CONF.replace(
            "location /internal/metrics { return 200; }",
            "location /claims/ { proxy_pass http://compliance:3011/; }",
        )
        manifest = manifest_for(conf)
        problems = run_checks(manifest, root)
        assert not problems, problems

    print("route-census self-test: ok (clean, unknown, stale, forbidden, compliance)")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true", help="print the parsed census")
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.list:
        list_routes(args.root)
        return 0
    problems = run_checks(args.manifest, args.root)
    if problems:
        for problem in problems:
            print(f"route-census: {problem}", file=sys.stderr)
        return 1
    counts = class_counts(args.manifest)
    summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
    print(f"route-census: OK ({sum(counts.values())} routes classified: {summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
