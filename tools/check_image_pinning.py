#!/usr/bin/env python3
"""Immutable image-pinning gate (external audit item 5).

Given a RENDERED compose config — the JSON of `docker compose config
--format json`, or a committed fixture of the same shape — fail when any
service's image is not content-pinned:

  * an image under the first-party namespace (default
    `ghcr.io/sbelakho2/apexmail`, override with `--namespace` / `GHCR_NS`)
    MUST be pinned either as `repo@sha256:<64-hex>` (OCI digest — the form
    the release manifest records and the digest override renders) or as
    `repo:<40-hex>` (the full git-SHA rollback tag — the no-registry
    fallback for daemons that do not record local repo digests; the run's
    `release-manifest.json` + deploy-stage digest verification are the
    tamper evidence for that form).
    `:latest`, bare repos, version tags and short SHAs are all REJECTED:
    a manual `docker compose up` must never resolve a mutable reference.
  * a third-party image (postgres, redis, grafana/*, …) MUST be on the
    explicit allowlist below. The allowlist is DERIVED from the images the
    pipeline does not build (every `image:` reference in
    `docker-compose.yml` + `docker-compose.prod.yml` that is not a
    first-party build) and is exact by design: a NEW third-party dependency
    fails until it is added here deliberately. Allowlisted images are
    exempt from pinning entirely (compose date/version-tags them; the
    audit's self-test case "third-party :latest passes via allowlist").

Wire-up (see ci/README.md and deploy/DEPLOYMENT.md):
  * validate stage: runs the committed FIXTURES through `--self-test` and
    the pass/fail cases — proves the checker's teeth without docker.
  * ci/stages/deploy.sh: the LIVE gate — renders the exact config the
    deploy is about to create (base + prod + digest override + env +
    monitoring profile) and runs this checker over it, scoped to the
    canonical service set (`--only-services`).

Usage:
  check_image_pinning.py <rendered.json> [more.json ...]
                         [--namespace NS] [--allowlist "repo1 repo2/* ..."]
                         [--only-services "svc1,svc2 ..."] [--quiet]
  check_image_pinning.py --self-test

Exit codes: 0 = every image pinned/allowlisted, 1 = pinning violations,
2 = usage/IO/JSON error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

DEFAULT_NAMESPACE = "ghcr.io/sbelakho2/apexmail"

# Third-party images the pipeline PULLS but never builds. Derived from the
# `image:` references of docker-compose.yml + docker-compose.prod.yml that do
# not carry the first-party namespace — keep in lockstep with those files (the
# validate stage's image-name guard derives the same split independently).
# `repo/*` entries are prefix patterns; everything else is an exact repo match.
DEFAULT_ALLOWLIST = frozenset(
    {
        # edge + TLS
        "nginx",
        "certbot/certbot",
        # data stores
        "postgres",
        "redis",
        "clickhouse/clickhouse-server",
        # monitoring stack (date-pinned sidecars)
        "prom/prometheus",
        "prom/alertmanager",
        "prom/node-exporter",
        "prom/blackbox-exporter",
        "grafana/grafana",
        "grafana/loki",
        "grafana/tempo",
        "otel/opentelemetry-collector-contrib",
        "prometheuscommunity/postgres-exporter",
        "oliver006/redis_exporter",
        # apexmail/ namespace but NOT pipeline builds: date-pinned exporters
        "apexmail/clickhouse-exporter",
        "apexmail/synthetic-monitor",
        # dev-only mail catcher
        "axllent/mailpit",
    }
)

OCI_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
GIT_SHA_TAG_RE = re.compile(r"^[0-9a-f]{40}$")


def parse_ref(ref: str) -> tuple[str, str, str]:
    """Split an image reference into (repo, tag, digest).

    Handles registry ports (`localhost:5000/repo:tag`), digests
    (`repo@sha256:...`) and the combined `repo:tag@sha256:...` form.
    """
    digest = ""
    repo_tag = ref
    if "@" in ref:
        repo_tag, digest = ref.rsplit("@", 1)
    tail = repo_tag.rsplit("/", 1)[-1]
    if ":" in tail:
        idx = repo_tag.rfind(":")
        return repo_tag[:idx], repo_tag[idx + 1 :], digest
    return repo_tag, "", digest


def is_pinned(ref: str) -> bool:
    repo, tag, digest = parse_ref(ref)
    if digest:
        return bool(OCI_DIGEST_RE.match(digest))
    if tag:
        # Full git-SHA rollback pin (ci/stages/images.sh tags `:$CI_SHA`,
        # the full 40-hex commit SHA). Version tags / short SHAs drift.
        return bool(GIT_SHA_TAG_RE.match(tag))
    return False


def pin_form(ref: str) -> str:
    repo, tag, digest = parse_ref(ref)
    if digest:
        return "digest"
    if tag:
        return "git-sha-tag"
    return "unpinned"


def load_services(path: str) -> dict[str, dict]:
    """Read a rendered compose config; return {service: {"image": ...}}.

    Accepts the canonical `docker compose config --format json` shape
    ({"services": {name: {...}}}) and the flat fixture shorthand
    ({name: {...}}). A JSON-array "services" value is an unsupported
    (compose v1) shape → error.
    """
    with open(path, encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"2: {path}: not valid JSON: {exc}")
    if not isinstance(doc, dict):
        raise SystemExit(f"2: {path}: expected a JSON object at the top level")
    services = doc.get("services", doc)
    if not isinstance(services, dict):
        raise SystemExit(
            f"2: {path}: 'services' must be an object mapping service -> config "
            "(compose v1 list shapes are not supported)"
        )
    return services


def check_file(
    path: str,
    namespace: str,
    allowlist: frozenset[str],
    only_services: set[str] | None,
    quiet: bool,
) -> list[str]:
    violations: list[str] = []
    services = load_services(path)
    names = sorted(services)
    for name in names:
        if only_services is not None and name not in only_services:
            continue
        cfg = services.get(name) or {}
        if not isinstance(cfg, dict):
            violations.append(f"{path}: service '{name}': config is not an object")
            continue
        ref = cfg.get("image")
        if not ref or not isinstance(ref, str):
            # A service without an image key (build:-only, profiles excluded
            # from the rendering) has nothing to pin — not a violation here;
            # the deploy-stage live gate only ever sees rendered images.
            continue
        repo, _tag, _digest = parse_ref(ref)
        allowlisted = repo in allowlist or any(
            pat.endswith("/*") and repo.startswith(pat[:-1]) for pat in allowlist
        )
        if allowlisted:
            if not quiet:
                print(f"  ok   {name}: {ref} (third-party allowlist)")
            continue
        first_party = repo == namespace or repo.startswith(namespace + "/")
        if first_party:
            if is_pinned(ref):
                if not quiet:
                    print(f"  ok   {name}: {ref} ({pin_form(ref)})")
            else:
                violations.append(
                    f"{path}: service '{name}': image '{ref}' is not content-pinned "
                    f"(expected {namespace}/…@sha256:<digest> or the full :<git-sha> "
                    "rollback tag — ':latest'/version tags resolve mutable content)"
                )
        else:
            violations.append(
                f"{path}: service '{name}': third-party image '{ref}' is not on the "
                "pinning allowlist — pin it (digest or full git-sha tag) or add its "
                "repository to DEFAULT_ALLOWLIST deliberately"
            )
    return violations


def self_test() -> int:
    """Prove the gate end-to-end on inline fixtures (no docker needed).

    This is the same matrix the validate stage asserts via the committed
    fixtures under tools/fixtures/compose_pinning/.
    """
    ns = DEFAULT_NAMESPACE
    cases: list[tuple[str, dict, int]] = [
        (
            "digest-pinned first-party passes",
            {"services": {"api-server": {"image": f"{ns}/api-server@sha256:" + "a" * 64}}},
            0,
        ),
        (
            "full git-sha tag pin passes (no-registry fallback)",
            {"services": {"mta": {"image": f"{ns}/mta:" + "b" * 40}}},
            0,
        ),
        (
            ":latest first-party FAILS",
            {"services": {"api-server": {"image": f"{ns}/api-server:latest"}}},
            1,
        ),
        (
            "version tag first-party FAILS",
            {"services": {"worker": {"image": f"{ns}/worker:1.2.3"}}},
            1,
        ),
        (
            "short-sha tag first-party FAILS",
            {"services": {"worker": {"image": f"{ns}/worker:" + "c" * 7}}},
            1,
        ),
        (
            "bare repo first-party FAILS",
            {"services": {"worker": {"image": f"{ns}/worker"}}},
            1,
        ),
        (
            "allowlisted third-party :latest passes",
            {"services": {"db": {"image": "postgres:16-alpine"}}},
            0,
        ),
        (
            "unknown third-party FAILS (allowlist is exact)",
            {"services": {"edge": {"image": "caddy:2"}}},
            1,
        ),
        (
            "--only-services scopes the check",
            {
                "services": {
                    "in-scope": {"image": f"{ns}/in-scope:latest"},
                    "out-of-scope": {"image": f"{ns}/out-of-scope:latest"},
                }
            },
            1,
        ),
        (
            "malformed digest FAILS (not 64 hex)",
            {"services": {"api-server": {"image": f"{ns}/api-server@sha256:deadbeef"}}},
            1,
        ),
    ]
    import tempfile

    failures = 0
    for label, doc, expected in cases:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(doc, fh)
            tmp = fh.name
        try:
            if label == "--only-services scopes the check":
                violations = check_file(
                    tmp, ns, DEFAULT_ALLOWLIST, {"in-scope"}, quiet=True
                )
            else:
                violations = check_file(tmp, ns, DEFAULT_ALLOWLIST, None, quiet=True)
            got = 1 if violations else 0
            verdict = "ok  " if got == expected else "FAIL"
            if got != expected:
                failures += 1
                for v in violations:
                    print(f"    {v}")
            print(f"  {verdict} [{expected}] {label}")
        finally:
            os.unlink(tmp)
    if failures:
        print(f"self-test: {failures} case(s) FAILED", file=sys.stderr)
        return 1
    print("self-test: ALL OK")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("configs", nargs="*", help="rendered compose config JSON file(s)")
    ap.add_argument(
        "--namespace",
        default=os.environ.get("GHCR_NS", DEFAULT_NAMESPACE),
        help="first-party image namespace (default: GHCR_NS or "
        f"{DEFAULT_NAMESPACE})",
    )
    ap.add_argument(
        "--allowlist",
        default=os.environ.get("APEXMAIL_PINNING_ALLOWLIST", ""),
        help="extra allowlisted repositories, whitespace/comma-separated "
        "(extends the built-in list; 'repo/*' entries are prefix patterns)",
    )
    ap.add_argument(
        "--only-services",
        default="",
        help="restrict the check to these services (whitespace/comma-separated)",
    )
    ap.add_argument("--quiet", action="store_true", help="only print violations")
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="run the inline fixture matrix instead of checking files",
    )
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.configs:
        ap.error("no compose config JSON given (or use --self-test)")

    allowlist = set(DEFAULT_ALLOWLIST)
    for entry in re.split(r"[\s,]+", args.allowlist.strip()):
        if entry:
            allowlist.add(entry)
    only = None
    if args.only_services.strip():
        only = {s for s in re.split(r"[\s,]+", args.only_services.strip()) if s}

    all_violations: list[str] = []
    for path in args.configs:
        if not os.path.isfile(path):
            print(f"2: config file not found: {path}", file=sys.stderr)
            return 2
        all_violations.extend(
            check_file(path, args.namespace, frozenset(allowlist), only, args.quiet)
        )
    if all_violations:
        for v in all_violations:
            print(f"PINNING VIOLATION: {v}", file=sys.stderr)
        print(
            f"image pinning: {len(all_violations)} violation(s) — "
            "see deploy/DEPLOYMENT.md (immutable deployment artifacts)",
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        print("image pinning: all services content-pinned or explicitly allowlisted")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
