#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlsplit, urlunsplit


DEFAULT_BROWSER = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_ARTIFACT_DIR = "reports/visual-parity/live-browser-smoke"
DEFAULT_TIMEOUT_MS = 2000


@dataclass(frozen=True)
class Viewport:
    name: str
    width: int
    height: int


@dataclass(frozen=True)
class RouteCheck:
    route_id: str
    group: str
    path: str
    expected_fragments: tuple[str, ...]
    host_override: str | None = None


VIEWPORTS = {
    "desktop": Viewport("desktop", 1440, 900),
    "tablet": Viewport("tablet", 834, 1194),
    "mobile": Viewport("mobile", 390, 844),
}


ROUTE_CHECKS = (
    RouteCheck(
        route_id="home",
        group="public",
        path="/",
        expected_fragments=(
            "ApexMail",
            "Modern email infrastructure for developers",
            "Go to Dashboard",
        ),
    ),
    RouteCheck(
        route_id="login",
        group="auth",
        path="/login",
        expected_fragments=(
            "Welcome back",
            "Enter your credentials to access the console",
            "Security check pending",
        ),
    ),
    RouteCheck(
        route_id="signup",
        group="auth",
        path="/signup",
        expected_fragments=(
            "Create your account",
            "Start sending with ApexMail in minutes",
            "Create Account",
        ),
    ),
    RouteCheck(
        route_id="forgot-password",
        group="auth",
        path="/forgot-password",
        expected_fragments=(
            "Reset your password",
            "Send Reset Link",
        ),
    ),
    RouteCheck(
        route_id="verify-email",
        group="auth",
        path="/verify-email",
        expected_fragments=(
            "Check your email",
            "Verification pending",
        ),
    ),
    RouteCheck(
        route_id="marketing-home",
        group="marketing",
        path="/",
        expected_fragments=(
            "ApexMail - Enterprise Email API for Developers",
            "Everything you need to send email.",
        ),
        host_override="apexmail.ee",
    ),
    RouteCheck(
        route_id="pricing",
        group="marketing",
        path="/pricing",
        expected_fragments=(
            "ApexMail - Enterprise Email API for Developers",
            "Frequently Asked Questions",
        ),
        host_override="apexmail.ee",
    ),
    RouteCheck(
        route_id="api-console",
        group="marketing",
        path="/api-console",
        expected_fragments=(
            "ApexMail - Enterprise Email API for Developers",
            "Explore the API",
            "Go from Playground to Production",
        ),
        host_override="apexmail.ee",
    ),
    RouteCheck(
        route_id="compare",
        group="marketing",
        path="/compare",
        expected_fragments=(
            "ApexMail vs Postmark | Feature Comparison",
            "ApexMail vs Resend | Feature Comparison",
            "ApexMail vs SendGrid | Feature Comparison",
        ),
        host_override="apexmail.ee",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Headless Brave browser smoke checks for live ApexMail routes."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for the live Rust-served app (default: {DEFAULT_BASE_URL}).",
    )
    parser.add_argument(
        "--browser-binary",
        default=DEFAULT_BROWSER,
        help=f"Path to a Chromium-compatible browser binary (default: {DEFAULT_BROWSER}).",
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=("all", "auth", "public", "marketing"),
        help="Route group to execute. Defaults to all live browser routes.",
    )
    parser.add_argument(
        "--route",
        action="append",
        help="Exact route id to execute (for example: login, verify-email).",
    )
    parser.add_argument(
        "--viewport",
        action="append",
        choices=tuple(VIEWPORTS.keys()),
        help="Viewport to execute. Defaults to desktop.",
    )
    parser.add_argument(
        "--update-artifacts",
        action="store_true",
        help="Capture screenshots and DOM dumps under the artifact directory.",
    )
    parser.add_argument(
        "--artifact-dir",
        default=DEFAULT_ARTIFACT_DIR,
        help=f"Output directory for screenshots and DOM dumps (default: {DEFAULT_ARTIFACT_DIR}).",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=DEFAULT_TIMEOUT_MS,
        help=f"Virtual time budget passed to Brave (default: {DEFAULT_TIMEOUT_MS}).",
    )
    return parser.parse_args()


def selected_viewports(args: argparse.Namespace) -> list[Viewport]:
    names = args.viewport or ["desktop"]
    return [VIEWPORTS[name] for name in names]


def selected_routes(args: argparse.Namespace) -> list[RouteCheck]:
    route_ids = set(args.route or [])
    groups = set(args.group or ["all"])

    checks: list[RouteCheck] = []
    for check in ROUTE_CHECKS:
        if route_ids and check.route_id not in route_ids:
            continue
        if route_ids:
            checks.append(check)
            continue
        if "all" in groups or check.group in groups:
            checks.append(check)

    if not checks:
        available = ", ".join(check.route_id for check in ROUTE_CHECKS)
        raise SystemExit(f"No routes selected. Available route ids: {available}")

    return checks


def ensure_browser(browser_binary: str) -> None:
    if not Path(browser_binary).exists():
        raise SystemExit(f"Browser binary does not exist: {browser_binary}")


def build_url(base_url: str, check: RouteCheck) -> str:
    parts = urlsplit(base_url)
    hostname = check.host_override or parts.hostname or "127.0.0.1"
    netloc = hostname
    if parts.port is not None:
        netloc = f"{hostname}:{parts.port}"
    rebuilt = urlunsplit((parts.scheme, netloc, "/", "", ""))
    return urljoin(rebuilt, check.path.lstrip("/"))


def host_resolver_rule(base_url: str, check: RouteCheck) -> str | None:
    if check.host_override is None:
        return None

    parts = urlsplit(base_url)
    base_host = parts.hostname
    if not base_host or base_host == check.host_override:
        return None

    return f"MAP {check.host_override} {base_host}"


def browser_flags(viewport: Viewport, timeout_ms: int, resolver_rule: str | None) -> list[str]:
    flags = [
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--window-size={viewport.width},{viewport.height}",
        f"--virtual-time-budget={timeout_ms}",
    ]
    if resolver_rule:
        flags.append(f"--host-resolver-rules={resolver_rule}")
    return flags


def dump_dom(
    browser_binary: str,
    viewport: Viewport,
    timeout_ms: int,
    url: str,
    resolver_rule: str | None,
) -> str:
    command = [browser_binary, *browser_flags(viewport, timeout_ms, resolver_rule), "--dump-dom", url]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"dump-dom failed for {url}")
    return result.stdout


def capture_screenshot(
    browser_binary: str,
    viewport: Viewport,
    timeout_ms: int,
    url: str,
    output_path: Path,
    resolver_rule: str | None,
) -> None:
    command = [
        browser_binary,
        *browser_flags(viewport, timeout_ms, resolver_rule),
        f"--screenshot={output_path}",
        url,
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"screenshot failed for {url}")


def artifact_base(artifact_dir: Path, check: RouteCheck, viewport: Viewport) -> Path:
    return artifact_dir / check.group / f"{check.route_id}-{viewport.name}"


def summarize_missing(expected_fragments: Iterable[str], dom: str) -> list[str]:
    return [fragment for fragment in expected_fragments if fragment not in dom]


def main() -> int:
    args = parse_args()
    ensure_browser(args.browser_binary)

    checks = selected_routes(args)
    viewports = selected_viewports(args)
    artifact_dir = Path(args.artifact_dir)
    if args.update_artifacts:
        artifact_dir.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    executed = 0

    for check in checks:
        for viewport in viewports:
            url = build_url(args.base_url, check)
            resolver_rule = host_resolver_rule(args.base_url, check)
            label = f"{check.route_id}@{viewport.name}"
            try:
                dom = dump_dom(
                    args.browser_binary,
                    viewport,
                    args.timeout_ms,
                    url,
                    resolver_rule,
                )
                missing = summarize_missing(check.expected_fragments, dom)
                if args.update_artifacts:
                    base = artifact_base(artifact_dir, check, viewport)
                    base.parent.mkdir(parents=True, exist_ok=True)
                    base.with_suffix(".html").write_text(dom, encoding="utf-8")
                    capture_screenshot(
                        args.browser_binary,
                        viewport,
                        args.timeout_ms,
                        url,
                        base.with_suffix(".png"),
                        resolver_rule,
                    )

                if missing:
                    failures.append(
                        f"{label} missing expected fragments: {', '.join(missing)}"
                    )
                    print(f"FAIL {label}")
                else:
                    print(f"PASS {label}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{label} failed: {exc}")
                print(f"FAIL {label}")

            executed += 1

    print(f"Executed {executed} browser smoke checks across {len(checks)} routes.")
    if args.update_artifacts:
        print(f"Artifacts updated under {artifact_dir}.")

    if failures:
        print("Failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())