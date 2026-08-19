#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, TypeVar
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen


DEFAULT_BROWSER = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
DEFAULT_BASE_URL = "http://127.0.0.1:3000"
DEFAULT_ARTIFACT_DIR = "reports/visual-parity/live-browser-smoke"
DEFAULT_BROWSER_ENV = "BROWSER_TEST_BROWSER"
DEFAULT_BASE_URL_ENV = "BROWSER_TEST_BASE_URL"
DEFAULT_TIMEOUT_MS = 2000
DEFAULT_RETRIES = 2
DEFAULT_RETRY_DELAY_MS = 250
DEFAULT_PROCESS_TIMEOUT_SECONDS = 30
DEFAULT_STYLESHEET_TIMEOUT_MS = 5000
CONSENT_COOKIE_NAME = "apexmail_cookie_consent"
CONSENT_COOKIE_VALUE = "dismiss"


T = TypeVar("T")


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
        route_id="web-dashboard",
        group="web",
        path="/dashboard",
        expected_fragments=(
            "Dashboard",
            "Emails Sent",
            "Send Volume",
        ),
    ),
    RouteCheck(
        route_id="login",
        group="auth",
        path="/login",
        expected_fragments=(
            "Welcome back",
            "Enter your credentials to access the console",
            "Security Check Active",
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
            "Verify your email",
            "Verification pending",
        ),
    ),
    RouteCheck(
        route_id="control-plane-home",
        group="control-plane",
        path="/",
        expected_fragments=(
            "Control Plane",
            "ApexMail administration and monitoring",
            "Open Sales Console",
        ),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-dashboard",
        group="control-plane",
        path="/dashboard",
        expected_fragments=(
            "Dashboard",
            "Active Tenants",
            "Control Plane",
        ),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-sales",
        group="control-plane",
        path="/sales",
        expected_fragments=(
            "Operator console for discovery, outreach, and autopilot approvals.",
            "Admin API session",
            "Lead inventory",
        ),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-tenants",
        group="control-plane",
        path="/tenants",
        expected_fragments=("Tenants", "No tenants yet", "Add Tenant"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-operators",
        group="control-plane",
        path="/operators",
        expected_fragments=("Operators", "No operators invited", "Add Operator"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-jobs",
        group="control-plane",
        path="/jobs",
        expected_fragments=("Jobs", "No background jobs running", "Queued"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-nodes",
        group="control-plane",
        path="/infrastructure/nodes",
        expected_fragments=("Nodes", "No nodes registered", "Capacity"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-queues",
        group="control-plane",
        path="/infrastructure/queues",
        expected_fragments=("Queues", "No queues reporting traffic", "Processing"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-domains",
        group="control-plane",
        path="/domains",
        expected_fragments=("Domains", "No domains registered", "Verified"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-billing-plans",
        group="control-plane",
        path="/billing/plans",
        expected_fragments=("Plans", "No plan rows loaded", "€3,000"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-alerts",
        group="control-plane",
        path="/alerts",
        expected_fragments=("Alerts", "No active alerts", "Manage Rules"),
        host_override="localhost",
    ),
    RouteCheck(
        route_id="control-plane-alert-rules",
        group="control-plane",
        path="/alerts/rules",
        expected_fragments=("Alert Rules", "No alert rules configured", "Enabled"),
        host_override="localhost",
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


def _env_or_default(env_var: str, default: str) -> str:
    """Return the environment variable value if set, otherwise the default."""
    return os.environ.get(env_var, default)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Headless Brave browser smoke checks for live ApexMail routes."
    )
    parser.add_argument(
        "--base-url",
        default=_env_or_default(DEFAULT_BASE_URL_ENV, DEFAULT_BASE_URL),
        help=(
            f"Base URL for the live Rust-served app "
            f"(default: {DEFAULT_BASE_URL}, env: {DEFAULT_BASE_URL_ENV})."
        ),
    )
    parser.add_argument(
        "--browser-binary",
        default=_env_or_default(DEFAULT_BROWSER_ENV, DEFAULT_BROWSER),
        help=(
            f"Path to a Chromium-compatible browser binary "
            f"(default: {DEFAULT_BROWSER}, env: {DEFAULT_BROWSER_ENV})."
        ),
    )
    parser.add_argument(
        "--group",
        action="append",
        choices=("all", "auth", "public", "web", "marketing", "control-plane"),
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
        "--skip-screenshots",
        action="store_true",
        help="When updating artifacts, write DOM dumps only and remove stale PNGs.",
    )
    parser.add_argument(
        "--screenshot-engine",
        choices=("playwright", "chromium-cli"),
        default="playwright",
        help="Screenshot capture engine. Playwright validates stylesheets and is the default.",
    )
    parser.add_argument(
        "--show-cookie-banner",
        action="store_true",
        help="Do not preload marketing cookie consent before screenshots.",
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
    parser.add_argument(
        "--process-timeout-s",
        type=int,
        default=DEFAULT_PROCESS_TIMEOUT_SECONDS,
        help=(
            "Wall-clock timeout for each Brave subprocess "
            f"(default: {DEFAULT_PROCESS_TIMEOUT_SECONDS}s)."
        ),
    )
    parser.add_argument(
        "--stylesheet-timeout-ms",
        type=int,
        default=DEFAULT_STYLESHEET_TIMEOUT_MS,
        help=f"Wait budget for linked stylesheet validation (default: {DEFAULT_STYLESHEET_TIMEOUT_MS}).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help=f"Number of retries for flaky browser operations (default: {DEFAULT_RETRIES}).",
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


def build_fetch_request(base_url: str, check: RouteCheck) -> Request:
    parts = urlsplit(base_url)
    request_base = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    request_url = urljoin(request_base, check.path.lstrip("/"))
    headers = {"User-Agent": "ApexMail visual smoke"}
    if check.host_override is not None and check.host_override != parts.hostname:
        host = check.host_override
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        headers["Host"] = host
    return Request(request_url, headers=headers)


def host_resolver_rule(base_url: str, check: RouteCheck) -> str | None:
    if check.host_override is None:
        return None

    parts = urlsplit(base_url)
    base_host = parts.hostname
    if not base_host or base_host == check.host_override:
        return None

    return f"MAP {check.host_override} {base_host}"


def browser_flags(
    viewport: Viewport,
    timeout_ms: int,
    resolver_rule: str | None,
    user_data_dir: Path,
) -> list[str]:
    flags = [
        "--headless=new",
        "--disable-gpu",
        "--disable-application-cache",
        "--disable-cache",
        "--hide-scrollbars",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--aggressive-cache-discard",
        "--disk-cache-size=0",
        "--media-cache-size=0",
        f"--user-data-dir={user_data_dir}",
        f"--window-size={viewport.width},{viewport.height}",
        f"--virtual-time-budget={timeout_ms}",
    ]
    if resolver_rule:
        flags.append(f"--host-resolver-rules={resolver_rule}")
    return flags


def dump_dom(
    base_url: str,
    check: RouteCheck,
    process_timeout_s: int,
) -> str:
    request = build_fetch_request(base_url, check)
    try:
        with urlopen(request, timeout=process_timeout_s) as response:
            body = response.read()
            charset = response.headers.get_content_charset() or "utf-8"
            return body.decode(charset, errors="replace")
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"DOM fetch failed for {request.full_url}: {exc}") from exc


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def with_retries(operation: Callable[[], T], retries: int) -> T:
    last_error: Exception | None = None

    for attempt in range(retries + 1):
        try:
            return operation()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt == retries:
                break
            time.sleep((DEFAULT_RETRY_DELAY_MS * (2**attempt)) / 1000)

    assert last_error is not None
    raise last_error


def validate_playwright_available() -> None:
    try:
        import playwright.sync_api  # noqa: F401
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Playwright is required for reliable visual screenshots. "
            "Install it with `python3 -m pip install playwright` and run `python3 -m playwright install chromium`."
        ) from exc


def consent_cookie_url(url: str) -> str:
    parts = urlsplit(url)
    netloc = parts.netloc
    return urlunsplit((parts.scheme, netloc, "/", "", ""))


def should_preload_consent(check: RouteCheck, show_cookie_banner: bool) -> bool:
    return check.group == "marketing" and not show_cookie_banner


def validate_stylesheets(page: object, stylesheet_timeout_ms: int, label: str) -> None:
    try:
        page.wait_for_function(
            """
            () => {
              const links = Array.from(document.querySelectorAll('link[rel~="stylesheet"]'));
              return links.length > 0 && links.every((link) => Boolean(link.sheet));
            }
            """,
            timeout=stylesheet_timeout_ms,
        )
    except Exception as exc:  # noqa: BLE001
        stylesheets = page.evaluate(
            """
            () => Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).map((link) => ({
              href: link.href,
              loaded: Boolean(link.sheet),
              disabled: Boolean(link.disabled),
              rel: link.rel,
            }))
            """
        )
        raise RuntimeError(f"{label} stylesheets did not become ready: {stylesheets}") from exc
    stylesheets = page.evaluate(
        """
        () => Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).map((link) => ({
          href: link.href,
          loaded: Boolean(link.sheet),
          disabled: Boolean(link.disabled),
        }))
        """
    )
    missing = [entry["href"] for entry in stylesheets if not entry["loaded"] or entry["disabled"]]
    if missing:
        raise RuntimeError(f"{label} stylesheets failed to load: {', '.join(missing)}")


def capture_screenshot_playwright(
    browser_binary: str,
    viewport: Viewport,
    process_timeout_s: int,
    stylesheet_timeout_ms: int,
    url: str,
    output_path: Path,
    resolver_rule: str | None,
    check: RouteCheck,
    show_cookie_banner: bool,
) -> None:
    from playwright.sync_api import sync_playwright

    output_path.unlink(missing_ok=True)
    launch_args = ["--disable-background-networking", "--disable-cache"]
    if resolver_rule:
        launch_args.append(f"--host-resolver-rules={resolver_rule}")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(
            executable_path=browser_binary,
            headless=True,
            args=launch_args,
        )
        try:
            context = browser.new_context(
                viewport={"width": viewport.width, "height": viewport.height},
                device_scale_factor=1,
                ignore_https_errors=True,
            )
            try:
                if should_preload_consent(check, show_cookie_banner):
                    context.add_cookies(
                        [
                            {
                                "name": CONSENT_COOKIE_NAME,
                                "value": CONSENT_COOKIE_VALUE,
                                "url": consent_cookie_url(url),
                                "sameSite": "Lax",
                            }
                        ]
                    )
                page = context.new_page()
                page.goto(url, wait_until="load", timeout=process_timeout_s * 1000)
                page.wait_for_load_state("networkidle", timeout=process_timeout_s * 1000)
                validate_stylesheets(page, stylesheet_timeout_ms, f"{check.route_id}@{viewport.name}")
                if should_preload_consent(check, show_cookie_banner):
                                        try:
                                                page.wait_for_function(
                                                        """
                                                        () => {
                                                            const banner = document.querySelector('#cookie-consent-banner');
                                                            return !banner || banner.hidden || getComputedStyle(banner).display === 'none';
                                                        }
                                                        """,
                                                        timeout=stylesheet_timeout_ms,
                                                )
                                        except Exception as exc:  # noqa: BLE001
                                                banner_state = page.evaluate(
                                                        """
                                                        () => {
                                                            const banner = document.querySelector('#cookie-consent-banner');
                                                            return {
                                                                cookie: document.cookie,
                                                                exists: Boolean(banner),
                                                                hidden: banner ? banner.hidden : null,
                                                                display: banner ? getComputedStyle(banner).display : null,
                                                            };
                                                        }
                                                        """
                                                )
                                                raise RuntimeError(
                                                        f"{check.route_id}@{viewport.name} cookie banner remained visible: {banner_state}"
                                                ) from exc
                page.screenshot(path=str(output_path), full_page=False, animations="disabled")
            finally:
                context.close()
        finally:
            browser.close()


def capture_screenshot_cli(
    browser_binary: str,
    viewport: Viewport,
    timeout_ms: int,
    process_timeout_s: int,
    url: str,
    output_path: Path,
    resolver_rule: str | None,
) -> None:
    output_path.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="apexmail-browser-smoke-") as profile_dir:
        command = [
            browser_binary,
            *browser_flags(viewport, timeout_ms, resolver_rule, Path(profile_dir)),
            f"--screenshot={output_path}",
            url,
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + process_timeout_s
        last_size = -1
        stable_samples = 0

        while time.monotonic() < deadline:
            if output_path.exists() and output_path.stat().st_size > 0:
                size = output_path.stat().st_size
                if size == last_size:
                    stable_samples += 1
                    if stable_samples >= 2:
                        stop_process(process)
                        return
                else:
                    last_size = size
                    stable_samples = 0
            if process.poll() is not None:
                break
            time.sleep(0.25)

        if output_path.exists() and output_path.stat().st_size > 0:
            stop_process(process)
            return

        _, stderr = process.communicate(timeout=2) if process.poll() is not None else (None, "")
        stop_process(process)
        if stderr:
            raise RuntimeError(stderr.strip())
        raise RuntimeError(f"screenshot timed out after {process_timeout_s}s for {url}")


def capture_screenshot(
    browser_binary: str,
    viewport: Viewport,
    timeout_ms: int,
    process_timeout_s: int,
    stylesheet_timeout_ms: int,
    url: str,
    output_path: Path,
    resolver_rule: str | None,
    check: RouteCheck,
    screenshot_engine: str,
    show_cookie_banner: bool,
) -> None:
    if screenshot_engine == "playwright":
        capture_screenshot_playwright(
            browser_binary,
            viewport,
            process_timeout_s,
            stylesheet_timeout_ms,
            url,
            output_path,
            resolver_rule,
            check,
            show_cookie_banner,
        )
        return

    capture_screenshot_cli(
        browser_binary,
        viewport,
        timeout_ms,
        process_timeout_s,
        url,
        output_path,
        resolver_rule,
    )


def artifact_base(artifact_dir: Path, check: RouteCheck, viewport: Viewport) -> Path:
    return artifact_dir / check.group / f"{check.route_id}-{viewport.name}"


def summarize_missing(expected_fragments: Iterable[str], dom: str) -> list[str]:
    return [fragment for fragment in expected_fragments if fragment not in dom]


def main() -> int:
    args = parse_args()
    ensure_browser(args.browser_binary)
    if args.update_artifacts and not args.skip_screenshots and args.screenshot_engine == "playwright":
        validate_playwright_available()

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
                dom = with_retries(
                    lambda: dump_dom(
                        args.base_url,
                        check,
                        args.process_timeout_s,
                    ),
                    args.retries,
                )
                missing = summarize_missing(check.expected_fragments, dom)
                if args.update_artifacts:
                    base = artifact_base(artifact_dir, check, viewport)
                    base.parent.mkdir(parents=True, exist_ok=True)
                    base.with_suffix(".html").write_text(dom, encoding="utf-8")
                    if args.skip_screenshots:
                        base.with_suffix(".png").unlink(missing_ok=True)
                    else:
                        with_retries(
                            lambda: capture_screenshot(
                                args.browser_binary,
                                viewport,
                                args.timeout_ms,
                                args.process_timeout_s,
                                args.stylesheet_timeout_ms,
                                url,
                                base.with_suffix(".png"),
                                resolver_rule,
                                check,
                                args.screenshot_engine,
                                args.show_cookie_banner,
                            ),
                            args.retries,
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
        if args.skip_screenshots:
            print("Screenshot capture skipped; refreshed DOM artifacts only.")

    if failures:
        print("Failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())