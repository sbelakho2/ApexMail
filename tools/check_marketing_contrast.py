#!/usr/bin/env python3
"""Marketing token contrast gate — WCAG AA over the SHIPPED stylesheet.

The authoritative rendered check is the pixel-verified WCAG suite
(`tools/contrast-audit/gate.sh`, run from the test stage). This gate is the
fast static layer in front of it: it parses the actual `--token: R G B`
declarations from BOTH marketing stylesheets —

  * the authored `apps/marketing-zola/static/css/input.css`, and
  * the built/shipped `apps/marketing-zola/static/css/styles.css`
    (the sheet zola copies into `public/`; the Docker image rebuilds the
    same pair with the pinned Tailwind v3.4.17),

computes the WCAG 2.1 contrast ratio for every text pair the marketing
design system promises (in BOTH themes: light `:root`, dark via
`prefers-color-scheme` and the `html.dark` JS toggle), and additionally
requires the pair tokens to carry IDENTICAL values in the authored and the
built sheet — the hand-maintained-copy drift class this repo shipped before
(a dark-mode token fixed in `input.css` but not regenerated into
`styles.css`, found 2026-10-07: `--card` 24 24 27 vs 16 16 18).

An earlier version of this file validated hardcoded constants and could not
fail against the shipped palette (gates review 2026-10-07); this version
reads the files, and `--self-test` proves both arms can fail.

Usage: python3 tools/check_marketing_contrast.py [--self-test]
"""
from __future__ import annotations

import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTHORED_CSS = ROOT / "apps/marketing-zola/static/css/input.css"
BUILT_CSS = ROOT / "apps/marketing-zola/static/css/styles.css"

# (theme, foreground, background, minimum, what it renders)
REQUIRED_PAIRS: list[tuple[str, str, str, float, str]] = [
    ("light", "foreground", "background", 4.5, "body text on the page background"),
    ("light", "foreground", "card", 4.5, "panel text on card surfaces"),
    ("light", "surface-500", "card", 4.5, "muted/secondary text on cards"),
    ("light", "surface-500", "background", 4.5, "muted/secondary text on sections"),
    ("light", "primary", "card", 4.5, "brand-red links/eyebrows on white"),
    ("light", "white", "primary", 4.5, "white label on the brand-red button"),
    ("light", "brand-700", "brand-50", 4.5, "brand chip text on the brand tint"),
    ("light", "danger-700", "card", 4.5, "error text on cards"),
    ("light", "warning-700", "card", 4.5, "warning text on cards"),
    ("dark", "foreground", "background", 4.5, "body text on the dark background"),
    ("dark", "foreground", "card", 4.5, "panel text on dark cards"),
    ("dark", "surface-600", "card", 4.5, "muted/secondary text on dark cards"),
    ("dark", "surface-600", "background", 4.5, "muted/secondary text on dark sections"),
    ("dark", "danger-400", "card", 4.5, "error text on dark cards"),
    ("dark", "danger-400", "background", 4.5, "error text on the dark background"),
    ("dark", "warning-300", "card", 4.5, "warning text on dark cards"),
    ("dark", "white", "primary", 4.5, "white label on the brand-red button"),
]

WHITE = (255, 255, 255)

# `--name: R G B` (or `--name:R G B`) — the token format both sheets use.
_TOKEN_RE = re.compile(r"--([a-z0-9-]+):\s*(\d{1,3}) (\d{1,3}) (\d{1,3})")

LIGHT_BLOCK_AUTHORED = re.compile(r"\n:root \{(.*?)\n\}", re.S)
DARK_BLOCK_AUTHORED = re.compile(r":root:not\(\.light\) \{(.*?)\n  \}", re.S)
LIGHT_BLOCK_BUILT = re.compile(r":root\{(.*?)\}", re.S)
DARK_BLOCK_BUILT = re.compile(
    r"@media \(prefers-color-scheme:dark\)\{:root:not\(\.light\)\{(.*?)\}\}", re.S
)
HTML_DARK_AUTHORED = re.compile(r"\nhtml\.dark \{(.*?)\n\}", re.S)
HTML_DARK_BUILT = re.compile(r"html\.dark\{(.*?)\}", re.S)


def _tokens(block: str) -> dict[str, tuple[int, int, int]]:
    return {
        name: (int(r), int(g), int(b)) for name, r, g, b in _TOKEN_RE.findall(block)
    }


def _blocks(css: str, authored: bool) -> dict[str, dict[str, tuple[int, int, int]]]:
    """light/dark/html_dark token maps for one stylesheet."""
    specs = (
        ("light", LIGHT_BLOCK_AUTHORED),
        ("dark", DARK_BLOCK_AUTHORED),
        ("html_dark", HTML_DARK_AUTHORED),
    ) if authored else (
        ("light", LIGHT_BLOCK_BUILT),
        ("dark", DARK_BLOCK_BUILT),
        ("html_dark", HTML_DARK_BUILT),
    )
    kind = "authored" if authored else "built"
    out: dict[str, dict[str, tuple[int, int, int]]] = {}
    for name, pattern in specs:
        match = pattern.search(css)
        if match is None:
            raise ValueError(
                f"cannot locate the {name} token block in the {kind} stylesheet "
                f"({pattern.pattern[:48]}…)"
            )
        out[name] = _tokens(match.group(1))
    return out


def _channel(value: int) -> float:
    normalized = value / 255
    if normalized <= 0.03928:
        return normalized / 12.92
    return ((normalized + 0.055) / 1.055) ** 2.4


def _luminance(rgb: tuple[int, int, int]) -> float:
    red, green, blue = (_channel(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(
    foreground: tuple[int, int, int], background: tuple[int, int, int]
) -> float:
    fg = _luminance(foreground)
    bg = _luminance(background)
    lighter = max(fg, bg)
    darker = min(fg, bg)
    return (lighter + 0.05) / (darker + 0.05)


def _resolve(
    token: str, theme: str, tokens: dict[str, dict[str, tuple[int, int, int]]]
) -> tuple[int, int, int] | None:
    """A token's value in `theme`, following the CSS cascade (dark inherits
    anything the dark block does not override). `white` is the literal
    Tailwind `text-white` utility used on the brand button."""
    if token == "white":
        return WHITE
    if theme == "dark":
        return tokens["dark"].get(token) or tokens["light"].get(token)
    return tokens["light"].get(token)


def run_checks(root: Path) -> list[str]:
    failures: list[str] = []
    try:
        authored = _blocks((root / AUTHORED_CSS.relative_to(ROOT)).read_text(), True)
    except ValueError as error:
        return [f"authored stylesheet unreadable: {error}"]
    try:
        built = _blocks((root / BUILT_CSS.relative_to(ROOT)).read_text(), False)
    except ValueError as error:
        return [f"built stylesheet unreadable: {error}"]

    checked = 0
    for theme, foreground, background, minimum, label in REQUIRED_PAIRS:
        for source, tokens in (("authored", authored), ("built", built)):
            fg = _resolve(foreground, theme, tokens)
            bg = _resolve(background, theme, tokens)
            if fg is None or bg is None:
                missing = foreground if fg is None else background
                failures.append(
                    f"{source} {theme}: token --{missing} not declared "
                    f"({label})"
                )
                continue
            ratio = contrast_ratio(fg, bg)
            if ratio < minimum:
                failures.append(
                    f"{source} {theme}: {foreground} on {background} = "
                    f"{ratio:.2f} < {minimum} ({label}; tokens "
                    f"{foreground}={fg} {background}={bg})"
                )
            checked += 1
        # authored == built for both pair tokens (cascade-resolved) — a token
        # fixed in one sheet but not the other is the shipped-drift class.
        for token in (foreground, background):
            if token == "white":
                continue
            value_a = _resolve(token, theme, authored)
            value_b = _resolve(token, theme, built)
            if value_a is not None and value_b is not None and value_a != value_b:
                failures.append(
                    f"drift {theme}: --{token} = {value_a} in input.css but "
                    f"{value_b} in the built styles.css"
                )
        # the JS-toggle block must match the media-query block
        for token in (foreground, background):
            if token == "white":
                continue
            for source, tokens in (("authored", authored), ("built", built)):
                media = (
                    tokens["dark"].get(token) or tokens["light"].get(token)
                    if theme == "dark"
                    else tokens["light"].get(token)
                )
                toggle = tokens["html_dark"].get(token)
                if theme == "dark" and media is not None and toggle is not None and media != toggle:
                    failures.append(
                        f"{source}: --{token} = {media} under the OS dark media "
                        f"query but {toggle} under html.dark — the JS toggle and "
                        f"OS dark mode must render the same theme"
                    )
    print(
        f"marketing token contrast: {checked} pair renderings checked across "
        f"authored+built stylesheets, light+dark themes"
    )
    return failures


def _self_test() -> int:
    ok = True

    def case(label: str, mutate, expect: str) -> None:
        nonlocal ok
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for source in (AUTHORED_CSS, BUILT_CSS):
                target = root / source.relative_to(ROOT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            mutate(root)
            problems = run_checks(root)
            matched = [p for p in problems if expect in p]
            if matched:
                print(f"self-test PASS [{label}]: {matched[0][:120]}")
            else:
                print(
                    f"self-test FAIL [{label}]: expected a problem about "
                    f"{expect!r}, got {problems[:2]}"
                )
                ok = False

    def edit(root: Path, rel: Path, old: str, new: str) -> None:
        target = root / rel.relative_to(ROOT)
        text = target.read_text()
        assert old in text, f"self-test anchor not found in {rel.name}: {old!r}"
        target.write_text(text.replace(old, new, 1))

    case(
        "authored-sheet drift vs built sheet fails",
        lambda root: edit(root, AUTHORED_CSS, "--surface-500:82 82 91;", "--surface-500:90 90 98;"),
        "drift",
    )

    def collapse(root: Path) -> None:
        edit(root, AUTHORED_CSS, "--danger-400: 248 113 113;", "--danger-400: 60 24 24;")
        edit(root, BUILT_CSS, "--danger-400:248 113 113", "--danger-400:60 24 24")

    case("collapsed dark-mode ratio fails", collapse, "danger-400 on card")

    def flatten_card(root: Path) -> None:
        # a muted token that stops being readable on the page background
        edit(root, AUTHORED_CSS, "--surface-500:82 82 91;", "--surface-500:225 225 228;")
        edit(root, BUILT_CSS, "--surface-500:82 82 91", "--surface-500:225 225 228")

    case("light muted text collapsing into the background fails", flatten_card, "surface-500 on background")

    if not run_checks(ROOT):
        print("self-test PASS [pristine tree]")
    else:
        print("self-test FAIL [pristine tree]: the gate flags the real stylesheets")
        ok = False

    print(f"marketing token contrast self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    if "--self-test" in argv[1:]:
        return _self_test()
    failures = run_checks(ROOT)
    if failures:
        for failure in failures:
            print(f"FAIL marketing contrast: {failure}")
        print(f"marketing contrast: FAIL ({len(failures)} problem(s))")
        return 1
    print("marketing token contrast: all pairs pass in both sheets and themes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
