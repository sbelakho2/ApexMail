#!/usr/bin/env python3
"""Check core marketing color pairs for WCAG AA contrast."""

from __future__ import annotations

import sys

COLORS = {
    "white": (255, 255, 255),
    "surface-50": (250, 250, 248),
    "surface-900": (18, 21, 21),
    "surface-500": (111, 115, 107),
    "surface-400": (158, 161, 151),
    "surface-100": (244, 244, 240),
    "primary-600": (63, 92, 184),
    "primary-700": (45, 67, 148),
    "amber-700": (180, 83, 9),
    "red-700": (185, 28, 28),
}

REQUIRED_PAIRS = [
    ("surface-500", "white", 4.5),
    ("surface-500", "surface-50", 4.5),
    ("surface-900", "white", 4.5),
    ("primary-600", "white", 4.5),
    ("primary-700", "white", 4.5),
    ("amber-700", "white", 4.5),
    ("red-700", "white", 4.5),
    ("surface-400", "surface-900", 4.5),
    ("white", "primary-600", 4.5),
]


def _channel(value: int) -> float:
    normalized = value / 255
    if normalized <= 0.03928:
        return normalized / 12.92
    return ((normalized + 0.055) / 1.055) ** 2.4


def _luminance(rgb: tuple[int, int, int]) -> float:
    red, green, blue = (_channel(channel) for channel in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(foreground: tuple[int, int, int], background: tuple[int, int, int]) -> float:
    fg = _luminance(foreground)
    bg = _luminance(background)
    lighter = max(fg, bg)
    darker = min(fg, bg)
    return (lighter + 0.05) / (darker + 0.05)


def main() -> int:
    failures: list[str] = []
    for foreground, background, minimum in REQUIRED_PAIRS:
        ratio = contrast_ratio(COLORS[foreground], COLORS[background])
        if ratio < minimum:
            failures.append(f"{foreground} on {background}: {ratio:.2f}, expected >= {minimum}")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("marketing contrast token validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
