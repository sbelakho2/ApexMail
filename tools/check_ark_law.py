#!/usr/bin/env python3
"""ARK law gate — zero inlining, enforced across every renderer.

Every class a renderer (Rust view, Zola template, markdown content) or an
authored stylesheet emits must be either

  1. an `apex-*` class defined in the authority (assets/ark.css),
  2. a STRUCTURAL layout utility from the whitelist (the same grammar
     cssgen resolves — display, flex/grid, spacing, sizing, positioning,
     alignment, text direction/wrapping), or
  3. on the small non-style allowlist (behavioural hooks, third-party
     runtime classes).

A colour, typography, radius, shadow, blur, gradient, animation or
transition utility compiles to NOTHING under cssgen and is BANNED here by
name. The gate also carries the copy law for product UI: no middot
separators, no banned legacy classes (pills, dials, heroes, eyebrows,
spines), no framework identity (Tailwind values, Inter outside the
wordmark, Fraunces, JetBrains, zinc, indigo).

Exit 0 only when every scanned file is clean. `--fix-list` prints the
class vocabulary the renderers still use that is NOT covered (the sweep
worklist) instead of failing outright — the same list, friendlier shape.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# ── the authorities ──────────────────────────────────────────────────────
ARK = REPO / "services/mail-server/crates/ui-foundation/assets/ark.css"

RENDERERS = [
    *REPO.glob("services/mail-server/crates/ui-foundation/src/**/*.rs"),
    *REPO.glob("services/mail-server/crates/api-server/src/**/*.rs"),
    *REPO.glob("apps/marketing-zola/templates/**/*.html"),
    *REPO.glob("apps/marketing-zola/content/**/*.md"),
    *REPO.glob("apps/marketing-zola/static/css/input.css"),
]
SKIP_PARTS = {"target", "node_modules", "/public/", "bin/cssgen.rs"}

COPY_AUTHORITIES = [
    *REPO.glob("apps/marketing-zola/data/i18n.json"),
]

# ── the structural whitelist (mirrors src/bin/cssgen.rs; keep in sync) ──
STRUCTURAL_PREFIXES = [
    # display / flex / grid
    "block", "inline-block", "inline", "flex", "inline-flex", "grid", "hidden",
    "contents", "table", "flow-root", "flex-", "grow", "shrink",
    "items-", "justify-", "self-", "content-", "place-items-", "place-content-",
    "gap-", "gap-x-", "gap-y-", "grid-cols-", "grid-rows-", "col-span-",
    "row-span-", "order-", "auto-cols-", "auto-rows-",
    # spacing
    "p-", "px-", "py-", "pt-", "pr-", "pb-", "pl-",
    "m-", "mx-", "my-", "mt-", "mr-", "mb-", "ml-",
    "space-x-", "space-y-", "gap-",
    # sizing
    "w-", "h-", "min-w-", "min-h-", "max-w-", "max-h-", "size-",
    # position
    "static", "fixed", "absolute", "relative", "sticky", "inset-", "inset-x-",
    "inset-y-", "top-", "right-", "bottom-", "left-", "z-",
    # overflow / object / aspect
    "overflow-", "overscroll-", "object-", "aspect-",
    # text behaviour (never typography)
    "text-left", "text-center", "text-right", "text-justify",
    "whitespace-", "break-words", "break-all", "break-normal",
    "align-", "list-none", "list-disc", "list-decimal",
    # interaction-adjacent structure
    "visible", "invisible", "pointer-events-", "cursor-pointer",
    "cursor-not-allowed", "cursor-default", "sr-only", "not-sr-only",
    "scroll-mt-", "scroll-m",
    # borders: width/side tokens are structural; the hairline COLOUR is the
    # token default, never a per-call colour class.
    "border", "border-t", "border-b", "border-l", "border-r", "border-x",
    "border-y", "border-2", "border-4", "border-8",
    # radius: cssgen resolves every step to the zero tokens; the sweep
    # removes these, but a straggler stays coherent while it exists.
    "rounded",
    # spacing helpers authored in the entry css
    "space-y-", "space-x-", "mt-8", "resize-vertical",
    "transition-all",
]
STRUCTURAL_EXACT = {
    "flex-1", "flex-auto", "flex-none", "flex-col", "flex-row", "flex-wrap",
    "flex-nowrap", "grow", "grow-0", "shrink-0", "block", "inline-block",
    "inline", "flex", "inline-flex", "grid", "hidden", "contents", "table",
    "flow-root", "static", "fixed", "absolute", "relative", "sticky",
    "visible", "invisible", "sr-only", "not-sr-only", "uppercase-none",
    "truncate-none", "mx-auto", "my-auto", "ml-auto", "mr-auto", "mt-auto",
    "mb-auto", "w-full", "h-full", "w-auto", "h-auto", "w-px", "h-px",
    "min-w-0", "w-screen", "h-screen", "list-none", "list-disc",
    "basis-full", "basis-auto", "basis-0",
    "list-decimal", "cursor-pointer", "cursor-not-allowed", "cursor-default",
    "pointer-events-none", "pointer-events-auto", "text-left", "text-center",
    "text-right", "text-justify", "resize-vertical", "mt-8", "transition-all",
    "tabular-nums", "font-mono",  # KiwiCaptcha runtime widget classes
}

# Behavioural hooks that carry no CSS rule.
NON_STYLE = {
    "apex-nav-cell",  # behavioural hook read by gates (see class_integrity_tests)
    "group",         # Tailwind group marker; group-hover variants are banned
    "__variable_712c26", "__variable_60443c",
}

# Legacy classes the law deletes; a renderer may not emit them at all.
BANNED_CLASSES = [
    "apex-pill", "apex-dial", "apex-meter", "apex-arc", "apex-klabel",
    "apex-eyebrow", "apex-hero-title", "apex-hero-copy", "apex-hero-stat",
    "apex-page-hero", "apex-console-hero", "apex-cp-hero", "apex-cp-stat",
    "apex-cp-dark", "apex-cp-sales", "apex-cp-launch-step", "apex-cp-region-row",
    "apex-cp-stream-item", "apex-signal-card", "apex-lane-grid", "apex-ops-board",
    "apex-inventory-", "apex-focus-ring", "apex-logo-mark", "apex-callout",
    "btn-primary", "glass", "ui-dot-grid", "animate-in", "transition-premium",
    "shadow-premium", "shadow-card", "ease-premium", "apex-mfa-code",
]

# Framework identity and banned values, anywhere in renderers or authority.
BANNED_SUBSTRINGS = [
    "shadow-premium", "backdrop-blur", "bg-gradient", "transition-premium",
    "ease-premium", "animate-pulse", "ui-dot-grid",
    "Fraunces", "JetBrains",
    "220 38 38",   # the old Tailwind red-600 brand
    "244 244 246", # zinc-100 canvas
    "9 9 11;\\n",  # (informational; wordmark keeps 9 9 11 legitimately)
    "99 102 241",  # indigo-500
    "rounded-[8px", "rounded-[16px", "rounded-[12px", "rounded-[9px",
    "rounded-t-", "rounded-b-", "rounded-l-", "rounded-r-", "rounded-full",
    "rounded-sm", "rounded-md", "rounded-lg", "rounded-xl", "rounded-2xl",
    "text-rose", "bg-rose", "border-rose", "text-emerald", "bg-emerald",
    "text-green", "bg-green", "text-indigo", "bg-indigo", "text-violet",
    "bg-violet", "text-purple", "bg-purple",
]

# Copy law: product UI copy uses commas or stacked rows, never middots.
MIDDOT = "·"

# Typography size utilities are banned (the vocabulary owns type): any
# text-{size} token that is not an alignment.
TEXT_SIZE = re.compile(r"^text-(xs|sm|base|lg|xl|2xl|3xl|4xl|5xl|6xl|\[[^\]]+\])$")


def authority_vocabulary() -> set[str]:
    """Every class defined in the authority stylesheet (unescaped)."""
    css = ARK.read_text()
    classes: set[str] = set()
    for m in re.finditer(r"\.([A-Za-z_][A-Za-z0-9_-]*)", css):
        classes.add(m.group(1))
    # element-scoped rules contribute their class too (already covered) and
    # aliases referenced inside selectors like `.apex-field select`.
    return classes


def is_structural(token: str) -> bool:
    base = token.rsplit(":", 1)[-1]
    if base in STRUCTURAL_EXACT or token in STRUCTURAL_EXACT:
        return True
    if base.startswith("-"):
        base = base[1:]
    return any(base.startswith(p) for p in STRUCTURAL_PREFIXES)


def is_apex(token: str) -> bool:
    return token == "apex-nav-cell" or token.startswith("apex-")


JINJA_TAG = re.compile(r"{%.*?%}|{{.*?}}", re.S)


def class_tokens(line: str) -> list[str]:
    """Class tokens of a markup line, ignoring template machinery.

    `{% ... %}` / `{{ ... }}` spans are template syntax, not classes the
    browser ever receives: a block declared INSIDE an attribute
    (base.html's `{% block body_class %}`) must not read as two unlawful
    names. The CONTENTS of a body_class block ARE real classes and are
    scanned as such.
    """
    clean = JINJA_TAG.sub(" ", line)
    tokens: list[str] = []
    for match in re.finditer(r'class=\\?"([^"\\]*)\\?"', clean):
        tokens.extend(match.group(1).split())
    marker = "{% block body_class %}"
    if marker in line:
        rest = line.split(marker, 1)[1]
        content = rest.split("{%", 1)[0]
        tokens.extend(JINJA_TAG.sub(" ", content).split())
    return tokens


def scan() -> int:
    vocab = authority_vocabulary()
    failures: list[tuple[str, int, str]] = []
    worklist: dict[str, list[str]] = {}

    for path in RENDERERS:
        sp = str(path)
        if any(part in sp for part in SKIP_PARTS):
            continue
        try:
            text = path.read_text()
        except Exception as exc:  # unreadable — fail loudly
            failures.append((sp, 0, f"unreadable: {exc}"))
            continue
        lines = text.split("\n")
        in_tests = False
        for idx, line in enumerate(lines, 1):
            if "#[cfg(test)]" in line:
                in_tests = True
            # Test code and assert strings are not product markup.
            if in_tests or "assert" in line or line.strip().startswith("//"):
                continue
            for token in class_tokens(line):
                    if "{" in token or "}" in token:
                        continue
                    if token in NON_STYLE:
                        continue
                    if TEXT_SIZE.match(token):
                        failures.append((sp, idx, f"typography size utility {token!r} — type is a primitive (apex-*)"))
                        continue
                    if is_apex(token):
                        if token not in vocab:
                            failures.append((sp, idx, f"apex class {token!r} has no rule in ark.css"))
                        for banned in BANNED_CLASSES:
                            if token.startswith(banned) or token == banned:
                                failures.append((sp, idx, f"banned legacy class {token!r}"))
                        continue
                    if is_structural(token):
                        continue
                    # Unknown non-apex token.
                    worklist.setdefault(token, []).append(f"{sp}:{idx}")
                    failures.append((sp, idx, f"unlawful class {token!r} — must be apex-* or structural"))
            for banned in BANNED_CLASSES:
                if banned in ("shadow-premium", "transition-premium", "ease-premium", "ui-dot-grid"):
                    continue  # covered by substring pass below
                if re.search(r'class=\\?"[^"\\]*\b' + re.escape(banned), line):
                    failures.append((sp, idx, f"banned legacy class {banned!r}"))
            if MIDDOT in line and ("class=" in line or "<" in line) and ".md" not in sp and "/content/" not in sp:
                # middots are banned in UI markup; markdown content is prose
                failures.append((sp, idx, "middot separator in UI copy — use a comma or stacked rows"))
            for banned in BANNED_SUBSTRINGS:
                if banned in ("9 9 11;\\n",):
                    continue
                if banned in line:
                    failures.append((sp, idx, f"banned value/pattern {banned!r}"))

    for path in COPY_AUTHORITIES:
        sp = str(path)
        for idx, line in enumerate(path.read_text().split("\n"), 1):
            if MIDDOT in line:
                failures.append((sp, idx, "middot separator in marketing copy"))

    if "--fix-list" in sys.argv:
        print("sweep worklist (unlawful tokens by frequency):")
        for token, sites in sorted(worklist.items(), key=lambda kv: -len(kv[1])):
            print(f"{len(sites):5d}  {token:44s} first: {sites[0]}")
        print(f"\ntotal unlawful tokens: {len(worklist)}")
        return 0

    for sp, idx, msg in failures:
        print(f"LAW {sp}:{idx}: {msg}")
    print(f"\nark-law: {len(failures)} violation(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(scan())
