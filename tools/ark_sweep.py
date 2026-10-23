#!/usr/bin/env python3
"""ARK sweep — mechanical codemod from raw utility classes to the vocabulary.

For every class attribute in the Rust renderers (class=\\"...\\" and
class="...") and the Zola templates (class="..."):

  1. DROP design-family tokens (colour, typography size/weight, radius,
     shadow, ring, gradient, blur, animation, transition, state variants):
     they compile to nothing under cssgen and their decisions must live in
     ark.css primitives.
  2. MAP legacy apex-* names to the ARK vocabulary (pill→status, callout→
     notice, stat tiles→kpi, ...).
  3. ADD the primitive the TAG requires (buttons get apex-btn, inputs get
     apex-input, tables apex-table, section heads apex-section-head, ...).
  4. Preserve every {fmt} fragment untouched.
  5. Replace middot separators in UI copy with commas (the copy law).

The tool is deliberately conservative: anything it cannot map mechanically
is LEFT IN PLACE and reported, for the structural rewrites that follow.
Run with --dry to preview, --report for the leftover list.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

RUST_FILES = [
    *REPO.glob("services/mail-server/crates/ui-foundation/src/**/*.rs"),
    *REPO.glob("services/mail-server/crates/api-server/src/**/*.rs"),
]
HTML_FILES = [
    *REPO.glob("apps/marketing-zola/templates/**/*.html"),
]
MD_FILES = [
    *REPO.glob("apps/marketing-zola/content/**/*.md"),
]
SKIP = ("target/", "bin/cssgen.rs", "/public/")

# ── token drop rules ─────────────────────────────────────────────────────
DROP_EXACT = {
    "antialiased", "subpixel-antialiased", "truncate", "uppercase", "lowercase",
    "opacity-25", "opacity-40", "opacity-50", "opacity-60", "opacity-70",
    "opacity-75", "border-transparent", "border-border", "bg-transparent",
    "bg-surface-50", "bg-surface-100", "top-1/2", "transition", "group",
    "text-brand-900", "border-border/80", "rounded-none", "shadow-none",
    "capitalize", "normal-case", "italic", "not-italic", "underline",
    "no-underline", "line-through", "border", "border-0", "border",
    "appearance-none", "select-none", "sr-only-placeholder",
    "invelte", "cursor-pointer", "cursor-not-allowed", "cursor-default",
    "is-active-marker",
}
DROP_PREFIXES = (
    # colour
    "bg-", "text-", "placeholder-", "caret-", "accent-", "fill-", "stroke-",
    "decoration-", "outline-", "ring-", "divide-",
    # typography
    "font-", "tracking-", "leading-",
    # radius / elevation / blur
    "rounded", "shadow-", "blur-", "backdrop-blur-", "backdrop-filter",
    # gradient
    "bg-gradient", "from-", "via-", "to-",
    # motion
    "transition-", "duration-", "ease-", "delay-", "animate-", "scale-",
    "translate-", "rotate-", "skew-", "will-change-",
    # state variants of design utilities (hover:, focus:, active:, dark:,
    # group-*, peer-*, after:, before:, first:, last:, md:hover:, ...)
)
KEEP_PREFIXES = (
    # border width/side tokens survive (colour comes from the hairline token)
    "border-t", "border-b", "border-l", "border-r", "border-x", "border-y",
    "border-2", "border-4", "border-8",
    "border",  # bare 1px hairline: the reset's border-color token applies
)
DROP_COLOR_BORDER = re.compile(
    r"^border-(surface|brand|primary|secondary|destructive|success|warning|info|danger"
    r"|rose|zinc|slate|gray|neutral|stone|red|blue|green|amber|yellow|emerald|indigo"
    r"|purple|violet|fuchsia|pink|sky|cyan|teal|lime|white|black|foreground|card|muted"
    r"|accent|popover|input|ring)([-/].*)?$"
)
STATE_VARIANTS = (
    "hover:", "focus:", "focus-visible:", "active:", "visited:", "disabled:",
    "group-hover:", "group-focus:", "peer-", "dark:", "first:", "last:",
    "odd:", "even:", "after:", "before:", "placeholder:", "sm:hover:",
    "md:hover:", "lg:hover:", "focus-within:", "focus-within", "motion-safe:",
    "motion-reduce:", "print:", "rtl:", "ltr:", "marker:", "selection:",
    "file:", "open:", "checked:", "required:", "invalid:", "user-invalid:",
)

# ── legacy → ARK mappings ────────────────────────────────────────────────
TOKEN_MAP: dict[str, str] = {
    "btn-primary": "apex-btn apex-btn--primary",
    "apex-pill": "apex-status",
    "apex-pill--success": "apex-status apex-status--on",
    "apex-pill--warning": "apex-status apex-status--warn",
    "apex-pill--brand": "apex-status",
    "apex-callout": "apex-notice",
    "apex-callout--success": "apex-notice apex-notice--ok",
    "apex-callout--info": "apex-notice",
    "apex-callout--warning": "apex-notice apex-notice--warn",
    "apex-callout--error": "apex-notice apex-notice--fail",
    "apex-metric-number": "apex-figure",
    "apex-cp-stat-tile": "apex-kpi",
    "apex-cp-stat-label": "apex-kpi__l",
    "apex-cp-stat-value": "apex-kpi__n",
    "apex-cp-stat-help": "apex-kpi__d",
    "apex-signal-card": "apex-kpi",
    "apex-cp-dark-panel": "apex-panel",
    "apex-cp-dark-panel--accent": "apex-panel",
    "apex-cp-dark-hero": "apex-panel",
    "apex-cp-hero": "apex-panel",
    "apex-cp-hero-main": "",
    "apex-cp-hero-side": "apex-panel",
    "apex-page-hero": "apex-page-heading",
    "apex-console-hero": "apex-page-heading",
    "apex-hero-copy": "apex-lead",
    "apex-inventory-panel": "apex-panel",
    "apex-inventory-head": "apex-section-head",
    "apex-inventory-empty": "apex-empty-state",
    "apex-chart-card": "apex-panel",
    "apex-chart-empty": "apex-empty-state",
    "apex-nav-active": "is-active",
    "apx-label": "apex-label",
    "apx-mono": "apex-mono",
    "resize-y": "apex-textarea",
    "apex-focus-ring": "",
    "glass": "",
    "ui-dot-grid": "",
    "animate-in": "",
    "fade-in": "",
    "zoom-in-95": "",
    "text-destructive": "apex-error",
}

# Legacy names the codemod cannot rebuild structurally. Their tokens are
# dropped and the structural rewrite is a reported leftover.
STRUCTURAL_LEFTOVERS = (
    "apex-cp-sales", "apex-cp-stat-tile", "apex-cp-stream-item",
    "apex-cp-launch-step", "apex-cp-region-row", "apex-lane-grid",
    "apex-ops-board", "apex-hero-stat-grid", "apex-hero-title",
    "apex-eyebrow", "apex-dial", "apex-meter", "apex-arc", "apex-klabel",
    "apex-cp-sales-badge", "apex-logo-mark",
)

# ── tag-context additions ────────────────────────────────────────────────
def primitive_for_tag(tag: str, classval: str) -> list[str]:
    add: list[str] = []
    if tag in ("button",) or (tag == "a" and re.search(r"\bapex-btn\b", classval)):
        if "apex-btn" not in classval and not classval.strip():
            add.append("apex-btn")
    if tag == "input" and "apex-input" not in classval:
        add.append("apex-input")
    if tag == "textarea":
        if "apex-input" not in classval:
            add.append("apex-input")
        if "apex-textarea" not in classval:
            add.append("apex-textarea")
    if tag == "select" and "apex-select" not in classval:
        add.append("apex-select")
    if tag == "table" and "apex-table" not in classval:
        add.append("apex-table")
    if tag == "label" and "apex-label" not in classval and "apex-check" not in classval:
        add.append("apex-label")
    if tag == "h1" and "apex-" not in classval:
        add.append("apex-page-title")
    if tag == "h2":
        if "apex-" not in classval:
            add.append("apex-h2")
    if tag == "h3" and "apex-" not in classval:
        add.append("apex-h3")
    return add


def transform_class(raw: str, tag: str) -> tuple[str, list[str]]:
    """Return (new_class_value, leftover_tokens)."""
    tokens = raw.split()
    out: list[str] = []
    leftovers: list[str] = []
    had_primary_fill = bool(re.search(r"\b(bg-primary|bg-brand-500|bg-brand-600|btn-primary)\b", raw))
    had_danger = bool(re.search(r"\b(text-destructive|bg-destructive|border-destructive|text-red-\d+|bg-red-\d+)\b", raw))
    had_sm = bool(re.search(r"\b(text-xs|py-1|px-2|apex-btn--sm)\b", raw))
    had_em = bool(re.search(r"\b(font-(bold|semibold|extrabold|black|medium))\b", raw))
    had_head_caps = bool(re.search(r"\b(uppercase|tracking-\[)", raw))
    seen = set()

    def emit(cls: str) -> None:
        for piece in cls.split():
            if not piece:
                continue
            # Format placeholders are positional: never dedupe `{}`.
            if "{" in piece or "}" in piece:
                out.append(piece)
                continue
            if piece not in seen:
                seen.add(piece)
                out.append(piece)

    def base_of(token: str) -> str:
        m = re.match(r"^(?:sm|md|lg|xl|2xl):(.+)$", token)
        return m.group(1) if m else token

    for token in tokens:
        if token.startswith("{{") or token.startswith("{%"):
            emit(token)  # Tera fragment — untouched
            continue
        if "{" in token or "}" in token:
            emit(token)  # fmt fragment — untouched
            continue
        base = base_of(token)
        if base in TOKEN_MAP:
            emit(TOKEN_MAP[base])
            continue
        if token in STRUCTURAL_LEFTOVERS:
            leftovers.append(token)
            continue
        if token.startswith(STATE_VARIANTS):
            continue  # state variant of anything: design, dropped
        if DROP_COLOR_BORDER.match(base):
            continue
        if base.startswith(KEEP_PREFIXES) and not base.startswith(("rounded", "shadow")):
            emit(token)
            continue
        if base in DROP_EXACT:
            continue
        if base.startswith(DROP_PREFIXES):
            continue
        emit(token)

    if had_em and "apex-em" not in seen and tag in ("span", "b", "strong", "p", "div", "td", "li", "a", "em", "label"):
        emit("apex-em")
    if had_head_caps and "apex-section-head" not in seen and tag in ("h2", "div", "span"):
        emit("apex-section-head")
    if tag in ("button", "a"):
        if "apex-btn" not in seen and ("absolute" not in raw):
            # A bare button/link that carried any styling becomes a button.
            if had_primary_fill or "py-" in raw or "px-" in raw or "rounded" in raw or "bg-" in raw or "border" in raw:
                emit("apex-btn")
        if had_primary_fill and "apex-btn--primary" not in seen and "apex-btn" in seen:
            emit("apex-btn--primary")
        if had_danger and "apex-btn" in seen:
            emit("apex-btn--danger")
        if had_sm and "apex-btn" in seen and "apex-btn--sm" not in seen:
            emit("apex-btn--sm")
        if tag == "a" and "apex-btn" not in seen and "apex-link" not in seen and "apex-" not in raw:
            emit("apex-link")
    add = primitive_for_tag(tag, " ".join(out) + " " + raw)
    for piece in add:
        emit(piece)
    return " ".join(out), leftovers


TAG_RE = re.compile(r"<(button|a|input|textarea|select|table|label|h1|h2|h3|span|div|p|td|li|em|b|strong)\b[^>]*?class=\\?\"([^\"\\]*)\\?\"")
CLASS_ONLY_RE = re.compile(r"class=\\\"([^\"\\]*)\\\"|class=\"([^\"]*)\"")


def sweep_text(text: str, leftovers: dict[str, list[str]], log: list[str], relpath: str) -> str:
    # Find the tag for each class attribute by scanning backwards.
    out = []
    pos = 0

    def find_tag(src: str, at: int) -> str:
        region = src[max(0, at - 400):at]
        tags = re.findall(r"<([a-zA-Z][a-zA-Z0-9-]*)\b", region)
        return tags[-1] if tags else ""

    for m in CLASS_ONLY_RE.finditer(text):
        # A class attribute follows whitespace inside a tag; a match right
        # after another string literal is a Rust tokeniser artifact.
        before = text[m.start() - 1 : m.start()]
        if before and before not in " \t\n":
            continue
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        tag = find_tag(text, m.start())
        new, left = transform_class(raw, tag)
        for token in left:
            leftovers.setdefault(token, []).append(relpath)
        if new != raw:
            log.append(f"{relpath}: class {raw!r} -> {new!r}")
            # rebuild the exact original quoting style
            whole = m.group(0)
            prefix = "class=\\\"" if whole.startswith("class=\\\"") else "class=\""
            suffix = "\\\"" if whole.endswith("\\\"") else "\""
            out.append((m.start(), m.end(), f"{prefix}{new}{suffix}"))
    # apply edits back-to-front
    for start, end, replacement in reversed(out):
        text = text[:start] + replacement + text[end:]
    return text


def sweep_middots(text: str) -> tuple[str, int]:
    # The copy law: ` · ` separators become `, `. Only in text nodes —
    # a middot is never inside a tag or attribute in our markup.
    count = 0
    def repl(m: re.Match) -> str:
        nonlocal count
        count += 1
        return f"{m.group(1)}, {m.group(2)}"
    text = re.sub(r"([\w\)\].!?…]) · ([\w\(\u00c0-\uffff])", repl, text)
    text = re.sub(r"([\u00c0-\uffff\w]) ·([\u00c0-\uffff\w])", repl, text)
    return text, count


def main() -> int:
    dry = "--dry" in sys.argv
    report_only = "--report" in sys.argv
    leftovers: dict[str, list[str]] = {}
    log: list[str] = []
    changed_files = 0
    middot_count = 0

    files = [
        (p, "rust") for p in RUST_FILES
        if not any(s in str(p) for s in SKIP)
    ] + [(p, "html") for p in HTML_FILES] + [(p, "md") for p in MD_FILES]

    for path, kind in files:
        relpath = str(path.relative_to(REPO))
        text = path.read_text()
        new_text = sweep_text(text, leftovers, log, relpath)
        new_text, dots = sweep_middots(new_text)
        middot_count += dots
        if new_text != text:
            changed_files += 1
            if not dry and not report_only:
                path.write_text(new_text)

    print(f"files changed: {changed_files}; edits: {len(log)}; middots fixed: {middot_count}")
    if report_only or dry:
        print("\nleftover tokens (need structural rewrites):")
        for token, sites in sorted(leftovers.items(), key=lambda kv: -len(kv[1])):
            print(f"{len(sites):5d}  {token}")
        return 0
    Path("/tmp/ark-sweep-log.txt").write_text("\n".join(log))
    print("full edit log: /tmp/ark-sweep-log.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
