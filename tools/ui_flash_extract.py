#!/usr/bin/env python3
"""Flash-copy extraction shared by the UI copy/terminology/catalog gates.

House style: stdlib only, mirrors tools/check_topology_contracts.py.

Extracts the string literal at every user-facing flash call site:

    redirect_success("…")   redirect_error("…")
    FlashMessage::success("…") / ::error("…") / ::info("…")

across services/mail-server/crates/*/src/**/*.rs. Files are split at the
first `#[cfg(test)]` (same contract as check_topology_contracts.py), so test
fixtures never gate. Also detects the `redirect_error(&error.to_string())`
call-site shape that leaks raw error Display text into the browser.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATES_SRC = ROOT / "services/mail-server/crates"

FLASH_CALL_RE = re.compile(
    r"\b(redirect_success|redirect_error|FlashMessage::success|"
    r"FlashMessage::error|FlashMessage::info)\s*\(\s*"
    r'("(?:[^"\\]|\\.)*")'
)

# `redirect_error(&error.to_string())` and friends — passing an error's
# Display through to the browser verbatim (leaked-error-display).
LEAKED_ERROR_DISPLAY_RE = re.compile(
    r"\bredirect_error\s*\(\s*&?"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\.to_string\(\)"
)

_RUST_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0"}

# ── test-region stripping ──────────────────────────────────────────────────
#
# check_topology_contracts.py splits a file at its first `#[cfg(test)]`.
# That works for app.rs, but api-server's web.rs carries TOP-LEVEL
# `#[cfg(test)]`-attributed items (a test-only middleware alias) followed by
# hundreds of lines of production routes — a naive split would gate nothing.
# The extractors therefore remove each TOP-LEVEL `#[cfg(test)]` ITEM
# individually (brace-aware, raw-string/comment aware) and keep everything
# else. Same contract, more precise: test code never gates, production code
# always does.

_CHAR_LIT_RE = re.compile(r"'(\\.|[^\\'])'")
_RAW_STR_OPEN_RE = re.compile(r"(?:\b[bc]?r)(#+)\"")


def _depth_prefix(text: str) -> list[int]:
    """depths[i] = brace depth immediately BEFORE text[i]."""
    depths = [0] * (len(text) + 1)
    depth = 0
    i = 0
    n = len(text)
    while i < n:
        depths[i] = depth
        ch = text[i]
        two = text[i:i + 2]
        if two == "//":
            end = text.find("\n", i)
            skip = n if end < 0 else end + 1
            for j in range(i, min(skip, n)):
                depths[j] = depth
            i = skip
            continue
        if two == "/*":
            nest = 1
            j = i + 2
            while j < n and nest:
                if text[j:j + 2] == "/*":
                    nest += 1
                    j += 2
                elif text[j:j + 2] == "*/":
                    nest -= 1
                    j += 2
                else:
                    j += 1
            for k in range(i, min(j, n)):
                depths[k] = depth
            i = j
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                depths[k] = depth
            i = j
            continue
        if ch == "r" and (m := _RAW_STR_OPEN_RE.match(text, i)) and \
                (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = m.group(1)
            close = text.find(f'"{hashes}', m.end())
            j = n if close < 0 else close + 1 + len(hashes)
            for k in range(i, min(j, n)):
                depths[k] = depth
            i = j
            continue
        if ch == "'" and (m := _CHAR_LIT_RE.match(text, i)):
            for k in range(i, min(m.end(), n)):
                depths[k] = depth
            i = m.end()
            continue
        if ch == "'":
            if m := _CHAR_LIT_RE.match(text, i):
                i = m.end()
            else:
                i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    depths[n] = depth
    return depths


def _matching_brace(text: str, open_idx: int) -> int:
    """Index of the `}` closing the `{` at `open_idx`, or -1.

    Single pass with early exit — string / raw-string / char-literal /
    comment aware, mirroring _depth_prefix's token rules.
    """
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if two == "//":
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
            continue
        if two == "/*":
            nest = 1
            i += 2
            while i < n and nest:
                if text[i:i + 2] == "/*":
                    nest += 1
                    i += 2
                elif text[i:i + 2] == "*/":
                    nest -= 1
                    i += 2
                else:
                    i += 1
            continue
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "r" and (m := _RAW_STR_OPEN_RE.match(text, i)) and \
                (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = m.group(1)
            close = text.find(f'"{hashes}', m.end())
            i = n if close < 0 else close + 1 + len(hashes)
            continue
        if ch == "'" and (m := _CHAR_LIT_RE.match(text, i)):
            i = m.end()
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def production_split(text: str) -> str:
    """Remove every top-level `#[cfg(test)]` item from `text`.

    An item spans from its `#[cfg(test)]` attribute to the end of the next
    top-level braced block, or to the terminating `;` for brace-less items
    (`use`, `extern crate`, …). Nested (depth > 0) `#[cfg(test)]` attributes
    are left alone — they vanish with their enclosing test module.
    """
    depths = _depth_prefix(text)
    top_level = [
        m.start()
        for m in re.finditer(r"#\[cfg\(test\)\]", text)
        if depths[m.start()] == 0
    ]
    if not top_level:
        return text

    # Cut from the END so earlier offsets stay valid.
    cuts: list[tuple[int, int]] = []
    for start in top_level:
        i = text.find("]", start) + 1
        n = len(text)
        # skip whitespace, comments and any further attributes, then cut the
        # item: to its matching top-level close brace, or its `;`
        while i < n:
            while i < n and text[i] in " \t\r\n":
                i += 1
            if text.startswith("//", i):
                end = text.find("\n", i)
                i = n if end < 0 else end + 1
                continue
            if text.startswith("/*", i):
                end = text.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
            if text.startswith("#![", i) or text.startswith("#[", i):
                end = text.find("]", i)
                i = (n if end < 0 else end + 1)
                continue
            break
        brace = text.find("{", i)
        semi = text.find(";", i)
        if brace != -1 and (semi == -1 or brace < semi):
            close = _matching_brace(text, brace)
            end = close + 1 if close >= 0 else n
        elif semi != -1:
            end = semi + 1
        else:
            end = n
        cuts.append((start, min(end, n)))

    out = text
    for start, end in reversed(cuts):
        out = out[:start] + out[end:]
    return out


def decode_rust_literal(literal: str) -> str:
    """Decode the simple escape subset Rust string literals actually carry."""
    out: list[str] = []
    i = 0
    while i < len(literal):
        ch = literal[i]
        if ch == "\\" and i + 1 < len(literal):
            nxt = literal[i + 1]
            if nxt == "\n":  # line continuation: skip leading whitespace
                i += 2
                while i < len(literal) and literal[i] in " \t\n\r":
                    i += 1
                continue
            out.append(_RUST_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


@dataclass
class FlashSite:
    path: str      # repo-relative posix path
    line: int      # 1-based line of the call site
    callee: str    # e.g. redirect_error / FlashMessage::info
    text: str      # decoded literal (the flash copy)


@dataclass
class LeakedErrorSite:
    path: str
    line: int
    snippet: str   # the offending call-site prefix


def production_text(path: Path) -> tuple[str, str]:
    """(repo-relative posix path, production text) for one .rs file."""
    rel = path.resolve().relative_to(ROOT).as_posix()
    return rel, production_split(path.read_text(errors="replace"))


# ── generic source/text helpers shared with the catalog gate ───────────────

_LINE_COMMENT_RE = re.compile(r"//")
_STYLE_RE = re.compile(r"<style\b[^>]*>.*?</style>", re.S | re.I)
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.S | re.I)
_FRAGMENT_RE = re.compile(r">([^<>]+)<")


def comment_spans(text: str) -> list[tuple[int, int]]:
    """[start, end) spans of // and /* */ comments (string-aware)."""
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        two = text[i:i + 2]
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if ch == "r" and (m := _RAW_STR_OPEN_RE.match(text, i)) and \
                (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = m.group(1)
            close = text.find(f'"{hashes}', m.end())
            i = n if close < 0 else close + 1 + len(hashes)
            continue
        if two == "//":
            end = text.find("\n", i)
            end = n if end < 0 else end
            spans.append((i, end))
            i = end + 1
            continue
        if two == "/*":
            end = text.find("*/", i + 2)
            end = n - 2 if end < 0 else end
            spans.append((i, end + 2))
            i = end + 2
            continue
        i += 1
    return spans


def rust_string_literals(text: str) -> list[tuple[int, int, str]]:
    """(start, end, raw-with-quotes) for every normal / raw string literal,
    skipping literals that live inside comments.

    A single left-to-right tokenizer: raw strings (r#"…"#, br#"…"#) win over
    normal quotes, so a `"` inside a raw template never starts a phantom
    normal string.
    """
    comments = comment_spans(text)
    out: list[tuple[int, int, str]] = []

    def in_comment(pos: int) -> bool:
        return any(s <= pos < e for s, e in comments)

    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "r" and (m := _RAW_STR_OPEN_RE.match(text, i)) and \
                (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = m.group(1)
            close = text.find(f'"{hashes}', m.end())
            if close < 0:
                i = m.end()
                continue
            end = close + 1 + len(hashes)
            if not in_comment(i):
                out.append((i, end, text[i:end]))
            i = end
            continue
        if ch == "'":
            if m := _CHAR_LIT_RE.match(text, i):
                i = m.end()  # char literal ('a', '\'', '\n') — never a string
            else:
                i += 1  # lifetime tick
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            if not in_comment(i):
                out.append((i, j, text[i:j]))
            i = j
            continue
        i += 1
    out.sort()
    return out


def visible_text_fragments(markup: str) -> list[str]:
    """User-visible text fragments of an HTML template: style/script dropped,
    the text between tags kept, whitespace collapsed, entities decoded."""
    markup = _STYLE_RE.sub("><", markup)
    markup = _SCRIPT_RE.sub("><", markup)
    fragments: list[str] = []
    import html as _html

    for m in _FRAGMENT_RE.finditer(f">{markup}<"):
        fragment = _html.unescape(m.group(1))
        fragment = re.sub(r"\s+", " ", fragment).strip()
        if fragment:
            fragments.append(fragment)
    return fragments


def flash_sites_ns(roots: list[Path] | None = None):
    """Re-export hook for the catalog gate (keeps one extractor)."""
    return all_flash_sites(roots)


def iter_rs_files(roots: list[Path] | None = None):
    for root in (roots or [CRATES_SRC]):
        if root.is_file():
            yield root
        elif root.is_dir():
            yield from sorted(p for p in root.rglob("*.rs") if p.is_file())


def extract_flash_sites(path: Path) -> tuple[list[FlashSite], list[LeakedErrorSite]]:
    sites: list[FlashSite] = []
    leaked: list[LeakedErrorSite] = []
    rel, production = production_text(path)
    for m in FLASH_CALL_RE.finditer(production):
        literal = m.group(2)
        text = decode_rust_literal(literal[1:-1])
        sites.append(
            FlashSite(
                path=rel,
                line=production.count("\n", 0, m.start(2)) + 1,
                callee=m.group(1),
                text=text,
            )
        )
    for m in LEAKED_ERROR_DISPLAY_RE.finditer(production):
        leaked.append(
            LeakedErrorSite(
                path=rel,
                line=production.count("\n", 0, m.start()) + 1,
                snippet=m.group(0)[:80],
            )
        )
    return sites, leaked


def all_flash_sites(
    roots: list[Path] | None = None,
) -> tuple[list[FlashSite], list[LeakedErrorSite]]:
    sites: list[FlashSite] = []
    leaked: list[LeakedErrorSite] = []
    for path in iter_rs_files(roots):
        s, l = extract_flash_sites(path)
        sites.extend(s)
        leaked.extend(l)
    return sites, leaked
