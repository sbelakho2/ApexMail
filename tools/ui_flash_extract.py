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
import sys
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


def _matching_brace(text: str, open_idx: int) -> int:
    """Index of the `}` closing the `{` at `open_idx`, or -1.

    Single pass with early exit — string / raw-string / char-literal /
    comment aware (the same token rules as `_mask_comments_and_strings`).
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


def _mask_comments_and_strings(text: str) -> str:
    """`text` with comments and string/raw-string literals blanked to spaces.

    Newlines are preserved so offsets and line numbers match the original.
    Uses this module's own tokenizers (comment_spans is string-aware,
    rust_string_literals skips comments).
    """
    masked = list(text)
    spans = comment_spans(text)
    spans += [(start, end) for start, end, _ in rust_string_literals(text)]
    for start, end in spans:
        for index in range(start, min(end, len(masked))):
            if masked[index] != "\n":
                masked[index] = " "
    return "".join(masked)


def _item_end(masked: str, start: int) -> int:
    """End offset of the item whose `#[cfg(test)]` attribute starts at `start`.

    Operates on MASKED text (comments/strings blanked), so brace matching
    cannot be fooled by a brace inside a literal.
    """
    n = len(masked)
    i = masked.find("]", start) + 1
    while i < n and masked[i] in " \t\r\n":
        i += 1
    while masked.startswith("#[", i) or masked.startswith("#![", i):
        close = masked.find("]", i)
        if close < 0:
            return n
        i = close + 1
        while i < n and masked[i] in " \t\r\n":
            i += 1
    brace = masked.find("{", i)
    semi = masked.find(";", i)
    if brace != -1 and (semi == -1 or brace < semi):
        depth = 0
        j = brace
        while j < n:
            if masked[j] == "{":
                depth += 1
            elif masked[j] == "}":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
        return n
    return semi + 1 if semi != -1 else n


def production_split(text: str) -> str:
    """Remove every top-level `#[cfg(test)]` item from `text`.

    An item spans from its `#[cfg(test)]` attribute to the end of the next
    top-level braced block, or to the terminating `;` for brace-less items
    (`use`, `extern crate`, …). Nested (depth > 0) `#[cfg(test)]` attributes
    are left alone — they vanish with their enclosing test module.

    Detection runs on MASKED text (comments and string/raw-string literals
    blanked), so an attribute-shaped token inside a doc comment or a string
    literal can never trigger a cut (the U-5 class: the old depth scan treated
    comment/string interiors as code and cut the file at the first such
    token, dropping everything after it). Comments are NOT blanked in the
    returned text — the callers' line numbers and prose stay intact.
    """
    masked = _mask_comments_and_strings(text)
    out = list(text)
    depth = 0
    i = 0
    n = len(masked)
    while i < n:
        char = masked[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and masked.startswith("#[cfg(test)]", i):
            end = _item_end(masked, i)
            for index in range(i, min(end, n)):
                if out[index] != "\n":
                    out[index] = " "
            i = end
            continue
        i += 1
    return "".join(out)


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


# ── self-test ──────────────────────────────────────────────────────────────
#
# The fixture is shaped like the F-4 / U-5 over-cut repro: a `#[cfg(test)]`
# token appears inside a line comment and inside a string literal, and a real
# top-level `#[cfg(test)]` alias item sits between production code. A split
# that treats comment/string interiors as code cuts at the comment token and
# swallows the production `use` import behind it; the extractor must keep the
# whole production region and drop exactly the cfg(test) items.
_SELF_TEST_FIXTURE = '''\
// A doc comment may mention #[cfg(test)] in prose without being an item.
use crate::middleware::rejection;

const TOKEN_IN_STRING: &str = "a string carrying #[cfg(test)] text";

pub async fn production_before_alias() {
    redirect_error("Post-token flash copy.");
}

#[cfg(test)]
pub(crate) use crate::middleware::rejection as alias_for_tests;

pub async fn production_after_alias() {
    redirect_error("Post-alias flash copy.");
}

#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn nested_attribute_vanishes_with_the_module() {}
}

pub async fn production_after_module() {
    redirect_success("After-module flash copy.");
}
'''


def self_test() -> int:
    """Prove `production_split` cannot over-cut (F-4 class). Exit 0 = pass."""
    failures: list[str] = []

    # Can-fail by construction: a naive first-token split must lose the
    # production region, or the fixture proves nothing.
    naive = _SELF_TEST_FIXTURE.split("#[cfg(test)]")[0]
    if "use crate::middleware::rejection;" in naive or "flash copy" in naive:
        failures.append("fixture does not exercise the over-cut (production precedes a token)")

    production = production_split(_SELF_TEST_FIXTURE)

    if "use crate::middleware::rejection;" not in production:
        failures.append("production import after the commented token was cut")
    if 'const TOKEN_IN_STRING: &str = "a string carrying #[cfg(test)] text";' not in production:
        failures.append("string literal containing the token was corrupted or cut")
    if "Post-token flash copy." not in production:
        failures.append("production call site before the alias item was cut")
    if "Post-alias flash copy." not in production:
        failures.append("post-alias production call site was cut (over-cut regression)")
    if "After-module flash copy." not in production:
        failures.append("post-module production call site was cut")
    if "alias_for_tests" in production:
        failures.append("top-level #[cfg(test)] use-item survived the split")
    if "nested_attribute_vanishes_with_the_module" in production:
        failures.append("top-level #[cfg(test)] mod tests survived the split")

    sites = [
        m for m in FLASH_CALL_RE.finditer(production) if "flash copy." in m.group(2)
    ]
    if len(sites) != 3:
        failures.append(f"expected 3 production flash call sites, found {len(sites)}")

    # A nested cfg(test) attribute inside a production item is left alone (it
    # is the item's concern, not the split's), but a top-level one is removed.
    nested = "fn f() {\n    #[cfg(test)]\n    fn inner() {}\n}\n"
    if production_split(nested) != nested:
        failures.append("nested (depth > 0) cfg(test) attribute was removed by the split")

    if failures:
        for failure in failures:
            print(f"ui_flash_extract self-test FAIL: {failure}", file=sys.stderr)
        return 1
    print(
        "ui_flash_extract self-test passed: post-alias and post-module flash copy "
        "survive the cfg(test) split; tokens in comments/strings do not cut"
    )
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    print("usage: python3 tools/ui_flash_extract.py --self-test", file=sys.stderr)
    raise SystemExit(2)

