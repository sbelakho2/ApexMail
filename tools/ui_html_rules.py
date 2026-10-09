#!/usr/bin/env python3
"""Shared HTML-rule helpers for the fixture-driven UI gates.

House style: stdlib only (html.parser), mirrors tools/check_topology_contracts.py.

Consumed by tools/check_ui_form_hygiene.py, tools/check_ui_a11y.py and
tools/check_ui_links.py — import from here, do not copy the logic.

Inputs are the visual-fixture exports of ui-foundation's
`export_visual_fixtures` bin (provisioned with APEX_EXPORT_ALL_UI_ROUTES=1):
a directory of normalized *.html files plus a manifest.json mapping every
entry to {surface, route, htmlFile}. One html file can appear under several
viewport entries — documents are deduplicated by html file.
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path

# Void (self-closing) HTML elements — html.parser does not emit end tags for
# them, so they must never go on the open-element stack.
VOID_ELEMENTS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr",
}

FORM_CONTROLS = {"input", "select", "textarea"}


class Element:
    """One observed start tag, with the form it syntactically belongs to and
    whether it sits inside a <label> (the wrapping-label association)."""

    __slots__ = ("tag", "attrs", "line", "form_seq", "label_depth")

    def __init__(
        self,
        tag: str,
        attrs: dict,
        line: int,
        form_seq: int | None,
        label_depth: int = 0,
    ):
        self.tag = tag
        self.attrs = attrs
        self.line = line
        self.form_seq = form_seq
        self.label_depth = label_depth

    def attr(self, name: str) -> str | None:
        return self.attrs.get(name)

    def is_post_form(self) -> bool:
        return self.tag == "form" and (self.attrs.get("method") or "").strip().lower() == "post"

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"<{self.tag} line={self.line} attrs={self.attrs}>"


class _FixtureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[Element] = []
        self._open: list[Element] = []
        self._form_seq = 0
        self._open_form_seqs: list[int] = []
        self._label_depth = 0

    def _current_form(self) -> int | None:
        return self._open_form_seqs[-1] if self._open_form_seqs else None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attr_map: dict = {}
        for name, value in attrs:
            name = name.lower()
            if name not in attr_map:  # first occurrence wins
                attr_map[name] = value if value is not None else ""
        form_seq = self._current_form()
        if tag == "form":
            self._form_seq += 1
            form_seq = self._form_seq
            self._open_form_seqs.append(form_seq)
        if tag == "label":
            self._label_depth += 1
        element = Element(
            tag, attr_map, self.getpos()[0], form_seq, self._label_depth
        )
        self.elements.append(element)
        if tag not in VOID_ELEMENTS:
            self._open.append(element)

    def handle_startendtag(self, tag, attrs):
        # <div/> style self-closing: record, never push.
        self.handle_starttag(tag, attrs)
        if self._open and self._open[-1].tag == tag.lower():
            self._open.pop()
        if tag.lower() == "form" and self._open_form_seqs:
            self._open_form_seqs.pop()
        if tag.lower() == "label" and self._label_depth > 0:
            self._label_depth -= 1

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "form" and self._open_form_seqs:
            self._open_form_seqs.pop()
        if tag == "label" and self._label_depth > 0:
            self._label_depth -= 1
        for i in range(len(self._open) - 1, -1, -1):
            if self._open[i].tag == tag:
                del self._open[i:]
                break


class Document:
    """Parsed fixture document: flat element list + source line count."""

    def __init__(self, path: Path):
        self.path = path
        self.text = path.read_text(errors="replace")
        parser = _FixtureParser()
        try:
            parser.feed(self.text)
            parser.close()
        except Exception:  # a fixture that crashes the parser is still gateable
            pass
        self.elements = parser.elements
        # Index <form> elements by emission order — the parser assigned
        # form_seq 1..N in exactly that order.
        forms = [e for e in self.elements if e.tag == "form"]
        self._form_by_seq: dict[int, Element] = {i + 1: f for i, f in enumerate(forms)}

    def by_tag(self, *tags: str) -> list[Element]:
        wanted = {t.lower() for t in tags}
        return [e for e in self.elements if e.tag in wanted]

    def forms(self) -> list[Element]:
        return self.by_tag("form")

    def post_forms(self) -> list[Element]:
        return [f for f in self.forms() if f.is_post_form()]

    def in_form(self, element: Element) -> Element | None:
        """The <form> element that syntactically contains `element`, if any."""
        if element.form_seq is None:
            return None
        return self._form_by_seq.get(element.form_seq)  # type: ignore[attr-defined]

    # label association -----------------------------------------------------

    def label_for_ids(self) -> set[str]:
        ids = set()
        for label in self.by_tag("label"):
            target = (label.attr("for") or "").strip()
            if target:
                ids.add(target)
        return ids

    def controls(self) -> list[Element]:
        """Visible(ish) form controls: input/select/textarea, minus hidden."""
        out = []
        for e in self.by_tag(*FORM_CONTROLS):
            if e.tag == "input" and (e.attr("type") or "text").strip().lower() == "hidden":
                continue
            out.append(e)
        return out


def parse_document(path: Path) -> Document:
    return Document(path)


# ── fixture-set discovery ──────────────────────────────────────────────────

def load_fixture_manifest(fixtures_dir: Path) -> list[dict]:
    """Deduplicated {surface, route, html_file} entries for the fixture set.

    Prefers the exporter's manifest.json (exact surface:route attribution);
    falls back to globbing *.html with unknown surface/route so the gates
    still run over a hand-made directory.
    """
    manifest_path = fixtures_dir / "manifest.json"
    entries: list[dict] = []
    seen: set[str] = set()
    if manifest_path.is_file():
        data = json.loads(manifest_path.read_text())
        for item in data.get("fixtures", []):
            html_file = item.get("htmlFile") or item.get("html_file")
            if not html_file or html_file in seen:
                continue
            seen.add(html_file)
            entries.append(
                {
                    "surface": item.get("surface", "unknown"),
                    "route": item.get("route", "unknown"),
                    "html_file": html_file,
                }
            )
    if not entries:
        for html_file in sorted(fixtures_dir.glob("*.html")):
            entries.append(
                {
                    "surface": "unknown",
                    "route": html_file.stem,
                    "html_file": html_file.name,
                }
            )
    return entries


def fixture_coverage_violations(fixtures_dir: Path) -> list[str]:
    """Manifest entries the gate CANNOT read: a referenced html file that is
    missing or empty.

    Silently skipping these made a gate over zero documents look green — the
    explicitly-failing contract the review asks for. An empty file is a
    violation too: a document with no markup proves nothing.
    """
    problems: list[str] = []
    entries = load_fixture_manifest(fixtures_dir)
    if not entries:
        problems.append(
            f"no fixture entries found under {fixtures_dir} (no manifest.json, no *.html)"
        )
    for entry in entries:
        html_path = fixtures_dir / entry["html_file"]
        if not html_path.is_file():
            problems.append(
                f"{entry['surface']}{entry['route']}: referenced fixture "
                f"{entry['html_file']} is missing"
            )
            continue
        if not html_path.read_text(errors="replace").strip():
            problems.append(
                f"{entry['surface']}{entry['route']}: referenced fixture "
                f"{entry['html_file']} is empty"
            )
    return problems


def require_fixture_coverage(fixtures_dir: Path) -> list[str]:
    """Print + return the coverage violations (callers exit non-zero)."""
    problems = fixture_coverage_violations(fixtures_dir)
    for problem in problems:
        print(f"FAIL fixture-coverage {problem}")
    return problems


def iter_documents(fixtures_dir: Path):
    """Yield (entry, Document) for every deduplicated fixture document.

    Missing/empty referenced files are NOT skipped here — callers run
    [`require_fixture_coverage`] first so the gate fails instead of quietly
    scanning a subset.
    """
    for entry in load_fixture_manifest(fixtures_dir):
        html_path = fixtures_dir / entry["html_file"]
        if not html_path.is_file():
            continue
        yield entry, parse_document(html_path)


# ── shared attribute checks (gates D and E) ────────────────────────────────

def control_label_state(doc: Document, control: Element) -> tuple[bool, str]:
    """(labelled?, detail) for a visible form control.

    Labelled means: a <label for=ID> exists, the control is WRAPPED in a
    <label> (implicit association — the only way a control without an id can
    be labelled), or the control carries aria-label / aria-labelledby. A
    control with NO id and no wrapper is unlabelled by construction: no
    label[for] can ever point at it.
    """
    control_id = (control.attr("id") or "").strip()
    if control_id and control_id in doc.label_for_ids():
        return True, f"label for={control_id}"
    if control.label_depth > 0:
        return True, "wrapped in <label>"
    if (control.attr("aria-label") or "").strip():
        return True, "aria-label"
    if (control.attr("aria-labelledby") or "").strip():
        return True, "aria-labelledby"
    if not control_id:
        return False, f"no id and no wrapping <label> (<{control.tag} line={control.line}>)"
    return False, f"<{control.tag} id={control_id} line={control.line}>"


def describedby_missing_ids(doc: Document) -> list[str]:
    """aria-describedby targets that no element in the document carries.

    `aria-invalid="true"` + a dangling `aria-describedby` is an error
    ANNOUNCED without an error MESSAGE: the association the review asks for
    is the actually-existing element, not the attribute's presence.
    """
    ids = {(e.attr("id") or "").strip() for e in doc.elements}
    ids.discard("")
    missing: list[str] = []
    for element in doc.elements:
        described_by = (element.attr("aria-describedby") or "").strip()
        if not described_by:
            continue
        for token in described_by.split():
            if token not in ids:
                missing.append(
                    f"<{element.tag} line={element.line}> aria-describedby={token} "
                    f"points at no element"
                )
    return missing


_HEADING_RE = re.compile(r"^h([1-6])$")
