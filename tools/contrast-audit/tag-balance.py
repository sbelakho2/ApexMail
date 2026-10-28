#!/usr/bin/env python3
"""ApexMail tag-balance gate.

Strict-closure HTML balance check over every built marketing page and every
exported console/control-plane fixture. Catches markup that never closes
(unclosed <header>, spans swallowing the footer, ...) — the class of defect
browsers silently repair by re-nesting the rest of the page, which manifests
as layout spills.

Tags with implicit closure in HTML (p, li, td, tr, ...) are excluded so the
check stays zero-noise on Markdown-generated markup.

Exit 1 on any unexpected unclosed element. The html/body pair is tolerated
when the document ends inside trailing script content; anything else is real.
"""
import sys
from html.parser import HTMLParser
from pathlib import Path

VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
        'meta', 'param', 'source', 'track', 'wbr', 'path', 'circle', 'rect',
        'line', 'polyline', 'polygon', 'ellipse', 'stop', 'use'}
IMPLICIT = {'p', 'li', 'tr', 'td', 'th', 'thead', 'tbody', 'tfoot', 'dt',
            'dd', 'option', 'optgroup', 'rt', 'rp', 'head'}


class Balance(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag in VOID or tag in IMPLICIT:
            return
        cls = dict(attrs).get('class', '')[:60]
        line, _ = self.getpos()
        self.stack.append((tag, cls, line))

    def handle_endtag(self, tag):
        if tag in VOID or tag in IMPLICIT:
            return
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()
            return
        names = [t for t, _, _ in self.stack]
        if tag in names:
            i = len(names) - 1 - names[::-1].index(tag)
            swallowed = self.stack[i + 1:]
            self.errors.append(
                f"line {self.getpos()[0]}: </{tag}> closed while "
                f"<{self.stack[-1][0]} class={self.stack[-1][1]!r}> open; "
                f"swallowed {[(t, c) for t, c, _ in swallowed[:5]]}")
            del self.stack[i:]
        else:
            self.errors.append(f"line {self.getpos()[0]}: stray </{tag}>")


def check(path: Path) -> list[str]:
    try:
        src = path.read_text(encoding='utf-8', errors='replace')
    except OSError as e:
        return [f"unreadable: {e}"]
    b = Balance()
    try:
        b.feed(src)
        b.close()
    except Exception as e:  # parser blowups are findings, not crashes
        return [f"parse error: {e}"]
    out = list(b.errors)
    leftover = [entry for entry in b.stack if entry[0] not in ('html', 'body')]
    if leftover:
        out.append("unclosed at EOF: " + ", ".join(
            f"<{t} class={c!r}> line {l}" for t, c, l in leftover[:8]))
    return out


def self_test() -> int:
    """Drift-injection proof: clean page passes, each defect class is caught."""
    import tempfile

    def miss(detail: str) -> int:
        print(f"self-test FAIL: {detail}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        good = d / "good.html"
        good.write_text(
            "<html><body><header><div class=\"hero\">Hi<p>para<li>item</div></header>"
            "<footer><span>ok</span><img src=\"x.png\"></footer></body></html>")
        if check(good):
            return miss(f"balanced page reported: {check(good)}")
        defects = {
            "unclosed-at-eof": ("<div class=\"cta\"><h1>Title</h1><p>push", "unclosed at EOF"),
            "stray-close": ("<div><span>x</span></div></section>", "stray </section>"),
            "swallowed": ("<div><a href=\"/x\"><span>link</a></div>", "swallowed"),
        }
        for label, (src, want) in defects.items():
            f = d / f"bad_{label}.html"
            f.write_text(src)
            errs = check(f)
            if not errs or not any(want in e for e in errs):
                return miss(f"{label} defect not reported ({errs})")
    print("self-test: ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    root = Path(__file__).resolve().parent
    repo = root.parent.parent
    files = []
    marketing = repo / 'apps/marketing-zola/public'
    if marketing.is_dir():
        files += sorted(marketing.rglob('*.html'))
    fixtures = root / 'fixtures'
    if fixtures.is_dir():
        files += sorted(fixtures.glob('*.html'))
    if not files:
        print("tag-balance: no pages found (build the site / export fixtures first)")
        return 2
    bad = 0
    for f in files:
        errs = check(f)
        if errs:
            bad += 1
            print(f"FAIL {f.relative_to(repo)}")
            for e in errs[:6]:
                print(f"     {e}")
    print(f"tag-balance: {len(files) - bad}/{len(files)} pages balanced")
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
