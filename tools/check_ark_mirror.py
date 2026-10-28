#!/usr/bin/env python3
"""ARK mirror gate — the marketing copy of the authority must be byte-equal.

apps/marketing-zola/static/css/ark.css is a mirror of
services/mail-server/crates/ui-foundation/assets/ark.css (the single design
authority both Tailwind-free cssgen builds inline). Any edit to the authority
must be mirrored; this gate fails when the copies diverge.
"""

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUTHORITY = REPO / "services/mail-server/crates/ui-foundation/assets/ark.css"
MIRROR = REPO / "apps/marketing-zola/static/css/ark.css"


def main(authority: Path = AUTHORITY, mirror: Path = MIRROR) -> int:
    if not authority.is_file():
        print(f"ark-mirror: authority missing: {authority}")
        return 1
    if not mirror.is_file():
        print(f"ark-mirror: mirror missing: {mirror}")
        return 1
    a = authority.read_bytes()
    m = mirror.read_bytes()
    if a == m:
        print(f"ark-mirror: byte-identical ({len(a)} bytes)")
        return 0
    # Locate the first divergence for the fixer.
    i = next((k for k, (x, y) in enumerate(zip(a, m)) if x != y), min(len(a), len(m)))
    print("ark-mirror: DIVERGED at byte", i)
    print("  authority:", a[max(0, i - 40) : i + 40])
    print("  mirror:   ", m[max(0, i - 40) : i + 40])
    print("  fix: cp services/mail-server/crates/ui-foundation/assets/ark.css "
          "apps/marketing-zola/static/css/ark.css")
    return 1


def self_test() -> int:
    """Prove the mirror gate on throwaway fixture copies (never mutates the repo)."""
    import contextlib
    import io
    import tempfile

    def run(authority_text: str | None, mirror_text: str | None) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            authority, mirror = root / "authority.css", root / "mirror.css"
            if authority_text is not None:
                authority.write_text(authority_text)
            if mirror_text is not None:
                mirror.write_text(mirror_text)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(authority, mirror)
            return code, out.getvalue()

    css = "/* the single design authority */\n.apex-panel { color: red; }\n"
    code, out = run(css, css)
    if code != 0 or "byte-identical" not in out:
        print(f"self-test FAIL: identical pair did not pass (exit {code}): {out}", file=sys.stderr)
        return 1
    for name, pair, needle in [
        ("missing-authority", (None, css), "authority missing"),
        ("missing-mirror", (css, None), "mirror missing"),
        ("diverged", (css, css.replace("red", "blue")), "DIVERGED"),
    ]:
        code, out = run(*pair)
        if code != 1 or needle not in out:
            print(f"self-test FAIL: {name} not caught (exit {code}): {out}", file=sys.stderr)
            return 1

    print("self-test: ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
