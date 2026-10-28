#!/usr/bin/env python3
"""ApexMail i18n completeness gate.

Enforces the site's localization contract on three levels:

1. data/i18n.json parity — every locale carries the exact same key set,
   every template-referenced key exists, and no value is empty.
2. Untranslated-value detection — values that are byte-identical to the
   English template default (extracted from the {% else %} fallback branch
   of the i18n_data conditionals) are flagged when they contain real prose
   (more than two words), i.e. not brand terms like "ApexMail".
3. Built-page link integrity — every internal link on a locale page
   (public/xx/**) must resolve to an existing file of that locale, or to a
   deliberately shared English path (developer docs, API explorer, CCPA
   notice, internal tooling). Also verifies locale pages exist for every
   content page that templates link to.

Run from anywhere; paths resolve relative to this file. Exit 1 on findings.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SITE = HERE.parent / "apps" / "marketing-zola"

# Paths that are intentionally single-language (shared English). Everything
# else linked from a locale page must exist in that locale.
SHARED_EN = (
    "/docs",          # developer API reference — industry convention English
    "/api-explorer",  # interactive developer tool
    "/architecture",  # technical reference (HTTP semantics)
    "/performance-methodology",  # benchmark methodology reference
    "/privacy/do-not-sell",  # CCPA notice — US-legal document
    "/route-inventory",      # internal tooling page
    "/pgp-key.txt",          # static security-contact key
    # Delivery Diagnostics: the page's console-screenshot timeline, SMTP
    # response codes and event vocabulary ARE the product's English
    # terminology — same developer-audience convention as /docs (the
    # footer already localizes its link label via i18n footer keys).
    "/email-logs",
)

LOCALES = ("de", "fr", "es")


def fail(msgs: list[str]) -> int:
    for m in msgs:
        print(f"i18n: {m}")
    print(f"i18n: {len(msgs)} finding(s)")
    return 1 if msgs else 0


def template_refs(site: Path = SITE) -> tuple[set[tuple[str, str]], dict[tuple[str, str], str]]:
    """Extract (section, key) references and their English default text
    from the {% if i18n_data[l]["s"]["k"] ... %}...{% else %}DEFAULT{% endif %}
    pattern (defaults are best-effort: same-line else branches)."""
    refs: set[tuple[str, str]] = set()
    defaults: dict[tuple[str, str], str] = {}
    pat = re.compile(
        r'i18n_data\[l\]\["([a-z_0-9]+)"\]\["([a-z_0-9]+)"\][^%}]*%\}'
        r'(.*?){%\s*else\s*%}(.*?){%\s*endif\s*%}',
        re.S,
    )
    for f in glob.glob(str(site / "templates" / "**" / "*.html"), recursive=True):
        src = open(f, encoding="utf-8").read()
        for m in re.finditer(
            r'i18n_data(?:\[l\])?\["([a-z_0-9]+)"\]\["([a-z_0-9]+)"\]', src
        ):
            refs.add((m.group(1), m.group(2)))
        for m in pat.finditer(src):
            default = m.group(3).strip()
            if default and "<" not in default and "{{" not in default:
                defaults.setdefault((m.group(1), m.group(2)), default)
    return refs, defaults


def check_json(refs, defaults, site: Path = SITE) -> list[str]:
    msgs = []
    data = json.loads((site / "data" / "i18n.json").read_text())

    def flat(loc: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for s, v in data[loc].items():
            if isinstance(v, dict):
                for k, val in v.items():
                    out[f"{s}.{k}"] = "" if val is None else str(val)
            else:
                out[s] = "" if v is None else str(v)
        return out

    flats = {loc: flat(loc) for loc in LOCALES}
    keysets = {loc: set(f) for loc, f in flats.items()}
    union = set().union(*keysets.values())
    for loc in LOCALES:
        missing = sorted(union - keysets[loc])
        if missing:
            msgs.append(f"i18n.json: {loc} missing {len(missing)} keys: {missing[:8]}")
    for (s, k) in sorted(refs):
        for loc in LOCALES:
            if f"{s}.{k}" not in flats[loc]:
                msgs.append(f"i18n.json: {loc} lacks template-referenced key {s}.{k}")
            elif not flats[loc][f"{s}.{k}"].strip():
                msgs.append(f"i18n.json: {loc}.{s}.{k} is empty")
    # untranslated prose: identical to the English default, >2 words
    for (s, k), default in sorted(defaults.items()):
        words = default.split()
        if len(words) <= 2:
            continue
        for loc in LOCALES:
            val = flats[loc].get(f"{s}.{k}")
            if val == default:
                msgs.append(
                    f"untranslated: {loc}.{s}.{k} equals the English default "
                    f"({default[:48]!r})"
                )
    return msgs


def check_links(site: Path = SITE) -> list[str]:
    msgs = []
    pub = site / "public"
    if not pub.is_dir():
        return ["public/ not built — run zola build first"]
    pat = re.compile(r'href=(?:"([^"]+)"|([^\s">]+))')

    def exists(path: str) -> bool:
        p = (pub / path.lstrip("/")).resolve()
        if p.is_file():
            return True
        return (p / "index.html").is_file()

    for loc in LOCALES:
        for f in glob.glob(str(pub / loc / "**" / "*.html"), recursive=True):
            src = open(f, encoding="utf-8").read()
            rel = os.path.relpath(f, pub)
            for m in pat.finditer(src):
                h = m.group(1) or m.group(2) or ""
                if not h.startswith("/"):
                    continue
                if h.startswith(("//", f"/{loc}/")) or h == "/":
                    continue
                base = h.split("#")[0].split("?")[0]
                if not base:
                    continue
                if any(base == s or base.startswith(s + "/") or base.startswith(s + "?") for s in SHARED_EN):
                    continue
                if base.startswith(("/css", "/fonts", "/images", "/favicon", "/manifest", "/assets", "/js", "/giallo", "/icon", "/robots", "/sitemap")):
                    continue
                if not exists(f"{loc}{base}"):
                    msgs.append(
                        f"mixed-language link: {rel} -> {h} (no /{loc}{base.rstrip('/')}/)"
                    )
    return msgs


def check_variants(site: Path = SITE) -> list[str]:
    """Every template-linked page (non-shared) must exist in every locale."""
    msgs = []
    pat = re.compile(r'href=(?:"(/[^"#?]+)"|(/([^\s">#?]+)))')
    targets: set[str] = set()
    for f in glob.glob(str(site / "templates" / "**" / "*.html"), recursive=True):
        src = open(f, encoding="utf-8").read()
        for m in pat.finditer(src):
            h = (m.group(1) or m.group(2) or "").split("#")[0].split("?")[0]
            if not h or h == "/":
                continue
            if any(h == s or h.startswith(s + "/") for s in SHARED_EN):
                continue
            if h.startswith(("/css", "/fonts", "/images", "/favicon", "/manifest", "/assets", "/js", "/giallo", "/icon")):
                continue
            targets.add(h.rstrip("/"))
    for t in sorted(targets):
        # a target is satisfied when either the default page exists (and
        # every locale has a variant) — variant files are base.<loc>.md
        for loc in LOCALES:
            found = any(
                (site / "content" / t.lstrip("/")).parent.glob(
                    f"{(site / 'content' / t.lstrip('/')).name}.{loc}.md"
                )
            ) if (site / "content" / t.lstrip("/")).name else False
            # handle both page.md and section/index.md shapes
            cand_base = site / "content" / (t.lstrip("/") + ".md")
            cand_index = site / "content" / t.lstrip("/") / "index.md"
            ok = (
                cand_base.with_suffix(f".{loc}.md").exists()
                if cand_base.name != "index.md"
                else False
            ) or cand_index.with_suffix(f".{loc}.md").exists()
            if not ok:
                msgs.append(f"missing variant: {t} has no {loc} translation")
    return msgs


def self_test() -> int:
    """Drift-injection proof on a synthetic site: the clean fixture passes
    all three checks; each seeded localization defect is reported."""
    import tempfile

    def miss(detail: str) -> int:
        print(f"self-test FAIL: {detail}", file=sys.stderr)
        return 1

    def caught(msgs: list[str], expect: str) -> bool:
        return any(expect in m for m in msgs)

    with tempfile.TemporaryDirectory() as td:
        site = Path(td) / "site"
        titles = {"de": "Enterprise-E-Mail zugestellt", "fr": "E-mail entreprise livree",
                  "es": "Correo empresarial entregado"}
        (site / "data").mkdir(parents=True)
        (site / "data/i18n.json").write_text(json.dumps(
            {loc: {"hero": {"title": t}} for loc, t in titles.items()}))
        (site / "templates").mkdir()
        (site / "templates/base.html").write_text(
            '{% if i18n_data[l]["hero"]["title"] %}Enterprise email delivered'
            "{% else %}Enterprise email delivered{% endif %}\n"
            '<a href="/pricing">Pricing</a> <a href="/docs">Docs</a>\n')
        (site / "content").mkdir()
        (site / "content/pricing.md").write_text("Pricing\n")
        for loc in LOCALES:
            (site / f"content/pricing.{loc}.md").write_text(f"Pricing ({loc})\n")
            (site / "public" / loc / "pricing").mkdir(parents=True)
            (site / f"public/{loc}/index.html").write_text('<a href="/">Home</a>')
            (site / f"public/{loc}/pricing/index.html").write_text(
                f'<a href="/pricing">{"Preise" if loc == "de" else "Prix" if loc == "fr" else "Precios"}</a>')

        refs, defaults = template_refs(site)
        if refs != {("hero", "title")} or defaults.get(("hero", "title")) != "Enterprise email delivered":
            return miss(f"template refs not extracted: {refs!r} {defaults!r}")
        if check_json(refs, defaults, site):
            return miss(f"clean i18n.json reported: {check_json(refs, defaults, site)}")
        if check_variants(site):
            return miss(f"clean variants reported: {check_variants(site)}")
        if check_links(site):
            return miss(f"clean links reported: {check_links(site)}")

        i18n = site / "data/i18n.json"
        good_json = i18n.read_text()

        def json_defect(mutate) -> list[str]:
            data = json.loads(good_json)
            mutate(data)
            i18n.write_text(json.dumps(data))
            try:
                return check_json(refs, defaults, site)
            finally:
                i18n.write_text(good_json)

        if not caught(json_defect(lambda d: d.__setitem__("fr", {})), "fr missing"):
            return miss("missing-key defect not reported")
        if not caught(json_defect(lambda d: d["de"]["hero"].__setitem__("title", "Enterprise email delivered")),
                      "untranslated: de.hero.title"):
            return miss("untranslated-value defect not reported")
        if not caught(json_defect(lambda d: d["es"]["hero"].__setitem__("title", "")),
                      "es.hero.title is empty"):
            return miss("empty-value defect not reported")

        fr_var = site / "content/pricing.fr.md"
        fr_var.rename(site / "content/held.tmp")
        try:
            msgs = check_variants(site)
        finally:
            (site / "content/held.tmp").rename(fr_var)
        if not caught(msgs, "missing variant: /pricing has no fr"):
            return miss("missing-variant defect not reported")

        page = site / "public/de/pricing/index.html"
        good_page = page.read_text()
        page.write_text(good_page + '<a href="/features">Features</a>')
        try:
            msgs = check_links(site)
        finally:
            page.write_text(good_page)
        if not caught(msgs, "mixed-language link"):
            return miss("mixed-language-link defect not reported")
    print("self-test: ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    if not (SITE / "data" / "i18n.json").exists():
        print("i18n: apps/marketing-zola/data/i18n.json not found")
        return 2
    msgs: list[str] = []
    refs, defaults = template_refs()
    msgs += check_json(refs, defaults)
    msgs += check_variants()
    msgs += check_links()
    return fail(msgs)


if __name__ == "__main__":
    sys.exit(main())
