#!/bin/sh
# docs-lint.sh — prose linter for the repository's documentation and
# (with --source) source comments; prints per-file violation counts and a
# total. Advisory (always exits 0) unless a baseline is given: --baseline
# FILE fails when the current total exceeds the tracked baseline;
# --update-baseline FILE regenerates it after deliberate rewrites. The
# committed baseline ratchets toward zero, then advisory mode is removed.
# Checks: em-dash density, sentence length, ALL-CAPS prose, filler
# vocabulary, 'never/not' contrast saturation, bold-emphasis density,
# nested parentheses, and duplicate sentences across the scanned files.

set -u

MAX_EM=2
MAX_WORDS=40
MAX_CONTRAST=2
MAX_BOLD=2
ALLOWLIST="WCAG HTTP HTTPS WASM HTML JSON HMAC NVDA SMIL POUR SLSA CORS QUIC OIDC UUID CIDR ASCII MUST POST PATCH OPTIONS CSRF SIGTERM A11Y SHA256SUMS HMAC-SHA IP-HMAC FAIL-CLOSED KIWI"

WITH_SOURCE=0
BASELINE=""
UPDATE_BASELINE=""
ROOT=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) WITH_SOURCE=1 ;;
    --baseline)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --baseline requires a file" >&2; exit 0; fi
      BASELINE="$1"
      ;;
    --update-baseline)
      shift
      if [ "$#" -eq 0 ]; then echo "docs-lint.sh: --update-baseline requires a file" >&2; exit 0; fi
      UPDATE_BASELINE="$1"
      ;;
    -h|--help)
      echo "usage: docs-lint.sh [--source] [--baseline FILE] [--update-baseline FILE] [ROOT_DIR]"
      echo "prose lint; advisory (exit 0) unless --baseline FILE is given,"
      echo "which fails (exit 1) when the current total exceeds the tracked"
      echo "baseline; --update-baseline FILE writes per-file counts + total"
      exit 0
      ;;
    -*) echo "docs-lint.sh: unknown option: $1" >&2; exit 0 ;;
    *) ROOT="$1" ;;
  esac
  shift
done

if [ -n "$UPDATE_BASELINE" ] && [ -n "$BASELINE" ]; then
  echo "docs-lint.sh: --baseline and --update-baseline are mutually exclusive" >&2
  exit 0
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "$ROOT" ]; then
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
fi
if [ ! -d "$ROOT/packages" ]; then
  echo "docs-lint.sh: not a repository root (no packages/ under $ROOT)" >&2
  exit 0
fi

tmpd=$(mktemp -d "${TMPDIR:-/tmp}/docs-lint.XXXXXX") || exit 0
trap 'rm -rf "$tmpd"' EXIT HUP INT TERM

cat > "$tmpd/mdprose.awk" <<'MDEOF'
# mdprose.awk — strip fenced code blocks and inline code spans from markdown
BEGIN { infence = 0 }
function emit(l,  nb, s, i) {
  gsub(/`[^`]*`/, " ", l)
  nb = 0
  s = l
  while ((i = index(s, "**")) > 0) { nb++; s = substr(s, i + 2) }
  gsub(/[*_~|]/, " ", l)
  gsub(/\[/, " ", l)
  gsub(/\]/, " ", l)
  gsub(/^[ \t]*>+[ \t]*/, "", l)
  print "\001B" nb "\002" l
}
{
  if ($0 ~ /^[ \t]*(```+|~~~+)/) {
    if (!infence) print ""
    infence = (infence ? 0 : 1)
    if (!infence) print ""
    next
  }
  if (infence) next
  emit($0)
}
MDEOF

cat > "$tmpd/checks.awk" <<'CHECKSEOF'
# checks.awk — mode=check: paragraph checks; mode=dup: sentence emission
BEGIN {
  max_em = max_em + 0
  max_words = max_words + 0
  max_contrast = max_contrast + 0
  max_bold = max_bold + 0
  n_al = split(allowlist, AL, " ")
  n_em = 0; n_long = 0; n_caps = 0; n_fill = 0
  n_contrast = 0; n_bold = 0; n_nest = 0
  pbold = 0
  pbuf = ""; pline = 0
}
function is_allowed(core,  i) {
  for (i = 1; i <= n_al; i++) if (core == AL[i]) return 1
  return 0
}
function nest_check(s,  d, c) {
  d = 0
  while (s != "") {
    c = substr(s, 1, 1)
    if (c == "(") { d++; if (d > 1) return 1 }
    if (c == ")") { if (d > 0) d-- }
    s = substr(s, 2)
  }
  return 0
}
function emit_sentences(  t, k, ns, s, n) {
  t = pbuf
  gsub(/\n/, " ", t)
  gsub(/[.!?] /, "\n", t)
  ns = split(t, S, "\n")
  for (k = 1; k <= ns; k++) {
    s = S[k]
    gsub(/^[^A-Za-z0-9]+|[^A-Za-z0-9]+$/, "", s)
    if (s == "") continue
    n = tolower(s)
    gsub(/[^A-Za-z0-9]+/, " ", n)
    gsub(/^ +| +$/, "", n)
    gsub(/  +/, " ", n)
    if (n != "") print n
  }
}
function check_para(  t, s, k, ns, wc, n, i, tok, core, after, lw, m) {
  t = pbuf
  gsub(/\n/, " ", t)
  n = 0; s = t
  while ((i = index(s, "—")) > 0) { n++; s = substr(s, i + 3) }
  if (n > max_em) {
    printf "%s:%d: em-dash: %d em dashes in one paragraph (limit %d)\n", file, pline, n, max_em
    n_em++
  }
  s = t
  gsub(/[.!?] /, "\n", s)
  ns = split(s, S, "\n")
  for (k = 1; k <= ns; k++) {
    if (S[k] == "") continue
    wc = split(S[k], W, /[ \t]+/)
    if (wc > max_words) {
      printf "%s:%d: long-sentence: %d words (limit %d): %.70s\n", file, pline, wc, max_words, S[k]
      n_long++
    }
  }
  s = t
  while (match(s, /[A-Z][A-Z0-9-]{3,}/)) {
    tok = substr(s, RSTART, RLENGTH)
    after = substr(s, RSTART + RLENGTH, 1)
    if (after ~ /[a-z]/) { s = substr(s, RSTART + 1); continue }
    core = tok
    gsub(/[0-9-]+$/, "", core)
    if (length(core) >= 4 && !is_allowed(core)) {
      printf "%s:%d: all-caps: '%s'\n", file, pline, tok
      n_caps++
    }
    s = substr(s, RSTART + RLENGTH)
  }
  lw = tolower(t)
  if (index(lw, "not merely") > 0) {
    printf "%s:%d: filler: 'not merely'\n", file, pline
    n_fill++
  }
  if (index(lw, "the property you can rely on") > 0) {
    printf "%s:%d: filler: 'the property you can rely on'\n", file, pline
    n_fill++
  }
  s = lw
  while (match(s, /(^|[^A-Za-z0-9_-])(premium|seamless|robust|comprehensive|battle-tested|enterprise-grade|production-ready|best-in-class|powerful|flexible)([^A-Za-z0-9_-]|$)/)) {
    m = substr(s, RSTART, RLENGTH)
    gsub(/^[^A-Za-z]+|[^A-Za-z]+$/, "", m)
    printf "%s:%d: filler: '%s'\n", file, pline, m
    n_fill++
    s = substr(s, RSTART + RLENGTH)
  }
  s = t
  n = gsub(/— never |, not |— and not | is not /, "", s)
  if (n > max_contrast) {
    printf "%s:%d: contrast: %d never/not constructions in one paragraph (limit %d)\n", file, pline, n, max_contrast
    n_contrast++
  }
  if (int(pbold / 2) > max_bold) {
    printf "%s:%d: bold: %d bold spans in one paragraph (limit %d)\n", file, pline, int(pbold / 2), max_bold
    n_bold++
  }
}
function flush() {
  if (pbuf == "") { pline = 0; pbold = 0; return }
  if (mode == "dup") emit_sentences()
  else check_para()
  pbuf = ""; pline = 0; pbold = 0
}
{
  nb = 0
  if (substr($0, 1, 2) == "\001B") {
    bmt = substr($0, 3)
    nb = bmt + 0
    bme = index(bmt, "\002")
    if (bme > 0) $0 = substr(bmt, bme + 1)
    else $0 = ""
  }
  if ($0 == "") { flush(); next }
  if (pline == 0) pline = NR
  pbold += nb
  pbuf = (pbuf == "" ? $0 : pbuf "\n" $0)
  if (mode != "dup" && nest_check($0) == 1) {
    printf "%s:%d: nested-parens: parentheses nested more than one level\n", file, NR
    n_nest++
  }
}
END {
  flush()
  if (mode != "dup") print "SUMMARY\t" file "\t" n_em "\t" n_long "\t" n_caps "\t" n_fill "\t" n_contrast "\t" n_bold "\t" n_nest
}
CHECKSEOF

cat > "$tmpd/comments.awk" <<'CMTEOF'
# comments.awk — emit comment text from source (lang=rs|js|php); a block
# comment is one paragraph, each line comment is one paragraph
function emit(s) {
  gsub(/^[ \t]+/, "", s)
  gsub(/[ \t]+$/, "", s)
  if (s != "") print s
}
function pick(lang, line,  a, b, c, f, k) {
  a = index(line, "//")
  b = (lang == "php" ? index(line, "#") : 0)
  c = index(line, "/*")
  f = 0; k = ""
  if (c > 0) { f = c; k = "B" }
  if (a > 0 && (f == 0 || a < f)) { f = a; k = "L" }
  if (b > 0 && (f == 0 || b < f)) { f = b; k = "L" }
  if (f == 0) return ""
  return k ":" f
}
BEGIN { inb = 0 }
{
  line = $0
  if (inb) {
    e = index(line, "*/")
    if (e > 0) {
      seg = substr(line, 1, e - 1)
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      line = substr(line, e + 2)
      inb = 0
    } else {
      seg = line
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      next
    }
  }
  while (line != "") {
    r = pick(lang, line)
    if (r == "") break
    split(r, fld, ":")
    pos = fld[2] + 0
    rest = substr(line, pos + 2)
    if (fld[1] == "L") { emit(rest); break }
    inb = 1
    e = index(rest, "*/")
    if (e > 0) {
      seg = substr(rest, 1, e - 1)
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      line = substr(rest, e + 2)
      inb = 0
    } else {
      seg = rest
      if (seg ~ /^[ \t]*\*/) seg = substr(seg, index(seg, "*") + 1)
      emit(seg)
      break
    }
  }
  if (!inb) print ""
}
CMTEOF

cat > "$tmpd/dupagg.awk" <<'DUPAWK'
# dupagg.awk — aggregate normalized sentences: duplicates across files
BEGIN { FS = "\t" }
{
  key = $1; f = $2
  if (key in cnt) {
    cnt[key]++
    if ((key SUBSEP f) in seenf) seenf[key SUBSEP f]++
    else seenf[key SUBSEP f] = 1
  } else {
    cnt[key] = 1
    firstfile[key] = f
    seenf[key SUBSEP f] = 1
  }
  files[f] = 1
}
END {
  for (k in cnt) if (cnt[k] > 1) {
    printf "  duplicate sentence (%d occurrences): %.70s\n", cnt[k], k
    for (f in files) {
      c = seenf[k SUBSEP f] + 0
      if (c > 0) {
        d = c - (f == firstfile[k] ? 1 : 0)
        if (d > 0) dupc[f] += d
      }
    }
  }
  for (f in dupc) printf "DUPSUMMARY\t%s\t%d\n", f, dupc[f]
  tot = 0
  for (f in dupc) tot += dupc[f]
  printf "DUPTOTAL\t%d\n", tot
}
DUPAWK

excluded() {
  awk '
    /\/vendor\// || /\/node_modules\// || /\/target\// || /\/pkg\// || /\/assets\// || /\/resources\// || /\/\.venv\// || /\/\.pytest_cache\// || /\/\.git\// { next }
    { print }
  '
}

scan_md() {
  find "$ROOT/packages" -type f -name '*.md' -print 2>/dev/null
  if [ -f "$ROOT/README.md" ]; then printf '%s\n' "$ROOT/README.md"; fi
  if [ -f "$ROOT/SECURITY.md" ]; then printf '%s\n' "$ROOT/SECURITY.md"; fi
}

scan_src() {
  for ext in rs php js; do
    find "$ROOT/packages" -type f -name "*.$ext" -print 2>/dev/null
  done
}

md_files=$(scan_md | excluded | sort -u)
src_files=""
if [ "$WITH_SOURCE" = 1 ]; then
  src_files=$(scan_src | excluded | sort -u)
fi

n_md=0
for f in $md_files; do n_md=$((n_md + 1)); done
n_src=0
for f in $src_files; do n_src=$((n_src + 1)); done

echo "== docs-lint (prose lint) =="
echo "scan root: $ROOT ($n_md markdown files, $n_src source files)"

summary_tmp="$tmpd/summary"
dup_tmp="$tmpd/dups"
dupout_tmp="$tmpd/dupout"
dupsum_tmp="$tmpd/dupsum"
out_tmp="$tmpd/out"
agg_tmp="$tmpd/agg"

{
  for f in $md_files; do
    awk -f "$tmpd/mdprose.awk" "$f" |
      awk -f "$tmpd/checks.awk" -v mode=check -v file="$f" \
          -v max_em="$MAX_EM" -v max_words="$MAX_WORDS" \
          -v max_contrast="$MAX_CONTRAST" -v max_bold="$MAX_BOLD" \
          -v allowlist="$ALLOWLIST"
  done
  if [ "$WITH_SOURCE" = 1 ]; then
    for f in $src_files; do
      case "$f" in
        *.php) lang=php ;;
        *) lang=rs ;;
      esac
      awk -f "$tmpd/comments.awk" -v lang="$lang" "$f" |
        awk -f "$tmpd/checks.awk" -v mode=check -v file="$f" \
            -v max_em="$MAX_EM" -v max_words="$MAX_WORDS" \
            -v max_contrast="$MAX_CONTRAST" -v max_bold="$MAX_BOLD" \
            -v allowlist="$ALLOWLIST"
    done
  fi
} > "$out_tmp"
grep '^SUMMARY' "$out_tmp" > "$summary_tmp"
grep -v '^SUMMARY' "$out_tmp"

for f in $md_files; do
  awk -f "$tmpd/mdprose.awk" "$f" |
    awk -f "$tmpd/checks.awk" -v mode=dup |
    awk -v f="$f" '{ printf "%s\t%s\n", $0, f }'
done > "$dup_tmp"

echo ""
echo "== duplicate sentences (markdown, normalized) =="
sort "$dup_tmp" | awk -f "$tmpd/dupagg.awk" > "$dupout_tmp"
grep -v '^DUPSUMMARY' "$dupout_tmp" | grep -v '^DUPTOTAL'
grep -E '^(DUPSUMMARY|DUPTOTAL)' "$dupout_tmp" > "$dupsum_tmp"

echo ""
cat "$summary_tmp" "$dupsum_tmp" | awk -F '\t' -v root="$ROOT" '
function rel(p) {
  if (root != "" && index(p, root "/") == 1) return substr(p, length(root) + 2)
  return p
}
$1 == "SUMMARY" {
  em = $3 + 0; lg = $4 + 0; cp = $5 + 0; fl = $6 + 0
  ct = $7 + 0; bd = $8 + 0; ns = $9 + 0
  cnt[$2] = em + lg + cp + fl + ct + bd + ns
  det[$2] = sprintf("em-dash %d, long-sentence %d, all-caps %d, filler %d, contrast %d, bold %d, nested-parens %d", em, lg, cp, fl, ct, bd, ns)
  nfiles++
  tot += em + lg + cp + fl + ct + bd + ns
}
$1 == "DUPSUMMARY" {
  dup[$2] = $3 + 0
  cnt[$2] += $3
  tot += $3
}
END {
  for (f in cnt) {
    printf "0\t%s\t%s, duplicate %d\n", f, det[f], dup[f] + 0
    printf "COUNT\t%s\t%d\n", rel(f), cnt[f]
  }
  printf "1\tTOTAL: %d violations across %d files\n", tot, nfiles
  printf "TOTALV\t%d\n", tot
}
' > "$agg_tmp"

tot=$(awk -F '\t' '/^TOTALV\t/ { print $2 }' "$agg_tmp")
tot=${tot:-0}

grep -v '^COUNT' "$agg_tmp" | grep -v '^TOTALV' | sort | sed -e 's/^0\t/  /' -e 's/^1\t/  /'

if [ -n "$UPDATE_BASELINE" ]; then
  awk -F '\t' '/^COUNT\t/ { printf "%s %s\n", $3, $2 }' "$agg_tmp" | LC_ALL=C sort -k2 > "$tmpd/baseline"
  printf 'TOTAL %s\n' "$tot" >> "$tmpd/baseline"
  if ! cat "$tmpd/baseline" > "$UPDATE_BASELINE"; then
    echo "docs-lint.sh: cannot write baseline: $UPDATE_BASELINE" >&2
    exit 1
  fi
  echo "docs-lint.sh: baseline written: $UPDATE_BASELINE (TOTAL $tot)"
  exit 0
fi

if [ -n "$BASELINE" ]; then
  if [ ! -f "$BASELINE" ]; then
    echo "docs-lint.sh: baseline file not found: $BASELINE (generate with --update-baseline)" >&2
    exit 1
  fi
  base_tot=$(awk '/^TOTAL[ \t]/ { t = $2 + 0 } END { print t + 0 }' "$BASELINE")
  base_tot=${base_tot:-0}
  if [ "$tot" -gt "$base_tot" ]; then
    echo "docs-lint.sh: FAIL: total $tot exceeds baseline $base_tot ($BASELINE); regenerate with --update-baseline only after deliberate rewrites" >&2
    exit 1
  fi
  echo "docs-lint.sh: OK: total $tot at or below baseline $base_tot"
  exit 0
fi

echo "docs-lint.sh: advisory: total $tot, no baseline given (exit 0)"
exit 0
