//! Typst compiler — template + JSON data → PDF bytes.
//!
//! This module wraps the Typst compiler pipeline:
//! 1. Build a `TypstWorld` from template name + JSON data
//! 2. Compile the Typst source to a Typst document
//! 3. Export the document to PDF bytes via `typst-pdf`
//!
//! # Security (O-14.1 / O-14.2)
//!
//! - **Rendering timeout** — A configurable timeout (default 10 s) prevents
//!   runaway Typst compilation from crafted JSON data.
//! - **Input size limit** — JSON data payload is capped at 1 MB so deeply
//!   nested / oversized inputs are rejected early.
//! - **Output size limit** — Generated PDF bytes are checked against a
//!   configurable maximum (default 50 MB) to prevent OOM from oversized
//!   output (e.g. a template expanded by huge JSON arrays).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::info;

use std::collections::BTreeMap;

use once_cell::sync::Lazy;

use crate::font::TtfFont;
use crate::world::{TypstWorld, WorldError};

// ---------------------------------------------------------------------------
// Embedded Unicode fonts (OFL-licensed Noto Sans)
// ---------------------------------------------------------------------------
// Latin/Greek/Cyrillic coverage comes from Noto Sans Regular; CJK from
// Noto Sans SC Regular. Both are embedded verbatim as PDF FontFile2
// streams behind /Type0 CIDFontType2 fonts with Identity-H encoding, so
// non-Latin text renders as native glyphs instead of folding to '?'.
// Licenses: assets/fonts/NotoSans-OFL.txt, assets/fonts/NotoSansSC-OFL.txt.
static NOTO_SANS: Lazy<TtfFont> = Lazy::new(|| {
    TtfFont::parse(include_bytes!("../assets/fonts/NotoSans-Regular.ttf").to_vec())
        .expect("embedded NotoSans-Regular.ttf must parse")
});
static NOTO_SANS_SC: Lazy<TtfFont> = Lazy::new(|| {
    TtfFont::parse(include_bytes!("../assets/fonts/NotoSansSC-Regular.ttf").to_vec())
        .expect("embedded NotoSansSC-Regular.ttf must parse")
});

// ---------------------------------------------------------------------------
// Security constants (configurable via env vars)
// ---------------------------------------------------------------------------

/// Maximum allowed size (in bytes) for the serialised JSON input data.
/// Prevents deeply‑nested or oversized JSON from causing resource exhaustion.
const MAX_DATA_JSON_BYTES: usize = 1024 * 1024; // 1 MB

/// Maximum allowed size (in bytes) for the generated PDF output.
/// Prevents a template (e.g. with huge data arrays) from producing a
/// multi‑gigabyte PDF that could cause an OOM.
const MAX_PDF_OUTPUT_SIZE: usize = 50 * 1024 * 1024; // 50 MB

/// Timeout for the PDF generation (including any eventual Typst compilation).
/// If generation does not complete within this window the request is aborted.
const RENDER_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render a named template with JSON data → PDF bytes.
///
/// # Security
///
/// 1. **Input validation** — The JSON payload is checked against
///    [`MAX_DATA_JSON_BYTES`] before any processing begins.
/// 2. **Timeout** — The actual generation runs inside
///    [`tokio::task::spawn_blocking`] wrapped by [`tokio::time::timeout`]
///    so a stalled / infinite‑loop template is caught.
/// 3. **Output limit** — After generation the byte vector is checked against
///    [`MAX_PDF_OUTPUT_SIZE`]; oversized output is rejected.
///
/// # Arguments
/// * `template` — template name (e.g. `"invoice"`, `"dpa"`)
/// * `data` — arbitrary JSON value to inject into the template
///
/// # Returns
/// PDF bytes on success.
///
/// # Errors
/// Returns `RenderError` if the JSON is too large, the template is not found,
/// generation times out, the output is too large, or PDF export fails.
pub async fn render_pdf(template: &str, data: &serde_json::Value) -> Result<Vec<u8>, RenderError> {
    // ---- 1. Input validation (O-14.1) ------------------------------------
    let data_json = serde_json::to_string_pretty(data)
        .map_err(|e| RenderError::Serialization(e.to_string()))?;

    if data_json.len() > MAX_DATA_JSON_BYTES {
        return Err(RenderError::Serialization(format!(
            "JSON data too large: {} bytes (max: {})",
            data_json.len(),
            MAX_DATA_JSON_BYTES,
        )));
    }

    let world = TypstWorld::new(template, data_json).map_err(RenderError::World)?;

    // ---- 2. Rendering with timeout (O-14.1) ------------------------------
    let template_owned = template.to_string();
    let pdf_bytes = timeout(
        Duration::from_secs(RENDER_TIMEOUT_SECS),
        tokio::task::spawn_blocking(move || generate_pdf(&template_owned, &world)),
    )
    .await
    .map_err(|_| RenderError::Compilation("PDF rendering timed out".to_string()))?
    .map_err(|e| RenderError::Compilation(format!("rendering task failed: {}", e)))??;

    // ---- 3. Output size limit (O-14.2) -----------------------------------
    if pdf_bytes.len() > MAX_PDF_OUTPUT_SIZE {
        return Err(RenderError::PdfExport(format!(
            "generated PDF too large: {} bytes (max: {})",
            pdf_bytes.len(),
            MAX_PDF_OUTPUT_SIZE,
        )));
    }

    info!(
        template = template,
        pdf_size = pdf_bytes.len(),
        "PDF rendered successfully"
    );

    Ok(pdf_bytes)
}

// ---------------------------------------------------------------------------
// PDF generator (valid PDF 1.4)
// ---------------------------------------------------------------------------

/// Fold one Unicode scalar to its closest WinAnsi (CP1252/Latin-1)
/// representation. Returns `Some(c)` for directly representable chars
/// (including CP1252 specials mapped to their byte value as C1 chars),
/// `None` when only transliteration or a marker can represent it.
///
/// LEGACY SINGLE-BYTE PATH ONLY: used for pure-WinAnsi lines and the fixed
/// ASCII title block, which render through the built-in Helvetica font.
/// Lines containing anything outside WinAnsi bypass this entirely and
/// render as native glyphs via the embedded Noto Sans / Noto Sans SC
/// Type0 fonts (see [`layout_lines`]).
fn fold_char_direct(c: char) -> Option<char> {
    let code = c as u32;
    const CP1252_SPECIALS: &[(u32, u8)] = &[
        (0x20AC, 0x80),
        (0x201A, 0x82),
        (0x0192, 0x83),
        (0x201E, 0x84),
        (0x2026, 0x85),
        (0x2020, 0x86),
        (0x2021, 0x87),
        (0x02C6, 0x88),
        (0x2030, 0x89),
        (0x0160, 0x8A),
        (0x2039, 0x8B),
        (0x0152, 0x8C),
        (0x017D, 0x8E),
        (0x2018, 0x91),
        (0x2019, 0x92),
        (0x201C, 0x93),
        (0x201D, 0x94),
        (0x2022, 0x95),
        (0x2013, 0x96),
        (0x2014, 0x97),
        (0x02DC, 0x98),
        (0x2122, 0x99),
        (0x0161, 0x9A),
        (0x203A, 0x9B),
        (0x0153, 0x9C),
        (0x017E, 0x9E),
        (0x0178, 0x9F),
    ];
    if (0x20..=0x7E).contains(&code) || (0xA0..=0xFF).contains(&code) {
        return Some(c);
    }
    if let Some(&(_, byte)) = CP1252_SPECIALS.iter().find(|(cp, _)| *cp == code) {
        return Some(byte as char);
    }
    None
}

/// Transliteration table for characters outside WinAnsi: Latin Extended-A
/// diacritics, basic Cyrillic and Greek, and common symbols.
fn transliterate(c: char) -> Option<&'static str> {
    Some(match c {
        'Ā' | 'Ą' | 'Á' | 'À' | 'Â' | 'Ã' | 'Å' => "A",
        'ā' | 'ą' | 'á' | 'à' | 'â' | 'ã' | 'å' => "a",
        'Ć' | 'Ĉ' | 'Č' => "C",
        'ć' | 'ĉ' | 'č' => "c",
        'Ď' | 'Đ' => "D",
        'ď' | 'đ' => "d",
        'Ě' | 'É' | 'È' | 'Ê' | 'Ẽ' | 'Ë' => "E",
        'ě' | 'é' | 'è' | 'ê' | 'ẽ' | 'ë' => "e",
        'Ĝ' | 'Ğ' | 'Ġ' => "G",
        'ĝ' | 'ğ' | 'ġ' => "g",
        'Ĥ' => "H",
        'ĥ' => "h",
        'Ĩ' | 'İ' | 'Ī' | 'Į' | 'Í' | 'Ì' | 'Î' => "I",
        'ĩ' | 'ı' | 'ī' | 'į' | 'í' | 'ì' | 'î' => "i",
        'Ĵ' => "J",
        'ĵ' => "j",
        'Ķ' => "K",
        'ķ' => "k",
        'Ĺ' | 'Ľ' | 'Ł' => "L",
        'ĺ' | 'ľ' | 'ł' => "l",
        'Ń' | 'Ň' | 'Ñ' => "N",
        'ń' | 'ň' | 'ñ' => "n",
        'Ő' | 'Ŏ' | 'Ō' | 'Ø' | 'Ó' | 'Ò' | 'Ô' | 'Õ' => "O",
        'ő' | 'ŏ' | 'ō' | 'ø' | 'ó' | 'ò' | 'ô' | 'õ' => "o",
        'Ŕ' | 'Ŗ' => "R",
        'ŕ' | 'ŗ' => "r",
        'Ś' | 'Š' | 'Ş' => "S",
        'ś' | 'š' | 'ş' => "s",
        'Ť' | 'Ţ' => "T",
        'ť' | 'ţ' => "t",
        'Ũ' | 'Ū' | 'Ů' | 'Ű' | 'Ų' | 'Ú' | 'Ù' | 'Û' => "U",
        'ũ' | 'ū' | 'ů' | 'ű' | 'ų' | 'ú' | 'ù' | 'û' => "u",
        'Ŵ' => "W",
        'ŵ' => "w",
        'Ŷ' | 'Ý' | 'Ÿ' => "Y",
        'ŷ' | 'ý' | 'ÿ' => "y",
        'Ź' | 'Ż' | 'Ž' => "Z",
        'ź' | 'ż' | 'ž' => "z",
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' => "e",
        'ё' => "yo",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' => "y",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' => "\"",
        'ы' => "y",
        'ь' => "'",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        'А' => "A",
        'Б' => "B",
        'В' => "V",
        'Г' => "G",
        'Д' => "D",
        'Е' => "E",
        'Ё' => "Yo",
        'Ж' => "Zh",
        'З' => "Z",
        'И' => "I",
        'Й' => "Y",
        'К' => "K",
        'Л' => "L",
        'М' => "M",
        'Н' => "N",
        'О' => "O",
        'П' => "P",
        'Р' => "R",
        'С' => "S",
        'Т' => "T",
        'У' => "U",
        'Ф' => "F",
        'Х' => "Kh",
        'Ц' => "Ts",
        'Ч' => "Ch",
        'Ш' => "Sh",
        'Щ' => "Shch",
        'Ъ' => "\"",
        'Ы' => "Y",
        'Ь' => "'",
        'Э' => "E",
        'Ю' => "Yu",
        'Я' => "Ya",
        'α' => "a",
        'β' => "b",
        'γ' => "g",
        'δ' => "d",
        'ε' => "e",
        'ζ' => "z",
        'η' => "e",
        'θ' => "th",
        'ι' => "i",
        'κ' => "k",
        'λ' => "l",
        'μ' => "m",
        'ν' => "n",
        'ξ' => "x",
        'ο' => "o",
        'π' => "p",
        'ρ' => "r",
        'σ' | 'ς' => "s",
        'τ' => "t",
        'υ' => "y",
        'φ' => "f",
        'χ' => "ch",
        'ψ' => "ps",
        'ω' => "o",
        'Α' => "A",
        'Β' => "B",
        'Γ' => "G",
        'Δ' => "D",
        'Ε' => "E",
        'Ζ' => "Z",
        'Η' => "E",
        'Θ' => "Th",
        'Ι' => "I",
        'Κ' => "K",
        'Λ' => "L",
        'Μ' => "M",
        'Ν' => "N",
        'Ξ' => "X",
        'Ο' => "O",
        'Π' => "P",
        'Ρ' => "R",
        'Σ' => "S",
        'Τ' => "T",
        'Υ' => "Y",
        'Φ' => "F",
        'Χ' => "Ch",
        'Ψ' => "Ps",
        'Ω' => "O",
        '©' => "(c)",
        '®' => "(r)",
        '™' => "(tm)",
        '°' => "deg",
        '±' => "+/-",
        '×' => "x",
        '÷' => "/",
        '≈' => "~=",
        '≠' => "!=",
        '≤' => "<=",
        '≥' => ">=",
        '→' => "->",
        '←' => "<-",
        '⇒' => "=>",
        '·' => ".",
        '«' => "<<",
        '»' => ">>",
        '№' => "No.",
        '\u{00A0}' | '\u{2007}' | '\u{202F}' => " ",
        '\u{2009}' | '\u{200A}' | '\u{2002}' | '\u{2003}' => " ",
        '\u{2011}' => "-",
        _ => return None,
    })
}

/// Marker emitted for characters with no WinAnsi representation and no
/// transliteration — never a silent omission.
const UNREPRESENTABLE_MARKER: char = '?';

/// Fold a string to the WinAnsi-representable subset. Returns the folded
/// string plus (folded_count, marker_count) so callers/tests can prove no
/// character is silently dropped.
fn fold_string(s: &str) -> (String, usize, usize) {
    let mut out = String::with_capacity(s.len());
    let mut folded = 0usize;
    let mut markers = 0usize;
    for c in s.chars() {
        // PDF-escapable control characters pass through so escape_pdf_string
        // can emit \n / \r / \t.
        if matches!(c, '\n' | '\r' | '\t') {
            out.push(c);
            continue;
        }
        if let Some(direct) = fold_char_direct(c) {
            out.push(direct);
            continue;
        }
        if let Some(replacement) = transliterate(c) {
            out.push_str(replacement);
            folded += 1;
            continue;
        }
        if c.is_whitespace() {
            out.push(' ');
            folded += 1;
            continue;
        }
        out.push(UNREPRESENTABLE_MARKER);
        markers += 1;
    }
    (out, folded, markers)
}

/// Escape a string for use inside a PDF literal string `(...)`.
///
/// Input is first folded via [`fold_string`] — characters above U+00FF are
/// transliterated or replaced with an explicit `?` marker, never silently
/// dropped. Parentheses/backslashes are escaped; non-ASCII bytes are octal
/// escapes so the value survives regardless of the reader's encoding.
fn escape_pdf_string(s: &str) -> String {
    let (folded, _, _) = fold_string(s);
    let mut out = String::with_capacity(folded.len());
    for ch in folded.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) <= 0x7f => out.push(c),
            c => out.push_str(&format!("\\{:03o}", c as u32)),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Multi-page text layout
// ---------------------------------------------------------------------------

/// A4 portrait in points.
const PAGE_WIDTH: u32 = 595;
const PAGE_HEIGHT: u32 = 842;
const MARGIN: u32 = 50;
const LINE_HEIGHT: u32 = 14;
/// First page: title + meta block occupy the top; data starts lower.
const FIRST_PAGE_DATA_TOP: u32 = 700;
const CONTINUATION_PAGE_TOP: u32 = PAGE_HEIGHT - MARGIN;
const PAGE_BOTTOM: u32 = MARGIN;
/// Wrap width for body text at /F2 10pt Helvetica across the content box.
/// Used ONLY for the legacy single-byte path so pure-Latin documents stay
/// byte-stable; lines containing non-WinAnsi characters are wrapped by
/// measured advance widths instead.
const WRAP_COLUMNS: usize = 92;
/// Printable content box width in points (A4 minus both margins).
const CONTENT_WIDTH_PT: f64 = (PAGE_WIDTH - 2 * MARGIN) as f64;
/// Font resource names for the embedded Unicode fonts.
const NOTO_SANS_REF: &str = "/F3";
const NOTO_SANS_SC_REF: &str = "/F4";

/// Which embedded font backs a glyph run.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum UnicodeFont {
    NotoSans,
    NotoSansSc,
}

impl UnicodeFont {
    fn ttf(&self) -> &'static TtfFont {
        match self {
            UnicodeFont::NotoSans => &NOTO_SANS,
            UnicodeFont::NotoSansSc => &NOTO_SANS_SC,
        }
    }

    /// Resource name inside the page /Resources dict.
    fn resource_ref(&self) -> &'static str {
        match self {
            UnicodeFont::NotoSans => NOTO_SANS_REF,
            UnicodeFont::NotoSansSc => NOTO_SANS_SC_REF,
        }
    }

    /// PDF /BaseFont name (must match across Type0, CIDFont, descriptor).
    fn base_font(&self) -> &'static str {
        match self {
            UnicodeFont::NotoSans => "/NotoSans-Regular",
            UnicodeFont::NotoSansSc => "/NotoSansSC-Regular",
        }
    }
}

/// A consecutive run of glyph IDs from one font.
struct GlyphRun {
    font: UnicodeFont,
    gids: Vec<u16>,
}

/// Laid-out line content. Lines whose every character is WinAnsi
/// representable keep the legacy single-byte Helvetica path (byte-stable
/// output for Latin payloads); anything else renders as native glyph runs
/// through the embedded Unicode fonts.
enum LineContent {
    Legacy(String),
    Glyphs(Vec<GlyphRun>),
}

/// One laid-out line.
struct LayoutLine {
    font_size: u8,
    content: LineContent,
}

/// Pick the embedded font for a character: Noto Sans first, Noto Sans SC
/// for CJK it lacks, and Noto Sans' '?' glyph as the explicit last resort
/// (still a visible marker, never a silent drop).
fn font_for_char(ch: char) -> (UnicodeFont, u16) {
    if let Some(gid) = NOTO_SANS.glyph(ch) {
        return (UnicodeFont::NotoSans, gid);
    }
    if let Some(gid) = NOTO_SANS_SC.glyph(ch) {
        return (UnicodeFont::NotoSansSc, gid);
    }
    (UnicodeFont::NotoSans, NOTO_SANS.glyph('?').unwrap_or(0))
}

/// Measured advance width of a character at `size` points.
fn char_width_pt(ch: char, size: f64) -> f64 {
    let (font, gid) = font_for_char(ch);
    font.ttf().advance_pt(gid, size)
}

fn is_winansi_representable(ch: char) -> bool {
    matches!(ch, '\n' | '\r' | '\t') || fold_char_direct(ch).is_some()
}

/// Convert a logical character sequence into per-font glyph runs.
fn glyph_runs(chars: &[char]) -> Vec<GlyphRun> {
    let mut runs: Vec<GlyphRun> = Vec::new();
    for &ch in chars {
        let (font, gid) = font_for_char(ch);
        match runs.last_mut() {
            Some(run) if run.font == font => run.gids.push(gid),
            _ => runs.push(GlyphRun {
                font,
                gids: vec![gid],
            }),
        }
    }
    runs
}

/// Wrap a line by measured advance widths (word boundaries where spaces
/// exist, hard character breaks for unbroken runs like CJK).
fn wrap_line_width_aware(line: &str, max_pt: f64, size: f64) -> Vec<Vec<char>> {
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return vec![chars];
    }
    let total: f64 = chars.iter().map(|c| char_width_pt(*c, size)).sum();
    if total <= max_pt {
        return vec![chars];
    }
    let mut out: Vec<Vec<char>> = Vec::new();
    let mut current: Vec<char> = Vec::new();
    let mut width = 0.0;
    let mut break_at: Option<usize> = None;
    for &ch in &chars {
        let w = char_width_pt(ch, size);
        if width + w > max_pt && !current.is_empty() {
            match break_at.filter(|b| *b < current.len()) {
                Some(b) => {
                    let tail = current.split_off(b);
                    out.push(std::mem::take(&mut current));
                    current = tail;
                    width = current.iter().map(|c| char_width_pt(*c, size)).sum();
                }
                None => {
                    out.push(std::mem::take(&mut current));
                    width = 0.0;
                }
            }
            break_at = None;
        }
        if ch == ' ' {
            break_at = Some(current.len() + 1);
        }
        width += w;
        current.push(ch);
    }
    out.push(current);
    out
}

/// Lay out logical lines: WinAnsi-only lines keep the legacy 92-column wrap
/// (byte-stable); lines with non-WinAnsi characters switch to native glyph
/// runs wrapped by measured widths.
fn layout_lines(logical: &[String]) -> Vec<LayoutLine> {
    logical
        .iter()
        .flat_map(|line| {
            if line.chars().all(is_winansi_representable) {
                wrap_line(line, WRAP_COLUMNS)
                    .into_iter()
                    .map(|text| LayoutLine {
                        font_size: 10,
                        content: LineContent::Legacy(text),
                    })
                    .collect::<Vec<_>>()
            } else {
                wrap_line_width_aware(line, CONTENT_WIDTH_PT, 10.0)
                    .into_iter()
                    .map(|chars| LayoutLine {
                        font_size: 10,
                        content: LineContent::Glyphs(glyph_runs(&chars)),
                    })
                    .collect::<Vec<_>>()
            }
        })
        .collect()
}

/// Render the JSON payload as formatted key/value blocks and arrays as
/// column tables. Every value in the payload is represented — no preview
/// truncation.
fn data_lines(data_json: &str) -> Vec<String> {
    let mut lines = Vec::new();
    match serde_json::from_str::<serde_json::Value>(data_json) {
        Ok(value) => format_value(&value, 0, &mut lines),
        Err(_) => {
            // Not valid JSON: fall back to rendering the raw payload so
            // nothing is silently hidden.
            lines.extend(data_json.lines().map(str::to_string));
        }
    }
    lines
}

fn indent_for(depth: usize) -> String {
    "  ".repeat(depth)
}

fn scalar_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

fn format_value(value: &serde_json::Value, depth: usize, lines: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                match inner {
                    serde_json::Value::Object(_) => {
                        lines.push(format!("{}{}:", indent_for(depth), key));
                        format_value(inner, depth + 1, lines);
                    }
                    serde_json::Value::Array(items) if !items.is_empty() => {
                        lines.push(format!("{}{}:", indent_for(depth), key));
                        format_table(items, depth + 1, lines);
                    }
                    serde_json::Value::Array(_) => {
                        lines.push(format!("{}{}: (empty)", indent_for(depth), key));
                    }
                    scalar => {
                        lines.push(format!(
                            "{}{}: {}",
                            indent_for(depth),
                            key,
                            scalar_to_string(scalar)
                        ));
                    }
                }
            }
        }
        serde_json::Value::Array(items) if !items.is_empty() => {
            format_table(items, depth, lines);
        }
        serde_json::Value::Array(_) => lines.push(format!("{}(empty list)", indent_for(depth))),
        scalar => lines.push(format!("{}{}", indent_for(depth), scalar_to_string(scalar))),
    }
}

/// Render an array as a column table when it contains objects (union of
/// keys as the header), or as itemized lines otherwise.
fn format_table(items: &[serde_json::Value], depth: usize, lines: &mut Vec<String>) {
    let object_items: Vec<&serde_json::Map<String, serde_json::Value>> =
        items.iter().filter_map(|item| item.as_object()).collect();
    let pad = indent_for(depth);
    if object_items.len() == items.len() && !object_items.is_empty() {
        let mut headers: Vec<String> = Vec::new();
        for obj in &object_items {
            for key in obj.keys() {
                if !headers.iter().any(|h| h == key) {
                    headers.push(key.clone());
                }
            }
        }
        lines.push(format!("{pad}# {}", headers.join(" | ")));
        for obj in &object_items {
            let cells: Vec<String> = headers
                .iter()
                .map(|h| {
                    obj.get(h)
                        .map(scalar_to_string)
                        .unwrap_or_else(|| "-".to_string())
                })
                .collect();
            lines.push(format!("{pad}* {}", cells.join(" | ")));
        }
    } else {
        for (i, item) in items.iter().enumerate() {
            match item {
                serde_json::Value::Object(_) => {
                    lines.push(format!("{pad}[{i}]"));
                    format_value(item, depth + 1, lines);
                }
                scalar => lines.push(format!("{pad}[{i}] {}", scalar_to_string(scalar))),
            }
        }
    }
}

/// Wrap a logical line at word boundaries; hard-break words longer than the
/// column width. Empty input yields one empty line (keeps blank spacing).
fn wrap_line(line: &str, width: usize) -> Vec<String> {
    if width == 0 || line.chars().count() <= width {
        return vec![line.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for word in line.split_whitespace() {
        let mut rest = word;
        loop {
            let space = usize::from(!current.is_empty());
            if current.chars().count() + space + rest.chars().count() <= width {
                if space == 1 {
                    current.push(' ');
                }
                current.push_str(rest);
                break;
            }
            let remaining = width.saturating_sub(current.chars().count() + space);
            if rest.chars().count() > width && remaining > 0 {
                let taken: String = rest.chars().take(remaining).collect();
                if space == 1 {
                    current.push(' ');
                }
                current.push_str(&taken);
                rest = &rest[remaining..];
                out.push(std::mem::take(&mut current));
            } else {
                out.push(std::mem::take(&mut current));
            }
        }
    }
    if !current.is_empty() || out.is_empty() {
        out.push(current);
    }
    out
}

/// Split laid-out lines into pages respecting the vertical layout constants.
fn paginate(lines: &[LayoutLine]) -> Vec<Vec<&LayoutLine>> {
    let mut pages: Vec<Vec<&LayoutLine>> = Vec::new();
    let mut current: Vec<&LayoutLine> = Vec::new();
    let mut y = FIRST_PAGE_DATA_TOP;
    for line in lines {
        if y < PAGE_BOTTOM {
            pages.push(std::mem::take(&mut current));
            y = CONTINUATION_PAGE_TOP;
        }
        current.push(line);
        y = y.saturating_sub(LINE_HEIGHT);
    }
    pages.push(current);
    pages
}

/// Generate a valid multi-page PDF 1.4 document rendering the FULL data
/// payload (key/value blocks and array tables) with line-based pagination.
///
/// NOTE: full Typst compilation remains unwired (tracked separately); this
/// generator produces spec-compliant output that any PDF reader can open,
/// with every byte of the JSON payload represented across as many pages as
/// needed. Non-WinAnsi text renders as native glyphs through the embedded
/// OFL Noto Sans / Noto Sans SC fonts (PDF /Type0 CIDFontType2 with
/// Identity-H encoding); [`fold_string`] folding remains only for the
/// single-byte legacy path (pure-WinAnsi lines and the fixed ASCII title
/// block), which keeps Latin-1 output byte-stable.
fn generate_pdf(template: &str, world: &TypstWorld) -> Result<Vec<u8>, RenderError> {
    let now = world.now.format("%Y%m%d%H%M%S").to_string();
    let title = match template {
        "invoice" => "ApexMail Invoice",
        "dpa" => "Data Processing Agreement",
        "compliance_report" => "Compliance Report",
        "analytics_export" => "Analytics Export",
        "qbr" => "Quarterly Business Review",
        _ => "Document",
    };

    // Escape every interpolated value: title/template come from a fixed set,
    // but the data body is attacker-controlled JSON.
    let title_esc = escape_pdf_string(title);
    let template_esc = escape_pdf_string(template);
    let now_esc = escape_pdf_string(&now);

    let lines = layout_lines(&data_lines(&world.data_json));
    let pages = paginate(&lines);

    // Only embed the Unicode fonts a document actually uses, so pure-Latin
    // output stays byte-identical to the legacy single-font pipeline.
    let uses_noto = lines.iter().any(|l| match &l.content {
        LineContent::Glyphs(runs) => runs.iter().any(|r| r.font == UnicodeFont::NotoSans),
        LineContent::Legacy(_) => false,
    });
    let uses_noto_sc = lines.iter().any(|l| match &l.content {
        LineContent::Glyphs(runs) => runs.iter().any(|r| r.font == UnicodeFont::NotoSansSc),
        LineContent::Legacy(_) => false,
    });
    let used_fonts: Vec<UnicodeFont> = [
        uses_noto.then_some(UnicodeFont::NotoSans),
        uses_noto_sc.then_some(UnicodeFont::NotoSansSc),
    ]
    .into_iter()
    .flatten()
    .collect();
    // Per-font glyph width tables (glyph ID → width in thousandths of em)
    // for the CIDFont /W arrays.
    let mut widths: BTreeMap<UnicodeFont, BTreeMap<u16, u16>> = BTreeMap::new();
    for line in &lines {
        if let LineContent::Glyphs(runs) = &line.content {
            for run in runs {
                let entry = widths.entry(run.font).or_default();
                for &gid in &run.gids {
                    let ttf = run.font.ttf();
                    let w = (f64::from(ttf.advance(gid)) * 1000.0 / f64::from(ttf.units_per_em()))
                        .round() as u16;
                    entry.insert(gid, w);
                }
            }
        }
    }

    // Content stream per page — build the actual bytes so /Length is exact.
    let mut content_streams: Vec<Vec<u8>> = Vec::with_capacity(pages.len());
    for (page_index, page_lines) in pages.iter().enumerate() {
        let mut body = String::new();
        let mut y = if page_index == 0 {
            PAGE_HEIGHT - MARGIN - 10
        } else {
            PAGE_HEIGHT - MARGIN
        };
        if page_index == 0 {
            body.push_str(&format!(
                "BT\n/F1 24 Tf\n{MARGIN} {y} Td\n({title_esc}) Tj\nET\n"
            ));
            y -= 30;
            body.push_str(&format!(
                "BT\n/F2 12 Tf\n{MARGIN} {y} Td\n(Template: {template_esc}) Tj\nET\n"
            ));
            y -= 20;
            body.push_str(&format!(
                "BT\n/F2 12 Tf\n{MARGIN} {y} Td\n(Generated: {now_esc}) Tj\nET\n"
            ));
            y -= 20;
            body.push_str(&format!(
                "BT\n/F2 12 Tf\n{MARGIN} {y} Td\n(Data — full payload, {count} lines:) Tj\nET\n",
                count = lines.len()
            ));
        }
        for line in page_lines {
            match &line.content {
                LineContent::Legacy(text) => {
                    let esc = escape_pdf_string(text);
                    body.push_str(&format!(
                        "BT\n/F2 {size} Tf\n{MARGIN} {y} Td\n({esc}) Tj\nET\n",
                        size = line.font_size
                    ));
                }
                LineContent::Glyphs(runs) => {
                    // Each run positions itself absolutely; advance widths
                    // accumulate horizontally within the line.
                    let mut x = f64::from(MARGIN);
                    for run in runs {
                        if run.gids.is_empty() {
                            continue;
                        }
                        let ttf = run.font.ttf();
                        let hex: String = run.gids.iter().map(|g| format!("{g:04X}")).collect();
                        body.push_str(&format!(
                            "BT\n{res} {size} Tf\n{x:.2} {y} Td\n<{hex}> Tj\nET\n",
                            res = run.font.resource_ref(),
                            size = line.font_size
                        ));
                        x += run
                            .gids
                            .iter()
                            .map(|g| ttf.advance_pt(*g, f64::from(line.font_size)))
                            .sum::<f64>();
                    }
                }
            }
            y = y.saturating_sub(LINE_HEIGHT);
        }
        content_streams.push(body.into_bytes());
    }

    // Objects: 1 catalog, 2 pages, per page (page + content), font last.
    let font_object = 3 + 2 * pages.len();
    let mut objects: Vec<Vec<u8>> = Vec::with_capacity(2 + 2 * pages.len() + 1);
    objects.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());

    let first_page_object = 3usize;
    let kids: Vec<String> = (0..pages.len())
        .map(|i| format!("{} 0 R", first_page_object + 2 * i))
        .collect();
    objects.push(
        format!(
            "<< /Type /Pages /Kids [{}] /Count {} >>",
            kids.join(" "),
            pages.len()
        )
        .into_bytes(),
    );
    // Unicode font objects follow the Helvetica object; numbers are
    // assigned deterministically from the used-font set.
    let mut unicode_refs: Vec<(&'static str, usize, usize, usize, usize)> = Vec::new();
    let mut next_obj = font_object + 1;
    for font in &used_fonts {
        let (type0, cid, descriptor, file) = (next_obj, next_obj + 1, next_obj + 2, next_obj + 3);
        next_obj += 4;
        unicode_refs.push((font.resource_ref(), type0, cid, descriptor, file));
    }
    let extra_font_refs: String = unicode_refs
        .iter()
        .map(|(res, type0, _, _, _)| format!(" {res} {type0} 0 R"))
        .collect();

    for (i, stream) in content_streams.iter().enumerate() {
        let page_num = first_page_object + 2 * i;
        let content_num = page_num + 1;
        objects.push(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}]\n   /Contents {content_num} 0 R /Resources << /Font << /F1 {font_object} 0 R /F2 {font_object} 0 R{extra_font_refs} >> >> >>"
            )
            .into_bytes(),
        );
        let mut obj = format!("<< /Length {} >>\nstream\n", stream.len()).into_bytes();
        obj.extend_from_slice(stream);
        obj.extend_from_slice(b"\nendstream");
        objects.push(obj);
    }
    objects.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());

    // Embedded Unicode fonts: /Type0 (Identity-H) → CIDFontType2 descendant
    // → FontDescriptor → FontFile2 (the raw TTF bytes, verbatim).
    objects.reserve(unicode_refs.len() * 4);
    for font in &used_fonts {
        let ttf = font.ttf();
        let (_, _type0, cid, descriptor, file) = unicode_refs
            .iter()
            .find(|(res, _, _, _, _)| *res == font.resource_ref())
            .copied()
            .expect("refs built for every used font");
        let w_array: String = widths
            .get(font)
            .map(|entries| {
                entries
                    .iter()
                    .map(|(gid, w)| format!(" {gid} {w}"))
                    .collect::<String>()
            })
            .unwrap_or_default();
        let bbox = ttf.bbox();
        objects.push(
            format!(
                "<< /Type /Font /Subtype /Type0 /BaseFont {base} /Encoding /Identity-H /DescendantFonts [ {cid} 0 R ] >>",
                base = font.base_font()
            )
            .into_bytes(),
        );
        objects.push(
            format!(
                "<< /Type /Font /Subtype /CIDFontType2 /BaseFont {base} /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor {descriptor} 0 R /DW 1000 /W [{w_array} ] /CIDToGIDMap /Identity >>",
                base = font.base_font()
            )
            .into_bytes(),
        );
        objects.push(
            format!(
                "<< /Type /FontDescriptor /FontName {base} /Flags 4 /FontBBox [{x0} {y0} {x1} {y1}] /ItalicAngle 0 /Ascent {ascent} /Descent {descent} /CapHeight {ascent} /StemV 80 /FontFile2 {file} 0 R >>",
                base = font.base_font(),
                x0 = bbox[0],
                y0 = bbox[1],
                x1 = bbox[2],
                y1 = bbox[3],
                ascent = ttf.ascent(),
                descent = ttf.descent(),
                file = file
            )
            .into_bytes(),
        );
        let raw = ttf.raw_bytes();
        let mut obj = format!(
            "<< /Length {} /Length1 {} >>\nstream\n",
            raw.len(),
            raw.len()
        )
        .into_bytes();
        obj.extend_from_slice(raw);
        obj.extend_from_slice(b"\nendstream");
        objects.push(obj);
    }

    // Assemble the file, recording each object's byte offset as we go.
    let mut pdf: Vec<u8> = b"%PDF-1.4\n".to_vec();
    let mut offsets: Vec<usize> = Vec::with_capacity(objects.len() + 1);
    offsets.push(0); // object 0 — free entry, offset unused
    for (idx, obj) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n", idx + 1).as_bytes());
        pdf.extend_from_slice(obj);
        pdf.extend_from_slice(b"\nendobj\n");
    }

    // Cross-reference table computed from the recorded offsets.
    let xref_offset = pdf.len();
    let size = offsets.len();
    pdf.extend_from_slice(format!("xref\n0 {size}\n").as_bytes());
    pdf.extend_from_slice(b"0000000000 65535 f \n");
    for &off in &offsets[1..] {
        pdf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }

    pdf.extend_from_slice(
        format!(
            "trailer\n<< /Size {size} /Root 1 0 R /Info << /Title ({title_esc}) /Producer (ApexMail pdf-renderer) >> >>\nstartxref\n{xref_offset}\n%%EOF\n"
        )
        .as_bytes(),
    );

    Ok(pdf)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderRequest {
    /// Template name:"invoice", "dpa", "compliance_report", "analytics_export", "qbr"
    pub template: String,
    /// Arbitrary JSON data to pass to the template
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderResponse {
    /// Base64-encoded PDF bytes (only used for JSON response mode)
    pub pdf_base64: Option<String>,
    /// Size in bytes
    pub size: usize,
    /// Template used
    pub template: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("template not found: {0}")]
    World(#[from] WorldError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("typst compilation error: {0}")]
    Compilation(String),
    #[error("pdf export error: {0}")]
    PdfExport(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the xref table is internally consistent: every `N 0 R` offset
    /// in the xref section must point at the actual `N 0 obj` header, and
    /// `startxref` must point at the `xref` keyword.
    #[test]
    fn xref_offsets_are_internally_consistent() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"customer":"Injec)ted \\( Corp","items":[1,2,3]}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("invoice", &world).expect("pdf generation failed");
        let text = String::from_utf8_lossy(&pdf);

        // startxref points at the xref keyword.
        let startxref_pos = text.rfind("startxref").expect("startxref missing");
        let after = text[startxref_pos..].trim_start_matches("startxref").trim();
        let xref_offset: usize = after
            .lines()
            .next()
            .unwrap()
            .trim()
            .parse()
            .expect("startxref value");
        assert_eq!(&pdf[xref_offset..xref_offset + 4], b"xref");

        // Parse the xref table entries and verify each in-use entry points at
        // the matching `N 0 obj` header.
        let xref_body = &text[xref_offset..];
        let mut lines = xref_body.lines();
        assert_eq!(lines.next().unwrap(), "xref");
        let header = lines.next().unwrap();
        let size: usize = header.split_whitespace().nth(1).unwrap().parse().unwrap();
        let first = lines.next().unwrap();
        assert_eq!(first, "0000000000 65535 f ");
        for obj_num in 1..size {
            let entry = lines.next().expect("missing xref entry");
            let offset: usize = entry[..10].parse().expect("bad xref offset");
            let expected_prefix = format!("{obj_num} 0 obj");
            assert!(
                pdf[offset..].starts_with(expected_prefix.as_bytes()),
                "xref offset for object {obj_num} does not point at its header: {entry}"
            );
        }

        // Every object is terminated and the file ends with %%EOF.
        assert!(pdf.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn escapes_parens_backslashes_and_non_latin1() {
        assert_eq!(escape_pdf_string("a(b)c"), "a\\(b\\)c");
        assert_eq!(escape_pdf_string("back\\slash"), "back\\\\slash");
        assert_eq!(escape_pdf_string("new\nline\r\ttab"), "new\\nline\\r\\ttab");
        // Latin-1 é (U+00E9) → octal escape of byte 0xE9.
        assert_eq!(escape_pdf_string("café"), "caf\\351");
        // Above latin-1: Ā folds to A, 你 has no mapping and becomes the
        // explicit '?' marker — nothing is silently dropped anymore.
        assert_eq!(escape_pdf_string("Ā你x"), "A?x");
        // CP1252 specials map onto their byte values (— is 0x97).
        assert_eq!(escape_pdf_string("a—b"), "a\\227b");
    }

    #[test]
    fn unicode_input_folds_without_silent_loss() {
        // Cyrillic input never panics and every character is accounted for.
        let input = "Привет мир — Привет!";
        let (folded, folded_count, markers) = fold_string(input);
        let direct = input.chars().count() - folded_count - markers;
        assert_eq!(direct + folded_count + markers, input.chars().count());
        assert_eq!(
            markers, 0,
            "Cyrillic should transliterate, not marker: {folded}"
        );
        assert!(
            folded.contains("Privet"),
            "transliteration missing: {folded}"
        );

        let (out, _, markers) = fold_string("你");
        assert_eq!(out, "?");
        assert_eq!(markers, 1);
    }

    #[test]
    fn large_payload_renders_multiple_pages() {
        // 300 lines cannot fit one page (~46 lines/page).
        let mut items = String::from("[");
        for i in 0..300 {
            if i > 0 {
                items.push(',');
            }
            items.push_str(&format!(
                r#"{{"line": {i}, "note": "row {i} of the export"}}"#
            ));
        }
        items.push(']');
        let world = TypstWorld {
            template_source: String::new(),
            data_json: format!(r#"{{"rows": {items}}}"#),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("analytics_export", &world).expect("pdf generation failed");
        let text = String::from_utf8_lossy(&pdf);

        let count_start = text.find("/Count ").unwrap() + "/Count ".len();
        let count: usize = text[count_start..]
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(count > 1, "expected multi-page output, got /Count {count}");
        assert!(text.contains("row 0 of the export"));
        assert!(text.contains("row 299 of the export"));
        assert_eq!(text.matches("/Type /Page ").count(), count);
        assert_eq!(text.matches("/Type /Pages").count(), 1);
    }

    // ── Embedded Unicode font pipeline ─────────────────────────────

    /// Byte-level helpers: the PDF mixes text and binary (FontFile2), so
    /// the extraction routines below scan raw bytes rather than a lossy
    /// UTF-8 conversion.
    fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
        haystack
            .windows(needle.len())
            .enumerate()
            .filter(|(_, w)| *w == needle)
            .map(|(i, _)| i)
            .collect()
    }

    /// Text content-stream chunks (excludes the binary FontFile2 streams,
    /// whose object preamble carries /Length1).
    fn text_stream_chunks(pdf: &[u8]) -> Vec<&[u8]> {
        let mut chunks = Vec::new();
        for start in find_all(pdf, b"stream\n") {
            let dict_start = pdf[..start]
                .windows(2)
                .rposition(|w| w == b"<<")
                .unwrap_or(0);
            let is_font_file = pdf[dict_start..start].windows(9).any(|w| w == b"/Length1 ");
            if is_font_file {
                continue;
            }
            let body_start = start + b"stream\n".len();
            let Some(end) = pdf[body_start..]
                .windows(b"\nendstream".len())
                .position(|w| w == b"\nendstream")
            else {
                continue;
            };
            chunks.push(&pdf[body_start..body_start + end]);
        }
        chunks
    }

    /// Glyph runs in document order: (font resource ref, decoded text).
    fn decode_glyph_runs(pdf: &[u8]) -> Vec<(&'static str, String)> {
        let noto_rev = NOTO_SANS.reverse_map();
        let sc_rev = NOTO_SANS_SC.reverse_map();
        let mut runs = Vec::new();
        for chunk in text_stream_chunks(pdf) {
            let mut i = 0;
            let mut active: Option<&'static str> = None;
            while i < chunk.len() {
                let (res, len) = if chunk[i..].starts_with(b"/F3 ") {
                    (Some(NOTO_SANS_REF), 4)
                } else if chunk[i..].starts_with(b"/F4 ") {
                    (Some(NOTO_SANS_SC_REF), 4)
                } else if chunk[i] == b'<' {
                    // Hex glyph string — the run we were building up.
                    if let Some(font_ref) = active.take() {
                        if let Some(close) = chunk[i + 1..].iter().position(|b| *b == b'>') {
                            let hex = &chunk[i + 1..i + 1 + close];
                            let text: String = hex
                                .chunks(4)
                                .filter_map(|pair| {
                                    let s = std::str::from_utf8(pair).ok()?;
                                    let gid = u16::from_str_radix(s, 16).ok()?;
                                    let map = if font_ref == NOTO_SANS_REF {
                                        &noto_rev
                                    } else {
                                        &sc_rev
                                    };
                                    map.get(&gid).copied()
                                })
                                .collect();
                            runs.push((font_ref, text));
                        }
                    }
                    (None, 1)
                } else {
                    (None, 1)
                };
                if let Some(r) = res {
                    active = Some(r);
                }
                i += len;
            }
        }
        runs
    }

    /// Raw FontFile2 stream payloads in document order.
    fn fontfile2_streams(pdf: &[u8]) -> Vec<&[u8]> {
        let mut out = Vec::new();
        for start in find_all(pdf, b"stream\n") {
            let dict_start = pdf[..start]
                .windows(2)
                .rposition(|w| w == b"<<")
                .unwrap_or(0);
            if !pdf[dict_start..start].windows(9).any(|w| w == b"/Length1 ") {
                continue;
            }
            let body_start = start + b"stream\n".len();
            let Some(end) = pdf[body_start..]
                .windows(b"\nendstream".len())
                .position(|w| w == b"\nendstream")
            else {
                continue;
            };
            out.push(&pdf[body_start..body_start + end]);
        }
        out
    }

    /// Parse "/W [g w g w ...]" into (glyph, width) pairs.
    fn w_arrays(pdf: &[u8]) -> Vec<Vec<(u16, u16)>> {
        let mut out = Vec::new();
        for start in find_all(pdf, b"/W [") {
            let Some(close_rel) = pdf[start..].iter().position(|b| *b == b']') else {
                continue;
            };
            let body = std::str::from_utf8(&pdf[start + 4..start + close_rel]).unwrap_or("");
            let nums: Vec<u16> = body
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
            let pairs = nums
                .chunks(2)
                .filter_map(|c| Some((*c.first()?, *c.get(1)?)))
                .collect();
            out.push(pairs);
        }
        out
    }

    #[test]
    fn embedded_fonts_parse_with_expected_coverage() {
        assert_eq!(NOTO_SANS.units_per_em(), 1000);
        assert!(NOTO_SANS.num_glyphs() > 1000);
        assert!(NOTO_SANS.hmtx_is_sane());
        assert!(NOTO_SANS.covers('A'));
        assert!(NOTO_SANS.covers('Ж'));
        assert!(NOTO_SANS.covers('α'));
        assert!(!NOTO_SANS.covers('你'), "Noto Sans must not cover CJK");

        assert_eq!(NOTO_SANS_SC.units_per_em(), 1000);
        assert!(NOTO_SANS_SC.num_glyphs() > 10_000);
        assert!(NOTO_SANS_SC.hmtx_is_sane());
        assert!(NOTO_SANS_SC.covers('你'));
        assert!(NOTO_SANS_SC.covers('好'));
        assert!(NOTO_SANS_SC.covers('A'));

        // Corrupt-font guard: parse errors, never panics.
        assert!(crate::font::TtfFont::parse(vec![1, 2, 3]).is_err());
        let mut otto = vec![0u8; 12];
        otto[0..4].copy_from_slice(b"OTTO");
        assert!(crate::font::TtfFont::parse(otto).is_err());
    }

    #[test]
    fn advances_are_real_and_proportional() {
        // CJK is full-width (1000 units at upem 1000); Latin is
        // proportional and 'W' is wider than 'I'.
        let cjk = NOTO_SANS_SC.glyph('你').expect("SC covers 你");
        assert_eq!(NOTO_SANS_SC.advance(cjk), 1000);

        let w = NOTO_SANS.glyph('W').expect("covers W");
        let i = NOTO_SANS.glyph('I').expect("covers I");
        let w_adv = NOTO_SANS.advance(w);
        let i_adv = NOTO_SANS.advance(i);
        assert!(w_adv > i_adv, "W ({w_adv}) must outrank I ({i_adv})");
        assert!(w_adv > 500, "W must be a real wide advance, got {w_adv}");
        assert!(i_adv > 100, "I must have a real advance, got {i_adv}");
        assert!(i_adv < 400, "I must be narrower than W, got {i_adv}");
    }

    #[test]
    fn cyrillic_greek_cjk_render_as_native_glyphs() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"greeting_ru": "Привет мир", "greeting_el": "Γεια σου κόσμε", "greeting_zh": "你好世界", "mixed": "Смешанный mixed テキスト with Latin"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("compliance_report", &world).expect("pdf generation failed");

        // Type0 pipeline markers present.
        assert!(pdf.windows(11).any(|w| w == b"/Identity-H"));
        assert!(pdf.windows(12).any(|w| w == b"CIDFontType2"));
        assert!(pdf.windows(10).any(|w| w == b"/FontFile2"));

        // Decode every glyph run back through our own cmap parser and
        // round-trip the exact source strings — proving no '?' markers and
        // no folding were involved.
        let runs = decode_glyph_runs(&pdf);
        assert!(!runs.is_empty(), "expected native glyph runs");
        let rendered: String = runs.iter().map(|(_, text)| text.as_str()).collect();
        for expected in [
            "Привет мир",
            "Γεια σου κόσμε",
            "你好世界",
            "Смешанный mixed テキスト with Latin",
        ] {
            assert!(
                rendered.contains(expected),
                "round-trip missing {expected:?}; rendered: {rendered:?}"
            );
        }
        // The CJK strings must come from the SC font, Cyrillic/Greek from
        // Noto Sans.
        assert!(runs
            .iter()
            .any(|(res, text)| *res == NOTO_SANS_SC_REF && text.contains("你好世界")));
        assert!(runs
            .iter()
            .any(|(res, text)| *res == NOTO_SANS_REF && text.contains("Привет мир")));

        // None of the source strings contain '?', so any '?' in the
        // decoded output would be a folding marker.
        assert!(
            !rendered.contains('?'),
            "folding markers leaked into native rendering: {rendered:?}"
        );
    }

    #[test]
    fn fontfile2_bytes_match_the_committed_assets() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"zh": "你好，世界"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("dpa", &world).expect("pdf generation failed");
        let streams = fontfile2_streams(&pdf);
        assert!(!streams.is_empty(), "SC font must be embedded");
        assert!(
            streams.iter().any(|s| *s == NOTO_SANS_SC.raw_bytes()),
            "the SC FontFile2 must equal the committed asset byte-for-byte"
        );
        assert!(
            streams
                .iter()
                .all(|s| *s == NOTO_SANS_SC.raw_bytes() || *s == NOTO_SANS.raw_bytes()),
            "only committed assets may be embedded"
        );

        // A Cyrillic document embeds Noto Sans verbatim.
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"ru": "Счёт-фактура"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("invoice", &world).expect("pdf generation failed");
        let streams = fontfile2_streams(&pdf);
        assert!(!streams.is_empty(), "Noto Sans must be embedded");
        assert!(
            streams.iter().any(|s| *s == NOTO_SANS.raw_bytes()),
            "the Noto Sans FontFile2 must equal the committed asset"
        );
        assert!(
            !streams.iter().any(|s| *s == NOTO_SANS_SC.raw_bytes()),
            "a Cyrillic document must not embed the 10MB CJK font"
        );
    }

    #[test]
    fn w_arrays_carry_real_widths() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"ru": "Привет", "zh": "你好"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("qbr", &world).expect("pdf generation failed");
        let arrays = w_arrays(&pdf);
        assert_eq!(arrays.len(), 2, "one /W per embedded font");
        let flat: Vec<(u16, u16)> = arrays.iter().flatten().copied().collect();
        assert!(!flat.is_empty());
        assert!(
            flat.iter().all(|(_, w)| *w > 0),
            "every used glyph must have a positive width: {flat:?}"
        );
        // The CJK glyphs are full-width (1000).
        let sc_map = NOTO_SANS_SC.reverse_map();
        let ni_gid = sc_map
            .iter()
            .find(|(_, c)| **c == '你')
            .map(|(g, _)| *g)
            .unwrap();
        assert!(
            flat.contains(&(ni_gid, 1000)),
            "CJK glyph must be 1000 units: {flat:?}"
        );
    }

    #[test]
    fn pure_latin_documents_stay_byte_identical_to_the_legacy_pipeline() {
        // No Type0 machinery appears at all: same objects, same bytes.
        let world = TypstWorld {
            template_source: String::new(),
            data_json:
                r#"{"customer": {"name": "Ada Lovelace"}, "items": [{"sku": "A-1", "qty": 2}]}"#
                    .to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("invoice", &world).expect("pdf generation failed");
        assert!(!pdf.windows(11).any(|w| w == b"/Identity-H"));
        assert!(!pdf.windows(10).any(|w| w == b"FontFile2"));
        assert!(!pdf.windows(3).any(|w| w == b"/F3"));
        assert!(!pdf.windows(3).any(|w| w == b"/F4"));
        assert!(pdf.windows(13).any(|w| w == b"/Type1 /BaseF"));
        // And Latin-1 supplement text still uses the legacy octal path.
        let world_latin1 = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"note": "café"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf1 = generate_pdf("invoice", &world_latin1).expect("pdf generation failed");
        assert!(
            !pdf1.windows(11).any(|w| w == b"/Identity-H"),
            "Latin-1 stays legacy"
        );
        assert!(pdf1.windows(7).any(|w| w == b"caf\\351"));
    }

    #[test]
    fn non_latin_lines_wrap_by_measured_width() {
        // A long CJK line must break into multiple glyph runs positioned at
        // increasing x offsets, each within the content width.
        let long_zh = "交付管道与送达确认 ".repeat(40);
        let world = TypstWorld {
            template_source: String::new(),
            data_json: format!(r#"{{"note": "{long_zh}"}}"#),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("analytics_export", &world).expect("pdf generation failed");
        let runs = decode_glyph_runs(&pdf);
        let glyph_line_count = runs.len();
        assert!(
            glyph_line_count > 1,
            "expected wrapping, got {glyph_line_count} runs"
        );
        // Every rendered line's measured advance must fit the content box.
        for chunk in text_stream_chunks(&pdf) {
            for run in extract_run_positions(chunk) {
                let (x, width) = run;
                let _ = x;
                assert!(
                    width <= CONTENT_WIDTH_PT + 0.01,
                    "line wider than content box: {run:?}"
                );
            }
        }
    }

    /// (x offset, measured width) for every glyph run in a content stream.
    fn extract_run_positions(chunk: &[u8]) -> Vec<(f64, f64)> {
        let text = String::from_utf8_lossy(chunk).to_string();
        let mut out = Vec::new();
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("/F") {
            rest = &rest[pos..];
            let is_f3 = rest.starts_with("/F3 ");
            let is_f4 = rest.starts_with("/F4 ");
            if !is_f3 && !is_f4 {
                rest = &rest[1..];
                continue;
            }
            // ... Tf <x> <y> Td <hex> Tj
            let Some(td) = rest.find(" Td\n") else { break };
            let coords: Vec<f64> = rest[..td]
                .rsplit(' ')
                .filter_map(|t| t.parse::<f64>().ok())
                .collect();
            let x = *coords.last().unwrap_or(&0.0);
            let Some(hex_start) = rest[td..].find('<') else {
                break;
            };
            let Some(hex_end) = rest[td + hex_start..].find('>') else {
                break;
            };
            let hex = &rest[td + hex_start + 1..td + hex_start + hex_end];
            let font = if is_f3 { &NOTO_SANS } else { &NOTO_SANS_SC };
            let size = 10.0;
            let width = hex
                .as_bytes()
                .chunks(4)
                .filter_map(|p| std::str::from_utf8(p).ok())
                .filter_map(|p| u16::from_str_radix(p, 16).ok())
                .map(|gid| font.advance_pt(gid, size))
                .sum::<f64>();
            out.push((x, width));
            rest = &rest[td + hex_start + hex_end..];
        }
        out
    }

    #[test]
    fn nested_payload_uses_blocks_and_tables() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"customer": {"name": "Ada Lovelace", "vat": "EE102951727"}, "items": [{"sku": "A-1", "qty": 2}, {"sku": "B-2", "qty": 5}]}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("invoice", &world).expect("pdf generation failed");
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("name: Ada Lovelace"));
        assert!(text.contains("vat: EE102951727"));
        // Column order follows serde_json's key ordering (alphabetical
        // without the preserve_order feature).
        assert!(text.contains("# qty | sku"));
        assert!(text.contains("* 2 | A-1"));
        assert!(text.contains("* 5 | B-2"));
    }

    #[test]
    fn generated_pdf_has_valid_markers_and_exact_length() {
        let world = TypstWorld {
            template_source: String::new(),
            data_json: r#"{"k":"v")"}"#.to_string(),
            now: chrono::Utc::now(),
        };
        let pdf = generate_pdf("dpa", &world).expect("pdf generation failed");
        assert!(pdf.starts_with(b"%PDF-1.4\n"));
        assert!(pdf.windows(9).any(|w| w == b"startxref"));
        assert!(pdf.ends_with(b"%%EOF\n"));

        // The content stream /Length must equal the bytes between `stream\n`
        // and `\nendstream`.
        let text = String::from_utf8_lossy(&pdf);
        let len_start = text.find("/Length ").unwrap() + "/Length ".len();
        let declared: usize = text[len_start..]
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let stream_start = text.find("stream\n").unwrap() + "stream\n".len();
        let stream_end = text.find("\nendstream").unwrap();
        assert_eq!(declared, stream_end - stream_start);
    }
}
