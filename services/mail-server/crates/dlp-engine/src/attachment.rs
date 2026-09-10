//! # Attachment Content Extraction & DLP Scanning
//!
//! Extracts text from common email attachment formats and runs DLP
//! scanning (PII, entropy, content policy) on the extracted content.
//!
//! Supported formats://! - **Plain text** (`.txt`, `.csv`, `.log`, `.json`, `.xml`, `.html`, `.md`)
//! - **OOXML** (`.docx`, `.xlsx`, `.pptx`) — extracts from inner XML parts
//! - **PDF** — extracts text streams between `BT`/`ET` operators
//! - **RTF** — strips RTF control words, extracts plain text
//!
//! Heavy lifting for PDF/OOXML intentionally stays zero-dep:we do a
//! best-effort text extraction rather than full rendering.

use crate::engine::{DlpAction, DlpEngine, DlpVerdict};
use flate2::read::DeflateDecoder;
use std::io::Read;

/// Maximum decompressed size for any single OOXML XML part (anti-zip-bomb).
/// 50 MB is generous for legitimate documents and tightly bounds memory.
const MAX_DEFLATED_PART_BYTES: u64 = 50 * 1024 * 1024;
/// Maximum cumulative decompressed bytes across an entire OOXML container.
const MAX_OOXML_TOTAL_DECOMPRESSED: u64 = 200 * 1024 * 1024;

/// File extension / MIME classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentKind {
    /// Plain UTF-8 text
    PlainText,
    /// OOXML (ZIP-based) document
    Ooxml,
    /// PDF
    Pdf,
    /// RTF
    Rtf,
    /// Unknown / unscannable binary
    Unknown,
}

impl AttachmentKind {
    /// Infer kind from filename extension.
    pub fn from_filename(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.ends_with(".txt")
            || lower.ends_with(".csv")
            || lower.ends_with(".log")
            || lower.ends_with(".json")
            || lower.ends_with(".xml")
            || lower.ends_with(".html")
            || lower.ends_with(".htm")
            || lower.ends_with(".md")
            || lower.ends_with(".yml")
            || lower.ends_with(".yaml")
            || lower.ends_with(".toml")
            || lower.ends_with(".ini")
            || lower.ends_with(".cfg")
            || lower.ends_with(".env")
        {
            Self::PlainText
        } else if lower.ends_with(".docx") || lower.ends_with(".xlsx") || lower.ends_with(".pptx") {
            Self::Ooxml
        } else if lower.ends_with(".pdf") {
            Self::Pdf
        } else if lower.ends_with(".rtf") {
            Self::Rtf
        } else {
            Self::Unknown
        }
    }

    /// Infer kind from the first few bytes (magic bytes).
    pub fn from_magic(data: &[u8]) -> Self {
        if data.starts_with(b"%PDF") {
            Self::Pdf
        } else if data.starts_with(b"PK\x03\x04") {
            // ZIP-based — could be OOXML
            Self::Ooxml
        } else if data.starts_with(b"{\\rtf") {
            Self::Rtf
        } else if bom_encoding(data).is_some() {
            // UTF-16/UTF-32 text carries a BOM but never validates as UTF-8 —
            // without this branch it lands in Unknown and is lossy-decoded
            // into replacement-character noise.
            Self::PlainText
        } else if data.is_ascii() || std::str::from_utf8(data).is_ok() {
            Self::PlainText
        } else {
            Self::Unknown
        }
    }
}

/// Whether the data is a legacy OLE compound document (old `.doc`/`.xls`/
/// `.ppt` files). These are text-bearing containers our zero-dep extractor
/// cannot read, so their contents are unverified (see
/// [`EXTRACTION_FAILED_RISK_FLOOR`]).
fn is_ole_container(data: &[u8]) -> bool {
    data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// Recognized BOM encodings (excluding plain UTF-8, which `from_utf8`
/// already handles).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BomEncoding {
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

/// BOM-sniff UTF-16/UTF-32. The 4-byte UTF-32 BOMs share their prefix with
/// the 2-byte UTF-16 BOMs, so they must be tested first.
fn bom_encoding(data: &[u8]) -> Option<BomEncoding> {
    match data {
        [0xFF, 0xFE, 0x00, 0x00, ..] => Some(BomEncoding::Utf32Le),
        [0x00, 0x00, 0xFE, 0xFF, ..] => Some(BomEncoding::Utf32Be),
        [0xFF, 0xFE, ..] => Some(BomEncoding::Utf16Le),
        [0xFE, 0xFF, ..] => Some(BomEncoding::Utf16Be),
        _ => None,
    }
}

/// Decode BOM-marked UTF-16/UTF-32 text. Returns `None` when the data has no
/// such BOM or does not decode cleanly (callers fall back to UTF-8/lossy).
fn decode_bom_text(data: &[u8]) -> Option<String> {
    let (encoding, bom_len) = match bom_encoding(data)? {
        BomEncoding::Utf16Le => (BomEncoding::Utf16Le, 2),
        BomEncoding::Utf16Be => (BomEncoding::Utf16Be, 2),
        BomEncoding::Utf32Le => (BomEncoding::Utf32Le, 4),
        BomEncoding::Utf32Be => (BomEncoding::Utf32Be, 4),
    };
    let payload = &data[bom_len..];
    match encoding {
        BomEncoding::Utf16Le | BomEncoding::Utf16Be => {
            let little_endian = encoding == BomEncoding::Utf16Le;
            let units: Vec<u16> = payload
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| {
                    if little_endian {
                        u16::from_le_bytes(*c)
                    } else {
                        u16::from_be_bytes(*c)
                    }
                })
                .collect();
            String::from_utf16(&units).ok()
        }
        BomEncoding::Utf32Le | BomEncoding::Utf32Be => {
            let little_endian = encoding == BomEncoding::Utf32Le;
            let mut out = String::with_capacity(payload.len() / 4);
            for chunk in payload.as_chunks::<4>().0 {
                let word = if little_endian {
                    u32::from_le_bytes(*chunk)
                } else {
                    u32::from_be_bytes(*chunk)
                };
                out.push(char::from_u32(word)?);
            }
            Some(out)
        }
    }
}

/// Attachment DLP verdict with extraction metadata.
#[derive(Debug, Clone)]
pub struct AttachmentVerdict {
    /// The underlying DLP verdict (PII, entropy, policy).
    pub dlp_verdict: DlpVerdict,
    /// What kind of attachment was processed.
    pub kind: AttachmentKind,
    /// Number of characters of text extracted from the attachment.
    pub extracted_text_len: usize,
    /// Whether the extraction was partial (e.g. binary fallback).
    pub partial_extraction: bool,
    /// Human-readable extraction note (e.g. "Extracted 2 XML parts from OOXML").
    pub extraction_note: String,
}

// ---------------------------------------------------------------------------
// Text extraction
// ---------------------------------------------------------------------------

/// Extract plain text from raw bytes based on file kind.
fn extract_text(data: &[u8], kind: AttachmentKind) -> (String, bool, String) {
    match kind {
        AttachmentKind::PlainText => extract_plaintext(data),
        AttachmentKind::Ooxml => extract_ooxml_text(data),
        AttachmentKind::Pdf => extract_pdf_text(data),
        AttachmentKind::Rtf => extract_rtf_text(data),
        AttachmentKind::Unknown => {
            // Try UTF-8 best-effort
            let text = String::from_utf8_lossy(data);
            let partial = text.contains('\u{FFFD}');
            (
                text.into_owned(),
                partial,
                "Binary file — best-effort UTF-8 decode".into(),
            )
        }
    }
}

fn extract_plaintext(data: &[u8]) -> (String, bool, String) {
    // BOM-marked UTF-16/UTF-32 first: decoded as UTF-8 these files are
    // replacement-character noise and every PII regex silently misses.
    if let Some(text) = decode_bom_text(data) {
        let note = match bom_encoding(data) {
            Some(BomEncoding::Utf16Le) => "Plain text (UTF-16LE, BOM-sniffed)",
            Some(BomEncoding::Utf16Be) => "Plain text (UTF-16BE, BOM-sniffed)",
            Some(BomEncoding::Utf32Le) => "Plain text (UTF-32LE, BOM-sniffed)",
            Some(BomEncoding::Utf32Be) => "Plain text (UTF-32BE, BOM-sniffed)",
            None => unreachable!("decode_bom_text only succeeds with a BOM"),
        };
        return (text, false, note.into());
    }
    match std::str::from_utf8(data) {
        Ok(s) => (s.to_string(), false, "Plain text extraction".into()),
        Err(_) => {
            let lossy = String::from_utf8_lossy(data).into_owned();
            (lossy, true, "Plain text with encoding errors".into())
        }
    }
}

/// Zero-dep OOXML text extraction.
/// OOXML files are ZIP archives. We scan for XML content parts and extract
/// text between `<w:t>`, `<a:t>`, `<t>` tags. This is a best-effort parser
/// that handles the common case without a full XML library.
fn extract_ooxml_text(data: &[u8]) -> (String, bool, String) {
    // Scan for PK local file headers and look for .xml entries
    let mut text = String::new();
    let mut parts_found = 0u32;
    let mut total_decompressed: u64 = 0;
    let mut bombed = false;

    // Simple ZIP scan:find local file headers (PK\x03\x04)
    let mut pos = 0;
    while pos + 30 < data.len() {
        if data[pos..].starts_with(b"PK\x03\x04") {
            let fname_len = u16::from_le_bytes([
                data.get(pos + 26).copied().unwrap_or(0),
                data.get(pos + 27).copied().unwrap_or(0),
            ]) as usize;
            let extra_len = u16::from_le_bytes([
                data.get(pos + 28).copied().unwrap_or(0),
                data.get(pos + 29).copied().unwrap_or(0),
            ]) as usize;
            let compressed_size = u32::from_le_bytes([
                data.get(pos + 18).copied().unwrap_or(0),
                data.get(pos + 19).copied().unwrap_or(0),
                data.get(pos + 20).copied().unwrap_or(0),
                data.get(pos + 21).copied().unwrap_or(0),
            ]) as usize;
            let compression = u16::from_le_bytes([
                data.get(pos + 8).copied().unwrap_or(0),
                data.get(pos + 9).copied().unwrap_or(0),
            ]);

            let header_end = pos + 30 + fname_len + extra_len;
            if pos + 30 + fname_len <= data.len() {
                let fname = String::from_utf8_lossy(&data[pos + 30..pos + 30 + fname_len]);
                if (fname.ends_with(".xml") || fname.contains("sharedStrings"))
                    && header_end + compressed_size <= data.len()
                {
                    let remaining_budget =
                        MAX_OOXML_TOTAL_DECOMPRESSED.saturating_sub(total_decompressed);
                    if remaining_budget == 0 {
                        bombed = true;
                        break;
                    }
                    let part_cap = remaining_budget.min(MAX_DEFLATED_PART_BYTES);
                    let compressed_bytes = &data[header_end..header_end + compressed_size];
                    match decode_zip_part(compression, compressed_bytes, part_cap) {
                        Ok(Some(xml_bytes)) => {
                            total_decompressed =
                                total_decompressed.saturating_add(xml_bytes.len() as u64);
                            let xml_str = String::from_utf8_lossy(&xml_bytes);
                            extract_xml_text_content(&xml_str, &mut text);
                            parts_found += 1;
                        }
                        Ok(None) => {}
                        Err(_) => {
                            // Bomb detected — abort to bound resource use.
                            bombed = true;
                            break;
                        }
                    }
                }
            }

            pos = header_end + compressed_size;
        } else {
            pos += 1;
        }
    }

    if bombed {
        return (
            text,
            true,
            format!(
                "OOXML: aborted — decompression exceeded safety cap ({} parts before abort)",
                parts_found
            ),
        );
    }

    if parts_found == 0 {
        (
            String::new(),
            true,
            "OOXML: no readable XML parts found".into(),
        )
    } else {
        let note = format!("Extracted text from {} OOXML XML parts", parts_found);
        (text, false, note)
    }
}

/// Decompress a ZIP entry, refusing to exceed `max_bytes`.
/// Returns `Ok(None)` for unsupported compression methods, `Err(())` if the
/// decompressed size would exceed `max_bytes` (decompression bomb).
fn decode_zip_part(compression: u16, bytes: &[u8], max_bytes: u64) -> Result<Option<Vec<u8>>, ()> {
    match compression {
        0 => {
            if bytes.len() as u64 > max_bytes {
                return Err(());
            }
            Ok(Some(bytes.to_vec()))
        }
        8 => {
            // Bound the DECODER OUTPUT, not the compressed input: `take`
            // on the input still lets a few KB of deflate expand to GBs
            // inside `read_to_end` before any post-hoc length check runs.
            // Reading at most `max_bytes + 1` decompressed bytes makes the
            // over-limit detection and the allocation bound the same event.
            let mut decoder = DeflateDecoder::new(bytes).take(max_bytes.saturating_add(1));
            let mut decoded = Vec::new();
            if decoder.read_to_end(&mut decoded).is_err() {
                return Ok(None);
            }
            if decoded.len() as u64 > max_bytes {
                return Err(());
            }
            Ok(Some(decoded))
        }
        _ => Ok(None),
    }
}

/// Extract text content from XML by finding text between `>` and `<` within
/// known content tags.
fn extract_xml_text_content(xml: &str, out: &mut String) {
    // Simple state machine:when we see a tag like <w:t>, <a:t>, <t>, <si>,
    // collect text until closing </...>
    let content_start_tags = ["<w:t", "<a:t", "<t>", "<t "];
    let mut remaining = xml;

    while !remaining.is_empty() {
        // Find next content start tag
        let next = content_start_tags
            .iter()
            .filter_map(|tag| remaining.find(tag).map(|pos| (pos, *tag)))
            .min_by_key(|(pos, _)| *pos);

        let Some((start_pos, _tag)) = next else {
            break;
        };

        // Find end of opening tag
        let after_tag = &remaining[start_pos..];
        let Some(gt_pos) = after_tag.find('>') else {
            break;
        };

        let text_start = start_pos + gt_pos + 1;
        let text_region = &remaining[text_start..];

        // Find next < (closing tag)
        let text_end = text_region.find('<').unwrap_or(text_region.len());
        let extracted = &text_region[..text_end];
        if !extracted.is_empty() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(extracted);
        }

        remaining = &remaining[text_start + text_end..];
    }
}

/// Maximum decompressed size for any single PDF FlateDecode stream.
const MAX_PDF_STREAM_BYTES: u64 = 20 * 1024 * 1024;

/// Maximum number of FlateDecode streams examined per PDF. Legitimate PDFs
/// have tens of streams; thousands of tiny streams is a resource-exhaustion
/// shape, so the walk stops here and reports it.
const MAX_PDF_STREAMS_EXAMINED: usize = 256;

/// Process-wide count of PDFs whose stream count exceeded
/// [`MAX_PDF_STREAMS_EXAMINED`] — observable metric for operators.
pub static PDF_STREAM_CAP_HITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Risk floor applied when a text-bearing attachment yields no — or an
/// implausibly small amount of — extractable text:contents are unverified,
/// so policy — not a silent Allow — decides.
const EXTRACTION_FAILED_RISK_FLOOR: f64 = 3.0;

/// Coverage heuristic denominator:extracted text below 1 byte per this many
/// bytes of attachment is "implausibly little" for a text-bearing container
/// (a 1 MiB PDF containing a single decoy character, for example). One
/// decoy character must not turn "we could not read this" into a clean
/// Allow.
const MIN_TEXT_COVERAGE_PER_BYTES: u64 = 100;

/// Zero-dep PDF text extraction.
/// Scans for text objects between BT (Begin Text) and ET (End Text) operators
/// and extracts string operands from Tj and TJ operators. Handles:
/// - literal strings in parentheses
/// - hex strings `<...>`
/// - FlateDecode-compressed content streams (inflated with flate2)
fn extract_pdf_text(data: &[u8]) -> (String, bool, String) {
    let content = String::from_utf8_lossy(data);
    let mut text = String::new();
    let mut partial = false;
    let mut text_objects = 0u32;

    // 1. Scan the raw (uncompressed) content.
    let mut remaining = content.as_ref();
    while let Some(bt_pos) = remaining.find("BT") {
        let after_bt = &remaining[bt_pos + 2..];
        let et_pos = after_bt.find("ET").unwrap_or(after_bt.len());
        let text_object = &after_bt[..et_pos];
        extract_pdf_strings(text_object, &mut text);
        text_objects += 1;
        remaining = &after_bt[et_pos..];
    }

    // 2. Inflate FlateDecode streams and scan their content too.
    // PDF text is very often compressed; skipping this missed most modern
    // PDFs entirely.
    let mut inflated_streams = 0u32;
    for stream in find_pdf_streams(data) {
        if let Some(inflated) = inflate_pdf_stream(stream) {
            let decoded = String::from_utf8_lossy(&inflated);
            let mut rem = decoded.as_ref();
            while let Some(bt_pos) = rem.find("BT") {
                let after_bt = &rem[bt_pos + 2..];
                let et_pos = after_bt.find("ET").unwrap_or(after_bt.len());
                extract_pdf_strings(&after_bt[..et_pos], &mut text);
                text_objects += 1;
                rem = &after_bt[et_pos..];
            }
            inflated_streams += 1;
        }
    }

    if text_objects == 0 {
        partial = true;
    }

    let note = if inflated_streams > 0 {
        format!(
            "PDF: extracted text from {} text objects ({} FlateDecode stream(s))",
            text_objects, inflated_streams
        )
    } else {
        format!("PDF: extracted text from {} text objects", text_objects)
    };
    (text, partial, note)
}

/// Locate the raw byte payload of every `stream … endstream` object whose
/// dictionary mentions `/FlateDecode`.
fn find_pdf_streams(data: &[u8]) -> Vec<&[u8]> {
    let mut streams = Vec::new();
    let mut pos = 0;
    while let Some(rel) = find_subslice(&data[pos..], b"stream") {
        // Resource-exhaustion guard: each collected stream costs an inflate
        // later; a PDF with thousands of streams is a DoS shape. Stop at the
        // cap, count it, and let text extraction proceed on what we have.
        if streams.len() >= MAX_PDF_STREAMS_EXAMINED {
            PDF_STREAM_CAP_HITS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                cap = MAX_PDF_STREAMS_EXAMINED,
                "PDF stream examination capped (possible resource-exhaustion shape)"
            );
            break;
        }
        let stream_kw = pos + rel;
        // The dictionary precedes the stream keyword; look back for the
        // object start to inspect the filter.
        let dict_start = data[..stream_kw]
            .windows(2)
            .rposition(|w| w == b"<<")
            .map(|i| i + 2)
            .unwrap_or(stream_kw);
        let dict = &data[dict_start..stream_kw];
        let is_flate = find_subslice(dict, b"/FlateDecode").is_some();

        // Payload starts after "stream" plus EOL (either \r\n or \n).
        let mut payload_start = stream_kw + "stream".len();
        if data.get(payload_start) == Some(&b'\r') {
            payload_start += 1;
        }
        if data.get(payload_start) == Some(&b'\n') {
            payload_start += 1;
        }

        if let Some(end_rel) = find_subslice(&data[payload_start..], b"endstream") {
            let payload_end = payload_start + end_rel;
            if is_flate && payload_end > payload_start {
                streams.push(&data[payload_start..payload_end]);
            }
            pos = payload_end + "endstream".len();
        } else {
            break;
        }
    }
    streams
}

/// Find a subslice in a haystack (memmem without extra deps).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Inflate a PDF FlateDecode stream (zlib format) with a hard output cap.
fn inflate_pdf_stream(bytes: &[u8]) -> Option<Vec<u8>> {
    inflate_with_cap(bytes, MAX_PDF_STREAM_BYTES)
}

/// Inflate a zlib stream, bounding the decoder OUTPUT at `max` bytes.
/// The `take` must wrap the decoder, not the input: bounding the input
/// lets a small compressed stream expand to GBs inside `read_to_end`
/// before the post-hoc length check ever runs.
fn inflate_with_cap(bytes: &[u8], max: u64) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(bytes).take(max.saturating_add(1));
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    if out.len() as u64 > max {
        return None; // decompression bomb — refuse
    }
    Some(out)
}

/// Extract parenthesized strings and hex strings from a PDF text object.
fn extract_pdf_strings(text_object: &str, out: &mut String) {
    let mut chars = text_object.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' => {
                // Collect until matching close paren (handle nesting)
                let mut depth = 1u32;
                let mut s = String::new();
                while let Some(nc) = chars.next() {
                    match nc {
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        '\\' => {
                            // Escape sequence — take next char literally
                            if let Some(esc) = chars.next() {
                                match esc {
                                    'n' => s.push('\n'),
                                    'r' => s.push('\r'),
                                    't' => s.push('\t'),
                                    _ => s.push(esc),
                                }
                            }
                        }
                        _ => s.push(nc),
                    }
                }
                if !s.is_empty() {
                    if !out.is_empty() {
                        out.push(' ');
                    }
                    out.push_str(&s);
                }
            }
            '<' => {
                // Hex string:<48656C6C6F> — decode hex digit pairs into text.
                // '<' also opens dictionaries, but a dictionary body never
                // consists solely of hex digits, so undecodable spans are
                // skipped harmlessly.
                let mut hex = String::new();
                let mut closed = false;
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc == '>' {
                        closed = true;
                        break;
                    }
                    if nc.is_ascii_hexdigit() {
                        hex.push(nc);
                    }
                }
                if closed && !hex.is_empty() {
                    let bytes: Vec<u8> = (0..hex.len() / 2)
                        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                        .collect();
                    let decoded = String::from_utf8_lossy(&bytes).into_owned();
                    if !decoded.is_empty() {
                        if !out.is_empty() {
                            out.push(' ');
                        }
                        out.push_str(&decoded);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Zero-dep RTF text extraction.
/// Strips RTF control words (`\keyword`) and groups, extracting the remaining
/// plain-text content.
fn extract_rtf_text(data: &[u8]) -> (String, bool, String) {
    let content = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            return (
                String::from_utf8_lossy(data).into_owned(),
                true,
                "RTF: encoding error, best-effort extraction".into(),
            );
        }
    };

    let mut text = String::new();
    let mut depth = 0i32;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '{' => depth += 1,
            '}' => depth = (depth - 1).max(0),
            '\\' => {
                // Skip control word
                let mut word = String::new();
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_alphabetic() {
                        word.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Skip optional numeric parameter
                while let Some(&nc) = chars.peek() {
                    if nc.is_ascii_digit() || nc == '-' {
                        chars.next();
                    } else {
                        break;
                    }
                }
                // Skip single trailing space
                if let Some(&' ') = chars.peek() {
                    chars.next();
                }
                // Some control words insert whitespace
                if word == "par" || word == "line" || word == "tab" {
                    text.push(' ');
                }
            }
            _ => {
                if depth <= 1 {
                    text.push(c);
                }
            }
        }
    }

    let note = format!("RTF: extracted {} chars of text", text.len());
    (text.trim().to_string(), false, note)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

impl DlpEngine {
    /// Scan an email attachment for sensitive data.
    /// This method:/// 1. Determines the attachment kind from filename + magic bytes
    /// 2. Extracts text content from the attachment
    /// 3. Runs full DLP scanning (PII, entropy, content policy) on extracted text
    /// 4. Returns an `AttachmentVerdict` with the findings and extraction metadata
    /// # Arguments
    /// * `data` - Raw attachment bytes
    /// * `filename` - Optional filename (used for kind detection)
    /// * `recipient_domain` - Optional recipient domain for allowlist checks
    pub fn scan_attachment(
        &self,
        data: &[u8],
        filename: Option<&str>,
        recipient_domain: Option<&str>,
    ) -> AttachmentVerdict {
        // Determine file kind. Container formats (PDF/OOXML/RTF) are
        // identified by MAGIC BYTES first — extension claims are trivially
        // spoofed (malicious.pdf that is really a ZIP) and magic bytes are
        // the only signal tied to the actual bytes.
        let by_magic = AttachmentKind::from_magic(data);
        let kind = match filename {
            Some(name) => {
                if matches!(
                    by_magic,
                    AttachmentKind::Pdf | AttachmentKind::Ooxml | AttachmentKind::Rtf
                ) {
                    by_magic
                } else {
                    let by_ext = AttachmentKind::from_filename(name);
                    if by_ext == AttachmentKind::Unknown {
                        by_magic
                    } else {
                        by_ext
                    }
                }
            }
            None => by_magic,
        };

        // Extract text
        let (text, partial, note) = extract_text(data, kind);
        let extracted_len = text.len();

        // Container formats whose contents we cannot fully read: PDF/OOXML/
        // RTF by kind, plus legacy OLE compound documents (.doc/.xls/.ppt)
        // which are text-bearing binaries our zero-dep extractor cannot
        // parse. For these, "no text" or "almost no text" means UNVERIFIED
        // contents, not a clean pass.
        let container_like = matches!(
            kind,
            AttachmentKind::Pdf | AttachmentKind::Ooxml | AttachmentKind::Rtf
        ) || is_ole_container(data);

        // Coverage heuristic:extracted text bytes vs attachment size. Below
        // 1 byte per MIN_TEXT_COVERAGE_PER_BYTES the extraction is treated as
        // failed even though it produced output.
        let low_coverage = !text.is_empty()
            && (extracted_len as u64).saturating_mul(MIN_TEXT_COVERAGE_PER_BYTES)
                < data.len() as u64;

        // Run DLP scan on extracted text
        let dlp_verdict = if text.is_empty() {
            if container_like {
                // Text-bearing formats that yield NO extractable text are a
                // red flag (compressed/obfuscated content our extractor cannot
                // read). Silently returning Allow here would let PII sail
                // through inside content we failed to decode — instead apply a
                // risk floor so policy (thresholds) decides the outcome.
                DlpVerdict {
                    risk_score: EXTRACTION_FAILED_RISK_FLOOR,
                    action: DlpAction::Audit,
                    pii_findings: Vec::new(),
                    entropy_findings: Vec::new(),
                    policy_matches: Vec::new(),
                    summary: format!(
                        "Attachment text extraction failed for kind={kind:?} — risk floor \
                         {EXTRACTION_FAILED_RISK_FLOOR} applied, contents unverified ({note})"
                    ),
                }
            } else {
                // Binary kinds (images etc.) legitimately have no text.
                DlpVerdict {
                    risk_score: 0.0,
                    action: DlpAction::Allow,
                    pii_findings: Vec::new(),
                    entropy_findings: Vec::new(),
                    policy_matches: Vec::new(),
                    summary: format!("No text extracted from attachment (kind={kind:?})"),
                }
            }
        } else if container_like && (low_coverage || partial) {
            // Some text came out, but it covers an implausibly small share of
            // the file or the extraction was partial. Scan what we have, then
            // raise the verdict to the unverified-contents floor — findings
            // below the floor would read as "verified clean" when most of the
            // attachment was never decoded.
            let mut verdict = self.scan(&text, recipient_domain);
            let coverage_pct = (extracted_len as f64 / data.len() as f64 * 100.0).round();
            if verdict.risk_score < EXTRACTION_FAILED_RISK_FLOOR {
                verdict.risk_score = EXTRACTION_FAILED_RISK_FLOOR;
                verdict.action = DlpAction::Audit;
            }
            verdict.summary = format!(
                "{}; extraction covers only ~{coverage_pct}% of the {}-byte attachment \
                 (partial={partial}) — risk floor {EXTRACTION_FAILED_RISK_FLOOR} applied, \
                 contents partially unverified ({note})",
                verdict.summary,
                data.len()
            );
            verdict
        } else {
            self.scan(&text, recipient_domain)
        };

        AttachmentVerdict {
            dlp_verdict,
            kind,
            extracted_text_len: extracted_len,
            partial_extraction: partial,
            extraction_note: note,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DlpConfig;

    #[test]
    fn test_kind_from_filename() {
        assert_eq!(
            AttachmentKind::from_filename("report.txt"),
            AttachmentKind::PlainText
        );
        assert_eq!(
            AttachmentKind::from_filename("data.csv"),
            AttachmentKind::PlainText
        );
        assert_eq!(
            AttachmentKind::from_filename("report.docx"),
            AttachmentKind::Ooxml
        );
        assert_eq!(
            AttachmentKind::from_filename("financials.xlsx"),
            AttachmentKind::Ooxml
        );
        assert_eq!(
            AttachmentKind::from_filename("invoice.pdf"),
            AttachmentKind::Pdf
        );
        assert_eq!(
            AttachmentKind::from_filename("letter.rtf"),
            AttachmentKind::Rtf
        );
        assert_eq!(
            AttachmentKind::from_filename("image.png"),
            AttachmentKind::Unknown
        );
        assert_eq!(
            AttachmentKind::from_filename("config.env"),
            AttachmentKind::PlainText
        );
    }

    #[test]
    fn test_kind_from_magic() {
        assert_eq!(
            AttachmentKind::from_magic(b"%PDF-1.4 some content"),
            AttachmentKind::Pdf
        );
        assert_eq!(
            AttachmentKind::from_magic(b"PK\x03\x04stuff"),
            AttachmentKind::Ooxml
        );
        assert_eq!(
            AttachmentKind::from_magic(b"{\\rtf1 content"),
            AttachmentKind::Rtf
        );
        assert_eq!(
            AttachmentKind::from_magic(b"Hello, this is plain text"),
            AttachmentKind::PlainText
        );
        assert_eq!(
            AttachmentKind::from_magic(&[0xFF, 0xD8, 0xFF, 0xE0]),
            AttachmentKind::Unknown
        );
    }

    #[test]
    fn test_plaintext_attachment_scan() {
        let engine = DlpEngine::new();
        let data = b"Employee SSN: 123-45-6789 and credit card 4111 1111 1111 1111";
        let result = engine.scan_attachment(data, Some("data.txt"), None);

        assert_eq!(result.kind, AttachmentKind::PlainText);
        assert!(!result.partial_extraction);
        assert!(result.dlp_verdict.risk_score > 0.0);
        assert!(!result.dlp_verdict.pii_findings.is_empty());
    }

    #[test]
    fn test_empty_attachment() {
        let engine = DlpEngine::new();
        let result = engine.scan_attachment(b"", Some("empty.txt"), None);

        assert_eq!(result.dlp_verdict.action, DlpAction::Allow);
        assert_eq!(result.dlp_verdict.risk_score, 0.0);
    }

    #[test]
    fn test_pdf_text_extraction() {
        // Minimal PDF-like content with text objects
        let pdf = b"%PDF-1.4\nBT\n/F1 12 Tf\n(SSN: 123-45-6789) Tj\nET";
        let (text, _partial, _note) = extract_pdf_text(pdf);
        assert!(text.contains("SSN: 123-45-6789"), "Extracted: {}", text);
    }

    #[test]
    fn test_pdf_attachment_scan() {
        let engine = DlpEngine::new();
        let pdf = b"%PDF-1.4\nBT\n(Credit card: 4111 1111 1111 1111) Tj\nET";
        let result = engine.scan_attachment(pdf, Some("invoice.pdf"), None);

        assert_eq!(result.kind, AttachmentKind::Pdf);
        assert!(
            result.dlp_verdict.risk_score > 0.0,
            "PDF with CC should score > 0"
        );
    }

    #[test]
    fn test_rtf_text_extraction() {
        let rtf = br"{\rtf1\ansi{\fonttbl\f0\fswiss Helvetica;}\f0\pard Hello world\par This is a test SSN: 123-45-6789\par}";
        let (text, partial, _note) = extract_rtf_text(rtf);
        assert!(!partial);
        assert!(text.contains("Hello world"), "Extracted: {}", text);
        assert!(text.contains("123-45-6789"), "Should contain SSN: {}", text);
    }

    #[test]
    fn test_rtf_attachment_scan() {
        let engine = DlpEngine::new();
        let rtf = br"{\rtf1 Sensitive data: SSN 123-45-6789 card 4111 1111 1111 1111}";
        let result = engine.scan_attachment(rtf, Some("letter.rtf"), None);

        assert_eq!(result.kind, AttachmentKind::Rtf);
        assert!(result.dlp_verdict.risk_score > 0.0);
    }

    #[test]
    fn test_xml_text_extraction() {
        let mut text = String::new();
        let xml = r#"<w:document><w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p><w:p><w:r><w:t>Secret data</w:t></w:r></w:p></w:body></w:document>"#;
        extract_xml_text_content(xml, &mut text);
        assert!(text.contains("Hello World"), "Extracted: {}", text);
        assert!(text.contains("Secret data"), "Extracted: {}", text);
    }

    #[test]
    fn test_ooxml_deflated_xml_extraction() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;

        let xml =
            br#"<w:document><w:body><w:t>Invoice 4111 1111 1111 1111</w:t></w:body></w:document>"#;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(xml).expect("deflate encoder accepts XML");
        let compressed = encoder.finish().expect("deflate encoder finishes");
        let filename = b"word/document.xml";

        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&[20, 0, 0, 0, 8, 0, 0, 0, 0, 0]);
        zip.extend_from_slice(&[0, 0, 0, 0]);
        zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(xml.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(filename.len() as u16).to_le_bytes());
        zip.extend_from_slice(&0u16.to_le_bytes());
        zip.extend_from_slice(filename);
        zip.extend_from_slice(&compressed);

        let (text, partial, note) = extract_ooxml_text(&zip);
        assert!(!partial, "{}", note);
        assert!(text.contains("4111 1111 1111 1111"), "{}", text);
    }

    #[test]
    fn test_unknown_binary_attachment() {
        let engine = DlpEngine::new();
        let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let result = engine.scan_attachment(&binary_data, Some("data.bin"), None);

        assert_eq!(result.kind, AttachmentKind::Unknown);
    }

    #[test]
    fn test_allowlisted_domain_attachment() {
        let config = DlpConfig {
            allowlisted_domains: vec!["internal.example.com".into()],
            ..Default::default()
        };
        let engine = DlpEngine::with_config(config);
        let data = b"SSN: 123-45-6789 CONFIDENTIAL";
        let result = engine.scan_attachment(data, Some("report.txt"), Some("internal.example.com"));

        assert_eq!(result.dlp_verdict.action, DlpAction::Allow);
        // But findings are still present for audit
        assert!(
            !result.dlp_verdict.pii_findings.is_empty()
                || !result.dlp_verdict.policy_matches.is_empty()
        );
    }

    #[test]
    fn test_env_file_detection() {
        let engine = DlpEngine::new();
        let env_content = b"DATABASE_URL=postgres://user:sk_live_4eC39HqLyjWDarjtT1zdp7dc@host/db\nAPI_KEY=very_secret_key_12345"; // nosemgrep: generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key — Stripe's public documentation example key (sk_live_4eC39HqLyjWDarjtT1zdp7dc) used as DLP detection-test corpus — the code that FINDS such keys
        let result = engine.scan_attachment(env_content, Some(".env"), None);

        assert_eq!(result.kind, AttachmentKind::PlainText);
        // Should detect high-entropy secrets
        assert!(
            result.dlp_verdict.risk_score > 0.0,
            "Should detect secrets in .env file"
        );
    }

    #[test]
    fn test_pdf_escape_sequences() {
        let pdf = b"%PDF-1.4\nBT\n(Line 1\\nLine 2\\tTabbed) Tj\nET";
        let (text, _, _) = extract_pdf_text(pdf);
        assert!(text.contains("Line 1"), "Should handle escape: {}", text);
        assert!(
            text.contains("Line 2"),
            "Should handle newline escape: {}",
            text
        );
    }

    #[test]
    fn test_multiple_pdf_text_objects() {
        let pdf = b"%PDF-1.4\nBT (First object) Tj ET\nBT (Second object) Tj ET";
        let (text, _, _) = extract_pdf_text(pdf);
        assert!(text.contains("First object"), "Got: {}", text);
        assert!(text.contains("Second object"), "Got: {}", text);
    }

    #[test]
    fn test_pdf_flate_stream_pii_detected() {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        // Build a PDF whose text object lives inside a FlateDecode stream.
        let inner = b"BT\n(Credit card: 4111 1111 1111 1111 SSN: 123-45-6789) Tj\nET";
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(inner).expect("zlib write");
        let compressed = enc.finish().expect("zlib finish");

        let mut pdf = b"%PDF-1.4\n1 0 obj\n<< /Length ".to_vec();
        pdf.extend_from_slice(compressed.len().to_string().as_bytes());
        pdf.extend_from_slice(b" /Filter /FlateDecode >>\nstream\n");
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");

        let engine = DlpEngine::new();
        let result = engine.scan_attachment(&pdf, Some("invoice.pdf"), None);
        assert_eq!(result.kind, AttachmentKind::Pdf);
        assert!(
            !result.dlp_verdict.pii_findings.is_empty(),
            "PII inside a FlateDecode stream must be detected (note: {}, text_len {})",
            result.extraction_note,
            result.extracted_text_len
        );
    }

    #[test]
    fn test_pdf_hex_string_extraction() {
        // <...> hex strings inside text objects must be decoded.
        // "SSN: 123-45-6789" hex-encoded.
        let hex = "53534e3a203132332d34352d36373839";
        let pdf = format!("%PDF-1.4\nBT\n<{hex}> Tj\nET");
        let (text, _partial, _note) = extract_pdf_text(pdf.as_bytes());
        assert!(
            text.contains("SSN: 123-45-6789"),
            "hex string must decode: got {text:?}"
        );
    }

    #[test]
    fn test_pdf_with_no_extractable_text_not_silent_allow() {
        // A PDF whose text cannot be extracted must NOT come back as a
        // clean Allow — it carries a risk floor so policy decides.
        let engine = DlpEngine::new();
        // Binary junk with a PDF magic and no text objects.
        let mut pdf = b"%PDF-1.7\n".to_vec();
        pdf.extend_from_slice(&[0x00, 0x01, 0x02, 0xFF, 0xFE, 0xA3, 0x5B]);
        let result = engine.scan_attachment(&pdf, Some("doc.pdf"), None);
        assert_eq!(result.kind, AttachmentKind::Pdf);
        assert!(
            result.dlp_verdict.risk_score >= 3.0,
            "extraction failure must apply a risk floor, got {} ({})",
            result.dlp_verdict.risk_score,
            result.dlp_verdict.summary
        );
        assert!(
            result.dlp_verdict.summary.contains("extraction failed"),
            "summary must be explicit about the failure: {}",
            result.dlp_verdict.summary
        );
        // Binary kinds (images) remain a legitimate Allow with no text.
        let img = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let result = engine.scan_attachment(&img, Some("photo.jpg"), None);
        assert_eq!(result.dlp_verdict.action, DlpAction::Allow);
    }

    /// Compress `data` with raw deflate (ZIP method 8).
    fn deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(data).expect("deflate write");
        enc.finish().expect("deflate finish")
    }

    /// Compress `data` as a zlib stream (PDF FlateDecode).
    fn zlib(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(data).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    #[test]
    fn test_zip_bomb_flagged_not_treated_as_unsupported() {
        // Fail-first: `take` bounded the COMPRESSED input, not the decoder
        // OUTPUT. With a compressed size above the cap the input was
        // truncated mid-stream, the decode failed, and a decompression
        // bomb was silently reported as "unsupported compression"
        // (Ok(None)) instead of a bomb (Err(())).
        let bomb = deflate(&vec![0u8; 8 * 1024 * 1024]); // ~8KB -> 8MB
        assert!(bomb.len() as u64 > 1024, "fixture must exceed the cap");
        let result = decode_zip_part(8, &bomb, 1024);
        assert!(
            matches!(result, Err(())),
            "bomb must be flagged as Err(()), got {:?}",
            result.map(|_| "data")
        );
    }

    #[test]
    fn test_zip_small_legit_part_passes() {
        let original = b"plain text content for the DLP scan".to_vec();
        let compressed = deflate(&original);
        let result = decode_zip_part(8, &compressed, 1024 * 1024);
        assert_eq!(result, Ok(Some(original)));
    }

    #[test]
    fn test_pdf_stream_bomb_rejected_quickly() {
        // An 8MB-expanding stream with a 20MB cap is legitimately allowed,
        // but the decode must stop at the OUTPUT cap; assert both a small
        // stream passes and a >cap stream is refused.
        let small = zlib(b"BT (hello) Tj ET".repeat(64).as_slice());
        assert!(inflate_pdf_stream(&small).is_some());
        let bomb = zlib(&vec![0u8; (MAX_PDF_STREAM_BYTES + 1024 * 1024) as usize]);
        assert!(inflate_pdf_stream(&bomb).is_none());
    }

    #[test]
    fn test_pdf_stream_examination_capped() {
        // Fail-first: stream examination was unbounded — thousands of tiny
        // streams each paid an inflate. The walk must stop at the cap and
        // bump the observable counter.
        let payload = zlib(b"BT (x) Tj ET");
        let mut pdf = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.4\n");
        for _ in 0..300 {
            pdf.extend_from_slice(b"<< /Filter /FlateDecode /Length ");
            pdf.extend_from_slice(payload.len().to_string().as_bytes());
            pdf.extend_from_slice(b" >>\nstream\n");
            pdf.extend_from_slice(&payload);
            pdf.extend_from_slice(b"\nendstream\n");
        }
        let before = PDF_STREAM_CAP_HITS.load(std::sync::atomic::Ordering::Relaxed);
        let streams = find_pdf_streams(&pdf);
        assert_eq!(
            streams.len(),
            MAX_PDF_STREAMS_EXAMINED,
            "stream walk must stop at the cap"
        );
        assert!(
            PDF_STREAM_CAP_HITS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "hitting the cap must be observable in the metric"
        );
    }

    #[test]
    fn test_kind_detection_prefers_magic_for_containers() {
        // A ZIP renamed to .pdf must be treated as OOXML (ZIP-based), not PDF.
        let engine = DlpEngine::new();
        let zip = b"PK\x03\x04fake-zip-bytes";
        let result = engine.scan_attachment(zip, Some("innocent.pdf"), None);
        assert_eq!(
            result.kind,
            AttachmentKind::Ooxml,
            "magic bytes must win over the extension for containers"
        );
    }

    // ── F1:extraction-coverage risk floor ─────────────────────────────

    #[test]
    fn test_pdf_decoy_single_char_gets_risk_floor() {
        // A PDF with ONE extractable character plus a large opaque payload
        // must not read as "verified clean" — the floor applies.
        let engine = DlpEngine::new();
        let mut pdf = b"%PDF-1.7\nBT\n(x) Tj\nET\n".to_vec();
        pdf.extend(
            [0x00, 0xAB, 0xCD, 0xEF]
                .iter()
                .cycle()
                .copied()
                .take(128 * 1024),
        );
        let result = engine.scan_attachment(&pdf, Some("doc.pdf"), None);
        assert_eq!(result.kind, AttachmentKind::Pdf);
        assert!(
            result.dlp_verdict.risk_score >= 3.0,
            "implausibly low text coverage must apply the risk floor, got {} ({})",
            result.dlp_verdict.risk_score,
            result.dlp_verdict.summary
        );
        assert!(
            result
                .dlp_verdict
                .summary
                .contains("contents partially unverified"),
            "summary must state the contents are partially unverified: {}",
            result.dlp_verdict.summary
        );
    }

    #[test]
    fn test_pdf_normal_coverage_stays_clean() {
        // Sanity:a tiny PDF whose extracted text covers a plausible share of
        // the file is scanned normally (no floor when nothing is suspicious).
        let engine = DlpEngine::new();
        let pdf = b"%PDF-1.4\nBT\n(Hello there, this is a normal document) Tj\nET";
        let result = engine.scan_attachment(pdf, Some("doc.pdf"), None);
        assert!(
            result.dlp_verdict.risk_score < 3.0,
            "well-covered PDF must not hit the floor, got {} ({})",
            result.dlp_verdict.risk_score,
            result.dlp_verdict.summary
        );
    }

    // ── F3:UTF-16/UTF-32 BOM decoding ─────────────────────────────────

    #[test]
    fn test_utf16le_credit_card_detected() {
        let engine = DlpEngine::new();
        let text = "Card number: 4111111111111111";
        let mut data = vec![0xFF, 0xFE]; // UTF-16LE BOM
        for unit in text.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let result = engine.scan_attachment(&data, Some("notes.txt"), None);
        assert_eq!(result.kind, AttachmentKind::PlainText);
        assert!(!result.partial_extraction);
        assert!(
            result
                .dlp_verdict
                .pii_findings
                .iter()
                .any(|f| f.pii_type == crate::pii::PiiType::CreditCard),
            "credit card inside UTF-16LE text must be detected (text: {:?})",
            result.extraction_note
        );
    }

    #[test]
    fn test_utf16be_and_utf32_bom_decode() {
        let text = "SSN: 123-45-6789";
        let engine = DlpEngine::new();

        // UTF-16BE
        let mut be = vec![0xFE, 0xFF];
        for unit in text.encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        let result = engine.scan_attachment(&be, Some("a.txt"), None);
        assert_eq!(result.kind, AttachmentKind::PlainText);
        assert!(!result.dlp_verdict.pii_findings.is_empty());

        // UTF-32LE
        let mut le32 = vec![0xFF, 0xFE, 0x00, 0x00];
        for c in text.chars() {
            le32.extend_from_slice(&(c as u32).to_le_bytes());
        }
        let result = engine.scan_attachment(&le32, Some("b.txt"), None);
        assert_eq!(result.kind, AttachmentKind::PlainText);
        assert!(!result.dlp_verdict.pii_findings.is_empty());
    }

    #[test]
    fn test_utf16_ssn_detected_via_extract_plaintext() {
        let text = "SSN: 123-45-6789";
        let mut data = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            data.extend_from_slice(&unit.to_le_bytes());
        }
        let (decoded, partial, note) = extract_plaintext(&data);
        assert!(!partial);
        assert!(note.contains("UTF-16LE"), "note: {note}");
        assert!(decoded.contains("123-45-6789"), "decoded: {decoded}");
    }

    // ── F3:OLE compound documents ─────────────────────────────────────

    #[test]
    fn test_ole_doc_gets_unverified_risk_floor() {
        // Legacy .doc/.xls (OLE compound files) are undecodable text-bearing
        // binaries — a clean Allow would assert we verified contents we
        // never read.
        let engine = DlpEngine::new();
        let mut doc = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        doc.extend(std::iter::repeat_n(0x41u8, 4096)); // opaque payload
        let result = engine.scan_attachment(&doc, Some("legacy.doc"), None);
        assert_eq!(result.kind, AttachmentKind::Unknown);
        assert!(result.partial_extraction);
        assert!(
            result.dlp_verdict.risk_score >= 3.0,
            "OLE container must get the unverified-contents floor, got {} ({})",
            result.dlp_verdict.risk_score,
            result.dlp_verdict.summary
        );
    }

    #[test]
    fn test_ole_magic_detected() {
        assert!(is_ole_container(&[
            0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00
        ]));
        assert!(!is_ole_container(b"%PDF-1.4"));
        assert!(!is_ole_container(&[0xFF, 0xFE, 0x00, 0x00]));
    }
}
