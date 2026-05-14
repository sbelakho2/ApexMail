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
        } else if data.is_ascii() || std::str::from_utf8(data).is_ok() {
            Self::PlainText
        } else {
            Self::Unknown
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
            // Bound the reader so the deflater cannot expand beyond the cap.
            let limited = std::io::Read::take(bytes, max_bytes.saturating_add(1));
            let mut decoder = DeflateDecoder::new(limited);
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

/// Zero-dep PDF text extraction.
/// Scans for text objects between BT (Begin Text) and ET (End Text) operators
/// and extracts string operands from Tj and TJ operators. This handles
/// the most common PDF text representation (literal strings in parentheses).
fn extract_pdf_text(data: &[u8]) -> (String, bool, String) {
    let content = String::from_utf8_lossy(data);
    let mut text = String::new();
    let mut partial = false;

    // Find text objects
    let mut remaining = content.as_ref();
    let mut text_objects = 0u32;

    while let Some(bt_pos) = remaining.find("BT") {
        let after_bt = &remaining[bt_pos + 2..];
        let et_pos = after_bt.find("ET").unwrap_or(after_bt.len());
        let text_object = &after_bt[..et_pos];

        // Extract strings from Tj/TJ operators (parenthesized strings)
        extract_pdf_strings(text_object, &mut text);
        text_objects += 1;

        remaining = &after_bt[et_pos..];
    }

    if text_objects == 0 {
        partial = true;
    }

    let note = format!("PDF: extracted text from {} text objects", text_objects);
    (text, partial, note)
}

/// Extract parenthesized strings from a PDF text object.
fn extract_pdf_strings(text_object: &str, out: &mut String) {
    let mut chars = text_object.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '(' {
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
        // Determine file kind
        let kind = match filename {
            Some(name) => {
                let by_ext = AttachmentKind::from_filename(name);
                if by_ext == AttachmentKind::Unknown {
                    AttachmentKind::from_magic(data)
                } else {
                    by_ext
                }
            }
            None => AttachmentKind::from_magic(data),
        };

        // Extract text
        let (text, partial, note) = extract_text(data, kind);
        let extracted_len = text.len();

        // Run DLP scan on extracted text
        let dlp_verdict = if text.is_empty() {
            // Nothing to scan — return clean verdict
            DlpVerdict {
                risk_score: 0.0,
                action: DlpAction::Allow,
                pii_findings: Vec::new(),
                entropy_findings: Vec::new(),
                policy_matches: Vec::new(),
                summary: format!("No text extracted from attachment (kind={:?})", kind),
            }
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
        let env_content = b"DATABASE_URL=postgres://user:sk_live_4eC39HqLyjWDarjtT1zdp7dc@host/db\nAPI_KEY=very_secret_key_12345";
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
}
