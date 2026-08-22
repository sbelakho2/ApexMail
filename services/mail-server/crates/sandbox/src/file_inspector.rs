//! File inspection — magic number detection, hash computation, content analysis
//!
//! Performs static analysis of file contents without executing anything://! - File type identification via magic bytes
//! - SHA-256 hash computation
//! - Archive detection and metadata extraction
//! - Embedded macro detection (OLE2 compound documents)
//! - Suspicious string/URL extraction

use sha2::{Digest, Sha256};
use std::fmt;

/// Detected file type from magic bytes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// PDF document
    Pdf,
    /// ZIP archive (also DOCX, XLSX, PPTX, JAR, APK)
    Zip,
    /// GZIP archive
    Gzip,
    /// RAR archive
    Rar,
    /// 7-Zip archive
    SevenZip,
    /// OLE2 compound (DOC, XLS, PPT with macros)
    Ole2,
    /// Windows PE executable (EXE/DLL)
    PeExe,
    /// ELF executable (Linux)
    Elf,
    /// Mach-O executable (macOS)
    MachO,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// GIF image
    Gif,
    /// HTML document
    Html,
    /// XML document
    Xml,
    /// RTF document
    Rtf,
    /// Plain text
    PlainText,
    /// Unknown binary
    Unknown,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Pdf => write!(f, "PDF"),
            FileType::Zip => write!(f, "ZIP"),
            FileType::Gzip => write!(f, "GZIP"),
            FileType::Rar => write!(f, "RAR"),
            FileType::SevenZip => write!(f, "7Z"),
            FileType::Ole2 => write!(f, "OLE2"),
            FileType::PeExe => write!(f, "PE/EXE"),
            FileType::Elf => write!(f, "ELF"),
            FileType::MachO => write!(f, "Mach-O"),
            FileType::Jpeg => write!(f, "JPEG"),
            FileType::Png => write!(f, "PNG"),
            FileType::Gif => write!(f, "GIF"),
            FileType::Html => write!(f, "HTML"),
            FileType::Xml => write!(f, "XML"),
            FileType::Rtf => write!(f, "RTF"),
            FileType::PlainText => write!(f, "TEXT"),
            FileType::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Result of file inspection
#[derive(Debug, Clone)]
pub struct FileInspection {
    /// Detected file type
    pub file_type: FileType,
    /// SHA-256 hash (hex string)
    pub sha256: String,
    /// File size in bytes
    pub size: u64,
    /// File extension (from filename, if provided)
    pub extension: Option<String>,
    /// Whether the extension matches the detected type
    pub extension_mismatch: bool,
    /// Findings from content inspection
    pub findings: Vec<InspectionFinding>,
    /// Risk score from static analysis
    pub risk_score: f64,
}

/// A finding from file inspection
#[derive(Debug, Clone)]
pub struct InspectionFinding {
    /// Finding identifier
    pub id: &'static str,
    /// Description
    pub description: String,
    /// Risk contribution
    pub risk: f64,
}

/// Detect file type from magic bytes
pub fn detect_file_type(data: &[u8]) -> FileType {
    if data.len() < 4 {
        return if data.iter().all(|b| b.is_ascii()) {
            FileType::PlainText
        } else {
            FileType::Unknown
        };
    }

    // Check magic bytes
    match &data[..4] {
        // PDF:%PDF
        [0x25, 0x50, 0x44, 0x46] => FileType::Pdf,
        // ZIP (also OOXML:docx, xlsx, pptx, jar)
        [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] | [0x50, 0x4B, 0x07, 0x08] => {
            FileType::Zip
        }
        // GZIP
        [0x1F, 0x8B, ..] => FileType::Gzip,
        // RAR
        [0x52, 0x61, 0x72, 0x21] => FileType::Rar,
        // 7Z
        [0x37, 0x7A, 0xBC, 0xAF] => FileType::SevenZip,
        // OLE2 Compound Document (DOC/XLS/PPT)
        [0xD0, 0xCF, 0x11, 0xE0] => FileType::Ole2,
        // PE executable (MZ header)
        [0x4D, 0x5A, ..] => FileType::PeExe,
        // ELF
        [0x7F, 0x45, 0x4C, 0x46] => FileType::Elf,
        // Mach-O (multiple magic values)
        [0xFE, 0xED, 0xFA, 0xCE]
        | [0xFE, 0xED, 0xFA, 0xCF]
        | [0xCE, 0xFA, 0xED, 0xFE]
        | [0xCF, 0xFA, 0xED, 0xFE] => FileType::MachO,
        // JPEG
        [0xFF, 0xD8, 0xFF, ..] => FileType::Jpeg,
        // GIF
        [0x47, 0x49, 0x46, 0x38] => FileType::Gif,
        _ => {
            // PNG (8-byte signature)
            if data.len() >= 8 && data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
                return FileType::Png;
            }
            // RTF
            if data.len() >= 5 && &data[..5] == b"{\\rtf" {
                return FileType::Rtf;
            }
            // HTML (heuristic)
            if let Ok(text) = std::str::from_utf8(&data[..data.len().min(512)]) {
                let lower = text.to_lowercase();
                if lower.contains("<!doctype html") || lower.contains("<html") {
                    return FileType::Html;
                }
                if lower.starts_with("<?xml") || lower.starts_with("<") {
                    return FileType::Xml;
                }
            }
            // ASCII text heuristic
            let sample = &data[..data.len().min(8192)];
            if sample
                .iter()
                .all(|b| b.is_ascii() || *b == 0x0A || *b == 0x0D)
            {
                FileType::PlainText
            } else {
                FileType::Unknown
            }
        }
    }
}

/// Scan for secondary magic signatures at non-zero offsets (polyglot detection).
/// A polyglot file is valid as type A from offset 0 but also contains a type B
/// magic at a later offset. Attackers use this to bypass type-based filters
/// (e.g., a file that identifies as PDF but contains an embedded ZIP with malware).
/// Returns a vec of secondary file types found at non-zero offsets.
pub fn detect_polyglot_signatures(data: &[u8]) -> Vec<(FileType, usize)> {
    let mut secondary = Vec::with_capacity(6);
    if data.len() < 8 {
        return secondary;
    }
    let primary = detect_file_type(data);
    // Only scan a reasonable prefix (first 64KB) to avoid DOS on huge files
    let scan_limit = data.len().min(65536);

    // Signatures to look for at non-zero offsets.
    // NOTE:"MZ" (PE) is deliberately NOT in this list:a 2-byte magic
    // occurring anywhere in the first 64 KB of a text/document file is a
    // massive false-positive source. PE executables are instead detected
    // via `detect_file_type`, which requires the MZ magic at offset 0.
    let signatures: &[(&[u8], FileType)] = &[
        (b"\x50\x4B\x03\x04", FileType::Zip),
        (b"\xD0\xCF\x11\xE0", FileType::Ole2),
        (b"\x7F\x45\x4C\x46", FileType::Elf),
        (b"%PDF", FileType::Pdf),
        (b"\x52\x61\x72\x21", FileType::Rar),
    ];

    for &(magic, file_type) in signatures {
        if file_type == primary {
            continue; // Skip the primary type
        }
        // Search from offset 1 onward
        for offset in 1..scan_limit.saturating_sub(magic.len()) {
            if data[offset..].starts_with(magic) {
                secondary.push((file_type, offset));
                break; // One match per type is sufficient
            }
        }
    }

    secondary
}

/// Compute SHA-256 hash of data
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Extract the effective file extension from a filename.
///
/// Windows (and some mail clients) strip trailing dots and spaces from
/// filenames, so `payload.exe.` and `payload.exe ` must be treated as `.exe`.
/// Names without a dot (`Makefile`) have no extension at all, and a filename
/// ending in a bare dot must not yield an empty-string extension.
pub fn extract_extension(filename: &str) -> Option<String> {
    // Trailing dots/spaces/NULs are dropped when the file is written on the
    // most common target platform — the *effective* name is what matters.
    let cleaned = filename.trim_end_matches(['.', ' ', '\u{0}']);
    // Only the final path component carries the extension.
    let last_component = cleaned.rsplit(['/', '\\']).next().unwrap_or(cleaned);
    let dot = last_component.rfind('.')?;
    let ext = &last_component[dot + 1..];
    if ext.is_empty() {
        return None;
    }
    Some(ext.to_lowercase())
}

/// Inspect a file's contents for risk indicators
pub fn inspect_file(data: &[u8], filename: Option<&str>) -> FileInspection {
    let file_type = detect_file_type(data);
    let sha256 = compute_sha256(data);
    let size = data.len() as u64;
    let mut findings = Vec::with_capacity(16);
    let mut risk_score = 0.0;

    // Extract extension (trailing-dot/space and no-extension safe)
    let extension = filename.and_then(extract_extension);

    // Check extension mismatch
    let extension_mismatch = if let Some(ref ext) = extension {
        let expected = match file_type {
            FileType::Pdf => Some(vec!["pdf"]),
            FileType::Zip => Some(vec![
                "zip", "docx", "xlsx", "pptx", "jar", "apk", "ods", "odt", "docm", "dotm", "xlsm",
                "xltm", "xlsb", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm",
            ]),
            FileType::Gzip => Some(vec!["gz", "tgz"]),
            FileType::Rar => Some(vec!["rar"]),
            FileType::PeExe => Some(vec!["exe", "dll", "scr", "com"]),
            FileType::Jpeg => Some(vec!["jpg", "jpeg"]),
            FileType::Png => Some(vec!["png"]),
            FileType::Gif => Some(vec!["gif"]),
            FileType::Html => Some(vec!["html", "htm"]),
            _ => None,
        };
        if let Some(valid_exts) = expected {
            let mismatch = !valid_exts.contains(&ext.as_str());
            if mismatch {
                findings.push(InspectionFinding {
                    id: "EXT_MISMATCH",
                    description: format!(
                        "Extension .{} doesn't match detected type {}",
                        ext, file_type
                    ),
                    risk: 4.0,
                });
                risk_score += 4.0;
            }
            mismatch
        } else {
            false
        }
    } else {
        false
    };

    // Check for executable types
    match file_type {
        FileType::PeExe => {
            findings.push(InspectionFinding {
                id: "EXECUTABLE_PE",
                description: "Windows PE executable detected".into(),
                risk: 8.0,
            });
            risk_score += 8.0;
        }
        FileType::Elf => {
            findings.push(InspectionFinding {
                id: "EXECUTABLE_ELF",
                description: "Linux ELF executable detected".into(),
                risk: 8.0,
            });
            risk_score += 8.0;
        }
        FileType::MachO => {
            findings.push(InspectionFinding {
                id: "EXECUTABLE_MACHO",
                description: "macOS Mach-O executable detected".into(),
                risk: 8.0,
            });
            risk_score += 8.0;
        }
        _ => {}
    }

    // Polyglot detection:scan for secondary magic signatures at non-zero offsets
    let polyglot_sigs = detect_polyglot_signatures(data);
    if !polyglot_sigs.is_empty() {
        let types_desc: Vec<String> = polyglot_sigs
            .iter()
            .map(|(ft, off)| format!("{} at offset {}", ft, off))
            .collect();
        findings.push(InspectionFinding {
            id: "POLYGLOT_DETECTED",
            description: format!(
                "Polyglot file: primary type {} but also contains: {}",
                file_type,
                types_desc.join(", ")
            ),
            risk: 7.0,
        });
        risk_score += 7.0;
    }

    // OLE2:Check for VBA macro indicators
    if file_type == FileType::Ole2 && has_vba_indicators(data) {
        findings.push(InspectionFinding {
            id: "OLE2_VBA_MACROS",
            description: "OLE2 document contains VBA macro indicators".into(),
            risk: 6.0,
        });
        risk_score += 6.0;
    }

    // ZIP-based OOXML:Check for macro-enabled formats
    if file_type == FileType::Zip {
        if let Some(ref ext) = extension {
            let macro_exts = [
                "docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppam", "ppsm",
                "sldm",
            ];
            if macro_exts.contains(&ext.as_str()) {
                findings.push(InspectionFinding {
                    id: "OOXML_MACRO",
                    description: format!("Macro-enabled Office format: .{}", ext),
                    risk: 5.0,
                });
                risk_score += 5.0;
            }
        }
        // Check for vbaProject.bin inside ZIP
        if has_zip_vba_project(data) {
            findings.push(InspectionFinding {
                id: "OOXML_VBA_BIN",
                description: "vbaProject.bin or VBA/ActiveX content found in Office document"
                    .into(),
                risk: 6.0,
            });
            risk_score += 6.0;
        }

        // Check for external OLE links (remote payload injection).
        // Risk lowered from 5.0 → 2.0:external *images* are common in
        // legitimate DOCX files and 5.0 alone pushed clean documents into
        // quarantine. 2.0 keeps the signal visible below the
        // suspicious/quarantine threshold while still accumulating.
        if has_external_ole_links(data) {
            findings.push(InspectionFinding {
                id: "OOXML_EXTERNAL_OLE",
                description: "External OLE/relationship links detected (potential remote payload)"
                    .into(),
                risk: 2.0,
            });
            risk_score += 2.0;
        }

        // Check for encrypted/password-protected ZIP
        if is_zip_encrypted(data) {
            findings.push(InspectionFinding {
                id: "ARCHIVE_ENCRYPTED",
                description: "ZIP archive is password-protected (contents cannot be inspected)"
                    .into(),
                risk: 7.0,
            });
            risk_score += 7.0;
        }
    }

    // RAR:Check for encryption
    if file_type == FileType::Rar && is_rar_encrypted(data) {
        findings.push(InspectionFinding {
            id: "ARCHIVE_ENCRYPTED",
            description: "RAR archive is password-protected (contents cannot be inspected)".into(),
            risk: 7.0,
        });
        risk_score += 7.0;
    }

    // 7-Zip:Check for encryption
    if file_type == FileType::SevenZip && is_7z_encrypted(data) {
        findings.push(InspectionFinding {
            id: "ARCHIVE_ENCRYPTED",
            description: "7-Zip archive is encrypted (contents cannot be inspected)".into(),
            risk: 7.0,
        });
        risk_score += 7.0;
    }

    // PDF:Check for suspicious elements
    if file_type == FileType::Pdf {
        let pdf_findings = inspect_pdf(data);
        for f in &pdf_findings {
            risk_score += f.risk;
        }
        findings.extend(pdf_findings);
    }

    // HTML:Check for script content
    if file_type == FileType::Html {
        if let Ok(text) = std::str::from_utf8(data) {
            let lower = text.to_lowercase();
            if lower.contains("<script") {
                findings.push(InspectionFinding {
                    id: "HTML_SCRIPT",
                    description: "HTML attachment contains script tags".into(),
                    risk: 4.0,
                });
                risk_score += 4.0;
            }
            if lower.contains("javascript:") {
                findings.push(InspectionFinding {
                    id: "HTML_JS_URI",
                    description: "HTML attachment contains javascript: URIs".into(),
                    risk: 4.0,
                });
                risk_score += 4.0;
            }
        }
    }

    // SVG / XML:Check for embedded scripts (SVG is a common XSS delivery vector)
    if file_type == FileType::Xml {
        if let Ok(text) = std::str::from_utf8(data) {
            let lower = text.to_lowercase();
            // Detect SVG documents
            let is_svg =
                lower.contains("<svg") || lower.contains("xmlns=\"http://www.w3.org/2000/svg\"");
            if is_svg {
                if lower.contains("<script") {
                    findings.push(InspectionFinding {
                        id: "SVG_SCRIPT",
                        description: "SVG image contains embedded <script> element (XSS risk)"
                            .into(),
                        risk: 6.0,
                    });
                    risk_score += 6.0;
                }
                // Check for event handler attributes commonly abused in SVG
                for attr in &["onload=", "onerror=", "onclick=", "onmouseover="] {
                    if lower.contains(attr) {
                        findings.push(InspectionFinding {
                            id: "SVG_EVENT_HANDLER",
                            description: format!("SVG contains event handler: {}", attr),
                            risk: 5.0,
                        });
                        risk_score += 5.0;
                        break; // One finding per SVG is sufficient
                    }
                }
                // javascript:URI in SVG href/src
                if lower.contains("javascript:") {
                    findings.push(InspectionFinding {
                        id: "SVG_JS_URI",
                        description: "SVG contains javascript: URI".into(),
                        risk: 6.0,
                    });
                    risk_score += 6.0;
                }
            }
        }
    }

    if is_mhtml_attachment(data, extension.as_deref()) {
        findings.push(InspectionFinding {
            id: "MHTML_ATTACHMENT",
            description: "MHTML web archive attachment can embed active web content".into(),
            risk: 5.0,
        });
        risk_score += 5.0;
    }

    // Dangerous extension check (regardless of content)
    if let Some(ref ext) = extension {
        let blocked = [
            "exe", "dll", "scr", "bat", "cmd", "com", "pif", "hta", "cpl", "msi", "ps1", "vbs",
            "vbe", "wsf",
        ];
        if blocked.contains(&ext.as_str()) {
            findings.push(InspectionFinding {
                id: "BLOCKED_EXTENSION",
                description: format!("Blocked file extension: .{}", ext),
                risk: 10.0,
            });
            risk_score += 10.0;
        }
    }

    // Double extension (e.g., "report.pdf.exe")
    if let Some(name) = filename {
        let parts: Vec<&str> = name.split('.').collect();
        if parts.len() >= 3 {
            let dangerous_inner = ["pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"];
            let dangerous_outer = ["exe", "scr", "bat", "cmd", "com", "pif", "js", "vbs"];
            if parts.len() >= 3 {
                let second_to_last = parts[parts.len() - 2].to_lowercase();
                let last = parts[parts.len() - 1].to_lowercase();
                if dangerous_inner.contains(&second_to_last.as_str())
                    && dangerous_outer.contains(&last.as_str())
                {
                    findings.push(InspectionFinding {
                        id: "DOUBLE_EXTENSION",
                        description: format!("Double extension: .{}.{}", second_to_last, last),
                        risk: 8.0,
                    });
                    risk_score += 8.0;
                }
            }
        }
    }

    FileInspection {
        file_type,
        sha256,
        size,
        extension,
        extension_mismatch,
        findings,
        risk_score,
    }
}

/// Check for VBA indicators in OLE2 data (heuristic)
fn has_vba_indicators(data: &[u8]) -> bool {
    // Look for "VBA" and "Attribute VB_" strings
    let vba_signatures: &[&[u8]] = &[
        b"Attribute VB_",
        b"VBAProject",
        b"_VBA_PROJECT",
        b"ThisDocument",
        b"Auto_Open",
        b"AutoOpen",
        b"Auto_Close",
        b"Document_Open",
        b"Workbook_Open",
    ];

    for sig in vba_signatures {
        if data.windows(sig.len()).any(|w| w == *sig) {
            return true;
        }
    }
    false
}

/// Check for vbaProject.bin and other VBA/ActiveX indicators inside a ZIP file (OOXML)
fn has_zip_vba_project(data: &[u8]) -> bool {
    // Look for any of these indicators in the ZIP contents
    const VBA_INDICATORS: &[&[u8]] = &[
        b"vbaProject.bin",          // Main VBA project binary
        b"vbaProjectSignature.bin", // VBA project signature
        b"xl/vbaProject",           // Excel VBA project path
        b"word/vbaProject",         // Word VBA project path
        b"ppt/vbaProject",          // PowerPoint VBA project path
        b"VBA/",                    // VBA directory
        b"_VBA_PROJECT_CUR",        // VBA stream marker
        b"activeX",                 // ActiveX controls (can execute code)
        b"oleObject",               // OLE objects (can embed executables)
        b"embeddedHtml",            // Embedded HTML (can contain scripts)
    ];

    for indicator in VBA_INDICATORS {
        if data
            .windows(indicator.len())
            .any(|w| w.eq_ignore_ascii_case(indicator))
        {
            return true;
        }
    }

    false
}

fn is_mhtml_attachment(data: &[u8], extension: Option<&str>) -> bool {
    let has_mhtml_extension = matches!(extension, Some("mht" | "mhtml"));
    let sample = String::from_utf8_lossy(&data[..data.len().min(4096)]).to_lowercase();
    let has_mhtml_markers = sample.contains("mime-version:")
        && (sample.contains("multipart/related")
            || sample.contains("content-location:")
            || sample.contains("content-type: text/html"));

    has_mhtml_extension || has_mhtml_markers
}

/// Check for external OLE links in OOXML that may pull remote payloads
pub fn has_external_ole_links(data: &[u8]) -> bool {
    // Look for relationship targets pointing to external resources
    const EXTERNAL_INDICATORS: &[&[u8]] = &[
        b"Target=\"http",           // External HTTP link
        b"Target=\"https",          // External HTTPS link
        b"TargetMode=\"External\"", // Explicit external target mode
        b"oleLink",                 // OLE link reference
        b"mso-application:",        // MS Office application directive
    ];

    for indicator in EXTERNAL_INDICATORS {
        if data
            .windows(indicator.len())
            .any(|w| w.eq_ignore_ascii_case(indicator))
        {
            return true;
        }
    }

    false
}

/// Check if a ZIP file is password-protected/encrypted.
/// ZIP encryption is indicated by the general purpose bit flag (bit 0).
/// ZIP local file header structure:/// - 0-3:Local file header signature (0x04034b50)
/// - 4-5:Version needed to extract
/// - 6-7:General purpose bit flag (bit 0 = encrypted)
/// - 8-9:Compression method
/// ...
/// This function checks multiple local file headers in case some files
/// are encrypted and others are not.
pub fn is_zip_encrypted(data: &[u8]) -> bool {
    // ZIP local file header signature:PK\x03\x04
    const LOCAL_HEADER_SIG: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

    // Minimum header size before the bit flag
    if data.len() < 10 {
        return false;
    }

    let mut offset = 0;
    while offset + 30 < data.len() {
        // Find the next local file header
        if data[offset..offset + 4] == LOCAL_HEADER_SIG {
            // General purpose bit flag is at offset 6-7 from the header start
            let flags = u16::from_le_bytes([data[offset + 6], data[offset + 7]]);

            // Bit 0 = file is encrypted
            if flags & 0x0001 != 0 {
                return true;
            }

            // Bit 3 = data descriptor present (used with encryption)
            // Bit 6 = strong encryption
            if flags & 0x0040 != 0 {
                return true;
            }

            // Move to next header (need to parse more to be accurate, but we'll
            // just scan forward to find the next signature for simplicity)
            offset += 30;
        } else {
            offset += 1;
        }
    }

    // Fall back to the central directory (authoritative):locate the End Of
    // Central Directory record and check each entry's general-purpose flags.
    // The previous heuristic flagged ANY occurrence of the two bytes
    // 0x99 0x01 anywhere in the file (e.g. inside file contents), producing
    // false "encrypted archive" verdicts on ordinary files.
    zip_central_directory_encrypted(data)
}

/// Walk the ZIP central directory and report whether any entry has the
/// "encrypted" general-purpose flag (bit 0) or strong-encryption flag
/// (bit 6) set. AES-encrypted entries created by WinZip set these flags and
/// carry an AES extra field (0x9901) *inside a central-directory header*, so
/// checking flags here is both stricter and more accurate than scanning for
/// the raw 0x99 0x01 byte pair anywhere in the file.
fn zip_central_directory_encrypted(data: &[u8]) -> bool {
    const EOCD_SIG: [u8; 4] = [0x50, 0x4B, 0x05, 0x06];
    const CDFH_SIG: [u8; 4] = [0x50, 0x4B, 0x01, 0x02];

    // Locate the End Of Central Directory record (search backwards; the
    // classic EOCD is 22 bytes plus an optional comment of up to 65535).
    let tail_start = data.len().saturating_sub(22 + 65_535);
    let mut eocd = None;
    if data.len() >= 22 {
        let mut i = data.len() - 22;
        loop {
            if data[i..].starts_with(&EOCD_SIG) {
                eocd = Some(i);
                break;
            }
            if i == tail_start || i == 0 {
                break;
            }
            i -= 1;
        }
    }
    let Some(eocd) = eocd else {
        return false;
    };
    if eocd + 22 > data.len() {
        return false;
    }

    let entry_count = u16::from_le_bytes([data[eocd + 10], data[eocd + 11]]);
    let cd_offset = u32::from_le_bytes([
        data[eocd + 16],
        data[eocd + 17],
        data[eocd + 18],
        data[eocd + 19],
    ]) as usize;

    // Walk `entry_count` central-directory file headers.
    let mut offset = cd_offset;
    for _ in 0..entry_count {
        if offset + 46 > data.len() || !data[offset..].starts_with(&CDFH_SIG) {
            break; // malformed or truncated — not evidence of encryption
        }
        let flags = u16::from_le_bytes([data[offset + 8], data[offset + 9]]);
        if flags & 0x0001 != 0 || flags & 0x0040 != 0 {
            return true;
        }
        let name_len = u16::from_le_bytes([data[offset + 28], data[offset + 29]]) as usize;
        let extra_len = u16::from_le_bytes([data[offset + 30], data[offset + 31]]) as usize;
        let comment_len = u16::from_le_bytes([data[offset + 32], data[offset + 33]]) as usize;
        offset += 46 + name_len + extra_len + comment_len;
    }

    false
}

/// Check if a RAR file is password-protected.
/// RAR encryption is indicated in the file header flags.
pub fn is_rar_encrypted(data: &[u8]) -> bool {
    // RAR signature:Rar!\x1a\x07\x00 (RAR 4.x) or Rar!\x1a\x07\x01\x00 (RAR 5.x)
    if data.len() < 14 {
        return false;
    }

    // Check for RAR5 encrypted archive flag (byte 11, bit 0x0004)
    if data.len() > 12 {
        // RAR5:Archive header at offset 7 has flags
        // Check for common encryption indicators
        // RAR5 uses different structure, but commonly has encryption flag
        if data[0..4] == [0x52, 0x61, 0x72, 0x21] {
            // "Rar!"
            // Look for HEAD_CRYPT header type or encryption flag
            // This is simplified - full parsing would be more complex
            for i in 7..data.len().min(200) {
                // HEAD_TYPE = 4 for encryption header
                if data[i] == 0x04 && i + 3 < data.len() {
                    return true;
                }
            }
        }
    }

    // RAR4:Check for encrypted header flag (bit 2 in archive header flags)
    // Archive header is typically at offset 7
    if data.len() > 12 && data[9] & 0x04 != 0 {
        return true;
    }

    false
}

/// Check if a 7-Zip file appears to be encrypted.
/// 7z format is complex, but we can detect encryption by looking for
/// specific codec IDs in the header.
pub fn is_7z_encrypted(data: &[u8]) -> bool {
    // 7z signature:7z\xBC\xAF\x27\x1C
    if data.len() < 32 || data[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return false;
    }

    // Look for AES encryption codec ID in the stream
    // 7z stores encryption method as a codec:0x06F10701 (AES-256)
    // In the 7z format, this appears as bytes:06 F1 07 01
    let aes_marker = [0x06, 0xF1, 0x07, 0x01];
    data.windows(4).any(|w| w == aes_marker)
}

/// Archived file encryption status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveEncryption {
    /// Archive is not encrypted
    NotEncrypted,
    /// Archive files are encrypted
    FilesEncrypted,
    /// Archive header is encrypted (filename hidden)
    HeaderEncrypted,
    /// Could not determine
    Unknown,
}

/// Check encryption status of an archive file
pub fn check_archive_encryption(data: &[u8], file_type: FileType) -> ArchiveEncryption {
    match file_type {
        FileType::Zip => {
            if is_zip_encrypted(data) {
                ArchiveEncryption::FilesEncrypted
            } else {
                ArchiveEncryption::NotEncrypted
            }
        }
        FileType::Rar => {
            if is_rar_encrypted(data) {
                ArchiveEncryption::FilesEncrypted
            } else {
                ArchiveEncryption::NotEncrypted
            }
        }
        FileType::SevenZip => {
            if is_7z_encrypted(data) {
                ArchiveEncryption::FilesEncrypted
            } else {
                ArchiveEncryption::NotEncrypted
            }
        }
        _ => ArchiveEncryption::Unknown,
    }
}

/// Inspect PDF for suspicious elements
fn inspect_pdf(data: &[u8]) -> Vec<InspectionFinding> {
    let mut findings = Vec::new();

    // Convert to string for pattern matching (PDF is mostly ASCII)
    let text = String::from_utf8_lossy(data);

    // JavaScript in PDF
    if text.contains("/JavaScript") || text.contains("/JS ") {
        findings.push(InspectionFinding {
            id: "PDF_JAVASCRIPT",
            description: "PDF contains JavaScript".into(),
            risk: 5.0,
        });
    }

    // OpenAction (auto-execute on open)
    if text.contains("/OpenAction") {
        findings.push(InspectionFinding {
            id: "PDF_OPENACTION",
            description: "PDF has OpenAction (auto-executes on open)".into(),
            risk: 4.0,
        });
    }

    // Launch action (execute external program)
    if text.contains("/Launch") {
        findings.push(InspectionFinding {
            id: "PDF_LAUNCH",
            description: "PDF has Launch action (can execute programs)".into(),
            risk: 7.0,
        });
    }

    // Embedded file
    if text.contains("/EmbeddedFile") {
        findings.push(InspectionFinding {
            id: "PDF_EMBEDDED_FILE",
            description: "PDF contains embedded files".into(),
            risk: 3.0,
        });
    }

    // URI action
    if text.contains("/URI") {
        findings.push(InspectionFinding {
            id: "PDF_URI",
            description: "PDF contains URI actions".into(),
            risk: 1.0,
        });
    }

    // Encrypted/obfuscated streams
    if text.contains("/Encrypt") {
        findings.push(InspectionFinding {
            id: "PDF_ENCRYPTED",
            description: "PDF uses encryption".into(),
            risk: 2.0,
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal (store-method) ZIP with one entry and controlled
    /// general-purpose flags for the local header and central directory.
    fn make_test_zip(local_flags: u16, central_flags: u16, content: &[u8]) -> Vec<u8> {
        let name = b"file.txt";
        let mut out = Vec::new();
        // Local file header (30 bytes + name)
        out.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&local_flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // method:store
        out.extend_from_slice(&0u16.to_le_bytes()); // mod time
        out.extend_from_slice(&0u16.to_le_bytes()); // mod date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // comp size
        out.extend_from_slice(&(content.len() as u32).to_le_bytes()); // uncomp size
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(content);
        let cd_offset = out.len() as u32;
        // Central directory file header (46 bytes + name)
        out.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&central_flags.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // method
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc32
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&cd_offset.to_le_bytes()); // local header offset
        out.extend_from_slice(name);
        let cd_size = out.len() as u32 - cd_offset;
        // End of central directory (22 bytes)
        out.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
        out.extend_from_slice(&1u16.to_le_bytes()); // entries this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // total entries
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out
    }

    #[test]
    fn test_detect_pdf() {
        let data = b"%PDF-1.4 test document";
        assert_eq!(detect_file_type(data), FileType::Pdf);
    }

    #[test]
    fn test_detect_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        assert_eq!(detect_file_type(&data), FileType::Zip);
    }

    #[test]
    fn test_detect_pe() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
        assert_eq!(detect_file_type(&data), FileType::PeExe);
    }

    #[test]
    fn test_detect_elf() {
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01];
        assert_eq!(detect_file_type(&data), FileType::Elf);
    }

    #[test]
    fn test_detect_ole2() {
        let data = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert_eq!(detect_file_type(&data), FileType::Ole2);
    }

    #[test]
    fn test_detect_plain_text() {
        let data = b"Hello, this is a plain text file\n";
        assert_eq!(detect_file_type(data), FileType::PlainText);
    }

    #[test]
    fn test_detect_html() {
        let data = b"<!DOCTYPE html><html><body>test</body></html>";
        assert_eq!(detect_file_type(data), FileType::Html);
    }

    #[test]
    fn test_sha256() {
        let hash = compute_sha256(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_inspect_executable() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let result = inspect_file(&data, Some("payload.exe"));
        assert!(result.findings.iter().any(|f| f.id == "EXECUTABLE_PE"));
        assert!(result.findings.iter().any(|f| f.id == "BLOCKED_EXTENSION"));
        assert!(result.risk_score >= 10.0);
    }

    #[test]
    fn test_double_extension() {
        let data = b"Just some text content";
        let result = inspect_file(data, Some("invoice.pdf.exe"));
        assert!(result.findings.iter().any(|f| f.id == "DOUBLE_EXTENSION"));
    }

    #[test]
    fn test_extension_mismatch() {
        // PE magic but .pdf extension
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let result = inspect_file(&data, Some("document.pdf"));
        assert!(result.extension_mismatch);
        assert!(result.findings.iter().any(|f| f.id == "EXT_MISMATCH"));
    }

    #[test]
    fn test_clean_pdf() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let result = inspect_file(data, Some("report.pdf"));
        assert_eq!(result.file_type, FileType::Pdf);
        assert!(!result.extension_mismatch);
        // Simple PDF without JS/Launch should have low risk
        assert!(
            result.risk_score < 5.0,
            "Clean PDF risk: {}",
            result.risk_score
        );
    }

    #[test]
    fn test_malicious_pdf() {
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\n/OpenAction /Launch";
        let result = inspect_file(data, Some("invoice.pdf"));
        assert!(result.findings.iter().any(|f| f.id == "PDF_JAVASCRIPT"));
        assert!(result.findings.iter().any(|f| f.id == "PDF_OPENACTION"));
        assert!(result.findings.iter().any(|f| f.id == "PDF_LAUNCH"));
    }

    #[test]
    fn test_vba_indicators() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(b"\x00\x00\x00Attribute VB_Name\x00\x00");
        let result = inspect_file(&data, Some("macro.doc"));
        assert!(result.findings.iter().any(|f| f.id == "OLE2_VBA_MACROS"));
    }

    #[test]
    fn test_ooxml_xl_vba_project_indicator() {
        let mut data = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
        data.extend_from_slice(b"xl/vbaProject.bin");

        let result = inspect_file(&data, Some("workbook.xlsx"));

        assert!(result.findings.iter().any(|f| f.id == "OOXML_VBA_BIN"));
    }

    #[test]
    fn test_macro_enabled_xlsb_and_xlam_extensions() {
        for filename in ["workbook.xlsb", "addin.xlam"] {
            let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00];
            let result = inspect_file(&data, Some(filename));

            assert!(
                result.findings.iter().any(|f| f.id == "OOXML_MACRO"),
                "expected OOXML_MACRO finding for {filename}: {:?}",
                result.findings
            );
            assert!(
                !result.extension_mismatch,
                "macro-enabled ZIP extension should still match ZIP container for {filename}"
            );
        }
    }

    #[test]
    fn test_mhtml_attachment_flagged() {
        let data = b"MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=x\r\nContent-Location: file:///invoice.htm\r\n\r\n<html><script>alert(1)</script>";
        let result = inspect_file(data, Some("invoice.mht"));

        assert!(result.findings.iter().any(|f| f.id == "MHTML_ATTACHMENT"));
        assert!(result.risk_score >= 5.0);
    }

    #[test]
    fn test_polyglot_pdf_zip() {
        // A PDF file with an embedded ZIP signature at offset 32
        let mut data = b"%PDF-1.4\n1 0 obj\n<< /Type >>\n".to_vec();
        // Pad to offset 32
        while data.len() < 32 {
            data.push(b' ');
        }
        // Embed a ZIP signature
        data.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);
        data.extend_from_slice(b"\nendobj\n");

        let result = inspect_file(&data, Some("invoice.pdf"));
        assert_eq!(result.file_type, FileType::Pdf);
        assert!(
            result.findings.iter().any(|f| f.id == "POLYGLOT_DETECTED"),
            "Should detect polyglot PDF+ZIP: {:?}",
            result.findings
        );
    }

    #[test]
    fn test_polyglot_detection_no_false_positive() {
        // A normal PDF without embedded signatures should NOT trigger polyglot
        let data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let sigs = detect_polyglot_signatures(data);
        assert!(
            sigs.is_empty(),
            "Clean PDF should not trigger polyglot: {:?}",
            sigs
        );
    }

    #[test]
    fn test_encrypted_archive_uninspectable_risk() {
        // ZIP local file header:signature (4) + version needed (2) + bit flag (2) + ...
        // Initialize with enough bytes so indices 6 and 7 exist.
        let mut data = vec![
            0x50, 0x4B, 0x03, 0x04, // ZIP signature
            0x14, 0x00, // version needed
            0x00, 0x00, // general purpose bit flag (will patch below)
        ];
        // Set general purpose bit flag bit 0 (encrypted)
        data[6] = 0x01;
        data[7] = 0x00;
        // Pad out
        data.extend_from_slice(&[0x00; 30]);
        let result = inspect_file(&data, Some("secrets.zip"));
        assert!(
            result.findings.iter().any(|f| f.id == "ARCHIVE_ENCRYPTED"),
            "Encrypted ZIP should be flagged: {:?}",
            result.findings
        );
        assert!(result.risk_score >= 7.0);
    }

    // ── FP-heuristic + extension-extraction regression tests ──

    #[test]
    fn test_midfile_mz_in_text_not_flagged() {
        // 'MZ' appearing mid-file in ordinary text must NOT be treated as an
        // embedded PE / polyglot indicator.
        let data = b"release notes: fixed MZ parsing bug and other issues\nsecond line\n";
        let result = inspect_file(data, Some("notes.txt"));
        assert_eq!(result.file_type, FileType::PlainText);
        assert!(
            !result.findings.iter().any(|f| f.id == "POLYGLOT_DETECTED"),
            "mid-file MZ in text must not flag polyglot: {:?}",
            result.findings
        );
        assert!(
            !result
                .findings
                .iter()
                .any(|f| f.id.starts_with("EXECUTABLE")),
            "mid-file MZ must not be treated as an executable"
        );
    }

    #[test]
    fn test_mz_at_offset_zero_flagged() {
        let data = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let result = inspect_file(&data, Some("update.exe"));
        assert_eq!(result.file_type, FileType::PeExe);
        assert!(result.findings.iter().any(|f| f.id == "EXECUTABLE_PE"));
    }

    #[test]
    fn test_zip_aes_magic_in_content_not_flagged_encrypted() {
        // The bytes 0x99 0x01 inside ordinary stored content must not trigger
        // the encrypted-archive heuristic (central-directory flags are the
        // authoritative signal now).
        let zip = make_test_zip(0, 0, b"binary-looking content \x99\x01 tail");
        assert!(!is_zip_encrypted(&zip));
    }

    #[test]
    fn test_zip_central_directory_encrypted_flag_detected() {
        // Central-directory flag bit 0 set → encrypted.
        let zip = make_test_zip(0, 0x0001, b"payload");
        assert!(is_zip_encrypted(&zip));
    }

    #[test]
    fn test_extract_extension_windows_trailing_dots_and_spaces() {
        assert_eq!(extract_extension("payload.exe."), Some("exe".into()));
        assert_eq!(extract_extension("payload.exe "), Some("exe".into()));
        assert_eq!(extract_extension("payload.exe. . "), Some("exe".into()));
        assert_eq!(extract_extension("Makefile"), None);
        assert_eq!(extract_extension("archive.tar.gz"), Some("gz".into()));
        assert_eq!(extract_extension("no_extension."), None);
        assert_eq!(extract_extension("dir/file.doc"), Some("doc".into()));
    }

    #[test]
    fn test_trailing_dot_exe_filename_blocked() {
        // "payload.exe." must be treated as an EXE attachment (Windows
        // strips the trailing dot when writing the file).
        let data = b"plain text, definitely not an executable";
        let result = inspect_file(data, Some("payload.exe."));
        assert_eq!(result.extension.as_deref(), Some("exe"));
        assert!(result.findings.iter().any(|f| f.id == "BLOCKED_EXTENSION"));
    }
}
