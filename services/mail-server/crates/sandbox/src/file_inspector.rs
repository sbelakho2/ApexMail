//! File inspection — magic number detection, hash computation, content analysis
//!
//! Performs static analysis of file contents without executing anything:
//! - File type identification via magic bytes
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
        // PDF: %PDF
        [0x25, 0x50, 0x44, 0x46] => FileType::Pdf,
        // ZIP (also OOXML: docx, xlsx, pptx, jar)
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
            if data.len() >= 8 && data[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
            {
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
            if sample.iter().all(|b| b.is_ascii() || *b == 0x0A || *b == 0x0D) {
                FileType::PlainText
            } else {
                FileType::Unknown
            }
        }
    }
}

/// Compute SHA-256 hash of data
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Inspect a file's contents for risk indicators
pub fn inspect_file(data: &[u8], filename: Option<&str>) -> FileInspection {
    let file_type = detect_file_type(data);
    let sha256 = compute_sha256(data);
    let size = data.len() as u64;
    let mut findings = Vec::new();
    let mut risk_score = 0.0;

    // Extract extension
    let extension = filename.and_then(|f| {
        f.rsplit('.').next().map(|e| e.to_lowercase())
    });

    // Check extension mismatch
    let extension_mismatch = if let Some(ref ext) = extension {
        let expected = match file_type {
            FileType::Pdf => Some(vec!["pdf"]),
            FileType::Zip => Some(vec!["zip", "docx", "xlsx", "pptx", "jar", "apk", "ods", "odt"]),
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

    // OLE2: Check for VBA macro indicators
    if file_type == FileType::Ole2 {
        if has_vba_indicators(data) {
            findings.push(InspectionFinding {
                id: "OLE2_VBA_MACROS",
                description: "OLE2 document contains VBA macro indicators".into(),
                risk: 6.0,
            });
            risk_score += 6.0;
        }
    }

    // ZIP-based OOXML: Check for macro-enabled formats
    if file_type == FileType::Zip {
        if let Some(ref ext) = extension {
            let macro_exts = ["docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam"];
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
                description: "vbaProject.bin found in Office document".into(),
                risk: 6.0,
            });
            risk_score += 6.0;
        }
        
        // Check for encrypted/password-protected ZIP
        if is_zip_encrypted(data) {
            findings.push(InspectionFinding {
                id: "ARCHIVE_ENCRYPTED",
                description: "ZIP archive is password-protected (contents cannot be inspected)".into(),
                risk: 7.0,
            });
            risk_score += 7.0;
        }
    }
    
    // RAR: Check for encryption
    if file_type == FileType::Rar {
        if is_rar_encrypted(data) {
            findings.push(InspectionFinding {
                id: "ARCHIVE_ENCRYPTED",
                description: "RAR archive is password-protected (contents cannot be inspected)".into(),
                risk: 7.0,
            });
            risk_score += 7.0;
        }
    }
    
    // 7-Zip: Check for encryption
    if file_type == FileType::SevenZip {
        if is_7z_encrypted(data) {
            findings.push(InspectionFinding {
                id: "ARCHIVE_ENCRYPTED",
                description: "7-Zip archive is encrypted (contents cannot be inspected)".into(),
                risk: 7.0,
            });
            risk_score += 7.0;
        }
    }

    // PDF: Check for suspicious elements
    if file_type == FileType::Pdf {
        let pdf_findings = inspect_pdf(data);
        for f in &pdf_findings {
            risk_score += f.risk;
        }
        findings.extend(pdf_findings);
    }

    // HTML: Check for script content
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

    // SVG / XML: Check for embedded scripts (SVG is a common XSS delivery vector)
    if file_type == FileType::Xml {
        if let Ok(text) = std::str::from_utf8(data) {
            let lower = text.to_lowercase();
            // Detect SVG documents
            let is_svg = lower.contains("<svg") || lower.contains("xmlns=\"http://www.w3.org/2000/svg\"");
            if is_svg {
                if lower.contains("<script") {
                    findings.push(InspectionFinding {
                        id: "SVG_SCRIPT",
                        description: "SVG image contains embedded <script> element (XSS risk)".into(),
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
                // javascript: URI in SVG href/src
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

    // Dangerous extension check (regardless of content)
    if let Some(ref ext) = extension {
        let blocked = [
            "exe", "dll", "scr", "bat", "cmd", "com", "pif",
            "hta", "cpl", "msi", "ps1", "vbs", "vbe", "wsf",
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
            let dangerous_inner = [
                "pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt",
            ];
            let dangerous_outer = [
                "exe", "scr", "bat", "cmd", "com", "pif", "js", "vbs",
            ];
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

/// Check for vbaProject.bin inside a ZIP file (OOXML)
fn has_zip_vba_project(data: &[u8]) -> bool {
    // Simple heuristic: look for the filename in the ZIP central directory
    data.windows(14).any(|w| w == b"vbaProject.bin")
}

/// Check if a ZIP file is password-protected/encrypted.
/// ZIP encryption is indicated by the general purpose bit flag (bit 0).
/// 
/// ZIP local file header structure:
/// - 0-3: Local file header signature (0x04034b50)
/// - 4-5: Version needed to extract
/// - 6-7: General purpose bit flag (bit 0 = encrypted)
/// - 8-9: Compression method
/// ...
/// 
/// This function checks multiple local file headers in case some files
/// are encrypted and others are not.
pub fn is_zip_encrypted(data: &[u8]) -> bool {
    // ZIP local file header signature: PK\x03\x04
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
    
    // Also check for encryption in central directory (end of ZIP)
    // Look for AES encryption marker
    if data.windows(2).any(|w| w == &[0x99, 0x01]) { // AES extra field ID
        return true;
    }
    
    false
}

/// Check if a RAR file is password-protected.
/// RAR encryption is indicated in the file header flags.
pub fn is_rar_encrypted(data: &[u8]) -> bool {
    // RAR signature: Rar!\x1a\x07\x00 (RAR 4.x) or Rar!\x1a\x07\x01\x00 (RAR 5.x)
    if data.len() < 14 {
        return false;
    }
    
    // Check for RAR5 encrypted archive flag (byte 11, bit 0x0004)
    if data.len() > 12 {
        // RAR5: Archive header at offset 7 has flags
        // Check for common encryption indicators
        // RAR5 uses different structure, but commonly has encryption flag
        if data[0..4] == [0x52, 0x61, 0x72, 0x21] { // "Rar!"
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
    
    // RAR4: Check for encrypted header flag (bit 2 in archive header flags)
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
    // 7z signature: 7z\xBC\xAF\x27\x1C
    if data.len() < 32 || data[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return false;
    }
    
    // Look for AES encryption codec ID in the stream
    // 7z stores encryption method as a codec: 0x06F10701 (AES-256)
    // In the 7z format, this appears as bytes: 06 F1 07 01
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
        assert!(result.risk_score < 5.0, "Clean PDF risk: {}", result.risk_score);
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
}
