//! Attachment validation service – size checks, extension/MIME blocklists,
//! magic-byte detection, double-extension detection, ClamAV virus scanning.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

use crate::config::{AttachmentLimits, ClamAVConfig, BASE64_OVERHEAD};

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: Option<String>,
    pub content: Vec<u8>,
    pub size: usize,
    pub disposition: String,
    pub content_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentValidation {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub virus_scanned: bool,
    pub virus_detected: bool,
    pub virus_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageSizeValidation {
    pub is_valid: bool,
    pub estimated_size: usize,
    pub max_size: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusScanResult {
    pub is_clean: bool,
    pub virus_name: Option<String>,
    pub scan_time_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentStats {
    pub count: usize,
    pub total_size: usize,
    pub mime_types: Vec<String>,
    pub has_inline: bool,
    pub has_attachment: bool,
}

// ── service ────────────────────────────────────────────────────────────────────

pub struct AttachmentService {
    pool: PgPool,
    limits: AttachmentLimits,
    clamav: ClamAVConfig,
}

impl AttachmentService {
    pub fn new(pool: PgPool, limits: AttachmentLimits, clamav: ClamAVConfig) -> Self {
        Self { pool, limits, clamav }
    }

/// Max single attachment size.
    pub fn max_single_size(&self) -> usize {
        self.limits.max_single_size
    }

/// Validate a single attachment.
    pub async fn validate_attachment(&self, attachment: &Attachment) -> AttachmentValidation {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

// 1. Size check
        if attachment.size > self.limits.max_single_size {
            errors.push(format!(
                "Attachment too large: {} (max {})",
                format_size(attachment.size),
                format_size(self.limits.max_single_size)
            ));
        }

// 2. Extension check
        let ext = get_file_extension(&attachment.filename);
        if self.limits.blocked_extensions.iter().any(|b| b.eq_ignore_ascii_case(&ext)) {
            errors.push(format!("Blocked file extension: {ext}"));
        }

// 3. Detect MIME type from magic bytes
        let detected_mime = detect_from_magic_bytes(&attachment.content);

// 4. MIME type blocklist
        let effective_mime = attachment
            .content_type
            .as_deref()
            .or(detected_mime)
            .unwrap_or("application/octet-stream");
        if self.limits.blocked_mime_types.iter().any(|b| b == effective_mime) {
            errors.push(format!("Blocked MIME type: {effective_mime}"));
        }

// 5. MIME mismatch warning
        if let (Some(declared), Some(detected)) = (attachment.content_type.as_deref(), detected_mime) {
            if declared != detected && !is_compatible_mime(declared, detected) {
                warnings.push(format!(
                    "MIME type mismatch: declared={declared}, detected={detected}"
                ));
            }
        }

// 6. Double extension
        if check_double_extension(&attachment.filename) {
            warnings.push("Suspicious double extension detected".into());
        }

// 7. Encrypted content
        if is_encrypted_content(&attachment.content, effective_mime) {
            warnings.push("Attachment appears to be encrypted".into());
        }

// 8. Virus scan
        let mut virus_scanned = false;
        let mut virus_detected = false;
        let mut virus_name = None;

        if self.clamav.enabled && errors.is_empty() {
            let scan = self.scan_for_virus(&attachment.content).await;
            virus_scanned = true;
            if !scan.is_clean {
                virus_detected = true;
                virus_name.clone_from(&scan.virus_name);
                errors.push(format!(
                    "Virus detected: {}",
                    scan.virus_name.as_deref().unwrap_or("unknown")
                ));
            }
            if let Some(err) = scan.error {
// Fail-closed:scan failure = not clean
                virus_detected = true;
                warnings.push(format!("Virus scan error: {err}"));
            }
        }

        AttachmentValidation {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            virus_scanned,
            virus_detected,
            virus_name,
        }
    }

/// Validate multiple attachments.
    pub async fn validate_attachments(
        &self,
        attachments: &[Attachment],
    ) -> AttachmentValidation {
        let mut all_errors = Vec::new();
        let mut all_warnings = Vec::new();
        let mut any_virus = false;
        let mut virus_name = None;

// Count check
        if attachments.len() > self.limits.max_count {
            all_errors.push(format!(
                "Too many attachments: {} (max {})",
                attachments.len(),
                self.limits.max_count,
            ));
        }

// Total size check
        let total: usize = attachments.iter().map(|a| a.size).sum();
        if total > self.limits.max_total_size {
            all_errors.push(format!(
                "Total attachment size too large: {} (max {})",
                format_size(total),
                format_size(self.limits.max_total_size)
            ));
        }

// Validate each
        for att in attachments {
            let result = self.validate_attachment(att).await;
            all_errors.extend(result.errors);
            all_warnings.extend(result.warnings);
            if result.virus_detected {
                any_virus = true;
                if virus_name.is_none() {
                    virus_name.clone_from(&result.virus_name);
                }
            }
        }

        AttachmentValidation {
            is_valid: all_errors.is_empty(),
            errors: all_errors,
            warnings: all_warnings,
            virus_scanned: self.clamav.enabled,
            virus_detected: any_virus,
            virus_name,
        }
    }

/// Pre-check estimated message size.
    pub fn validate_message_size(
        &self,
        body_size: usize,
        html_size: Option<usize>,
        attachments: &[(usize,)],
    ) -> MessageSizeValidation {
        let headers = 1024;
        let text_part = body_size + 200;
        let html_part = html_size.map(|h| h + 200).unwrap_or(0);
        let attachment_size: usize = attachments
            .iter()
            .map(|(sz,)| (*sz as f64 * BASE64_OVERHEAD) as usize + 500)
            .sum();
        let boundaries = (attachments.len() + 2) * 100;
        let estimated = headers + text_part + html_part + attachment_size + boundaries;

        MessageSizeValidation {
            is_valid: estimated <= self.limits.max_total_size,
            estimated_size: estimated,
            max_size: self.limits.max_total_size,
            error: if estimated > self.limits.max_total_size {
                Some(format!(
                    "Estimated size {} exceeds limit {}",
                    format_size(estimated),
                    format_size(self.limits.max_total_size),
                ))
            } else {
                None
            },
        }
    }

/// Get aggregate attachment statistics.
    pub fn get_attachment_stats(attachments: &[Attachment]) -> AttachmentStats {
        let mut mime_set = std::collections::HashSet::new();
        let mut has_inline = false;
        let mut has_attachment = false;
        let mut total_size = 0;

        for att in attachments {
            total_size += att.size;
            if let Some(ref ct) = att.content_type {
                mime_set.insert(ct.clone());
            }
            if att.disposition == "inline" {
                has_inline = true;
            } else {
                has_attachment = true;
            }
        }

        AttachmentStats {
            count: attachments.len(),
            total_size,
            mime_types: mime_set.into_iter().collect(),
            has_inline,
            has_attachment,
        }
    }

/// Record scan result in DB.
    pub async fn record_scan_result(
        &self,
        message_id: &str,
        filename: &str,
        result: &AttachmentValidation,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO edge_attachment_scans
               (id, message_id, filename, is_valid, virus_scanned, virus_detected,
                virus_name, errors, warnings, scanned_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, NOW())"#,
        )
        .bind(message_id)
        .bind(filename)
        .bind(result.is_valid)
        .bind(result.virus_scanned)
        .bind(result.virus_detected)
        .bind(&result.virus_name)
        .bind(serde_json::to_value(&result.errors).map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?)
        .bind(serde_json::to_value(&result.warnings).map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

// ── ClamAV INSTREAM protocol ───────────────────────────────────────────────

    async fn scan_for_virus(&self, content: &[u8]) -> VirusScanResult {
        let start = std::time::Instant::now();

        let addr = format!("{}:{}", self.clamav.host, self.clamav.port);
        let timeout = Duration::from_secs(self.clamav.timeout_secs);

        let result = tokio::time::timeout(timeout, async {
            let mut stream = TcpStream::connect(&addr).await?;

// Send INSTREAM command
            stream.write_all(b"nINSTREAM\n").await?;

// Send content in chunks with 4-byte BE length prefix
            for chunk in content.chunks(8192) {
                let len = (chunk.len() as u32).to_be_bytes();
                stream.write_all(&len).await?;
                stream.write_all(chunk).await?;
            }
// Zero-length terminator
            stream.write_all(&[0u8; 4]).await?;
            stream.flush().await?;

// Read response
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            let response_str = String::from_utf8_lossy(&response);

            if response_str.contains("OK") && !response_str.contains("FOUND") {
                Ok::<VirusScanResult, anyhow::Error>(VirusScanResult {
                    is_clean: true,
                    virus_name: None,
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    error: None,
                })
            } else if let Some(idx) = response_str.find("FOUND") {
                let virus = response_str[..idx].rsplit(':').next()
                    .unwrap_or("unknown").trim().to_string();
                Ok(VirusScanResult {
                    is_clean: false,
                    virus_name: Some(virus),
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    error: None,
                })
            } else {
                Ok(VirusScanResult {
                    is_clean: false,
                    virus_name: None,
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    error: Some(format!("Unexpected response: {response_str}")),
                })
            }
        })
        .await;

        match result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                warn!(error = %e, "ClamAV scan error");
                VirusScanResult {
                    is_clean: false,
                    virus_name: None,
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    error: Some(e.to_string()),
                }
            }
            Err(_) => {
                warn!("ClamAV scan timed out");
                VirusScanResult {
                    is_clean: false,
                    virus_name: None,
                    scan_time_ms: start.elapsed().as_millis() as u64,
                    error: Some("Scan timed out".into()),
                }
            }
        }
    }
}

// ── detection helpers ──────────────────────────────────────────────────────────

/// Detect MIME type from magic bytes.
pub fn detect_from_magic_bytes(content: &[u8]) -> Option<&'static str> {
    if content.len() < 4 {
        return None;
    }
// PDF
    if content.starts_with(b"%PDF") {
        return Some("application/pdf");
    }
// ZIP / Office XML
    if content.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return Some("application/zip");
    }
// JPEG
    if content.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
// PNG
    if content.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        return Some("image/png");
    }
// GIF
    if content.starts_with(b"GIF8") {
        return Some("image/gif");
    }
// Windows EXE
    if content.starts_with(b"MZ") {
        return Some("application/x-msdownload");
    }
// RAR
    if content.starts_with(b"Rar!") {
        return Some("application/x-rar-compressed");
    }
// 7z
    if content.len() >= 6 && content[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return Some("application/x-7z-compressed");
    }
    None
}

fn get_file_extension(filename: &str) -> String {
    filename
        .rsplit('.')
        .next()
        .map(|e| format!(".{}", e.to_lowercase()))
        .unwrap_or_default()
}

fn check_double_extension(filename: &str) -> bool {
    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() < 3 {
        return false;
    }
// Safety:parts.len >= 3 guaranteed by guard above
    let Some(last) = parts.last() else { return false };
    let last = last.to_lowercase();
    let dangerous = ["exe", "bat", "cmd", "com", "dll", "scr", "pif", "vbs", "js", "jar", "msi", "ps1", "sh"];
    dangerous.contains(&last.as_str())
}

fn is_compatible_mime(declared: &str, detected: &str) -> bool {
// ZIP can be Office XML
    if declared.contains("officedocument") && detected == "application/zip" {
        return true;
    }
// Generic octet-stream matches anything
    if declared == "application/octet-stream" || detected == "application/octet-stream" {
        return true;
    }
    false
}

fn is_encrypted_content(content: &[u8], mime: &str) -> bool {
// PDF encryption
    if mime == "application/pdf" {
        let text = String::from_utf8_lossy(content);
        if text.contains("/Encrypt") {
            return true;
        }
    }
// ZIP encryption flag (bit 0 at offset 6)
    if mime == "application/zip" && content.len() > 7
        && content[6] & 0x01 != 0 {
            return true;
        }
    false
}

pub fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_magic_bytes_pdf() {
        assert_eq!(detect_from_magic_bytes(b"%PDF-1.4"), Some("application/pdf"));
    }

    #[test]
    fn test_detect_magic_bytes_png() {
        assert_eq!(
            detect_from_magic_bytes(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A]),
            Some("image/png")
        );
    }

    #[test]
    fn test_detect_magic_bytes_exe() {
        assert_eq!(detect_from_magic_bytes(b"MZ\x90\x00"), Some("application/x-msdownload"));
    }

    #[test]
    fn test_detect_magic_bytes_unknown() {
        assert_eq!(detect_from_magic_bytes(b"hello world"), None);
    }

    #[test]
    fn test_get_file_extension() {
        assert_eq!(get_file_extension("doc.pdf"), ".pdf");
        assert_eq!(get_file_extension("image.PNG"), ".png");
        assert_eq!(get_file_extension("noext"), ".noext");
    }

    #[test]
    fn test_check_double_extension() {
        assert!(check_double_extension("report.pdf.exe"));
        assert!(!check_double_extension("report.pdf"));
        assert!(!check_double_extension("archive.tar.gz"));
        assert!(check_double_extension("photo.jpg.js"));
    }

    #[test]
    fn test_is_encrypted_pdf() {
        let content = b"%PDF-1.4 some content /Encrypt more content";
        assert!(is_encrypted_content(content, "application/pdf"));
    }

    #[test]
    fn test_is_encrypted_zip() {
        let mut content = vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x01, 0x00];
        assert!(is_encrypted_content(&content, "application/zip"));
        content[6] = 0x00;
        assert!(!is_encrypted_content(&content, "application/zip"));
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn test_is_compatible_mime() {
        assert!(is_compatible_mime(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/zip"
        ));
        assert!(is_compatible_mime("application/octet-stream", "image/png"));
        assert!(!is_compatible_mime("image/png", "image/jpeg"));
    }
}
