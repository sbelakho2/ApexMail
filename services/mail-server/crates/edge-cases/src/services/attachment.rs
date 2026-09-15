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
        Self {
            pool,
            limits,
            clamav,
        }
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
        if self
            .limits
            .blocked_extensions
            .iter()
            .any(|b| b.eq_ignore_ascii_case(&ext))
        {
            errors.push(format!("Blocked file extension: {ext}"));
        }

        // 3. Detect MIME type from magic bytes
        let detected_mime = detect_from_magic_bytes(&attachment.content);

        // 4. MIME type blocklist — decided on BOTH the declared and the
        // detected type (F4): block if EITHER is on the blocklist. The
        // previous logic preferred the declared Content-Type, so an EXE with
        // a spoofed `Content-Type: application/pdf` sailed past the
        // executable blocklist.
        let blocked_mime = [attachment.content_type.as_deref(), detected_mime]
            .into_iter()
            .flatten()
            .find(|mime| self.limits.blocked_mime_types.iter().any(|b| b == mime));

        if let Some(blocked) = blocked_mime {
            errors.push(format!("Blocked MIME type: {blocked}"));
        }

        let effective_mime = attachment
            .content_type
            .as_deref()
            .or(detected_mime)
            .unwrap_or("application/octet-stream");

        // 5. MIME mismatch warning
        if let (Some(declared), Some(detected)) =
            (attachment.content_type.as_deref(), detected_mime)
        {
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
    pub async fn validate_attachments(&self, attachments: &[Attachment]) -> AttachmentValidation {
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
        .bind(
            serde_json::to_value(&result.errors)
                .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?,
        )
        .bind(
            serde_json::to_value(&result.warnings)
                .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?,
        )
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

            // O-21.1: Use configurable chunk size from ClamAVConfig
            let chunk_size = self.clamav.chunk_size;
            for chunk in content.chunks(chunk_size) {
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
                let virus = response_str[..idx]
                    .rsplit(':')
                    .next()
                    .unwrap_or("unknown")
                    .trim()
                    .to_string();
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
    let Some(last) = parts.last() else {
        return false;
    };
    let last = last.to_lowercase();
    let dangerous = [
        "exe", "bat", "cmd", "com", "dll", "scr", "pif", "vbs", "js", "jar", "msi", "ps1", "sh",
    ];
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
    if mime == "application/zip" && content.len() > 7 && content[6] & 0x01 != 0 {
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
        assert_eq!(
            detect_from_magic_bytes(b"%PDF-1.4"),
            Some("application/pdf")
        );
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
        assert_eq!(
            detect_from_magic_bytes(b"MZ\x90\x00"),
            Some("application/x-msdownload")
        );
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

    // ── F4:blocklist must consult declared AND detected MIME types ──

    fn test_service() -> AttachmentService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("lazy pool never connects");
        let clamav = ClamAVConfig {
            enabled: false,
            ..ClamAVConfig::default()
        };
        AttachmentService::new(pool, AttachmentLimits::default(), clamav)
    }

    #[tokio::test]
    async fn test_exe_magic_with_declared_pdf_is_blocked() {
        // EXE magic bytes + declared application/pdf: the detected type is on
        // the blocklist, so the attachment must be blocked even though the
        // declared type is benign. Previously the declared type won and the
        // executable passed validation.
        let service = test_service();
        let attachment = Attachment {
            filename: "invoice.pdf".into(),
            content_type: Some("application/pdf".into()),
            content: b"MZ\x90\x00\x03\x00\x00\x00\x04\x00".to_vec(),
            size: 10,
            disposition: "attachment".into(),
            content_id: None,
        };

        let result = service.validate_attachment(&attachment).await;
        assert!(
            !result.is_valid,
            "EXE magic under a declared PDF must be blocked: {:?}",
            result.errors
        );
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("application/x-msdownload")));
        // The declared/detected mismatch is still surfaced as a warning.
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("declared=application/pdf")));
    }

    #[tokio::test]
    async fn test_declared_blocked_mime_is_blocked_even_with_clean_magic() {
        // Declared type on the blocklist blocks regardless of what the magic
        // bytes look like (unknown bytes here).
        let service = test_service();
        let attachment = Attachment {
            filename: "payload.bin".into(),
            content_type: Some("application/x-dosexec".into()),
            content: b"\x00\x01\x02\x03randomdata".to_vec(),
            size: 16,
            disposition: "attachment".into(),
            content_id: None,
        };

        let result = service.validate_attachment(&attachment).await;
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("application/x-dosexec")));
    }

    #[tokio::test]
    async fn test_clean_png_declared_and_detected_allowed() {
        // Neither declared nor detected type is blocked → valid, no mismatch.
        let service = test_service();
        let attachment = Attachment {
            filename: "photo.png".into(),
            content_type: Some("image/png".into()),
            content: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
            size: 8,
            disposition: "inline".into(),
            content_id: None,
        };

        let result = service.validate_attachment(&attachment).await;
        assert!(result.is_valid, "clean PNG must pass: {:?}", result.errors);
        assert!(result.warnings.is_empty());
    }

    // ── adversarial: size, extensions, encryption, aggregation ────────

    fn attachment(filename: &str, content_type: Option<&str>, content: Vec<u8>) -> Attachment {
        let size = content.len();
        Attachment {
            filename: filename.into(),
            content_type: content_type.map(str::to_string),
            content,
            size,
            disposition: "attachment".into(),
            content_id: None,
        }
    }

    fn service_with(clamav: ClamAVConfig, limits: AttachmentLimits) -> AttachmentService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("lazy pool never connects");
        AttachmentService::new(pool, limits, clamav)
    }

    #[tokio::test]
    async fn oversize_and_blocked_extension_are_rejected() {
        let limits = AttachmentLimits {
            max_single_size: 10,
            ..AttachmentLimits::default()
        };
        let service = service_with(
            ClamAVConfig {
                enabled: false,
                ..ClamAVConfig::default()
            },
            limits,
        );

        let mut att = attachment("big.bin", Some("application/octet-stream"), vec![0u8; 11]);
        att.size = 11; // declared size (not content length) is authoritative
        let result = service.validate_attachment(&att).await;
        assert!(!result.is_valid);
        assert!(result.errors.iter().any(|e| e.contains("too large")));
        assert_eq!(service.max_single_size(), 10);

        // Extension matching is case-insensitive.
        let att = attachment(
            "payload.EXE",
            Some("application/octet-stream"),
            b"hello".to_vec(),
        );
        let result = service.validate_attachment(&att).await;
        assert!(!result.is_valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Blocked file extension: .exe")));

        // Exactly at the limit is allowed.
        let mut att = attachment("ok.bin", Some("application/octet-stream"), vec![0u8; 10]);
        att.size = 10;
        assert!(service.validate_attachment(&att).await.is_valid);
    }

    #[tokio::test]
    async fn double_extension_and_encrypted_content_warn() {
        let service = service_with(
            ClamAVConfig {
                enabled: false,
                ..ClamAVConfig::default()
            },
            AttachmentLimits::default(),
        );

        let att = attachment(
            "invoice.pdf.exe",
            Some("application/pdf"),
            b"%PDF-1.4".to_vec(),
        );
        let result = service.validate_attachment(&att).await;
        assert!(!result.is_valid, "the .exe extension is blocked");
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("double extension")));

        // Encrypted PDF: valid file, warning only.
        let att = attachment(
            "secret.pdf",
            Some("application/pdf"),
            b"%PDF-1.4 trailer /Encrypt 5.0".to_vec(),
        );
        let result = service.validate_attachment(&att).await;
        assert!(result.is_valid, "{:?}", result.errors);
        assert!(result.warnings.iter().any(|w| w.contains("encrypted")));

        // Encrypted ZIP: bit 0 of the GP flags byte (offset 6).
        let zip = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00];
        let att = attachment("archive.zip", Some("application/zip"), zip);
        let result = service.validate_attachment(&att).await;
        assert!(result.warnings.iter().any(|w| w.contains("encrypted")));

        // Declared/detected mismatch → warning, still valid.
        let att = attachment(
            "photo.jpg",
            Some("image/jpeg"),
            vec![0x89, 0x50, 0x4E, 0x47],
        );
        let result = service.validate_attachment(&att).await;
        assert!(result.is_valid);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("declared=image/jpeg, detected=image/png")));

        // Office document declared over ZIP magic is a compatible pair.
        let att = attachment(
            "sheet.xlsx",
            Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            vec![0x50, 0x4B, 0x03, 0x04, 0x00, 0x00],
        );
        let result = service.validate_attachment(&att).await;
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[tokio::test]
    async fn multi_attachment_limits_are_enforced() {
        let limits = AttachmentLimits {
            max_count: 2,
            max_total_size: 100,
            ..AttachmentLimits::default()
        };
        let service = service_with(
            ClamAVConfig {
                enabled: false,
                ..ClamAVConfig::default()
            },
            limits,
        );

        let ok = service
            .validate_attachments(&[
                attachment("a.bin", None, vec![0u8; 10]),
                attachment("b.bin", None, vec![0u8; 10]),
            ])
            .await;
        assert!(ok.is_valid, "{:?}", ok.errors);

        let too_many = service
            .validate_attachments(&[
                attachment("a.bin", None, vec![]),
                attachment("b.bin", None, vec![]),
                attachment("c.bin", None, vec![]),
            ])
            .await;
        assert!(too_many
            .errors
            .iter()
            .any(|e| e.contains("Too many attachments: 3 (max 2)")));

        let too_big = service
            .validate_attachments(&[
                attachment("a.bin", None, vec![0u8; 60]),
                attachment("b.bin", None, vec![0u8; 60]),
            ])
            .await;
        assert!(too_big
            .errors
            .iter()
            .any(|e| e.contains("Total attachment size too large")));
    }

    #[tokio::test]
    async fn message_size_precheck_and_stats() {
        let service = service_with(
            ClamAVConfig {
                enabled: false,
                ..ClamAVConfig::default()
            },
            AttachmentLimits::default(),
        );
        let small = service.validate_message_size(100, Some(100), &[(10,)]);
        assert!(small.is_valid);
        assert_eq!(small.error, None);
        assert!(small.estimated_size > 0);

        let huge = service.validate_message_size(
            AttachmentLimits::default().max_total_size,
            None,
            &[(0,)],
        );
        assert!(!huge.is_valid);
        assert!(huge.error.unwrap().contains("exceeds limit"));

        let mut inline = attachment("b.pdf", Some("application/pdf"), vec![0u8; 5]);
        inline.disposition = "inline".into();
        inline.content_id = Some("cid1".into());
        let mut untyped = attachment("c.bin", None, vec![0u8; 1]);
        untyped.disposition = "inline".into();
        let stats = AttachmentService::get_attachment_stats(&[
            attachment("a.png", Some("image/png"), vec![0u8; 3]),
            inline,
            untyped,
        ]);
        assert_eq!(stats.count, 3);
        assert_eq!(stats.total_size, 9);
        assert!(stats.has_inline);
        assert!(stats.has_attachment);
        assert_eq!(stats.mime_types.len(), 2);

        let empty = AttachmentService::get_attachment_stats(&[]);
        assert_eq!(empty.count, 0);
        assert!(!empty.has_inline && !empty.has_attachment);
    }

    #[tokio::test]
    async fn magic_bytes_cover_every_branch_and_short_inputs() {
        assert_eq!(detect_from_magic_bytes(b"MZ"), None, "too short");
        assert_eq!(
            detect_from_magic_bytes(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some("image/jpeg")
        );
        assert_eq!(detect_from_magic_bytes(b"GIF89a"), Some("image/gif"));
        assert_eq!(
            detect_from_magic_bytes(b"Rar!\x1a\x07\x00"),
            Some("application/x-rar-compressed")
        );
        assert_eq!(
            detect_from_magic_bytes(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]),
            Some("application/x-7z-compressed")
        );
        assert_eq!(detect_from_magic_bytes(b"\x37\x7A\xBC"), None);
        assert_eq!(format_size(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    // ── ClamAV INSTREAM (fake local server; no real network) ──────────

    /// Spawn a fake ClamAV endpoint that consumes one INSTREAM request
    /// (until the zero-length terminator) and answers with `response`.
    async fn spawn_clamav(response: &'static str) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut window = [0u8; 4];
            let mut filled = 0usize;
            let mut buf = vec![0u8; 4096];
            loop {
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                for &byte in &buf[..n] {
                    if filled < 4 {
                        window[filled] = byte;
                        filled += 1;
                    } else {
                        window.rotate_left(1);
                        window[3] = byte;
                    }
                    if filled == 4 && window == [0u8; 4] {
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.flush().await;
                        let _ = stream.shutdown().await;
                        return;
                    }
                }
            }
        });
        addr
    }

    fn clamav_config(addr: std::net::SocketAddr) -> ClamAVConfig {
        ClamAVConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            timeout_secs: 2,
            enabled: true,
            chunk_size: 4, // exercise the multi-chunk write path
        }
    }

    #[tokio::test]
    async fn virus_scan_marks_clean_and_infected_content() {
        // Clean response.
        let addr = spawn_clamav("stream: OK\0").await;
        let service = service_with(clamav_config(addr), AttachmentLimits::default());
        let result = service
            .validate_attachment(&attachment("ok.bin", None, b"hello world".to_vec()))
            .await;
        assert!(result.is_valid, "{:?}", result.errors);
        assert!(result.virus_scanned);
        assert!(!result.virus_detected);

        // Infected response: the virus name is extracted from the signature.
        let addr = spawn_clamav("stream: Eicar-Test-Signature FOUND\0").await;
        let service = service_with(clamav_config(addr), AttachmentLimits::default());
        let result = service
            .validate_attachment(&attachment("evil.bin", None, b"X5O!P%@AP".to_vec()))
            .await;
        assert!(!result.is_valid);
        assert!(result.virus_detected);
        assert_eq!(result.virus_name.as_deref(), Some("Eicar-Test-Signature"));
        assert!(result.errors.iter().any(|e| e.contains("Virus detected")));
    }

    #[tokio::test]
    async fn multi_attachment_scan_propagates_the_virus_name() {
        let addr = spawn_clamav("stream: Eicar-Test-Signature FOUND\0").await;
        let service = service_with(clamav_config(addr), AttachmentLimits::default());
        let result = service
            .validate_attachments(&[
                attachment("clean.bin", None, b"hello".to_vec()),
                attachment("evil.bin", None, b"X5O!P%@AP".to_vec()),
            ])
            .await;
        assert!(!result.is_valid);
        assert!(result.virus_scanned);
        assert!(result.virus_detected);
        assert_eq!(result.virus_name.as_deref(), Some("Eicar-Test-Signature"));
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Virus detected: Eicar-Test-Signature")));
    }

    #[tokio::test]
    async fn virus_scan_fails_closed_on_bad_responses_and_outages() {
        // Unexpected response: not clean, error surfaced, never a pass.
        let addr = spawn_clamav("bogus\0").await;
        let service = service_with(clamav_config(addr), AttachmentLimits::default());
        let result = service
            .validate_attachment(&attachment("odd.bin", None, b"data".to_vec()))
            .await;
        assert!(!result.is_valid, "an unparseable scan must fail closed");
        assert!(result.virus_detected);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Virus scan error")));

        // Connection refused (no listener): refused immediately, error set.
        let refused_addr = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let service = service_with(clamav_config(refused_addr), AttachmentLimits::default());
        let result = service
            .validate_attachment(&attachment("x.bin", None, b"data".to_vec()))
            .await;
        assert!(!result.is_valid);
        assert!(result.virus_detected);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Virus scan error")));

        // A silent server (accepts, never answers) with a zero timeout →
        // timeout is reported honestly.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _keep = listener.accept().await;
            // Hold the connection open without answering.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut cfg = clamav_config(silent);
        cfg.timeout_secs = 0;
        let service = service_with(cfg, AttachmentLimits::default());
        let result = service
            .validate_attachment(&attachment("slow.bin", None, b"data".to_vec()))
            .await;
        assert!(!result.is_valid);
        assert!(result.virus_detected);
        assert!(result.warnings.iter().any(|w| w.contains("timed out")));
    }

    #[tokio::test]
    async fn virus_scan_is_skipped_when_other_errors_already_block() {
        // The scan must not even contact ClamAV when the attachment is
        // already invalid: point it at a dead port, the result must still be
        // virus_scanned = false.
        let limits = AttachmentLimits {
            max_single_size: 1,
            ..AttachmentLimits::default()
        };
        let cfg = ClamAVConfig {
            host: "127.0.0.1".into(),
            port: 1,
            timeout_secs: 0,
            enabled: true,
            chunk_size: 4,
        };
        let service = service_with(cfg, limits);
        let result = service
            .validate_attachment(&attachment("big.bin", None, b"0123456789".to_vec()))
            .await;
        assert!(!result.is_valid);
        assert!(!result.virus_scanned);
        assert!(!result.virus_detected);
    }

    #[tokio::test]
    async fn scan_results_persist_to_the_canonical_schema() {
        let pool = match migrator::test_support::fresh_canonical_pool(
            "edge_attachment_scan_db",
            "edge_attachment_scan_db",
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        };
        let Some(pool) = pool else { return };
        // Use the real pool; ClamAV stays disabled so no network is touched.
        let service = AttachmentService::new(
            pool.clone(),
            AttachmentLimits::default(),
            ClamAVConfig {
                enabled: false,
                ..ClamAVConfig::default()
            },
        );

        let validation = service
            .validate_attachment(&attachment(
                "doc.pdf",
                Some("application/pdf"),
                b"%PDF-1.7".to_vec(),
            ))
            .await;
        assert!(validation.is_valid);
        service
            .record_scan_result("msg_scan_1", "doc.pdf", &validation)
            .await
            .expect("record scan");

        let (valid, scanned, detected, errors): (bool, bool, bool, serde_json::Value) =
            sqlx::query_as(
                "SELECT is_valid, virus_scanned, virus_detected, errors
                 FROM edge_attachment_scans WHERE message_id = $1",
            )
            .bind("msg_scan_1")
            .fetch_one(&pool)
            .await
            .expect("row exists");
        assert!(valid);
        assert!(!scanned);
        assert!(!detected);
        assert_eq!(errors, serde_json::json!([]));
    }
}
