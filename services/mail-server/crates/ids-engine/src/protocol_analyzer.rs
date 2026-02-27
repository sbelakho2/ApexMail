//! Protocol-specific anomaly detection for SMTP, DNS, and TLS

use crate::signature::{SigSeverity, SignatureAction};

/// Protocol anomaly result
#[derive(Debug, Clone)]
pub struct ProtocolAnomaly {
    /// Rule/anomaly ID
    pub id: u32,
    /// Description
    pub message: String,
    /// Severity
    pub severity: SigSeverity,
    /// Recommended action
    pub action: SignatureAction,
    /// Protocol
    pub protocol: String,
}

/// Validate SMTP data for protocol-level anomalies
pub fn analyze_smtp(payload: &[u8]) -> Vec<ProtocolAnomaly> {
    let mut anomalies = Vec::new();
    let text = String::from_utf8_lossy(payload);

    // Extremely long command lines (RFC 5321: max 512 chars)
    for line in text.lines() {
        if line.len() > 512 {
            anomalies.push(ProtocolAnomaly {
                id: 3000001,
                message: format!("SMTP line exceeds 512 chars ({} bytes)", line.len()),
                severity: SigSeverity::Medium,
                action: SignatureAction::Alert,
                protocol: "smtp".into(),
            });
            break;
        }
    }

    // Bare LF (without CR) — RFC violation, common in attack tools
    let bytes = payload;
    for i in 0..bytes.len() {
        if bytes[i] == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            anomalies.push(ProtocolAnomaly {
                id: 3000002,
                message: "SMTP bare LF detected (RFC 5321 violation)".into(),
                severity: SigSeverity::Low,
                action: SignatureAction::Alert,
                protocol: "smtp".into(),
            });
            break;
        }
    }

    // Pipelining abuse: multiple commands without waiting for response
    let command_count = text.lines()
        .filter(|l| {
            let upper = l.to_uppercase();
            upper.starts_with("EHLO") || upper.starts_with("HELO") ||
            upper.starts_with("MAIL") || upper.starts_with("RCPT") ||
            upper.starts_with("DATA") || upper.starts_with("QUIT") ||
            upper.starts_with("RSET") || upper.starts_with("NOOP") ||
            upper.starts_with("VRFY") || upper.starts_with("EXPN") ||
            upper.starts_with("AUTH") || upper.starts_with("STARTTLS")
        })
        .count();
    if command_count > 5 {
        anomalies.push(ProtocolAnomaly {
            id: 3000003,
            message: format!("Excessive SMTP pipelining ({} commands in single payload)", command_count),
            severity: SigSeverity::Medium,
            action: SignatureAction::Alert,
            protocol: "smtp".into(),
        });
    }

    // RCPT TO burst in a single payload can indicate directory harvesting.
    let rcpt_to_count = text
        .lines()
        .filter(|line| line.trim_start().to_uppercase().starts_with("RCPT TO:"))
        .count();
    if rcpt_to_count >= 3 {
        anomalies.push(ProtocolAnomaly {
            id: 3000007,
            message: format!(
                "SMTP RCPT TO burst detected ({} recipients in single payload)",
                rcpt_to_count
            ),
            severity: SigSeverity::Medium,
            action: SignatureAction::Alert,
            protocol: "smtp".into(),
        });
    }

    // Null bytes in SMTP stream
    if payload.contains(&0u8) {
        anomalies.push(ProtocolAnomaly {
            id: 3000004,
            message: "Null byte in SMTP stream (possible evasion)".into(),
            severity: SigSeverity::High,
            action: SignatureAction::Drop,
            protocol: "smtp".into(),
        });
    }

    // Bare CR (without LF) can indicate command smuggling attempts
    for i in 0..bytes.len() {
        if bytes[i] == b'\r' && (i + 1 >= bytes.len() || bytes[i + 1] != b'\n') {
            anomalies.push(ProtocolAnomaly {
                id: 3000005,
                message: "SMTP bare CR detected (potential command smuggling)".into(),
                severity: SigSeverity::Medium,
                action: SignatureAction::Alert,
                protocol: "smtp".into(),
            });
            break;
        }
    }

    // DATA terminator smuggling pattern (\r.\r without expected \n framing)
    if text.contains("\r.\r") {
        anomalies.push(ProtocolAnomaly {
            id: 3000006,
            message: "SMTP DATA terminator smuggling pattern detected".into(),
            severity: SigSeverity::High,
            action: SignatureAction::Drop,
            protocol: "smtp".into(),
        });
    }

    anomalies
}

/// Validate DNS query for anomalies
pub fn analyze_dns(payload: &[u8]) -> Vec<ProtocolAnomaly> {
    let mut anomalies = Vec::new();

    // DNS queries should be relatively small; oversized = amplification
    if payload.len() > 512 {
        anomalies.push(ProtocolAnomaly {
            id: 3000010,
            message: format!("Oversized DNS query ({} bytes, max typical: 512)", payload.len()),
            severity: SigSeverity::Medium,
            action: SignatureAction::Alert,
            protocol: "dns".into(),
        });
    }

    // Extremely long DNS labels
    if payload.len() >= 12 {
        // Skip DNS header (12 bytes) and check label lengths
        let mut i = 12;
        while i < payload.len() {
            let label_len = payload[i] as usize;
            if label_len == 0 { break; }
            if label_len > 63 {
                anomalies.push(ProtocolAnomaly {
                    id: 3000011,
                    message: format!("DNS label exceeds 63 chars ({} bytes)", label_len),
                    severity: SigSeverity::High,
                    action: SignatureAction::Drop,
                    protocol: "dns".into(),
                });
                break;
            }
            i += label_len + 1;
            // Safety: prevent infinite loop on malformed data
            if i > payload.len() + 1 { break; }
        }
    }

    // Compression-pointer sanity checks to reduce parser/evasion abuse.
    // DNS name pointers have top two bits set (11xxxxxx xxxxxxxx).
    if payload.len() >= 14 {
        let mut i = 12usize;
        let mut pointer_hops = 0usize;
        while i + 1 < payload.len() {
            let first = payload[i];
            if first == 0 {
                break;
            }

            if first & 0xC0 == 0xC0 {
                pointer_hops += 1;
                let offset = (((first as usize) & 0x3F) << 8) | payload[i + 1] as usize;
                if offset >= payload.len() {
                    anomalies.push(ProtocolAnomaly {
                        id: 3000012,
                        message: format!("DNS compression pointer out of bounds: {}", offset),
                        severity: SigSeverity::High,
                        action: SignatureAction::Drop,
                        protocol: "dns".into(),
                    });
                    break;
                }
                if pointer_hops > 10 {
                    anomalies.push(ProtocolAnomaly {
                        id: 3000013,
                        message: "Excessive DNS compression pointer indirection".into(),
                        severity: SigSeverity::Medium,
                        action: SignatureAction::Alert,
                        protocol: "dns".into(),
                    });
                    break;
                }
                i += 2;
                continue;
            }

            let label_len = first as usize;
            if label_len == 0 || i + label_len >= payload.len() {
                break;
            }
            i += label_len + 1;
        }
    }

    anomalies
}

/// Validate TLS handshake for protocol anomalies
pub fn analyze_tls(payload: &[u8]) -> Vec<ProtocolAnomaly> {
    let mut anomalies = Vec::new();

    if payload.len() < 5 {
        return anomalies;
    }

    // TLS record: content_type (1 byte), version (2 bytes), length (2 bytes)
    let content_type = payload[0];
    let major_version = payload[1];
    let minor_version = payload[2];

    // Detect SSLv2 (0x00 0x02) or SSLv3 (0x03 0x00)
    if major_version == 0x03 && minor_version == 0x00 {
        anomalies.push(ProtocolAnomaly {
            id: 3000020,
            message: "SSLv3 handshake detected (POODLE vulnerable)".into(),
            severity: SigSeverity::High,
            action: SignatureAction::Alert,
            protocol: "tls".into(),
        });
    }

    // Record type 22 = Handshake, 23 = Application Data
    // Reject unexpected content types
    if content_type != 20 && content_type != 21 && content_type != 22 && content_type != 23 {
        anomalies.push(ProtocolAnomaly {
            id: 3000021,
            message: format!("Unknown TLS content type: {}", content_type),
            severity: SigSeverity::Medium,
            action: SignatureAction::Alert,
            protocol: "tls".into(),
        });
    }

    // Detect extremely large TLS records (>16KB + overhead)
    let record_len = ((payload[3] as usize) << 8) | (payload[4] as usize);
    if record_len > 16_384 + 2048 {
        anomalies.push(ProtocolAnomaly {
            id: 3000022,
            message: format!("Oversized TLS record ({} bytes)", record_len),
            severity: SigSeverity::High,
            action: SignatureAction::Drop,
            protocol: "tls".into(),
        });
    }

    // Truncated record length mismatch can indicate evasive fragmentation.
    if payload.len() < 5 + record_len {
        anomalies.push(ProtocolAnomaly {
            id: 3000023,
            message: format!(
                "TLS record truncated: declared {} bytes but payload has {}",
                record_len,
                payload.len().saturating_sub(5)
            ),
            severity: SigSeverity::High,
            action: SignatureAction::Drop,
            protocol: "tls".into(),
        });
    }

    anomalies
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_bare_lf() {
        let payload = b"EHLO test.com\nMAIL FROM:<a@b.com>\n";
        let anomalies = analyze_smtp(payload);
        assert!(anomalies.iter().any(|a| a.id == 3000002));
    }

    #[test]
    fn test_smtp_null_byte() {
        let payload = b"EHLO test\x00.com\r\n";
        let anomalies = analyze_smtp(payload);
        assert!(anomalies.iter().any(|a| a.id == 3000004));
    }

    #[test]
    fn test_dns_oversized() {
        let payload = vec![0u8; 600]; // oversized
        let anomalies = analyze_dns(&payload);
        assert!(anomalies.iter().any(|a| a.id == 3000010));
    }

    #[test]
    fn test_tls_sslv3() {
        // TLS record with SSLv3 version
        let payload = [22, 0x03, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let anomalies = analyze_tls(&payload);
        assert!(anomalies.iter().any(|a| a.id == 3000020));
    }

    #[test]
    fn test_smtp_bare_cr() {
        let payload = b"EHLO test.com\rMAIL FROM:<a@b.com>\r\n";
        let anomalies = analyze_smtp(payload);
        assert!(anomalies.iter().any(|a| a.id == 3000005));
    }

    #[test]
    fn test_dns_bad_pointer_offset() {
        let payload = vec![
            // Header (12 bytes)
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Name pointer to offset 0x3FFF (out of bounds)
            0xFF, 0xFF,
        ];
        let anomalies = analyze_dns(&payload);
        assert!(anomalies.iter().any(|a| a.id == 3000012));
    }

    #[test]
    fn test_tls_truncated_record() {
        // Declares 16 bytes payload but provides only 2.
        let payload = [22, 0x03, 0x03, 0x00, 0x10, 0x01, 0x00];
        let anomalies = analyze_tls(&payload);
        assert!(anomalies.iter().any(|a| a.id == 3000023));
    }
}
