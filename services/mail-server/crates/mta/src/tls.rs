//! TLS certificate inspection, production fail-fast, and expiry alarms.
//!
//! Policy:
//! * **Port 25 stays opportunistic STARTTLS** — a missing certificate must
//!   not stop inbound mail (and the binary logs the no-TLS state loudly at
//!   WARN plus exposes `apexmail_mta_tls_enabled` = 0).
//! * **Submission (AUTH) in production must not start without a usable
//!   certificate**: missing file, unparseable PEM, not-yet-valid, or expired
//!   certificate is a startup failure ([`enforce_submission_tls_production`]).
//! * **Expiry alarms** at 30/14/7/1 days ([`cert_expiry_alarm`]): the
//!   tightest crossed threshold is reported once per check; the binary
//!   schedules the check periodically and emits structured logs plus
//!   `apexmail_mta_tls_cert_expiry_alarm_total{alarm="..."}` counters and an
//!   `apexmail_mta_tls_cert_days_remaining` gauge.

use std::io::BufReader;
use std::path::Path;

use anyhow::Context;
use x509_parser::prelude::*;

/// Alarm thresholds in days remaining, tightest first.
pub const CERT_EXPIRY_ALARM_THRESHOLDS_DAYS: [i64; 4] = [1, 7, 14, 30];

/// Relaxed (non-production) restart warning: warn this far ahead.
pub const CERT_EXPIRY_WARN_DAYS: i64 = 30;

/// Which expiry threshold a certificate has crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertExpiryAlarm {
    Days30,
    Days14,
    Days7,
    Day1,
}

impl CertExpiryAlarm {
    pub fn threshold_days(&self) -> i64 {
        match self {
            Self::Days30 => 30,
            Self::Days14 => 14,
            Self::Days7 => 7,
            Self::Day1 => 1,
        }
    }

    /// Stable label for metrics/log aggregation.
    pub fn metric_label(&self) -> &'static str {
        match self {
            Self::Days30 => "30d",
            Self::Days14 => "14d",
            Self::Days7 => "7d",
            Self::Day1 => "1d",
        }
    }

    /// Documented operator-visible level: WARN at 30/14/7 days, ERROR at
    /// 1 day (renewal is now urgent and mail will bounce when it lapses).
    pub fn is_error(&self) -> bool {
        matches!(self, Self::Day1)
    }
}

/// Tightest alarm threshold crossed by `days_remaining` (an expiry in the
/// past reports the 1-day alarm — the loudest).
pub fn cert_expiry_alarm(days_remaining: i64) -> Option<CertExpiryAlarm> {
    if days_remaining <= 1 {
        Some(CertExpiryAlarm::Day1)
    } else if days_remaining <= 7 {
        Some(CertExpiryAlarm::Days7)
    } else if days_remaining <= 14 {
        Some(CertExpiryAlarm::Days14)
    } else if days_remaining <= 30 {
        Some(CertExpiryAlarm::Days30)
    } else {
        None
    }
}

/// Result of inspecting one certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateExpiry {
    pub not_before: i64,
    pub not_after: i64,
    pub days_remaining: i64,
}

impl CertificateExpiry {
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.not_after
    }

    pub fn is_not_yet_valid(&self, now_unix: i64) -> bool {
        now_unix < self.not_before
    }
}

/// Parse one DER certificate and compute its validity window.
pub fn inspect_certificate_der(der: &[u8], now_unix: i64) -> anyhow::Result<CertificateExpiry> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| anyhow::anyhow!("invalid X.509 certificate: {e}"))?;
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    Ok(CertificateExpiry {
        not_before,
        not_after,
        // Floor division: 0 means "less than a day remains".
        days_remaining: (not_after - now_unix).div_euclid(86_400),
    })
}

/// Read every PEM certificate from `cert_path` as DER.
pub fn load_certificates_der(cert_path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let file = std::fs::File::open(cert_path)
        .with_context(|| format!("cannot open certificate {}", cert_path.display()))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<Vec<u8>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("cannot parse PEM certificates in {}", cert_path.display()))?
        .into_iter()
        .map(|der| der.as_ref().to_vec())
        .collect();
    if certs.is_empty() {
        anyhow::bail!(
            "no certificates found in {} (expected PEM CERTIFICATE blocks)",
            cert_path.display()
        );
    }
    Ok(certs)
}

/// Inspect the FIRST certificate of a PEM chain (the leaf).
pub fn inspect_certificate_file(
    cert_path: &Path,
    now_unix: i64,
) -> anyhow::Result<CertificateExpiry> {
    let certs = load_certificates_der(cert_path)?;
    inspect_certificate_der(&certs[0], now_unix)
}

/// Production submission TLS gate.
///
/// When `production && submission_enabled`, the submission listener accepts
/// AUTH and therefore requires a usable certificate: the file must exist,
/// parse, be currently valid, and not be expired. Returns the inspected
/// expiry on success; any violation is an error the caller must treat as a
/// startup failure.
pub fn enforce_submission_tls_production(
    production: bool,
    submission_enabled: bool,
    tls_enabled: bool,
    cert_path: Option<&str>,
    now_unix: i64,
) -> anyhow::Result<Option<CertificateExpiry>> {
    if !(production && submission_enabled) {
        return Ok(None);
    }
    if !tls_enabled {
        anyhow::bail!(
            "refusing to start submission in production without TLS: configure TLS_ENABLED=true \
             and a valid TLS_CERT_PATH/TLS_KEY_PATH (submission accepts AUTH and must offer \
             STARTTLS)"
        );
    }
    let cert_path = cert_path.ok_or_else(|| {
        anyhow::anyhow!("refusing to start submission in production: TLS_CERT_PATH is not set")
    })?;
    let expiry = inspect_certificate_file(Path::new(cert_path), now_unix).with_context(|| {
        format!(
            "refusing to start submission in production: submission TLS certificate {cert_path} \
             is missing or invalid"
        )
    })?;
    if expiry.is_not_yet_valid(now_unix) {
        anyhow::bail!(
            "refusing to start submission in production: certificate {cert_path} is not valid \
             before {} (now {now_unix})",
            expiry.not_before
        );
    }
    if expiry.is_expired(now_unix) {
        anyhow::bail!(
            "refusing to start submission in production: certificate {cert_path} expired at {}",
            expiry.not_after
        );
    }
    Ok(Some(expiry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};

    fn now() -> i64 {
        Utc::now().timestamp()
    }

    fn self_signed_expiring_in(days: i64) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["mail.apexmail.ee".to_string()])
            .expect("valid rcgen params");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        let not_after = Utc::now() + ChronoDuration::days(days);
        params.not_after = rcgen::date_time_ymd(
            not_after.format("%Y").to_string().parse().unwrap(),
            not_after.format("%m").to_string().parse().unwrap(),
            not_after.format("%d").to_string().parse().unwrap(),
        );
        let key = rcgen::KeyPair::generate().expect("key generation");
        let cert = params.self_signed(&key).expect("self-signed cert");
        cert.der().as_ref().to_vec()
    }

    #[test]
    fn alarm_thresholds_are_30_14_7_and_1_days() {
        assert_eq!(cert_expiry_alarm(31), None);
        assert_eq!(cert_expiry_alarm(30), Some(CertExpiryAlarm::Days30));
        assert_eq!(cert_expiry_alarm(20), Some(CertExpiryAlarm::Days30));
        // 15 days has crossed the 30-day threshold but not the 14-day one:
        // the tightest crossed threshold is reported.
        assert_eq!(cert_expiry_alarm(15), Some(CertExpiryAlarm::Days30));
        assert_eq!(cert_expiry_alarm(14), Some(CertExpiryAlarm::Days14));
        assert_eq!(cert_expiry_alarm(8), Some(CertExpiryAlarm::Days14));
        assert_eq!(cert_expiry_alarm(7), Some(CertExpiryAlarm::Days7));
        assert_eq!(cert_expiry_alarm(6), Some(CertExpiryAlarm::Days7));
        assert_eq!(cert_expiry_alarm(2), Some(CertExpiryAlarm::Days7));
        assert_eq!(cert_expiry_alarm(1), Some(CertExpiryAlarm::Day1));
        assert_eq!(cert_expiry_alarm(0), Some(CertExpiryAlarm::Day1));
        assert_eq!(cert_expiry_alarm(-5), Some(CertExpiryAlarm::Day1));
        assert!(!CertExpiryAlarm::Days30.is_error());
        assert!(!CertExpiryAlarm::Days7.is_error());
        assert!(
            CertExpiryAlarm::Day1.is_error(),
            "1-day alarm is ERROR level"
        );
    }

    #[test]
    fn certificate_expiring_inside_threshold_produces_the_alarm() {
        // Real self-signed cert expiring ~20 days out: inspect -> Days30.
        let der = self_signed_expiring_in(20);
        let expiry = inspect_certificate_der(&der, now()).expect("parse generated cert");
        assert!(
            (19..=20).contains(&expiry.days_remaining),
            "unexpected remaining days: {}",
            expiry.days_remaining
        );
        assert_eq!(
            cert_expiry_alarm(expiry.days_remaining),
            Some(CertExpiryAlarm::Days30),
            "a certificate inside the 30-day window must raise the alarm"
        );
        assert!(!expiry.is_expired(now()));
    }

    #[test]
    fn certificate_expiring_in_3_days_reports_the_7_day_alarm() {
        let der = self_signed_expiring_in(3);
        let expiry = inspect_certificate_der(&der, now()).expect("parse generated cert");
        assert_eq!(
            cert_expiry_alarm(expiry.days_remaining),
            Some(CertExpiryAlarm::Days7)
        );
    }

    #[test]
    fn far_future_certificate_has_no_alarm() {
        let der = self_signed_expiring_in(200);
        let expiry = inspect_certificate_der(&der, now()).expect("parse generated cert");
        assert_eq!(cert_expiry_alarm(expiry.days_remaining), None);
    }

    #[test]
    fn production_submission_gate_fails_fast_on_missing_invalid_and_expired() {
        let now = now();

        // Not production: no gate.
        assert!(enforce_submission_tls_production(false, true, false, None, now).is_ok());

        // Production + submission + TLS disabled -> startup failure.
        let err = enforce_submission_tls_production(true, true, false, None, now).unwrap_err();
        assert!(err.to_string().contains("without TLS"));

        // Production + submission + TLS enabled but no cert path.
        let err = enforce_submission_tls_production(true, true, true, None, now).unwrap_err();
        assert!(err.to_string().contains("TLS_CERT_PATH"));

        // Missing file.
        let err = enforce_submission_tls_production(
            true,
            true,
            true,
            Some("/nonexistent/mta-cert.pem"),
            now,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("missing or invalid"));

        // Expired certificate.
        let dir = std::env::temp_dir().join(format!("mta-tls-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("expired.pem");
        let der = self_signed_expiring_in(-1);
        let expired_pem = pem(&der);
        std::fs::write(&cert_path, expired_pem).unwrap();
        let err = enforce_submission_tls_production(
            true,
            true,
            true,
            Some(cert_path.to_str().unwrap()),
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");

        // Live certificate passes.
        let live_path = dir.join("live.pem");
        std::fs::write(&live_path, pem(&self_signed_expiring_in(60))).unwrap();
        assert!(enforce_submission_tls_production(
            true,
            true,
            true,
            Some(live_path.to_str().unwrap()),
            now,
        )
        .unwrap()
        .is_some());

        std::fs::remove_dir_all(&dir).ok();
    }

    fn pem(der: &[u8]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }
}
