//! Microsoft Smart Network Data Services (SNDS) client.
//!
//! Endpoint: `https://sendersupport.olc.protection.outlook.com/snds/data.aspx?key=...`
//!
//! Returns CSV: one row per (IP, day) with columns:
//!   `ip,activityStart,activityEnd,rcpt_commands,data_commands,
//!    message_recipients,filter_result,complaint_rate,trap_message_count,
//!    sample_helo,sample_mail_from`
//!
//! filter_result is one of GREEN | YELLOW | RED; complaint_rate is a "<1"-style
//! string in some rows (Microsoft caps the lower bound).

use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use reqwest::Client;
use sqlx::PgPool;
use tracing::{debug, info, warn};

use super::SndsRecord;

const SNDS_DATA_URL: &str = "https://sendersupport.olc.protection.outlook.com/snds/data.aspx";

#[derive(Debug, Clone)]
pub struct SndsCredentials {
    pub access_key: String,
}

pub struct SndsClient {
    http: Client,
    creds: SndsCredentials,
}

impl SndsClient {
    pub fn new(creds: SndsCredentials) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| format!("HTTP build: {e}"))?;
        Ok(Self { http, creds })
    }

    /// Pull the SNDS CSV and parse into records.  An empty body is a valid
    /// "no traffic this period" response.
    pub async fn fetch(&self) -> Result<Vec<SndsRecord>, String> {
        let resp = self
            .http
            .get(SNDS_DATA_URL)
            .query(&[("key", self.creds.access_key.as_str())])
            .send()
            .await
            .map_err(|e| format!("SNDS request: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("SNDS {status}: {body}"));
        }
        let body = resp.text().await.map_err(|e| format!("SNDS body: {e}"))?;
        Ok(parse_csv(&body))
    }
}

/// Parse a SNDS CSV body. Malformed rows are skipped with a warn.
pub fn parse_csv(body: &str) -> Vec<SndsRecord> {
    let mut out = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        match parse_row(line) {
            Ok(r) => out.push(r),
            Err(e) => warn!(line, error = %e, "SNDS row parse failed"),
        }
    }
    out
}

fn parse_row(line: &str) -> Result<SndsRecord, String> {
    // SNDS commas inside sample_from are escaped with quoting on Microsoft's
    // side but in practice their CSV is comma-separated unquoted; if a sample
    // contains a comma it's truncated.  We match their format exactly.
    let fields: Vec<&str> = line.split(',').collect();
    if fields.len() < 9 {
        return Err(format!("expected >=9 columns, got {}", fields.len()));
    }
    let ip =
        IpAddr::from_str(fields[0].trim()).map_err(|e| format!("bad ip {}: {e}", fields[0]))?;
    let activity_start = parse_dt(fields[1]);
    let activity_end = parse_dt(fields[2]);
    let observed_at = activity_start
        .map(|d| d.date_naive())
        .or_else(|| activity_end.map(|d| d.date_naive()))
        .unwrap_or_else(|| Utc::now().date_naive());
    let rcpt_commands = fields[3].trim().parse::<i64>().unwrap_or(0);
    let data_commands = fields[4].trim().parse::<i64>().unwrap_or(0);
    let message_recipients = fields[5].trim().parse::<i64>().unwrap_or(0);
    let filter_result = match fields[6].trim() {
        "" | "-" => None,
        s => Some(s.to_string()),
    };
    let complaint_rate = parse_complaint(fields[7]);
    let trap_hits = fields[8].trim().parse::<i64>().unwrap_or(0);
    let sample_helo = fields
        .get(9)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let sample_from = fields
        .get(10)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Ok(SndsRecord {
        ip,
        observed_at,
        activity_start,
        activity_end,
        rcpt_commands,
        data_commands,
        message_recipients,
        filter_result,
        complaint_rate,
        trap_hits,
        sample_helo,
        sample_from,
        raw: serde_json::Value::String(line.to_string()),
    })
}

fn parse_dt(s: &str) -> Option<DateTime<Utc>> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    // Format used by SNDS: "M/D/YYYY h:MM:SS [AM|PM]" in UTC.
    for fmt in [
        "%-m/%-d/%Y %-I:%M:%S %p",
        "%-m/%-d/%Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(t, fmt) {
            return Utc.from_local_datetime(&ndt).single();
        }
    }
    // Fallback: try a date-only field.
    if let Ok(d) = NaiveDate::parse_from_str(t, "%Y-%m-%d") {
        return d
            .and_hms_opt(0, 0, 0)
            .and_then(|n| Utc.from_local_datetime(&n).single());
    }
    None
}

/// SNDS reports complaint rate as either an empty string, "<1", or a percent
/// like "0.5" or "0.05".  We normalise to a 0..=1 fraction; "<1" becomes 0.005.
fn parse_complaint(s: &str) -> Option<f64> {
    let t = s.trim().trim_end_matches('%');
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.strip_prefix('<') {
        // "<1" means strictly less than 1%, treat as half that.
        return rest.parse::<f64>().ok().map(|v| (v / 2.0) / 100.0);
    }
    let v: f64 = t.parse().ok()?;
    // Heuristic: values <=1 are already fractions; >1 are percentages.
    Some(if v <= 1.0 { v } else { v / 100.0 })
}

pub async fn upsert_records(db: &PgPool, rows: &[SndsRecord]) -> Result<usize, String> {
    let mut n = 0;
    for r in rows {
        let ip_str = r.ip.to_string();
        sqlx::query(
            "INSERT INTO postmaster_snds_reputation
               (ip, observed_at, activity_start, activity_end, rcpt_commands,
                data_commands, message_recipients, filter_result,
                complaint_rate, trap_hits, sample_helo, sample_from, raw, fetched_at)
             VALUES ($1::inet, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
             ON CONFLICT (ip, observed_at) DO UPDATE SET
               activity_start = EXCLUDED.activity_start,
               activity_end = EXCLUDED.activity_end,
               rcpt_commands = EXCLUDED.rcpt_commands,
               data_commands = EXCLUDED.data_commands,
               message_recipients = EXCLUDED.message_recipients,
               filter_result = EXCLUDED.filter_result,
               complaint_rate = EXCLUDED.complaint_rate,
               trap_hits = EXCLUDED.trap_hits,
               sample_helo = EXCLUDED.sample_helo,
               sample_from = EXCLUDED.sample_from,
               raw = EXCLUDED.raw,
               fetched_at = NOW()",
        )
        .bind(&ip_str)
        .bind(r.observed_at)
        .bind(r.activity_start)
        .bind(r.activity_end)
        .bind(r.rcpt_commands)
        .bind(r.data_commands)
        .bind(r.message_recipients)
        .bind(&r.filter_result)
        .bind(r.complaint_rate)
        .bind(r.trap_hits)
        .bind(&r.sample_helo)
        .bind(&r.sample_from)
        .bind(&r.raw)
        .execute(db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        n += 1;
    }
    debug!(rows = n, "SNDS records upserted");
    Ok(n)
}

pub async fn ingest_all(db: &PgPool, client: &SndsClient) -> Result<usize, String> {
    let rows = client.fetch().await?;
    info!(rows = rows.len(), "SNDS: starting ingest");
    let n = upsert_records(db, &rows).await?;
    info!(rows = n, "SNDS: ingest complete");
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_row() {
        let line =
            "1.2.3.4,1/15/2026 0:00:00 AM,1/16/2026 0:00:00 AM,1000,950,2500,GREEN,<1,0,smtp.example.com,foo@example.com";
        let row = parse_row(line).expect("parse");
        assert_eq!(row.ip, IpAddr::from([1u8, 2, 3, 4]));
        assert_eq!(row.rcpt_commands, 1000);
        assert_eq!(row.filter_result.as_deref(), Some("GREEN"));
        assert!(row.complaint_rate.unwrap() <= 0.01);
        assert_eq!(row.sample_helo.as_deref(), Some("smtp.example.com"));
    }

    #[test]
    fn complaint_rate_fraction() {
        assert_eq!(parse_complaint("0.05"), Some(0.05));
        assert_eq!(parse_complaint("5"), Some(0.05));
        assert_eq!(parse_complaint("5%"), Some(0.05));
        assert_eq!(parse_complaint("<1"), Some(0.005));
        assert_eq!(parse_complaint(""), None);
    }

    #[test]
    fn skips_empty_body() {
        assert!(parse_csv("").is_empty());
        assert!(parse_csv("\n\n").is_empty());
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Malformed SNDS feeds must degrade to zeroed/skipped rows — never a
    //! panic, never a bogus reputation signal — and the upsert must be
    //! idempotent per (ip, day).

    use super::*;

    fn record(ip: &str, filter: &str, rate: f64) -> SndsRecord {
        SndsRecord {
            ip: ip.parse().unwrap(),
            observed_at: NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            activity_start: None,
            activity_end: None,
            rcpt_commands: 10,
            data_commands: 9,
            message_recipients: 8,
            filter_result: Some(filter.to_string()),
            complaint_rate: Some(rate),
            trap_hits: 1,
            sample_helo: None,
            sample_from: None,
            raw: serde_json::json!({"row": "fixture"}),
        }
    }

    #[test]
    fn client_construction_accepts_any_key() {
        assert!(SndsClient::new(SndsCredentials {
            access_key: "k".into()
        })
        .is_ok());
    }

    #[test]
    fn malformed_rows_are_skipped_not_panicking() {
        // Too few columns, bad IP, blank lines.
        assert!(parse_csv("1.2.3.4,1,2,3").is_empty());
        assert!(
            parse_csv("not-an-ip,1/15/2026 0:00:00 AM,1/16/2026 0:00:00 AM,1,1,1,GREEN,0,0")
                .is_empty()
        );
        assert!(parse_csv("   ").is_empty());

        // A parseable row with garbage numerics degrades to zeros, and an
        // unparseable date falls back to "today" (never an error).
        let row = parse_row("1.2.3.4,x,y,n/a,n/a,n/a,-,weird,n/a").expect("ip is enough");
        assert_eq!(row.rcpt_commands, 0);
        assert_eq!(row.data_commands, 0);
        assert_eq!(row.message_recipients, 0);
        assert!(row.filter_result.is_none(), "'-' means no verdict");
        assert!(row.complaint_rate.is_none());
        assert!(row.activity_start.is_none());
        assert_eq!(row.observed_at, Utc::now().date_naive());
    }

    #[test]
    fn date_formats_and_complaint_scales_are_normalised() {
        assert!(parse_dt("").is_none());
        assert!(parse_dt("not a date").is_none());
        assert!(parse_dt("2026-01-15").is_some(), "date-only fallback");
        assert!(parse_dt("2026-01-15 10:30:00").is_some());
        assert!(parse_dt("2026-01-15T10:30:00Z").is_some());
        assert!(parse_dt("1/15/2026 10:30:00 AM").is_some());

        assert_eq!(parse_complaint("<1%"), Some(0.005));
        assert_eq!(parse_complaint(" 0.5 "), Some(0.5));
        assert_eq!(parse_complaint("100"), Some(1.0));
        assert_eq!(parse_complaint("-"), None);
        assert_eq!(parse_complaint("banana"), None);
    }

    #[tokio::test]
    async fn upsert_is_idempotent_per_ip_and_day() {
        let pool = match migrator::test_support::fresh_canonical_pool("snds_upsert", "snds_upsert")
            .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => return,
            Err(error) => panic!("{}", error.panic_message()),
        };

        let ip = format!("203.0.113.{}", 1 + (std::process::id() % 200) as u8);
        let first = record(&ip, "GREEN", 0.001);
        assert_eq!(
            upsert_records(&pool, std::slice::from_ref(&first))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            upsert_records(&pool, std::slice::from_ref(&first))
                .await
                .unwrap(),
            1
        );

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM postmaster_snds_reputation WHERE ip = $1::inet",
        )
        .bind(&ip)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "the same (ip, day) upserts in place");

        // A RED verdict for the same day REPLACES the fields (no stale GREEN).
        let red = SndsRecord {
            filter_result: Some("RED".into()),
            complaint_rate: Some(0.05),
            trap_hits: 42,
            raw: serde_json::json!({"row": "updated"}),
            ..first
        };
        assert_eq!(upsert_records(&pool, &[red]).await.unwrap(), 1);
        let (filter, rate, traps): (Option<String>, Option<f64>, i64) = sqlx::query_as(
            "SELECT filter_result, complaint_rate, trap_hits \
             FROM postmaster_snds_reputation WHERE ip = $1::inet",
        )
        .bind(&ip)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(filter.as_deref(), Some("RED"));
        assert_eq!(rate, Some(0.05));
        assert_eq!(traps, 42);

        // An empty batch is a no-op.
        assert_eq!(upsert_records(&pool, &[]).await.unwrap(), 0);
        pool.close().await;
    }
}
