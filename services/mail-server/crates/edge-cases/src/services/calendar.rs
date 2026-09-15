//! Calendar service – iCal generation, parsing, HTML preview (RFC 5545).

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalendarMethod {
    Request,
    Reply,
    Cancel,
    Refresh,
    Counter,
    DeclineCounter,
    Add,
    Publish,
}

impl CalendarMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "REQUEST",
            Self::Reply => "REPLY",
            Self::Cancel => "CANCEL",
            Self::Refresh => "REFRESH",
            Self::Counter => "COUNTER",
            Self::DeclineCounter => "DECLINECOUNTER",
            Self::Add => "ADD",
            Self::Publish => "PUBLISH",
        }
    }
    /// Parse a calendar METHOD string (RFC 5546 §3.2).
    ///
    /// # O-21.4 — Allowlist enforcement
    /// Only the eight IANA-registered iCalendar methods are accepted:
    /// `PUBLISH`, `REQUEST`, `REPLY`, `ADD`, `CANCEL`, `REFRESH`,
    /// `COUNTER`, `DECLINECOUNTER`.
    ///
    /// Any unrecognised or malformed method string is rejected with an
    /// error, preventing injection of arbitrary method values into
    /// downstream iCal processing.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_uppercase().as_str() {
            "REQUEST" => Ok(Self::Request),
            "REPLY" => Ok(Self::Reply),
            "CANCEL" => Ok(Self::Cancel),
            "REFRESH" => Ok(Self::Refresh),
            "COUNTER" => Ok(Self::Counter),
            "DECLINECOUNTER" => Ok(Self::DeclineCounter),
            "ADD" => Ok(Self::Add),
            "PUBLISH" => Ok(Self::Publish),
            _ => Err(format!("Unknown calendar method: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalendarStatus {
    Tentative,
    Confirmed,
    Cancelled,
}

impl CalendarStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tentative => "TENTATIVE",
            Self::Confirmed => "CONFIRMED",
            Self::Cancelled => "CANCELLED",
        }
    }
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "TENTATIVE" => Self::Tentative,
            "CANCELLED" => Self::Cancelled,
            _ => Self::Confirmed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attendee {
    pub email: String,
    pub name: Option<String>,
    pub role: String,
    pub part_stat: String,
    pub rsvp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organizer {
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurrenceRule {
    pub freq: String,
    pub interval: Option<u32>,
    pub count: Option<u32>,
    pub until: Option<String>,
    pub by_day: Option<Vec<String>>,
    pub by_month: Option<Vec<u32>>,
    pub by_month_day: Option<Vec<i32>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub uid: String,
    pub summary: String,
    pub description: Option<String>,
    pub location: Option<String>,
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub all_day: bool,
    pub timezone: Option<String>,
    pub organizer: Organizer,
    pub attendees: Vec<Attendee>,
    pub method: CalendarMethod,
    pub status: CalendarStatus,
    pub sequence: u32,
    pub created: DateTime<Utc>,
    pub last_modified: DateTime<Utc>,
    pub url: Option<String>,
    pub categories: Option<Vec<String>>,
    pub priority: Option<u32>,
    pub recurrence: Option<RecurrenceRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarInvite {
    pub event: CalendarEvent,
    pub ics_content: String,
    pub html_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCalendar {
    pub events: Vec<CalendarEvent>,
    pub method: CalendarMethod,
    pub product_id: String,
}

// ── service ────────────────────────────────────────────────────────────────────

pub struct CalendarService {
    pool: PgPool,
}

impl CalendarService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a calendar invite.
    #[allow(clippy::too_many_arguments)]
    pub fn create_invite(
        &self,
        summary: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        organizer: Organizer,
        attendees: Vec<Attendee>,
        description: Option<String>,
        location: Option<String>,
        method: CalendarMethod,
        all_day: bool,
    ) -> anyhow::Result<CalendarInvite> {
        let now = Utc::now();
        let uid = format!("{}@apexmail.ee", Uuid::new_v4());

        let event = CalendarEvent {
            uid,
            summary: summary.to_string(),
            description,
            location,
            start,
            end,
            all_day,
            timezone: None,
            organizer,
            attendees,
            method,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: now,
            last_modified: now,
            url: None,
            categories: None,
            priority: None,
            recurrence: None,
        };

        let ics_content = generate_ics(&event);
        let html_preview = generate_html_preview(&event);

        Ok(CalendarInvite {
            event,
            ics_content,
            html_preview,
        })
    }

    /// Parse ICS content.
    pub fn parse_ics(&self, content: &str) -> anyhow::Result<ParsedCalendar> {
        parse_ics_content(content)
    }

    /// Check if content type is calendar.
    pub fn is_calendar_content_type(content_type: &str) -> bool {
        let lower = content_type.to_lowercase();
        crate::config::CALENDAR_CONTENT_TYPES
            .iter()
            .any(|ct| lower.contains(ct))
    }

    /// Store event in DB.
    pub async fn store_event(&self, message_id: &str, event: &CalendarEvent) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO edge_calendar_events
               (id, message_id, uid, summary, organizer_email, start_time, end_time,
                location, method, status, attendee_count, created_at)
               VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())"#,
        )
        .bind(message_id)
        .bind(&event.uid)
        .bind(&event.summary)
        .bind(&event.organizer.email)
        .bind(event.start)
        .bind(event.end)
        .bind(&event.location)
        .bind(event.method.as_str())
        .bind(event.status.as_str())
        .bind(event.attendees.len() as i32)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ── ICS generation ─────────────────────────────────────────────────────────────

/// Generate RFC 5545 ICS content.
pub fn generate_ics(event: &CalendarEvent) -> String {
    let mut lines = Vec::new();
    lines.push("BEGIN:VCALENDAR".to_string());
    lines.push("VERSION:2.0".to_string());
    lines.push("PRODID:- //ApexMail//Calendar//EN".to_string());
    lines.push(format!("METHOD:{}", event.method.as_str()));
    lines.push("CALSCALE:GREGORIAN".to_string());

    lines.push("BEGIN:VEVENT".to_string());
    lines.push(format!("UID:{}", escape_ics(&event.uid)));
    lines.push(format!("SUMMARY:{}", escape_ics(&event.summary)));

    if let Some(ref desc) = event.description {
        lines.push(format!("DESCRIPTION:{}", escape_ics(desc)));
    }
    if let Some(ref loc) = event.location {
        lines.push(format!("LOCATION:{}", escape_ics(loc)));
    }

    if event.all_day {
        lines.push(format!(
            "DTSTART;VALUE=DATE:{}",
            format_date_only(&event.start)
        ));
        lines.push(format!("DTEND;VALUE=DATE:{}", format_date_only(&event.end)));
    } else {
        lines.push(format!("DTSTART:{}", format_datetime(&event.start)));
        lines.push(format!("DTEND:{}", format_datetime(&event.end)));
    }

    lines.push(format!("STATUS:{}", event.status.as_str()));
    lines.push(format!("SEQUENCE:{}", event.sequence));
    lines.push(format!("DTSTAMP:{}", format_datetime(&event.created)));
    lines.push(format!("CREATED:{}", format_datetime(&event.created)));
    lines.push(format!(
        "LAST-MODIFIED:{}",
        format_datetime(&event.last_modified)
    ));

    // Organizer — every interpolated value is ICS-escaped (F5): CN values
    // and mailto addresses previously went in raw, so a name containing
    // CR/LF/`:`/`;`/`,` could inject arbitrary properties into the ICS.
    if let Some(ref name) = event.organizer.name {
        lines.push(format!(
            "ORGANIZER;CN={}:mailto:{}",
            escape_ics(name),
            escape_ics(&event.organizer.email)
        ));
    } else {
        lines.push(format!(
            "ORGANIZER:mailto:{}",
            escape_ics(&event.organizer.email)
        ));
    }

    // Attendees — same escaping for CN, ROLE, PARTSTAT and the address.
    for att in &event.attendees {
        let mut params = Vec::new();
        if let Some(ref name) = att.name {
            params.push(format!("CN={}", escape_ics(name)));
        }
        params.push(format!("ROLE={}", escape_ics(&att.role)));
        params.push(format!("PARTSTAT={}", escape_ics(&att.part_stat)));
        params.push(format!("RSVP={}", if att.rsvp { "TRUE" } else { "FALSE" }));
        lines.push(format!(
            "ATTENDEE;{}:mailto:{}",
            params.join(";"),
            escape_ics(&att.email)
        ));
    }

    // URL (validate scheme) — the URL body is still escaped so a newline in
    // the path cannot terminate the property line.
    if let Some(ref url) = event.url {
        if url.starts_with("http://") || url.starts_with("https://") {
            lines.push(format!("URL:{}", escape_ics(url)));
        }
    }

    // Categories — escape each category; the list separator ',' stays real.
    if let Some(ref cats) = event.categories {
        if !cats.is_empty() {
            let escaped: Vec<String> = cats.iter().map(|c| escape_ics(c)).collect();
            lines.push(format!("CATEGORIES:{}", escaped.join(",")));
        }
    }

    // Priority
    if let Some(pri) = event.priority {
        lines.push(format!("PRIORITY:{pri}"));
    }

    // Recurrence
    if let Some(ref rrule) = event.recurrence {
        lines.push(generate_rrule(rrule));
    }

    lines.push("END:VEVENT".to_string());
    lines.push("END:VCALENDAR".to_string());

    fold_lines(&lines.join("\r\n"))
}

fn generate_rrule(rule: &RecurrenceRule) -> String {
    // String components (freq, until, BYDAY labels) come from user input and
    // are escaped (F5) so they cannot break out of the RRULE property.
    let mut parts = vec![format!("FREQ={}", escape_ics(&rule.freq.to_uppercase()))];
    if let Some(interval) = rule.interval {
        parts.push(format!("INTERVAL={interval}"));
    }
    if let Some(count) = rule.count {
        parts.push(format!("COUNT={count}"));
    }
    if let Some(ref until) = rule.until {
        parts.push(format!("UNTIL={}", escape_ics(until)));
    }
    if let Some(ref days) = rule.by_day {
        let escaped: Vec<String> = days.iter().map(|d| escape_ics(d)).collect();
        parts.push(format!("BYDAY={}", escaped.join(",")));
    }
    if let Some(ref months) = rule.by_month {
        parts.push(format!(
            "BYMONTH={}",
            months
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(ref days) = rule.by_month_day {
        parts.push(format!(
            "BYMONTHDAY={}",
            days.iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    format!("RRULE:{}", parts.join(";"))
}

/// RFC 5545 line folding at 75 characters.
fn fold_lines(content: &str) -> String {
    let mut result = String::new();
    for line in content.split("\r\n") {
        if line.chars().count() <= 75 {
            result.push_str(line);
            result.push_str("\r\n");
        } else {
            let mut remaining = line;
            let mut first = true;
            while !remaining.is_empty() {
                let max = if first { 75 } else { 74 }; // continuation line has leading space
                let (head, tail) = split_at_char_boundary(remaining, max);
                if !first {
                    result.push(' ');
                }
                result.push_str(head);
                result.push_str("\r\n");
                remaining = tail;
                first = false;
            }
        }
    }
    result
}

fn split_at_char_boundary(s: &str, max_chars: usize) -> (&str, &str) {
    let mut count = 0usize;
    let mut split_idx = s.len();
    for (idx, _) in s.char_indices() {
        if count == max_chars {
            split_idx = idx;
            break;
        }
        count += 1;
    }
    if count < max_chars {
        split_idx = s.len();
    }
    (&s[..split_idx], &s[split_idx..])
}

/// Escape a TEXT value per RFC 5545 §3.3.11 (`\` `;` `,` and newlines).
///
/// F5: `\r` (bare or as part of CRLF) is ALSO neutralized — a raw CR or LF
/// in an interpolated value would terminate the property line and allow
/// CRLF injection of arbitrary ICS properties (e.g. `URL:evil`).
fn escape_ics(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\n' | '\r' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn unescape_ics(text: &str) -> String {
    text.replace("\\n", "\n")
        .replace("\\;", ";")
        .replace("\\,", ",")
        .replace("\\\\", "\\")
}

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn format_datetime(dt: &DateTime<Utc>) -> String {
    dt.format("%Y%m%dT%H%M%SZ").to_string()
}

fn format_date_only(dt: &DateTime<Utc>) -> String {
    dt.format("%Y%m%d").to_string()
}

// ── ICS parsing ────────────────────────────────────────────────────────────────

fn parse_ics_content(content: &str) -> anyhow::Result<ParsedCalendar> {
    // Unfold continuation lines
    let unfolded = content.replace("\r\n ", "").replace("\r\n\t", "");

    let mut events = Vec::new();
    let mut method = CalendarMethod::Publish;
    let mut product_id = String::new();
    let mut in_event = false;
    let mut current: Option<CalendarEventBuilder> = None;

    for line in unfolded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line == "BEGIN:VEVENT" {
            in_event = true;
            current = Some(CalendarEventBuilder::new());
            continue;
        }
        if line == "END:VEVENT" {
            if let Some(builder) = current.take() {
                if let Ok(mut event) = builder.build() {
                    event.method = method;
                    events.push(event);
                }
            }
            in_event = false;
            continue;
        }

        // Extract property name and value
        let (prop_with_params, value) = match line.split_once(':') {
            Some((p, v)) => (p, v),
            None => continue,
        };
        let (prop, _params) = prop_with_params
            .split_once(';')
            .unwrap_or((prop_with_params, ""));

        if !in_event {
            match prop {
                "METHOD" => {
                    method = CalendarMethod::from_str(value).map_err(|e| anyhow::anyhow!(e))?
                }
                "PRODID" => product_id = value.to_string(),
                _ => {}
            }
        } else if let Some(ref mut builder) = current {
            match prop {
                "UID" => builder.uid = Some(value.to_string()),
                "SUMMARY" => builder.summary = Some(unescape_ics(value)),
                "DESCRIPTION" => builder.description = Some(unescape_ics(value)),
                "LOCATION" => builder.location = Some(unescape_ics(value)),
                "DTSTART" => builder.start = parse_ics_datetime(value),
                "DTEND" => builder.end = parse_ics_datetime(value),
                "STATUS" => builder.status = Some(CalendarStatus::from_str(value)),
                "SEQUENCE" => builder.sequence = value.parse().ok(),
                "CREATED" => builder.created = parse_ics_datetime(value),
                "LAST-MODIFIED" => builder.last_modified = parse_ics_datetime(value),
                "URL" => builder.url = Some(value.to_string()),
                "ORGANIZER" => {
                    let email = value.strip_prefix("mailto:").unwrap_or(value);
                    builder.organizer = Some(Organizer {
                        email: email.to_string(),
                        name: None,
                    });
                }
                "ATTENDEE" => {
                    let email = value.strip_prefix("mailto:").unwrap_or(value);
                    builder.attendees.push(Attendee {
                        email: email.to_string(),
                        name: None,
                        role: "REQ-PARTICIPANT".into(),
                        part_stat: "NEEDS-ACTION".into(),
                        rsvp: true,
                    });
                }
                "CATEGORIES" => {
                    builder.categories =
                        Some(value.split(',').map(|s| s.trim().to_string()).collect());
                }
                "RRULE" => builder.rrule = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Ok(ParsedCalendar {
        events,
        method,
        product_id,
    })
}

fn parse_ics_datetime(value: &str) -> Option<DateTime<Utc>> {
    let clean = value.trim();
    // YYYYMMDDTHHMMSSZ
    if clean.len() == 16 && clean.ends_with('Z') {
        return chrono::NaiveDateTime::parse_from_str(&clean[..15], "%Y%m%dT%H%M%S")
            .ok()
            .map(|n| n.and_utc());
    }
    // YYYYMMDDTHHMMSS
    if clean.len() == 15 {
        return chrono::NaiveDateTime::parse_from_str(clean, "%Y%m%dT%H%M%S")
            .ok()
            .map(|n| n.and_utc());
    }
    // YYYYMMDD (date only)
    if clean.len() == 8 {
        return NaiveDate::parse_from_str(clean, "%Y%m%d")
            .ok()
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map(|dt| dt.and_utc());
    }
    None
}

struct CalendarEventBuilder {
    uid: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    status: Option<CalendarStatus>,
    sequence: Option<u32>,
    created: Option<DateTime<Utc>>,
    last_modified: Option<DateTime<Utc>>,
    organizer: Option<Organizer>,
    attendees: Vec<Attendee>,
    url: Option<String>,
    categories: Option<Vec<String>>,
    rrule: Option<String>,
}

impl CalendarEventBuilder {
    fn new() -> Self {
        Self {
            uid: None,
            summary: None,
            description: None,
            location: None,
            start: None,
            end: None,
            status: None,
            sequence: None,
            created: None,
            last_modified: None,
            organizer: None,
            attendees: Vec::new(),
            url: None,
            categories: None,
            rrule: None,
        }
    }

    fn build(self) -> anyhow::Result<CalendarEvent> {
        let now = Utc::now();
        Ok(CalendarEvent {
            uid: self
                .uid
                .unwrap_or_else(|| format!("{}@apexmail.ee", Uuid::new_v4())),
            summary: self.summary.unwrap_or_default(),
            description: self.description,
            location: self.location,
            start: self.start.unwrap_or(now),
            end: self.end.unwrap_or(now),
            all_day: false,
            timezone: None,
            organizer: self.organizer.unwrap_or(Organizer {
                email: "unknown@unknown".into(),
                name: None,
            }),
            attendees: self.attendees,
            method: CalendarMethod::Publish,
            status: self.status.unwrap_or(CalendarStatus::Confirmed),
            sequence: self.sequence.unwrap_or(0),
            created: self.created.unwrap_or(now),
            last_modified: self.last_modified.unwrap_or(now),
            url: self.url,
            categories: self.categories,
            priority: None,
            recurrence: self.rrule.as_ref().and_then(|s| parse_rrule(s)),
        })
    }
}

/// Parse an RRULE string into a RecurrenceRule struct.
/// Example:"FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE,FR;COUNT=10"
fn parse_rrule(rrule: &str) -> Option<RecurrenceRule> {
    // Remove the "RRULE:" prefix if present
    let s = rrule.strip_prefix("RRULE:").unwrap_or(rrule);

    let mut freq = None;
    let mut interval = None;
    let mut count = None;
    let mut until = None;
    let mut by_day = None;
    let mut by_month = None;
    let mut by_month_day = None;

    for part in s.split(';') {
        let mut kv = part.splitn(2, '=');
        let key = kv.next()?;
        let value = kv.next().unwrap_or("");

        match key.to_uppercase().as_str() {
            "FREQ" => freq = Some(value.to_uppercase()),
            "INTERVAL" => interval = value.parse().ok(),
            "COUNT" => count = value.parse().ok(),
            "UNTIL" => until = Some(value.to_string()),
            "BYDAY" => {
                by_day = Some(value.split(',').map(|s| s.trim().to_uppercase()).collect());
            }
            "BYMONTH" => {
                by_month = Some(
                    value
                        .split(',')
                        .filter_map(|s| s.trim().parse::<u32>().ok())
                        .collect(),
                );
            }
            "BYMONTHDAY" => {
                by_month_day = Some(
                    value
                        .split(',')
                        .filter_map(|s| s.trim().parse::<i32>().ok())
                        .collect(),
                );
            }
            _ => {} // Ignore unknown properties
        }
    }

    // FREQ is required
    let freq = freq?;

    Some(RecurrenceRule {
        freq,
        interval,
        count,
        until,
        by_day,
        by_month,
        by_month_day,
    })
}

// ── HTML preview ───────────────────────────────────────────────────────────────

fn generate_html_preview(event: &CalendarEvent) -> String {
    let summary_html = escape_html(&event.summary);
    let when = format!(
        "{} – {}",
        event.start.format("%B %d, %Y %H:%M"),
        event.end.format("%H:%M %Z")
    );
    let location_html = event
        .location
        .as_deref()
        .map(escape_html)
        .unwrap_or_default();
    let desc_html = event
        .description
        .as_deref()
        .map(escape_html)
        .unwrap_or_default();
    let organizer_html = event
        .organizer
        .name
        .as_deref()
        .map(|n| {
            format!(
                "{} ({})",
                escape_html(n),
                escape_html(&event.organizer.email)
            )
        })
        .unwrap_or_else(|| escape_html(&event.organizer.email));

    let mut attendee_rows = String::new();
    for att in &event.attendees {
        let icon = match att.part_stat.as_str() {
            "ACCEPTED" => "&#10003;",
            "DECLINED" => "&#10007;",
            "TENTATIVE" => "?",
            _ => "&#9675;",
        };
        let name = att.name.as_deref().unwrap_or(&att.email);
        attendee_rows.push_str(&format!(
            "<tr><td>{icon}</td><td>{}</td><td>{}</td></tr>",
            escape_html(name),
            att.part_stat
        ));
    }

    format!(
        r#"<div style="font-family:sans-serif;max-width:600px;margin:auto">
<div style="background:#18181b;color:#fff;padding:16px;border-radius:0px">
  <h2 style="margin:0">{summary_html}</h2>
</div>
<div style="padding:16px;border:1px solid #e4e4e7;border-top:0;border-radius:0px">
  <p><strong>When:</strong> {when}</p>
  {loc}
  {desc}
  <p><strong>Organizer:</strong> {organizer_html}</p>
  {att_table}
</div>
</div>"#,
        loc = if location_html.is_empty() {
            String::new()
        } else {
            format!("<p><strong>Where:</strong> {location_html}</p>")
        },
        desc = if desc_html.is_empty() {
            String::new()
        } else {
            format!("<p>{desc_html}</p>")
        },
        att_table = if attendee_rows.is_empty() {
            String::new()
        } else {
            format!("<table><thead><tr><th></th><th>Attendee</th><th>Status</th></tr></thead><tbody>{attendee_rows}</tbody></table>")
        },
    )
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ics() {
        let event = CalendarEvent {
            uid: "test-uid@apexmail.ee".into(),
            summary: "Team Meeting".into(),
            description: Some("Weekly sync".into()),
            location: Some("Room 101".into()),
            start: chrono::DateTime::parse_from_rfc3339("2025-03-15T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            end: chrono::DateTime::parse_from_rfc3339("2025-03-15T11:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            all_day: false,
            timezone: None,
            organizer: Organizer {
                email: "org@example.com".into(),
                name: Some("Organizer".into()),
            },
            attendees: vec![Attendee {
                email: "att@example.com".into(),
                name: Some("Attendee".into()),
                role: "REQ-PARTICIPANT".into(),
                part_stat: "NEEDS-ACTION".into(),
                rsvp: true,
            }],
            method: CalendarMethod::Request,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: Utc::now(),
            last_modified: Utc::now(),
            url: None,
            categories: None,
            priority: None,
            recurrence: None,
        };

        let ics = generate_ics(&event);
        assert!(ics.contains("BEGIN:VCALENDAR"));
        assert!(ics.contains("METHOD:REQUEST"));
        assert!(ics.contains("SUMMARY:Team Meeting"));
        assert!(ics.contains("LOCATION:Room 101"));
        assert!(ics.contains("ATTENDEE"));
        assert!(ics.contains("END:VCALENDAR"));
    }

    #[test]
    fn test_parse_ics() {
        let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nPRODID:- //Test//EN\r\nBEGIN:VEVENT\r\nUID:uid123\r\nSUMMARY:Test Event\r\nDTSTART:20250315T100000Z\r\nDTEND:20250315T110000Z\r\nORGANIZER:mailto:org@test.com\r\nATTENDEE:mailto:att@test.com\r\nEND:VEVENT\r\nEND:VCALENDAR";
        let result = parse_ics_content(ics).unwrap();
        assert_eq!(result.method, CalendarMethod::Request);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.events[0].uid, "uid123");
        assert_eq!(result.events[0].summary, "Test Event");
        assert_eq!(result.events[0].organizer.email, "org@test.com");
        assert_eq!(result.events[0].attendees.len(), 1);
    }

    #[test]
    fn test_parse_ics_datetime() {
        let dt = parse_ics_datetime("20250315T100000Z").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-03-15");

        let dt = parse_ics_datetime("20250315").unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-03-15");

        assert!(parse_ics_datetime("invalid").is_none());
    }

    #[test]
    fn test_escape_ics() {
        assert_eq!(escape_ics("hello; world,test"), "hello\\; world\\,test");
        assert_eq!(escape_ics("line\nbreak"), "line\\nbreak");
        // F5: CR and CRLF must not survive into the output — a raw CR/LF
        // terminates an ICS property line and enables property injection.
        assert_eq!(escape_ics("cr\ronly"), "cr\\nonly");
        assert_eq!(escape_ics("crlf\r\ninject"), "crlf\\n\\ninject");
        assert_eq!(escape_ics("back\\slash"), "back\\\\slash");
    }

    // ── F5:CRLF/property injection into ORGANIZER/ATTENDEE ──────────

    #[test]
    fn test_organizer_attendee_injection_is_escaped() {
        let event = CalendarEvent {
            uid: "uid\r\nX-Evil:1".into(),
            summary: "Meeting".into(),
            description: None,
            location: None,
            start: Utc::now(),
            end: Utc::now(),
            all_day: false,
            timezone: None,
            organizer: Organizer {
                email: "org@example.com".into(),
                name: Some("Evil\r\nURL:evil.example/collect".into()),
            },
            attendees: vec![Attendee {
                email: "att@example.com\r\nX-Pwned: yes".into(),
                name: Some("Guest;ROLE=CHAIRNobody".into()),
                role: "REQ-PARTICIPANT\r\nX-Bad:1".into(),
                part_stat: "NEEDS-ACTION".into(),
                rsvp: true,
            }],
            method: CalendarMethod::Request,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: Utc::now(),
            last_modified: Utc::now(),
            url: None,
            categories: Some(vec!["team\r\nX-Inject:1".into()]),
            priority: None,
            recurrence: None,
        };

        let ics = generate_ics(&event);

        // No raw CR/LF may appear anywhere in the output — every line must be
        // a single property ending in CRLF, so injected content cannot start
        // a new property. The escaped text stays on the ORGANIZER/ATTENDEE
        // line; the check is that no LINE begins with an injected property.
        let lines: Vec<&str> = ics.split("\r\n").collect();
        for line in &lines {
            let stripped = line.strip_prefix(' ').unwrap_or(line);
            assert!(
                !stripped.starts_with("URL:evil")
                    && !stripped.starts_with("X-Pwned")
                    && !stripped.starts_with("X-Bad")
                    && !stripped.starts_with("X-Evil")
                    && !stripped.starts_with("X-Inject"),
                "injected property leaked onto its own line: {line:?}"
            );
        }
        // The attacker's URL never becomes a real URL property.
        assert!(!ics.split("\r\n").any(|l| l.starts_with("URL:")));
        // The malicious values survive as (escaped) text inside the CN param.
        assert!(ics.contains("URL\\nevil.example/collect") || ics.contains("URL:evil"));
        assert!(ics.contains("ORGANIZER"));
        assert!(ics.contains("ATTENDEE"));
        // UID injection neutralized too.
        assert!(!ics.split("\r\n").any(|l| l.starts_with("X-Evil:")));
    }

    #[test]
    fn test_url_and_categories_injection_is_escaped() {
        let event = CalendarEvent {
            uid: "uid-ok".into(),
            summary: "Sync".into(),
            description: None,
            location: None,
            start: Utc::now(),
            end: Utc::now(),
            all_day: false,
            timezone: None,
            organizer: Organizer {
                email: "org@example.com".into(),
                name: None,
            },
            attendees: vec![],
            method: CalendarMethod::Publish,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: Utc::now(),
            last_modified: Utc::now(),
            url: Some("http://example.com/\r\nDESCRIPTION:pwned".into()),
            categories: Some(vec!["a;b".into(), "c,d".into()]),
            priority: None,
            recurrence: None,
        };

        let ics = generate_ics(&event);
        assert!(
            !ics.split("\r\n")
                .any(|l| l.starts_with("DESCRIPTION:pwned")),
            "URL must not be able to inject a DESCRIPTION property"
        );
        // ';' and ',' in category values are escaped as \; and \,.
        assert!(ics.contains("a\\;b") && ics.contains("c\\,d"));
    }

    #[test]
    fn test_fold_lines() {
        let long_line = "A".repeat(100);
        let folded = fold_lines(&long_line);
        for line in folded.split("\r\n") {
            if !line.is_empty() {
                assert!(line.len() <= 75, "Line too long: {} chars", line.len());
            }
        }
    }

    #[test]
    fn test_calendar_method() {
        assert_eq!(
            CalendarMethod::from_str("REQUEST").unwrap(),
            CalendarMethod::Request
        );
        assert_eq!(
            CalendarMethod::from_str("cancel").unwrap(),
            CalendarMethod::Cancel
        );
        assert_eq!(CalendarMethod::Request.as_str(), "REQUEST");
    }

    #[test]
    fn test_generate_rrule() {
        let rule = RecurrenceRule {
            freq: "WEEKLY".into(),
            interval: Some(2),
            count: Some(10),
            until: None,
            by_day: Some(vec!["MO".into(), "WE".into(), "FR".into()]),
            by_month: None,
            by_month_day: None,
        };
        let rrule = generate_rrule(&rule);
        assert!(rrule.contains("FREQ=WEEKLY"));
        assert!(rrule.contains("INTERVAL=2"));
        assert!(rrule.contains("COUNT=10"));
        assert!(rrule.contains("BYDAY=MO,WE,FR"));
    }

    #[test]
    fn test_generate_html_preview() {
        let event = CalendarEvent {
            uid: "test@apexmail.ee".into(),
            summary: "Test <Event>".into(),
            description: None,
            location: None,
            start: Utc::now(),
            end: Utc::now(),
            all_day: false,
            timezone: None,
            organizer: Organizer {
                email: "org@test.com".into(),
                name: None,
            },
            attendees: vec![],
            method: CalendarMethod::Publish,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: Utc::now(),
            last_modified: Utc::now(),
            url: None,
            categories: None,
            priority: None,
            recurrence: None,
        };
        let html = generate_html_preview(&event);
        // Should properly escape HTML
        assert!(html.contains("Test &lt;Event&gt;"));
        assert!(html.contains("org@test.com"));
    }

    // ── adversarial: enums, invite creation, ICS round-trips ──────────

    fn offline_service() -> CalendarService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .expect("lazy pool never connects");
        CalendarService::new(pool)
    }

    fn sample_event() -> CalendarEvent {
        CalendarEvent {
            uid: "uid-1@apexmail.ee".into(),
            summary: "Meeting".into(),
            description: Some("Agenda".into()),
            location: Some("Room 1".into()),
            start: Utc::now(),
            end: Utc::now(),
            all_day: false,
            timezone: None,
            organizer: Organizer {
                email: "org@example.com".into(),
                name: Some("Org".into()),
            },
            attendees: vec![],
            method: CalendarMethod::Request,
            status: CalendarStatus::Confirmed,
            sequence: 0,
            created: Utc::now(),
            last_modified: Utc::now(),
            url: None,
            categories: None,
            priority: None,
            recurrence: None,
        }
    }

    #[tokio::test]
    async fn calendar_method_and_status_parsing_is_allowlisted() {
        for (raw, method, expected) in [
            ("request", CalendarMethod::Request, "REQUEST"),
            ("REPLY", CalendarMethod::Reply, "REPLY"),
            ("cancel", CalendarMethod::Cancel, "CANCEL"),
            ("refresh", CalendarMethod::Refresh, "REFRESH"),
            ("counter", CalendarMethod::Counter, "COUNTER"),
            (
                "declinecounter",
                CalendarMethod::DeclineCounter,
                "DECLINECOUNTER",
            ),
            ("add", CalendarMethod::Add, "ADD"),
            ("publish", CalendarMethod::Publish, "PUBLISH"),
        ] {
            assert_eq!(CalendarMethod::from_str(raw).unwrap(), method);
            assert_eq!(method.as_str(), expected);
            assert_eq!(
                raw.to_uppercase().parse::<CalendarMethod>().unwrap(),
                method
            );
        }
        assert!(CalendarMethod::from_str("EVIL\nMETHOD").is_err());
        assert!(CalendarMethod::from_str("").is_err());

        assert_eq!(
            CalendarStatus::from_str("tentative"),
            CalendarStatus::Tentative
        );
        assert_eq!(
            CalendarStatus::from_str("Cancelled"),
            CalendarStatus::Cancelled
        );
        assert_eq!(
            CalendarStatus::from_str("garbage"),
            CalendarStatus::Confirmed
        );
        assert_eq!(CalendarStatus::Tentative.as_str(), "TENTATIVE");
        assert_eq!(CalendarStatus::Cancelled.as_str(), "CANCELLED");
        assert_eq!(CalendarStatus::Confirmed.as_str(), "CONFIRMED");
    }

    #[tokio::test]
    async fn content_type_detection_is_case_insensitive() {
        assert!(CalendarService::is_calendar_content_type(
            "text/calendar; charset=utf-8"
        ));
        assert!(CalendarService::is_calendar_content_type("APPLICATION/ICS"));
        assert!(!CalendarService::is_calendar_content_type("text/plain"));
        assert!(!CalendarService::is_calendar_content_type(""));
    }

    #[tokio::test]
    async fn create_invite_marks_all_day_and_escapes() {
        let service = offline_service();
        let invite = service
            .create_invite(
                "Standup; with, commas",
                Utc::now(),
                Utc::now(),
                Organizer {
                    email: "boss@example.com".into(),
                    name: Some("Boss\nInjected".into()),
                },
                vec![Attendee {
                    email: "dev@example.com".into(),
                    name: Some("Dev, Jr.".into()),
                    role: "OPT-PARTICIPANT".into(),
                    part_stat: "ACCEPTED".into(),
                    rsvp: false,
                }],
                Some("Notes".into()),
                Some("HQ".into()),
                CalendarMethod::Request,
                true,
            )
            .expect("invite");
        assert!(invite.event.uid.ends_with("@apexmail.ee"));
        assert!(invite.ics_content.contains("DTSTART;VALUE=DATE:"));
        assert!(invite.ics_content.contains("DTEND;VALUE=DATE:"));
        assert!(
            !invite.ics_content.contains("\nInjected"),
            "CRLF must be neutralized"
        );
        assert!(invite
            .ics_content
            .contains("SUMMARY:Standup\\; with\\, commas"));
        assert!(invite.ics_content.contains("RSVP=FALSE"));
        assert!(invite.ics_content.contains("CN=Dev\\, Jr."));
        assert!(invite.html_preview.contains("Standup; with, commas"));
        assert!(invite.html_preview.contains("HQ"));
        assert!(invite.html_preview.contains("Notes"));
    }

    #[tokio::test]
    async fn generate_ics_optional_sections() {
        let mut event = sample_event();
        event.url = Some("https://example.com/e".into());
        event.categories = Some(vec!["work".into(), "urgent".into()]);
        event.priority = Some(1);
        event.recurrence = Some(RecurrenceRule {
            freq: "weekly".into(),
            interval: Some(2),
            count: None,
            until: Some("20260101T000000Z".into()),
            by_day: Some(vec!["mo".into(), "we".into()]),
            by_month: Some(vec![1, 6]),
            by_month_day: Some(vec![1, -1]),
        });
        let ics = generate_ics(&event);
        assert!(ics.contains("URL:https://example.com/e"));
        assert!(ics.contains("CATEGORIES:work,urgent"));
        assert!(ics.contains("PRIORITY:1"));
        // Long properties are folded at 75 chars — unfold before comparing.
        let unfolded = ics.replace("\r\n ", "");
        // FREQ is upper-cased; BYDAY values are passed through verbatim.
        assert!(unfolded.contains(
            "RRULE:FREQ=WEEKLY;INTERVAL=2;UNTIL=20260101T000000Z;BYDAY=mo,we;BYMONTH=1,6;BYMONTHDAY=1,-1"
        ));

        // A javascript: URL is never emitted.
        event.url = Some("javascript:alert(1)".into());
        assert!(!generate_ics(&event).contains("javascript"));
        // Empty categories emit no line.
        event.categories = Some(vec![]);
        assert!(!generate_ics(&event).contains("CATEGORIES"));

        // Organizer without a name and attendee without a name.
        let mut event = sample_event();
        event.organizer.name = None;
        event.attendees = vec![Attendee {
            email: "a@example.com".into(),
            name: None,
            role: "REQ-PARTICIPANT".into(),
            part_stat: "NEEDS-ACTION".into(),
            rsvp: true,
        }];
        let unfolded = generate_ics(&event).replace("\r\n ", "");
        assert!(unfolded.contains("ORGANIZER:mailto:org@example.com"));
        assert!(unfolded.contains(
            "ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:a@example.com"
        ));
    }

    #[tokio::test]
    async fn ics_round_trip_preserves_event_fields() {
        let service = offline_service();
        let mut event = sample_event();
        event.all_day = true;
        event.status = CalendarStatus::Tentative;
        event.sequence = 7;
        event.recurrence = Some(RecurrenceRule {
            freq: "DAILY".into(),
            interval: None,
            count: Some(3),
            until: None,
            by_day: None,
            by_month: None,
            by_month_day: None,
        });
        event.attendees = vec![Attendee {
            email: "guest@example.com".into(),
            name: None,
            role: "REQ-PARTICIPANT".into(),
            part_stat: "NEEDS-ACTION".into(),
            rsvp: true,
        }];
        event.categories = Some(vec!["ops".into(), "oncall".into()]);

        let ics = generate_ics(&event);
        let parsed = service.parse_ics(&ics).expect("round-trip parses");
        assert_eq!(parsed.method, CalendarMethod::Request);
        assert_eq!(parsed.product_id, "- //ApexMail//Calendar//EN");
        assert_eq!(parsed.events.len(), 1);
        let round = &parsed.events[0];
        assert_eq!(round.uid, event.uid);
        assert_eq!(round.summary, "Meeting");
        assert_eq!(round.description.as_deref(), Some("Agenda"));
        assert_eq!(round.location.as_deref(), Some("Room 1"));
        assert_eq!(round.status, CalendarStatus::Tentative);
        assert_eq!(round.sequence, 7);
        assert_eq!(round.organizer.email, "org@example.com");
        assert_eq!(round.attendees.len(), 1);
        assert_eq!(round.attendees[0].email, "guest@example.com");
        assert_eq!(
            round.categories.as_deref(),
            Some(&["ops".to_string(), "oncall".to_string()][..])
        );
        let recurrence = round.recurrence.as_ref().expect("rrule parsed");
        assert_eq!(recurrence.freq, "DAILY");
        assert_eq!(recurrence.count, Some(3));
    }

    #[tokio::test]
    async fn parse_ics_rejects_unknown_method_and_skips_junk() {
        let service = offline_service();
        let ics = "BEGIN:VCALENDAR\r\nMETHOD:TELEPORT\r\nPRODID:x\r\nEND:VCALENDAR\r\n";
        assert!(
            service.parse_ics(ics).is_err(),
            "unknown METHOD must be refused"
        );

        // No METHOD → defaults to PUBLISH; lines without ':' are skipped;
        // unknown properties inside an event are ignored; a stray END:VEVENT
        // without BEGIN is tolerated.
        let ics = "BEGIN:VCALENDAR\r\nGARBAGE-LINE-WITHOUT-COLON\r\nEND:VEVENT\r\n\
                   BEGIN:VEVENT\r\nUID:u@example.com\r\nX-CUSTOM:1\r\nEND:VEVENT\r\n\
                   END:VCALENDAR\r\n";
        let parsed = service.parse_ics(ics).unwrap();
        assert_eq!(parsed.method, CalendarMethod::Publish);
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].uid, "u@example.com");

        // Two VEVENT blocks share the calendar-level METHOD. (Build the
        // blocks directly: nesting a full VCALENDAR inside another is not
        // what an iTIP body looks like and the parser is not a nesting
        // parser.)
        let block = |summary: &str| {
            format!(
                "BEGIN:VEVENT\r\nUID:{summary}@apexmail.ee\r\nSUMMARY:{summary}\r\n\
                 DTSTART:20260101T000000Z\r\nDTEND:20260101T010000Z\r\nEND:VEVENT\r\n"
            )
        };
        let ics = format!(
            "BEGIN:VCALENDAR\r\nMETHOD:REPLY\r\n{}{}\r\nEND:VCALENDAR\r\n",
            block("one"),
            block("two")
        );
        let parsed = service.parse_ics(&ics).unwrap();
        assert_eq!(parsed.events.len(), 2);
        assert!(parsed
            .events
            .iter()
            .all(|e| e.method == CalendarMethod::Reply));
        assert_eq!(parsed.events[0].summary, "one");
        assert_eq!(parsed.events[1].summary, "two");
    }

    #[tokio::test]
    async fn parse_ics_datetime_formats_and_invalid_input() {
        assert_eq!(
            parse_ics_datetime("20250102T030405Z").unwrap().to_rfc3339(),
            "2025-01-02T03:04:05+00:00"
        );
        assert_eq!(
            parse_ics_datetime("20250102T030405").unwrap().to_rfc3339(),
            "2025-01-02T03:04:05+00:00"
        );
        assert_eq!(
            parse_ics_datetime("20250102").unwrap().to_rfc3339(),
            "2025-01-02T00:00:00+00:00"
        );
        assert!(parse_ics_datetime("2025-01-02T03:04:05Z").is_none());
        assert!(parse_ics_datetime("20251340T030405Z").is_none());
        assert!(parse_ics_datetime("garbage").is_none());
    }

    #[tokio::test]
    async fn parse_rrule_handles_missing_freq_and_bad_numbers() {
        assert!(parse_rrule("INTERVAL=2").is_none(), "FREQ is required");
        let rule = parse_rrule(
            "RRULE:FREQ=MONTHLY;INTERVAL=oops;BYMONTH=1,x,12;BYMONTHDAY=1,bad;BYDAY=mo, we;X-UNKNOWN=1",
        )
        .expect("freq present");
        assert_eq!(rule.by_day, Some(vec!["MO".to_string(), "WE".to_string()]));
        assert_eq!(rule.freq, "MONTHLY");
        assert_eq!(rule.interval, None, "unparsable numbers are dropped");
        assert_eq!(rule.by_month, Some(vec![1, 12]));
        assert_eq!(rule.by_month_day, Some(vec![1]));
        assert_eq!(rule.count, None);
        assert_eq!(rule.until, None);
    }

    #[tokio::test]
    async fn folding_splits_long_lines_on_char_boundaries() {
        // Long multibyte line: every output line is ≤75 chars, continuation
        // lines start with a space, and the content survives intact.
        let long = "é".repeat(200);
        let folded = fold_lines(&format!("X:{long}"));
        let mut unfolded = String::new();
        for line in folded.split("\r\n") {
            if line.is_empty() {
                continue;
            }
            if let Some(rest) = line.strip_prefix(' ') {
                unfolded.push_str(rest);
            } else {
                unfolded.push_str(line);
            }
        }
        assert_eq!(unfolded, format!("X:{long}"));
        for line in folded.split("\r\n") {
            assert!(line.chars().count() <= 75, "line too long: {line:?}");
        }
    }

    #[tokio::test]
    async fn html_preview_icons_and_fallbacks() {
        let mut event = sample_event();
        event.description = None;
        event.location = None;
        event.attendees = vec![
            Attendee {
                email: "yes@example.com".into(),
                name: None,
                role: "REQ-PARTICIPANT".into(),
                part_stat: "ACCEPTED".into(),
                rsvp: true,
            },
            Attendee {
                email: "no@example.com".into(),
                name: Some("N".into()),
                role: "REQ-PARTICIPANT".into(),
                part_stat: "DECLINED".into(),
                rsvp: true,
            },
            Attendee {
                email: "maybe@example.com".into(),
                name: None,
                role: "REQ-PARTICIPANT".into(),
                part_stat: "TENTATIVE".into(),
                rsvp: true,
            },
            Attendee {
                email: "other@example.com".into(),
                name: None,
                role: "REQ-PARTICIPANT".into(),
                part_stat: "NEEDS-ACTION".into(),
                rsvp: true,
            },
        ];
        let html = generate_html_preview(&event);
        assert!(html.contains("&#10003;"), "accepted icon");
        assert!(html.contains("&#10007;"), "declined icon");
        assert!(html.contains(">?<"), "tentative icon");
        assert!(html.contains("&#9675;"), "unknown icon");
        assert!(
            html.contains("yes@example.com"),
            "email fallback for a nameless attendee"
        );
        assert!(!html.contains("<p><strong>Where:</strong>"));
        assert!(!html.contains("<p></p>"), "no empty description paragraph");
        assert!(html.contains("Org (org@example.com)"));
    }

    #[tokio::test]
    async fn store_event_persists_to_the_canonical_schema() {
        let pool = match migrator::test_support::fresh_canonical_pool(
            "edge_calendar_store",
            "edge_calendar_store",
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        };
        let Some(pool) = pool else { return };
        let service = CalendarService::new(pool.clone());
        let mut event = sample_event();
        event.attendees = vec![Attendee {
            email: "a@example.com".into(),
            name: None,
            role: "REQ-PARTICIPANT".into(),
            part_stat: "NEEDS-ACTION".into(),
            rsvp: true,
        }];
        service
            .store_event("msg_cal_1", &event)
            .await
            .expect("store");

        let (uid, summary, method, status, count): (String, String, String, String, i32) =
            sqlx::query_as(
                "SELECT uid, summary, method, status, attendee_count
                 FROM edge_calendar_events WHERE message_id = $1",
            )
            .bind("msg_cal_1")
            .fetch_one(&pool)
            .await
            .expect("row exists");
        assert_eq!(uid, event.uid);
        assert_eq!(summary, "Meeting");
        assert_eq!(method, "REQUEST");
        assert_eq!(status, "CONFIRMED");
        assert_eq!(count, 1);
    }
}
