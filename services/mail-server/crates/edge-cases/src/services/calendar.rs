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
    lines.push(format!("UID:{}", event.uid));
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

    // Organizer
    if let Some(ref name) = event.organizer.name {
        lines.push(format!(
            "ORGANIZER;CN={}:mailto:{}",
            name, event.organizer.email
        ));
    } else {
        lines.push(format!("ORGANIZER:mailto:{}", event.organizer.email));
    }

    // Attendees
    for att in &event.attendees {
        let mut params = Vec::new();
        if let Some(ref name) = att.name {
            params.push(format!("CN={name}"));
        }
        params.push(format!("ROLE={}", att.role));
        params.push(format!("PARTSTAT={}", att.part_stat));
        params.push(format!("RSVP={}", if att.rsvp { "TRUE" } else { "FALSE" }));
        lines.push(format!(
            "ATTENDEE;{}:mailto:{}",
            params.join(";"),
            att.email
        ));
    }

    // URL (validate scheme)
    if let Some(ref url) = event.url {
        if url.starts_with("http://") || url.starts_with("https://") {
            lines.push(format!("URL:{url}"));
        }
    }

    // Categories
    if let Some(ref cats) = event.categories {
        if !cats.is_empty() {
            lines.push(format!("CATEGORIES:{}", cats.join(",")));
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
    let mut parts = vec![format!("FREQ={}", rule.freq.to_uppercase())];
    if let Some(interval) = rule.interval {
        parts.push(format!("INTERVAL={interval}"));
    }
    if let Some(count) = rule.count {
        parts.push(format!("COUNT={count}"));
    }
    if let Some(ref until) = rule.until {
        parts.push(format!("UNTIL={until}"));
    }
    if let Some(ref days) = rule.by_day {
        parts.push(format!("BYDAY={}", days.join(",")));
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

fn escape_ics(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
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
<div style="background:#1a73e8;color:#fff;padding:16px;border-radius:8px 8px 0 0">
  <h2 style="margin:0">{summary_html}</h2>
</div>
<div style="padding:16px;border:1px solid #ddd;border-top:0;border-radius:0 0 8px 8px">
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
}
