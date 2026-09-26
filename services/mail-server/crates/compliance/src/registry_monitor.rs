use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::interval;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeStatus {
    Pending,
    InProgress,
    Completed,
    Overdue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recurrence {
    Annual,
    Quarterly,
    Monthly,
    OneTime,
}

impl Recurrence {
    pub fn next_due(&self, from: NaiveDate) -> NaiveDate {
        match self {
            Recurrence::Annual => {
                let next_year = from.year() + 1;
                NaiveDate::from_ymd_opt(next_year, from.month(), from.day())
                    .or_else(|| NaiveDate::from_ymd_opt(next_year, from.month(), 28))
                    .unwrap_or(from)
            }
            Recurrence::Quarterly => {
                let m = from.month() + 3;
                if m > 12 {
                    let next_year = from.year() + 1;
                    let next_month = m - 12;
                    NaiveDate::from_ymd_opt(next_year, next_month, from.day())
                        .or_else(|| NaiveDate::from_ymd_opt(next_year, next_month, 28))
                        .unwrap_or(from)
                } else {
                    NaiveDate::from_ymd_opt(from.year(), m, from.day())
                        .or_else(|| NaiveDate::from_ymd_opt(from.year(), m, 28))
                        .unwrap_or(from)
                }
            }
            Recurrence::Monthly => {
                let m = from.month() + 1;
                if m > 12 {
                    // Year rollover: the target month is January, which has
                    // 31 days, so the source day (1..=31) always exists and
                    // no clamp fallback is reachable.
                    NaiveDate::from_ymd_opt(from.year() + 1, 1, from.day()).unwrap_or(from)
                } else {
                    NaiveDate::from_ymd_opt(from.year(), m, from.day())
                        .or_else(|| NaiveDate::from_ymd_opt(from.year(), m, 28))
                        .unwrap_or(from)
                }
            }
            Recurrence::OneTime => from,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryNotice {
    pub notice_id: String,
    pub title: String,
    pub description: String,
    pub jurisdiction: String,
    pub authority: Option<String>,
    pub due_date: NaiveDate,
    pub recurrence: Recurrence,
    pub status: NoticeStatus,
    pub responsible_party: String,
    pub evidence_location: Option<String>,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct RegistryMonitor {
    notices: HashMap<String, RegistryNotice>,
}

impl RegistryMonitor {
    pub fn new() -> Self {
        Self {
            notices: HashMap::new(),
        }
    }

    pub fn add_notice(&mut self, notice: RegistryNotice) {
        self.notices.insert(notice.notice_id.clone(), notice);
    }

    pub fn get_notice(&self, notice_id: &str) -> Option<&RegistryNotice> {
        self.notices.get(notice_id)
    }

    pub fn list_all(&self) -> Vec<&RegistryNotice> {
        self.notices.values().collect()
    }

    pub fn check_monthly(&self, reference_date: NaiveDate) -> Vec<&RegistryNotice> {
        let month_start = NaiveDate::from_ymd_opt(reference_date.year(), reference_date.month(), 1)
            .unwrap_or(reference_date);
        let next_month = reference_date.month() + 1;
        let (end_year, end_month) = if next_month > 12 {
            (reference_date.year() + 1, 1)
        } else {
            (reference_date.year(), next_month)
        };
        let month_end = NaiveDate::from_ymd_opt(end_year, end_month, 1)
            .map(|d| d.pred_opt().unwrap_or(d))
            .unwrap_or(reference_date);

        self.notices
            .values()
            .filter(|n| {
                n.status != NoticeStatus::Completed
                    && n.due_date >= month_start
                    && n.due_date <= month_end
            })
            .collect()
    }

    pub fn complete_notice(&mut self, notice_id: &str) -> bool {
        if let Some(notice) = self.notices.get_mut(notice_id) {
            notice.status = NoticeStatus::Completed;
            notice.completed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    pub fn overdue_notices(&self, reference_date: NaiveDate) -> Vec<&RegistryNotice> {
        self.notices
            .values()
            .filter(|n| n.status != NoticeStatus::Completed && n.due_date < reference_date)
            .collect()
    }

    pub fn notices_by_category(&self, status: NoticeStatus) -> Vec<&RegistryNotice> {
        self.notices
            .values()
            .filter(|n| n.status == status)
            .collect()
    }

    pub fn generate_annual_report_deadlines(&self, year: i32) -> Vec<RegistryNotice> {
        let mut deadlines = Vec::new();
        for notice in self.notices.values() {
            if notice.recurrence == Recurrence::Annual && notice.status != NoticeStatus::Completed {
                deadlines.push(RegistryNotice {
                    notice_id: format!("annual-{}-{}", year, notice.notice_id),
                    title: format!("Annual: {}", notice.title),
                    description: notice.description.clone(),
                    jurisdiction: notice.jurisdiction.clone(),
                    authority: notice.authority.clone(),
                    due_date: notice.due_date.with_year(year).unwrap_or(notice.due_date),
                    recurrence: Recurrence::Annual,
                    status: NoticeStatus::Pending,
                    responsible_party: notice.responsible_party.clone(),
                    evidence_location: None,
                    notes: Some(format!("Recurring from parent notice {}", notice.notice_id)),
                    created_at: Utc::now(),
                    completed_at: None,
                });
            }
        }
        deadlines
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCheckResult {
    pub registry_code: String,
    pub company_name: String,
    pub status: String,
    pub checked_at: DateTime<Utc>,
    pub is_active: bool,
    pub last_annual_report_date: Option<NaiveDate>,
    pub contact_person_name: Option<String>,
    pub contact_person_changed: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScheduledRegistryMonitor {
    inner: RegistryMonitor,
    check_interval: Duration,
    registry_code: String,
}

impl ScheduledRegistryMonitor {
    pub fn new(registry_code: String) -> Self {
        Self {
            inner: RegistryMonitor::new(),
            check_interval: Duration::from_secs(30 * 24 * 3600),
            registry_code,
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Test seam: the configured tick period (compiled only under test).
    #[cfg(test)]
    fn check_interval_snapshot(&self) -> Duration {
        self.check_interval
    }

    pub fn monitor(&self) -> &RegistryMonitor {
        &self.inner
    }

    pub fn monitor_mut(&mut self) -> &mut RegistryMonitor {
        &mut self.inner
    }

    pub fn registry_code(&self) -> &str {
        &self.registry_code
    }

    pub async fn run_monthly(&mut self) {
        let mut ticker = interval(self.check_interval);
        loop {
            ticker.tick().await;
            let now = Utc::now();
            let today = now.date_naive();

            let overdue = self.inner.overdue_notices(today);
            if !overdue.is_empty() {
                tracing::warn!(
                    count = overdue.len(),
                    notice_ids = ?overdue.iter().map(|n| &n.notice_id).collect::<Vec<_>>(),
                    "Registry notices are overdue"
                );
            }

            let due_this_month = self.inner.check_monthly(today);
            if !due_this_month.is_empty() {
                tracing::info!(
                    count = due_this_month.len(),
                    notice_ids = ?due_this_month.iter().map(|n| &n.notice_id).collect::<Vec<_>>(),
                    "Registry notices due this month"
                );
            }
        }
    }

    pub fn validate_registry_code(&self, code: &str) -> bool {
        if code.is_empty() || code.len() > 20 {
            return false;
        }
        code.chars().all(|c| c.is_ascii_digit())
    }

    pub fn check_annual_report_deadline(&self, year: i32) -> Vec<RegistryNotice> {
        self.inner.generate_annual_report_deadlines(year)
    }

    pub fn seed_estonian_ou_notices(&mut self, company_name: &str, registry_code: &str) {
        let now = Utc::now();
        let today = now.date_naive();

        self.inner.add_notice(RegistryNotice {
            notice_id: "REG-EE-ANNUAL-REPORT".into(),
            title: format!("Annual Report Filing — {}", company_name),
            description: format!(
                "Submit annual report (majandusaasta aruanne) to Estonian Business Register for {} (registry {})",
                company_name, registry_code
            ),
            jurisdiction: "Estonia".into(),
            authority: Some("Estonian Business Register (Äriregister)".into()),
            due_date: NaiveDate::from_ymd_opt(today.year(), 6, 30).unwrap(),
            recurrence: Recurrence::Annual,
            status: NoticeStatus::Pending,
            responsible_party: "legal@apexmail.ee".into(),
            evidence_location: Some("compliance_submissions/".into()),
            notes: Some("Required by Äriseadustik §97. Must be submitted within 6 months after fiscal year end.".into()),
            created_at: now,
            completed_at: None,
        });

        self.inner.add_notice(RegistryNotice {
            notice_id: "REG-EE-CONTACT-PERSON".into(),
            title: format!("Contact Person Verification — {}", company_name),
            description: format!(
                "Verify contact person details for {} (registry {}) are current in the Estonian Business Register",
                company_name, registry_code
            ),
            jurisdiction: "Estonia".into(),
            authority: Some("Estonian Business Register (Äriregister)".into()),
            due_date: NaiveDate::from_ymd_opt(today.year(), 1, 31).unwrap(),
            recurrence: Recurrence::Annual,
            status: NoticeStatus::Pending,
            responsible_party: "legal@apexmail.ee".into(),
            evidence_location: Some("compliance/contact_person_verification/".into()),
            notes: Some("Contact person must be a natural person with Estonian personal identification code or residence permit.".into()),
            created_at: now,
            completed_at: None,
        });

        self.inner.add_notice(RegistryNotice {
            notice_id: "REG-EE-VAT-KMD".into(),
            title: format!("Monthly VAT Declaration (KMD) — {}", company_name),
            description: "Submit KMD (käibedeklaratsioon) to Estonian Tax and Customs Board".into(),
            jurisdiction: "Estonia".into(),
            authority: Some("Estonian Tax and Customs Board (EMTA)".into()),
            due_date: NaiveDate::from_ymd_opt(today.year(), today.month(), 20).unwrap(),
            recurrence: Recurrence::Monthly,
            status: NoticeStatus::Pending,
            responsible_party: "finance@apexmail.ee".into(),
            evidence_location: Some("compliance_submissions/".into()),
            notes: Some("Due by 20th of each month per KMS §27.".into()),
            created_at: now,
            completed_at: None,
        });

        self.inner.add_notice(RegistryNotice {
            notice_id: "REG-EE-SOCIAL-TAX".into(),
            title: format!("Monthly Social Tax Declaration (TSD) — {}", company_name),
            description: "Submit TSD (deklaratsioon sotsiaalmaksu kohta) to EMTA".into(),
            jurisdiction: "Estonia".into(),
            authority: Some("Estonian Tax and Customs Board (EMTA)".into()),
            due_date: NaiveDate::from_ymd_opt(today.year(), today.month(), 10).unwrap(),
            recurrence: Recurrence::Monthly,
            status: NoticeStatus::Pending,
            responsible_party: "finance@apexmail.ee".into(),
            evidence_location: Some("compliance_submissions/".into()),
            notes: Some("Due by 10th of each month per SOS §9.".into()),
            created_at: now,
            completed_at: None,
        });

        self.inner.add_notice(RegistryNotice {
            notice_id: "REG-EE-STATISTICAL".into(),
            title: format!("Annual Statistical Report — {}", company_name),
            description: "Submit annual statistical report to Statistics Estonia".into(),
            jurisdiction: "Estonia".into(),
            authority: Some("Statistics Estonia (Statistikaamet)".into()),
            due_date: NaiveDate::from_ymd_opt(today.year(), 7, 1).unwrap(),
            recurrence: Recurrence::Annual,
            status: NoticeStatus::Pending,
            responsible_party: "legal@apexmail.ee".into(),
            evidence_location: Some("compliance_submissions/".into()),
            notes: Some("Required by RTS §8 for IT sector companies.".into()),
            created_at: now,
            completed_at: None,
        });
    }
}

impl Default for ScheduledRegistryMonitor {
    fn default() -> Self {
        Self::new("16588745".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_notice(
        id: &str,
        title: &str,
        due: NaiveDate,
        recurrence: Recurrence,
    ) -> RegistryNotice {
        RegistryNotice {
            notice_id: id.to_string(),
            title: title.to_string(),
            description: format!("Description for {}", title),
            jurisdiction: "Estonia".to_string(),
            authority: Some("Estonian Business Register".to_string()),
            due_date: due,
            recurrence,
            status: NoticeStatus::Pending,
            responsible_party: "legal@apexmail.ee".to_string(),
            evidence_location: None,
            notes: None,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn test_add_and_retrieve_notice() {
        let mut monitor = RegistryMonitor::new();
        let notice = sample_notice(
            "REG-001",
            "Annual Report Filing",
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
            Recurrence::Annual,
        );
        monitor.add_notice(notice);
        let retrieved = monitor.get_notice("REG-001");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().title, "Annual Report Filing");
    }

    #[test]
    fn test_check_monthly_includes_notices_due_within_month() {
        let mut monitor = RegistryMonitor::new();
        let in_month = sample_notice(
            "REG-002",
            "VAT Return",
            NaiveDate::from_ymd_opt(2026, 7, 20).unwrap(),
            Recurrence::Monthly,
        );
        let out_of_month = sample_notice(
            "REG-003",
            "Annual Report",
            NaiveDate::from_ymd_opt(2026, 9, 1).unwrap(),
            Recurrence::Annual,
        );
        monitor.add_notice(in_month);
        monitor.add_notice(out_of_month);

        let due = monitor.check_monthly(NaiveDate::from_ymd_opt(2026, 7, 15).unwrap());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].notice_id, "REG-002");
    }

    #[test]
    fn test_check_monthly_excludes_completed_notices() {
        let mut monitor = RegistryMonitor::new();
        let notice = sample_notice(
            "REG-004",
            "Data Protection Filing",
            NaiveDate::from_ymd_opt(2026, 7, 10).unwrap(),
            Recurrence::Annual,
        );
        monitor.add_notice(notice);
        monitor.complete_notice("REG-004");

        let due = monitor.check_monthly(NaiveDate::from_ymd_opt(2026, 7, 15).unwrap());
        assert_eq!(due.len(), 0);
    }

    #[test]
    fn test_overdue_notices_returns_past_due() {
        let mut monitor = RegistryMonitor::new();
        let late = sample_notice(
            "REG-005",
            "Missed Filing",
            NaiveDate::from_ymd_opt(2026, 1, 15).unwrap(),
            Recurrence::Annual,
        );
        let future = sample_notice(
            "REG-006",
            "Future Filing",
            NaiveDate::from_ymd_opt(2026, 12, 1).unwrap(),
            Recurrence::Annual,
        );
        monitor.add_notice(late);
        monitor.add_notice(future);

        let overdue = monitor.overdue_notices(NaiveDate::from_ymd_opt(2026, 7, 1).unwrap());
        assert_eq!(overdue.len(), 1);
        assert_eq!(overdue[0].notice_id, "REG-005");
    }

    #[test]
    fn test_generate_annual_report_deadlines_creates_recurring_entries() {
        let mut monitor = RegistryMonitor::new();
        let annual = sample_notice(
            "REG-007",
            "Annual Report Filing",
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
            Recurrence::Annual,
        );
        monitor.add_notice(annual);

        let deadlines = monitor.generate_annual_report_deadlines(2027);
        assert_eq!(deadlines.len(), 1);
        assert!(deadlines[0].notice_id.contains("annual-2027"));
        assert_eq!(deadlines[0].due_date.year(), 2027);
        assert_eq!(deadlines[0].due_date.month(), 6);
    }

    #[test]
    fn test_recurrence_next_due_annual() {
        let date = NaiveDate::from_ymd_opt(2026, 6, 30).unwrap();
        let next = Recurrence::Annual.next_due(date);
        assert_eq!(next.year(), 2027);
        assert_eq!(next.month(), 6);
        assert_eq!(next.day(), 30);
    }

    #[test]
    fn test_recurrence_next_due_quarterly() {
        let date = NaiveDate::from_ymd_opt(2026, 1, 15).unwrap();
        let next = Recurrence::Quarterly.next_due(date);
        assert_eq!(next.year(), 2026);
        assert_eq!(next.month(), 4);
        assert_eq!(next.day(), 15);
    }

    #[test]
    fn test_scheduled_monitor_validate_registry_code() {
        let monitor = ScheduledRegistryMonitor::new("16588745".into());
        assert!(monitor.validate_registry_code("16588745"));
        assert!(monitor.validate_registry_code("12345678"));
        assert!(!monitor.validate_registry_code(""));
        assert!(!monitor.validate_registry_code("ABC123"));
        assert!(!monitor.validate_registry_code("123456789012345678901"));
    }

    #[test]
    fn test_scheduled_monitor_seed_estonian_ou_notices() {
        let mut monitor = ScheduledRegistryMonitor::new("16588745".into());
        monitor.seed_estonian_ou_notices("Bel Consulting OÜ", "16588745");

        let all = monitor.monitor().list_all();
        assert_eq!(all.len(), 5, "Expected 5 seeded notices");

        let titles: Vec<&str> = all.iter().map(|n| n.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("Annual Report Filing")));
        assert!(titles
            .iter()
            .any(|t| t.contains("Contact Person Verification")));
        assert!(titles.iter().any(|t| t.contains("VAT Declaration")));
        assert!(titles.iter().any(|t| t.contains("Social Tax Declaration")));
        assert!(titles.iter().any(|t| t.contains("Statistical Report")));
    }

    #[test]
    fn test_scheduled_monitor_check_annual_report() {
        let mut monitor = ScheduledRegistryMonitor::new("16588745".into());
        monitor.seed_estonian_ou_notices("Bel Consulting OÜ", "16588745");

        let deadlines = monitor.check_annual_report_deadline(2027);
        let annual_reports: Vec<&RegistryNotice> = deadlines
            .iter()
            .filter(|n| n.title.contains("Annual Report Filing"))
            .collect();
        assert!(!annual_reports.is_empty());
        assert_eq!(annual_reports[0].due_date.year(), 2027);
    }

    #[test]
    fn test_registry_code_property() {
        let monitor = ScheduledRegistryMonitor::new("16588745".into());
        assert_eq!(monitor.registry_code(), "16588745");
    }

    #[test]
    fn test_check_monthly_edge_case_month_end() {
        let mut monitor = RegistryMonitor::new();
        let notice = sample_notice(
            "REG-EDGE",
            "End of month deadline",
            NaiveDate::from_ymd_opt(2026, 7, 31).unwrap(),
            Recurrence::Monthly,
        );
        monitor.add_notice(notice);

        let due = monitor.check_monthly(NaiveDate::from_ymd_opt(2026, 7, 15).unwrap());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].notice_id, "REG-EDGE");
    }

    // ── residual-arm coverage: recurrence rollovers, category/failed lookups,
    //    the scheduler seam and the default registry code ───────────────────

    #[test]
    fn next_due_quarterly_and_monthly_roll_over_the_year_end() {
        // Quarterly across the year boundary (Oct 31 -> Jan 31 next year).
        let q = Recurrence::Quarterly.next_due(NaiveDate::from_ymd_opt(2026, 10, 31).unwrap());
        assert_eq!(q, NaiveDate::from_ymd_opt(2027, 1, 31).unwrap());
        // Quarterly where the target month is shorter than the source day:
        // Jan 31 + 3 months clamps to Apr 28, and Nov 30 + 3 months clamps
        // to the (non-leap) Feb 28 — both take the or_else arm.
        let q_clamped =
            Recurrence::Quarterly.next_due(NaiveDate::from_ymd_opt(2026, 1, 31).unwrap());
        assert_eq!(q_clamped, NaiveDate::from_ymd_opt(2026, 4, 28).unwrap());
        let q_feb = Recurrence::Quarterly.next_due(NaiveDate::from_ymd_opt(2026, 11, 30).unwrap());
        assert_eq!(q_feb, NaiveDate::from_ymd_opt(2027, 2, 28).unwrap());
        // Monthly with a day the next month lacks: Jan 30 clamps to Feb 28.
        assert_eq!(
            Recurrence::Monthly.next_due(NaiveDate::from_ymd_opt(2026, 1, 30).unwrap()),
            NaiveDate::from_ymd_opt(2026, 2, 28).unwrap()
        );
        // Monthly across the year boundary (Dec 15 -> Jan 15 next year).
        let m = Recurrence::Monthly.next_due(NaiveDate::from_ymd_opt(2026, 12, 15).unwrap());
        assert_eq!(m, NaiveDate::from_ymd_opt(2027, 1, 15).unwrap());
        // A same-year monthly step and a same-year quarterly step.
        assert_eq!(
            Recurrence::Monthly.next_due(NaiveDate::from_ymd_opt(2026, 4, 30).unwrap()),
            NaiveDate::from_ymd_opt(2026, 5, 30).unwrap()
        );
        assert_eq!(
            Recurrence::Quarterly.next_due(NaiveDate::from_ymd_opt(2026, 2, 1).unwrap()),
            NaiveDate::from_ymd_opt(2026, 5, 1).unwrap()
        );
        // Annual on Feb 29 clamps to Feb 28 of the next year.
        assert_eq!(
            Recurrence::Annual.next_due(NaiveDate::from_ymd_opt(2028, 2, 29).unwrap()),
            NaiveDate::from_ymd_opt(2029, 2, 28).unwrap()
        );
        // One-time notices are their own next due date.
        assert_eq!(
            Recurrence::OneTime.next_due(NaiveDate::from_ymd_opt(2026, 9, 21).unwrap()),
            NaiveDate::from_ymd_opt(2026, 9, 21).unwrap()
        );
    }

    #[test]
    fn check_monthly_rolls_into_january_for_december_reference() {
        let mut monitor = RegistryMonitor::new();
        monitor.add_notice(sample_notice(
            "REG-DEC-END",
            "Year-end filing",
            NaiveDate::from_ymd_opt(2026, 12, 20).unwrap(),
            Recurrence::Monthly,
        ));
        // A December reference builds the window end from the NEXT YEAR's
        // January 1 (the rollover arm) minus one day.
        let due = monitor.check_monthly(NaiveDate::from_ymd_opt(2026, 12, 15).unwrap());
        assert_eq!(due.len(), 1, "a late-December notice is inside the window");
        assert_eq!(due[0].notice_id, "REG-DEC-END");
    }

    #[test]
    fn complete_notice_reports_unknown_ids_and_category_lookup_filters() {
        let mut monitor = RegistryMonitor::new();
        assert!(
            !monitor.complete_notice("REG-NEVER"),
            "an unknown notice must not report completion"
        );
        monitor.add_notice(sample_notice(
            "REG-CAT",
            "Categorised",
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
            Recurrence::Annual,
        ));
        let pending = monitor.notices_by_category(NoticeStatus::Pending);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].notice_id, "REG-CAT");
        assert!(monitor
            .notices_by_category(NoticeStatus::InProgress)
            .is_empty());
        monitor.complete_notice("REG-CAT");
        assert_eq!(
            monitor.notices_by_category(NoticeStatus::Completed).len(),
            1,
            "the completed notice is found by its new status"
        );
    }

    #[tokio::test]
    async fn scheduled_monitor_seam_and_default_drive_the_monthly_loop() {
        // Default: the production registry code.
        let monitor = ScheduledRegistryMonitor::default();
        assert_eq!(monitor.registry_code(), "16588745");
        assert_eq!(
            monitor.check_interval_snapshot(),
            Duration::from_secs(30 * 24 * 3600)
        );

        // with_interval overrides the tick period; monitor_mut exposes the
        // inner registry for seeding.
        let mut monitor = ScheduledRegistryMonitor::new("12345678".into())
            .with_interval(Duration::from_millis(10));
        assert_eq!(monitor.check_interval_snapshot(), Duration::from_millis(10));
        monitor.monitor_mut().add_notice(sample_notice(
            "REG-OVERDUE",
            "Already late",
            // Long past: flagged by the loop's overdue arm.
            NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
            Recurrence::OneTime,
        ));
        monitor.monitor_mut().add_notice(sample_notice(
            "REG-DUE-NOW",
            "Due this month",
            Utc::now().date_naive(),
            Recurrence::Monthly,
        ));

        // Drive the loop: the first tick fires immediately, the second after
        // one 10 ms period — both arms (overdue warn + due-this-month info)
        // execute against real notices. Aborted after 50 ms.
        let task = tokio::spawn(async move { monitor.run_monthly().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
    }
}
