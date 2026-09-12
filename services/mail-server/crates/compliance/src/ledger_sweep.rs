//! Interim production runner for the accounting-core payroll/expense sweeps.
//!
//! The statutory reports this crate produces (KMD/TSD/annual report) must
//! derive from the posted ledger, not from operational tables, so a complete
//! ledger is a compliance concern. There is no dedicated accounting service or
//! scheduler in the repository yet: the compliance server's existing cron is
//! the honest interim host for the two sources whose policy lives in this
//! crate.
//!
//! # What is actually missing (stated plainly)
//!
//! * **Payroll** — nothing in the repository inserts `payroll_records`: there
//!   is no payroll-run feature, admin endpoint or CLI. The missing piece is
//!   the payroll-run feature itself; the posting side is complete.
//!   [`EstonianPayrollPolicy`] computes the statutory amounts from the
//!   date-effective [`crate::tax_policy`] (the same formula as
//!   `estonia_ou::query_employees`), and the sweep posts every unposted
//!   record the moment any writer creates one.
//! * **Expenses** — `operating_costs` is deployment-optional (migration 220
//!   deliberately does not create it) and nothing writes it. The sweep
//!   reports `source_table_missing` when the store is absent and posts every
//!   positive row once a deployment provisions it or an expense feature
//!   writes one. The missing piece is the expense-entry feature.
//!
//! The bank statement sweep is NOT run here: a bank ledger loop belongs to
//! the bank feed service, which does not exist yet. It is implemented and
//! tested in `accounting_core::sweeps` (`sweep_unposted_bank_statement_lines`)
//! and awaits its host.

use accounting_core::sweeps::{
    self, PayrollAmountsPolicy, PayrollRecordFacts, SweepConfig, SweepReport,
};
use accounting_core::PayrollAmounts;
use sqlx::PgPool;

use crate::tax_policy;

/// Estonian payroll policy: per-employee II-pillar rate and exemptions from
/// the payroll record, rates from the versioned date-effective
/// [`crate::tax_policy`] module — never a permanent constant.
///
/// Mirrors `estonia_ou::query_employees` exactly (employer cost = gross +
/// social + employer unemployment; withholding base = gross − employee
/// unemployment − funded pension). A record with no pension participation
/// input (`funded_pension_rate IS NULL` and no exemption) returns `None`:
/// "incomplete", never an assumed rate (migration 199's contract).
#[derive(Debug, Clone, Copy, Default)]
pub struct EstonianPayrollPolicy;

impl PayrollAmountsPolicy for EstonianPayrollPolicy {
    fn amounts_for(
        &self,
        record: &PayrollRecordFacts,
    ) -> accounting_core::Result<Option<PayrollAmounts>> {
        if record.gross_salary_cents <= 0 {
            // The sweep reports a zero-gross record as unpostable before
            // calling the policy; keep the policy honest for direct callers.
            return Ok(None);
        }

        let gross = record.gross_salary_cents;
        let date = record.pay_period.date_naive();

        let social_tax_cents = (gross as f64 * tax_policy::social_tax_rate(date)).round() as i64;
        let unemployment_employer_cents = if record.unemployment_insurance_exemption {
            0
        } else {
            (gross as f64 * tax_policy::unemployment_insurance_employer_rate(date)).round() as i64
        };
        let unemployment_employee_cents = if record.unemployment_insurance_exemption {
            0
        } else {
            (gross as f64 * tax_policy::unemployment_insurance_employee_rate(date)).round() as i64
        };

        let pension_rate = if record.pension_exemption {
            Some(0.0)
        } else {
            record.funded_pension_rate
        };
        let Some(pension_rate) = pension_rate else {
            // Participation unknown: the record is incomplete, not zero-rated.
            return Ok(None);
        };
        let pension_cents = (gross as f64 * pension_rate).round() as i64;

        let taxable_cents = gross - unemployment_employee_cents - pension_cents;
        let income_tax_cents =
            (taxable_cents as f64 * tax_policy::income_tax_withheld_rate(date)).round() as i64;
        let net_cents = gross - unemployment_employee_cents - pension_cents - income_tax_cents;

        Ok(Some(PayrollAmounts {
            income_tax_cents,
            social_tax_cents,
            unemployment_employee_cents,
            unemployment_employer_cents,
            pension_cents,
            net_cents,
        }))
    }
}

/// One sweep tick for the two compliance-owned financial sources.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct LedgerSweepReport {
    pub payroll: SweepReport,
    pub expenses: SweepReport,
}

impl LedgerSweepReport {
    pub fn total_posted(&self) -> u64 {
        self.payroll.posted + self.expenses.posted
    }
}

/// Run the payroll and expense sweeps once. Idempotent; safe to call on every
/// tick and from multiple processes (SKIP LOCKED claim, see
/// `accounting_core::sweeps`).
pub async fn sweep_payroll_and_expenses(db: &PgPool) -> anyhow::Result<LedgerSweepReport> {
    let config = SweepConfig::default();
    let payroll = sweeps::sweep_unposted_payroll(db, &config, &EstonianPayrollPolicy).await?;
    let expenses = sweeps::sweep_unposted_expenses(db, &config).await?;
    Ok(LedgerSweepReport { payroll, expenses })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn record(
        gross_salary_cents: i64,
        funded_pension_rate: Option<f64>,
        pension_exemption: bool,
    ) -> PayrollRecordFacts {
        PayrollRecordFacts {
            id: Uuid::nil(),
            employee_name: Some("Test".to_string()),
            gross_salary_cents,
            funded_pension_rate,
            pension_exemption,
            unemployment_insurance_exemption: false,
            pay_period: chrono::Utc.with_ymd_and_hms(2026, 6, 30, 12, 0, 0).unwrap(),
        }
    }

    #[test]
    fn computes_the_same_amounts_as_the_tsd_declaration() {
        // 2026 rates: social 33%, employer unemployment 0.8%, employee 1.6%,
        // withheld income 22%; employee pension choice 2%.
        let amounts = EstonianPayrollPolicy
            .amounts_for(&record(200_000, Some(0.02), false))
            .expect("policy")
            .expect("complete record");
        assert_eq!(amounts.social_tax_cents, 66_000);
        assert_eq!(amounts.unemployment_employer_cents, 1_600);
        assert_eq!(amounts.unemployment_employee_cents, 3_200);
        assert_eq!(amounts.pension_cents, 4_000);
        assert_eq!(amounts.income_tax_cents, 42_416);
        assert_eq!(amounts.net_cents, 150_384);
        // The adapter's identity: gross = net + withheld employee items.
        assert_eq!(
            amounts.net_cents
                + amounts.income_tax_cents
                + amounts.unemployment_employee_cents
                + amounts.pension_cents,
            200_000
        );
    }

    #[test]
    fn unknown_pension_participation_is_incomplete_not_zero_rated() {
        assert!(EstonianPayrollPolicy
            .amounts_for(&record(100_000, None, false))
            .expect("policy")
            .is_none());
        // A legal exemption is a KNOWN 0% choice and posts.
        let exempt = EstonianPayrollPolicy
            .amounts_for(&record(100_000, None, true))
            .expect("policy")
            .expect("exempt is complete");
        assert_eq!(exempt.pension_cents, 0);
        assert_eq!(exempt.social_tax_cents, 33_000);
    }

    #[test]
    fn zero_gross_is_left_to_the_sweep_to_report() {
        assert!(EstonianPayrollPolicy
            .amounts_for(&record(0, Some(0.02), false))
            .expect("policy")
            .is_none());
    }
}
