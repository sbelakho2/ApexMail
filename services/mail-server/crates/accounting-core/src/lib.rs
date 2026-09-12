//! ApexMail statutory accounting core (migration 220).
//!
//! This crate is the first-class accounting domain the statutory reports must
//! derive from. Before it existed, `compliance/src/estonia_ou.rs` assembled
//! annual reports and KMD/TSD declarations directly from operational tables
//! (`invoices`, `payroll_records`, `operating_costs`) with a hard-coded
//! company identity and no journal, no balancing rule and no retention
//! guarantee. Estonian law (RPS §12, MKS §25) requires source documents and
//! accounting registers — journals and ledgers — to be retained for seven
//! years.
//!
//! # Invariants and where they are enforced
//!
//! | Invariant | Enforcement |
//! |---|---|
//! | `SUM(debit) == SUM(credit)` per posted journal | DEFERRABLE constraint trigger `trg_journal_entries_balanced` (migration 220) plus the fail-fast check in [`posting::post_journal_entry`] |
//! | Posted entries immutable | BEFORE UPDATE/DELETE triggers `trg_journal_entries_guard` / `trg_journal_lines_guard`; corrections are reversal/adjusting entries ([`posting::reverse_entry`]) |
//! | Every entry has a source/evidence hash | `journal_entries.source_hash NOT NULL` (sha256 hex), computed by [`hash::evidence_hash`] |
//! | Periods lock after close | `fiscal_periods.status` open → closed → locked, state machine trigger, and posting guard that refuses non-open periods |
//! | Idempotent posting per source document | `UNIQUE (source_type, source_table, source_id)` on `accounting_source_documents` and `UNIQUE (idempotency_key)` on `journal_entries`; every adapter uses `INSERT .. ON CONFLICT DO NOTHING` |
//! | Seven-year retention | `retention_class` columns referencing `accounting_retention_classes`; BEFORE DELETE guard refusing `legal_7y`/`legal_10y` deletes without an explicit audited override |
//!
//! # Read contract for tax / annual-report derivation
//!
//! Filing code (KMD, TSD, annual report) MUST read posted ledger data through
//! [`derive`] (or the equivalent SQL views `v_accounting_trial_balance`,
//! `v_accounting_vat_entries`, `v_accounting_payroll_taxes`,
//! `v_accounting_period_movement`, `v_accounting_posted_entries`). The
//! operational tables remain the evidence trail; they are not the ledger.
//!
//! * VAT-recognizable entries for period P:
//!   [`derive::vat_entries_for_period`] → every posted journal line on a
//!   `vat_output`/`vat_input` account, carrying `net_cents` (taxable base),
//!   `vat_cents` (tax), `vat_rate_bp`, `vat_code` and the source document it
//!   derives from. [`derive::vat_totals_for_period`] aggregates them.
//! * Payroll/tax (TSD) entries for period P:
//!   [`derive::payroll_taxes_for_period`].
//! * Annual report inputs for period P: [`derive::trial_balance`] and
//!   [`derive::period_movement`].
//! * Full audit trail: [`derive::posted_entries`] and
//!   [`derive::entries_for_source`].
//!
//! # Adapters
//!
//! [`adapters`] contains the postings from real operational sources; each
//! function documents the origin file:line of its event. The billing service
//! calls the invoice / credit-note / payment-allocation adapters from the
//! flow that already records the event (see
//! `billing-service/src/accounting_postings.rs`).
//!
//! Payroll, expenses and bank statements have NO production writer in the
//! repository (no payroll run, no expense entry, no bank feed). For those,
//! [`sweeps`] posts every unposted source row with the same `FOR UPDATE SKIP
//! LOCKED` discipline as the projectors, so a future writer — or `psql` — is
//! posted with no further wiring; see the module docs for the exact claim
//! protocol and the per-source gap statement.
//!
//! # Guarantees of this crate
//!
//! * `#![deny(unsafe_code)]`
//! * no panics / unwraps outside tests
//! * no runtime DDL — the schema in migration 220 is deploy-time only

#![deny(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

pub mod adapters;
pub mod chart;
pub mod derive;
pub mod error;
pub mod hash;
pub mod periods;
pub mod posting;
pub mod retention;
pub mod sweeps;
pub mod types;

pub use error::{AccountingError, Result};
pub use types::{
    EntryType, JournalLine, PayrollAmounts, PostJournalRequest, PostOutcome, PostStatus,
    SourceIdentity, RETENTION_LEGAL_10Y, RETENTION_LEGAL_7Y, RETENTION_OPERATIONAL, ROLE_AP,
    ROLE_AR, ROLE_BANK, ROLE_EXPENSE_DEFAULT, ROLE_REFUNDS, ROLE_REVENUE, ROLE_VAT_INPUT,
    ROLE_VAT_OUTPUT, ROLE_WALLET_LIABILITY,
};
