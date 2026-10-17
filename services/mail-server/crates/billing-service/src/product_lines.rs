//! Contract product-line billing: the **Platform** and **Mailboxes** lines
//! (the owner's 2026-10-15 price table, `platform-catalog`).
//!
//! Before this module the two lines existed only as catalog rows: the
//! `platform` contract line (base + per-1K overage + per-subaccount fee),
//! and the Mailboxes add-on (per-seat, 10-seat minimum, archive add-on).
//! `ent_sub_accounts` rows were an enterprise feature nothing billed;
//! `mail_accounts` were provisioning-only. This module turns both into real
//! monthly invoices through the SAME machinery the subscription/PAYG sweeps
//! use — `billing_periods` rows (one per tenant/line/period), an invoice
//! created with a period-identity marker, per-period state transitions and
//! the shared collection ladder ([`crate::overage::collect_usage_invoice`]:
//! wallet first, then the recurring Adyen charge, then dunning).
//!
//! # The model (and its truth source)
//!
//! * **Who is billed.** `product_line_contracts` (migration 256) — one row
//!   per (tenant, product line), written by ops/sales when the line is
//!   contracted. Only a row with `status = 'active'` (or a terminated row
//!   whose recorded `ended_at` is still in the future) makes a tenant
//!   billable. There was no other record of "this tenant holds the Platform
//!   plan": `tenants.plan` names self-serve plans in the `plans` table and
//!   the catalog product lines are contractual, not self-serve.
//! * **What period.** Completed CALENDAR months, the same period shape the
//!   PAYG half of the overage sweep invoices (contract lines are billed
//!   monthly on 12-month terms; there is no subscription cycle to read).
//!   No proration exists: a month bills only when the contract covered it
//!   IN FULL ([`contract_covers_period`]) — a partially covered first or
//!   final month is not billed, and that is stated, not prorated.
//! * **Currency.** The tenant's billing currency (`settings.billingCurrency`),
//!   normalized exactly like the api-server checkout resolver; the catalog
//!   prices in EUR and USD, and the USD list applies when (and only when)
//!   the tenant bills in USD — the same rule the self-serve checkout uses
//!   (`routes/billing.rs` `resolve_tenant_billing_currency`). The resolved
//!   currency (and the whole price set) is snapshotted onto the period row
//!   at claim time (audit F32 discipline): a later settings change can never
//!   reprice an existing month.
//! * **Freeze.** Per period, per line: the price set, the invoice identity
//!   and the invoice itself are written under an advisory lock and one
//!   transaction per phase, so a replay either finds the terminal state or
//!   adopts the existing invoice — never a second charge.
//!
//! # Platform line
//!
//! * base 990 EUR / 1 090 USD per month for tenants on the `platform` line
//!   (`platform-catalog` `PRODUCT_LINES` row, pinned by test);
//! * usage tier: `emails_sent` in the period minus the 1 000 000 included
//!   at 0.30 EUR / 0.35 USD per 1 000 — computed with the SAME integer
//!   millicents-per-email arithmetic as the plan overage ladder
//!   ([`crate::plans::calculate_overage_cost_with_rate`], ceiling to the
//!   cent, i128 intermediate, no floats). The catalog's per-1K cent figure
//!   and the per-email millicent rate are numerically the same number by
//!   construction (0.30 EUR/1 000 emails = 0.03 cents = 30 millicents per
//!   email) — pinned by test so a future edit of either constant fails;
//! * active subaccounts above the included 100 bill 1 EUR / 1 USD each.
//!   **"Active" is `ent_sub_accounts.status = 'active'`** — the table's own
//!   status vocabulary (`CHECK (status IN ('active','suspended'))`,
//!   migration 092) and the exact filter the enterprise list/read paths
//!   apply. Suspended children do not bill. The count is read as
//!   `parent_id = tenant` — the same parent column the quota check locks on.
//!
//! # Mailboxes line
//!
//! * Seats bill from the mailboxes actually PROVISIONED for the tenant:
//!   `mail_accounts` rows with `tenant_id = <tenant>` and `is_active`
//!   (`mail_mailboxes` are FOLDERS — INBOX, Sent, ... — inside an account,
//!   not mailboxes; the account row is the seat). The entitlement-gated
//!   provisioning path (`api-server` `routes/admin/mailboxes.rs`) is the
//!   purchase act, so no separate contracted-seat count exists.
//! * The billable seat count is floored at the catalog minimum
//!   ([`platform_catalog::MAILBOX_MINIMUM_SEATS`], 10): 5 provisioned
//!   mailboxes bill 10 seats.
//! * 6 EUR / 7 USD per seat per month, plus 2 EUR / 2 USD per seat carrying
//!   the archive flag (`mail_accounts.archive_enabled`, migration 256) —
//!   the flag bills ARCHIVE seats for seats that exist: a flagged seat is
//!   counted once, and the minimum-seat floor applies to seats, never to
//!   the archive add-on (5 flagged seats bill 10 seats + 5 archive seats).
//!
//! # What is NOT built (named, not faked)
//!
//! * **Operator CRUD for product-line contracts.** Contract rows are
//!   written by ops SQL (or a future admin route); this deliverable is the
//!   billing path the brief asked for, and the table is the single truth
//!   source both the sweep and the Mailboxes provisioning gate read.
//! * **Mailbox journaling.** Nothing copies inbound/outbound messages to a
//!   journal destination, and there is no third-party journal connector.
//!   The billing flag and the mail-side retention marker (the account's
//!   `Archive` folder + `archive_enabled_at`) are wired; the journaling
//!   transport is not.
//! * **Archive retrieval UI.** No tenant-facing archive browse/search
//!   surface exists; archived messages are reachable through IMAP like any
//!   other folder. `compliance::legal_archive` is the regulatory
//!   disclosure archive (GDPR evidence), explicitly NOT a mail archive.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::invoices::{create_invoice_in_tx, CreateInvoiceInput, InvoiceError, NewLineItem};
use crate::AppState;

/// `billing_periods.usage_kind` for the Platform contract line.
pub const PLATFORM_USAGE_KIND: &str = "platform";

/// `billing_periods.usage_kind` for the Mailboxes seat line.
pub const MAILBOXES_USAGE_KIND: &str = "mailboxes";

/// The `product_line_contracts.product_line` values this module bills.
pub const PLATFORM_PRODUCT_LINE: &str = "platform";
/// The Mailboxes product line (also the provisioning entitlement record).
pub const MAILBOXES_PRODUCT_LINE: &str = "mailboxes";

/// Default currency when the tenant has no valid billing currency — the
/// same default the api-server resolver applies.
pub const DEFAULT_PRODUCT_LINE_CURRENCY: &str = "EUR";

/// Name of the schema-level invoice-identity backstop (migration 256).
const PRODUCT_LINES_UNIQUE_CONSTRAINT: &str = "uq_invoices_tenant_product_lines_period";

/// Sweep page size (same shape as the overage sweep's tenant pagination).
const SWEEP_PAGE: i64 = 100;

/// Tenants holding a sweepable contract, keyset-paginated on `tenant_id`.
///
/// The status filter is EXPLICITLY parenthesized: SQL binds `AND` tighter
/// than `OR`, so the unparenthesized form applied the cursor predicate to
/// the terminated branch only — every page re-selected all `active` tenants
/// and the paging loop could never terminate once more than one page held
/// active contracts. Pinned by unit test.
const SWEEP_TENANTS_SQL: &str = r#"
    SELECT DISTINCT tenant_id
    FROM product_line_contracts
    WHERE (status = 'active'
           OR (status = 'terminated' AND ended_at IS NOT NULL))
      AND ($1::text IS NULL OR tenant_id > $1::text)
    ORDER BY tenant_id
    LIMIT $2
    "#;

/// Whether the product-line sweep is enabled. Default ON; the env switch
/// mirrors `OVERAGE_INVOICING_ENABLED` so an operator can stop the sweep
/// without a deploy (`PRODUCT_LINE_INVOICING_ENABLED=false|0|off|no`).
pub fn product_line_invoicing_enabled() -> bool {
    parse_invoicing_switch(
        std::env::var("PRODUCT_LINE_INVOICING_ENABLED")
            .ok()
            .as_deref(),
    )
}

/// The switch's value parsing, split out so every accepted spelling is
/// unit-testable without mutating the process environment.
fn parse_invoicing_switch(raw: Option<&str>) -> bool {
    match raw {
        None => true,
        Some(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
    }
}

// ---------------------------------------------------------------------------
// Currency
// ---------------------------------------------------------------------------

/// Normalize a `settings.billingCurrency` value exactly like the api-server
/// resolver (`routes::billing::resolve_tenant_billing_currency`): trim,
/// uppercase, accept only a 3-letter ASCII code; anything else is EUR. Kept
/// as a mirror (both are pinned by tests) because the billing service does
/// not depend on the api-server crate.
pub fn normalize_billing_currency(raw: Option<&str>) -> String {
    let normalized = raw
        .unwrap_or(DEFAULT_PRODUCT_LINE_CURRENCY)
        .trim()
        .to_uppercase();
    if normalized.len() == 3 && normalized.chars().all(|c| c.is_ascii_uppercase()) {
        normalized
    } else {
        DEFAULT_PRODUCT_LINE_CURRENCY.to_string()
    }
}

/// The catalog price list a billing currency maps to: the USD list when the
/// tenant bills in USD, the EUR list otherwise — the checkout's rule (the
/// catalog carries exactly these two lists; a GBP-billing tenant is quoted
/// the EUR list, exactly as self-serve checkout charges them).
pub fn catalog_price_currency(billing_currency: &str) -> &'static str {
    if billing_currency.trim().eq_ignore_ascii_case("USD") {
        "USD"
    } else {
        "EUR"
    }
}

// ---------------------------------------------------------------------------
// Platform line — pricing and charge computation (pure, integer cents)
// ---------------------------------------------------------------------------

/// The Platform line's frozen price set for one currency (`platform-catalog`
/// is the source; nothing here is a second price table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformPricing {
    pub currency: &'static str,
    /// Contract-line base fee, cents per month.
    pub base_cents: i64,
    /// Emails included per month before the usage tier applies.
    pub included_emails: i64,
    /// Usage rate in `billing_periods.overage_rate_millicents` units
    /// (millicents per email — the per-1K cent figure, see the module doc).
    pub overage_rate_millicents: i64,
    /// Active subaccounts included before the per-subaccount fee.
    pub included_subaccounts: i64,
    /// Monthly fee per active subaccount above the included count, cents.
    pub subaccount_cents: i64,
}

impl PlatformPricing {
    /// The whole price set as the period's `pricing_snapshot` JSON (audit
    /// F32: the period is priced from THIS, never from today's catalog).
    pub fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshotVersion": 1,
            "usageKind": PLATFORM_USAGE_KIND,
            "currency": self.currency,
            "baseCents": self.base_cents,
            "includedEmails": self.included_emails,
            "overageRateMillicents": self.overage_rate_millicents,
            "includedSubaccounts": self.included_subaccounts,
            "subaccountMonthlyCents": self.subaccount_cents,
            "source": "platform-catalog",
        })
    }
}

/// The Platform price set for a catalog price currency ("EUR" or "USD";
/// anything else reads as EUR through [`catalog_price_currency`]).
pub fn platform_pricing(price_currency: &str) -> PlatformPricing {
    let currency = catalog_price_currency(price_currency);
    let (base_cents, overage_rate_millicents, subaccount_cents) = if currency == "USD" {
        (
            platform_catalog::product_line_by_name(PLATFORM_PRODUCT_LINE)
                .expect("catalog carries the platform line")
                .price_monthly_usd_cents,
            platform_catalog::PLATFORM_OVERAGE_USD_CENTS_PER_1K,
            platform_catalog::PLATFORM_SUBACCOUNT_MONTHLY_USD_CENTS,
        )
    } else {
        (
            platform_catalog::product_line_by_name(PLATFORM_PRODUCT_LINE)
                .expect("catalog carries the platform line")
                .price_monthly_cents,
            platform_catalog::PLATFORM_OVERAGE_CENTS_PER_1K,
            platform_catalog::PLATFORM_SUBACCOUNT_MONTHLY_CENTS,
        )
    };
    PlatformPricing {
        currency,
        base_cents,
        included_emails: platform_catalog::PLATFORM_INCLUDED_EMAILS,
        overage_rate_millicents,
        included_subaccounts: platform_catalog::PLATFORM_INCLUDED_SUBACCOUNTS,
        subaccount_cents,
    }
}

/// One Platform charge for a period, every component in integer cents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformCharge {
    pub pricing: PlatformPricing,
    pub emails_sent: i64,
    pub overage_emails: i64,
    pub overage_cents: i64,
    pub active_subaccounts: i64,
    pub billable_subaccounts: i64,
    pub subaccount_cents: i64,
}

impl PlatformCharge {
    /// The line total: base + usage tier + subaccount fee.
    pub fn total_cents(&self) -> i64 {
        self.pricing
            .base_cents
            .saturating_add(self.overage_cents)
            .saturating_add(self.subaccount_cents)
    }
}

/// Compute one Platform period charge. Integer cents throughout; the usage
/// tier reuses the plan overage ladder's exact arithmetic
/// ([`crate::plans::calculate_overage_cost_with_rate`]: ceiling to the
/// cent, i128 intermediate). Saturating adds keep a pathological reading
/// from wrapping — `i64::MAX` cents is ~9.2 × 10^16 EUR.
pub fn platform_charge(
    emails_sent: i64,
    active_subaccounts: i64,
    pricing: &PlatformPricing,
) -> PlatformCharge {
    let emails_sent = emails_sent.max(0);
    let active_subaccounts = active_subaccounts.max(0);
    let overage_emails = emails_sent.saturating_sub(pricing.included_emails).max(0);
    let overage_cents = crate::plans::calculate_overage_cost_with_rate(
        emails_sent,
        pricing.included_emails,
        pricing.overage_rate_millicents,
    );
    let billable_subaccounts = active_subaccounts
        .saturating_sub(pricing.included_subaccounts)
        .max(0);
    let subaccount_cents = billable_subaccounts.saturating_mul(pricing.subaccount_cents);
    PlatformCharge {
        pricing: *pricing,
        emails_sent,
        overage_emails,
        overage_cents,
        active_subaccounts,
        billable_subaccounts,
        subaccount_cents,
    }
}

// ---------------------------------------------------------------------------
// Mailboxes line — pricing and charge computation (pure, integer cents)
// ---------------------------------------------------------------------------

/// The Mailboxes line's frozen price set for one currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxPricing {
    pub currency: &'static str,
    /// Billable seats never fall below this (`platform-catalog`).
    pub minimum_seats: i64,
    /// Seat price, cents per mailbox per month.
    pub seat_cents: i64,
    /// Archive add-on price, cents per flagged seat per month.
    pub archive_seat_cents: i64,
}

impl MailboxPricing {
    /// The whole price set as the period's `pricing_snapshot` JSON.
    pub fn snapshot_json(&self) -> serde_json::Value {
        serde_json::json!({
            "snapshotVersion": 1,
            "usageKind": MAILBOXES_USAGE_KIND,
            "currency": self.currency,
            "minimumSeats": self.minimum_seats,
            "seatCents": self.seat_cents,
            "archiveSeatCents": self.archive_seat_cents,
            "source": "platform-catalog",
        })
    }
}

/// The Mailboxes price set for a catalog price currency.
pub fn mailbox_pricing(price_currency: &str) -> MailboxPricing {
    let currency = catalog_price_currency(price_currency);
    let in_usd = currency == "USD";
    let seats = platform_catalog::addon_by_name("mailboxes").expect("catalog add-on row");
    let archive =
        platform_catalog::addon_by_name("mailbox_archive_journaling").expect("catalog add-on row");
    MailboxPricing {
        currency,
        minimum_seats: platform_catalog::MAILBOX_MINIMUM_SEATS,
        seat_cents: if in_usd {
            seats.price_usd_cents
        } else {
            seats.price_cents
        },
        archive_seat_cents: if in_usd {
            archive.price_usd_cents
        } else {
            archive.price_cents
        },
    }
}

/// One Mailboxes charge for a period, integer cents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxCharge {
    pub pricing: MailboxPricing,
    /// Active mailbox accounts bound to the tenant.
    pub provisioned_seats: i64,
    /// What bills: `max(provisioned, minimum_seats)`.
    pub billable_seats: i64,
    pub seat_cents: i64,
    /// Provisioned seats carrying the archive flag.
    pub archive_seats: i64,
    pub archive_cents: i64,
}

impl MailboxCharge {
    pub fn total_cents(&self) -> i64 {
        self.seat_cents.saturating_add(self.archive_cents)
    }
}

/// Compute one Mailboxes period charge. The 10-seat minimum floors the
/// seat line; archive bills per flagged PROVISIONED seat (a flagged seat
/// beyond the floor is impossible — the floor is a minimum, not a pool).
pub fn mailbox_charge(
    provisioned_seats: i64,
    archive_seats: i64,
    pricing: &MailboxPricing,
) -> MailboxCharge {
    let provisioned_seats = provisioned_seats.max(0);
    // A flagged seat that does not exist is not a seat: archive bills per
    // flagged PROVISIONED seat (the SQL counts it that way; the clamp keeps
    // a hand-written snapshot from inventing seats).
    let archive_seats = archive_seats.max(0).min(provisioned_seats);
    let billable_seats = provisioned_seats.max(pricing.minimum_seats);
    MailboxCharge {
        pricing: *pricing,
        provisioned_seats,
        billable_seats,
        seat_cents: billable_seats.saturating_mul(pricing.seat_cents),
        archive_seats,
        archive_cents: archive_seats.saturating_mul(pricing.archive_seat_cents),
    }
}

// ---------------------------------------------------------------------------
// Invoice line shapes
// ---------------------------------------------------------------------------

/// One invoice line, before it becomes a [`NewLineItem`]. Kept as its own
/// comparable type so the exact line shapes (description, quantity, unit
/// price) are unit-testable without a database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChargeLine {
    pub description: String,
    pub quantity: i64,
    pub unit_price: i64,
}

impl ChargeLine {
    /// Line amount in cents (`quantity × unit_price`), checked — the same
    /// multiplication `create_invoice_in_tx` performs.
    pub fn amount_cents(&self) -> i64 {
        self.quantity.saturating_mul(self.unit_price)
    }
}

fn to_new_line_items(lines: &[ChargeLine]) -> Vec<NewLineItem> {
    lines
        .iter()
        .map(|line| NewLineItem {
            description: line.description.clone(),
            quantity: line.quantity,
            unit_price: line.unit_price,
        })
        .collect()
}

/// `99000` EUR → `"990.00 EUR"` — integer math, ISO code (never a symbol:
/// a legal document quoting "€… USD" misquotes the money, audit SM7 F9).
fn format_cents(cents: i64, currency: &str) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let absolute = cents.unsigned_abs();
    format!(
        "{sign}{}.{:02} {}",
        absolute / 100,
        absolute % 100,
        currency.trim().to_uppercase()
    )
}

/// The Platform invoice lines for one period: base always, then the usage
/// tier and the subaccount fee only when they are non-zero (a zero line on
/// a VAT invoice is noise; the brief's "zero-usage month still bills the
/// base" is exactly this shape).
pub fn platform_charge_lines(charge: &PlatformCharge, period_label: &str) -> Vec<ChargeLine> {
    let currency = charge.pricing.currency;
    let mut lines = vec![ChargeLine {
        description: format!(
            "Platform base ({period_label}) — {}/month, {} emails included",
            format_cents(charge.pricing.base_cents, currency),
            charge.pricing.included_emails
        ),
        quantity: 1,
        unit_price: charge.pricing.base_cents,
    }];
    if charge.overage_cents > 0 {
        lines.push(ChargeLine {
            description: format!(
                "Platform email usage ({period_label}) — {} emails beyond the {} included at {} per 1,000",
                charge.overage_emails,
                charge.pricing.included_emails,
                format_cents(charge.pricing.overage_rate_millicents, currency),
            ),
            quantity: 1,
            unit_price: charge.overage_cents,
        });
    }
    if charge.subaccount_cents > 0 {
        lines.push(ChargeLine {
            description: format!(
                "Platform active subaccounts ({period_label}) — {} above the {} included at {} each",
                charge.billable_subaccounts,
                charge.pricing.included_subaccounts,
                format_cents(charge.pricing.subaccount_cents, currency)
            ),
            quantity: charge.billable_subaccounts,
            unit_price: charge.pricing.subaccount_cents,
        });
    }
    lines
}

/// The Mailboxes invoice lines for one period: seats (floored at the
/// minimum) always, the archive add-on only when seats carry the flag.
pub fn mailbox_charge_lines(charge: &MailboxCharge, period_label: &str) -> Vec<ChargeLine> {
    let currency = charge.pricing.currency;
    let mut lines = vec![ChargeLine {
        description: format!(
            "Mailboxes ({period_label}) — {} billable seats at {} per seat per month ({} minimum)",
            charge.billable_seats,
            format_cents(charge.pricing.seat_cents, currency),
            charge.pricing.minimum_seats
        ),
        quantity: charge.billable_seats,
        unit_price: charge.pricing.seat_cents,
    }];
    if charge.archive_cents > 0 {
        lines.push(ChargeLine {
            description: format!(
                "Mailbox archive + journaling ({period_label}) — {} seats at {} per seat per month",
                charge.archive_seats,
                format_cents(charge.pricing.archive_seat_cents, currency)
            ),
            quantity: charge.archive_seats,
            unit_price: charge.pricing.archive_seat_cents,
        });
    }
    lines
}

// ---------------------------------------------------------------------------
// Contract coverage
// ---------------------------------------------------------------------------

/// Whether a contract covered a calendar month IN FULL. No proration:
/// `active_from` on/after the period start and no recorded end before the
/// period end. A partial first/last month is deliberately unbilled (the
/// safe direction — never a charge for days the tenant did not hold the
/// line).
pub fn contract_covers_period(
    active_from: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> bool {
    active_from <= period_start && ended_at.map(|ended| ended >= period_end).unwrap_or(true)
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

/// The sweep's run summary (one line per swept month, aggregated).
#[derive(Debug, Default, Clone)]
pub struct ProductLineSweepResult {
    /// Tenants holding at least one product-line contract that were visited.
    pub tenants_checked: u64,
    /// Tenant-months for which at least one line was billable.
    pub tenant_months_checked: u64,
    /// `billing_periods` rows billed by this run.
    pub periods_invoiced: u64,
    /// Invoices created by this run.
    pub invoices_created: u64,
    /// Months whose invoice identity was ALREADY taken by an existing
    /// invoice while this run had an unbilled line left (a backdated
    /// contract): the line is surfaced as `needs_review` for manual
    /// reconciliation — never silently linked, never re-collected.
    pub months_already_invoiced: u64,
    /// Period rows already in a terminal state (nothing to do).
    pub periods_already_terminal: u64,
    /// Months deferred because the tenant has no billing address (committed
    /// `needs_review` so the month stays visible).
    pub skipped_no_address: u64,
    /// Period rows surfaced as `needs_review` for a broken snapshot.
    pub periods_needs_review: u64,
    /// Tenant-months whose invoice failed — isolated, retried next sweep.
    pub failed_months: u64,
    /// Invoices settled from wallet balance by this run.
    pub wallet_paid: u64,
    /// Invoices handed to dunning by this run.
    pub pending_dunning: u64,
}

/// One contract row selected for sweeping.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProductLineContractRow {
    pub tenant_id: String,
    pub product_line: String,
    pub active_from: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// One claimed (unbilled) `billing_periods` row plus its frozen pricing.
#[derive(Debug, Clone)]
struct ClaimedPeriod {
    id: Uuid,
    usage_kind: &'static str,
    currency: String,
    pricing_snapshot: serde_json::Value,
}

/// The monthly contract-line sweep: for every tenant holding a product-line
/// contract, bill each completed calendar month the contract covered in
/// full, in the tenant's billing currency, through the shared invoice +
/// collection machinery. Idempotent per (tenant, line, month): the
/// `billing_periods` UNIQUE (tenant, usage_kind, period_start) and the
/// invoice's `product_lines_period` UNIQUE (tenant, period) are the
/// schema-level backstops; a replay finds the terminal period state and
/// creates nothing, and a line claimed against an ALREADY-invoiced month
/// (a backdated contract) is surfaced as `needs_review` rather than
/// silently joined to an invoice that never billed it.
pub async fn sweep_product_line_months(state: &AppState) -> Result<ProductLineSweepResult, String> {
    if !product_line_invoicing_enabled() {
        info!("product-line invoicing disabled (PRODUCT_LINE_INVOICING_ENABLED=false)");
        return Ok(ProductLineSweepResult::default());
    }

    let mut result = ProductLineSweepResult::default();
    // The completed months whose end lies inside the metering TTL window —
    // the same window the PAYG half uses (the platform usage tier reads
    // metering_events, which age out at 40 days).
    let months = crate::overage::recent_completed_calendar_months(Utc::now());

    let mut cursor: Option<String> = None;
    loop {
        let tenants: Vec<String> = sqlx::query_scalar(SWEEP_TENANTS_SQL)
            .bind(cursor.as_ref().cloned())
            .bind(SWEEP_PAGE)
            .fetch_all(&state.db)
            .await
            .map_err(|e| format!("product-line sweep: tenant query failed: {e}"))?;

        let page_len = tenants.len();
        // P3 fix 3 — the page's contracts and billing currencies load in ONE
        // query each. Before this, `load_contracts` ran once per tenant and
        // `resolve_tenant_billing_currency` once per tenant-MONTH (up to 2),
        // so a 100-tenant page cost up to 300 round trips before any billing
        // work; now it costs two.
        let contracts_by_tenant = load_contracts_for_tenants(state, &tenants).await?;
        let currencies_by_tenant = load_billing_currencies(&state.db, &tenants).await?;
        for tenant_id in &tenants {
            result.tenants_checked += 1;
            let contracts = contracts_by_tenant
                .get(tenant_id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let currency = currencies_by_tenant
                .get(tenant_id)
                .cloned()
                .unwrap_or_else(|| DEFAULT_PRODUCT_LINE_CURRENCY.to_string());
            for &(month_start, month_end) in &months {
                if let Err(error) = process_tenant_month(
                    state,
                    tenant_id,
                    month_start,
                    month_end,
                    contracts,
                    &currency,
                    &mut result,
                )
                .await
                {
                    // ONE failing tenant-month must not abort the sweep —
                    // it retries on the next run (nothing was committed for
                    // it: the claim and the invoice share transactions).
                    result.failed_months += 1;
                    warn!(
                        tenant_id = %tenant_id,
                        month = %month_start.format("%Y-%m"),
                        error = %error,
                        "product-line sweep: tenant-month failed — isolated; retried next sweep"
                    );
                }
            }
        }

        if page_len < SWEEP_PAGE as usize {
            break;
        }
        cursor = tenants.last().cloned();
    }

    Ok(result)
}

/// Load the sweepable contracts for a whole PAGE of tenants in ONE query,
/// grouped by tenant. This replaces the per-tenant load that made the sweep
/// N+1 in its tenant dimension (P3 fix 3). Tenants without a contract simply
/// have no map entry.
async fn load_contracts_for_tenants(
    state: &AppState,
    tenant_ids: &[String],
) -> Result<HashMap<String, Vec<ProductLineContractRow>>, String> {
    let mut by_tenant: HashMap<String, Vec<ProductLineContractRow>> = HashMap::new();
    if tenant_ids.is_empty() {
        return Ok(by_tenant);
    }
    #[cfg(test)]
    crate::test_support::query_count::bump("product_lines.contract_load");
    let rows: Vec<ProductLineContractRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, product_line, active_from, ended_at
        FROM product_line_contracts
        WHERE tenant_id = ANY($1)
          AND (status = 'active' OR (status = 'terminated' AND ended_at IS NOT NULL))
        ORDER BY tenant_id, product_line
        "#,
    )
    .bind(tenant_ids)
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("product-line sweep: contract query failed: {e}"))?;
    for row in rows {
        by_tenant
            .entry(row.tenant_id.clone())
            .or_default()
            .push(row);
    }
    Ok(by_tenant)
}

/// Resolve the billing currency for a whole PAGE of tenants in ONE query
/// (P3 fix 3: this used to run once per tenant-month). Missing/invalid
/// settings normalize to [`DEFAULT_PRODUCT_LINE_CURRENCY`] exactly like the
/// single-tenant resolver did.
async fn load_billing_currencies(
    db: &PgPool,
    tenant_ids: &[String],
) -> Result<HashMap<String, String>, String> {
    let mut currencies = HashMap::new();
    if tenant_ids.is_empty() {
        return Ok(currencies);
    }
    #[cfg(test)]
    crate::test_support::query_count::bump("product_lines.currency_load");
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT id, settings->>'billingCurrency' FROM tenants WHERE id = ANY($1)")
            .bind(tenant_ids)
            .fetch_all(db)
            .await
            .map_err(|e| format!("product-line sweep: billing currency query failed: {e}"))?;
    for (tenant_id, raw) in rows {
        currencies.insert(tenant_id, normalize_billing_currency(raw.as_deref()));
    }
    Ok(currencies)
}

/// The lines billable for one month: a contract row per line that covered
/// the month in full. An unknown `product_line` value is skipped with a
/// warning (the enum is closed by the migration's CHECK; a row from a newer
/// deployment must not be billed by guessed pricing).
fn billable_lines_for_month(
    contracts: &[ProductLineContractRow],
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Vec<&ProductLineContractRow> {
    contracts
        .iter()
        .filter(|row| {
            if !matches!(
                row.product_line.as_str(),
                PLATFORM_PRODUCT_LINE | MAILBOXES_PRODUCT_LINE
            ) {
                warn!(
                    tenant_id = %row.tenant_id,
                    product_line = %row.product_line,
                    "product-line sweep: unknown product line — skipped, never billed by guesswork"
                );
                return false;
            }
            contract_covers_period(row.active_from, row.ended_at, period_start, period_end)
        })
        .collect()
}

/// Process one tenant-month: claim the period rows (committed first — the
/// periods are the sweep's durable work queue), then invoice + mark in one
/// transaction and collect after the commit.
async fn process_tenant_month(
    state: &AppState,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    contracts: &[ProductLineContractRow],
    currency: &str,
    result: &mut ProductLineSweepResult,
) -> Result<(), String> {
    let lines = billable_lines_for_month(contracts, period_start, period_end);
    if lines.is_empty() {
        return Ok(());
    }
    result.tenant_months_checked += 1;

    ensure_period_records(state, tenant_id, period_start, period_end, &lines, currency).await?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("product-line sweep: claim tx failed: {e}"))?;

    // Serialize the per-(tenant, month) claim: the same advisory-lock shape
    // the PAYG half uses, held to the end of the invoice transaction.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "product-lines:{tenant_id}:{}",
            period_start.to_rfc3339()
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("product-line sweep: advisory lock failed: {e}"))?;

    let mut claimed: Vec<ClaimedPeriod> = Vec::new();
    for line in &lines {
        match claim_period(&mut tx, tenant_id, line.product_line.as_str(), period_start).await? {
            Some(period) => claimed.push(period),
            None => result.periods_already_terminal += 1,
        }
    }
    if claimed.is_empty() {
        tx.commit()
            .await
            .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
        return Ok(());
    }

    // A billing address is mandatory on a VAT invoice. The claim COMMITS as
    // `needs_review` (the PAYG precedent, audit SM7 F5): the month stays
    // visible for reconciliation instead of vanishing with a rollback.
    if !tenant_has_billing_address(tenant_id, &mut *tx).await? {
        result.skipped_no_address += 1;
        for period in &claimed {
            crate::overage::mark_period_needs_review(
                &mut tx,
                period.id,
                "no billing address on file — contract-line month retained for reconciliation",
            )
            .await?;
        }
        tx.commit()
            .await
            .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
        warn!(
            tenant_id = %tenant_id,
            month = %period_start.format("%Y-%m"),
            "product-line sweep: contract month billable but no billing address — committed as needs_review"
        );
        return Ok(());
    }

    // Prices come ONLY from each period's frozen snapshot (audit F32).
    let charges = match build_charges(&mut tx, tenant_id, period_start, period_end, &claimed).await
    {
        Ok(charges) => charges,
        Err(ChargeFailure::Unpriced { period_id, reason }) => {
            // A period with no usable snapshot is surfaced, never priced
            // from today's catalog.
            result.periods_needs_review += 1;
            crate::overage::mark_period_needs_review(&mut tx, period_id, &reason).await?;
            tx.commit()
                .await
                .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
            return Ok(());
        }
        Err(ChargeFailure::Fatal(error)) => {
            let _ = tx.rollback().await;
            return Err(error);
        }
    };

    // Every line on ONE invoice must be in ONE currency: the periods carry
    // their own frozen currency, and a mismatch (e.g. an old unbilled row
    // frozen in EUR next to a fresh USD row after a settings change) must
    // never mint a mixed-currency invoice. Surface the month for review.
    let period_currency = claimed[0].currency.clone();
    if let Some(mismatched) = claimed
        .iter()
        .find(|period| !period.currency.eq_ignore_ascii_case(&period_currency))
    {
        result.periods_needs_review += 1;
        for period in &claimed {
            crate::overage::mark_period_needs_review(
                &mut tx,
                period.id,
                &format!(
                    "currency mismatch across lines ({} vs {}) — refusing a mixed-currency invoice",
                    period_currency, mismatched.currency
                ),
            )
            .await?;
        }
        tx.commit()
            .await
            .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
        warn!(
            tenant_id = %tenant_id,
            month = %period_start.format("%Y-%m"),
            %period_currency,
            other = %mismatched.currency,
            "product-line sweep: period currencies disagree — month surfaced for review"
        );
        return Ok(());
    }

    let mut line_items: Vec<ChargeLine> = Vec::new();
    let mut metered_watermarks: Vec<(Uuid, Option<i64>)> = Vec::new();
    let mut description = String::new();
    for (period, charge) in claimed.iter().zip(charges.iter()) {
        let period_label = period_start.format("%Y-%m").to_string();
        match charge {
            PeriodCharge::Platform(charge) => {
                line_items.extend(platform_charge_lines(charge, &period_label));
                metered_watermarks.push((period.id, Some(charge.emails_sent)));
                description = format!("Platform contract line for {period_label}");
            }
            PeriodCharge::Mailboxes(charge) => {
                line_items.extend(mailbox_charge_lines(charge, &period_label));
                metered_watermarks.push((period.id, None));
                description = format!(
                    "Mailboxes contract line for {period_label} — {} billable seats",
                    charge.billable_seats
                );
            }
        }
    }

    let mut subtotal: i64 = 0;
    for line in &line_items {
        subtotal = subtotal.saturating_add(line.amount_cents());
    }
    if subtotal <= 0 {
        // Unreachable for the billable lines (base and seat floor are
        // non-zero), but a zero invoice is never issued: terminal skip.
        for period in &claimed {
            crate::overage::mark_period_skipped(&mut tx, period.id).await?;
        }
        tx.commit()
            .await
            .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
        return Ok(());
    }

    let input = CreateInvoiceInput {
        tenant_id: tenant_id.to_string(),
        adyen_psp_reference: None,
        line_items: to_new_line_items(&line_items),
        period_start,
        period_end,
        due_at: None,
        // The period's snapshot currency, never an implicit default.
        currency: Some(period_currency.to_lowercase()),
        overage_period: None,
        product_lines_period: Some(period_start),
    };

    // SAVEPOINT around the insert (audit F29): a period-identity unique
    // violation rolls back to the savepoint only, so the adoption SELECT
    // runs in the still-healthy claim transaction — no 25P02, and never a
    // second collection.
    sqlx::query("SAVEPOINT invoice_creation")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("product-line sweep: invoice savepoint failed: {e}"))?;

    let invoice = match create_invoice_in_tx(&mut tx, input).await {
        Ok(invoice) => {
            sqlx::query("RELEASE SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    format!("product-line sweep: invoice savepoint release failed: {e}")
                })?;
            invoice
        }
        Err(error) if is_product_lines_period_unique_violation(&error) => {
            sqlx::query("ROLLBACK TO SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    format!("product-line sweep: invoice savepoint rollback failed: {e}")
                })?;

            let existing: Option<(Uuid, i64, String)> = sqlx::query_as(
                "SELECT id, COALESCE(total, amount, 0)::bigint, currency \
                 FROM invoices WHERE tenant_id = $1 AND product_lines_period = $2 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(period_start)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("product-line sweep: existing-invoice lookup failed: {e}"))?;

            let Some((existing_id, existing_total, existing_currency)) = existing else {
                // The constraint fired but the invoice is not visible inside
                // this transaction — retry later rather than adopt something
                // unverified.
                return Err(format!(
                    "product-line sweep: period-identity constraint fired but no existing \
                     invoice is visible for tenant {tenant_id} month {}",
                    period_start.to_rfc3339()
                ));
            };

            if !existing_currency.eq_ignore_ascii_case(&period_currency)
                || existing_total != subtotal
            {
                warn!(
                    tenant_id = %tenant_id,
                    invoice_id = %existing_id,
                    existing_total,
                    existing_currency = %existing_currency,
                    snapshot_total = subtotal,
                    snapshot_currency = %period_currency,
                    "product-line sweep: existing month invoice disagrees with the period snapshot — surfaced for review"
                );
            }

            // The month already has an invoice. Under the per-(tenant,
            // month) advisory lock and the atomic claim+invoice transaction
            // this can only mean the claimed line was activated (or its
            // period row written) AFTER that invoice was issued — for
            // example a backdated contract. Linking the line to that
            // invoice would silently swallow its charge and minting a
            // second invoice for the month is impossible (the identity is
            // taken), so the line is surfaced: never a silent loss, never a
            // mutated frozen invoice.
            result.months_already_invoiced += 1;
            for period in &claimed {
                crate::overage::mark_period_needs_review(
                    &mut tx,
                    period.id,
                    &format!(
                        "month already invoiced (invoice {existing_id}); this line was not part \
                         of it — reconcile manually"
                    ),
                )
                .await?;
            }
            crate::overage::enqueue_collection(
                &mut tx,
                tenant_id,
                existing_id,
                period_start,
                &description,
                "product_lines",
            )
            .await?;
            tx.commit()
                .await
                .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;
            info!(
                tenant_id = %tenant_id,
                invoice_id = %existing_id,
                month = %period_start.format("%Y-%m"),
                "product-line sweep: month already invoiced — the claimed line was surfaced for \
                 reconciliation, no second collection"
            );
            return Ok(());
        }
        Err(error) => {
            let _ = tx.rollback().await;
            return Err(format!("product-line invoice creation failed: {error}"));
        }
    };

    for (period, watermark) in claimed.iter().zip(metered_watermarks.iter()) {
        crate::overage::mark_period_invoiced(&mut tx, period.id, invoice.id, watermark.1).await?;
        crate::overage::clear_period_sweep_failure(&mut tx, period.id).await?;
    }
    crate::overage::enqueue_collection(
        &mut tx,
        tenant_id,
        invoice.id,
        period_start,
        &description,
        "product_lines",
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| format!("product-line sweep: claim commit failed: {e}"))?;

    result.invoices_created += 1;
    result.periods_invoiced += claimed.len() as u64;
    info!(
        tenant_id = %tenant_id,
        invoice_number = %invoice.invoice_number,
        month = %period_start.format("%Y-%m"),
        subtotal_cents = subtotal,
        currency = %period_currency,
        lines = line_items.len(),
        "product-line invoice created for completed calendar month"
    );

    // Collection runs AFTER the claim committed — external calls stay out
    // of the claim transaction (audit F33). Failures leave the outbox
    // retryable; the invoice itself is durably claimed above.
    if let Err(error) = crate::overage::collect_usage_invoice(
        state,
        &invoice,
        period_start,
        &description,
        "product_lines",
        &mut result.wallet_paid,
        &mut result.pending_dunning,
    )
    .await
    {
        warn!(
            tenant_id = %tenant_id,
            invoice_id = %invoice.id,
            error = %error,
            "product-line sweep: collection failed — outbox retains retryable state"
        );
    }

    Ok(())
}

/// Create the month's `billing_periods` rows for every billable line, each
/// with the full frozen price set for the tenant's billing currency (audit
/// F32). Runs in its OWN committed transaction: the period rows are the
/// sweep's durable queue, so a later failure leaves a visible unbilled
/// period (with backoff state) rather than nothing.
async fn ensure_period_records(
    state: &AppState,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    lines: &[&ProductLineContractRow],
    currency: &str,
) -> Result<(), String> {
    let price_currency = catalog_price_currency(currency);

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("product-line sweep: period claim tx failed: {e}"))?;
    for line in lines {
        let (plan_name, rate_millicents, snapshot) = match line.product_line.as_str() {
            PLATFORM_PRODUCT_LINE => {
                let pricing = platform_pricing(price_currency);
                (
                    PLATFORM_PRODUCT_LINE,
                    Some(pricing.overage_rate_millicents),
                    pricing.snapshot_json(),
                )
            }
            _ => {
                let pricing = mailbox_pricing(price_currency);
                (MAILBOXES_PRODUCT_LINE, None, pricing.snapshot_json())
            }
        };
        sqlx::query(
            r#"
            INSERT INTO billing_periods (
                tenant_id, usage_kind, period_start, period_end, currency, plan_name,
                overage_rate_millicents, pricing_snapshot, pricing_resolved_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, NOW())
            ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING
            "#,
        )
        .bind(tenant_id)
        .bind(line.product_line.as_str())
        .bind(period_start)
        .bind(period_end)
        .bind(currency)
        .bind(plan_name)
        .bind(rate_millicents.map(|rate| rate as i32))
        .bind(snapshot.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("product-line sweep: period claim failed: {e}"))?;
    }
    tx.commit()
        .await
        .map_err(|e| format!("product-line sweep: period claim commit failed: {e}"))?;
    Ok(())
}

/// Claim one UNBILLED period row inside the caller's transaction. Returns
/// `None` when the row already exists in a terminal state (invoiced,
/// skipped, needs_review, collected) — a replay never re-bills.
async fn claim_period(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    usage_kind: &str,
    period_start: DateTime<Utc>,
) -> Result<Option<ClaimedPeriod>, String> {
    let row: Option<(Uuid, String, String, Option<serde_json::Value>)> = sqlx::query_as(
        r#"
        SELECT id, invoice_state::text, currency, pricing_snapshot
        FROM billing_periods
        WHERE tenant_id = $1 AND usage_kind = $2 AND period_start = $3
        "#,
    )
    .bind(tenant_id)
    .bind(usage_kind)
    .bind(period_start)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("product-line sweep: period lookup failed: {e}"))?;

    let Some((id, state, currency, snapshot)) = row else {
        return Err(format!(
            "product-line sweep: no {usage_kind} period row for tenant {tenant_id} month {}",
            period_start.to_rfc3339()
        ));
    };
    if state != "unbilled" {
        return Ok(None);
    }
    let usage_kind: &'static str = match usage_kind {
        PLATFORM_USAGE_KIND => PLATFORM_USAGE_KIND,
        MAILBOXES_USAGE_KIND => MAILBOXES_USAGE_KIND,
        other => {
            return Err(format!(
                "product-line sweep: unsupported usage kind {other}"
            ))
        }
    };
    Ok(Some(ClaimedPeriod {
        id,
        usage_kind,
        currency,
        pricing_snapshot: snapshot.unwrap_or(serde_json::Value::Null),
    }))
}

/// Every line's charge for one tenant-month, priced from the period's frozen
/// snapshot.
enum PeriodCharge {
    Platform(PlatformCharge),
    Mailboxes(MailboxCharge),
}

#[derive(Debug)]
enum ChargeFailure {
    /// The period cannot be priced from its snapshot — surface it for review.
    Unpriced { period_id: Uuid, reason: String },
    /// Infrastructure failure — propagate.
    Fatal(String),
}

impl From<String> for ChargeFailure {
    fn from(error: String) -> Self {
        ChargeFailure::Fatal(error)
    }
}

async fn build_charges(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    claimed: &[ClaimedPeriod],
) -> Result<Vec<PeriodCharge>, ChargeFailure> {
    let mut charges = Vec::with_capacity(claimed.len());
    for period in claimed {
        match period.usage_kind {
            PLATFORM_USAGE_KIND => {
                let pricing =
                    snapshot_platform_pricing(&period.pricing_snapshot).ok_or_else(|| {
                        ChargeFailure::Unpriced {
                            period_id: period.id,
                            reason: "platform period has no usable pricing snapshot".to_string(),
                        }
                    })?;
                let sent =
                    metered_emails_for_period(&mut **tx, tenant_id, period_start, period_end)
                        .await?;
                let subaccounts = active_subaccounts(&mut **tx, tenant_id).await?;
                charges.push(PeriodCharge::Platform(platform_charge(
                    sent,
                    subaccounts,
                    &pricing,
                )));
            }
            MAILBOXES_USAGE_KIND => {
                let pricing =
                    snapshot_mailbox_pricing(&period.pricing_snapshot).ok_or_else(|| {
                        ChargeFailure::Unpriced {
                            period_id: period.id,
                            reason: "mailboxes period has no usable pricing snapshot".to_string(),
                        }
                    })?;
                let (seats, archived) = mailbox_seats(&mut **tx, tenant_id).await?;
                charges.push(PeriodCharge::Mailboxes(mailbox_charge(
                    seats, archived, &pricing,
                )));
            }
            other => {
                return Err(ChargeFailure::Fatal(format!(
                    "product-line sweep: unsupported usage kind {other}"
                )))
            }
        }
    }
    Ok(charges)
}

/// Rebuild [`PlatformPricing`] from a period's snapshot JSON. `None` when
/// the snapshot is missing/corrupt — the caller surfaces the period for
/// review instead of pricing from today's catalog (audit F32).
fn snapshot_platform_pricing(snapshot: &serde_json::Value) -> Option<PlatformPricing> {
    let currency: &'static str = match snapshot.get("currency").and_then(|v| v.as_str())? {
        "USD" => "USD",
        "EUR" => "EUR",
        _ => return None,
    };
    Some(PlatformPricing {
        currency,
        base_cents: snapshot.get("baseCents").and_then(|v| v.as_i64())?,
        included_emails: snapshot.get("includedEmails").and_then(|v| v.as_i64())?,
        overage_rate_millicents: snapshot
            .get("overageRateMillicents")
            .and_then(|v| v.as_i64())?,
        included_subaccounts: snapshot
            .get("includedSubaccounts")
            .and_then(|v| v.as_i64())?,
        subaccount_cents: snapshot
            .get("subaccountMonthlyCents")
            .and_then(|v| v.as_i64())?,
    })
}

fn snapshot_mailbox_pricing(snapshot: &serde_json::Value) -> Option<MailboxPricing> {
    let currency: &'static str = match snapshot.get("currency").and_then(|v| v.as_str())? {
        "USD" => "USD",
        "EUR" => "EUR",
        _ => return None,
    };
    Some(MailboxPricing {
        currency,
        minimum_seats: snapshot.get("minimumSeats").and_then(|v| v.as_i64())?,
        seat_cents: snapshot.get("seatCents").and_then(|v| v.as_i64())?,
        archive_seat_cents: snapshot.get("archiveSeatCents").and_then(|v| v.as_i64())?,
    })
}

/// Metered `emails_sent` for exactly one billing period (metered_emails is
/// the metering pipeline's event type for sends).
async fn metered_emails_for_period(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<i64, ChargeFailure> {
    let sent: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(quantity), 0)::bigint
        FROM metering_events
        WHERE tenant_id = $1
          AND event_type = 'emails_sent'
          AND timestamp >= $2
          AND timestamp <  $3
        "#,
    )
    .bind(tenant_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_one(executor)
    .await
    .map_err(|e| ChargeFailure::Fatal(format!("product-line sweep: usage query failed: {e}")))?;
    Ok(sent)
}

/// ACTIVE subaccounts: `status = 'active'` is the table's own vocabulary
/// (migration 092) and the filter the enterprise list path applies;
/// suspended children do not bill. `parent_id` is the same parent column
/// the creation quota locks on.
async fn active_subaccounts(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    tenant_id: &str,
) -> Result<i64, ChargeFailure> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM ent_sub_accounts WHERE parent_id = $1 AND status = 'active'",
    )
    .bind(tenant_id)
    .fetch_one(executor)
    .await
    .map_err(|e| {
        ChargeFailure::Fatal(format!("product-line sweep: subaccount query failed: {e}"))
    })?;
    Ok(count)
}

/// (active mailbox accounts, active accounts carrying the archive flag) for
/// one tenant. The account row is the seat — `mail_mailboxes` are folders.
async fn mailbox_seats(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    tenant_id: &str,
) -> Result<(i64, i64), ChargeFailure> {
    let row: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE is_active)::bigint,
            COUNT(*) FILTER (WHERE is_active AND archive_enabled)::bigint
        FROM mail_accounts
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_one(executor)
    .await
    .map_err(|e| {
        ChargeFailure::Fatal(format!(
            "product-line sweep: mailbox seat query failed: {e}"
        ))
    })?;
    Ok(row)
}

/// Whether the tenant has a billing address on file (mandatory on a VAT
/// invoice). Uses the shared `SELECT EXISTS` (audit F28).
async fn tenant_has_billing_address<'e, T>(tenant_id: &str, executor: T) -> Result<bool, String>
where
    T: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_scalar(crate::overage::ADDRESS_EXISTS_SQL)
        .bind(tenant_id)
        .fetch_one(executor)
        .await
        .map_err(|e| format!("product-line sweep: address query failed: {e}"))
}

/// Whether an invoice-creation error is a violation of the EXACT
/// product-line period-identity constraint (migration 256). Arbitrary
/// 23505s (invoice number sequence, external invoice id, ...) are not
/// replays and must never be reinterpreted as one.
fn is_product_lines_period_unique_violation(error: &InvoiceError) -> bool {
    match error {
        InvoiceError::Db(sqlx::Error::Database(db_error)) => {
            db_error.code().as_deref() == Some("23505")
                && db_error.constraint() == Some(PRODUCT_LINES_UNIQUE_CONSTRAINT)
        }
        _ => false,
    }
}

/// Whether the tenant holds an ACTIVE Mailboxes product-line contract —
/// the runtime entitlement the provisioning path gates on (the API surface
/// lives in api-server; the query is shared so both agree on "active").
pub async fn mailboxes_contract_active(db: &PgPool, tenant_id: &str) -> Result<bool, String> {
    let active: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM product_line_contracts
            WHERE tenant_id = $1 AND product_line = $2 AND status = 'active'
        )
        "#,
    )
    .bind(tenant_id)
    .bind(MAILBOXES_PRODUCT_LINE)
    .fetch_one(db)
    .await
    .map_err(|e| format!("mailboxes contract lookup failed: {e}"))?;
    Ok(active)
}

// ---------------------------------------------------------------------------
// Unit tests — pure pricing, boundaries, currency, line shapes
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn utc(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn eur() -> PlatformPricing {
        platform_pricing("EUR")
    }

    fn usd() -> PlatformPricing {
        platform_pricing("USD")
    }

    /// The catalog IS the price table: the ProductLine row and the per-1K /
    /// per-subaccount constants, in both currencies.
    #[test]
    fn platform_prices_come_from_the_catalog_row() {
        let line = platform_catalog::product_line_by_name("platform").expect("platform row");
        let eur_pricing = eur();
        assert_eq!(eur_pricing.base_cents, 99_000, "€990/month");
        assert_eq!(eur_pricing.base_cents, line.price_monthly_cents);
        assert_eq!(eur_pricing.overage_rate_millicents, 30, "€0.30/1K");
        assert_eq!(
            eur_pricing.overage_rate_millicents,
            platform_catalog::PLATFORM_OVERAGE_CENTS_PER_1K
        );
        assert_eq!(eur_pricing.included_emails, 1_000_000);
        assert_eq!(eur_pricing.included_subaccounts, 100);
        assert_eq!(
            eur_pricing.subaccount_cents, 100,
            "€1 per active subaccount"
        );

        let usd_pricing = usd();
        assert_eq!(usd_pricing.base_cents, 109_000, "$1,090/month");
        assert_eq!(usd_pricing.base_cents, line.price_monthly_usd_cents);
        assert_eq!(usd_pricing.overage_rate_millicents, 35, "$0.35/1K");
        assert_eq!(
            usd_pricing.overage_rate_millicents,
            platform_catalog::PLATFORM_OVERAGE_USD_CENTS_PER_1K
        );
        assert_eq!(
            usd_pricing.subaccount_cents, 100,
            "$1 per active subaccount"
        );

        // The per-1K cent figure and the per-email millicent rate are the
        // same number by construction (0.30 EUR/1 000 = 0.03 cents =
        // 30 millicents/email). Pin the identity so editing one constant
        // without the other cannot ship.
        assert_eq!(
            platform_catalog::PLATFORM_OVERAGE_CENTS_PER_1K,
            eur().overage_rate_millicents,
            "€0.30 per 1,000 IS 30 millicents per email"
        );
        assert_eq!(
            platform_catalog::PLATFORM_OVERAGE_USD_CENTS_PER_1K,
            usd().overage_rate_millicents,
            "$0.35 per 1,000 IS 35 millicents per email"
        );
    }

    /// The usage tier at its exact boundaries: 1,000,000 included; one email
    /// over rounds UP to one cent (the plan ladder's ceiling semantics).
    #[test]
    fn platform_usage_tier_at_exact_boundaries() {
        let included = eur().included_emails;
        assert_eq!(included, 1_000_000);

        let at_limit = platform_charge(1_000_000, 0, &eur());
        assert_eq!(at_limit.overage_emails, 0);
        assert_eq!(at_limit.overage_cents, 0);

        let one_over = platform_charge(1_000_001, 0, &eur());
        assert_eq!(one_over.overage_emails, 1);
        assert_eq!(one_over.overage_cents, 1, "ceil(1 × 30 / 1000) = 1 cent");

        // Exactly one thousand over: 1,000 × 30 millicents = 30 cents.
        let thousand_over = platform_charge(1_001_000, 0, &eur());
        assert_eq!(thousand_over.overage_emails, 1_000);
        assert_eq!(thousand_over.overage_cents, 30, "€0.30 per 1,000");

        // 2M sent → 1M over → €300.00.
        let two_million = platform_charge(2_000_000, 0, &eur());
        assert_eq!(two_million.overage_cents, 30_000);

        // USD ladder: 1,000,001 → 35 millicents → 1 cent; 2M → $350.00.
        let usd_one_over = platform_charge(1_000_001, 0, &usd());
        assert_eq!(
            usd_one_over.overage_cents, 1,
            "ceil(1 × 35 / 1000) = 1 cent"
        );
        let usd_two_million = platform_charge(2_000_000, 0, &usd());
        assert_eq!(usd_two_million.overage_cents, 35_000);

        // A zero-usage month still bills the base, both currencies.
        let idle = platform_charge(0, 0, &eur());
        assert_eq!(idle.total_cents(), 99_000);
        assert_eq!(platform_charge(0, 0, &usd()).total_cents(), 109_000);
    }

    /// The subaccount fee starts at 101 active subaccounts.
    #[test]
    fn subaccount_fee_bills_only_above_one_hundred() {
        let at_hundred = platform_charge(0, 100, &eur());
        assert_eq!(at_hundred.billable_subaccounts, 0);
        assert_eq!(at_hundred.subaccount_cents, 0);

        let one_over = platform_charge(0, 101, &eur());
        assert_eq!(one_over.billable_subaccounts, 1);
        assert_eq!(one_over.subaccount_cents, 100, "€1 each");

        let many = platform_charge(0, 250, &usd());
        assert_eq!(many.billable_subaccounts, 150);
        assert_eq!(many.subaccount_cents, 15_000, "$1 each");

        // Charges compose: base + tier + subaccounts.
        let full = platform_charge(1_500_000, 150, &eur());
        assert_eq!(full.overage_cents, 15_000);
        assert_eq!(full.subaccount_cents, 5_000);
        assert_eq!(full.total_cents(), 99_000 + 15_000 + 5_000);
    }

    /// Mailboxes: 10-seat minimum, per-seat price, archive per flagged seat.
    #[test]
    fn mailbox_seats_floor_at_ten_and_archive_prices_per_flagged_seat() {
        let pricing = mailbox_pricing("EUR");
        assert_eq!(pricing.minimum_seats, 10);
        assert_eq!(pricing.seat_cents, 600, "€6 per seat");
        assert_eq!(pricing.archive_seat_cents, 200, "€2 per archived seat");

        for provisioned in [0, 1, 5, 9] {
            let charge = mailbox_charge(provisioned, 0, &pricing);
            assert_eq!(charge.provisioned_seats, provisioned);
            assert_eq!(charge.billable_seats, 10, "5 seats → billed 10");
            assert_eq!(charge.seat_cents, 6_000);
        }
        let exactly_ten = mailbox_charge(10, 0, &pricing);
        assert_eq!(exactly_ten.billable_seats, 10);
        assert_eq!(exactly_ten.seat_cents, 6_000);
        let eleven = mailbox_charge(11, 0, &pricing);
        assert_eq!(eleven.billable_seats, 11);
        assert_eq!(eleven.seat_cents, 6_600);

        // Archive bills per FLAGGED SEAT: 5 flagged seats under the floor
        // still bill 5 archive seats (the floor is on seats, not on the
        // add-on).
        let five_with_archive = mailbox_charge(5, 5, &pricing);
        assert_eq!(five_with_archive.billable_seats, 10);
        assert_eq!(five_with_archive.seat_cents, 6_000);
        assert_eq!(five_with_archive.archive_seats, 5);
        assert_eq!(five_with_archive.archive_cents, 1_000);
        assert_eq!(five_with_archive.total_cents(), 7_000);

        let twelve_four = mailbox_charge(12, 4, &pricing);
        assert_eq!(twelve_four.total_cents(), 12 * 600 + 4 * 200);

        // USD ladder: $7 per seat, $2 archive.
        let usd = mailbox_pricing("USD");
        assert_eq!(usd.seat_cents, 700);
        assert_eq!(usd.archive_seat_cents, 200);
        let usd_charge = mailbox_charge(15, 3, &usd);
        assert_eq!(usd_charge.total_cents(), 15 * 700 + 3 * 200);
    }

    /// The Mailboxes price set comes from the catalog add-on rows.
    #[test]
    fn mailbox_prices_come_from_the_catalog_addon_rows() {
        let seats = platform_catalog::addon_by_name("mailboxes").expect("add-on row");
        let archive =
            platform_catalog::addon_by_name("mailbox_archive_journaling").expect("add-on row");
        let eur = mailbox_pricing("EUR");
        assert_eq!(eur.seat_cents, seats.price_cents);
        assert_eq!(eur.seat_cents, 600);
        assert_eq!(eur.archive_seat_cents, archive.price_cents);
        assert_eq!(eur.archive_seat_cents, 200);
        assert_eq!(eur.minimum_seats, platform_catalog::MAILBOX_MINIMUM_SEATS);

        let usd = mailbox_pricing("USD");
        assert_eq!(usd.seat_cents, seats.price_usd_cents);
        assert_eq!(usd.seat_cents, 700);
        assert_eq!(usd.archive_seat_cents, archive.price_usd_cents);
        assert_eq!(usd.archive_seat_cents, 200);
    }

    /// Currency selection mirrors the checkout rule: USD only for a
    /// USD-billing tenant, EUR otherwise.
    #[test]
    fn currency_selection_follows_the_tenant_billing_currency() {
        assert_eq!(catalog_price_currency("USD"), "USD");
        assert_eq!(catalog_price_currency("usd"), "USD");
        assert_eq!(catalog_price_currency(" usd "), "USD");
        assert_eq!(catalog_price_currency("EUR"), "EUR");
        assert_eq!(catalog_price_currency("GBP"), "EUR");
        assert_eq!(catalog_price_currency(""), "EUR");

        // A USD tenant's whole price set is the USD list.
        let usd = platform_pricing(catalog_price_currency("USD"));
        assert_eq!(usd.currency, "USD");
        assert_eq!(usd.base_cents, 109_000);
        let usd_seats = mailbox_pricing(catalog_price_currency("USD"));
        assert_eq!(usd_seats.currency, "USD");
        assert_eq!(usd_seats.seat_cents, 700);
    }

    /// `normalize_billing_currency` mirrors the api-server resolver exactly
    /// (trim, uppercase, 3-letter ASCII only, else EUR).
    #[test]
    fn billing_currency_normalization_matches_the_resolver() {
        assert_eq!(normalize_billing_currency(Some("usd")), "USD");
        assert_eq!(normalize_billing_currency(Some(" eur ")), "EUR");
        assert_eq!(normalize_billing_currency(Some("gbp")), "GBP");
        assert_eq!(normalize_billing_currency(Some("US")), "EUR");
        assert_eq!(normalize_billing_currency(Some("EURO")), "EUR");
        assert_eq!(normalize_billing_currency(Some("")), "EUR");
        assert_eq!(normalize_billing_currency(Some("e1r")), "EUR");
        assert_eq!(normalize_billing_currency(None), "EUR");
        assert_eq!(
            normalize_billing_currency(None),
            DEFAULT_PRODUCT_LINE_CURRENCY
        );
    }

    /// Contract coverage is full-month only — no proration.
    #[test]
    fn contract_covers_a_period_only_in_full() {
        let start = utc(2026, 5, 1);
        let end = utc(2026, 6, 1);
        assert!(contract_covers_period(utc(2026, 4, 1), None, start, end));
        assert!(
            contract_covers_period(start, None, start, end),
            "on the 1st"
        );
        assert!(
            !contract_covers_period(utc(2026, 5, 15), None, start, end),
            "mid-month first month is not billed (no proration)"
        );
        assert!(contract_covers_period(
            utc(2026, 4, 1),
            Some(end),
            start,
            end
        ));
        assert!(
            !contract_covers_period(utc(2026, 4, 1), Some(utc(2026, 5, 20)), start, end),
            "terminated mid-month: the partial final month is not billed"
        );
        assert!(
            !contract_covers_period(utc(2026, 4, 1), Some(utc(2026, 5, 31)), start, end),
            "an end before period_end leaves the month partially covered"
        );
    }

    /// Invoice line shapes: exact description/quantity/unit-price tuples and
    /// the sum that the invoice's `subtotal` will carry.
    #[test]
    fn platform_invoice_line_shapes_are_exact() {
        let charge = platform_charge(1_500_000, 105, &eur());
        let lines = platform_charge_lines(&charge, "2026-05");
        assert_eq!(lines.len(), 3);

        assert_eq!(lines[0].quantity, 1);
        assert_eq!(lines[0].unit_price, 99_000);
        assert!(lines[0].description.contains("Platform base"));
        assert!(lines[0].description.contains("990.00 EUR"));
        assert!(lines[0].description.contains("1000000 emails included"));

        assert_eq!(lines[1].quantity, 1);
        assert_eq!(lines[1].unit_price, 15_000, "500,000 over × €0.30/1K");
        assert!(lines[1].description.contains("500000 emails"));
        assert!(
            lines[1].description.contains("0.30 EUR"),
            "the rate is quoted in the snapshot currency: {}",
            lines[1].description
        );

        assert_eq!(lines[2].quantity, 5, "105 active − 100 included");
        assert_eq!(lines[2].unit_price, 100);
        assert!(lines[2].description.contains("5 above the 100 included"));

        let subtotal: i64 = lines.iter().map(|line| line.amount_cents()).sum();
        assert_eq!(subtotal, charge.total_cents());
        assert_eq!(subtotal, 99_000 + 15_000 + 500);

        // Zero usage: base only — the brief's "zero-usage month still bills
        // the base".
        let idle = platform_charge_lines(&platform_charge(0, 0, &eur()), "2026-05");
        assert_eq!(idle.len(), 1);
        assert_eq!(idle[0].unit_price, 99_000);
    }

    /// Mailbox line shapes: the seat line always, the archive line only
    /// when flagged seats exist.
    #[test]
    fn mailbox_invoice_line_shapes_are_exact() {
        let charge = mailbox_charge(5, 2, &mailbox_pricing("EUR"));
        let lines = mailbox_charge_lines(&charge, "2026-05");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].quantity, 10, "floored at the 10-seat minimum");
        assert_eq!(lines[0].unit_price, 600);
        assert!(lines[0].description.contains("6.00 EUR"));
        assert_eq!(lines[1].quantity, 2, "flagged seats only");
        assert_eq!(lines[1].unit_price, 200);
        let subtotal: i64 = lines.iter().map(|line| line.amount_cents()).sum();
        assert_eq!(subtotal, 6_000 + 400);
        assert_eq!(subtotal, charge.total_cents());

        let no_archive =
            mailbox_charge_lines(&mailbox_charge(10, 0, &mailbox_pricing("EUR")), "2026-05");
        assert_eq!(no_archive.len(), 1);
    }

    /// The frozen price set round-trips through the snapshot JSON — the
    /// period's stored pricing rebuilds exactly.
    #[test]
    fn pricing_snapshots_round_trip() {
        let platform = eur();
        assert_eq!(
            snapshot_platform_pricing(&platform.snapshot_json()),
            Some(platform)
        );
        let seats = mailbox_pricing("USD");
        assert_eq!(
            snapshot_mailbox_pricing(&seats.snapshot_json()),
            Some(seats)
        );

        // A missing or corrupt snapshot is NOT silently repriced.
        assert_eq!(snapshot_platform_pricing(&serde_json::Value::Null), None);
        assert_eq!(
            snapshot_platform_pricing(&serde_json::json!({"currency": "USD"})),
            None
        );
        assert_eq!(
            snapshot_mailbox_pricing(&serde_json::json!({"currency": "SEK", "minimumSeats": 10})),
            None
        );
    }

    /// Integer display only — no floats anywhere in the money path.
    #[test]
    fn cents_render_with_integer_math() {
        assert_eq!(format_cents(99_000, "EUR"), "990.00 EUR");
        assert_eq!(format_cents(109_000, "usd"), "1090.00 USD");
        assert_eq!(format_cents(1, "EUR"), "0.01 EUR");
        assert_eq!(format_cents(0, "EUR"), "0.00 EUR");
    }

    /// The pagination predicate keeps its parentheses: without them the
    /// `AND` cursor clause binds to the terminated branch alone and the
    /// paging loop never advances past the active tenants.
    #[test]
    fn sweep_pagination_sql_parenthesizes_the_status_filter() {
        assert!(SWEEP_TENANTS_SQL.contains("WHERE (status = 'active'"));
        assert!(
            SWEEP_TENANTS_SQL.contains("ended_at IS NOT NULL))"),
            "the status filter must close as one parenthesized group"
        );
        assert!(SWEEP_TENANTS_SQL.contains("AND ($1::text IS NULL OR tenant_id > $1::text)"));
    }

    /// The kill switch: every accepted spelling, default on.
    #[test]
    fn product_line_kill_switch_parses_documented_values() {
        assert!(parse_invoicing_switch(None));
        assert!(parse_invoicing_switch(Some("true")));
        assert!(parse_invoicing_switch(Some("1")));
        assert!(parse_invoicing_switch(Some("yes")));
        assert!(!parse_invoicing_switch(Some("false")));
        assert!(!parse_invoicing_switch(Some("FALSE")));
        assert!(!parse_invoicing_switch(Some(" 0 ")));
        assert!(!parse_invoicing_switch(Some("off")));
        assert!(!parse_invoicing_switch(Some("no")));
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB backed) — the monthly sweep end to end.
//
// Every test provisions its own canonical database clone (private, dropped
// on finish); `TEST_DATABASE_URL` unset → soft-skip (the workspace
// convention), a configured provisioning failure panics.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::*;
    use sqlx::PgPool;
    use std::sync::Arc;

    struct Env {
        state: Arc<AppState>,
        pool: PgPool,
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                let Some(owned) = crate::test_support::provision(stringify!($name)).await else {
                    return;
                };
                let $e = &Env {
                    state: owned.state.clone(),
                    pool: owned.pool.clone(),
                };
                $body
                owned.finish().await;
            }
        };
    }

    /// The FIRST completed calendar month the sweep looks at — tests seed
    /// data for exactly the month the sweep will consider.
    fn target_month() -> (DateTime<Utc>, DateTime<Utc>) {
        crate::overage::recent_completed_calendar_months(Utc::now())[0]
    }

    async fn seed_tenant(env: &Env, tenant: &str, billing_currency: Option<&str>) {
        let settings = billing_currency
            .map(|currency| serde_json::json!({ "billingCurrency": currency }))
            .unwrap_or_else(|| serde_json::json!({}));
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, settings)
             VALUES ($1, $2, 'growth', 'active', $3::jsonb)
             ON CONFLICT (id) DO UPDATE SET status = 'active', settings = EXCLUDED.settings",
        )
        .bind(tenant)
        .bind(format!("Product-line {tenant}"))
        .bind(settings.to_string())
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_address(env: &Env, tenant: &str) {
        sqlx::query("INSERT INTO billing_addresses (tenant_id, country) VALUES ($1, 'EE')")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("seed billing address");
    }

    async fn seed_contract(
        env: &Env,
        tenant: &str,
        product_line: &str,
        status: &str,
        active_from: DateTime<Utc>,
        ended_at: Option<DateTime<Utc>>,
    ) {
        sqlx::query(
            "INSERT INTO product_line_contracts
                 (tenant_id, product_line, status, active_from, ended_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, product_line) DO UPDATE
                 SET status = EXCLUDED.status, active_from = EXCLUDED.active_from,
                     ended_at = EXCLUDED.ended_at",
        )
        .bind(tenant)
        .bind(product_line)
        .bind(status)
        .bind(active_from)
        .bind(ended_at)
        .execute(&env.pool)
        .await
        .expect("seed contract");
    }

    async fn send_emails(env: &Env, tenant: &str, quantity: i64, at: DateTime<Utc>) {
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', $2, $3)",
        )
        .bind(tenant)
        .bind(quantity)
        .bind(at)
        .execute(&env.pool)
        .await
        .expect("metering event");
    }

    async fn seed_subaccounts(env: &Env, tenant: &str, count: i64, status: &str) {
        for index in 0..count {
            sqlx::query(
                "INSERT INTO ent_sub_accounts (id, parent_id, name, status)
                 VALUES (gen_random_uuid(), $1, $2, $3)",
            )
            .bind(tenant)
            .bind(format!("child-{status}-{index}"))
            .bind(status)
            .execute(&env.pool)
            .await
            .expect("seed sub-account");
        }
    }

    async fn seed_mailbox(
        env: &Env,
        tenant: &str,
        email: &str,
        is_active: bool,
        archive_enabled: bool,
    ) {
        let domain = email.split_once('@').expect("email domain").1.to_string();
        sqlx::query(
            "INSERT INTO mail_accounts
                 (email, domain, password_hash, display_name, tenant_id, is_active,
                  archive_enabled, archive_enabled_at)
             VALUES ($1, $2, 'x', 'seed', $3, $4, $5,
                     CASE WHEN $5 THEN NOW() ELSE NULL END)",
        )
        .bind(email)
        .bind(domain)
        .bind(tenant)
        .bind(is_active)
        .bind(archive_enabled)
        .execute(&env.pool)
        .await
        .expect("seed mailbox");
    }

    async fn invoice_rows(env: &Env, tenant: &str) -> Vec<(Uuid, i64, i64, String, String)> {
        sqlx::query_as(
            "SELECT id, subtotal, total, currency, status FROM invoices
             WHERE tenant_id = $1 AND product_lines_period IS NOT NULL
             ORDER BY created_at",
        )
        .bind(tenant)
        .fetch_all(&env.pool)
        .await
        .expect("invoice rows")
    }

    async fn line_items(env: &Env, invoice_id: Uuid) -> Vec<serde_json::Value> {
        let raw: serde_json::Value =
            sqlx::query_scalar("SELECT line_items FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("line items read");
        raw["items"].as_array().cloned().unwrap_or_default()
    }

    async fn period_row(
        env: &Env,
        tenant: &str,
        usage_kind: &str,
    ) -> Option<(String, Option<i64>, Option<Uuid>, String)> {
        sqlx::query_as(
            "SELECT invoice_state::text, metered_emails, invoice_id, currency
             FROM billing_periods
             WHERE tenant_id = $1 AND usage_kind = $2",
        )
        .bind(tenant)
        .bind(usage_kind)
        .fetch_optional(&env.pool)
        .await
        .expect("period row")
    }

    // ------------------------------------------------------------------
    // Platform line
    // ------------------------------------------------------------------

    env_test!(
        platform_month_bills_base_tier_and_subaccounts_end_to_end,
        |env| {
            let tenant = "plcov_platform";
            let (start, end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "platform",
                "active",
                start - chrono::Duration::days(60),
                None,
            )
            .await;
            // 1,200,000 sent → 200,000 over → ceil(200000 × 30 / 1000) = 6,000 cents.
            send_emails(env, tenant, 1_200_000, start + chrono::Duration::days(5)).await;
            // 105 ACTIVE subaccounts (billed: 5) plus 3 suspended (not billed).
            seed_subaccounts(env, tenant, 105, "active").await;
            seed_subaccounts(env, tenant, 3, "suspended").await;

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(result.invoices_created, 1);
            assert_eq!(result.periods_invoiced, 1);

            let rows = invoice_rows(env, tenant).await;
            assert_eq!(rows.len(), 1, "exactly one invoice for the month");
            let (invoice_id, subtotal, total, currency, _status) = rows[0].clone();
            assert_eq!(subtotal, 99_000 + 6_000 + 500);
            assert_eq!(currency, "eur");
            assert!(
                total >= subtotal,
                "VAT is added on top: {total} vs {subtotal}"
            );

            let items = line_items(env, invoice_id).await;
            assert_eq!(items.len(), 3);
            assert_eq!(items[0]["quantity"], 1);
            assert_eq!(items[0]["unit_price"], 99_000);
            assert!(items[0]["description"]
                .as_str()
                .expect("description")
                .contains("Platform base"));
            assert_eq!(items[1]["unit_price"], 6_000);
            assert_eq!(items[2]["quantity"], 5);
            assert_eq!(items[2]["unit_price"], 100);
            assert_eq!(items[2]["amount"], 500);

            let (state, metered, invoice_link, period_currency) =
                period_row(env, tenant, "platform")
                    .await
                    .expect("period row");
            assert_eq!(state, "invoiced");
            assert_eq!(metered, Some(1_200_000), "usage watermark frozen");
            assert_eq!(
                invoice_link,
                Some(invoice_id),
                "the period links its invoice"
            );
            assert_eq!(period_currency, "EUR");

            // The collection outbox operation committed with the invoice.
            let outbox: i64 = sqlx::query_scalar(
                "SELECT COUNT(*)::bigint FROM invoice_collection_outbox WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("outbox count");
            assert_eq!(
                outbox, 1,
                "collection is enqueued in the invoice transaction"
            );

            // Replaying the sweep is a no-op: the period is terminal and the
            // invoice is not created a second time.
            let replay = sweep_product_line_months(&env.state).await.expect("replay");
            assert_eq!(replay.invoices_created, 0, "no second invoice");
            assert_eq!(replay.periods_already_terminal, 1);
            assert_eq!(invoice_rows(env, tenant).await.len(), 1);
            // Calendar-month bounds: the period start is a month first, the end
            // is the next one.
            assert_eq!(start, crate::overage::first_of_month(start));
            assert_eq!(end, crate::overage::first_of_month(end));
            assert!(end > start);
        }
    );

    env_test!(zero_usage_month_still_bills_the_platform_base, |env| {
        let tenant = "plcov_idle";
        let (start, _end) = target_month();
        seed_tenant(env, tenant, None).await;
        seed_address(env, tenant).await;
        seed_contract(
            env,
            tenant,
            "platform",
            "active",
            start - chrono::Duration::days(30),
            None,
        )
        .await;

        let result = sweep_product_line_months(&env.state).await.expect("sweep");
        assert_eq!(result.invoices_created, 1);

        let rows = invoice_rows(env, tenant).await;
        assert_eq!(rows[0].1, 99_000, "base only, no usage lines");
        let items = line_items(env, rows[0].0).await;
        assert_eq!(items.len(), 1);
        assert!(items[0]["description"]
            .as_str()
            .expect("description")
            .contains("Platform base"));
    });

    env_test!(usd_tenant_is_invoiced_from_the_usd_list, |env| {
        let tenant = "plcov_usd";
        let (start, _end) = target_month();
        seed_tenant(env, tenant, Some("usd")).await;
        seed_address(env, tenant).await;
        seed_contract(
            env,
            tenant,
            "platform",
            "active",
            start - chrono::Duration::days(30),
            None,
        )
        .await;
        seed_contract(
            env,
            tenant,
            "mailboxes",
            "active",
            start - chrono::Duration::days(30),
            None,
        )
        .await;
        for index in 0..10 {
            seed_mailbox(
                env,
                tenant,
                &format!("usd{index}@example.test"),
                true,
                false,
            )
            .await;
        }

        sweep_product_line_months(&env.state).await.expect("sweep");

        let rows = invoice_rows(env, tenant).await;
        assert_eq!(rows.len(), 1, "one invoice per tenant-month across lines");
        let (invoice_id, subtotal, _total, currency, _status) = rows[0].clone();
        assert_eq!(currency, "usd");
        // $1,090 base + 10 × $7 seats.
        assert_eq!(subtotal, 109_000 + 7_000);
        let items = line_items(env, invoice_id).await;
        assert_eq!(items.len(), 2, "one line per line");
        let description = |index: usize| {
            items[index]["description"]
                .as_str()
                .expect("description")
                .to_string()
        };
        let platform_line = items
            .iter()
            .find(|item| {
                item["description"]
                    .as_str()
                    .is_some_and(|text| text.contains("Platform base"))
            })
            .expect("platform base line");
        let seat_line = items
            .iter()
            .find(|item| {
                item["description"]
                    .as_str()
                    .is_some_and(|text| text.contains("Mailboxes"))
            })
            .expect("mailboxes seat line");
        assert_eq!(platform_line["unit_price"], 109_000);
        assert_eq!(seat_line["quantity"], 10);
        assert_eq!(seat_line["unit_price"], 700);
        assert!(!description(0).is_empty() && !description(1).is_empty());

        let (state, _metered, _, period_currency) = period_row(env, tenant, "mailboxes")
            .await
            .expect("mailboxes period");
        assert_eq!(state, "invoiced");
        assert_eq!(period_currency, "USD");

        // The tenant's switch to USD happened BEFORE the claim: flipping it
        // now cannot reprice the frozen period.
        sqlx::query(
            "UPDATE tenants SET settings = '{\"billingCurrency\":\"eur\"}'::jsonb WHERE id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("flip currency");
        let replay = sweep_product_line_months(&env.state).await.expect("replay");
        assert_eq!(replay.invoices_created, 0);
        assert_eq!(
            invoice_rows(env, tenant).await[0].3,
            "usd",
            "snapshot froze USD"
        );
    });

    // ------------------------------------------------------------------
    // Mailboxes line
    // ------------------------------------------------------------------

    env_test!(
        mailboxes_month_floors_at_ten_seats_and_bills_archive_seats,
        |env| {
            let tenant = "plcov_mailboxes";
            let (start, _end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "mailboxes",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;
            // 5 ACTIVE provisioned accounts (2 flagged) plus one SUSPENDED
            // flagged account that must neither bill a seat nor archive.
            for index in 0..5 {
                seed_mailbox(
                    env,
                    tenant,
                    &format!("m{index}@example.test"),
                    true,
                    index < 2,
                )
                .await;
            }
            seed_mailbox(env, tenant, "suspended@example.test", false, true).await;
            assert_eq!(
                mailbox_seats(&env.pool, tenant).await.expect("seats"),
                (5, 2),
                "seats count active accounts; a suspended account never bills"
            );

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(result.invoices_created, 1);

            let rows = invoice_rows(env, tenant).await;
            // 5 seats floor to 10 → 10 × €6 = €60, plus 2 archive seats × €2.
            assert_eq!(rows[0].1, 6_000 + 400);
            let items = line_items(env, rows[0].0).await;
            assert_eq!(items.len(), 2);
            assert_eq!(items[0]["quantity"], 10, "5 seats → billed 10");
            assert_eq!(items[0]["unit_price"], 600);
            assert_eq!(items[1]["quantity"], 2, "only flagged active seats");
            assert_eq!(items[1]["unit_price"], 200);

            let (state, metered, _, _) = period_row(env, tenant, "mailboxes")
                .await
                .expect("mailboxes period");
            assert_eq!(state, "invoiced");
            assert_eq!(
                metered, None,
                "the seat line carries no email watermark — never a fake zero"
            );
        }
    );

    env_test!(mailboxes_line_requires_a_contract_to_bill, |env| {
        let tenant = "plcov_nocontract";
        let (start, _end) = target_month();
        seed_tenant(env, tenant, None).await;
        seed_address(env, tenant).await;
        // Mailboxes exist for the tenant but no contract row: nothing bills
        // (the operator provisioning gate is what makes a mailbox a seat).
        seed_mailbox(env, tenant, "orphan@example.test", true, true).await;
        seed_contract(
            env,
            tenant,
            "platform",
            "active",
            start - chrono::Duration::days(30),
            None,
        )
        .await;

        sweep_product_line_months(&env.state).await.expect("sweep");
        assert!(
            period_row(env, tenant, "mailboxes").await.is_none(),
            "no Mailboxes contract → no Mailboxes period row"
        );
        let rows = invoice_rows(env, tenant).await;
        assert_eq!(rows.len(), 1, "only the Platform line billed");
        assert_eq!(rows[0].1, 99_000);
    });

    // ------------------------------------------------------------------
    // Period identity, coverage windows, failure surfaces
    // ------------------------------------------------------------------

    env_test!(
        product_line_invoice_coexists_with_a_payg_invoice_for_the_same_month,
        |env| {
            let tenant = "plcov_payg";
            let (start, end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "platform",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;
            // A PAYG month invoice for the SAME (tenant, month) — the identity
            // the overage sweep uses.
            sqlx::query(
                "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end, overage_period, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, 1234, 'eur', 'pending', 'PAYG-PLCOV',
                     1234, 0, 1234, NOW(), NOW(), $2, $3, $2, NOW(), NOW())",
            )
            .bind(tenant)
            .bind(start)
            .bind(end)
            .execute(&env.pool)
            .await
            .expect("seed payg invoice");

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(
                result.invoices_created, 1,
                "the product-line binder is a SEPARATE column: no collision with PAYG"
            );
            let rows = invoice_rows(env, tenant).await;
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].1, 99_000);
        }
    );

    env_test!(
        contract_started_mid_month_defers_to_the_next_full_month,
        |env| {
            let tenant = "plcov_midmonth";
            let (start, _end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "platform",
                "active",
                start + chrono::Duration::days(9),
                None,
            )
            .await;

            sweep_product_line_months(&env.state).await.expect("sweep");
            assert!(
                period_row(env, tenant, "platform").await.is_none(),
                "no proration: a partially covered month is not billed"
            );
            assert!(invoice_rows(env, tenant).await.is_empty());
        }
    );

    env_test!(terminated_contract_bills_only_fully_covered_months, |env| {
        let tenant = "plcov_end";
        let (start, end) = target_month();
        seed_tenant(env, tenant, None).await;
        seed_address(env, tenant).await;
        seed_contract(
            env,
            tenant,
            "platform",
            "terminated",
            start - chrono::Duration::days(60),
            Some(end),
        )
        .await;

        sweep_product_line_months(&env.state).await.expect("sweep");
        let rows = invoice_rows(env, tenant).await;
        assert_eq!(
            rows.len(),
            1,
            "a month covered in full still bills after termination"
        );
        assert_eq!(rows[0].1, 99_000);

        // A termination DURING the month leaves it partially covered: the
        // next month is never billed by this sweep.
        let partial = format!("{tenant}_p");
        seed_tenant(env, &partial, None).await;
        seed_address(env, &partial).await;
        seed_contract(
            env,
            &partial,
            "platform",
            "terminated",
            start - chrono::Duration::days(60),
            Some(start + chrono::Duration::days(10)),
        )
        .await;
        sweep_product_line_months(&env.state).await.expect("sweep");
        assert!(
            invoice_rows(env, &partial).await.is_empty(),
            "a partially covered final month is not billed"
        );
    });

    env_test!(suspended_contract_is_not_billed, |env| {
        let tenant = "plcov_suspended";
        let (start, _end) = target_month();
        seed_tenant(env, tenant, None).await;
        seed_address(env, tenant).await;
        seed_contract(
            env,
            tenant,
            "platform",
            "suspended",
            start - chrono::Duration::days(30),
            None,
        )
        .await;

        let result = sweep_product_line_months(&env.state).await.expect("sweep");
        assert_eq!(
            result.tenants_checked, 0,
            "suspended rows are not swept at all"
        );
        assert!(invoice_rows(env, tenant).await.is_empty());
    });

    env_test!(
        missing_billing_address_commits_the_month_as_needs_review,
        |env| {
            let tenant = "plcov_noaddr";
            let (start, _end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_contract(
                env,
                tenant,
                "platform",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(result.skipped_no_address, 1);
            assert_eq!(result.invoices_created, 0);
            let (state, _metered, _, _) = period_row(env, tenant, "platform")
                .await
                .expect("period row stays visible");
            assert_eq!(
                state, "needs_review",
                "a billable month without an address is retained, never dropped"
            );
            assert!(invoice_rows(env, tenant).await.is_empty());
        }
    );

    // The keyset cursor actually advances: the query is driven with a page
    // of ONE over three contracted tenants and must visit each tenant
    // exactly once and terminate (the unparenthesized status filter made the
    // cursor skip the active branch entirely).
    env_test!(tenant_pagination_visits_every_contract_once, |env| {
        let (start, _end) = target_month();
        for suffix in ["a", "b", "c"] {
            let tenant = format!("plcov_page_{suffix}");
            seed_tenant(env, &tenant, None).await;
            seed_contract(
                env,
                &tenant,
                "platform",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;
        }

        let mut cursor: Option<String> = None;
        let mut seen: Vec<String> = Vec::new();
        loop {
            let page: Vec<String> = sqlx::query_scalar(SWEEP_TENANTS_SQL)
                .bind(cursor.clone())
                .bind(1_i64)
                .fetch_all(&env.pool)
                .await
                .expect("tenant page");
            if page.is_empty() {
                break;
            }
            cursor = page.last().cloned();
            seen.extend(page);
            assert!(seen.len() <= 3, "pagination must terminate");
        }
        assert_eq!(
            seen,
            vec!["plcov_page_a", "plcov_page_b", "plcov_page_c"],
            "every contracted tenant visited exactly once, in keyset order"
        );
    });

    // P3 fix 3 — contracts and billing currencies load ONCE for the whole
    // tenant page, not once per tenant (contracts) / per tenant-month
    // (currency). The counters would read 3 (contracts) and 3–6 (currency)
    // on the pre-fix per-tenant loops; they must read exactly 1 and 1 here,
    // including when the real sweep drives them.
    env_test!(
        contract_and_currency_loads_are_one_statement_per_page,
        |env| {
            use crate::test_support::query_count;

            let (start, _end) = target_month();
            let mut tenants = Vec::new();
            for suffix in ["a", "b", "c"] {
                let tenant = format!("plcov_batch_{suffix}");
                seed_tenant(env, &tenant, Some("USD")).await;
                seed_contract(
                    env,
                    &tenant,
                    "platform",
                    "active",
                    start - chrono::Duration::days(30),
                    None,
                )
                .await;
                tenants.push(tenant);
            }

            // Helper level: one statement, full map.
            query_count::reset();
            let contracts = load_contracts_for_tenants(&env.state, &tenants)
                .await
                .expect("batch contracts");
            assert_eq!(query_count::count("product_lines.contract_load"), 1);
            assert_eq!(contracts.len(), 3);
            assert!(
                contracts
                    .values()
                    .all(|rows| rows.len() == 1 && rows[0].product_line == PLATFORM_PRODUCT_LINE),
                "every tenant's contract is present"
            );

            query_count::reset();
            let currencies = load_billing_currencies(&env.pool, &tenants)
                .await
                .expect("batch currencies");
            assert_eq!(query_count::count("product_lines.currency_load"), 1);
            assert_eq!(currencies.len(), 3);
            assert!(currencies.values().all(|currency| currency == "USD"));

            // Sweep level: the same two statements drive all three tenants
            // (no addresses: the months are surfaced as needs_review, which is
            // irrelevant to the load count).
            query_count::reset();
            let sweep = sweep_product_line_months(&env.state)
                .await
                .expect("batch sweep");
            assert_eq!(sweep.tenants_checked, 3, "{sweep:?}");
            assert_eq!(
                query_count::count("product_lines.contract_load"),
                1,
                "contracts load once for the page, not once per tenant"
            );
            assert_eq!(
                query_count::count("product_lines.currency_load"),
                1,
                "currencies load once for the page, not once per tenant-month"
            );
        }
    );

    env_test!(
        a_backdated_line_never_silently_joins_an_existing_month_invoice,
        |env| {
            let tenant = "plcov_backdate";
            let (start, end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "mailboxes",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;
            seed_mailbox(env, tenant, "back@example.test", true, false).await;
            // The month's invoice identity is already taken (an earlier run
            // billed a since-removed line for the same month): the newly
            // claimed Mailboxes line must NOT be swallowed by it.
            sqlx::query(
                "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                       subtotal, vat_total, total, issued_at, due_at,
                                       period_start, period_end, product_lines_period,
                                       created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 99000, 'eur', 'pending', 'PL-PLCOV-BACK',
                         99000, 0, 99000, NOW(), NOW(), $2, $3, $2, NOW(), NOW())",
            )
            .bind(tenant)
            .bind(start)
            .bind(end)
            .execute(&env.pool)
            .await
            .expect("seed existing month invoice");

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(result.months_already_invoiced, 1);
            assert_eq!(
                result.invoices_created, 0,
                "never a second invoice for the month"
            );
            let (state, _metered, _, _) = period_row(env, tenant, "mailboxes")
                .await
                .expect("period row");
            assert_eq!(
                state, "needs_review",
                "the unlinked line is surfaced for reconciliation, never silently linked"
            );
            assert_eq!(
                invoice_rows(env, tenant).await.len(),
                1,
                "the pre-existing invoice is untouched"
            );
        }
    );

    env_test!(
        period_without_a_snapshot_surfaces_for_review_instead_of_repricing,
        |env| {
            let tenant = "plcov_nosnapshot";
            let (start, end) = target_month();
            seed_tenant(env, tenant, None).await;
            seed_address(env, tenant).await;
            seed_contract(
                env,
                tenant,
                "platform",
                "active",
                start - chrono::Duration::days(30),
                None,
            )
            .await;
            // An unbilled period row with NO pricing snapshot (an ops-inserted
            // row): pricing must never fall back to today's catalog (audit F32).
            sqlx::query(
                "INSERT INTO billing_periods
                 (tenant_id, usage_kind, period_start, period_end, currency, plan_name)
             VALUES ($1, 'platform', $2, $3, 'EUR', 'platform')
             ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING",
            )
            .bind(tenant)
            .bind(start)
            .bind(end)
            .execute(&env.pool)
            .await
            .expect("seed snapshot-less period");

            let result = sweep_product_line_months(&env.state).await.expect("sweep");
            assert_eq!(result.periods_needs_review, 1);
            assert_eq!(result.invoices_created, 0);
            let (state, _metered, _, _) = period_row(env, tenant, "platform")
                .await
                .expect("period row");
            assert_eq!(state, "needs_review");
            assert!(invoice_rows(env, tenant).await.is_empty());
        }
    );
}
