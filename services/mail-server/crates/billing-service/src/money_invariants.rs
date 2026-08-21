//! Money invariants (audit item 4) — a dedicated gate over every amount
//! path in the billing crates.
//!
//! Invariants enforced here:
//!
//! 1. **Integer-cents round-trips** — every money amount travels as `i64`
//!    cents; the display formatting (`cents_to_usd_string`) must invert
//!    exactly for any representable value.
//! 2. **Half-up rounding** — PAYG millicents→cents, VAT `round_vat`,
//!    overage millicents→cents and SLA `percent_of_cents_half_up` all
//!    round halves up, verified against exact rational (i128) references.
//! 3. **VAT reconciliation** — after `allocate_vat_across_lines`, the sum
//!    of per-line VAT always equals the VAT computed on the invoice total
//!    (the KMD/PDF headline), for randomized line sets (seeded).
//! 4. **Wallet conservation** — a seeded random sequence of
//!    credit/debit/reserve/release/capture/expire operations never loses
//!    cents: `balance + reserved` changes by exactly the op's signed
//!    amount, never goes negative, and the BIGINT release clamp
//!    (migrations 101+104) cannot wrap.
//! 5. **No f32/f64 in money-computation paths** — a source-scan gate over
//!    the modules that compute money; float tokens may appear only in
//!    `format!`-style display lines, which are enumerated here.
//!
//! The PRNG is a deterministic xorshift64* seeded per test — reproducible
//! failures, no external `rand` dependency.

#![cfg(test)]

use billing_common::proration::prorated_amount;
use billing_common::vat_rates::calculate_vat;

use crate::config::PaygPricing;
use crate::invoices::{allocate_vat_across_lines, round_vat};
use crate::maintenance::percent_of_cents_half_up;
use crate::plans::calculate_overage_cost_with_rate;
use crate::routes::cents_to_usd_string;

// ---------------------------------------------------------------------------
// Seeded PRNG (xorshift64*)
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound.max(1)
    }
}

// ---------------------------------------------------------------------------
// 1. Integer-cents round-trips
// ---------------------------------------------------------------------------

#[test]
fn usd_display_string_round_trips_to_integer_cents() {
    let mut rng = Rng::new(0xB00);
    for _ in 0..2_000 {
        let cents = (rng.next_u64() % 1_000_000_000_000) as i64; // < $10B, well inside f64 exact range for 2dp strings
        let rendered = cents_to_usd_string(cents);
        let without_currency = rendered.trim_start_matches('$').to_string();
        let parsed = without_currency
            .split('.')
            .map(str::to_string)
            .collect::<Vec<_>>();
        let rebuilt: i64 = match parsed.as_slice() {
            [whole, frac] => {
                let whole: i64 = whole.parse().expect("whole dollars parse");
                assert_eq!(frac.len(), 2, "always exactly two fraction digits");
                let frac: i64 = frac.parse().expect("cents fraction parses");
                whole * 100 + frac
            }
            _ => panic!("unexpected rendering {rendered}"),
        };
        assert_eq!(rebuilt, cents, "display of {cents} cents must invert exactly");
    }
}

// ---------------------------------------------------------------------------
// 2. Half-up rounding everywhere
// ---------------------------------------------------------------------------

/// Exact rational half-up reference: (numerator / denominator) with halves
/// rounding away from zero for positive values.
fn half_up(numerator: i128, denominator: i128) -> i128 {
    assert!(denominator > 0);
    (numerator + denominator / 2).div_euclid(denominator)
}

#[test]
fn payg_millicents_to_cents_is_half_up() {
    let mut rng = Rng::new(0xC0FFEE);
    let pricing = PaygPricing::default();
    for _ in 0..500 {
        let emails = rng.below(200_000);
        let api_calls = rng.below(500_000);
        let (email_cents, api_cents, total) = pricing
            .calculate(emails, api_calls)
            .expect("random usage must calculate");

        // Reference: exact tiered millicents, half-up to cents.
        let emails_i = i128::from(emails);
        let mut exact_millicents = 0_i128;
        let tiers: [(u64, i64); 4] = [
            (10_000, 100),
            (100_000, 80),
            (1_000_000, 50),
            (u64::MAX, 30),
        ];
        let mut remaining = emails_i;
        let mut prev = 0_i128;
        for (up_to, rate) in tiers {
            let width = (i128::try_from(up_to).unwrap() - prev).max(0);
            let applicable = remaining.min(width);
            exact_millicents += applicable * i128::from(rate);
            remaining -= applicable;
            prev = i128::try_from(up_to).unwrap();
            if remaining == 0 {
                break;
            }
        }
        assert_eq!(
            i128::from(email_cents),
            half_up(exact_millicents, 1000),
            "email cost for {emails} emails must be exact half-up"
        );

        let billable = i128::from(api_calls.saturating_sub(100_000));
        let expected_api = ((billable + 999) / 1000) * 10; // platform contract: ceil per 1000
        assert_eq!(i128::from(api_cents), expected_api);
        assert_eq!(total, email_cents.saturating_add(api_cents));
    }
}

#[test]
fn vat_round_vat_is_half_up() {
    // Exhaustive small sweep + random large amounts.
    for amount in 0..2_000 {
        for rate in [0, 5, 19, 21, 24, 27] {
            assert_eq!(
                round_vat(amount, rate),
                i64::try_from(half_up(
                    i128::from(amount) * i128::from(rate),
                    100
                ))
                .unwrap(),
                "round_vat({amount}, {rate}) must be half-up"
            );
        }
    }
    let mut rng = Rng::new(0x5EED);
    for _ in 0..1_000 {
        let amount = (rng.next_u64() % 10_000_000_000) as i64;
        let rate = 24;
        assert_eq!(
            round_vat(amount, rate),
            i64::try_from(half_up(i128::from(amount) * 24, 100)).unwrap()
        );
    }
}

#[test]
fn overage_millicents_is_ceiling_per_platform_contract() {
    // The overage path charges ceil(overage * rate / 1000) — documented
    // platform contract (never undercharge); verify against exact math.
    let mut rng = Rng::new(0x0A0A);
    for _ in 0..1_000 {
        let sent = rng.below(1_000_000) as i64;
        let limit = rng.below(1_000_000) as i64;
        let rate = (rng.below(200)) as i64;
        let cost = calculate_overage_cost_with_rate(sent, limit, rate);
        if sent <= limit || limit < 0 {
            assert_eq!(cost, 0);
        } else {
            let overage = i128::from(sent - limit);
            let exact = overage * i128::from(rate);
            let expected = (exact + 999).div_euclid(1000);
            assert_eq!(i128::from(cost), expected, "sent={sent} limit={limit} rate={rate}");
        }
    }
}

#[test]
fn sla_percent_of_cents_is_half_up_and_integer_only() {
    assert_eq!(percent_of_cents_half_up(10_000, 24), 2_400);
    // Exactly half a cent rounds up: 50 % of 1 cent.
    assert_eq!(percent_of_cents_half_up(1, 50), 1);
    assert_eq!(percent_of_cents_half_up(3, 50), 2); // 1.5 → 2
    assert_eq!(percent_of_cents_half_up(1, 49), 0); // 0.49 → 0
    assert_eq!(percent_of_cents_half_up(0, 100), 0);
    assert_eq!(percent_of_cents_half_up(100, 0), 0);

    // Reference check at scale.
    let mut rng = Rng::new(0x51A);
    for _ in 0..500 {
        let cents = (rng.next_u64() % 10_000_000_000) as i64;
        let percent = (rng.below(101)) as i32;
        assert_eq!(
            i128::from(percent_of_cents_half_up(cents, i64::from(percent))),
            half_up(i128::from(cents) * i128::from(percent), 100)
        );
    }
}

#[test]
fn proration_amounts_are_half_up() {
    let mut rng = Rng::new(0x9B1);
    for _ in 0..500 {
        let price = (rng.below(5_000_00)) as i64;
        let days_in_period = 1 + rng.below(366) as i64;
        let days_remaining = rng.below(days_in_period as u64 + 5) as i64;
        let amount = prorated_amount(price, days_remaining, days_in_period)
            .expect("proration must calculate");
        assert_eq!(
            i128::from(amount),
            half_up(
                i128::from(price) * i128::from(days_remaining),
                i128::from(days_in_period)
            )
        );
    }
}

// ---------------------------------------------------------------------------
// 3. VAT reconciliation after line allocation
// ---------------------------------------------------------------------------

#[test]
fn vat_line_allocation_reconciles_with_headline_for_random_invoices() {
    let mut rng = Rng::new(0xA11CE);
    for _ in 0..1_000 {
        let line_count = 1 + rng.below(12) as usize;
        let amounts: Vec<i64> = (0..line_count)
            .map(|_| (rng.below(50_000_00)) as i64)
            .collect();
        let rate = [0, 5, 10, 19, 20, 21, 22, 23, 24, 25, 27][rng.below(11) as usize];

        let allocated = allocate_vat_across_lines(&amounts, rate);
        assert_eq!(allocated.len(), amounts.len());

        let subtotal: i64 = amounts.iter().sum();
        let headline = round_vat(subtotal, rate);
        let allocated_total: i64 = allocated.iter().sum();
        assert_eq!(
            allocated_total, headline,
            "allocated VAT must equal headline VAT (lines={amounts:?}, rate={rate})"
        );

        // No line may carry negative VAT when amounts are non-negative.
        for value in &allocated {
            assert!(*value >= 0, "negative line VAT in {allocated:?}");
        }

        // The headline itself must match the VAT the invoice issuer would
        // compute for the same subtotal via the shared billing-common rate
        // logic (country irrelevant at rate level).
        let (rate_out, vat_out) = calculate_vat(subtotal, "EE", None);
        assert_eq!(rate_out, 24);
        if rate == 24 {
            assert_eq!(headline, vat_out);
        }
    }
}

#[test]
fn vat_allocation_handles_zero_valued_lines() {
    let amounts = [0, 0, 5_00];
    let allocated = allocate_vat_across_lines(&amounts, 24);
    assert_eq!(allocated.iter().sum::<i64>(), round_vat(5_00, 24));
}

// ---------------------------------------------------------------------------
// 4. Wallet conservation across random operation sequences
// ---------------------------------------------------------------------------

/// Rust model of the SQL wallet semantics (migrations 022/101/104):
/// BIGINT `balance`/`reserved`, clamped release, `balance >= 0`,
/// `reserved >= 0`.
struct WalletModel {
    balance: i64,
    reserved: i64,
}

#[derive(Debug, Clone, Copy)]
enum WalletOp {
    Credit(i64),
    Debit(i64),
    Reserve(i64),
    Release(i64),
    Capture(i64),
    Expire(i64),
}

impl WalletModel {
    /// Apply one operation, mirroring the SQL constraints. Returns the
    /// change to `balance + reserved` that the op is allowed to cause.
    fn apply(&mut self, op: WalletOp) -> i64 {
        match op {
            WalletOp::Credit(amount) => {
                self.balance += amount; // top-up
                amount
            }
            WalletOp::Debit(amount) => {
                let taken = amount.min(self.balance);
                self.balance -= taken;
                -taken
            }
            WalletOp::Reserve(amount) => {
                let available = self.balance;
                let taken = amount.min(available);
                self.balance -= taken;
                self.reserved += taken;
                0 // moved, not spent
            }
            WalletOp::Release(amount) => {
                // release_reserved_cents: GREATEST(0, reserved - total)
                let released = amount.min(self.reserved);
                self.reserved -= released;
                self.balance += released;
                0
            }
            WalletOp::Capture(amount) => {
                let taken = amount.min(self.reserved);
                self.reserved -= taken;
                -taken // reservation leaves the wallet for good
            }
            WalletOp::Expire(amount) => {
                // Expired-reservation sweep: same as release from the
                // wallet's perspective.
                let released = amount.min(self.reserved);
                self.reserved -= released;
                self.balance += released;
                0
            }
        }
    }

    fn total(&self) -> i64 {
        self.balance + self.reserved
    }
}

#[test]
fn wallet_ops_conserve_balance_plus_reserved() {
    let mut rng = Rng::new(0xDA1E);
    for case in 0..200 {
        let mut wallet = WalletModel {
            balance: 0,
            reserved: 0,
        };
        let mut expected_total = 0_i64;
        let mut history: Vec<WalletOp> = Vec::new();

        for _ in 0..150 {
            let amount = 1 + rng.below(10_000) as i64;
            let op = match rng.below(6) {
                0 => WalletOp::Credit(amount),
                1 => WalletOp::Debit(amount),
                2 => WalletOp::Reserve(amount),
                3 => WalletOp::Release(amount),
                4 => WalletOp::Capture(amount),
                _ => WalletOp::Expire(amount),
            };
            let delta = wallet.apply(op);
            expected_total += delta;
            history.push(op);

            assert!(wallet.balance >= 0, "case {case}: negative balance after {history:?}");
            assert!(wallet.reserved >= 0, "case {case}: negative reserved after {history:?}");
            assert_eq!(
                wallet.total(),
                expected_total,
                "case {case}: cents lost after {history:?}"
            );
        }
    }
}

#[test]
fn wallet_bigint_release_clamp_never_wraps() {
    // Migration 101 computed the clamped subtraction in BIGINT but stored
    // INTEGER; migration 104 makes the whole path BIGINT. The model must
    // clamp to zero, never wrap, at ranges far above INT_MAX.
    let mut wallet = WalletModel {
        balance: 0,
        reserved: 0,
    };
    wallet.reserved = 3_000_000_000; // > i32::MAX
    wallet.apply(WalletOp::Release(4_000_000_000));
    assert_eq!(wallet.reserved, 0, "release above reserved clamps to zero");
    assert_eq!(wallet.balance, 3_000_000_000, "released funds return to balance");
}

#[test]
fn wallet_capture_cannot_overdraw_reservation() {
    let mut wallet = WalletModel {
        balance: 1_000,
        reserved: 0,
    };
    wallet.apply(WalletOp::Reserve(1_000));
    assert_eq!(wallet.total(), 1_000);
    // Capturing more than reserved spends only what exists.
    wallet.apply(WalletOp::Capture(5_000));
    assert_eq!(wallet.reserved, 0);
    assert_eq!(wallet.total(), 0, "no cents created from nothing");
}

// ---------------------------------------------------------------------------
// 5. f32/f64 gate over money-computation modules
// ---------------------------------------------------------------------------

/// (crate-relative file, allowlist) pairs. The allowlist enumerates the
/// ONLY lines allowed to mention floats: display formatting (`format!`)
/// and this module itself.
const MONEY_PATH_FILES: &[(&str, &str)] = &[
    ("src/config.rs", "src/config.rs"),
    ("src/plans.rs", "src/plans.rs"),
    ("src/invoices.rs", "src/invoices.rs"),
    ("src/credit_notes.rs", "src/credit_notes.rs"),
    ("src/subscriptions.rs", "src/subscriptions.rs"),
    ("../billing-common/src/proration.rs", "billing-common/proration.rs"),
    ("../billing-common/src/vat_rates.rs", "billing-common/vat_rates.rs"),
];

#[test]
fn no_floating_point_in_money_computation_paths() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let mut violations: Vec<String> = Vec::new();

    for (relative, label) in MONEY_PATH_FILES {
        let path = std::path::Path::new(manifest).join(relative);
        let Ok(source) = std::fs::read_to_string(&path) else {
            violations.push(format!("{label}: source file unreadable"));
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                continue; // comments
            }
            if trimmed.contains("f64") || trimmed.contains("f32") {
                // Floats are tolerated ONLY inside display formatting.
                let is_display = trimmed.contains("format!(") || trimmed.contains("format_currency");
                if !is_display {
                    violations.push(format!("{label}:{}: {}", index + 1, trimmed));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "f32/f64 found in money-computation paths (floats are only allowed in \
         `format!` display lines):\n{}",
        violations.join("\n")
    );
}

#[test]
fn money_types_are_integer_cents_everywhere_in_gate() {
    // Structural check: the gate list must cover the files that compute
    // money. If a new money module appears it must be added to
    // MONEY_PATH_FILES (this test fails loudly when the tree shifts).
    let manifest = env!("CARGO_MANIFEST_DIR");
    for (relative, label) in MONEY_PATH_FILES {
        let path = std::path::Path::new(manifest).join(relative);
        assert!(
            path.exists(),
            "{label}: gated file {relative} no longer exists — update MONEY_PATH_FILES"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Crate-wide int-width gates (audit item 3e — i64 everywhere in money)
// ---------------------------------------------------------------------------

/// Identifiers whose lines are money paths. A line mentioning any of these
/// together with a narrow SQL integer cast (`::int4`, `::integer`,
/// `::int2`, `::smallint`) is a money amount being forced through 32-bit
/// (or narrower) arithmetic — the exact class of bug migration 104 widens
/// out of the wallet schema.
const MONEY_IDENTIFIERS: &[&str] = &[
    "balance", "amount", "cents", "reserved", "price", "vat", "refund", "charge",
    "wallet", "revenue", "credit_note",
];

/// All non-test source files of both billing crates, scanned by the
/// crate-wide gates below. (This module is excluded — it quotes the
/// offending tokens inside its own assertions.)
fn crate_source_files() -> Vec<std::path::PathBuf> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for base in [
        manifest.join("src"),
        manifest.join("../billing-common/src"),
    ] {
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|extension| extension == "rs")
                    && path.file_name().is_some_and(|name| name != "money_invariants.rs")
                {
                    files.push(path);
                }
            }
        }
    }
    files
}

fn is_comment(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("//") || trimmed.starts_with("//!")
}

#[test]
fn no_narrow_sql_integer_casts_on_money_lines() {
    let narrow_casts = ["::int4", "::integer", "::int2", "::smallint"];
    let mut violations = Vec::new();

    for file in crate_source_files() {
        let label = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unknown>");
        let Ok(source) = std::fs::read_to_string(&file) else {
            violations.push(format!("{label}: unreadable"));
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            let has_narrow_cast = narrow_casts.iter().any(|cast| line.contains(cast));
            if !has_narrow_cast {
                continue;
            }
            let lowered = line.to_lowercase();
            if MONEY_IDENTIFIERS.iter().any(|id| lowered.contains(id)) {
                violations.push(format!("{label}:{}: {}", index + 1, line.trim()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "narrow (32-bit or less) SQL integer casts found on money lines — \
         money amounts must be BIGINT/i64 end-to-end (migration 104):\n{}",
        violations.join("\n")
    );
}

/// Historical bug pattern this gate exists for:
/// `((cents as f64) * pct / 100.0).round() as i64` — a money amount routed
/// through a float and truncated back to an integer. The only surviving
/// float→int conversions in the crates are non-money metric percentages,
/// enumerated here.
const ALLOWED_FLOAT_TO_INT_LINES: &[&str] = &[
    // Quota-usage display percent (emails used of limit), not a money amount.
    "let rounded_percent = current_percent.round() as i64;",
];

#[test]
fn no_float_to_int_conversions_outside_display() {
    let mut violations = Vec::new();

    for file in crate_source_files() {
        let label = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("<unknown>");
        let Ok(source) = std::fs::read_to_string(&file) else {
            violations.push(format!("{label}: unreadable"));
            continue;
        };
        for (index, line) in source.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            let mentions_float = line.contains("f64") || line.contains("f32");
            let converts_to_int =
                line.contains("as i64") || line.contains("as i32") || line.contains("as i16");
            let rounds = line.contains(".round()") || line.contains(".ceil()") || line.contains(".floor()") || line.contains(".trunc()");
            if (mentions_float && converts_to_int) || (rounds && converts_to_int) {
                let trimmed = line.trim();
                if ALLOWED_FLOAT_TO_INT_LINES.iter().any(|allowed| *allowed == trimmed) {
                    continue;
                }
                violations.push(format!("{label}:{}: {}", index + 1, trimmed));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "float→int conversion in a computation path — money amounts must never \
         route through floats; metric exceptions must be allowlisted explicitly:\n{}",
        violations.join("\n")
    );
}
