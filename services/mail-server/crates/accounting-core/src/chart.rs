//! Legal entities and the chart of accounts.
//!
//! The company identity that used to be hard-coded in
//! `compliance/src/estonia_ou.rs` (`COMPANY_NAME`, `REGISTRY_CODE`,
//! `COMPANY_ADDRESS`, file lines 46-52) lives in `legal_entities` now.
//! Adapters resolve accounts by semantic role, never by numeric code.

use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::{AccountingError, Result};
use crate::types::*;

/// One chart-of-accounts template row.
#[derive(Debug, Clone, Copy)]
pub struct AccountSpec {
    pub code: &'static str,
    pub name: &'static str,
    pub account_type: &'static str,
    pub normal_balance: &'static str,
    pub role: Option<&'static str>,
    pub vat_code: Option<&'static str>,
}

/// Standard chart seeded by [`ensure_standard_chart`]. Codes are internal
/// (adapters use roles); entities may rename codes as long as roles stay.
pub const STANDARD_CHART: &[AccountSpec] = &[
    AccountSpec {
        code: "1010",
        name: "Bank",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_BANK),
        vat_code: None,
    },
    AccountSpec {
        code: "1020",
        name: "Payment processor clearing",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_STRIPE_CLEARING),
        vat_code: None,
    },
    AccountSpec {
        code: "1030",
        name: "Bank clearing",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_BANK_CLEARING),
        vat_code: None,
    },
    AccountSpec {
        code: "1100",
        name: "Accounts receivable",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_AR),
        vat_code: None,
    },
    AccountSpec {
        code: "1200",
        name: "Input VAT",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_VAT_INPUT),
        vat_code: Some("INPUT"),
    },
    AccountSpec {
        code: "1300",
        name: "Suspense",
        account_type: "asset",
        normal_balance: "debit",
        role: Some(ROLE_SUSPENSE),
        vat_code: None,
    },
    AccountSpec {
        code: "1510",
        name: "Accumulated depreciation",
        account_type: "asset",
        normal_balance: "credit",
        role: Some(ROLE_ACCUMULATED_DEPRECIATION),
        vat_code: None,
    },
    AccountSpec {
        code: "2000",
        name: "Accounts payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_AP),
        vat_code: None,
    },
    AccountSpec {
        code: "2100",
        name: "Net wages payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_NET_WAGES_PAYABLE),
        vat_code: None,
    },
    AccountSpec {
        code: "2110",
        name: "Income tax payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_INCOME_TAX_PAYABLE),
        vat_code: None,
    },
    AccountSpec {
        code: "2120",
        name: "Social tax payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_SOCIAL_TAX_PAYABLE),
        vat_code: None,
    },
    AccountSpec {
        code: "2130",
        name: "Unemployment insurance payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_UNEMPLOYMENT_PAYABLE),
        vat_code: None,
    },
    AccountSpec {
        code: "2140",
        name: "Funded pension payable",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_PENSION_PAYABLE),
        vat_code: None,
    },
    AccountSpec {
        code: "2200",
        name: "Output VAT",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_VAT_OUTPUT),
        vat_code: Some("OUTPUT"),
    },
    AccountSpec {
        code: "2300",
        name: "Customer wallet liability",
        account_type: "liability",
        normal_balance: "credit",
        role: Some(ROLE_WALLET_LIABILITY),
        vat_code: None,
    },
    AccountSpec {
        code: "3000",
        name: "Retained earnings",
        account_type: "equity",
        normal_balance: "credit",
        role: Some(ROLE_RETAINED_EARNINGS),
        vat_code: None,
    },
    AccountSpec {
        code: "4000",
        name: "Revenue",
        account_type: "revenue",
        normal_balance: "credit",
        role: Some(ROLE_REVENUE),
        vat_code: None,
    },
    AccountSpec {
        code: "4100",
        name: "Refunds and credit notes",
        account_type: "revenue",
        normal_balance: "debit",
        role: Some(ROLE_REFUNDS),
        vat_code: None,
    },
    AccountSpec {
        code: "4200",
        name: "Other income",
        account_type: "revenue",
        normal_balance: "credit",
        role: Some(ROLE_OTHER_INCOME),
        vat_code: None,
    },
    AccountSpec {
        code: "5000",
        name: "Operating expenses",
        account_type: "expense",
        normal_balance: "debit",
        role: Some(ROLE_EXPENSE_DEFAULT),
        vat_code: None,
    },
    AccountSpec {
        code: "5100",
        name: "Payment processing fees",
        account_type: "expense",
        normal_balance: "debit",
        role: Some(ROLE_STRIPE_FEES),
        vat_code: None,
    },
    AccountSpec {
        code: "5200",
        name: "Payroll expense",
        account_type: "expense",
        normal_balance: "debit",
        role: Some(ROLE_PAYROLL_EXPENSE),
        vat_code: None,
    },
    AccountSpec {
        code: "5300",
        name: "Depreciation expense",
        account_type: "expense",
        normal_balance: "debit",
        role: Some(ROLE_DEPRECIATION_EXPENSE),
        vat_code: None,
    },
    AccountSpec {
        code: "6100",
        name: "FX loss",
        account_type: "expense",
        normal_balance: "debit",
        role: Some(ROLE_FX_LOSS),
        vat_code: None,
    },
    AccountSpec {
        code: "7100",
        name: "FX gain",
        account_type: "revenue",
        normal_balance: "credit",
        role: Some(ROLE_FX_GAIN),
        vat_code: None,
    },
];

/// Input for [`create_legal_entity`].
#[derive(Debug, Clone)]
pub struct LegalEntityInput {
    pub legal_name: String,
    pub trading_name: Option<String>,
    pub registry_code: String,
    pub vat_number: Option<String>,
    pub address_line1: Option<String>,
    pub city: Option<String>,
    pub postal_code: Option<String>,
    pub country_code: String,
    pub default_currency: String,
    pub fiscal_year_start_month: i16,
    pub is_default: bool,
}

/// Create a legal entity (idempotent by registry code) and return its id.
pub async fn create_legal_entity(
    conn: &mut PgConnection,
    input: &LegalEntityInput,
) -> Result<Uuid> {
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO legal_entities (
            legal_name, trading_name, registry_code, vat_number,
            address_line1, city, postal_code, country_code,
            default_currency, fiscal_year_start_month, is_default
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (registry_code) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(&input.legal_name)
    .bind(&input.trading_name)
    .bind(&input.registry_code)
    .bind(&input.vat_number)
    .bind(&input.address_line1)
    .bind(&input.city)
    .bind(&input.postal_code)
    .bind(input.country_code.to_uppercase())
    .bind(input.default_currency.to_uppercase())
    .bind(input.fiscal_year_start_month)
    .bind(input.is_default)
    .fetch_optional(&mut *conn)
    .await?;

    if let Some(id) = inserted {
        return Ok(id);
    }

    sqlx::query_scalar("SELECT id FROM legal_entities WHERE registry_code = $1")
        .bind(&input.registry_code)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| {
            AccountingError::Invalid(format!(
                "legal entity with registry code {} not found after insert conflict",
                input.registry_code
            ))
        })
}

/// The default legal entity adapters resolve when none is configured.
pub async fn default_legal_entity(conn: &mut PgConnection) -> Result<Uuid> {
    sqlx::query_scalar("SELECT id FROM legal_entities WHERE is_default LIMIT 1")
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(AccountingError::NoDefaultLegalEntity)
}

/// Seed the standard chart of accounts for an entity (idempotent).
/// Returns the number of rows actually inserted.
pub async fn ensure_standard_chart(conn: &mut PgConnection, legal_entity_id: Uuid) -> Result<u64> {
    let mut inserted = 0u64;
    for spec in STANDARD_CHART {
        let result = sqlx::query(
            r#"
            INSERT INTO chart_of_accounts (
                legal_entity_id, code, name, account_type, normal_balance,
                account_role, vat_code
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(legal_entity_id)
        .bind(spec.code)
        .bind(spec.name)
        .bind(spec.account_type)
        .bind(spec.normal_balance)
        .bind(spec.role)
        .bind(spec.vat_code)
        .execute(&mut *conn)
        .await?;
        inserted += result.rows_affected();
    }
    Ok(inserted)
}

/// Resolve an account by semantic role. Missing roles are a configuration
/// error, never silently substituted.
pub async fn resolve_account_role(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    role: &'static str,
) -> Result<Uuid> {
    sqlx::query_scalar(
        "SELECT id FROM chart_of_accounts \
         WHERE legal_entity_id = $1 AND account_role = $2 AND is_active LIMIT 1",
    )
    .bind(legal_entity_id)
    .bind(role)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(AccountingError::MissingAccountRole {
        legal_entity_id,
        role,
    })
}

/// Resolve a tax account: the entity's date-effective `tax_accounts` mapping
/// first, falling back to the chart role when no mapping is configured.
pub async fn resolve_tax_account(
    conn: &mut PgConnection,
    legal_entity_id: Uuid,
    tax_type: &'static str,
    fallback_role: &'static str,
    on_date: chrono::NaiveDate,
) -> Result<Uuid> {
    let mapped: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT account_id FROM tax_accounts
        WHERE legal_entity_id = $1
          AND tax_type = $2
          AND effective_from <= $3
          AND (effective_to IS NULL OR effective_to >= $3)
        ORDER BY effective_from DESC
        LIMIT 1
        "#,
    )
    .bind(legal_entity_id)
    .bind(tax_type)
    .bind(on_date)
    .fetch_optional(&mut *conn)
    .await?;

    match mapped {
        Some(account_id) => Ok(account_id),
        None => resolve_account_role(conn, legal_entity_id, fallback_role).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_chart_roles_are_unique_and_known() {
        let mut seen = std::collections::HashSet::new();
        for spec in STANDARD_CHART {
            if let Some(role) = spec.role {
                assert!(ACCOUNT_ROLES.contains(&role), "unknown role {role}");
                assert!(seen.insert(role), "role {role} used twice");
            }
            assert!(
                ["asset", "liability", "equity", "revenue", "expense"].contains(&spec.account_type),
                "bad account type {}",
                spec.account_type
            );
            assert!(["debit", "credit"].contains(&spec.normal_balance));
        }
    }
}
