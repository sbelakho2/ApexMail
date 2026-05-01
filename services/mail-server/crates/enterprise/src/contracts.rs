use chrono::{DateTime, Months, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{
    ApiResult, ContractAdditionalFee, ContractAmendmentResult, ContractPurchaseOrderReceipt,
    ContractRenewalQuote, ContractRenewalTerms, ContractUsageSummary, EnterpriseContract,
};

pub struct ContractService {
    db: PgPool,
}

pub struct CreateContractInput {
    pub tenant_id: String,
    pub name: String,
    pub start_date: DateTime<Utc>,
    pub end_date: DateTime<Utc>,
    pub auto_renew: bool,
    pub base_price: i64,
    pub committed_volume: i64,
    pub overage_rate: i64,
    pub annual_prepay_discount: i32,
    pub additional_fees: Vec<ContractAdditionalFee>,
    pub payment_terms_days: i32,
    pub sla_credit_percentage: i32,
    pub custom_terms: Option<String>,
    pub allow_purchase_orders: bool,
    pub dedicated_support: bool,
    pub custom_features: Vec<String>,
    pub custom_sla: Option<serde_json::Value>,
}

pub struct SignContractInput {
    pub signature_data: String,
    pub signer_name: String,
    pub signer_title: String,
    pub signed_at: DateTime<Utc>,
}

pub struct AmendmentInput {
    pub reason: String,
    pub proposed_changes: serde_json::Value,
}

pub struct CancelContractInput {
    pub reason: String,
    pub effective_date: Option<DateTime<Utc>>,
}

pub struct RenewContractInput {
    pub new_end_date: DateTime<Utc>,
    pub new_terms: Option<ContractRenewalTerms>,
}

pub struct PurchaseOrderInput {
    pub po_number: String,
    pub amount: i64,
    pub issued_date: DateTime<Utc>,
    pub expiry_date: Option<DateTime<Utc>>,
    pub attachment_url: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ContractRow {
    id: Uuid,
    tenant_id: String,
    contract_number: String,
    name: String,
    status: String,
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
    auto_renew: bool,
    base_price: i32,
    committed_volume: i32,
    overage_rate: i32,
    annual_prepay_discount: i32,
    additional_fees: Option<serde_json::Value>,
    payment_terms_days: i32,
    sla_credit_percentage: i32,
    custom_terms: Option<String>,
    allow_purchase_orders: bool,
    dedicated_support: bool,
    custom_features: Option<serde_json::Value>,
    custom_sla: Option<serde_json::Value>,
    signed_at: Option<DateTime<Utc>>,
    signed_by: Option<String>,
    purchase_order_number: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ContractRow {
    fn into_contract(self) -> EnterpriseContract {
        let additional_fees = self
            .additional_fees
            .and_then(|value| serde_json::from_value::<Vec<ContractAdditionalFee>>(value).ok())
            .unwrap_or_default();
        let custom_features = self
            .custom_features
            .and_then(|value| serde_json::from_value::<Vec<String>>(value).ok())
            .unwrap_or_default();

        EnterpriseContract {
            id: self.id,
            tenant_id: self.tenant_id,
            contract_number: self.contract_number,
            name: self.name,
            status: self.status,
            start_date: self.start_date,
            end_date: self.end_date,
            auto_renew: self.auto_renew,
            base_price: i64::from(self.base_price),
            committed_volume: i64::from(self.committed_volume),
            overage_rate: i64::from(self.overage_rate),
            annual_prepay_discount: self.annual_prepay_discount,
            additional_fees,
            payment_terms_days: self.payment_terms_days,
            sla_credit_percentage: self.sla_credit_percentage,
            custom_terms: self.custom_terms,
            allow_purchase_orders: self.allow_purchase_orders,
            dedicated_support: self.dedicated_support,
            custom_features,
            custom_sla: self.custom_sla,
            signed_at: self.signed_at,
            signed_by: self.signed_by,
            purchase_order_number: self.purchase_order_number,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

impl ContractService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    pub async fn create_contract(
        &self,
        input: CreateContractInput,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let additional_fees = serde_json::to_value(&input.additional_fees)
            .map_err(|error| format!("Serialize additional fees: {error}"))?;
        let custom_features = serde_json::to_value(&input.custom_features)
            .map_err(|error| format!("Serialize custom features: {error}"))?;

        let row = sqlx::query_as::<_, ContractRow>(
            r#"
            INSERT INTO enterprise_contracts (
                tenant_id, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                created_at, updated_at
            ) VALUES (
                $1, $2, 'draft', $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, $12, $13,
                $14, $15, $16, $17,
                NOW(), NOW()
            )
            RETURNING
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            "#,
        )
        .bind(&input.tenant_id)
        .bind(&input.name)
        .bind(input.start_date)
        .bind(input.end_date)
        .bind(input.auto_renew)
        .bind(input.base_price)
        .bind(input.committed_volume)
        .bind(input.overage_rate)
        .bind(input.annual_prepay_discount)
        .bind(additional_fees)
        .bind(input.payment_terms_days)
        .bind(input.sla_credit_percentage)
        .bind(input.custom_terms)
        .bind(input.allow_purchase_orders)
        .bind(input.dedicated_support)
        .bind(custom_features)
        .bind(input.custom_sla)
        .fetch_one(&self.db)
        .await
        .map_err(|error| format!("Create contract: {error}"))?;

        Ok(ApiResult::ok(row.into_contract()))
    }

    pub async fn list_contracts(
        &self,
        tenant_id: &str,
    ) -> Result<ApiResult<Vec<EnterpriseContract>>, String> {
        let rows = sqlx::query_as::<_, ContractRow>(
            r#"
            SELECT
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            FROM enterprise_contracts
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|error| format!("List contracts: {error}"))?;

        Ok(ApiResult::ok(
            rows.into_iter().map(ContractRow::into_contract).collect(),
        ))
    }

    pub async fn get_contract(
        &self,
        contract_id: Uuid,
        tenant_id: &str,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let row = sqlx::query_as::<_, ContractRow>(
            r#"
            SELECT
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            FROM enterprise_contracts
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(contract_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Get contract: {error}"))?;

        match row {
            Some(contract) => Ok(ApiResult::ok(contract.into_contract())),
            None => Ok(ApiResult::err("Contract not found", "NOT_FOUND")),
        }
    }

    pub async fn get_contract_usage(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
    ) -> Result<ApiResult<ContractUsageSummary>, String> {
        let contract = match self.get_contract(contract_id, tenant_id).await? {
            ApiResult {
                success: true,
                data: Some(contract),
                ..
            } => contract,
            missing => {
                return Ok(ApiResult {
                    success: missing.success,
                    data: None,
                    error: missing.error,
                    code: missing.code,
                });
            }
        };

        let now = Utc::now();
        let periods = contract_billing_periods(contract.start_date, contract.end_date);
        let Some(period_index) = resolve_contract_billing_period(&periods, now) else {
            return Ok(ApiResult::ok(ContractUsageSummary {
                current_usage: 0,
                committed_volume: 0,
                percent_used: 0.0,
                projected_usage: 0,
                overage_estimate: 0,
            }));
        };
        let current_period = &periods[period_index];
        let period_start = current_period.start;
        let period_end = current_period.end;

        let current_usage: i64 = sqlx::query_scalar(
            r#"
                        SELECT COALESCE(SUM(quantity), 0)::bigint
            FROM metering_events
            WHERE tenant_id = $1
              AND event_type = 'emails_sent'
              AND timestamp >= $2
              AND timestamp < $3
            "#,
        )
        .bind(tenant_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_one(&self.db)
        .await
        .map_err(|error| format!("Get contract usage: {error}"))?;

        let committed_volume =
            calculate_period_committed_volume(contract.committed_volume, &periods, period_index);
        let percent_used = if committed_volume > 0 {
            (current_usage as f64 / committed_volume as f64) * 100.0
        } else {
            0.0
        };

        let reference_time = if now < period_start {
            period_start
        } else if now > period_end {
            period_end
        } else {
            now
        };
        let elapsed_seconds = ((reference_time - period_start).num_seconds()).max(1) as f64;
        let period_seconds = ((period_end - period_start).num_seconds()).max(1) as f64;
        let projected_usage = if reference_time >= period_end {
            current_usage
        } else {
            ((current_usage as f64 / elapsed_seconds) * period_seconds).floor() as i64
        };
        let overage_estimate = (projected_usage - committed_volume).max(0) * contract.overage_rate;

        Ok(ApiResult::ok(ContractUsageSummary {
            current_usage,
            committed_volume,
            percent_used,
            projected_usage,
            overage_estimate,
        }))
    }

    pub async fn submit_for_signature(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let row = sqlx::query_as::<_, ContractRow>(
            r#"
            UPDATE enterprise_contracts
            SET status = 'pending_signature', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            "#,
        )
        .bind(contract_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Submit contract for signature: {error}"))?;

        match row {
            Some(contract) => Ok(ApiResult::ok(contract.into_contract())),
            None => Ok(ApiResult::err("Contract not found", "NOT_FOUND")),
        }
    }

    pub async fn sign_contract(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
        input: SignContractInput,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|error| format!("Begin sign transaction: {error}"))?;

        sqlx::query(
            r#"
            INSERT INTO contract_signatures (
                id, contract_id, tenant_id, signature_data, signer_name, signer_title, signed_at, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(contract_id)
        .bind(tenant_id)
        .bind(&input.signature_data)
        .bind(&input.signer_name)
        .bind(&input.signer_title)
        .bind(input.signed_at)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Insert contract signature: {error}"))?;

        let row = sqlx::query_as::<_, ContractRow>(
            r#"
            UPDATE enterprise_contracts
            SET status = 'active',
                signed_at = $2,
                signed_by = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $4
            RETURNING
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            "#,
        )
        .bind(contract_id)
        .bind(input.signed_at)
        .bind(format!("{} ({})", input.signer_name, input.signer_title))
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("Activate contract: {error}"))?;

        let Some(row) = row else {
            tx.rollback()
                .await
                .map_err(|error| format!("Rollback sign transaction: {error}"))?;
            return Ok(ApiResult::err("Contract not found", "NOT_FOUND"));
        };

        sqlx::query("UPDATE tenants SET plan = 'enterprise', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("Promote tenant plan: {error}"))?;

        tx.commit()
            .await
            .map_err(|error| format!("Commit sign transaction: {error}"))?;

        Ok(ApiResult::ok(row.into_contract()))
    }

    pub async fn request_amendment(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
        input: AmendmentInput,
    ) -> Result<ApiResult<ContractAmendmentResult>, String> {
        let row = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            INSERT INTO contract_amendments (
                id, contract_id, tenant_id, reason, proposed_changes, status, created_at
            )
            SELECT gen_random_uuid(), c.id, c.tenant_id, $3, $4, 'pending', NOW()
            FROM enterprise_contracts c
            WHERE c.id = $1 AND c.tenant_id = $2
            RETURNING id, status
            "#,
        )
        .bind(contract_id)
        .bind(tenant_id)
        .bind(&input.reason)
        .bind(input.proposed_changes)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Request amendment: {error}"))?;

        match row {
            Some((id, status)) => Ok(ApiResult::ok(ContractAmendmentResult { id, status })),
            None => Ok(ApiResult::err("Contract not found", "NOT_FOUND")),
        }
    }

    pub async fn cancel_contract(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
        input: CancelContractInput,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let effective_date = input.effective_date.unwrap_or_else(Utc::now);
        let row = sqlx::query_as::<_, ContractRow>(
            r#"
            UPDATE enterprise_contracts
            SET status = 'terminated', end_date = $2, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $3
            RETURNING
                id, tenant_id, contract_number, name, status, start_date, end_date, auto_renew,
                base_price, committed_volume, overage_rate, annual_prepay_discount,
                additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
                allow_purchase_orders, dedicated_support, custom_features, custom_sla,
                signed_at, signed_by, purchase_order_number, created_at, updated_at
            "#,
        )
        .bind(contract_id)
        .bind(effective_date)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Cancel contract: {error}"))?;

        let Some(contract) = row else {
            return Ok(ApiResult::err("Contract not found", "NOT_FOUND"));
        };

        if effective_date <= Utc::now() {
            sqlx::query("UPDATE tenants SET plan = 'scale', updated_at = NOW() WHERE id = $1")
                .bind(tenant_id)
                .execute(&self.db)
                .await
                .map_err(|error| format!("Downgrade tenant plan: {error}"))?;
        }

        let _ = input.reason;

        Ok(ApiResult::ok(contract.into_contract()))
    }

    pub async fn get_renewal_quote(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
    ) -> Result<ApiResult<ContractRenewalQuote>, String> {
        let contract = match self.get_contract(contract_id, tenant_id).await? {
            ApiResult {
                success: true,
                data: Some(contract),
                ..
            } => contract,
            missing => {
                return Ok(ApiResult {
                    success: missing.success,
                    data: None,
                    error: missing.error,
                    code: missing.code,
                });
            }
        };

        let discounted_price = (contract.base_price * 95) / 100;

        Ok(ApiResult::ok(ContractRenewalQuote {
            current_contract: contract.clone(),
            proposed_terms: ContractRenewalTerms {
                base_fee: Some(discounted_price),
                committed_volume: Some(contract.committed_volume),
                overage_rate: Some(contract.overage_rate),
            },
            savings: (contract.base_price - discounted_price) * 12,
        }))
    }

    pub async fn renew_contract(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
        input: RenewContractInput,
    ) -> Result<ApiResult<EnterpriseContract>, String> {
        let existing = match self.get_contract(contract_id, tenant_id).await? {
            ApiResult {
                success: true,
                data: Some(contract),
                ..
            } => contract,
            missing => {
                return Ok(ApiResult {
                    success: missing.success,
                    data: None,
                    error: missing.error,
                    code: missing.code,
                });
            }
        };

        self.create_contract(CreateContractInput {
            tenant_id: existing.tenant_id.clone(),
            name: format!("{} (Renewed)", existing.name),
            start_date: existing.end_date,
            end_date: input.new_end_date,
            auto_renew: existing.auto_renew,
            base_price: input
                .new_terms
                .as_ref()
                .and_then(|terms| terms.base_fee)
                .unwrap_or(existing.base_price),
            committed_volume: input
                .new_terms
                .as_ref()
                .and_then(|terms| terms.committed_volume)
                .unwrap_or(existing.committed_volume),
            overage_rate: input
                .new_terms
                .as_ref()
                .and_then(|terms| terms.overage_rate)
                .unwrap_or(existing.overage_rate),
            annual_prepay_discount: existing.annual_prepay_discount,
            additional_fees: existing.additional_fees.clone(),
            payment_terms_days: existing.payment_terms_days,
            sla_credit_percentage: existing.sla_credit_percentage,
            custom_terms: existing.custom_terms.clone(),
            allow_purchase_orders: existing.allow_purchase_orders,
            dedicated_support: existing.dedicated_support,
            custom_features: existing.custom_features.clone(),
            custom_sla: existing.custom_sla.clone(),
        })
        .await
    }

    pub async fn submit_purchase_order(
        &self,
        tenant_id: &str,
        contract_id: Uuid,
        input: PurchaseOrderInput,
    ) -> Result<ApiResult<ContractPurchaseOrderReceipt>, String> {
        let row = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            INSERT INTO purchase_orders (
                id, tenant_id, contract_id, po_number, amount, currency,
                issued_date, expiry_date, attachment_url, status, created_at
            )
            SELECT gen_random_uuid(), c.tenant_id, c.id, $3, $4, 'USD',
                   $5, $6, $7, 'received', NOW()
            FROM enterprise_contracts c
            WHERE c.id = $1 AND c.tenant_id = $2
            RETURNING id, po_number, status
            "#,
        )
        .bind(contract_id)
        .bind(tenant_id)
        .bind(&input.po_number)
        .bind(input.amount)
        .bind(input.issued_date)
        .bind(input.expiry_date)
        .bind(input.attachment_url)
        .fetch_optional(&self.db)
        .await
        .map_err(|error| format!("Submit purchase order: {error}"))?;

        let Some((id, po_number, status)) = row else {
            return Ok(ApiResult::err("Contract not found", "NOT_FOUND"));
        };

        sqlx::query(
            "UPDATE enterprise_contracts SET purchase_order_number = $2, updated_at = NOW() WHERE id = $1"
        )
        .bind(contract_id)
        .bind(&po_number)
        .execute(&self.db)
        .await
        .map_err(|error| format!("Link purchase order to contract: {error}"))?;

        Ok(ApiResult::ok(ContractPurchaseOrderReceipt {
            id,
            po_number,
            status,
        }))
    }

    pub fn generate_contract_pdf(&self, contract: &EnterpriseContract) -> String {
        generate_contract_pdf(contract)
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ContractBillingPeriod {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    full_end: DateTime<Utc>,
}

fn contract_billing_periods(
    contract_start: DateTime<Utc>,
    contract_end: DateTime<Utc>,
) -> Vec<ContractBillingPeriod> {
    if contract_end <= contract_start {
        return Vec::new();
    }

    let mut periods = Vec::new();
    let mut period_start = contract_start;

    loop {
        let Some(full_end) = period_start.checked_add_months(Months::new(1)) else {
            periods.push(ContractBillingPeriod {
                start: period_start,
                end: contract_end,
                full_end: contract_end,
            });
            break;
        };

        let period_end = full_end.min(contract_end);
        periods.push(ContractBillingPeriod {
            start: period_start,
            end: period_end,
            full_end,
        });

        if period_end >= contract_end {
            break;
        }

        period_start = full_end;
    }

    periods
}

fn resolve_contract_billing_period(
    periods: &[ContractBillingPeriod],
    at: DateTime<Utc>,
) -> Option<usize> {
    if periods.is_empty() {
        return None;
    }

    for (index, period) in periods.iter().enumerate() {
        if at < period.end {
            return Some(index);
        }
    }

    Some(periods.len() - 1)
}

fn billing_period_weight(period: &ContractBillingPeriod) -> f64 {
    let full_seconds = ((period.full_end - period.start).num_seconds()).max(1) as f64;
    let billed_seconds = ((period.end - period.start).num_seconds()).max(0) as f64;

    (billed_seconds / full_seconds).clamp(0.0, 1.0)
}

fn calculate_period_committed_volume(
    committed_volume: i64,
    periods: &[ContractBillingPeriod],
    period_index: usize,
) -> i64 {
    if committed_volume <= 0 || periods.is_empty() {
        return 0;
    }

    let weights: Vec<f64> = periods.iter().map(billing_period_weight).collect();
    let total_weight: f64 = weights.iter().sum();
    if total_weight <= f64::EPSILON {
        return 0;
    }

    let exact_allocations: Vec<f64> = weights
        .iter()
        .map(|weight| committed_volume as f64 * (*weight / total_weight))
        .collect();
    let mut allocations: Vec<i64> = exact_allocations
        .iter()
        .map(|allocation| allocation.floor() as i64)
        .collect();

    let mut remainder = committed_volume - allocations.iter().sum::<i64>();
    if remainder > 0 {
        let mut fractions: Vec<(usize, f64)> = exact_allocations
            .iter()
            .enumerate()
            .map(|(index, allocation)| (index, allocation - allocations[index] as f64))
            .collect();
        fractions.sort_by(|left, right| {
            right
                .1
                .partial_cmp(&left.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.0.cmp(&right.0))
        });

        for (index, _) in fractions {
            if remainder == 0 {
                break;
            }
            allocations[index] += 1;
            remainder -= 1;
        }
    }

    allocations
        .get(period_index.min(allocations.len().saturating_sub(1)))
        .copied()
        .unwrap_or(0)
}

fn generate_contract_pdf(contract: &EnterpriseContract) -> String {
    fn escape_html(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    fn format_currency(cents: i64) -> String {
        format!("${:.2}", cents as f64 / 100.0)
    }

    fn format_date(date: DateTime<Utc>) -> String {
        date.format("%Y-%m-%d").to_string()
    }

    let purchase_order_line = contract
        .purchase_order_number
        .as_ref()
        .map(|value| {
            format!(
                "<p><strong>Purchase Order:</strong> {}</p>",
                escape_html(value)
            )
        })
        .unwrap_or_default();

    let additional_fees = contract
        .additional_fees
        .iter()
        .map(|fee| {
            format!(
                "<tr><td>{} ({})</td><td>{}</td></tr>",
                escape_html(&fee.name),
                escape_html(&fee.frequency),
                format_currency(fee.amount)
            )
        })
        .collect::<String>();

    let custom_terms = contract
        .custom_terms
        .as_ref()
        .map(|terms| {
            format!(
                "<h2>Additional Terms</h2><div class=\"section\"><p>{}</p></div>",
                escape_html(terms)
            )
        })
        .unwrap_or_default();

    format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Enterprise Contract - {title}</title><style>body{{font-family:Georgia,serif;font-size:11pt;line-height:1.6;margin:60px;color:#333}}h1{{font-size:18pt;margin-bottom:30px;text-align:center}}h2{{font-size:14pt;margin-top:30px;border-bottom:1px solid #ccc;padding-bottom:5px}}table{{width:100%;border-collapse:collapse;margin:20px 0}}th,td{{padding:10px;text-align:left;border:1px solid #ddd}}th{{background:#f5f5f5}}.section{{margin:20px 0}}</style></head><body><h1>Enterprise Services Agreement</h1><p style=\"text-align:center\">Contract Reference: {reference}</p><h2>Client</h2><div class=\"section\"><p>{client}</p><p>Tenant ID: {tenant}</p></div><h2>Contract Term</h2><div class=\"section\"><p><strong>Start Date:</strong> {start}</p><p><strong>End Date:</strong> {end}</p><p><strong>Auto-Renewal:</strong> {auto_renew}</p></div><h2>Service Fees</h2><table><tr><th>Description</th><th>Amount</th></tr><tr><td>Monthly Platform Fee</td><td>{base}/month</td></tr><tr><td>Committed Email Volume</td><td>{volume} emails/year</td></tr><tr><td>Overage Rate</td><td>{overage}/email</td></tr>{fees}</table><h2>Payment Terms</h2><div class=\"section\"><p>Net {payment_terms} days.</p>{purchase_order}</div><h2>SLA</h2><div class=\"section\"><p>Service credits: {sla}% of monthly fees.</p></div>{custom_terms}<div class=\"section\"><p><strong>Signed By:</strong> {signed_by}</p><p><strong>Signed At:</strong> {signed_at}</p></div></body></html>",
        title = escape_html(&contract.name),
        reference = escape_html(&contract.contract_number),
        client = escape_html(&contract.name),
        tenant = escape_html(&contract.tenant_id),
        start = format_date(contract.start_date),
        end = format_date(contract.end_date),
        auto_renew = if contract.auto_renew { "Yes" } else { "No" },
        base = format_currency(contract.base_price),
        volume = contract.committed_volume,
        overage = format_currency(contract.overage_rate),
        fees = additional_fees,
        payment_terms = contract.payment_terms_days,
        purchase_order = purchase_order_line,
        sla = contract.sla_credit_percentage,
        custom_terms = custom_terms,
        signed_by = contract
            .signed_by
            .as_deref()
            .map(escape_html)
            .unwrap_or_else(|| "_________________".to_string()),
        signed_at = contract
            .signed_at
            .map(format_date)
            .unwrap_or_else(|| "_________________".to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_billing_periods_clip_partial_final_month() {
        let start = DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let periods = contract_billing_periods(start, end);

        assert_eq!(periods.len(), 3);
        assert_eq!(periods[0].start, start);
        assert_eq!(
            periods[0].end,
            DateTime::parse_from_rfc3339("2026-02-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            periods[2].start,
            DateTime::parse_from_rfc3339("2026-03-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(periods[2].end, end);
        assert_eq!(
            periods[2].full_end,
            DateTime::parse_from_rfc3339("2026-04-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn period_committed_volume_prorates_partial_final_month() {
        let start = DateTime::parse_from_rfc3339("2026-01-15T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let periods = contract_billing_periods(start, end);

        let allocations: Vec<i64> = (0..periods.len())
            .map(|index| calculate_period_committed_volume(300, &periods, index))
            .collect();

        assert_eq!(allocations.iter().sum::<i64>(), 300);
        assert_eq!(allocations[0], allocations[1]);
        assert!(allocations[2] < allocations[1]);
    }

    #[test]
    fn contract_pdf_escapes_html() {
        let contract = EnterpriseContract {
            id: Uuid::new_v4(),
            tenant_id: "tenant-123".into(),
            contract_number: "ENT-000001".into(),
            name: "Acme <script>".into(),
            status: "draft".into(),
            start_date: Utc::now(),
            end_date: Utc::now(),
            auto_renew: false,
            base_price: 1000,
            committed_volume: 100,
            overage_rate: 1,
            annual_prepay_discount: 0,
            additional_fees: vec![],
            payment_terms_days: 30,
            sla_credit_percentage: 10,
            custom_terms: Some("<b>unsafe</b>".into()),
            allow_purchase_orders: false,
            dedicated_support: false,
            custom_features: vec![],
            custom_sla: None,
            signed_at: None,
            signed_by: None,
            purchase_order_number: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let pdf = generate_contract_pdf(&contract);
        assert!(pdf.contains("Acme &lt;script&gt;"));
        assert!(pdf.contains("&lt;b&gt;unsafe&lt;/b&gt;"));
    }
}
