//! The V30 list-price VAT rule (audit MON-10), resolved at every tax point.
//!
//! Catalog prices are NET business list prices. The amount a customer is
//! CHARGED depends on the buyer:
//!
//! | Buyer | Net | VAT | Charged |
//! |---|---|---|---|
//! | Business, EU, VIES-verified cross-border VAT | list | 0 % (reverse charge) | list |
//! | Business, Estonia or unverified VAT | list | EE / destination rate | list + VAT |
//! | Business, non-EU | list | 0 % | list |
//! | Consumer | list | destination rate | list + VAT (one total) |
//!
//! The pure money rule is [`billing_common::vat_rates::quote_purchase`]
//! (Option A: an owner-set consumer GROSS card is charged exactly, VAT
//! extracted gross-first; without one, the Option B fallback charges net +
//! destination VAT as one total. Businesses always use the net list rule).
//! This module owns the PERSISTED inputs and their re-resolution:
//!
//! * the buyer's declaration (`billing_addresses.is_business`, country, VAT
//!   number — migration 288);
//! * authoritative VIES evidence (`vat_validation_evidence`, migration 213);
//! * a live VIES consultation at CHECKOUT, driven through the injectable
//!   [`VatNumberValidator`] trait and recorded before the payment is created.
//!
//! Renewals and usage charges call [`quote_for_tenant`], which re-reads the
//! declaration and the current evidence AT THE TAX POINT. If the evidence is
//! missing, invalid, an outage, or for another number/country, the supply is
//! not reverse-charged and VAT is added (fail closed, never under-collect).

use async_trait::async_trait;
use chrono::NaiveDate;
use sqlx::PgPool;

use billing_common::vat_rates::{quote_purchase, VatQuote};

/// The buyer facts that decide the VAT branch, as stored on the billing
/// address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaxSubject {
    pub business: bool,
    pub country: String,
    pub vat_number: Option<String>,
}

impl TaxSubject {
    /// A consumer with no country (legacy rows): destination VAT cannot be
    /// resolved, so the caller treats it as an invalid checkout rather than
    /// inventing a country.
    pub fn consumer(country: &str) -> Self {
        Self {
            business: false,
            country: country.trim().to_ascii_uppercase(),
            vat_number: None,
        }
    }
}

/// The buyer's declaration submitted with a checkout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutTaxDeclaration {
    pub business: bool,
    /// ISO 3166-1 alpha-2. Required: consumer totals depend on the
    /// destination country, so it cannot be guessed.
    pub country: String,
    pub vat_number: Option<String>,
}

impl CheckoutTaxDeclaration {
    /// Normalise the declaration: trim, uppercase the country/VAT number,
    /// drop an empty VAT number, and reject a country that is not two ASCII
    /// letters.
    pub fn normalised(&self) -> Result<Self, String> {
        let country = self.country.trim().to_ascii_uppercase();
        if country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            return Err(format!(
                "billing country {country:?} must be a two-letter ISO 3166-1 code"
            ));
        }
        let vat_number = self
            .vat_number
            .as_deref()
            .map(|value| value.trim().replace(' ', "").to_ascii_uppercase())
            .filter(|value| !value.is_empty());
        Ok(Self {
            business: self.business,
            country,
            vat_number,
        })
    }
}

/// The injectable VIES consultation. Production uses [`ViesValidator`];
/// tests script a deterministic one. A failed consultation (transport,
/// authority outage) is not an error the checkout must abort: it simply
/// leaves no valid evidence, so the quote adds VAT.
#[async_trait]
pub trait VatNumberValidator: Send + Sync {
    /// Consult the authority and PERSIST the answer as evidence. Implementors
    /// must record even an invalid/outage answer so the audit trail shows
    /// what was consulted.
    async fn validate(
        &self,
        tenant_id: &str,
        country: &str,
        vat_number: &str,
    ) -> Result<(), String>;
}

/// The production validator: the compliance crate's VIES client + the
/// `vat_validation_evidence` record.
pub struct ViesValidator {
    pool: PgPool,
    http: reqwest::Client,
}

impl ViesValidator {
    pub fn new(pool: PgPool, http: reqwest::Client) -> Self {
        Self { pool, http }
    }
}

#[async_trait]
impl VatNumberValidator for ViesValidator {
    async fn validate(
        &self,
        tenant_id: &str,
        country: &str,
        vat_number: &str,
    ) -> Result<(), String> {
        compliance::vat_vies::validate_and_record(
            &self.pool,
            &self.http,
            Some(tenant_id),
            None,
            country,
            vat_number,
        )
        .await
        .map(|_| ())
        .map_err(|error| format!("VIES consultation failed: {error}"))
    }
}

/// Persist the buyer's declaration on the billing address. The row is the
/// tax-point authority for renewals (and the invoice address snapshot).
async fn persist_declaration(
    pool: &PgPool,
    tenant_id: &str,
    declaration: &CheckoutTaxDeclaration,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO billing_addresses (tenant_id, country, vat_number, is_business, updated_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            country = EXCLUDED.country,
            vat_number = EXCLUDED.vat_number,
            is_business = EXCLUDED.is_business,
            updated_at = NOW()
        "#,
    )
    .bind(tenant_id)
    .bind(&declaration.country)
    .bind(declaration.vat_number.as_deref())
    .bind(declaration.business)
    .execute(pool)
    .await
    .map_err(|error| format!("failed to persist the billing tax declaration: {error}"))?;
    Ok(())
}

/// Whether a live VIES consultation is required before the payment: a
/// business claiming an intra-EU reverse charge with a structurally valid
/// number for its country. Local Estonian and non-EU supplies are not
/// reverse charges, and consumers never carry a number into the quote.
pub fn requires_vies_consultation(declaration: &CheckoutTaxDeclaration) -> bool {
    declaration.business
        && declaration.country != "EE"
        && billing_common::vat_rates::is_eu_country(&declaration.country)
        && declaration.vat_number.as_deref().is_some_and(|vat| {
            billing_common::vat_rates::is_valid_vat_number(vat, Some(&declaration.country))
        })
}

/// Resolve the checkout VAT quote BEFORE the payment exists: persist the
/// declaration, consult VIES when a reverse charge is claimed, then quote
/// the NET list price at `at` with the evidence now on record.
///
/// A consultation failure is logged and the quote proceeds on persisted
/// evidence (none ⇒ VAT added), so a VIES outage can never zero-rate a sale.
pub async fn resolve_checkout_quote(
    pool: &PgPool,
    tenant_id: &str,
    declaration: &CheckoutTaxDeclaration,
    net_cents: i64,
    consumer_gross_cents: Option<i64>,
    at: NaiveDate,
    validator: Option<&dyn VatNumberValidator>,
) -> Result<VatQuote, String> {
    let declaration = declaration.normalised()?;
    persist_declaration(pool, tenant_id, &declaration).await?;
    if let (true, Some(vat_number), Some(validator)) = (
        requires_vies_consultation(&declaration),
        declaration.vat_number.as_deref(),
        validator,
    ) {
        if let Err(error) = validator
            .validate(tenant_id, &declaration.country, vat_number)
            .await
        {
            tracing::warn!(
                tenant_id = %tenant_id,
                country = %declaration.country,
                error = %error,
                "VIES consultation failed before checkout; the quote fails closed to VAT"
            );
        }
    }
    let evidence = match declaration.vat_number.as_deref() {
        Some(vat_number) if declaration.business => {
            crate::invoices::load_vat_evidence_for_tenant(pool, tenant_id, vat_number).await
        }
        _ => None,
    };
    Ok(quote_purchase(
        net_cents,
        consumer_gross_cents,
        &declaration.country,
        declaration.business,
        declaration.vat_number.as_deref(),
        evidence.as_ref(),
        at,
    ))
}

/// Load the stored buyer facts (billing address + declaration).
pub async fn load_tenant_tax_subject(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<TaxSubject>, String> {
    let row: Option<(Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT country, vat_number, is_business FROM billing_addresses WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("billing tax subject lookup failed: {error}"))?;
    Ok(row.and_then(|(country, vat_number, business)| {
        let country = country
            .map(|value| value.trim().to_ascii_uppercase())
            .filter(|value| value.len() == 2)?;
        Some(TaxSubject {
            business,
            country,
            vat_number: vat_number
                .map(|value| value.trim().replace(' ', "").to_ascii_uppercase())
                .filter(|value| !value.is_empty()),
        })
    }))
}

/// Re-validate the tenant's reverse-charge VIES evidence at a tax point
/// (the renewal path). Returns whether a consultation was needed/attempted.
///
/// The quote itself always re-reads the persisted evidence, so an expired,
/// invalid or missing row already fails closed to VAT. The live consultation
/// here keeps the evidence fresh at each renewal; a VIES outage or transport
/// failure is logged and leaves the previous evidence in place.
///
/// FRESHNESS POLICY (30 Oct re-audit #22, formalized): persisted evidence
/// earns reverse charge only inside the documented grace bound
/// (`VAT_EVIDENCE_MAX_AGE_DAYS` in billing-common — 90 days) AND before any
/// explicit `valid_until`. `valid_until = NULL` means "no explicit
/// invalidation", never "valid forever". So a prolonged VIES outage runs the
/// last-known-valid answer out of the grace period and the quote then charges
/// VAT — the conservative policy the research memo documents. There is no
/// configuration switch that extends validity indefinitely.
pub async fn revalidate_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
    validator: &dyn VatNumberValidator,
) -> Result<bool, String> {
    let Some(subject) = load_tenant_tax_subject(pool, tenant_id).await? else {
        return Ok(false);
    };
    let Some(vat_number) = subject.vat_number.as_deref() else {
        return Ok(false);
    };
    if !subject.business
        || subject.country == "EE"
        || !billing_common::vat_rates::is_eu_country(&subject.country)
        || !billing_common::vat_rates::is_valid_vat_number(vat_number, Some(&subject.country))
    {
        return Ok(false);
    }
    validator
        .validate(tenant_id, &subject.country, vat_number)
        .await?;
    Ok(true)
}

/// Quote a NET list price for a tenant AT A TAX POINT. Renewals and usage
/// charges call this on every invoice: the declaration and the evidence are
/// re-read, so a VAT-number change, an expired/invalidated number, a new
/// rate, or a business-status change all take effect without code changes.
pub async fn quote_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
    net_cents: i64,
    consumer_gross_cents: Option<i64>,
    at: NaiveDate,
) -> Result<VatQuote, String> {
    let Some(subject) = load_tenant_tax_subject(pool, tenant_id).await? else {
        return Err(format!(
            "tenant {tenant_id} has no billing address; the destination country (and therefore the VAT) cannot be resolved"
        ));
    };
    let evidence = match subject.vat_number.as_deref() {
        Some(vat_number) if subject.business => {
            crate::invoices::load_vat_evidence_for_tenant(pool, tenant_id, vat_number).await
        }
        _ => None,
    };
    Ok(quote_purchase(
        net_cents,
        consumer_gross_cents,
        &subject.country,
        subject.business,
        subject.vat_number.as_deref(),
        evidence.as_ref(),
        at,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use billing_common::vat_rates::quote_list_price;

    fn declaration(business: bool, country: &str, vat: Option<&str>) -> CheckoutTaxDeclaration {
        CheckoutTaxDeclaration {
            business,
            country: country.to_string(),
            vat_number: vat.map(str::to_string),
        }
    }

    #[test]
    fn declarations_are_normalised_and_countries_validated() {
        let normalised = declaration(true, " de ", Some("de 123 456 789"))
            .normalised()
            .expect("valid");
        assert_eq!(normalised.country, "DE");
        assert_eq!(normalised.vat_number.as_deref(), Some("DE123456789"));
        assert!(declaration(false, "", None).normalised().is_err());
        assert!(declaration(false, "DEU", None).normalised().is_err());
        assert!(declaration(false, "D1", None).normalised().is_err());
        // An empty VAT number is dropped, never stored as "".
        assert_eq!(
            declaration(true, "DE", Some("  "))
                .normalised()
                .expect("valid")
                .vat_number,
            None
        );
    }

    /// The V30 property over EVERY EU country and buyer class: the net is
    /// always the list price (VAT is added, never extracted), a verified
    /// cross-border business is reverse-charged, an Estonian/unverified
    /// business and a consumer pay list + destination VAT, and the charged
    /// total always reconciles as net + VAT.
    #[test]
    fn vat_price_base_over_every_eu_country_and_buyer_class() {
        use billing_common::vat_rates::{
            get_eu_vat_rate_on, is_eu_country, vat_amount_half_up, VatValidationEvidence,
            VatValidationOutcome, VatValidationSource, EU_COUNTRIES,
        };
        use chrono::NaiveDate;
        use uuid::Uuid;

        let at = NaiveDate::from_ymd_opt(2026, 10, 29).expect("date");
        let list_net = 10_000_i64;
        let mut countries: Vec<String> = EU_COUNTRIES.iter().cloned().collect();
        countries.sort();
        assert_eq!(
            countries.len(),
            27,
            "the property covers every member state"
        );

        let evidence_for = |country: &str, vat: &str| VatValidationEvidence {
            requested_at: None,
            returned_name: None,
            returned_address: None,
            authority_request_id: None,
            response_hash: None,
            id: Some(Uuid::new_v4()),
            vat_number: vat.to_string(),
            country: country.to_string(),
            source: VatValidationSource::Vies,
            outcome: VatValidationOutcome::Valid,
            // Inside the formal freshness bound at `at` (30 Oct re-audit #22:
            // NULL valid_until is a bounded grace period, not "valid forever").
            valid_from: NaiveDate::from_ymd_opt(2026, 9, 1).expect("date"),
            valid_until: None,
            outage_state: None,
        };

        for country in &countries {
            let prefix = if country == "GR" {
                "EL"
            } else {
                country.as_str()
            };
            let vat = format!("{prefix}123456789");
            let rate = get_eu_vat_rate_on(country, at).expect("every member state is dated");

            // 1. Verified cross-border business: reverse charge.
            if country != "EE" {
                let evidence = evidence_for(country, &vat);
                let verified =
                    quote_list_price(list_net, country, true, Some(&vat), Some(&evidence), at);
                assert_eq!(
                    verified.net_cents, list_net,
                    "{country}: net is the list price"
                );
                assert_eq!(verified.vat_cents, 0, "{country}: reverse charge is 0 %");
                assert_eq!(
                    verified.gross_cents, list_net,
                    "{country}: charge is the list price"
                );
                assert!(
                    verified.reverse_charge,
                    "{country}: notation is reverse charge"
                );
            }

            // 2. Unverified business: list + destination VAT.
            let unverified = quote_list_price(list_net, country, true, Some(&vat), None, at);
            assert_eq!(
                unverified.net_cents, list_net,
                "{country}: net is the list price"
            );
            let expected_vat = vat_amount_half_up(list_net, rate);
            assert_eq!(
                unverified.vat_cents, expected_vat,
                "{country}: VAT added on top"
            );
            assert_eq!(
                unverified.gross_cents,
                list_net + expected_vat,
                "{country}: the invoice total is net + VAT"
            );
            assert!(
                !unverified.reverse_charge,
                "{country}: unverified never reverse charges"
            );

            // 3. Consumer, Option B fallback (no owner-set gross card): the
            // same list + destination VAT, shown as ONE total.
            let consumer = quote_list_price(list_net, country, false, None, None, at);
            assert_eq!(
                consumer.net_cents, list_net,
                "{country}: consumer net is the list price"
            );
            assert_eq!(
                consumer.vat_cents, expected_vat,
                "{country}: the consumer total uses the destination rate"
            );
            assert_eq!(
                consumer.gross_cents,
                consumer.net_cents + consumer.vat_cents,
                "{country}: the displayed total is exactly net + VAT"
            );

            // 4. Consumer, Option A (owner-set gross): the SAME headline is
            // charged in every country, VAT extracted gross-first, and the
            // invoice split reconciles to the charge exactly.
            let consumer_gross = 2_480_i64;
            let option_a = billing_common::vat_rates::quote_purchase(
                list_net,
                Some(consumer_gross),
                country,
                false,
                None,
                None,
                at,
            );
            assert_eq!(
                option_a.gross_cents, consumer_gross,
                "{country}: the consumer headline is the charged gross"
            );
            assert_eq!(
                option_a.net_cents + option_a.vat_cents,
                consumer_gross,
                "{country}: Option A invoice net + VAT reconciles to the gross"
            );
            let inclusive =
                billing_common::vat_rates::vat_amount_inclusive_half_up(consumer_gross, rate);
            assert_eq!(
                option_a.vat_cents, inclusive,
                "{country}: Option A VAT is extracted gross-first at the destination rate"
            );

            // 5. Price-leakage guard: a self-declared business WITHOUT a
            // valid VAT number never gets the zero-rated net — it pays
            // net + destination VAT exactly like an unverified business.
            let unverified_business = quote_list_price(list_net, country, true, None, None, at);
            assert_eq!(
                unverified_business.gross_cents,
                list_net + expected_vat,
                "{country}: no VAT number means no reverse charge"
            );
            assert!(!unverified_business.reverse_charge);
        }

        // The brief's named examples.
        let ee = quote_list_price(list_net, "EE", true, Some("EE100591102"), None, at);
        assert_eq!(
            (ee.net_cents, ee.vat_cents, ee.gross_cents),
            (10_000, 2_400, 12_400)
        );
        let de_evidence = evidence_for("DE", "DE123456789");
        let de = quote_list_price(
            list_net,
            "DE",
            true,
            Some("DE123456789"),
            Some(&de_evidence),
            at,
        );
        assert_eq!(
            (de.net_cents, de.vat_cents, de.gross_cents),
            (10_000, 0, 10_000)
        );
        assert!(de.reverse_charge);

        // Non-EU: no VAT, the list price, and NOT a reverse charge.
        let swiss = quote_list_price(list_net, "CH", true, None, None, at);
        assert_eq!(
            (
                swiss.net_cents,
                swiss.vat_cents,
                swiss.gross_cents,
                swiss.reverse_charge
            ),
            (10_000, 0, 10_000, false)
        );
        assert!(!is_eu_country("CH"));
    }

    #[test]
    fn only_a_business_claiming_intra_eu_vat_needs_vies() {
        assert!(requires_vies_consultation(&declaration(
            true,
            "DE",
            Some("DE123456789")
        )));
        // Estonia is local: no reverse charge, no consultation.
        assert!(!requires_vies_consultation(&declaration(
            true,
            "EE",
            Some("EE100591102")
        )));
        // Non-EU: no VAT, no reverse charge.
        assert!(!requires_vies_consultation(&declaration(
            true,
            "CH",
            Some("CHE123456789")
        )));
        // Consumers never consult.
        assert!(!requires_vies_consultation(&declaration(
            false,
            "DE",
            Some("DE123456789")
        )));
        // A structurally invalid number cannot support a reverse charge.
        assert!(!requires_vies_consultation(&declaration(
            true,
            "DE",
            Some("nonsense")
        )));
    }
}
