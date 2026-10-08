//! Gmail Annotations – schema.org JSON‑LD for promotion cards & deals.
//!
//! # Wiring (where the effect actually happens)
//!
//! `GmailAnnotationsService::generate_annotations` produces the
//! `<script type="application/ld+json">…</script>` block. The live
//! injection point is `worker-processors`' `prepare_email` (see
//! `crates/worker-processors/src/email/processor.rs`): when the queue
//! row's server-side `metadata.gmail_annotations` object is present, the
//! generated block is inserted into the message HTML `<head>` before the
//! message is handed to any transport. The documented campaign API
//! (`docs/security/advanced-analytics.md`) feeds that metadata field; a
//! configuration that fails validation is logged and never blocks the
//! send.
//!
//! The deserialization shape below accepts the DOCUMENTED payload
//! (camelCase, `organization` as a `{name,…}` object, `deal` with
//! `discountDescription`/`availabilityEnds`) as well as the legacy
//! snake_case form.

use serde::{Deserialize, Serialize};

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PromotionCardProduct {
    pub name: String,
    #[serde(alias = "image_url")]
    pub image_url: String,
    pub price: f64,
    pub currency: String,
    pub url: String,
    pub discount: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DealBadge {
    #[serde(alias = "discount_code")]
    pub discount_code: Option<String>,
    /// The documented API spelling is `discountDescription`; plain
    /// `description` is accepted for callers built against the internal
    /// field name.
    #[serde(alias = "discountDescription")]
    pub description: String,
    #[serde(alias = "start_date")]
    pub start_date: Option<String>,
    /// The documented API spelling is `availabilityEnds`.
    #[serde(alias = "availabilityEnds", alias = "end_date")]
    pub end_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailAnnotationConfig {
    #[serde(alias = "logo_url")]
    pub logo_url: Option<String>,
    #[serde(alias = "featured_image_url")]
    pub featured_image_url: Option<String>,
    pub deal: Option<DealBadge>,
    #[serde(default)]
    pub products: Vec<PromotionCardProduct>,
    #[serde(alias = "go_to_action")]
    pub go_to_action: Option<GoToAction>,
    /// Accepts both the documented `{"name": "…"}` object and a bare string.
    #[serde(default, deserialize_with = "deserialize_organization")]
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GoToAction {
    pub name: String,
    pub url: String,
    pub description: Option<String>,
}

/// Deserialize `organization` from either a string or the documented
/// `{"name": …}` object (other keys such as `url`/`logoUrl` are ignored).
fn deserialize_organization<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Organization {
        Name(String),
        Object { name: Option<String> },
    }

    Ok(match Option::<Organization>::deserialize(deserializer)? {
        None => None,
        Some(Organization::Name(name)) => Some(name),
        Some(Organization::Object { name }) => name,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailAnnotationResult {
    pub json_ld: String,
    pub html: String,
    pub validation: ValidationResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageRecommendations {
    pub logo: ImageSpec,
    pub featured: ImageSpec,
    pub product: ImageSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSpec {
    pub min_width: u32,
    pub min_height: u32,
    pub aspect_ratio: String,
    pub format: String,
}

// ── service ────────────────────────────────────────────────────────────────────

pub struct GmailAnnotationsService;

impl Default for GmailAnnotationsService {
    fn default() -> Self {
        Self::new()
    }
}

impl GmailAnnotationsService {
    pub fn new() -> Self {
        Self
    }

    /// Generate JSON‑LD + HTML annotations for a Gmail promotion tab email.
    pub fn generate_annotations(&self, config: &GmailAnnotationConfig) -> GmailAnnotationResult {
        let validation = self.validate_config(config);
        let json_ld = self.build_json_ld(config);
        let html = self.build_html(&json_ld);

        GmailAnnotationResult {
            json_ld,
            html,
            validation,
        }
    }

    /// Validate annotation config.
    pub fn validate_config(&self, config: &GmailAnnotationConfig) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        if config.products.is_empty() && config.deal.is_none() && config.go_to_action.is_none() {
            errors.push("At least one of: products, deal, or go_to_action is required".into());
        }

        for (i, product) in config.products.iter().enumerate() {
            if product.name.is_empty() {
                errors.push(format!("Product {i}: name is required"));
            }
            if product.image_url.is_empty() {
                warnings.push(format!("Product {i}: image_url is recommended"));
            }
            if product.price < 0.0 {
                errors.push(format!("Product {i}: price must be non-negative"));
            }
            if product.url.is_empty() {
                errors.push(format!("Product {i}: url is required"));
            }
        }

        if let Some(ref deal) = config.deal {
            if deal.description.is_empty() {
                errors.push("Deal description is required".into());
            }
        }

        if let Some(ref logo) = config.logo_url {
            if !logo.starts_with("https://") {
                warnings.push("Logo URL should use HTTPS".into());
            }
        }

        if config.products.len() > 10 {
            warnings.push("Gmail supports a maximum of 10 products in a carousel".into());
        }

        ValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Generate a "preview badge" HTML snippet for the deal.
    /// #153:HTML-escapes user-provided text to prevent XSS.
    pub fn generate_preview_badge(&self, deal: &DealBadge) -> String {
        let mut badge = String::from("<span class=\"gmail-promo-badge\">");
        badge.push_str(&html_escape(&deal.description));
        if let Some(ref code) = deal.discount_code {
            badge.push_str(&format!(" \u{2013} Code: {}", html_escape(code)));
        }
        badge.push_str("</span>");
        badge
    }

    /// Get recommended image sizes.
    pub fn get_image_recommendations(&self) -> ImageRecommendations {
        ImageRecommendations {
            logo: ImageSpec {
                min_width: 48,
                min_height: 48,
                aspect_ratio: "1:1".into(),
                format: "PNG or SVG".into(),
            },
            featured: ImageSpec {
                min_width: 538,
                min_height: 138,
                aspect_ratio: "3.9:1".into(),
                format: "PNG or JPEG".into(),
            },
            product: ImageSpec {
                min_width: 116,
                min_height: 116,
                aspect_ratio: "1:1".into(),
                format: "PNG or JPEG".into(),
            },
        }
    }

    /// Generate a complete promotion email annotation (convenience wrapper).
    pub fn generate_promotion_email_annotations(
        &self,
        config: &GmailAnnotationConfig,
    ) -> GmailAnnotationResult {
        self.generate_annotations(config)
    }

    // ── internal ───────────────────────────────────────────────────────────────

    fn build_json_ld(&self, config: &GmailAnnotationConfig) -> String {
        let mut json = serde_json::json!({
            "@context": "http://schema.org",
            "@type": "PromotionCard",
        });

        if let Some(ref org) = config.organization {
            json["provider"] = serde_json::json!({
                "@type": "Organization",
                "name": org,
            });
        }

        if let Some(ref logo) = config.logo_url {
            json["image"] = serde_json::json!(logo);
        } else if let Some(ref featured) = config.featured_image_url {
            // The documented "featured image" is the promotion preview image
            // when no brand logo is configured.
            json["image"] = serde_json::json!(featured);
        }

        // Deal
        if let Some(ref deal) = config.deal {
            let mut offer = serde_json::json!({
                "@type": "Offer",
                "description": deal.description,
            });
            if let Some(ref code) = deal.discount_code {
                offer["discountCode"] = serde_json::json!(code);
            }
            if let Some(ref start) = deal.start_date {
                offer["availabilityStarts"] = serde_json::json!(start);
            }
            if let Some(ref end) = deal.end_date {
                offer["availabilityEnds"] = serde_json::json!(end);
            }
            json["offers"] = serde_json::json!([offer]);
        }

        // Products carousel
        if !config.products.is_empty() {
            let items: Vec<serde_json::Value> = config
                .products
                .iter()
                .map(|p| {
                    let mut item = serde_json::json!({
                        "@type": "Product",
                        "name": p.name,
                        "url": p.url,
                        "offers": {
                            "@type": "Offer",
                            "price": p.price,
                            "priceCurrency": p.currency,
                        },
                    });
                    if !p.image_url.is_empty() {
                        item["image"] = serde_json::json!(p.image_url);
                    }
                    if let Some(disc) = p.discount {
                        item["offers"]["discount"] = serde_json::json!(disc);
                    }
                    item
                })
                .collect();
            json["itemListElement"] = serde_json::json!(items);
        }

        // GoToAction
        if let Some(ref action) = config.go_to_action {
            let mut act = serde_json::json!({
                "@type": "ViewAction",
                "name": action.name,
                "url": action.url,
            });
            if let Some(ref desc) = action.description {
                act["description"] = serde_json::json!(desc);
            }
            json["potentialAction"] = act;
        }

        // E-5:script-safe serialization. serde_json does NOT escape `<`, `>`,
        // `&`, U+2028 or U+2029 inside string literals, but this JSON is
        // embedded in a <script> block — an org name like
        // `</script><img src=x onerror=alert(1)>` used to break out of the
        // script context (XSS). Post-process the serialized JSON so those
        // characters are always emitted as JSON unicode escapes.
        match serde_json::to_string_pretty(&json) {
            Ok(serialized) => escape_json_for_script(&serialized),
            // #154:Log an error instead of silently returning empty on serialization failure
            Err(e) => {
                tracing::error!(error = %e, "Failed to serialize Gmail annotation JSON-LD");
                String::new()
            }
        }
    }

    fn build_html(&self, json_ld: &str) -> String {
        format!("<script type=\"application/ld+json\">\n{json_ld}\n</script>")
    }
}

/// E-5:escape a serialized JSON document for safe embedding inside an HTML
/// `<script>` element. Replacements are JSON-legal unicode escapes (inside
/// string literals) and never appear in JSON structure:
///   `<` → `\u003c`, `>` → `\u003e`, `&` → `\u0026`,
///   U+2028 → `\u2028`, U+2029 → `\u2029`
/// The escape texts themselves contain none of the replaced characters, so a
/// single left-to-right pass is confluent (no double-escaping).
fn escape_json_for_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for ch in json.chars() {
        match ch {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}

/// #153:HTML-escape user-provided text to prevent XSS in badge output.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Factory function.
pub fn create_gmail_annotations_service() -> GmailAnnotationsService {
    GmailAnnotationsService::new()
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload shape published in `docs/security/advanced-analytics.md`
    /// (camelCase, `organization` as an object, `deal` with
    /// `discountDescription`/`availabilityEnds`) must deserialize into the
    /// config the injection point consumes. Previously the struct only
    /// accepted snake_case, so the documented API payload could never be
    /// turned into annotations.
    #[test]
    fn documented_camel_case_payload_deserializes() {
        let payload = serde_json::json!({
            "organization": { "name": "Acme Store", "url": "https://acme.com" },
            "featuredImageUrl": "https://acme.com/promo-banner.png",
            "deal": {
                "discountDescription": "25% off everything",
                "discountCode": "SAVE25",
                "availabilityEnds": "2025-02-28T00:00:00Z"
            },
            "goToAction": { "name": "Shop Now", "url": "https://acme.com/sale" },
            "products": [{
                "name": "Premium Widget",
                "imageUrl": "https://acme.com/widget.png",
                "price": 49.99,
                "currency": "USD",
                "url": "https://acme.com/widget"
            }]
        });
        let config: GmailAnnotationConfig =
            serde_json::from_value(payload).expect("documented payload must deserialize");

        assert_eq!(config.organization.as_deref(), Some("Acme Store"));
        assert_eq!(
            config.featured_image_url.as_deref(),
            Some("https://acme.com/promo-banner.png")
        );
        assert_eq!(config.products.len(), 1);
        assert_eq!(config.products[0].image_url, "https://acme.com/widget.png");
        assert_eq!(
            config.deal.as_ref().unwrap().description,
            "25% off everything"
        );
        assert_eq!(
            config.deal.as_ref().unwrap().discount_code.as_deref(),
            Some("SAVE25")
        );
        assert_eq!(
            config.deal.as_ref().unwrap().end_date.as_deref(),
            Some("2025-02-28T00:00:00Z")
        );

        let result = GmailAnnotationsService::new().generate_annotations(&config);
        assert!(result.validation.valid, "{:?}", result.validation.errors);
        let parsed: serde_json::Value =
            serde_json::from_str(&result.json_ld).expect("valid JSON-LD");
        assert_eq!(parsed["image"], "https://acme.com/promo-banner.png");
        assert!(parsed.get("discountCode").is_none());
        assert_eq!(parsed["offers"][0]["discountCode"], "SAVE25");
    }

    /// The legacy snake_case shape keeps working (callers built against the
    /// internal field names).
    #[test]
    fn legacy_snake_case_payload_still_deserializes() {
        let payload = serde_json::json!({
            "logo_url": "https://example.com/logo.png",
            "organization": "Example Corp",
            "products": []
        });
        let config: GmailAnnotationConfig = serde_json::from_value(payload).unwrap();
        assert_eq!(
            config.logo_url.as_deref(),
            Some("https://example.com/logo.png")
        );
        assert_eq!(config.organization.as_deref(), Some("Example Corp"));
    }

    #[test]
    fn test_generate_annotations_with_deal() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: Some("https://example.com/logo.png".into()),
            featured_image_url: None,
            deal: Some(DealBadge {
                discount_code: Some("SAVE20".into()),
                description: "20% off everything".into(),
                start_date: None,
                end_date: None,
            }),
            products: vec![],
            go_to_action: Some(GoToAction {
                name: "Shop Now".into(),
                url: "https://example.com/shop".into(),
                description: None,
            }),
            organization: Some("Example Corp".into()),
        };

        let result = svc.generate_annotations(&config);
        assert!(result.validation.valid);
        assert!(result.json_ld.contains("PromotionCard"));
        assert!(result.json_ld.contains("SAVE20"));
        assert!(result.html.contains("application/ld+json"));
    }

    #[test]
    fn test_generate_annotations_with_products() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: None,
            featured_image_url: None,
            deal: None,
            products: vec![
                PromotionCardProduct {
                    name: "Widget".into(),
                    image_url: "https://example.com/widget.jpg".into(),
                    price: 9.99,
                    currency: "USD".into(),
                    url: "https://example.com/widget".into(),
                    discount: Some(0.1),
                },
                PromotionCardProduct {
                    name: "Gadget".into(),
                    image_url: "https://example.com/gadget.jpg".into(),
                    price: 19.99,
                    currency: "USD".into(),
                    url: "https://example.com/gadget".into(),
                    discount: None,
                },
            ],
            go_to_action: None,
            organization: None,
        };

        let result = svc.generate_annotations(&config);
        assert!(result.validation.valid);
        assert!(result.json_ld.contains("Widget"));
        assert!(result.json_ld.contains("Gadget"));
    }

    #[test]
    fn test_validate_config_empty() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: None,
            featured_image_url: None,
            deal: None,
            products: vec![],
            go_to_action: None,
            organization: None,
        };
        let result = svc.validate_config(&config);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_validate_config_invalid_product() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: None,
            featured_image_url: None,
            deal: None,
            products: vec![PromotionCardProduct {
                name: String::new(),
                image_url: String::new(),
                price: -5.0,
                currency: "USD".into(),
                url: String::new(),
                discount: None,
            }],
            go_to_action: None,
            organization: None,
        };
        let result = svc.validate_config(&config);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("name")));
        assert!(result.errors.iter().any(|e| e.contains("price")));
    }

    #[test]
    fn test_generate_preview_badge() {
        let svc = GmailAnnotationsService::new();
        let deal = DealBadge {
            discount_code: Some("SUMMER50".into()),
            description: "50% off summer sale".into(),
            start_date: None,
            end_date: None,
        };
        let badge = svc.generate_preview_badge(&deal);
        assert!(badge.contains("50% off summer sale"));
        assert!(badge.contains("SUMMER50"));
    }

    #[test]
    fn test_image_recommendations() {
        let svc = GmailAnnotationsService::new();
        let recs = svc.get_image_recommendations();
        assert_eq!(recs.logo.min_width, 48);
        assert_eq!(recs.featured.min_width, 538);
        assert_eq!(recs.product.min_width, 116);
    }

    // ── E-5: </script> breakout in the JSON-LD block ────────────────────────

    #[test]
    fn script_breakout_payload_cannot_leave_the_script_context() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: None,
            featured_image_url: None,
            deal: Some(DealBadge {
                discount_code: None,
                description: "20% off".into(),
                start_date: None,
                end_date: None,
            }),
            products: vec![],
            go_to_action: None,
            organization: Some("</script><img src=x onerror=alert(1)>".into()),
        };

        let result = svc.generate_annotations(&config);
        // No literal `</script>` may appear inside the JSON-LD payload.
        assert!(
            !result.json_ld.contains("</script>"),
            "JSON-LD must not contain a literal </script>: {}",
            result.json_ld
        );
        // The dangerous characters are unicode-escaped instead.
        assert!(result.json_ld.contains("\\u003c"));
        assert!(result.json_ld.contains("\\u003e"));
        // The surrounding HTML still has exactly the two structural tags.
        assert_eq!(result.html.matches("</script>").count(), 1);
        // And the payload still parses as JSON after unescaping.
        let parsed: serde_json::Value =
            serde_json::from_str(&result.json_ld).expect("escaped JSON-LD must remain valid JSON");
        assert_eq!(
            parsed["provider"]["name"],
            "</script><img src=x onerror=alert(1)>"
        );
    }

    #[test]
    fn json_ld_escapes_ampersand_and_line_separators() {
        // `&` breaks out of some HTML parser contexts; U+2028/U+2029 are
        // valid JSON but terminate JS string literals in older engines.
        let escaped = escape_json_for_script("a & b\u{2028}\u{2029} <c>");
        assert_eq!(escaped, "a \\u0026 b\\u2028\\u2029 \\u003cc\\u003e");
        // Structural JSON characters are untouched.
        assert_eq!(
            escape_json_for_script(r#"{"k": [1, 2]}"#),
            r#"{"k": [1, 2]}"#
        );
    }

    #[test]
    fn preview_badge_escapes_xss_payload() {
        let svc = GmailAnnotationsService::new();
        let deal = DealBadge {
            discount_code: Some("<script>alert(1)</script>".into()),
            description: "<b>bold</b> & scary".into(),
            start_date: None,
            end_date: None,
        };
        let badge = svc.generate_preview_badge(&deal);
        assert!(
            !badge.contains("<script>"),
            "badge must escape script tags: {badge}"
        );
        assert!(!badge.contains("<b>"), "badge must escape HTML: {badge}");
        assert!(badge.contains("&lt;b&gt;bold&lt;/b&gt; &amp; scary"));
        assert!(badge.contains("&lt;script&gt;"));
    }

    #[test]
    fn validation_requires_deal_copy_and_warns_on_http_logos_and_oversized_carousels() {
        let svc = GmailAnnotationsService::new();
        let products: Vec<PromotionCardProduct> = (0..11)
            .map(|i| PromotionCardProduct {
                name: format!("Widget {i}"),
                image_url: format!("https://example.com/{i}.jpg"),
                price: 1.0 + i as f64,
                currency: "USD".into(),
                url: format!("https://example.com/{i}"),
                discount: None,
            })
            .collect();
        let config = GmailAnnotationConfig {
            logo_url: Some("http://insecure.example/logo.png".into()),
            featured_image_url: None,
            deal: Some(DealBadge {
                discount_code: None,
                description: String::new(),
                start_date: None,
                end_date: None,
            }),
            products,
            go_to_action: None,
            organization: None,
        };
        let validation = svc.validate_config(&config);
        assert!(
            !validation.valid,
            "an empty deal description is a hard error: {:?}",
            validation.errors
        );
        assert!(
            validation
                .errors
                .iter()
                .any(|e| e.contains("Deal description is required")),
            "{:?}",
            validation.errors
        );
        assert!(
            validation
                .warnings
                .iter()
                .any(|w| w.contains("should use HTTPS")),
            "a plaintext logo URL is warned about: {:?}",
            validation.warnings
        );
        assert!(
            validation
                .warnings
                .iter()
                .any(|w| w.contains("maximum of 10 products")),
            "an 11-product carousel is warned about: {:?}",
            validation.warnings
        );

        // The convenience wrapper produces the identical verdict.
        let wrapped = svc.generate_promotion_email_annotations(&config);
        assert_eq!(wrapped.validation.errors, validation.errors);
        assert_eq!(wrapped.validation.warnings, validation.warnings);
    }

    #[test]
    fn json_ld_carries_deal_code_dates_product_image_and_action_description() {
        let svc = GmailAnnotationsService::new();
        let config = GmailAnnotationConfig {
            logo_url: None,
            featured_image_url: None,
            deal: Some(DealBadge {
                discount_code: Some("SAVE5".into()),
                description: "5% off".into(),
                start_date: Some("2026-01-01".into()),
                end_date: Some("2026-02-01".into()),
            }),
            products: vec![PromotionCardProduct {
                name: "Widget".into(),
                image_url: "https://example.com/widget.jpg".into(),
                price: 9.99,
                currency: "USD".into(),
                url: "https://example.com/widget".into(),
                discount: Some(0.15),
            }],
            go_to_action: Some(GoToAction {
                name: "Shop".into(),
                url: "https://example.com/shop".into(),
                description: Some("Shop the deal".into()),
            }),
            organization: None,
        };
        let result = svc.generate_annotations(&config);
        let parsed: serde_json::Value =
            serde_json::from_str(&result.json_ld).expect("valid JSON-LD");
        let offer = &parsed["offers"][0];
        assert_eq!(offer["discountCode"], "SAVE5");
        assert_eq!(offer["availabilityStarts"], "2026-01-01");
        assert_eq!(offer["availabilityEnds"], "2026-02-01");
        let item = &parsed["itemListElement"][0];
        assert_eq!(item["image"], "https://example.com/widget.jpg");
        assert_eq!(item["offers"]["discount"], 0.15);
        assert_eq!(parsed["potentialAction"]["description"], "Shop the deal");
    }
}
