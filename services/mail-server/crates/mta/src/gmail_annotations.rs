//! Gmail Annotations – schema.org JSON‑LD for promotion cards & deals.

use serde::{Deserialize, Serialize};

// ── types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionCardProduct {
    pub name: String,
    pub image_url: String,
    pub price: f64,
    pub currency: String,
    pub url: String,
    pub discount: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DealBadge {
    pub discount_code: Option<String>,
    pub description: String,
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailAnnotationConfig {
    pub logo_url: Option<String>,
    pub featured_image_url: Option<String>,
    pub deal: Option<DealBadge>,
    pub products: Vec<PromotionCardProduct>,
    pub go_to_action: Option<GoToAction>,
    pub organization: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoToAction {
    pub name: String,
    pub url: String,
    pub description: Option<String>,
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
        let parsed: serde_json::Value = serde_json::from_str(&result.json_ld)
            .expect("escaped JSON-LD must remain valid JSON");
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
        assert_eq!(escape_json_for_script(r#"{"k": [1, 2]}"#), r#"{"k": [1, 2]}"#);
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
        assert!(!badge.contains("<script>"), "badge must escape script tags: {badge}");
        assert!(!badge.contains("<b>"), "badge must escape HTML: {badge}");
        assert!(badge.contains("&lt;b&gt;bold&lt;/b&gt; &amp; scary"));
        assert!(badge.contains("&lt;script&gt;"));
    }
}
