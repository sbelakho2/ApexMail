pub mod leads {
    pub fn source_icon(name: &str) -> &'static str {
        match name.to_lowercase().as_str() {
            "linkedin" => "🔗",
            "website" => "🌐",
            "referral" => "👥",
            "conference" => "🎤",
            "cold_outreach" | "cold outreach" => "📧",
            _ => "📋",
        }
    }

    #[cfg(test)]
    mod tests {
        use super::source_icon;

        #[test]
        fn source_icon_maps_known_lead_sources() {
            assert_eq!(source_icon("LinkedIn"), "🔗");
            assert_eq!(source_icon("cold outreach"), "📧");
            assert_eq!(source_icon("cold_outreach"), "📧");
        }

        #[test]
        fn source_icon_uses_default_for_unknown_sources() {
            assert_eq!(source_icon("partner import"), "📋");
        }
    }
}
