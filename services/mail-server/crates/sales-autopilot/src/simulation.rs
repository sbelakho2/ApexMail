#[cfg(test)]
mod simulation {
    use std::sync::Arc;

    use crate::crm::CrmService;
    use crate::enrichment::{EnrichmentService, MockEnrichmentProvider};
    use crate::types::{CampaignStatus, Lead, LeadStatus, SalesError};

    #[tokio::test]
    async fn simulation_full_pipeline() {
        let tenant_id = "sim_tenant_full";
        let enrichment = EnrichmentService::new(Arc::new(MockEnrichmentProvider));
        let crm = CrmService::new();

        let leads_data = vec![
            ("alice@acme.com", "Alice", "Acme Corp", "CTO", "product_hunt"),
            ("bob@beta.io", "Bob", "Beta Inc", "CEO", "manual"),
            ("carol@gamma.dev", "Carol", "Gamma Labs", "VP Eng", "referral"),
            ("dave@unknown.xyz", "Dave", "Unknown LLC", "Engineer", "website"),
        ];

        let mut created: Vec<Lead> = Vec::new();
        for (email, name, company, title, source) in &leads_data {
            let lead = crm.create_lead(
                tenant_id.to_string(), email.to_string(), name.to_string(),
                company.to_string(), title.to_string(), source.to_string(),
            );
            let score = compute_score(&enrichment, email).await;
            let mut l = lead.clone();
            l.score = score;
            created.push(l);
        }
        assert_eq!(created.len(), 4);

        let all = crm.list_leads(tenant_id, None, None);
        assert_eq!(all.len(), 4);

        let found = crm.search_leads(tenant_id, "alice");
        assert_eq!(found.len(), 1);

        let product_hunt = crm.list_leads(tenant_id, None, Some("product_hunt"));
        assert_eq!(product_hunt.len(), 1);

        for lead in &created {
            if lead.score >= 30 {
                // New → Qualified is a valid transition in the lifecycle
                // state machine.
                crm.update_lead_status(&lead.id, LeadStatus::Qualified, tenant_id).unwrap();
            }
        }

        let qualified = crm.list_leads(tenant_id, Some(LeadStatus::Qualified), None);
        assert!(qualified.len() > 0);

        // Cross-tenant isolation
        assert!(matches!(
            crm.get_lead(&created[0].id, "other_tenant"),
            Err(SalesError::LeadNotFound(_))
        ));

        // Scoring verification
        assert_eq!(CrmService::score_lead(1.0, 1.0, 1.0), 100);
        assert_eq!(CrmService::score_lead(0.0, 0.0, 0.0), 0);
        assert_eq!(CrmService::score_lead(0.5, 0.5, 0.5), 50);
    }

    #[test]
    fn simulation_scoring_formula() {
        assert_eq!(CrmService::score_lead(1.0, 0.0, 0.0), 40);
        assert_eq!(CrmService::score_lead(0.0, 1.0, 0.0), 30);
        assert_eq!(CrmService::score_lead(0.0, 0.0, 1.0), 30);
        assert_eq!(CrmService::score_lead(-1.0, -1.0, -1.0), 0);
        assert_eq!(CrmService::score_lead(100.0, 100.0, 100.0), 100);
        assert_eq!(CrmService::score_lead(f64::NAN, 0.5, 0.5), 0);
        assert_eq!(CrmService::score_lead(0.5, f64::NAN, 0.5), 0);
        assert_eq!(CrmService::score_lead(0.5, 0.5, f64::NAN), 0);
    }

    #[test]
    fn simulation_lead_status_transitions() {
        let crm = CrmService::new();
        let lead = crm.create_lead(
            "t".into(), "a@a.com".into(), "A".into(), "A Inc".into(),
            "CEO".into(), "manual".into(),
        );
        let updated = crm.update_lead_status(&lead.id, LeadStatus::Contacted, "t").unwrap();
        assert_eq!(updated.status, LeadStatus::Contacted);
        let updated = crm.update_lead_status(&lead.id, LeadStatus::Qualified, "t").unwrap();
        assert_eq!(updated.status, LeadStatus::Qualified);
        let updated = crm.update_lead_status(&lead.id, LeadStatus::Converted, "t").unwrap();
        assert_eq!(updated.status, LeadStatus::Converted);
    }

    #[tokio::test]
    async fn simulation_enrichment_deterministic() {
        let enrichment = EnrichmentService::mock();
        let c1 = enrichment.enrich_company("acme.com").await.unwrap();
        let c2 = enrichment.enrich_company("acme.com").await.unwrap();
        assert_eq!(c1.name, c2.name);
        assert_eq!(c1.industry, c2.industry);
    }

    #[test]
    fn simulation_campaign_status_display() {
        assert_eq!(CampaignStatus::Draft.to_string(), "draft");
        assert_eq!(CampaignStatus::Active.to_string(), "active");
        assert_eq!(CampaignStatus::Paused.to_string(), "paused");
        assert_eq!(CampaignStatus::Completed.to_string(), "completed");
    }

    async fn compute_score(enrichment: &EnrichmentService, email: &str) -> u8 {
        let company = enrichment.enrich_lead(email).await.ok();
        if let Some(ref c) = company {
            let cs = match c.size.as_str() {
                "1-10" => 0.2, "10-50" => 0.4, "50-200" => 0.6,
                "200-1000" => 0.8, "1000+" => 1.0, _ => 0.3,
            };
            let recency = 1.0;
            let engagement = if c.industry != "Unknown" { 0.5 } else { 0.3 };
            CrmService::score_lead_with_weights(engagement, cs, recency, 40, 30, 30)
        } else {
            10
        }
    }
}
