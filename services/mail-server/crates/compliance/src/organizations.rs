use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub billing_email: String,
    pub country: String,
    pub tax_id: Option<String>,
    pub website: Option<String>,
    pub consolidated_billing: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub suspended: bool,
    pub suspended_at: Option<DateTime<Utc>>,
    pub suspended_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub plan: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub name: String,
    pub avatar_url: Option<String>,
    pub two_factor_enabled: bool,
    pub two_factor_required: bool,
    pub recovery_codes: Vec<RecoveryCode>,
    pub active_sessions: Vec<ActiveSession>,
    pub login_notifications_enabled: bool,
    pub oauth_accounts: Vec<OAuthAccount>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    pub code_hash: String,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub provider: String,
    pub provider_user_id: String,
    pub linked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMembership {
    pub id: String,
    pub organization_id: String,
    pub user_id: String,
    pub role: OrganizationRole,
    pub custom_role_id: Option<String>,
    pub joined_at: DateTime<Utc>,
    pub invited_by: Option<String>,
    pub removed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceMembership {
    pub id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub role: WorkspaceRole,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Billing,
    Member,
    Custom,
}

impl OrganizationRole {
    pub fn can_manage_billing(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin | Self::Billing)
    }

    pub fn can_manage_organization(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_view_audit_logs(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn requires_2fa(&self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRole {
    Admin,
    Developer,
    Viewer,
}

impl WorkspaceRole {
    pub fn can_send(&self) -> bool {
        matches!(self, Self::Admin | Self::Developer)
    }

    pub fn can_manage_settings(&self) -> bool {
        matches!(self, Self::Admin)
    }

    pub fn can_view_activity(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRole {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<Permission>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    MessagesSend,
    MessagesRead,
    DomainsRead,
    DomainsWrite,
    EventsRead,
    WebhooksRead,
    WebhooksWrite,
    TemplatesRead,
    TemplatesWrite,
    SuppressionsRead,
    SuppressionsWrite,
    AnalyticsRead,
    ComplianceRead,
    ComplianceWrite,
    BillingRead,
    BillingWrite,
    OrganizationRead,
    OrganizationWrite,
    UsersRead,
    UsersWrite,
    SubaccountsRead,
    SubaccountsWrite,
    AuditLogsRead,
    SecuritySettingsWrite,
    ApiKeysWrite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subaccount {
    pub id: String,
    pub parent_organization_id: String,
    pub parent_workspace_id: Option<String>,
    pub name: String,
    pub quotas: SubaccountQuotas,
    pub api_key_limit: i32,
    pub smtp_credential_limit: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub suspended: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubaccountQuotas {
    pub max_daily_recipients: Option<i64>,
    pub max_monthly_recipients: Option<i64>,
    pub max_sending_domains: Option<i32>,
    pub max_webhook_endpoints: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainOwnership {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub subaccount_id: Option<String>,
    pub domain: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub verification_method: Option<VerificationMethod>,
    pub spf_status: Option<String>,
    pub dkim_status: Option<String>,
    pub dmarc_status: Option<String>,
    pub return_path_configured: bool,
    pub tracking_domain: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    DnsTxt,
    DnsCname,
    EmailCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPPoolOwnership {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub pool_name: String,
    pub pool_type: IPPoolType,
    pub ip_addresses: Vec<String>,
    pub assigned_at: DateTime<Utc>,
    pub billing_started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IPPoolType {
    Shared,
    Dedicated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidatedBilling {
    pub organization_id: String,
    pub billing_contact: String,
    pub payment_method_id: Option<String>,
    pub billing_address: Option<BillingAddress>,
    pub tax_exempt: bool,
    pub tax_exempt_certificate_url: Option<String>,
    pub annual_commitment: bool,
    pub annual_commitment_start: Option<DateTime<Utc>>,
    pub annual_commitment_end: Option<DateTime<Utc>>,
    pub billing_cycle: BillingCycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BillingCycle {
    Monthly,
    Annual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingAddress {
    pub line1: String,
    pub line2: Option<String>,
    pub city: String,
    pub postal_code: String,
    pub country: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationAuditLog {
    pub id: String,
    pub organization_id: String,
    pub actor_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub changes: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub organization_id: String,
    pub mandatory_email_verification: bool,
    pub two_factor_required_for_admins: bool,
    pub two_factor_available_for_all: bool,
    pub session_max_duration_hours: Option<u32>,
    pub ip_allowlist: Vec<String>,
    pub support_access_enabled: bool,
    pub support_access_audit_enabled: bool,
    pub sso_enabled: bool,
    pub sso_provider: Option<SSOProvider>,
    pub scim_enabled: bool,
    pub scim_endpoint: Option<String>,
    pub sensitive_action_reauth_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOProvider {
    pub provider_type: SSOProviderType,
    pub entity_id: String,
    pub sso_url: String,
    pub certificate_fingerprint: String,
    pub configured_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SSOProviderType {
    SAML,
    OIDC,
}

#[derive(Debug, Clone, Default)]
pub struct OrganizationRegistry {
    organizations: HashMap<String, Organization>,
    membership: Vec<OrganizationMembership>,
    workspaces: Vec<Workspace>,
    workspace_membership: Vec<WorkspaceMembership>,
    subaccounts: Vec<Subaccount>,
}

impl OrganizationRegistry {
    pub fn new() -> Self {
        Self {
            organizations: HashMap::new(),
            membership: Vec::new(),
            workspaces: Vec::new(),
            workspace_membership: Vec::new(),
            subaccounts: Vec::new(),
        }
    }

    pub fn add_organization(&mut self, org: Organization) {
        self.organizations.insert(org.id.clone(), org);
    }

    pub fn get_organization(&self, id: &str) -> Option<&Organization> {
        self.organizations.get(id)
    }

    pub fn add_membership(&mut self, m: OrganizationMembership) {
        self.membership.push(m);
    }

    pub fn get_user_organizations(&self, user_id: &str) -> Vec<&Organization> {
        self.membership
            .iter()
            .filter(|m| m.user_id == user_id && m.removed_at.is_none())
            .filter_map(|m| self.organizations.get(&m.organization_id))
            .collect()
    }

    pub fn get_organization_members(&self, org_id: &str) -> Vec<&OrganizationMembership> {
        self.membership
            .iter()
            .filter(|m| m.organization_id == org_id && m.removed_at.is_none())
            .collect()
    }

    pub fn get_user_role(&self, org_id: &str, user_id: &str) -> Option<OrganizationRole> {
        self.membership
            .iter()
            .find(|m| m.organization_id == org_id && m.user_id == user_id && m.removed_at.is_none())
            .map(|m| m.role)
    }

    pub fn add_workspace(&mut self, ws: Workspace) {
        self.workspaces.push(ws);
    }

    pub fn get_organization_workspaces(&self, org_id: &str) -> Vec<&Workspace> {
        self.workspaces
            .iter()
            .filter(|w| w.organization_id == org_id)
            .collect()
    }

    pub fn add_subaccount(&mut self, sub: Subaccount) {
        self.subaccounts.push(sub);
    }

    pub fn get_organization_subaccounts(&self, org_id: &str) -> Vec<&Subaccount> {
        self.subaccounts
            .iter()
            .filter(|s| s.parent_organization_id == org_id)
            .collect()
    }

    pub fn remove_user_from_organization(&mut self, org_id: &str, user_id: &str) -> bool {
        if let Some(m) = self.membership.iter_mut().find(|m| {
            m.organization_id == org_id && m.user_id == user_id && m.removed_at.is_none()
        }) {
            m.removed_at = Some(Utc::now());
            true
        } else {
            false
        }
    }

    pub fn is_user_in_organization(&self, org_id: &str, user_id: &str) -> bool {
        self.membership
            .iter()
            .any(|m| m.organization_id == org_id && m.user_id == user_id && m.removed_at.is_none())
    }

    pub fn total_subaccount_count(&self, org_id: &str) -> usize {
        self.subaccounts
            .iter()
            .filter(|s| s.parent_organization_id == org_id)
            .count()
    }

    pub fn total_domain_count(&self, _org_id: &str) -> usize {
        0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationCreatedEvent {
    pub organization_id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRemovedEvent {
    pub organization_id: String,
    pub user_id: String,
    pub removed_by: String,
    pub sessions_revoked: usize,
    pub api_keys_revoked: usize,
    pub removed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivilegedActionEvent {
    pub organization_id: String,
    pub user_id: String,
    pub action: String,
    pub target_resource: String,
    pub target_id: String,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_org() -> Organization {
        Organization {
            id: "org_001".into(),
            name: "Test Corp".into(),
            billing_email: "billing@testcorp.com".into(),
            country: "EE".into(),
            tax_id: Some("EE102951727".into()),
            website: Some("https://testcorp.com".into()),
            consolidated_billing: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            suspended: false,
            suspended_at: None,
            suspended_reason: None,
        }
    }

    #[test]
    fn test_org_roles_permissions() {
        assert!(OrganizationRole::Owner.can_manage_billing());
        assert!(OrganizationRole::Admin.can_manage_billing());
        assert!(OrganizationRole::Billing.can_manage_billing());
        assert!(!OrganizationRole::Member.can_manage_billing());

        assert!(OrganizationRole::Owner.can_manage_organization());
        assert!(OrganizationRole::Admin.can_manage_organization());
        assert!(!OrganizationRole::Member.can_manage_organization());

        assert!(OrganizationRole::Owner.requires_2fa());
        assert!(OrganizationRole::Admin.requires_2fa());
        assert!(!OrganizationRole::Member.requires_2fa());
    }

    #[test]
    fn test_workspace_roles() {
        assert!(WorkspaceRole::Admin.can_send());
        assert!(WorkspaceRole::Developer.can_send());
        assert!(!WorkspaceRole::Viewer.can_send());

        assert!(WorkspaceRole::Admin.can_manage_settings());
        assert!(!WorkspaceRole::Developer.can_manage_settings());
    }

    #[test]
    fn test_registry_add_and_lookup() {
        let mut registry = OrganizationRegistry::new();
        let org = sample_org();
        registry.add_organization(org);

        assert!(registry.get_organization("org_001").is_some());
        assert!(registry.get_organization("nonexistent").is_none());
    }

    #[test]
    fn test_user_organization_membership() {
        let mut registry = OrganizationRegistry::new();
        registry.add_organization(sample_org());
        registry.add_organization(Organization {
            id: "org_002".into(),
            ..sample_org()
        });

        registry.add_membership(OrganizationMembership {
            id: "mem_001".into(),
            organization_id: "org_001".into(),
            user_id: "user_001".into(),
            role: OrganizationRole::Admin,
            custom_role_id: None,
            joined_at: Utc::now(),
            invited_by: None,
            removed_at: None,
        });

        let orgs = registry.get_user_organizations("user_001");
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0].id, "org_001");

        let role = registry.get_user_role("org_001", "user_001");
        assert_eq!(role, Some(OrganizationRole::Admin));
    }

    #[test]
    fn test_remove_user_from_organization() {
        let mut registry = OrganizationRegistry::new();
        registry.add_organization(sample_org());
        registry.add_membership(OrganizationMembership {
            id: "mem_001".into(),
            organization_id: "org_001".into(),
            user_id: "user_001".into(),
            role: OrganizationRole::Member,
            custom_role_id: None,
            joined_at: Utc::now(),
            invited_by: None,
            removed_at: None,
        });

        assert!(registry.is_user_in_organization("org_001", "user_001"));
        assert!(registry.remove_user_from_organization("org_001", "user_001"));
        assert!(!registry.is_user_in_organization("org_001", "user_001"));
    }

    #[test]
    fn test_subaccount_scope() {
        let mut registry = OrganizationRegistry::new();
        registry.add_organization(sample_org());
        registry.add_subaccount(Subaccount {
            id: "sub_001".into(),
            parent_organization_id: "org_001".into(),
            parent_workspace_id: None,
            name: "Dev Team".into(),
            quotas: SubaccountQuotas {
                max_daily_recipients: Some(1000),
                max_monthly_recipients: Some(10000),
                max_sending_domains: Some(1),
                max_webhook_endpoints: Some(3),
            },
            api_key_limit: 5,
            smtp_credential_limit: 3,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            suspended: false,
        });

        assert_eq!(registry.get_organization_subaccounts("org_001").len(), 1);
        assert_eq!(registry.total_subaccount_count("org_001"), 1);
    }

    #[test]
    fn test_workspace_creation() {
        let mut registry = OrganizationRegistry::new();
        registry.add_organization(sample_org());
        registry.add_workspace(Workspace {
            id: "ws_001".into(),
            organization_id: "org_001".into(),
            name: "Default".into(),
            plan: "developer".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            is_default: true,
        });

        let workspaces = registry.get_organization_workspaces("org_001");
        assert_eq!(workspaces.len(), 1);
        assert!(workspaces[0].is_default);
    }

    #[test]
    fn test_security_settings_defaults() {
        let settings = SecuritySettings {
            organization_id: "org_001".into(),
            mandatory_email_verification: true,
            two_factor_required_for_admins: true,
            two_factor_available_for_all: true,
            session_max_duration_hours: Some(24),
            ip_allowlist: vec![],
            support_access_enabled: false,
            support_access_audit_enabled: true,
            sso_enabled: false,
            sso_provider: None,
            scim_enabled: false,
            scim_endpoint: None,
            sensitive_action_reauth_required: true,
        };

        assert!(settings.mandatory_email_verification);
        assert!(settings.two_factor_required_for_admins);
        assert!(settings.two_factor_available_for_all);
        assert!(settings.sensitive_action_reauth_required);
    }

    #[test]
    fn test_billing_cycle() {
        assert_eq!(
            serde_json::to_string(&BillingCycle::Monthly).unwrap(),
            r#""monthly""#
        );
        assert_eq!(
            serde_json::to_string(&BillingCycle::Annual).unwrap(),
            r#""annual""#
        );
    }

    #[test]
    fn test_permissions_serialization() {
        let perm = Permission::MessagesSend;
        let json = serde_json::to_string(&perm).unwrap();
        assert_eq!(json, r#""messages_send""#);
    }

    #[test]
    fn test_ip_pool_ownership() {
        let pool = IPPoolOwnership {
            id: "pool_001".into(),
            organization_id: "org_001".into(),
            workspace_id: None,
            pool_name: "dedicated-pool-1".into(),
            pool_type: IPPoolType::Dedicated,
            ip_addresses: vec!["192.0.2.1".into(), "192.0.2.2".into()],
            assigned_at: Utc::now(),
            billing_started_at: None,
        };

        assert_eq!(pool.ip_addresses.len(), 2);
        assert!(matches!(pool.pool_type, IPPoolType::Dedicated));
    }
}
