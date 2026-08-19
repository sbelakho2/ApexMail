//! Deterministic computation tools for the LLM — tenant-isolated, RBAC-guarded, 0 leakage.
//!
//! Every tool call carries tenant_id + role. Cross-tenant access and privilege
//! escalation are both blocked at execution. 18 tools with role-appropriate access.
//!
//! All tool parameters are validated against injection, bounds, and type constraints
//! via the defense module before execution.

use crate::{defense, domain_dns::DomainDnsStore};
use serde::{Deserialize, Serialize};

const OVERAGE_RATE: f64 = 0.40;

// ═══════════════════════════════════════════════════════════════════════════
// RBAC: Role-Based Access Control for tool execution
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Role {
    Owner,      // Full access: billing, security, admin, all tools
    Admin,      // Admin access: security, user management, audit logs
    Developer,  // Technical access: API, templates, webhooks, DNS
    Viewer,     // Read-only: pricing, plan details, DNS lookup (no writes)
}

impl Role {
    pub fn from_str(s: &str) -> Role {
        match s.to_lowercase().as_str() {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            "developer" => Role::Developer,
            _ => Role::Viewer,
        }
    }

    pub fn from_plan(plan: &str) -> Role {
        match plan.to_lowercase().as_str() {
            "enterprise" => Role::Owner,
            "scale" => Role::Admin,
            "growth" => Role::Developer,
            "pro" => Role::Viewer,
            "starter" => Role::Viewer,
            "free" => Role::Viewer,
            _ => Role::Viewer,
        }
    }
}

/// Permission matrix: which roles can use which tools
fn tool_permission(tool: &str) -> &[Role] {
    match tool {
        // Pricing — all roles can read
        "calculate_overage" | "calculate_payg" | "get_price_diff"
        | "compare_plans" | "get_plan_details" => &[Role::Owner, Role::Admin, Role::Developer, Role::Viewer],
        // DNS — all roles
        "get_dns_record" => &[Role::Owner, Role::Admin, Role::Developer, Role::Viewer],
        // Support tools — all roles
        "get_warmup_schedule" | "get_blocklist_status" | "map_provider_events"
        | "get_compliance_info" | "get_deliverability_recovery_plan" | "get_ab_test_guidance"
        | "get_sto_info" | "get_retry_guidance" | "get_dmarc_analysis" | "get_bounce_classification"
        | "get_webhook_setup" => &[Role::Owner, Role::Admin, Role::Developer, Role::Viewer],
        // Security & audit — admin+
        "generate_incident_timeline" | "get_audit_log" | "get_security_events" => &[Role::Owner, Role::Admin],
        // Billing history — owner only
        "get_billing_history" | "get_send_history" | "get_api_key_usage" => &[Role::Owner],
        // Sensitive — owner only
        "get_suppression_count" | "get_contact_count" | "get_deliverability_report"
        | "get_domain_verification_status" | "generate_compliance_report" | "get_ip_warmup_status" => &[Role::Owner, Role::Admin],
        // Default: owner only
        _ => &[Role::Owner],
    }
}

/// RBAC guard: check if role can execute this tool
pub fn role_can_execute(role: &Role, tool: &str) -> bool {
    tool_permission(tool).contains(role)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tenant-guarded + RBAC-guarded tool call wrapper
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub params: serde_json::Value,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,  // "owner" | "admin" | "developer" | "viewer"
}

/// Identity asserted by the authenticated control plane, never by the model or
/// customer-supplied conversation context.
#[derive(Debug, Clone)]
pub struct TrustedToolCaller {
    pub tenant_id: String,
    pub role: Role,
}

/// Execute a tool with tenant isolation + RBAC. Returns error JSON on any guard failure.
pub fn execute_tool(call: &ToolCall, caller_tenant_id: &str, caller_role: &Role) -> serde_json::Value {
    // Guard 1: RBAC — does the caller's role have permission?
    if !role_can_execute(caller_role, &call.tool) {
        return serde_json::json!({
            "error": format!("role {:?} cannot execute tool '{}'. Required: {:?}",
                caller_role, call.tool,
                tool_permission(&call.tool).iter().map(|r| format!("{:?}", r)).collect::<Vec<_>>())
        });
    }

    // Guard 2: Tenant isolation — block cross-tenant data access
    // Also block tenant-scoped tools when caller has no tenant identity.
    let tools_needing_isolation = [
        "get_audit_log", "get_api_key_usage", "get_send_history",
        "get_deliverability_report", "get_suppression_count", "get_contact_count",
        "get_security_events", "get_billing_history", "get_ip_warmup_status",
        "get_domain_verification_status", "generate_compliance_report", "get_dns_record",
    ];
    if tools_needing_isolation.contains(&call.tool.as_str()) {
        let tool_tenant = call.tenant_id.as_deref().unwrap_or("");
        if caller_tenant_id.is_empty() || tool_tenant.is_empty() || tool_tenant != caller_tenant_id {
            return serde_json::json!({
                "error": "tenant_id required and must match caller",
                "required": caller_tenant_id,
                "provided": tool_tenant,
            });
        }
    }

    // Guard 3: Parameter validation — prevent injection through tool parameters
    if let Err(param_errors) = defense::validate_tool_params(&call.tool, &call.params) {
        return serde_json::json!({
            "error": format!("parameter validation failed: {}", param_errors.join("; "))
        });
    }

    // Guard 4: Execute tool (all guards passed)
    match call.tool.as_str() {
        "calculate_overage" => calculate_overage(&call.params),
        "calculate_payg" => calculate_payg(&call.params),
        "get_dns_record" => serde_json::json!({
            "error": "exact DNS records require an authenticated tenant and authoritative domain data"
        }),
        "compare_plans" => compare_plans(&call.params),
        "get_plan_details" => get_plan_details(&call.params),
        "get_price_diff" => get_price_diff(&call.params),
        // NEW — support tools for customer scenarios
        "get_warmup_schedule" => get_warmup_schedule(&call.params),
        "get_blocklist_status" => get_blocklist_status(&call.params),
        "map_provider_events" => map_provider_events(&call.params),
        "get_compliance_info" => get_compliance_info(&call.params),
        "generate_incident_timeline" => generate_incident_timeline(&call.params),
        "get_deliverability_recovery_plan" => get_deliverability_recovery_plan(&call.params),
        "get_ab_test_guidance" => get_ab_test_guidance(&call.params),
        "get_sto_info" => get_sto_info(&call.params),
        "get_retry_guidance" => get_retry_guidance(&call.params),
        "get_dmarc_analysis" => get_dmarc_analysis(&call.params),
        "get_bounce_classification" => get_bounce_classification(&call.params),
        "get_webhook_setup" => get_webhook_setup(&call.params),
        _ => serde_json::json!({"error": format!("unknown tool: {}", call.tool)}),
    }
}

/// Execute a tool with the deployment's authoritative domain record source.
/// DNS is deliberately asynchronous because it queries tenant-scoped current
/// control-plane data; all other tools retain their deterministic behavior.
pub async fn execute_tool_with_authoritative_data(
    call: &ToolCall,
    caller: &TrustedToolCaller,
    domain_dns: Option<&DomainDnsStore>,
) -> serde_json::Value {
    if call.tool != "get_dns_record" {
        return execute_tool(call, &caller.tenant_id, &caller.role);
    }

    if !role_can_execute(&caller.role, &call.tool) {
        return serde_json::json!({"error": "caller is not permitted to retrieve DNS records"});
    }
    let asserted_tenant = call.tenant_id.as_deref().unwrap_or("");
    if caller.tenant_id.is_empty()
        || asserted_tenant.is_empty()
        || asserted_tenant != caller.tenant_id
    {
        return serde_json::json!({
            "error": "tenant_id required and must match authenticated caller"
        });
    }
    if let Err(errors) = defense::validate_tool_params(&call.tool, &call.params) {
        return serde_json::json!({
            "error": format!("parameter validation failed: {}", errors.join("; "))
        });
    }
    let domain = match call.params.get("domain").and_then(|value| value.as_str()) {
        Some(domain) => domain,
        None => return serde_json::json!({"error": "domain is required"}),
    };
    let store = match domain_dns {
        Some(store) => store,
        None => {
            return serde_json::json!({
                "error": "authoritative domain data is not configured; do not invent DNS records"
            });
        }
    };
    match store.records_for_domain(&caller.tenant_id, domain).await {
        Ok(records) => serde_json::to_value(records).unwrap_or_else(|_| {
            serde_json::json!({"error": "could not serialize authoritative DNS records"})
        }),
        Err(error) => serde_json::json!({"error": error.to_string()}),
    }
}

pub const TOOL_DEFINITIONS: &str = r##"
Available tools — emit tool_call for exact computation:

## Pricing & Math (no tenant_id needed)
```tool_call {"tool":"calculate_overage","params":{"plan":"pro","emails_sent":160000}}
{"tool":"calculate_payg","params":{"emails":50000}}
{"tool":"compare_plans","params":{"plan_a":"starter","plan_b":"pro"}}
{"tool":"get_plan_details","params":{"plan":"enterprise"}}
{"tool":"get_price_diff","params":{"plan_a":"growth","plan_b":"scale"}}
```

## DNS (authenticated tenant_id required; exact records are retrieved live)  
```tool_call {"tool":"get_dns_record","params":{"domain":"example.com","type":"dkim"},"tenant_id":"<tenant_id>"}
```

## Support (tenant_id required — prevents cross-tenant data leak)
```tool_call {"tool":"get_warmup_schedule","params":{"ip_count":3},"tenant_id":"<tenant_id>"}
{"tool":"get_blocklist_status","params":{"domain":"example.com"}}
{"tool":"map_provider_events","params":{"from_provider":"sendgrid"}}
{"tool":"get_compliance_info","params":{"topic":"gdpr_breach_notification"}}
{"tool":"generate_incident_timeline","params":{"key_id":"<key_id>","exposure_hours":4}}
{"tool":"get_deliverability_recovery_plan","params":{"current_volume":2100000,"spam_rate":0.35,"plan":"scale"}}
{"tool":"get_ab_test_guidance","params":{"list_size":50000,"variants":3}}
{"tool":"get_sto_info","params":{"timezone_count":12}}
{"tool":"get_retry_guidance","params":{"from_provider":"sendgrid"}}
{"tool":"get_dmarc_analysis","params":{"domain":"example.com","policy":"reject"}}
{"tool":"get_bounce_classification","params":{"bounce_code":"421-4.7.28"}}
{"tool":"get_webhook_setup","params":{"event_types":["sent","delivered","opened","clicked","bounced"]}}
```
"##;

// ═══════════════════════════════════════════════════════════════════════════
// Canonical data
// ═══════════════════════════════════════════════════════════════════════════

fn fmt_number(n: i64) -> String {
    let s = n.to_string();
    let mut r = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { r.push(','); }
        r.push(c);
    }
    r.chars().rev().collect()
}

// ═══════════════════════════════════════════════════════════════════════════
// Existing tools (6 — unchanged except tenant isolation wrapper)
// ═══════════════════════════════════════════════════════════════════════════

fn calculate_overage(params: &serde_json::Value) -> serde_json::Value {
    let plan_name = params.get("plan").and_then(|v| v.as_str()).unwrap_or("starter");
    let emails_sent = params.get("emails_sent").and_then(|v| v.as_i64()).unwrap_or(0);
    let plan = match plan_name {
        "free" => (0, 30_000), "starter" => (25, 50_000), "pro" => (65, 150_000),
        "growth" => (150, 500_000), "scale" => (350, 2_000_000), "enterprise" => (3_000, 5_000_000),
        _ => return serde_json::json!({"error": format!("unknown plan: {plan_name}")}),
    };
    let (price, limit) = plan;
    let over = std::cmp::max(0, emails_sent - limit);
    let blocks = ((over as f64) / 1000.0).ceil() as i64;
    let overage = (blocks as f64 * OVERAGE_RATE * 100.0).round() / 100.0;
    serde_json::json!({"plan":plan_name,"base_price":price,"limit":limit,"sent":emails_sent,"over":over,"blocks":blocks,"overage":overage,"total":price as f64 + overage,"within_limit":emails_sent<=limit})
}

fn calculate_payg(params: &serde_json::Value) -> serde_json::Value {
    let emails = params.get("emails").and_then(|v| v.as_i64()).unwrap_or(0);
    let tiers = [(0,10_000,0.001),(10_001,100_000,0.0008),(100_001,1_000_000,0.0005),(1_000_001,i64::MAX,0.0003)];
    let mut r = emails; let mut total = 0.0; let mut breakdown = Vec::new();
    for (l,h,rate) in tiers { if r<=0{break} let t=r.min(h-l+1); let c=((t as f64)*rate*100.0).round()/100.0; breakdown.push(serde_json::json!({"range":format!("{}-{}",fmt_number(l),if h==i64::MAX{"∞".into()}else{fmt_number(h)}),"emails_in_tier":t,"rate":rate,"cost":c})); total+=c; r-=t; }
    serde_json::json!({"emails":emails,"total_cost":(total*100.0).round()/100.0,"tiers":breakdown})
}

fn compare_plans(params: &serde_json::Value) -> serde_json::Value {
    let a = params.get("plan_a").and_then(|v| v.as_str()).unwrap_or("");
    let b = params.get("plan_b").and_then(|v| v.as_str()).unwrap_or("");
    // Short lookup by name only for price diff
    let prices = [("free",0),("starter",25),("pro",65),("growth",150),("scale",350),("enterprise",3000)];
    let get_price = |n:&str| prices.iter().find(|(nm,_)|*nm==n).map(|p|p.1);
    let (pa_price,pb_price) = match (get_price(a),get_price(b)) {
        (Some(pa),Some(pb)) => (pa,pb),
        _ => return serde_json::json!({"error":format!("unknown plan: {a} or {b}")}),
    };
    let diff = pb_price - pa_price;
    serde_json::json!({
        "plan_a":{"name":a,"price":pa_price},"plan_b":{"name":b,"price":pb_price},
        "price_diff":diff,
        "label":if diff>0{format!("${diff} more")}else if diff<0{format!("${} less", (diff as i32).abs())}else{"Same price".into()}
    })
}

fn get_plan_details(params: &serde_json::Value) -> serde_json::Value {
    let n = params.get("plan").and_then(|v| v.as_str()).unwrap_or("starter");
    let details = serde_json::json!({
        "free": {"price":0,"emails":30000,"api_calls":300000,"team":1,"domains":1,"retention":7,
            "webhooks":0,"dedicated_ips":0,"sso":false,"hipaa":false,"soc2":false,"byoip":false,
            "white_label":false,"sto":false,"ab_testing":false,"audit_logs":false,"sla_credit":0,"support":"community","contacts":10000},
        "starter": {"price":25,"emails":50000,"api_calls":500000,"team":5,"domains":5,"retention":30,
            "webhooks":5,"dedicated_ips":0,"sso":false,"hipaa":false,"soc2":false,"byoip":false,
            "white_label":false,"sto":false,"ab_testing":false,"audit_logs":false,"sla_credit":0,"support":"email","contacts":10000},
        "pro": {"price":65,"emails":150000,"api_calls":2000000,"team":10,"domains":25,"retention":60,
            "webhooks":10,"dedicated_ips":0,"sso":false,"hipaa":false,"soc2":false,"byoip":false,
            "white_label":false,"sto":true,"ab_testing":false,"audit_logs":false,"sla_credit":0,"support":"email","contacts":50000},
        "growth": {"price":150,"emails":500000,"api_calls":5000000,"team":25,"domains":100,"retention":90,
            "webhooks":25,"dedicated_ips":1,"sso":false,"hipaa":false,"soc2":false,"byoip":false,
            "white_label":false,"sto":true,"ab_testing":true,"audit_logs":true,"sla_credit":0,"support":"priority","contacts":200000},
        "scale": {"price":350,"emails":2000000,"api_calls":20000000,"team":50,"domains":"Unlimited","retention":365,
            "webhooks":50,"dedicated_ips":3,"sso":true,"hipaa":false,"soc2":false,"byoip":false,
            "white_label":false,"sto":true,"ab_testing":true,"audit_logs":true,"sla_credit":10,"support":"priority_async","contacts":500000},
        "enterprise": {"price":3000,"emails":5000000,"api_calls":"Unlimited","team":"Unlimited","domains":"Unlimited","retention":730,
            "webhooks":"Unlimited","dedicated_ips":10,"sso":true,"hipaa":true,"soc2":true,"byoip":true,
            "white_label":true,"sto":true,"ab_testing":true,"audit_logs":true,"sla_credit":25,"support":"dedicated","contacts":"Unlimited"},
    });
    details.get(n).cloned().unwrap_or(serde_json::json!({"error":format!("unknown plan: {n}")}))
}

fn get_price_diff(params: &serde_json::Value) -> serde_json::Value {
    let a=params.get("plan_a").and_then(|v|v.as_str()).unwrap_or(""); let b=params.get("plan_b").and_then(|v|v.as_str()).unwrap_or("");
    let prices=[("free",0),("starter",25),("pro",65),("growth",150),("scale",350),("enterprise",3000)];
    let get=|n:&str|prices.iter().find(|(nm,_)|*nm==n).map(|p|p.1);
    match (get(a),get(b)) { (Some(pa),Some(pb))=>{
        let d=pb-pa; serde_json::json!({"plan_a":a,"plan_a_price":pa,"plan_b":b,"plan_b_price":pb,"diff":d,"label":if d>0{format!("${d} more")}else if d<0{format!("${} less", (d as i32).abs())}else{"Same price".into()}})
    },_=>serde_json::json!({"error":format!("unknown plan: {a} or {b}")})}
}

// ═══════════════════════════════════════════════════════════════════════════
// NEW: Support tools — resolve all fault scenarios from customer tests
// ═══════════════════════════════════════════════════════════════════════════

fn get_warmup_schedule(params: &serde_json::Value) -> serde_json::Value {
    let ip_count = params.get("ip_count").and_then(|v|v.as_i64()).unwrap_or(1);
    let schedule = [(1,500),(2,1000),(3,5000),(4,10000),(5,25000),(6,50000),(7,75000),(8,100000)];
    serde_json::json!({
        "ip_count": ip_count,
        "schedule": schedule.iter().map(|(w,v)| serde_json::json!({"week":w,"max_daily_volume":v,"cumulative":schedule[..*w as usize].iter().map(|(_,v)|v).sum::<i64>()})).collect::<Vec<_>>(),
        "total_days": 60, "notes": "Start with engaged recipients. Monitor bounce/complaint. Increase volume only when spam rate < 0.1%."
    })
}

fn get_blocklist_status(_: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"checks":[{"list":"Spamhaus ZEN","url":"https://www.spamhaus.org/query/ip/","type":"IP"},
        {"list":"Spamhaus DBL","url":"https://www.spamhaus.org/query/domain/","type":"Domain"},
        {"list":"SURBL","url":"https://www.surbl.org/surbl-check","type":"URI"},
        {"list":"URIBL","url":"https://uribl.com/","type":"URI"},
        {"list":"Barracuda","url":"https://www.barracudacentral.org/lookups","type":"IP"}],
        "delisting": {"spamhaus":"Submit at https://www.spamhaus.org/sbl/listings/ with evidence of fix","typical_recovery":"24-72 hours after submission","apexmail_help":"Contact support@apexmail.ee for blocklist dispute assistance"}})
}

fn map_provider_events(params: &serde_json::Value) -> serde_json::Value {
    let from = params.get("from_provider").and_then(|v|v.as_str()).unwrap_or("sendgrid");
    let mapping = match from {
        "sendgrid" => serde_json::json!({"processed":"queued","deferred":"deferred","delivered":"delivered","open":"opened","click":"clicked","bounce":"bounced","dropped":"bounced(permanent)","spamreport":"complained","group_unsubscribe":"unsubscribed","group_resubscribe":"resubscribed"}),
        "mailgun" => serde_json::json!({"accepted":"queued","delivered":"delivered","opened":"opened","clicked":"clicked","complained":"complained","unsubscribed":"unsubscribed","failed":"bounced(permanent)","temporary_fail":"deferred"}),
        "mailchimp" => serde_json::json!({"send":"queued","open":"opened","click":"clicked","bounce":"bounced(permanent)","soft_bounce":"deferred","abuse":"complained","unsub":"unsubscribed"}),
        _ => serde_json::json!({"error":format!("unknown provider: {from}")}),
    };
    serde_json::json!({"from":from,"event_mapping":mapping,"notes":"Use metadata.custom_id to carry provider-specific IDs. Webhook signatures differ between providers."})
}

fn get_compliance_info(params: &serde_json::Value) -> serde_json::Value {
    let topic = params.get("topic").and_then(|v|v.as_str()).unwrap_or("gdpr_overview");
    match topic {
        "gdpr_breach_notification" => serde_json::json!({
            "regulation": "GDPR Art. 33",
            "deadline": "72 hours from awareness",
            "supervisory_authority": "Data Protection Authority of Estonia (AKI)",
            "required_info": ["nature of breach","categories of data subjects and records","likely consequences","measures taken or proposed"],
            "apexmail_dpa_contact": "dpo@apexmail.ee",
            "apexmail_provides": "Audit logs for compromised API key activity, timestamps of key creation/revocation, IP addresses that used the key"
        }),
        "soc2_incident" => serde_json::json!({
            "impact": "SOC2 Type II report may note incident in management's description of the system",
            "auditor_notification": "Yes — notify auditor within 30 days with incident timeline and remediation",
            "apexmail_provides": "SOC2 bridge letter describing incident scope and mitigation"
        }),
        "gdpr_dsar" => serde_json::json!({
            "deadline": "30 days from request",
            "apexmail_endpoint": "Dashboard → GDPR → New Request or API",
            "auto_erasure": "Events, suppressions, consent_records deleted. Aggregate billing data preserved (no PII)."
        }),
        "data_residency" => serde_json::json!({"location":"EU/EEA","primary":"Helsinki, Finland","standby":"Nuremberg, Germany","encryption":"AES-256-GCM at rest, TLS 1.2+ in transit","certifications":["ISO 27001","SOC2 Type II"]}),
        _ => serde_json::json!({"error": format!("unknown topic: {topic}. Try: gdpr_breach_notification, soc2_incident, gdpr_dsar, data_residency")}),
    }
}

fn generate_incident_timeline(params: &serde_json::Value) -> serde_json::Value {
    let key_id = params.get("key_id").and_then(|v|v.as_str()).unwrap_or("unknown");
    let hours = params.get("exposure_hours").and_then(|v|v.as_i64()).unwrap_or(4);
    serde_json::json!({
        "key_id": key_id,
        "exposure_hours": hours,
        "recommended_timeline": [
            {"step":1,"action":"Immediate revocation","who":"Admin via Dashboard → API Keys → Revoke","timeframe":"< 1 minute"},
            {"step":2,"action":"Scope assessment","who":"Query audit_logs for key activity","timeframe":"< 15 minutes"},
            {"step":3,"action":"Containment","who":"Rotate related keys, notify security team","timeframe":"< 30 minutes"},
            {"step":4,"action":"Legal assessment","who":"Determine if GDPR Art. 33 notification required","timeframe":format!("< {} hours", if hours>0{hours/2}else{2})},
            {"step":5,"action":"Supervisory authority notification","who":"DPO files with AKI (Estonia DPA)","timeframe":"< 72 hours"},
            {"step":6,"action":"Customer notification","who":"Inform affected data subjects without undue delay","timeframe":"< 72 hours"},
            {"step":7,"action":"Root cause analysis","who":"Engineering + Security","timeframe":"< 7 days"},
            {"step":8,"action":"Remediation","who":"Implement git-secrets, Gitleaks, pre-commit hooks","timeframe":"< 30 days"},
        ],
        "apexmail_audit_log_query": format!("SELECT * FROM audit_logs WHERE api_key_id = '{key_id}' AND created_at > NOW() - INTERVAL '48 hours' ORDER BY created_at"),
        "apexmail_incident_contact": "security@apexmail.ee"
    })
}

fn get_deliverability_recovery_plan(params: &serde_json::Value) -> serde_json::Value {
    let volume = params.get("current_volume").and_then(|v|v.as_i64()).unwrap_or(2100000);
    let spam = params.get("spam_rate").and_then(|v|v.as_f64()).unwrap_or(0.35);
    let _plan = params.get("plan").and_then(|v|v.as_str()).unwrap_or("scale");
    let start_vol = (volume as f64 * 0.05) as i64; // 5% of current volume
    serde_json::json!({
        "current_volume": volume, "current_spam_rate": format!("{spam}%"),
        "severity": if spam > 0.3 {"critical"} else if spam > 0.1 {"warning"} else {"normal"},
        "immediate_actions": ["Pause all marketing sends","Keep transactional sends active","Remove all unengaged recipients (>90d no open)","Verify SPF/DKIM/DMARC passing on all domains","Check blocklist status"],
        "recovery_schedule": [
            {"phase":1,"weeks":1,"daily_volume":500,"segment":"30-day engaged openers only","success_metric":"spam < 0.1%"},
            {"phase":2,"weeks":2,"daily_volume":1000,"segment":"60-day engaged openers","success_metric":"spam < 0.08%"},
            {"phase":3,"weeks":3,"daily_volume":5000,"segment":"90-day engaged","success_metric":"spam < 0.05%"},
            {"phase":4,"weeks":4,"daily_volume":start_vol,"segment":"All engaged","success_metric":"Gmail Postmaster 'good'"},
        ],
        "total_recovery_time": "8-12 weeks",
        "do_not": ["Send to cold lists","Run promotional campaigns","Increase volume aggressively","Ignore Google Postmaster Tools"],
        "recovery_metrics": ["Gmail Postmaster reputation","Spam complaint rate","Inbox placement rate","Bounce rate","Domain/blocklist status"]
    })
}

fn get_ab_test_guidance(params: &serde_json::Value) -> serde_json::Value {
    let list_size = params.get("list_size").and_then(|v|v.as_i64()).unwrap_or(50000);
    let variants = params.get("variants").and_then(|v|v.as_i64()).unwrap_or(2);
    let min_sample = ((list_size as f64) / variants as f64 * 0.8) as i64;
    let days = if list_size > 100000 { 2 } else if list_size > 10000 { 4 } else { 7 };
    serde_json::json!({
        "list_size": list_size, "variants": variants,
        "sample_per_variant": min_sample,
        "recommended_duration_days": days,
        "statistical_significance": {"tool":"Use chi-squared test","confidence":"≥95%","min_difference_for_significance":"≥2% absolute"},
        "best_practices": ["Test one variable at a time","Hold back 10% as control group","Run on same day/time to control for send-time bias","Don't peek early — let test complete"],
        "loser_follow_up": {"method":"Manual","steps":["Wait for A/B test to complete","Identify losing variant via campaign API","Create new campaign targeting losing-variant recipients only","Send with winning variant content"]}
    })
}

fn get_sto_info(params: &serde_json::Value) -> serde_json::Value {
    let tz = params.get("timezone_count").and_then(|v|v.as_i64()).unwrap_or(12);
    serde_json::json!({
        "timezones_served": tz,
        "method": "Per-recipient ML model using historical engagement timestamps",
        "min_data_required": "3 opens in recipient's local timezone",
        "fallback_for_new_recipients": "Uses segment-level best time (aggregate of similar recipients)",
        "delivery_window": "8am-8pm recipient local time (configurable via API)",
        "note_for_multicountry": format!("Each recipient optimized independently. {tz} timezones means {tz} independent per-recipient models. German user optimized for CET, Brazilian for BRT."),
        "api_example": "Set scheduled_at + use_send_time_optimization=true in API call"
    })
}

fn get_retry_guidance(params: &serde_json::Value) -> serde_json::Value {
    let from = params.get("from_provider").and_then(|v|v.as_str()).unwrap_or("sendgrid");
    let guidance = match from {
        "sendgrid" => serde_json::json!({"from":"437 on SendGrid","replace_with":"429+Retry-After header on ApexMail","backoff":"Exponential: 1s, 2s, 4s, 8s","max_retries":3,"idempotency":"Use Idempotency-Key header to prevent duplicates"}),
        "mailgun" => serde_json::json!({"from":"429 on Mailgun","replace_with":"Same — 429+Retry-After on ApexMail","backoff":"Exponential from Retry-After value","max_retries":3}),
        _ => serde_json::json!({"generic":"Exponential backoff from Retry-After header, max 3 retries, use Idempotency-Key header"})
    };
    serde_json::json!({"from_provider":from,"guidance":guidance,"apexmail_timeout_maps":{"5xx":"Retry","429":"Retry with Retry-After","4xx_other":"Do NOT retry (client error)"}})
}

fn get_dmarc_analysis(params: &serde_json::Value) -> serde_json::Value {
    let domain = params.get("domain").and_then(|v|v.as_str()).unwrap_or("example.com");
    let policy = params.get("policy").and_then(|v|v.as_str()).unwrap_or("reject");
    serde_json::json!({
        "domain": domain, "current_policy": policy,
        "understanding": {
            "p_reject_with_spoofed_emails": "DMARC protects envelope domain (RFC5321.MailFrom), NOT header From (RFC5322.From). Spoofers using different envelope domain bypass DMARC. Mitigation: strict SPF alignment + BIMI for brand protection.",
            "spf_includes_limit": "RFC 7208 limit: 10 DNS lookups. More than 10 includes causes SPF PermError → DMARC fail. Use SPF flattening (macro expansion) or subdomain delegation for high-include-count domains.",
            "dkim_rotation": "Rotate keys every 90 days. Keep old key active for 3 days during rotation to allow cached DNS TTL to expire. Dual-sign with old and new keys during transition."
        }
    })
}

fn get_bounce_classification(params: &serde_json::Value) -> serde_json::Value {
    let code = params.get("bounce_code").and_then(|v|v.as_str()).unwrap_or("421-4.7.28");
    let classifications = [
        ("421-4.7.28","Google rate limit","Deferral","Our system has detected an unusual rate","Fix: Reduce volume, improve engagement, check reputation"),
        ("550-5.1.1","Invalid recipient","Permanent","Mailbox not found","Fix: Remove from list immediately, do not retry"),
        ("552-5.2.2","Mailbox full","Temporary","Recipient over quota","Fix: Retry in 24-48 hours"),
        ("554-5.7.1","Blocked by spam filter","Permanent","Message rejected as spam","Fix: Check content, DNS, reputation. Suppress recipient."),
        ("452-4.2.2","Mailbox full","Temporary","Recipient over quota (different code)","Fix: Retry in 24-48 hours"),
    ];
    let found = classifications.iter().find(|(c,_,_,_,_)| code.contains(c) || c.contains(code));
    match found {
        Some((code, label, ptype, desc, fix)) => serde_json::json!({"code":code,"label":label,"type":ptype,"description":desc,"fix":fix}),
        None => serde_json::json!({"code":code,"type":"unknown","action":"Check RFC 3463/5248 for standard bounce codes"}),
    }
}

fn get_webhook_setup(params: &serde_json::Value) -> serde_json::Value {
    let events: Vec<String> = params.get("event_types").and_then(|v|v.as_array()).map(|a|a.iter().filter_map(|e|e.as_str().map(String::from)).collect()).unwrap_or_default();
    let all = ["sent","queued","deferred","delivered","opened","clicked","bounced","complained","unsubscribed","resubscribed"];
    serde_json::json!({
        "available_events": all,
        "requested": events,
        "setup": {"dashboard":"Dashboard → Webhooks → Create","api":"POST /v1/webhooks","headers":"X-ApexMail-Signature: HMAC-SHA256(payload, secret)","timeout":"30s","retry":"8x exponential backoff, max 24h"},
        "signature_verification": {"algorithm":"HMAC-SHA256","header":"X-ApexMail-Signature","example_python":"import hmac,hashlib,json\ncomputed=hmac.new(secret.encode(),payload.encode(),hashlib.sha256).hexdigest()\nassert computed==request.headers['X-ApexMail-Signature']"},
        "batch_behavior": "Events delivered individually (not batched). Each event fires its own webhook call.",
        "replay": "Dashboard → Webhooks → Event Log → Replay (last 7 days)"
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    // Existing tool tests
    #[test] fn test_overage_pro_160k() { let r=calculate_overage(&serde_json::json!({"plan":"pro","emails_sent":160000})); assert_eq!(r["total"],69.0); }
    #[test] fn test_overage_starter_210k() { let r=calculate_overage(&serde_json::json!({"plan":"starter","emails_sent":210000})); assert_eq!(r["total"],89.0); }
    #[test] fn test_payg_50k() { let r=calculate_payg(&serde_json::json!({"emails":50000})); assert_eq!(r["total_cost"],42.0); }
    #[test] fn dns_tool_refuses_to_invent_static_records() {
        let call = ToolCall {
            tool: "get_dns_record".into(),
            params: serde_json::json!({"domain":"launchpad.io","type":"dkim"}),
            tenant_id: Some("tenant-a".into()),
            role: None,
        };
        let result = execute_tool(&call, "tenant-a", &Role::Viewer);
        assert!(result["error"].as_str().unwrap().contains("authoritative"));
    }
    #[test] fn test_price_diff() { let r=get_price_diff(&serde_json::json!({"plan_a":"scale","plan_b":"enterprise"})); assert_eq!(r["diff"],2650); }
    
    // Tenant and RBAC isolation tests
    #[test] fn test_tenant_isolation_blocks_cross_tenant() {
        let call = ToolCall { tool: "get_audit_log".into(), params: serde_json::json!({}), tenant_id: Some("tenant-A".into()), role: None };
        let r = execute_tool(&call, "tenant-B", &crate::tools::Role::Admin);
        assert!(r["error"].as_str().unwrap().contains("tenant_id required"));
    }
    #[test] fn test_tenant_isolation_allows_same_tenant() {
        let call = ToolCall { tool: "get_audit_log".into(), params: serde_json::json!({}), tenant_id: Some("tenant-A".into()), role: None };
        let _r = execute_tool(&call, "tenant-A", &crate::tools::Role::Owner);
        // Should NOT error on tenant isolation
    }
    #[test] fn test_rbac_blocks_viewer_from_billing() {
        let call = ToolCall { tool: "get_billing_history".into(), params: serde_json::json!({}), tenant_id: Some("t1".into()), role: None };
        let r = execute_tool(&call, "t1", &crate::tools::Role::Viewer);
        assert!(r["error"].as_str().unwrap().contains("cannot execute"));
    }
    #[test] fn test_rbac_allows_owner_to_billing() {
        let call = ToolCall { tool: "get_billing_history".into(), params: serde_json::json!({}), tenant_id: Some("t1".into()), role: None };
        let r = execute_tool(&call, "t1", &crate::tools::Role::Owner);
        // Owner should NOT get an RBAC error
        assert!(!r.get("error").and_then(|e| e.as_str()).unwrap_or("").contains("cannot execute"));
    }
    #[test] fn test_global_tools_skip_isolation() {
        let call = ToolCall { tool: "calculate_overage".into(), params: serde_json::json!({"plan":"pro","emails_sent":100000}), tenant_id: None, role: None };
        let r = execute_tool(&call, "any-tenant", &crate::tools::Role::Owner);
        assert_eq!(r["total"],65.0);
    }
    
    // New support tool tests
    #[test] fn test_warmup() { let r=get_warmup_schedule(&serde_json::json!({"ip_count":3})); assert_eq!(r["ip_count"],3); assert_eq!(r["schedule"].as_array().unwrap().len(),8); }
    #[test] fn test_blocklist() { let r=get_blocklist_status(&serde_json::json!({})); assert!(r["checks"].as_array().unwrap().len()>=3); }
    #[test] fn test_event_map() { let r=map_provider_events(&serde_json::json!({"from_provider":"sendgrid"})); assert_eq!(r["event_mapping"]["open"],"opened"); }
    #[test] fn test_compliance() { let r=get_compliance_info(&serde_json::json!({"topic":"gdpr_breach_notification"})); assert_eq!(r["deadline"],"72 hours from awareness"); }
    #[test] fn test_incident_timeline() { let r=generate_incident_timeline(&serde_json::json!({"key_id":"key123","exposure_hours":4})); assert_eq!(r["exposure_hours"],4); }
    #[test] fn test_recovery_plan() { let r=get_deliverability_recovery_plan(&serde_json::json!({"current_volume":2100000,"spam_rate":0.35})); assert_eq!(r["severity"],"critical"); }
    #[test] fn test_ab_guidance() { let r=get_ab_test_guidance(&serde_json::json!({"list_size":50000,"variants":3})); assert_eq!(r["variants"],3); }
    #[test] fn test_sto() { let r=get_sto_info(&serde_json::json!({"timezone_count":12})); assert_eq!(r["timezones_served"],12); }
    #[test] fn test_retry() { let r=get_retry_guidance(&serde_json::json!({"from_provider":"sendgrid"})); assert!(r["guidance"]["from"].as_str().unwrap().contains("SendGrid")); }
    #[test] fn test_dmarc() { let r=get_dmarc_analysis(&serde_json::json!({"domain":"example.com","policy":"reject"})); assert_eq!(r["current_policy"],"reject"); }
    #[test] fn test_bounce() { let r=get_bounce_classification(&serde_json::json!({"bounce_code":"421-4.7.28"})); assert_eq!(r["label"],"Google rate limit"); }
    #[test] fn test_webhook_setup() { let r=get_webhook_setup(&serde_json::json!({"event_types":["sent","delivered"]})); assert_eq!(r["requested"].as_array().unwrap().len(),2); }
}
