# Jobs-to-be-Done (JTBD) Navigation Mapping

Maps user goals to canonical navigation entry points.

## Customer Console (`web` surface via `services/mail-server/crates/api-server`)

- **Launch a campaign quickly** → `Campaigns`, `Templates`, `Lists`
- **Understand deliverability performance** → `Reports`, `Activity`, `AI Insights`
- **Manage account and plan** → `Settings`, `Billing`, `Dedicated IPs`
- **Operate team permissions** → `Settings` → `Team`

## Control Plane (`control-plane` surface via `services/mail-server/crates/api-server`)

- **Triage platform health** → Operations Dashboard
- **Respond to compliance risk** → Risk / Compliance, GDPR
- **Advance revenue pipeline** → CRM / Sales Pipeline
- **Operate content and support** → Content/CMS, Inbox

## Role-Based Landing Defaults

- Customer `owner/admin` → Dashboard
- Customer `member/viewer` → Dashboard with role-constrained nav
- Internal operator/compliance roles → Control Plane dashboard

## Label Quality Rules

- Prefer action clarity with noun-first labels.
- Keep related tasks clustered by workflow sequence.
- Avoid duplicate concepts under different names across surfaces.

## Entitlement Context Rule

- When a feature is plan/role constrained, nav labels remain stable.
- Explain entitlement in context with immediate next action (upgrade/request access).
