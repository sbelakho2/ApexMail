# Access Control Policy

> **Classification:** Internal Policy — Confidential
> **Owner:** Engineering Lead, Bel Consulting OÜ
> **Legal Entity:** Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> **Last Reviewed:** 2026-02-09
> **Review Cycle:** Annually, and upon team changes

---

## 1. Purpose

This policy defines how access to ApexMail systems, infrastructure, data, and
tooling is granted, managed, and revoked. It enforces the principle of least
privilege to minimise the risk of unauthorised access.

---

## 2. Scope

All systems operated by Bel Consulting OÜ for ApexMail:

- Production and staging infrastructure (Hetzner Cloud ARM servers).
- PostgreSQL and Redis instances.
- Application admin interfaces.
- Source code repositories (GitHub).
- CI/CD pipelines.
- Cloud dashboards (Hetzner Cloud Console).
- Monitoring and observability tools.
- Internal communication tools.

---

## 3. Principle of Least Privilege

- Access is granted only to the resources required for a person's role.
- Access defaults to **deny**. Permissions are explicitly granted.
- Elevated access is temporary and time-bound where possible.
- No shared accounts. Every individual has a unique identity.

---

## 4. Role-Based Access Control (RBAC)

### 4.1 Defined Roles

| Role | Description | Scope |
|------|-------------|-------|
| **Admin** | Full platform access including infrastructure, database, and user management. Reserved for founders/CTO. | All systems |
| **Developer** | Code repository access (read/write), CI/CD, staging environment, application logs. Production access limited to read-only monitoring. | Repos, CI/CD, staging, monitoring |
| **Support** | Customer-facing admin panel (read-only customer data, limited actions: password reset, account unlock). No infrastructure access. | Admin panel (scoped) |
| **Billing** | Access to billing dashboard, invoice management, Stripe dashboard. No access to customer email content or recipient data. | Billing systems |

### 4.2 Access Matrix

| System | Admin | Developer | Support | Billing |
|--------|-------|-----------|---------|---------|
| Hetzner Cloud Console | ✅ Full | ❌ | ❌ | ❌ |
| Production servers (SSH) | ✅ Full | ❌ (break-glass only) | ❌ | ❌ |
| Staging servers (SSH) | ✅ Full | ✅ Full | ❌ | ❌ |
| PostgreSQL (production) | ✅ Read/write | 🔶 Read-only | ❌ | ❌ |
| PostgreSQL (staging) | ✅ Read/write | ✅ Read/write | ❌ | ❌ |
| Redis (production) | ✅ Full | 🔶 Read-only | ❌ | ❌ |
| GitHub repositories | ✅ Admin | ✅ Write | ❌ | ❌ |
| CI/CD pipeline | ✅ Admin | ✅ Trigger/view | ❌ | ❌ |
| Admin panel | ✅ Full | 🔶 Read-only | 🔶 Scoped | ❌ |
| Monitoring dashboards | ✅ Full | ✅ Full | 🔶 Read-only | ❌ |
| Billing dashboard | ✅ Full | ❌ | ❌ | ✅ Full |

---

## 5. Authentication Requirements

### 5.1 Multi-Factor Authentication (MFA)

MFA is **mandatory** for:

- All access to production infrastructure.
- Hetzner Cloud Console.
- GitHub organisation membership.
- CI/CD admin access.
- Admin panel access.
- Billing and payment dashboards.

Acceptable MFA methods:

- Hardware security keys (FIDO2/WebAuthn) — **preferred**.
- TOTP authenticator apps (Authy, Google Authenticator).
- SMS-based MFA is **not accepted** due to SIM-swap risks.

### 5.2 Password Policy

- Minimum 16 characters.
- Use of a password manager is required.
- No password reuse across services.
- Passwords rotated upon suspected compromise.

---

## 6. SSH Key Management (Hetzner Servers)

### 6.1 Key Requirements

- **Algorithm:** Ed25519 (preferred) or RSA 4096-bit minimum.
- **Passphrase:** Required on all private keys.
- **Storage:** Private keys stored only on the user's workstation, protected by
  the OS keychain or an encrypted vault.

### 6.2 Key Distribution

- Public keys added to servers via configuration management (Ansible/scripts in
  `tools/` or deploy configuration).
- No manual key placement on production servers.
- Root login via SSH is **disabled**. Access via named user accounts with `sudo`.

### 6.3 Key Rotation

- SSH keys rotated annually, or immediately upon suspected compromise.
- Departing team members' keys removed within **24 hours** of offboarding.

---

## 7. Database Access

### 7.1 Production Database (PostgreSQL)

| Role | Access Level | Connection Method |
|------|-------------|-------------------|
| Application service | Read/write (scoped to application schema) | Connection string in secrets manager |
| Admin | Read/write (all schemas) | SSH tunnel + named user |
| Developer | **Read-only** | SSH tunnel + read-only role (break-glass, logged) |
| Migrations | Read/write (DDL + DML) | Separate `migration_runner` role, CI-only |
| Support / Billing | ❌ No direct access | Via admin panel only |

### 7.2 Migration Safeguards

- Production migrations executed only through the CI/CD pipeline.
- The `migration_runner` role has DDL permissions but is only activated during
  migration runs.
- Destructive migrations (DROP TABLE, DROP COLUMN, data deletion) require
  **two approvals** and are never auto-applied
  (see [Change Management](./change-management.md)).

### 7.3 Query Logging

All queries executed against production PostgreSQL by human users are logged
(statement logging for the read-only and admin roles). Logs retained for 1 year.

---

## 8. Secrets Management

### 8.1 Storage

- All secrets (API keys, database credentials, TLS keys, third-party tokens)
  stored in environment variables injected at deploy time.
- Secrets **never** committed to source code repositories.
- `.env` files are in `.gitignore` and used only for local development with
  non-production values.

### 8.2 Rotation

| Secret Type | Rotation Frequency |
|-------------|-------------------|
| Database passwords | Every 6 months, or on compromise |
| API keys (internal) | Every 6 months |
| TLS certificates | Auto-renewed (Let's Encrypt) |
| SSH keys | Annually |
| Third-party tokens | Per vendor recommendation, max 1 year |

### 8.3 Exposure Response

If a secret is suspected or confirmed to be exposed:

1. Rotate the secret immediately.
2. Audit access logs for the compromised credential.
3. File a security incident if misuse is suspected
   (see [Incident Response](./incident-response.md)).

---

## 9. Access Reviews

### 9.1 Quarterly Reviews

Every quarter, the Admin role holder reviews:

- List of all personnel with access to each system.
- Appropriateness of each person's role and permissions.
- Any dormant accounts (no login in 90+ days).
- Any lingering temporary/elevated access.

Findings documented and remediated within 7 days.

### 9.2 Annual Certification

Annually, each team member confirms:

- They still require the access they hold.
- They are not aware of any shared or compromised credentials.
- Their MFA is active and recovery codes are stored securely.

---

## 10. Offboarding Procedure

When a team member departs (voluntary or involuntary):

| Step | Action | Deadline |
|------|--------|----------|
| 1 | Disable/remove GitHub organisation membership | Within 1 hour |
| 2 | Remove SSH keys from all servers | Within 24 hours |
| 3 | Revoke Hetzner Cloud Console access | Within 1 hour |
| 4 | Revoke CI/CD access | Within 1 hour |
| 5 | Revoke admin panel credentials | Within 1 hour |
| 6 | Rotate any shared secrets the person had access to | Within 24 hours |
| 7 | Revoke access to monitoring, communication, and billing tools | Within 24 hours |
| 8 | Confirm all access removed (checklist sign-off) | Within 48 hours |

For involuntary departures, steps 1–5 are executed **before** the departure
notification where possible.

---

## 11. Break-Glass Procedure

For emergency access beyond normal role permissions:

1. Requester contacts an Admin with justification.
2. Access granted with time limit (max 4 hours, extendable once).
3. All actions performed under break-glass access are logged.
4. Access revoked automatically at expiry or manually by Admin.
5. Post-access review within 24 hours to confirm no misuse.

---

## 12. Related Documents

- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Incident Response Plan](./incident-response.md)
- [Change Management Policy](./change-management.md)
- [Vulnerability Management Policy](./vulnerability-management.md)
