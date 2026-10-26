# Access Control Policy

> **Classification:** Internal Policy, Confidential
> **Owner:** ApexMail
> Legal Entity: Bel Consulting OÜ, Registry Code 16588745, Tallinn, Estonia
> Last Reviewed: 2026-10-25
> Review Cycle: Annually

---

## 1. Purpose

This policy defines how access to ApexMail systems, data, and tooling is
granted, used, and revoked. It enforces least privilege to reduce the risk of
unauthorised access.

---

## 2. Scope

All systems operated by ApexMail:

- The production environment and its services.
- The ApexMail console, dashboard, and API.
- Source code repositories and the release pipeline.
- Monitoring and observability tooling.
- Secrets, credentials, and certificates.

---

## 3. Principle of Least Privilege

- Access is granted only to what a task requires.
- Access defaults to deny. Permissions are granted explicitly.
- Elevated access is temporary and recorded.
- No shared accounts. Every identity is unique.

---

## 4. Console Roles

The product implements role-based access control for every console session and
API key. Roles and their scope sets are defined in the auth code and applied
on every request.

| Role | Grants |
|------|--------|
| **owner** | Full access to every scope, including billing. MFA required. |
| **admin** | Full access to every scope, including billing. MFA required. |
| **developer** | Read and write scopes for messages, domains, templates, events, analytics, contacts, lists, logs, webhooks, campaigns, automations, suppressions, dedicated IPs, support, and retention. |
| **viewer** | Read-only scopes across the same areas. |
| **member** | Default role for accounts with no other assignment. Message reading only. |

Enforcement:

- The control plane, which is the production administration surface, accepts
  only `admin` and `owner` sessions with MFA enabled. It re-reads the live
  role, MFA state, and account status from the database on every request, so a
  role demotion or MFA removal revokes control-plane authority immediately.
- Session scopes are recomputed from the current role on every request. A
  demotion narrows an existing session without waiting for token expiry.
- MFA is required to establish a session with an `admin` or `owner` role,
  including sign-in through the SSO path.
- Billing read is granted by no role. Invoice access requires a deliberately
  minted credential that carries that scope.

---

## 5. Authentication and MFA

- Passwords run from 15 to 128 characters, are screened against common weak
  passwords, and refuse repeated or sequential character runs. Password
  managers and paste are supported.
- Multi-factor authentication uses time-based one-time passwords with lockout
  and replay hardening, plus recovery codes. SMS-based MFA is not used.
- Production administration requires MFA: console `admin` and `owner` sessions
  carry MFA on every control-plane request.
- Password authentication is disabled on the production host. SSH accepts key
  pairs only, and root login is limited to keys.

---

## 6. Production Host Access

- Production host access is limited to authorized personnel with production
  access.
- Administrative actions taken on production are recorded in the audit trail
  (§8).
- Elevated access for a specific task is time-bound and recorded.

---

## 7. API Keys

- API keys are stored as keyed hashes. The plaintext key is shown once and is
  never persisted.
- Keys carry scopes from a registered scope registry. An issuing caller can
  only mint scopes it already holds, and the wildcard scope only passes to
  callers that already hold it.
- Every key carries an expiry timestamp and is looked up by hash on every
  request.
- Key issuance and use are auditable through the tenant audit trail (§8).

---

## 8. Audit Logging

Administrative actions are written to the `audit_logs` table. Entries form a
hash chain: each entry links to the hash of its predecessor, and the chain head
advances transactionally, so tampering with history is detectable.

Customers read their own trail through the audit API with the `audit:read`
scope, and exports are themselves audited. Retention follows the Data
Retention Policy: one year minimum.

---

## 9. Secrets Management

- Production secrets reach services as files through Docker secrets, mounted
  by the compose files. Nothing secret is committed: `.env` files are
  gitignored and hold non-production values only.
- Rotation follows the schedule in `docs/operations/secret-rotation.md` and is
  performed by `scripts/rotate-secrets.sh` with dual-key overlap windows.
- Secrets stored through the platform secret manager are encrypted with
  `AES-256-GCM`, carry an access hierarchy with expiry and revocation, keep
  version history, and support automatic rotation.

---

## 10. Access Reviews

### 10.1 Quarterly review

Every quarter, dashboard roles and API keys are reviewed:

- Each role still matches what its holder needs.
- API keys still match the scopes their consumers need.
- Dormant accounts and unused keys are identified.
- Lingering elevated access is removed.

Findings are remediated within 7 days.

---

## 11. Access Revocation

- Access is removed as soon as it is no longer required.
- A role demotion or MFA removal takes effect on the next request through the
  live re-check in the control plane (§4).
- Secrets tied to removed access are rotated under §9.

---

## 12. Roadmap — not currently implemented

- A formal internal role matrix for production access, beyond the product
  roles in §4.
- A time-boxed break-glass workflow for elevated production access.
- WebAuthn passkeys as an MFA method alongside time-based one-time passwords.
- A documented inventory and rotation schedule for SSH keys.
- Statement logging for interactive database sessions.

---

## 13. Related Documents

- [GDPR Compliance Framework](./gdpr-compliance.md)
- [Incident Response Plan](./incident-response.md)
- [Change Management Policy](./change-management.md)
- [Vulnerability Management Policy](./vulnerability-management.md)
