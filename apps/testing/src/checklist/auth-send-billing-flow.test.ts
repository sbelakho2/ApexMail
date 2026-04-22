import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const ROOT_DIR = path.resolve(__dirname, '../../../..');

function read(relativePath: string): string {
  return fs.readFileSync(path.join(ROOT_DIR, relativePath), 'utf8');
}

function sliceBetween(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker);
  expect(start).toBeGreaterThanOrEqual(0);
  expect(end).toBeGreaterThan(start);
  return source.slice(start, end);
}

function extractVecBranch(source: string, role: string): string {
  const branch = source.match(new RegExp(`"${role}"\\s*=>\\s*vec!\\[(.*?)\\],`, 's'));
  expect(branch, `missing ${role} branch in scopes_for_role`).not.toBeNull();
  return branch?.[1] ?? '';
}

describe('Auth → send → billing coverage', () => {
  it('keeps message sending scopes aligned with the authenticated route contract', () => {
    const authSource = read('services/mail-server/crates/api-server/src/routes/auth.rs');
    const messagesSource = read('services/mail-server/crates/api-server/src/routes/messages.rs');

    const developerBranch = extractVecBranch(authSource, 'developer');
    const memberBranch = extractVecBranch(authSource, 'member');
    const viewerBranch = extractVecBranch(authSource, 'viewer');

    expect(developerBranch).toContain('"messages:send".into()');
    expect(memberBranch).toContain('"messages:send".into()');
    expect(viewerBranch).not.toContain('"messages:send".into()');
    expect(authSource).toContain('unknown role encountered; denying all scopes');
    expect(authSource).toMatch(/_ => \{\s*tracing::warn!\(role = %role, "unknown role encountered; denying all scopes"\);\s*Vec::new\(\)\s*\}/s);

    const sendMessage = sliceBetween(
      messagesSource,
      'async fn send_message',
      'async fn send_batch',
    );
    const sendBatch = sliceBetween(
      messagesSource,
      'async fn send_batch',
      'async fn list_messages',
    );

    expect(sendMessage).toContain('require_scopes(&auth, &["messages:send"])?;');
    expect(sendMessage).toContain('validate_send(&body, &state, &auth.tenant_id).await?;');
    expect(sendMessage).toContain('check_tenant_quota(&state, &auth.tenant_id).await?;');
    expect(
      sendMessage.indexOf('require_scopes(&auth, &["messages:send"])?;'),
    ).toBeLessThan(sendMessage.indexOf('validate_send(&body, &state, &auth.tenant_id).await?;'));
    expect(
      sendMessage.indexOf('validate_send(&body, &state, &auth.tenant_id).await?;'),
    ).toBeLessThan(sendMessage.indexOf('check_tenant_quota(&state, &auth.tenant_id).await?;'));

    expect(sendBatch).toContain('require_scopes(&auth, &["messages:send"])?;');
    expect(sendBatch).toContain('check_tenant_quota(&state, &auth.tenant_id).await?;');
    expect(
      sendBatch.indexOf('require_scopes(&auth, &["messages:send"])?;'),
    ).toBeLessThan(sendBatch.indexOf('check_tenant_quota(&state, &auth.tenant_id).await?;'));
  });

  it('keeps the billing quota fallback wired into the message send path', () => {
    const messagesSource = read('services/mail-server/crates/api-server/src/routes/messages.rs');
    const usageSource = read('services/mail-server/crates/billing-service/src/usage.rs');
    const plansSource = read('services/mail-server/crates/billing-service/src/plans.rs');

    expect(messagesSource).toContain(
      'billing_service::usage::check_quota(&state.db, &state.redis, tenant_id)',
    );
    expect(usageSource).toContain('LEFT JOIN plans p ON t.plan = p.name');
    expect(usageSource).toContain('let resolved_limits = resolve_plan_limits(limits);');
    expect(usageSource).toContain('builtin_quota_limits(Some(&row.plan_name))');
    expect(plansSource).toContain('pub fn builtin_quota_limits');
    expect(plansSource).toContain('name: "pro"');
    expect(plansSource).toContain('dedicated_ip_count: 1');
  });

  it('keeps the browser registration and verification routes publicly reachable', () => {
    const appSource = read('services/mail-server/crates/api-server/src/app.rs');

    expect(appSource).toContain('.nest("/v1/auth", routes::auth::router())');
    expect(appSource).toContain('.route("/verify-email", get(browser_verify_email_page))');
    expect(appSource).toContain('let verify_response = app');
    expect(appSource).toContain('assert!(verify_body.contains("Check your email"));');
  });
});