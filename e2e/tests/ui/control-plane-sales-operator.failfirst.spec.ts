import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';

import { expect, test } from '@playwright/test';

import { assertServiceReachable, serviceBaseUrl } from '../support/env';

function quoteLiteral(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function sql(query: string): string {
  return execFileSync(
    'psql',
    [
      '-P', 'pager=off',
      '-h', '127.0.0.1',
      '-p', '55432',
      '-U', 'apexmail',
      '-d', 'apexmail',
      '-At',
      '-v', 'ON_ERROR_STOP=1',
      '-c', query,
    ],
    {
      env: { ...process.env, PGPASSWORD: 'devpass123' },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  ).trim();
}

test.describe('control-plane sales operator live flow fail-first', () => {
  test.beforeEach(async ({}, testInfo) => {
    test.skip(!testInfo.project.name.includes('control-plane'), 'control-plane-only suite');
  });

  test('serves the Rust sales shell and exercises discovery and outreach with a real API key', async ({ page, request }) => {
    test.slow();
    test.setTimeout(180_000);

    const apiBaseUrl = serviceBaseUrl('api-server') ?? 'http://127.0.0.1:3000';
    await assertServiceReachable('api-server', apiBaseUrl);

    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const email = `playwright-sales-${suffix}@example.com`;
    const password = 'ApexMail!Pass1234';
    const discoveryDomain = `playwright-discovery-${suffix}.example.test`;
    const discoveryCompany = `Playwright Discovery ${suffix}`;
    const outreachLeadId = `plwlead_${suffix}`;
    const outreachCompany = `Playwright Outreach ${suffix}`;
    const outreachDomain = `playwright-outreach-${suffix}.example.test`;
    const outreachEmail = `ops+${suffix}@example.com`;
    const offerId = `runtime_ui_offer_${suffix}`;
    const templateName = 'runtime-ui';

    let tenantId = '';
    let bearerToken = '';
    let apiKeyId = '';

    try {
      const register = await request.post(`${apiBaseUrl}/v1/auth/register`, {
        data: {
          company_name: 'Playwright Sales Validation',
          email,
          name: 'Playwright Operator',
          password,
          plan: 'free',
        },
      });
      expect(register.status()).toBe(202);

      const login = await request.post(`${apiBaseUrl}/v1/auth/login`, {
        data: { email, password },
      });
      expect(login.status()).toBe(200);
      const loginBody = await login.json();
      bearerToken = loginBody.token as string;
      tenantId = loginBody.user.tenant_id as string;

      expect(typeof bearerToken).toBe('string');
      expect(bearerToken.length).toBeGreaterThan(0);
      expect(typeof tenantId).toBe('string');
      expect(tenantId.length).toBeGreaterThan(0);

      const apiKeyResponse = await request.post(`${apiBaseUrl}/v1/auth/api-keys`, {
        headers: { authorization: `Bearer ${bearerToken}` },
        data: {
          name: `Playwright sales operator ${suffix}`,
          scopes: ['*'],
        },
      });
      expect(apiKeyResponse.status()).toBe(201);
      const apiKeyBody = await apiKeyResponse.json();
      apiKeyId = apiKeyBody.id as string;
      const apiKey = apiKeyBody.key as string;

      expect(typeof apiKey).toBe('string');
      expect(apiKey.length).toBeGreaterThan(0);

      sql(`
        INSERT INTO enriched_companies (
          id, tenant_id, domain, company_name, industry, description, last_enriched_at, created_at, updated_at
        ) VALUES (
          ${quoteLiteral(randomUUID())},
          ${quoteLiteral(tenantId)},
          ${quoteLiteral(discoveryDomain)},
          ${quoteLiteral(discoveryCompany)},
          'security software',
          'playwright discovery seed',
          NOW() + INTERVAL '1 day',
          NOW(),
          NOW()
        );

        INSERT INTO sales_leads (
          tenant_id, id, company_name, domain, status, source, notes, score, contact_email, contact_name, tags, created_at, updated_at
        ) VALUES (
          ${quoteLiteral(tenantId)},
          ${quoteLiteral(outreachLeadId)},
          ${quoteLiteral(outreachCompany)},
          ${quoteLiteral(outreachDomain)},
          'new',
          'playwright-seed',
          'playwright outreach seed',
          88,
          ${quoteLiteral(outreachEmail)},
          'Playwright Contact',
          '["playwright"]'::jsonb,
          NOW(),
          NOW()
        );
      `);

      const response = await page.goto('/sales', { waitUntil: 'domcontentloaded' });
      if (response) {
        expect(response.status()).toBeLessThan(500);
      }

      await expect(page.getByRole('heading', { name: /operator console/i })).toBeVisible();
      await expect(page.getByLabel(/api base url/i)).toBeVisible();
      await expect(page.getByLabel(/admin api key/i)).toBeVisible();
      await expect(page.getByRole('button', { name: /^connect$/i })).toBeVisible();

      const adminHeaders = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      };

      const leadSnapshot = await request.get(`${apiBaseUrl}/v1/admin/sales/leads`, {
        headers: adminHeaders,
      });
      expect(leadSnapshot.status()).toBe(200);
      const leadSnapshotBody = await leadSnapshot.json() as { leads: Array<{ id: string; companyName: string; domain: string }> };
      expect(leadSnapshotBody.leads.some((lead) => lead.id === outreachLeadId || lead.companyName === outreachCompany)).toBe(true);

      const discoveryRun = await request.post(`${apiBaseUrl}/v1/admin/sales/discovery/run`, {
        headers: adminHeaders,
        data: {
          sources: ['runtime-ui'],
          categories: ['security'],
          maxPages: 1,
        },
      });
      expect(discoveryRun.status()).toBe(200);
      const discoveryBody = await discoveryRun.json() as { status: string; discovered: number; imported: number };
      expect(discoveryBody.status).toBe('completed');
      expect(discoveryBody.discovered).toBeGreaterThanOrEqual(1);
      expect(discoveryBody.imported).toBeGreaterThanOrEqual(1);

      const discoveredLeads = await request.get(`${apiBaseUrl}/v1/admin/sales/leads`, {
        headers: adminHeaders,
      });
      expect(discoveredLeads.status()).toBe(200);
      const discoveredLeadsBody = await discoveredLeads.json() as { leads: Array<{ domain: string }> };
      expect(discoveredLeadsBody.leads.some((lead) => lead.domain === discoveryDomain)).toBe(true);

      const outreachStart = await request.post(`${apiBaseUrl}/v1/admin/sales/outreach/start`, {
        headers: adminHeaders,
        data: {
          leadIds: [outreachLeadId],
          offerId,
          templateName,
          subject: `Runtime UI ${suffix}`,
        },
      });
      expect(outreachStart.status()).toBe(200);
      const outreachBody = await outreachStart.json() as { success: boolean; campaignId: string; leadsEnrolled: number; template: string };
      expect(outreachBody.success).toBe(true);
      expect(outreachBody.leadsEnrolled).toBe(1);
      expect(outreachBody.template).toBe(templateName);

      const campaigns = await request.get(`${apiBaseUrl}/v1/admin/sales/campaigns`, {
        headers: {
          Accept: 'application/json',
          'x-api-key': apiKey,
        },
      });
      expect(campaigns.status()).toBe(200);
      const campaignList = await campaigns.json() as Array<{ id: string; name: string }>;
      expect(campaignList.some((campaign) => campaign.id === outreachBody.campaignId && /runtime ui offer/i.test(campaign.name))).toBe(true);
    } finally {
      if (bearerToken && apiKeyId) {
        await request.delete(`${apiBaseUrl}/v1/auth/api-keys/${apiKeyId}`, {
          headers: { authorization: `Bearer ${bearerToken}` },
        }).catch(() => undefined);
      }

      try {
        sql(`
          DELETE FROM drip_campaigns
          WHERE id IN (
            SELECT campaign_id FROM campaign_recipients WHERE lead_id = ${quoteLiteral(outreachLeadId)}
          );
          DELETE FROM sales_leads WHERE id = ${quoteLiteral(outreachLeadId)};
          DELETE FROM sales_leads WHERE domain = ${quoteLiteral(discoveryDomain)};
          DELETE FROM enriched_companies WHERE domain = ${quoteLiteral(discoveryDomain)};
        `);
      } catch {
        // cleanup is best-effort for this live test
      }
    }
  });
});