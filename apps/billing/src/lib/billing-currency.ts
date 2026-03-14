import type { DatabasePool } from '@apexmail/db';

export const DEFAULT_BILLING_CURRENCY = 'USD';

export function normalizeBillingCurrency(currency: string | null | undefined): string {
  const normalized = currency?.trim().toUpperCase();
  if (normalized && /^[A-Z]{3}$/.test(normalized)) {
    return normalized;
  }
  return DEFAULT_BILLING_CURRENCY;
}

export async function resolveTenantBillingCurrency(
  db: DatabasePool,
  tenantId: string,
): Promise<string> {
  const result = await db.query<{ billing_currency: string | null }>(
    `SELECT settings->>'billingCurrency' AS billing_currency
     FROM tenants
     WHERE id = $1`,
    [tenantId],
  );

  if (!result.ok) {
    return DEFAULT_BILLING_CURRENCY;
  }

  return normalizeBillingCurrency(result.value.rows[0]?.billing_currency);
}