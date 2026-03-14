/**
 * Enterprise Billing Service
 * Contract management, purchase orders, and custom pricing
 */

import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger();

export interface Contract {
  id: string;
  tenantId: string;
  name: string;
  status: 'draft' | 'pending_signature' | 'active' | 'expired' | 'terminated';
  startDate: Date;
  endDate: Date;
  autoRenew: boolean;
  
  // Pricing
  basePrice: number;              // Monthly base fee in cents
  committedVolume: number;        // Committed email volume
  overageRate: number;            // Per-email overage rate in cents
  annualPrepayDiscount: number;   // Percentage discount for annual prepay
  
  // Additional fees
  additionalFees: Array<{
    name: string;
    amount: number;
    frequency: 'one_time' | 'monthly' | 'yearly';
  }>;
  
  // Terms
  paymentTermsDays: number;       // Net payment terms (e.g., 30, 60)
  slaCreditPercentage: number;    // SLA credit percentage
  customTerms: string | null;
  
  // Metadata
  signedAt: Date | null;
  signedBy: string | null;
  purchaseOrderNumber: string | null;
  
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateContractInput {
  tenantId: string;
  name: string;
  startDate: Date;
  endDate: Date;
  autoRenew?: boolean;
  basePrice: number;
  committedVolume: number;
  overageRate: number;
  annualPrepayDiscount?: number;
  additionalFees?: Contract['additionalFees'];
  paymentTermsDays?: number;
  slaCreditPercentage?: number;
  customTerms?: string;
}

type ContractRow = {
  id: string;
  tenant_id: string;
  name: string;
  status: Contract['status'];
  start_date: Date;
  end_date: Date;
  auto_renew: boolean;
  base_price: number;
  committed_volume: number;
  overage_rate: number;
  annual_prepay_discount: number;
  additional_fees: string;
  payment_terms_days: number;
  sla_credit_percentage: number;
  custom_terms: string | null;
  signed_at: Date | null;
  signed_by: string | null;
  purchase_order_number: string | null;
  created_at: Date;
  updated_at: Date;
};

/**
 * Enterprise contract management service
 */
export class EnterpriseContractService {
  constructor(private readonly db: DatabasePool) {}

  /**
   * Create a new contract
   */
  async createContract(input: CreateContractInput): Promise<Result<Contract, Error>> {
    const result = await this.db.query<ContractRow>(
      `INSERT INTO enterprise_contracts (
        id, tenant_id, name, status, start_date, end_date, auto_renew,
        base_price, committed_volume, overage_rate, annual_prepay_discount,
        additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
        created_at, updated_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, 'draft', $3, $4, $5,
        $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW()
      )
      RETURNING *`,
      [
        input.tenantId,
        input.name,
        input.startDate,
        input.endDate,
        input.autoRenew ?? false,
        input.basePrice,
        input.committedVolume,
        input.overageRate,
        input.annualPrepayDiscount ?? 0,
        JSON.stringify(input.additionalFees ?? []),
        input.paymentTermsDays ?? 30,
        input.slaCreditPercentage ?? 10,
        input.customTerms ?? null,
      ]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Failed to create contract'));

    return Result.ok(this.mapRow(row));
  }

  /**
   * Activate a contract (after signature)
   * CRITICAL: Uses atomic CTE to ensure contract and tenant are updated together
   */
  async activateContract(
    contractId: string,
    signedBy: string,
    purchaseOrderNumber?: string
  ): Promise<Result<Contract, Error>> {
    // Use atomic CTE to activate contract and upgrade tenant plan together
    const result = await this.db.query<ContractRow>(
      `WITH activate_contract AS (
        UPDATE enterprise_contracts
        SET status = 'active',
            signed_at = NOW(),
            signed_by = $2,
            purchase_order_number = $3,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
      ),
      upgrade_tenant AS (
        UPDATE tenants 
        SET plan = 'enterprise', updated_at = NOW()
        WHERE id = (SELECT tenant_id FROM activate_contract)
        RETURNING id
      )
      SELECT * FROM activate_contract`,
      [contractId, signedBy, purchaseOrderNumber ?? null]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Contract not found'));

    logger.info('Contract activated', { contractId, tenantId: row.tenant_id });

    return Result.ok(this.mapRow(row));
  }

  /**
   * Calculate contract billing for a period
   */
  async calculateContractBilling(
    contractId: string,
    periodStart: Date,
    periodEnd: Date
  ): Promise<Result<{
    baseCharge: number;
    additionalFees: number;
    overageCharge: number;
    totalCharge: number;
    lineItems: Array<{
      description: string;
      amount: number;
    }>;
  }, Error>> {
    // Get contract details
    const contractResult = await this.getContract(contractId);
    if (!contractResult.ok) return Result.err(contractResult.error);
    
    const contract = contractResult.value;
    if (!contract) return Result.err(new Error('Contract not found'));

    const lineItems: Array<{ description: string; amount: number }> = [];

    // Base price
    lineItems.push({
      description: 'Monthly Platform Fee',
      amount: contract.basePrice,
    });

    // Additional fees (monthly only for this period)
    let additionalFees = 0;
    for (const fee of contract.additionalFees) {
      if (fee.frequency === 'monthly') {
        lineItems.push({
          description: fee.name,
          amount: fee.amount,
        });
        additionalFees += fee.amount;
      }
    }

    // Calculate usage overage
    const usageResult = await this.db.query<{ total: string }>(
      `SELECT COALESCE(SUM(quantity), 0)::text as total
       FROM metering_events
       WHERE tenant_id = $1
         AND event_type = 'emails_sent'
         AND timestamp >= $2
         AND timestamp < $3`,
      [contract.tenantId, periodStart, periodEnd]
    );

    const totalUsage = usageResult.ok 
      ? parseInt(usageResult.value.rows[0]?.total ?? '0', 10) 
      : 0;

    // Calculate monthly committed volume
    const monthsInContract = Math.max(1, Math.ceil(
      (contract.endDate.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
    ));
    const monthIndex = Math.max(0, Math.floor(
      (periodStart.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
    ));
    const monthlyCommitted = this.calculateMonthlyCommittedVolume(
      contract.committedVolume,
      monthsInContract,
      monthIndex
    );

    let overageCharge = 0;
    if (totalUsage > monthlyCommitted) {
      const overageAmount = totalUsage - monthlyCommitted;
      overageCharge = overageAmount * contract.overageRate;
      lineItems.push({
        description: `Overage (${overageAmount.toLocaleString()} emails @ $${(contract.overageRate / 100).toFixed(4)}/email)`,
        amount: overageCharge,
      });
    }

    const totalCharge = contract.basePrice + additionalFees + overageCharge;

    return Result.ok({
      baseCharge: contract.basePrice,
      additionalFees,
      overageCharge,
      totalCharge,
      lineItems,
    });
  }

  /**
   * Get contract by ID
   */
  async getContract(contractId: string, tenantId?: string): Promise<Result<Contract | null, Error>> {
    const result = await this.db.query<ContractRow>(
      `SELECT id, tenant_id, name, status, start_date, end_date, auto_renew,
              base_price, committed_volume, overage_rate, annual_prepay_discount,
              additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
              signed_at, signed_by, purchase_order_number, created_at, updated_at
       FROM enterprise_contracts
       WHERE id = $1
         AND ($2::text IS NULL OR tenant_id = $2)`,
      [contractId, tenantId ?? null]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok(this.mapRow(row));
  }

  /**
   * Get active contract for tenant
   */
  async getActiveContract(tenantId: string): Promise<Result<Contract | null, Error>> {
    const result = await this.db.query<ContractRow>(
      `SELECT id, tenant_id, name, status, start_date, end_date, auto_renew,
              base_price, committed_volume, overage_rate, annual_prepay_discount,
              additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
              signed_at, signed_by, purchase_order_number, created_at, updated_at
       FROM enterprise_contracts 
       WHERE tenant_id = $1 AND status = 'active'
       ORDER BY created_at DESC
       LIMIT 1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok(this.mapRow(row));
  }

  /**
   * Check for expiring contracts (run daily)
   */
  async checkExpiringContracts(): Promise<Result<{
    expiringSoon: string[];
    expired: string[];
  }, Error>> {
    const now = new Date();
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

    // Find contracts expiring in 30 days and queue notifications atomically
    const expiringResult = await this.db.query<{ id: string; tenant_id: string }>(
      `WITH expiring_contracts AS (
        SELECT id, tenant_id FROM enterprise_contracts
        WHERE status = 'active'
          AND end_date <= $1
          AND end_date > $2
      ),
      queue_notifications AS (
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        SELECT gen_random_uuid(), tenant_id, 'contract_expiring', jsonb_build_object('contractId', id), 'pending', NOW()
        FROM expiring_contracts
        ON CONFLICT (tenant_id, type) WHERE status = 'pending'
        DO NOTHING
        RETURNING tenant_id
      )
      SELECT id, tenant_id FROM expiring_contracts`,
      [thirtyDaysFromNow, now]
    );

    const expiringSoon: string[] = [];
    if (expiringResult.ok) {
      expiringSoon.push(...expiringResult.value.rows.map(r => r.id));
    }

    // Handle expired contracts atomically - auto-renew or expire and downgrade
    const expiredResult = await this.db.query<{
      id: string;
      action: string;
    }>(
      `WITH expired_contracts AS (
        SELECT id, tenant_id, auto_renew FROM enterprise_contracts
        WHERE status = 'active' AND end_date <= $1
      ),
      auto_renew_contracts AS (
        UPDATE enterprise_contracts 
        SET end_date = end_date + INTERVAL '1 year', updated_at = NOW()
        WHERE id IN (SELECT id FROM expired_contracts WHERE auto_renew = true)
        RETURNING id, 'renewed' as action
      ),
      expire_contracts AS (
        UPDATE enterprise_contracts 
        SET status = 'expired', updated_at = NOW()
        WHERE id IN (SELECT id FROM expired_contracts WHERE auto_renew = false)
        RETURNING id, tenant_id, 'expired' as action
      ),
      downgrade_tenants AS (
        UPDATE tenants 
        SET plan = 'scale', updated_at = NOW()
        WHERE id IN (SELECT tenant_id FROM expire_contracts)
        RETURNING id
      )
      SELECT id, action FROM auto_renew_contracts
      UNION ALL
      SELECT id, action FROM expire_contracts`,
      [now]
    );

    const expired: string[] = [];
    if (expiredResult.ok) {
      for (const row of expiredResult.value.rows) {
        if (row.action === 'renewed') {
          logger.info('Contract auto-renewed', { contractId: row.id });
        } else {
          expired.push(row.id);
          logger.info('Contract expired', { contractId: row.id });
        }
      }
    }

    return Result.ok({ expiringSoon, expired });
  }

  /**
   * Generate contract PDF content
   */
  generateContractPdf(contract: Contract): string {
    // FIX-500-363: HTML-escape user-provided fields to prevent XSS in generated PDFs
    const esc = (s: string | undefined | null): string => {
      if (!s) return '';
      return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    };
    const formatCurrency = (cents: number): string =>
      `€${(cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

    const formatDate = (date: Date): string =>
      date.toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });

    const clientName = contract.name || `Tenant ${contract.tenantId}`;
    const clientAddress = `Tenant ID: ${contract.tenantId}`;
    const clientVatOrReference = contract.purchaseOrderNumber
      ? `PO Number: ${contract.purchaseOrderNumber}`
      : 'VAT Number: Not provided';

    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enterprise Contract - ${esc(contract.name)}</title>
  <style>
    body { font-family: 'Georgia', serif; font-size: 11pt; line-height: 1.6; margin: 60px; color: #333; }
    h1 { font-size: 18pt; margin-bottom: 30px; text-align: center; }
    h2 { font-size: 14pt; margin-top: 30px; border-bottom: 1px solid #ccc; padding-bottom: 5px; }
    .parties { margin: 30px 0; }
    .party { margin-bottom: 20px; }
    .section { margin: 20px 0; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
    th { background: #f5f5f5; }
    .signature-block { margin-top: 60px; display: flex; justify-content: space-between; }
    .signature-line { width: 45%; }
    .signature-line hr { border: none; border-top: 1px solid #333; margin: 40px 0 10px 0; }
    .footer { margin-top: 60px; font-size: 9pt; color: #666; text-align: center; }
  </style>
</head>
<body>
  <h1>Enterprise Services Agreement</h1>
  <p style="text-align: center">Contract Reference: ${contract.id.substring(0, 8).toUpperCase()}</p>

  <div class="parties">
    <div class="party">
      <strong>Service Provider:</strong><br>
      Bel Consulting OÜ (trading as ApexMail)<br>
      Sakala 7-2, 10141 Tallinn, Estonia<br>
      Registry Code: 16192499<br>
      VAT: EE102951727
    </div>
    <div class="party">
      <strong>Client:</strong><br>
          ${esc(clientName)}<br>
          ${esc(clientAddress)}<br>
          ${esc(clientVatOrReference)}
    </div>
  </div>

  <h2>1. Contract Term</h2>
  <div class="section">
    <p><strong>Start Date:</strong> ${formatDate(contract.startDate)}</p>
    <p><strong>End Date:</strong> ${formatDate(contract.endDate)}</p>
    <p><strong>Auto-Renewal:</strong> ${contract.autoRenew ? 'Yes - automatically renews for successive 1-year terms unless terminated with 30 days notice' : 'No'}</p>
  </div>

  <h2>2. Service Fees</h2>
  <table>
    <tr>
      <th>Description</th>
      <th>Amount</th>
    </tr>
    <tr>
      <td>Monthly Platform Fee</td>
      <td>${formatCurrency(contract.basePrice)}/month</td>
    </tr>
    <tr>
      <td>Committed Email Volume</td>
      <td>${contract.committedVolume.toLocaleString()} emails/year</td>
    </tr>
    <tr>
      <td>Overage Rate</td>
      <td>${formatCurrency(contract.overageRate)}/email</td>
    </tr>
    ${contract.annualPrepayDiscount > 0 ? `
    <tr>
      <td>Annual Prepayment Discount</td>
      <td>${contract.annualPrepayDiscount}%</td>
    </tr>
    ` : ''}
    ${contract.additionalFees.map(fee => `
    <tr>
      <td>${esc(fee.name)} (${esc(fee.frequency)})</td>
      <td>${formatCurrency(fee.amount)}</td>
    </tr>
    `).join('')}
  </table>

  <h2>3. Payment Terms</h2>
  <div class="section">
    <p>Payment is due within ${contract.paymentTermsDays} days of invoice date (Net ${contract.paymentTermsDays}).</p>
    <p>Invoices will be issued monthly in arrears for usage and monthly fees.</p>
    ${contract.purchaseOrderNumber ? `<p><strong>Purchase Order:</strong> ${esc(contract.purchaseOrderNumber)}</p>` : ''}
  </div>

  <h2>4. Service Level Agreement</h2>
  <div class="section">
    <p>Service Provider commits to the following service levels:</p>
    <ul>
      <li><strong>Availability:</strong> 99.9% monthly uptime</li>
      <li><strong>API Latency:</strong> &lt;200ms p95 response time</li>
      <li><strong>Support Response:</strong> 1 hour for P1 incidents</li>
    </ul>
    <p>In the event of SLA breach, Client shall receive a service credit of ${contract.slaCreditPercentage}% of monthly fees.</p>
  </div>

  <h2>5. Data Protection</h2>
  <div class="section">
    <p>Service Provider shall process personal data in accordance with GDPR and the Data Processing Agreement executed separately.</p>
    <p>Data residency: European Union (Estonia)</p>
  </div>

  ${contract.customTerms ? `
  <h2>6. Additional Terms</h2>
  <div class="section">
    <p>${esc(contract.customTerms)}</p>
  </div>
  ` : ''}

  <div class="signature-block">
    <div class="signature-line">
      <hr>
      <p>For Bel Consulting OÜ (ApexMail)</p>
      <p>Name: _________________</p>
      <p>Title: _________________</p>
      <p>Date: _________________</p>
    </div>
    <div class="signature-line">
      <hr>
      <p>For Client</p>
      <p>Name: ${esc(contract.signedBy) || '_________________'}</p>
      <p>Title: _________________</p>
      <p>Date: ${contract.signedAt ? formatDate(contract.signedAt) : '_________________'}</p>
    </div>
  </div>

  <div class="footer">
    <p>This agreement is governed by the laws of the Republic of Estonia.</p>
    <p>Bel Consulting OÜ (trading as ApexMail) • Sakala 7-2 • 10141 Tallinn • Estonia • info@apexmail.ee</p>
    <p>Reg. 16192499 • VAT: EE102951727</p>
  </div>
</body>
</html>`;
  }

  private mapRow(row: ContractRow): Contract {
    // Safe JSON parsing for additional_fees
    let additionalFees: Contract['additionalFees'] = [];
    try {
      additionalFees = JSON.parse(row.additional_fees || '[]') as Contract['additionalFees'];
    } catch (error) {
      logger.warn('Failed to parse contract additional fees', { contractId: row.id, error });
    }
    
    return {
      id: row.id,
      tenantId: row.tenant_id,
      name: row.name,
      status: row.status,
      startDate: row.start_date,
      endDate: row.end_date,
      autoRenew: row.auto_renew,
      basePrice: row.base_price,
      committedVolume: row.committed_volume,
      overageRate: row.overage_rate,
      annualPrepayDiscount: row.annual_prepay_discount,
      additionalFees,
      paymentTermsDays: row.payment_terms_days,
      slaCreditPercentage: row.sla_credit_percentage,
      customTerms: row.custom_terms,
      signedAt: row.signed_at,
      signedBy: row.signed_by,
      purchaseOrderNumber: row.purchase_order_number,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  private calculateMonthlyCommittedVolume(
    committedVolume: number,
    monthsInContract: number,
    monthIndex: number
  ): number {
    const safeMonths = Math.max(1, monthsInContract);
    const boundedMonthIndex = Math.min(Math.max(0, monthIndex), safeMonths - 1);
    const baseMonthly = Math.floor(committedVolume / safeMonths);
    const remainder = committedVolume % safeMonths;
    return baseMonthly + (boundedMonthIndex < remainder ? 1 : 0);
  }

  /**
   * List all contracts for a tenant
   */
  async listContracts(tenantId: string): Promise<Result<Contract[], Error>> {
    const result = await this.db.query<ContractRow>(
      `SELECT id, tenant_id, name, status, start_date, end_date, auto_renew,
              base_price, committed_volume, overage_rate, annual_prepay_discount,
              additional_fees, payment_terms_days, sla_credit_percentage, custom_terms,
              signed_at, signed_by, purchase_order_number, created_at, updated_at
       FROM enterprise_contracts WHERE tenant_id = $1 ORDER BY created_at DESC`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    return Result.ok(result.value.rows.map(row => this.mapRow(row)));
  }

  /**
   * Get contract usage
   */
  async getContractUsage(tenantId: string, contractId: string): Promise<Result<{
    currentUsage: number;
    committedVolume: number;
    percentUsed: number;
    projectedUsage: number;
    overageEstimate: number;
  }, Error>> {
    const contractResult = await this.getContract(contractId, tenantId);
    if (!contractResult.ok) return Result.err(contractResult.error);
    if (!contractResult.value) return Result.err(new Error('Contract not found'));

    const contract = contractResult.value;
    
    // Calculate current period dates based on contract
    const now = new Date();
    const contractStart = new Date(contract.startDate);
    
    // Calculate which period we're in (monthly periods from contract start)
    const monthsSinceStart = Math.floor(
      (now.getTime() - contractStart.getTime()) / (1000 * 60 * 60 * 24 * 30)
    );
    
    // SECURITY: Use UTC-based date manipulation for billing consistency
    const periodStart = new Date(contractStart.getTime());
    periodStart.setUTCMonth(periodStart.getUTCMonth() + monthsSinceStart);
    const periodEnd = new Date(periodStart.getTime());
    periodEnd.setUTCMonth(periodEnd.getUTCMonth() + 1);
    
    // Query actual usage from usage_events table
    const usageResult = await this.db.query<{ total: string }>(
      `SELECT COALESCE(SUM(quantity), 0)::text as total
       FROM metering_events
       WHERE tenant_id = $1
         AND event_type = 'emails_sent'
         AND timestamp >= $2
         AND timestamp < $3`,
      [tenantId, periodStart, periodEnd]
    );

    const currentUsage = usageResult.ok 
      ? parseInt(usageResult.value.rows[0]?.total ?? '0', 10) 
      : 0;

    // Calculate committed volume for the current period
    const monthsInContract = Math.max(1, Math.ceil(
      (contract.endDate.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
    ));
    const monthlyCommitted = this.calculateMonthlyCommittedVolume(
      contract.committedVolume,
      monthsInContract,
      monthsSinceStart
    );
    
    // Calculate percentage used
    const percentUsed = monthlyCommitted > 0 ? (currentUsage / monthlyCommitted) * 100 : 0;
    
    // Project usage based on current rate and time elapsed in period
    const daysSincePeriodStart = Math.max(1, Math.floor(
      (now.getTime() - periodStart.getTime()) / (1000 * 60 * 60 * 24)
    ));
    const daysInPeriod = Math.max(1, Math.floor(
      (periodEnd.getTime() - periodStart.getTime()) / (1000 * 60 * 60 * 24)
    ));
    // Guard against division by zero (daysSincePeriodStart is already guarded with Math.max(1, ...))
    const dailyRate = currentUsage / daysSincePeriodStart;
    const projectedUsage = Math.floor(dailyRate * daysInPeriod);
    
    // Estimate overage based on projected usage
    const projectedOverage = Math.max(0, projectedUsage - monthlyCommitted);
    const overageEstimate = projectedOverage * contract.overageRate;

    return Result.ok({
      currentUsage,
      committedVolume: monthlyCommitted,
      percentUsed,
      projectedUsage,
      overageEstimate,
    });
  }

  /**
   * Submit contract for signature
   */
  async submitForSignature(tenantId: string, contractId: string): Promise<Result<Contract, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      status: Contract['status'];
      start_date: Date;
      end_date: Date;
      auto_renew: boolean;
      base_price: number;
      committed_volume: number;
      overage_rate: number;
      annual_prepay_discount: number;
      additional_fees: string;
      payment_terms_days: number;
      sla_credit_percentage: number;
      custom_terms: string | null;
      signed_at: Date | null;
      signed_by: string | null;
      purchase_order_number: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE enterprise_contracts SET status = 'pending_signature', updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2 RETURNING *`,
      [contractId, tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Contract not found'));
    return Result.ok(this.mapRow(row));
  }

  /**
   * Sign contract
   */
  async signContract(tenantId: string, contractId: string, data: {
    signatureData: string;
    signerName: string;
    signerTitle: string;
    signedAt: Date;
  }): Promise<Result<Contract, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      status: Contract['status'];
      start_date: Date;
      end_date: Date;
      auto_renew: boolean;
      base_price: number;
      committed_volume: number;
      overage_rate: number;
      annual_prepay_discount: number;
      additional_fees: string;
      payment_terms_days: number;
      sla_credit_percentage: number;
      custom_terms: string | null;
      signed_at: Date | null;
      signed_by: string | null;
      purchase_order_number: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE enterprise_contracts SET 
        status = 'active', 
        signed_at = $2, 
        signed_by = $3,
        updated_at = NOW() 
       WHERE id = $1 AND tenant_id = $4 RETURNING *`,
      [contractId, data.signedAt, `${data.signerName} (${data.signerTitle})`, tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Contract not found'));
    logger.info('Contract signed', { contractId, signedBy: data.signerName });
    return Result.ok(this.mapRow(row));
  }

  /**
   * Request contract amendment
   * 
   * Amendments are stored in the contract_amendments table and go through
   * an approval workflow before being applied to the contract.
   */
  async requestAmendment(tenantId: string, contractId: string, amendment: {
    reason: string;
    proposedChanges: Record<string, unknown>;
  }): Promise<Result<{ id: string; status: string }, Error>> {
    // Create amendment record in contract_amendments table
    const result = await this.db.query<{ id: string; status: string }>(
      `INSERT INTO contract_amendments (
        contract_id, reason, proposed_changes, status, created_at
      )
      SELECT c.id, $3, $4, 'pending', NOW()
      FROM enterprise_contracts c
      WHERE c.id = $1 AND c.tenant_id = $2
      RETURNING id, status`,
      [contractId, tenantId, amendment.reason, JSON.stringify(amendment.proposedChanges)]
    );
    
    if (!result.ok) {
      logger.error('Failed to create amendment', { contractId, error: result.error });
      return Result.err(result.error);
    }
    
    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Contract not found'));
    }

    logger.info('Amendment requested', { 
      contractId, 
      amendmentId: row.id,
      reason: amendment.reason,
    });
    
    return Result.ok({ id: row.id, status: row.status });
  }

  /**
   * Cancel contract
   */
  async cancelContract(tenantId: string, contractId: string, data: {
    reason: string;
    effectiveDate?: Date;
  }): Promise<Result<Contract, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      status: Contract['status'];
      start_date: Date;
      end_date: Date;
      auto_renew: boolean;
      base_price: number;
      committed_volume: number;
      overage_rate: number;
      annual_prepay_discount: number;
      additional_fees: string;
      payment_terms_days: number;
      sla_credit_percentage: number;
      custom_terms: string | null;
      signed_at: Date | null;
      signed_by: string | null;
      purchase_order_number: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE enterprise_contracts SET 
        status = 'terminated', 
        end_date = $2,
        updated_at = NOW() 
       WHERE id = $1 AND tenant_id = $3 RETURNING *`,
      [contractId, data.effectiveDate || new Date(), tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Contract not found'));
    logger.info('Contract cancelled', { contractId, reason: data.reason });
    return Result.ok(this.mapRow(row));
  }

  /**
   * Get renewal quote
   */
  async getRenewalQuote(tenantId: string, contractId: string): Promise<Result<{
    currentContract: Contract;
    proposedTerms: {
      basePrice: number;
      committedVolume: number;
      overageRate: number;
    };
    savings: number;
  }, Error>> {
    const contractResult = await this.getContract(contractId, tenantId);
    if (!contractResult.ok) return Result.err(contractResult.error);
    if (!contractResult.value) return Result.err(new Error('Contract not found'));

    const contract = contractResult.value;
    // Offer 5% discount on renewal
    const discountedPrice = Math.floor(contract.basePrice * 0.95);

    return Result.ok({
      currentContract: contract,
      proposedTerms: {
        basePrice: discountedPrice,
        committedVolume: contract.committedVolume,
        overageRate: contract.overageRate,
      },
      savings: (contract.basePrice - discountedPrice) * 12,
    });
  }

  /**
   * Renew contract
   */
  async renewContract(tenantId: string, contractId: string, terms: {
    newEndDate: Date;
    newTerms?: {
      baseFee?: number;
      committedVolume?: Record<string, number>;
      overageRates?: Record<string, number>;
    };
  }): Promise<Result<Contract, Error>> {
    const existingResult = await this.getContract(contractId, tenantId);
    if (!existingResult.ok) return Result.err(existingResult.error);
    if (!existingResult.value) return Result.err(new Error('Contract not found'));

    const existing = existingResult.value;
    const newContract = await this.createContract({
      tenantId: existing.tenantId,
      name: `${existing.name} (Renewed)`,
      startDate: existing.endDate,
      endDate: terms.newEndDate,
      autoRenew: existing.autoRenew,
      basePrice: terms.newTerms?.baseFee ?? existing.basePrice,
      committedVolume: existing.committedVolume,
      overageRate: existing.overageRate,
      annualPrepayDiscount: existing.annualPrepayDiscount,
      paymentTermsDays: existing.paymentTermsDays,
      slaCreditPercentage: existing.slaCreditPercentage,
    });

    if (!newContract.ok) return Result.err(newContract.error);
    logger.info('Contract renewed', { oldContractId: contractId, newContractId: newContract.value.id });
    return newContract;
  }

  /**
   * Submit purchase order
   */
  async submitPurchaseOrder(tenantId: string, contractId: string, po: {
    poNumber: string;
    amount: number;
    issuedDate: Date;
    expiryDate?: Date;
    attachmentUrl?: string;
  }): Promise<Result<{ id: string; poNumber: string; status: string }, Error>> {
    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      name: string;
      status: Contract['status'];
      start_date: Date;
      end_date: Date;
      auto_renew: boolean;
      base_price: number;
      committed_volume: number;
      overage_rate: number;
      annual_prepay_discount: number;
      additional_fees: string;
      payment_terms_days: number;
      sla_credit_percentage: number;
      custom_terms: string | null;
      signed_at: Date | null;
      signed_by: string | null;
      purchase_order_number: string | null;
      created_at: Date;
      updated_at: Date;
    }>(
      `UPDATE enterprise_contracts SET 
        purchase_order_number = $2,
        updated_at = NOW() 
       WHERE id = $1 AND tenant_id = $3 RETURNING *`,
      [contractId, po.poNumber, tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    logger.info('Purchase order submitted', { contractId, poNumber: po.poNumber });
    return Result.ok({
      id: `po-${Date.now()}`,
      poNumber: po.poNumber,
      status: 'received',
    });
  }
}
