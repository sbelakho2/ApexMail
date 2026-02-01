/**
 * Enterprise Billing Service
 * Contract management, purchase orders, and custom pricing
 */

import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger('enterprise-billing');

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

/**
 * Enterprise contract management service
 */
export class EnterpriseContractService {
  constructor(private readonly db: DatabasePool) {}

  /**
   * Create a new contract
   */
  async createContract(input: CreateContractInput): Promise<Result<Contract, Error>> {
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
      `INSERT INTO contracts (
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
   */
  async activateContract(
    contractId: string,
    signedBy: string,
    purchaseOrderNumber?: string
  ): Promise<Result<Contract, Error>> {
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
      `UPDATE contracts
       SET status = 'active',
           signed_at = NOW(),
           signed_by = $2,
           purchase_order_number = $3,
           updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [contractId, signedBy, purchaseOrderNumber ?? null]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Contract not found'));

    // Upgrade tenant to enterprise plan
    await this.db.query(
      `UPDATE tenants SET plan = 'enterprise', updated_at = NOW() WHERE id = $1`,
      [row.tenant_id]
    );

    logger.info({ contractId, tenantId: row.tenant_id }, 'Contract activated');

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
       FROM usage_events
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
    const monthsInContract = Math.ceil(
      (contract.endDate.getTime() - contract.startDate.getTime()) / (1000 * 60 * 60 * 24 * 30)
    );
    const monthlyCommitted = Math.floor(contract.committedVolume / monthsInContract);

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
  async getContract(contractId: string): Promise<Result<Contract | null, Error>> {
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
      `SELECT * FROM contracts WHERE id = $1`,
      [contractId]
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
      `SELECT * FROM contracts 
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

    // Find contracts expiring in 30 days
    const expiringResult = await this.db.query<{ id: string; tenant_id: string }>(
      `SELECT id, tenant_id FROM contracts
       WHERE status = 'active'
         AND end_date <= $1
         AND end_date > $2`,
      [thirtyDaysFromNow, now]
    );

    const expiringSoon: string[] = [];
    if (expiringResult.ok) {
      for (const row of expiringResult.value.rows) {
        expiringSoon.push(row.id);
        
        // Queue renewal reminder
        await this.db.query(
          `INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
           VALUES (gen_random_uuid(), $1, 'contract_expiring', $2, 'pending', NOW())
           ON CONFLICT (tenant_id, type) WHERE status = 'pending'
           DO NOTHING`,
          [row.tenant_id, JSON.stringify({ contractId: row.id })]
        );
      }
    }

    // Find and handle expired contracts
    const expiredResult = await this.db.query<{
      id: string;
      tenant_id: string;
      auto_renew: boolean;
    }>(
      `SELECT id, tenant_id, auto_renew FROM contracts
       WHERE status = 'active' AND end_date <= $1`,
      [now]
    );

    const expired: string[] = [];
    if (expiredResult.ok) {
      for (const row of expiredResult.value.rows) {
        if (row.auto_renew) {
          // Auto-renew: extend by 1 year
          await this.db.query(
            `UPDATE contracts
             SET end_date = end_date + INTERVAL '1 year', updated_at = NOW()
             WHERE id = $1`,
            [row.id]
          );
          logger.info({ contractId: row.id }, 'Contract auto-renewed');
        } else {
          // Mark as expired
          await this.db.query(
            `UPDATE contracts SET status = 'expired', updated_at = NOW() WHERE id = $1`,
            [row.id]
          );
          
          // Downgrade tenant
          await this.db.query(
            `UPDATE tenants SET plan = 'scale', updated_at = NOW() WHERE id = $1`,
            [row.tenant_id]
          );
          
          expired.push(row.id);
          logger.info({ contractId: row.id }, 'Contract expired');
        }
      }
    }

    return Result.ok({ expiringSoon, expired });
  }

  /**
   * Generate contract PDF content
   */
  generateContractPdf(contract: Contract): string {
    const formatCurrency = (cents: number): string =>
      `€${(cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2 })}`;

    const formatDate = (date: Date): string =>
      date.toLocaleDateString('en-GB', { year: 'numeric', month: 'long', day: 'numeric' });

    return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Enterprise Contract - ${contract.name}</title>
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
      ApexMail OÜ<br>
      Tartu mnt 67/1-13b, 10115 Tallinn, Estonia<br>
      Registry Code: 16123456<br>
      VAT: EE102345678
    </div>
    <div class="party">
      <strong>Client:</strong><br>
      [Client Name]<br>
      [Client Address]<br>
      [Client VAT Number]
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
      <td>${fee.name} (${fee.frequency})</td>
      <td>${formatCurrency(fee.amount)}</td>
    </tr>
    `).join('')}
  </table>

  <h2>3. Payment Terms</h2>
  <div class="section">
    <p>Payment is due within ${contract.paymentTermsDays} days of invoice date (Net ${contract.paymentTermsDays}).</p>
    <p>Invoices will be issued monthly in arrears for usage and monthly fees.</p>
    ${contract.purchaseOrderNumber ? `<p><strong>Purchase Order:</strong> ${contract.purchaseOrderNumber}</p>` : ''}
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
    <p>${contract.customTerms}</p>
  </div>
  ` : ''}

  <div class="signature-block">
    <div class="signature-line">
      <hr>
      <p>For ApexMail OÜ</p>
      <p>Name: _________________</p>
      <p>Title: _________________</p>
      <p>Date: _________________</p>
    </div>
    <div class="signature-line">
      <hr>
      <p>For Client</p>
      <p>Name: ${contract.signedBy || '_________________'}</p>
      <p>Title: _________________</p>
      <p>Date: ${contract.signedAt ? formatDate(contract.signedAt) : '_________________'}</p>
    </div>
  </div>

  <div class="footer">
    <p>This agreement is governed by the laws of the Republic of Estonia.</p>
    <p>ApexMail OÜ • Tartu mnt 67/1-13b • 10115 Tallinn • Estonia • info@apexmail.ee</p>
  </div>
</body>
</html>`;
  }

  private mapRow(row: {
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
  }): Contract {
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
      additionalFees: JSON.parse(row.additional_fees),
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
}
