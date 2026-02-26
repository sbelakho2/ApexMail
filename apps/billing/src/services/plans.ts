/**
 * Plans Service
 * Manages pricing tiers with feature flags
 */

import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';

export interface Plan {
  id: string;
  name: string;
  displayName: string;
  description: string;
  priceMonthly: number; // In cents
  priceYearly: number;  // In cents (discounted)
  emailLimit: number;
  apiCallLimit: number;
  features: PlanFeatures;
  stripePriceIdMonthly: string | null;
  stripePriceIdYearly: string | null;
  isActive: boolean;
  sortOrder: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface PlanFeatures {
  // Infrastructure
  dedicatedIp: boolean;
  dedicatedIpCount: number;
  maxSendingDomains: number;
  
  // Authentication & Security
  ssoEnabled: boolean;
  auditLogs: boolean;
  
  // API & Integrations
  apiAccess: boolean;
  webhooksEnabled: boolean;
  inboundEmail: boolean;
  
  // Analytics & Data
  advancedAnalytics: boolean;
  sendTimeOptimization: boolean;
  abTesting: boolean;
  timeTravelDebugging: boolean;
  dataExport: boolean;
  
  // Customization
  customTrackingDomain: boolean;
  customTemplates: boolean;
  templateApprovalWorkflow: boolean;
  whiteLabel: boolean;
  poweredByFooter: boolean;
  
  // Retention
  customRetention: boolean;
  maxRetentionDays: number;
  
  // Team & Organization
  maxTeamMembers: number;
  subaccounts: boolean;
  maxSubaccounts: number;
  
  // Support
  supportLevel: 'community' | 'email' | 'priority' | 'phone' | 'dedicated';
  dedicatedCsm: boolean;
  priorityOnboarding: boolean;
  
  // Enterprise
  byoip: boolean;
  slaGuarantee: boolean;
  slaCreditPercentage: number;
  hipaaCompliance: boolean;
  soc2Compliance: boolean;
  privateCloud: boolean;
}

const DEFAULT_PLAN_FEATURES: PlanFeatures = {
  // Infrastructure
  dedicatedIp: false,
  dedicatedIpCount: 0,
  maxSendingDomains: 1,
  
  // Authentication & Security
  ssoEnabled: false,
  auditLogs: false,
  
  // API & Integrations
  apiAccess: true,
  webhooksEnabled: false,
  inboundEmail: false,
  
  // Analytics & Data
  advancedAnalytics: false,
  sendTimeOptimization: false,
  abTesting: false,
  timeTravelDebugging: false,
  dataExport: false,
  
  // Customization
  customTrackingDomain: false,
  customTemplates: false,
  templateApprovalWorkflow: false,
  whiteLabel: false,
  poweredByFooter: true,
  
  // Retention
  customRetention: false,
  maxRetentionDays: 7,
  
  // Team & Organization
  maxTeamMembers: 1,
  subaccounts: false,
  maxSubaccounts: 0,
  
  // Support
  supportLevel: 'community',
  dedicatedCsm: false,
  priorityOnboarding: false,
  
  // Enterprise
  byoip: false,
  slaGuarantee: false,
  slaCreditPercentage: 0,
  hipaaCompliance: false,
  soc2Compliance: false,
  privateCloud: false,
};

/**
 * Pay As You Go pricing configuration
 * All prices in integer cents/millicents
 */
export const PAYG_PRICING = {
  // Email pricing tiers (price per email in millicents, with volume discounts)
  emailPricing: [
    { upTo: 10000, pricePerEmailMillicents: 100 },      // $0.001/email for first 10k
    { upTo: 100000, pricePerEmailMillicents: 80 },      // $0.0008/email for 10k-100k
    { upTo: 1000000, pricePerEmailMillicents: 50 },     // $0.0005/email for 100k-1M
    { upTo: Infinity, pricePerEmailMillicents: 30 },    // $0.0003/email for 1M+
  ],
  // API call pricing (free up to limit, then charged)
  apiPricing: {
    freeCallsPerMonth: 100000,
    pricePerThousandCallsCents: 10, // $0.10 per 1000 API calls
  },
  // Minimum monthly charge
  minimumMonthlyChargeCents: 0, // No minimum
} as const;

/**
 * Calculate PAYG cost for a given usage
 */
export function calculatePaygCost(emailsSent: number, apiCalls: number): {
  emailCostCents: number;
  apiCostCents: number;
  totalCostCents: number;
  emailCostUsd: string;
  apiCostUsd: string;
  totalCostUsd: string;
} {
  const centsToUsdString = (cents: number): string => {
    const dollars = Math.floor(cents / 100);
    const remainder = cents % 100;
    return `$${dollars}.${remainder.toString().padStart(2, '0')}`;
  };

  let emailCostMillicents = 0;
  let remaining = emailsSent;

  for (let i = 0; i < PAYG_PRICING.emailPricing.length; i += 1) {
    const tier = PAYG_PRICING.emailPricing[i]!;
    if (remaining <= 0) break;
    const previousUpTo = PAYG_PRICING.emailPricing[i - 1]?.upTo ?? 0;
    const tierEmails = Math.min(remaining, tier.upTo - previousUpTo);
    emailCostMillicents += tierEmails * tier.pricePerEmailMillicents;
    remaining -= tierEmails;
  }

  // API costs (only for calls over free limit)
  const billableApiCalls = Math.max(0, apiCalls - PAYG_PRICING.apiPricing.freeCallsPerMonth);
  const apiCostCents =
    Math.ceil(billableApiCalls / 1000) * PAYG_PRICING.apiPricing.pricePerThousandCallsCents;

  const emailCostCents = Math.floor((emailCostMillicents + 500) / 1000);
  const minimumMonthlyChargeCents = PAYG_PRICING.minimumMonthlyChargeCents;
  const totalCostCents = Math.max(emailCostCents + apiCostCents, minimumMonthlyChargeCents);

  return {
    emailCostCents,
    apiCostCents,
    totalCostCents,
    emailCostUsd: centsToUsdString(emailCostCents),
    apiCostUsd: centsToUsdString(apiCostCents),
    totalCostUsd: centsToUsdString(totalCostCents),
  };
}

/**
 * Subscription overage pricing
 * $0.40 per 1,000 emails = $0.0004 per email = 0.04 cents per email
 */
export const OVERAGE_RATE_PER_EMAIL_MILLICENTS = 40; // $0.40/1K = 0.04 cents/email

/**
 * Calculate overage cost for subscription plans that exceed their monthly email limit.
 * Returns cost in cents.
 * 
 * @param emailsSent - Total emails sent in the billing period
 * @param emailLimit - Plan's email limit (-1 for unlimited)
 * @returns Overage cost in cents
 */
export function calculateOverageCost(emailsSent: number, emailLimit: number): number {
  // Unlimited plans (-1) have no overage
  if (emailLimit === -1) return 0;
  // No overage if within limit
  if (emailsSent <= emailLimit) return 0;
  
  const overageEmails = emailsSent - emailLimit;
  // Round up to nearest cent
  return Math.floor((overageEmails * OVERAGE_RATE_PER_EMAIL_MILLICENTS + 999) / 1000);
}

export interface CreatePlanInput {
  name: string;
  displayName: string;
  description: string;
  priceMonthly: number;
  priceYearly: number;
  emailLimit: number;
  apiCallLimit: number;
  features: PlanFeatures;
  stripePriceIdMonthly?: string;
  stripePriceIdYearly?: string;
  sortOrder?: number;
}

const DEFAULT_PLANS: CreatePlanInput[] = [
  {
    name: 'free',
    displayName: 'Free',
    description: 'Get started with basic email sending',
    priceMonthly: 0,
    priceYearly: 0,
    emailLimit: 3000,
    apiCallLimit: 50000,
    features: {
      dedicatedIp: false,
      dedicatedIpCount: 0,
      maxSendingDomains: 1,
      ssoEnabled: false,
      auditLogs: false,
      apiAccess: true,
      webhooksEnabled: false,
      inboundEmail: false,
      advancedAnalytics: false,
      sendTimeOptimization: false,
      abTesting: false,
      timeTravelDebugging: false,
      dataExport: false,
      customTrackingDomain: false,
      customTemplates: false,
      templateApprovalWorkflow: false,
      whiteLabel: false,
      poweredByFooter: true,
      customRetention: false,
      maxRetentionDays: 7,
      maxTeamMembers: 1,
      subaccounts: false,
      maxSubaccounts: 0,
      supportLevel: 'community',
      dedicatedCsm: false,
      priorityOnboarding: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 0,
  },
  {
    name: 'starter',
    displayName: 'Starter',
    description: 'For growing businesses with moderate email needs',
    priceMonthly: 2500, // $25
    priceYearly: 25000, // $250 (~17% discount)
    emailLimit: 50000,
    apiCallLimit: 500000,
    features: {
      dedicatedIp: false,
      dedicatedIpCount: 0,
      maxSendingDomains: 5,
      ssoEnabled: false,
      auditLogs: false,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: false,
      advancedAnalytics: true,
      sendTimeOptimization: false,
      abTesting: false,
      timeTravelDebugging: false,
      dataExport: true,
      customTrackingDomain: false,
      customTemplates: true,
      templateApprovalWorkflow: false,
      whiteLabel: false,
      poweredByFooter: false,
      customRetention: false,
      maxRetentionDays: 30,
      maxTeamMembers: 5,
      subaccounts: false,
      maxSubaccounts: 0,
      supportLevel: 'email',
      dedicatedCsm: false,
      priorityOnboarding: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 1,
  },
  {
    name: 'pro',
    displayName: 'Pro',
    description: 'For scaling teams with custom tracking needs',
    priceMonthly: 6500, // $65
    priceYearly: 65000, // $650 (~17% discount)
    emailLimit: 150000,
    apiCallLimit: 2000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 0,
      maxSendingDomains: 25,
      ssoEnabled: false,
      auditLogs: false,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: false,
      advancedAnalytics: true,
      sendTimeOptimization: true,
      abTesting: true,
      timeTravelDebugging: false,
      dataExport: true,
      customTrackingDomain: true,
      customTemplates: true,
      templateApprovalWorkflow: false,
      whiteLabel: false,
      poweredByFooter: false,
      customRetention: true,
      maxRetentionDays: 60,
      maxTeamMembers: 10,
      subaccounts: false,
      maxSubaccounts: 0,
      supportLevel: 'email',
      dedicatedCsm: false,
      priorityOnboarding: true,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 2,
  },
  {
    name: 'growth',
    displayName: 'Growth',
    description: 'For teams that need advanced deliverability features',
    priceMonthly: 15000, // $150
    priceYearly: 150000, // $1500 (~17% discount)
    emailLimit: 500000,
    apiCallLimit: 5000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 1,
      maxSendingDomains: 100,
      ssoEnabled: false,
      auditLogs: true,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: false,
      advancedAnalytics: true,
      sendTimeOptimization: true,
      abTesting: true,
      timeTravelDebugging: true,
      dataExport: true,
      customTrackingDomain: true,
      customTemplates: true,
      templateApprovalWorkflow: false,
      whiteLabel: false,
      poweredByFooter: false,
      customRetention: true,
      maxRetentionDays: 90,
      maxTeamMembers: 25,
      subaccounts: false,
      maxSubaccounts: 0,
      supportLevel: 'priority',
      dedicatedCsm: false,
      priorityOnboarding: true,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 3,
  },
  {
    name: 'scale',
    displayName: 'Scale',
    description: 'For high-volume senders needing isolation',
    priceMonthly: 35000, // $350
    priceYearly: 350000, // $3500 (~17% discount)
    emailLimit: 2000000,
    apiCallLimit: 20000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 3,
      maxSendingDomains: -1, // Unlimited
      ssoEnabled: true,
      auditLogs: true,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: true,
      advancedAnalytics: true,
      sendTimeOptimization: true,
      abTesting: true,
      timeTravelDebugging: true,
      dataExport: true,
      customTrackingDomain: true,
      customTemplates: true,
      templateApprovalWorkflow: true,
      whiteLabel: false,
      poweredByFooter: false,
      customRetention: true,
      maxRetentionDays: 365,
      maxTeamMembers: 50,
      subaccounts: true,
      maxSubaccounts: 10,
      supportLevel: 'phone',
      dedicatedCsm: true,
      priorityOnboarding: true,
      byoip: false,
      slaGuarantee: true,
      slaCreditPercentage: 10,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 4,
  },
  {
    name: 'enterprise',
    displayName: 'Enterprise',
    description: 'Custom solutions for large organizations',
    priceMonthly: 80000, // $800 (base)
    priceYearly: 800000, // $8000 (~17% discount)
    emailLimit: 5000000,
    apiCallLimit: -1, // Unlimited
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 10,
      maxSendingDomains: -1, // Unlimited
      ssoEnabled: true,
      auditLogs: true,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: true,
      advancedAnalytics: true,
      sendTimeOptimization: true,
      abTesting: true,
      timeTravelDebugging: true,
      dataExport: true,
      customTrackingDomain: true,
      customTemplates: true,
      templateApprovalWorkflow: true,
      whiteLabel: true,
      poweredByFooter: false,
      customRetention: true,
      maxRetentionDays: 730,
      maxTeamMembers: -1, // Unlimited
      subaccounts: true,
      maxSubaccounts: 100,
      supportLevel: 'dedicated',
      dedicatedCsm: true,
      priorityOnboarding: true,
      byoip: true,
      slaGuarantee: true,
      slaCreditPercentage: 25,
      hipaaCompliance: true,
      soc2Compliance: true,
      privateCloud: true,
    },
    sortOrder: 5,
  },
  {
    name: 'payg',
    displayName: 'Pay As You Go',
    description: 'Flexible usage-based pricing for variable volume',
    priceMonthly: 0, // No base fee
    priceYearly: 0,
    emailLimit: -1, // Unlimited (billed per use)
    apiCallLimit: -1, // Unlimited (billed per use)
    features: {
      dedicatedIp: false,
      dedicatedIpCount: 0,
      maxSendingDomains: 5,
      ssoEnabled: false,
      auditLogs: false,
      apiAccess: true,
      webhooksEnabled: true,
      inboundEmail: false,
      advancedAnalytics: true,
      sendTimeOptimization: false,
      abTesting: false,
      timeTravelDebugging: false,
      dataExport: true,
      customTrackingDomain: false,
      customTemplates: true,
      templateApprovalWorkflow: false,
      whiteLabel: false,
      poweredByFooter: false,
      customRetention: false,
      maxRetentionDays: 30,
      maxTeamMembers: 5,
      subaccounts: false,
      maxSubaccounts: 0,
      supportLevel: 'email',
      dedicatedCsm: false,
      priorityOnboarding: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      hipaaCompliance: false,
      soc2Compliance: false,
      privateCloud: false,
    },
    sortOrder: 6,
  },
];

/**
 * Plans management service
 */
export class PlansService {
  constructor(private readonly db: DatabasePool) {}

  /**
   * Initialize default plans
   */
  async initializeDefaultPlans(): Promise<Result<void, Error>> {
    const results = await Promise.all(DEFAULT_PLANS.map((plan) => this.createOrUpdatePlan(plan)));
    for (const result of results) {
      if (!result.ok) {
        return Result.err(result.error);
      }
    }

    return Result.ok(undefined);
  }

  /**
   * Create or update a plan
   */
  async createOrUpdatePlan(input: CreatePlanInput): Promise<Result<Plan, Error>> {
    const result = await this.db.query<{
      id: string;
      name: string;
      display_name: string;
      description: string;
      price_monthly: number;
      price_yearly: number;
      email_limit: number;
      api_call_limit: number;
      features: string;
      stripe_price_id_monthly: string | null;
      stripe_price_id_yearly: string | null;
      is_active: boolean;
      sort_order: number;
      created_at: Date;
      updated_at: Date;
    }>(
      `INSERT INTO plans (
        id, name, display_name, description, price_monthly, price_yearly,
        email_limit, api_call_limit, features, stripe_price_id_monthly,
        stripe_price_id_yearly, is_active, sort_order, created_at, updated_at
      )
      VALUES (
        gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11, NOW(), NOW()
      )
      ON CONFLICT (name) DO UPDATE SET
        display_name = $2,
        description = $3,
        price_monthly = $4,
        price_yearly = $5,
        email_limit = $6,
        api_call_limit = $7,
        features = $8,
        stripe_price_id_monthly = COALESCE($9, plans.stripe_price_id_monthly),
        stripe_price_id_yearly = COALESCE($10, plans.stripe_price_id_yearly),
        sort_order = $11,
        updated_at = NOW()
      RETURNING *`,
      [
        input.name,
        input.displayName,
        input.description,
        input.priceMonthly,
        input.priceYearly,
        input.emailLimit,
        input.apiCallLimit,
        JSON.stringify(input.features),
        input.stripePriceIdMonthly ?? null,
        input.stripePriceIdYearly ?? null,
        input.sortOrder ?? 0,
      ]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.err(new Error('Failed to create plan'));

    return Result.ok(this.mapRow(row));
  }

  /**
   * Get all active plans
   */
  async getActivePlans(): Promise<Result<Plan[], Error>> {
    const result = await this.db.query<{
      id: string;
      name: string;
      display_name: string;
      description: string;
      price_monthly: number;
      price_yearly: number;
      email_limit: number;
      api_call_limit: number;
      features: string;
      stripe_price_id_monthly: string | null;
      stripe_price_id_yearly: string | null;
      is_active: boolean;
      sort_order: number;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, name, display_name, description, price_monthly, price_yearly,
              email_limit, api_call_limit, features, stripe_price_id_monthly,
              stripe_price_id_yearly, is_active, sort_order, created_at, updated_at
       FROM plans WHERE is_active = true ORDER BY sort_order ASC LIMIT 100`
    );

    if (!result.ok) return Result.err(result.error);

    return Result.ok(result.value.rows.map(row => this.mapRow(row)));
  }

  /**
   * Get plan by name
   */
  async getPlanByName(name: string): Promise<Result<Plan | null, Error>> {
    const result = await this.db.query<{
      id: string;
      name: string;
      display_name: string;
      description: string;
      price_monthly: number;
      price_yearly: number;
      email_limit: number;
      api_call_limit: number;
      features: string;
      stripe_price_id_monthly: string | null;
      stripe_price_id_yearly: string | null;
      is_active: boolean;
      sort_order: number;
      created_at: Date;
      updated_at: Date;
    }>(
      `SELECT id, name, display_name, description, price_monthly, price_yearly,
              email_limit, api_call_limit, features, stripe_price_id_monthly,
              stripe_price_id_yearly, is_active, sort_order, created_at, updated_at
       FROM plans WHERE name = $1`,
      [name]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok(this.mapRow(row));
  }

  /**
   * Check if tenant has feature access
   */
  async hasFeature(tenantId: string, feature: keyof PlanFeatures): Promise<Result<boolean, Error>> {
    const result = await this.db.query<{
      features: string;
    }>(
      `SELECT p.features
       FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(false);

    try {
      const features = JSON.parse(row.features) as PlanFeatures;
      return Result.ok(Boolean(features[feature]));
    } catch {
      return Result.err(new Error('Invalid plan features data'));
    }
  }

  /**
   * Get plan limits for a tenant
   */
  async getPlanLimits(tenantId: string): Promise<Result<{
    emailLimit: number;
    apiCallLimit: number;
    features: PlanFeatures;
  } | null, Error>> {
    const result = await this.db.query<{
      email_limit: number;
      api_call_limit: number;
      features: string;
    }>(
      `SELECT p.email_limit, p.api_call_limit, p.features
       FROM tenants t
       JOIN plans p ON t.plan = p.name
       WHERE t.id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    let features: PlanFeatures;
    try {
      features = JSON.parse(row.features) as PlanFeatures;
    } catch {
      return Result.err(new Error('Invalid plan features data'));
    }
    
    return Result.ok({
      emailLimit: row.email_limit,
      apiCallLimit: row.api_call_limit,
      features,
    });
  }

  /**
   * Update a tenant's plan
   */
  async updateTenantPlan(tenantId: string, planName: string): Promise<Result<void, Error>> {
    // Verify plan exists
    const planResult = await this.getPlanByName(planName);
    if (!planResult.ok) return Result.err(planResult.error);
    if (!planResult.value) return Result.err(new Error('Plan not found'));

    const result = await this.db.query(
      `UPDATE tenants SET plan = $1, updated_at = NOW() WHERE id = $2`,
      [planName, tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    return Result.ok(undefined);
  }

  /**
   * Get tenant's current plan
   */
  async getTenantPlan(tenantId: string): Promise<Result<Plan | null, Error>> {
    const result = await this.db.query<{
      plan: string;
    }>(
      `SELECT plan FROM tenants WHERE id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);
    
    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return this.getPlanByName(row.plan);
  }

  private mapRow(row: {
    id: string;
    name: string;
    display_name: string;
    description: string;
    price_monthly: number;
    price_yearly: number;
    email_limit: number;
    api_call_limit: number;
    features: string;
    stripe_price_id_monthly: string | null;
    stripe_price_id_yearly: string | null;
    is_active: boolean;
    sort_order: number;
    created_at: Date;
    updated_at: Date;
  }): Plan {
    let features: PlanFeatures = { ...DEFAULT_PLAN_FEATURES };
    try {
      const parsed = JSON.parse(row.features);
      features = { ...DEFAULT_PLAN_FEATURES, ...parsed };
    } catch {
      console.error('Invalid plan features JSON for plan:', row.id);
    }
    
    return {
      id: row.id,
      name: row.name,
      displayName: row.display_name,
      description: row.description,
      priceMonthly: row.price_monthly,
      priceYearly: row.price_yearly,
      emailLimit: row.email_limit,
      apiCallLimit: row.api_call_limit,
      features,
      stripePriceIdMonthly: row.stripe_price_id_monthly,
      stripePriceIdYearly: row.stripe_price_id_yearly,
      isActive: row.is_active,
      sortOrder: row.sort_order,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
