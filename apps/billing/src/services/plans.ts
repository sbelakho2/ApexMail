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
  dedicatedIp: boolean;
  dedicatedIpCount: number;
  ssoEnabled: boolean;
  apiAccess: boolean;
  webhooksEnabled: boolean;
  advancedAnalytics: boolean;
  customTrackingDomain: boolean;
  prioritySupport: boolean;
  templateApprovalWorkflow: boolean;
  customRetention: boolean;
  maxRetentionDays: number;
  subaccounts: boolean;
  maxSubaccounts: number;
  whiteLabel: boolean;
  byoip: boolean;
  slaGuarantee: boolean;
  slaCreditPercentage: number;
  maxTeamMembers: number;
  dataExport: boolean;
  auditLogs: boolean;
  poweredByFooter: boolean;
}

const DEFAULT_PLAN_FEATURES: PlanFeatures = {
  dedicatedIp: false,
  dedicatedIpCount: 0,
  ssoEnabled: false,
  apiAccess: true,
  webhooksEnabled: false,
  advancedAnalytics: false,
  customTrackingDomain: false,
  prioritySupport: false,
  templateApprovalWorkflow: false,
  customRetention: false,
  maxRetentionDays: 30,
  subaccounts: false,
  maxSubaccounts: 0,
  whiteLabel: false,
  byoip: false,
  slaGuarantee: false,
  slaCreditPercentage: 0,
  maxTeamMembers: 1,
  dataExport: false,
  auditLogs: false,
  poweredByFooter: true,
};

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
    emailLimit: 1000,
    apiCallLimit: 10000,
    features: {
      dedicatedIp: false,
      dedicatedIpCount: 0,
      ssoEnabled: false,
      apiAccess: true,
      webhooksEnabled: false,
      advancedAnalytics: false,
      customTrackingDomain: false,
      prioritySupport: false,
      templateApprovalWorkflow: false,
      customRetention: false,
      maxRetentionDays: 7,
      subaccounts: false,
      maxSubaccounts: 0,
      whiteLabel: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      maxTeamMembers: 1,
      dataExport: false,
      auditLogs: false,
      poweredByFooter: true,
    },
    sortOrder: 0,
  },
  {
    name: 'starter',
    displayName: 'Starter',
    description: 'For growing businesses with moderate email needs',
    priceMonthly: 2900, // $29
    priceYearly: 29000, // $290 (~17% discount)
    emailLimit: 25000,
    apiCallLimit: 250000,
    features: {
      dedicatedIp: false,
      dedicatedIpCount: 0,
      ssoEnabled: false,
      apiAccess: true,
      webhooksEnabled: true,
      advancedAnalytics: true,
      customTrackingDomain: false,
      prioritySupport: false,
      templateApprovalWorkflow: false,
      customRetention: false,
      maxRetentionDays: 30,
      subaccounts: false,
      maxSubaccounts: 0,
      whiteLabel: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      maxTeamMembers: 3,
      dataExport: true,
      auditLogs: false,
      poweredByFooter: false,
    },
    sortOrder: 1,
  },
  {
    name: 'growth',
    displayName: 'Growth',
    description: 'For teams that need advanced features',
    priceMonthly: 9900, // $99
    priceYearly: 99000, // $990 (~17% discount)
    emailLimit: 100000,
    apiCallLimit: 1000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 1,
      ssoEnabled: false,
      apiAccess: true,
      webhooksEnabled: true,
      advancedAnalytics: true,
      customTrackingDomain: true,
      prioritySupport: true,
      templateApprovalWorkflow: false,
      customRetention: true,
      maxRetentionDays: 90,
      subaccounts: false,
      maxSubaccounts: 0,
      whiteLabel: false,
      byoip: false,
      slaGuarantee: false,
      slaCreditPercentage: 0,
      maxTeamMembers: 10,
      dataExport: true,
      auditLogs: true,
      poweredByFooter: false,
    },
    sortOrder: 2,
  },
  {
    name: 'scale',
    displayName: 'Scale',
    description: 'For high-volume senders',
    priceMonthly: 29900, // $299
    priceYearly: 299000, // $2990 (~17% discount)
    emailLimit: 500000,
    apiCallLimit: 5000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 3,
      ssoEnabled: true,
      apiAccess: true,
      webhooksEnabled: true,
      advancedAnalytics: true,
      customTrackingDomain: true,
      prioritySupport: true,
      templateApprovalWorkflow: true,
      customRetention: true,
      maxRetentionDays: 365,
      subaccounts: true,
      maxSubaccounts: 10,
      whiteLabel: false,
      byoip: false,
      slaGuarantee: true,
      slaCreditPercentage: 10,
      maxTeamMembers: 25,
      dataExport: true,
      auditLogs: true,
      poweredByFooter: false,
    },
    sortOrder: 3,
  },
  {
    name: 'enterprise',
    displayName: 'Enterprise',
    description: 'Custom solutions for large organizations',
    priceMonthly: 99900, // $999 (base)
    priceYearly: 999000, // $9990
    emailLimit: 2000000,
    apiCallLimit: 20000000,
    features: {
      dedicatedIp: true,
      dedicatedIpCount: 10,
      ssoEnabled: true,
      apiAccess: true,
      webhooksEnabled: true,
      advancedAnalytics: true,
      customTrackingDomain: true,
      prioritySupport: true,
      templateApprovalWorkflow: true,
      customRetention: true,
      maxRetentionDays: 730,
      subaccounts: true,
      maxSubaccounts: 100,
      whiteLabel: true,
      byoip: true,
      slaGuarantee: true,
      slaCreditPercentage: 25,
      maxTeamMembers: -1, // Unlimited
      dataExport: true,
      auditLogs: true,
      poweredByFooter: false,
    },
    sortOrder: 4,
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
    for (const plan of DEFAULT_PLANS) {
      await this.createOrUpdatePlan(plan);
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
      `SELECT * FROM plans WHERE is_active = true ORDER BY sort_order ASC LIMIT 100`
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
      `SELECT * FROM plans WHERE name = $1`,
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
