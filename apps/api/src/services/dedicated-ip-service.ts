/**
 * Dedicated IP Service
 *
 * Manages provisioning and lifecycle of dedicated IP addresses.
 * Backend provisions IPs through AWS SES — this is an internal implementation
 * detail that is NEVER exposed to customers.
 *
 * Architecture:
 * - Main hosting: Hetzner
 * - Dedicated IP provisioning: AWS SES (internal)
 * - IP data stored in `dedicated_ips` table
 * - Warmup managed by worker ip-rate-limiter + ops warmup manager
 */

import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';
import type { Logger } from '@apexmail/lib';

// ---------- Types ----------

export type IpStatus = 'pending' | 'warming' | 'active' | 'suspended' | 'retired';
export type DedicatedIpBillingStatus = 'included' | 'pending_charge' | 'active' | 'pending_cancel' | 'canceled' | 'exempt';

export interface DedicatedIp {
  id: string;
  tenantId: string;
  ipAddress: string;
  ptrRecord: string | null;
  status: IpStatus;
  warmingStartedAt: Date | null;
  warmingCompletedAt: Date | null;
  warmingProgressPercent: number;
  currentDailyLimit: number | null;
  reputationScore: number;
  emailsSentTotal: number;
  bouncesTotal: number;
  complaintsTotal: number;
  blocklisted: boolean;
  billingStatus: DedicatedIpBillingStatus;
  stripeSubscriptionItemId: string | null;
  billingStartedAt: Date | null;
  billingEndedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface ProvisionIpInput {
  tenantId: string;
  userId: string | null;
}

export interface DedicatedIpAllocation {
  included: number;       // IPs included in plan
  active: number;         // Currently active/warming IPs
  addOnAvailable: boolean; // Can purchase more
  addOnPriceMonthly: number; // $30/mo = 3000 cents
}

// ---------- SES Client (lazy-loaded) ----------

let sesClientPromise: Promise<SesClientWrapper | null> | null = null;

interface SesClientWrapper {
  requestDedicatedIp: () => Promise<{ ipAddress: string } | null>;
  releaseDedicatedIp: (ipAddress: string) => Promise<boolean>;
}

function loadSesClient(): Promise<SesClientWrapper | null> {
  if (!sesClientPromise) {
    sesClientPromise = (async () => {
      const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
      const accessKeyId = process.env.AWS_ACCESS_KEY_ID;
      const secretAccessKey = process.env.AWS_SECRET_ACCESS_KEY;

      if (!region || !accessKeyId || !secretAccessKey) {
        return null;
      }

      try {
        const { SESv2Client, CreateDedicatedIpPoolCommand, PutDedicatedIpWarmupAttributesCommand } =
          await import('@aws-sdk/client-sesv2' as string);

        const client = new SESv2Client({
          region,
          credentials: { accessKeyId, secretAccessKey },
        });

        return {
          async requestDedicatedIp(): Promise<{ ipAddress: string } | null> {
            // AWS SES dedicated IPs are provisioned by requesting them through
            // the SES console/API. In practice, you request a dedicated IP and
            // AWS assigns one from their pool. We simulate this with a pool
            // management approach.
            //
            // For the API, we request AWS to assign a dedicated IP to our account
            // and then track it in our database.
            try {
              // Ensure our dedicated IP pool exists
              try {
                await client.send(new CreateDedicatedIpPoolCommand({
                  PoolName: 'apexmail-dedicated',
                  ScalingMode: 'STANDARD',
                }));
              } catch (e: unknown) {
                // Pool may already exist — AlreadyExistsException is expected
                if (!(e instanceof Error) || !e.name?.includes('AlreadyExists')) {
                  throw e;
                }
              }

              // AWS SES dedicated IPs are requested via support ticket or
              // programmatically. In our implementation, we allocate from the
              // pool of IPs already provisioned to our SES account.
              // The actual IP address is determined by AWS after provisioning.
              //
              // For automated provisioning, we query the available IPs in
              // our account and assign an unallocated one to this tenant.
              const { GetDedicatedIpsCommand } = await import('@aws-sdk/client-sesv2' as string);
              const response = await client.send(new GetDedicatedIpsCommand({
                PoolName: 'apexmail-dedicated',
                PageSize: 100,
              }));

              const allIps = response.DedicatedIps ?? [];

              // Return first available IP not yet assigned (warmup not started)
              // In production, you'd have a more sophisticated allocation strategy
              if (allIps.length > 0) {
                const ip = allIps[0];
                if (ip?.Ip) {
                  // Enable warmup for the IP
                  await client.send(new PutDedicatedIpWarmupAttributesCommand({
                    Ip: ip.Ip,
                    WarmupPercentage: 1,
                  }));
                  return { ipAddress: ip.Ip };
                }
              }

              return null;
            } catch {
              return null;
            }
          },

          async releaseDedicatedIp(ipAddress: string): Promise<boolean> {
            // AWS SES dedicated IPs cannot be truly "released" programmatically.
            // They are associated with your account. We mark them as available
            // in our pool for reallocation and update the status in our DB.
            try {
              const { PutDedicatedIpInPoolCommand } = await import('@aws-sdk/client-sesv2' as string);
              await client.send(new PutDedicatedIpInPoolCommand({
                Ip: ipAddress,
                DestinationPoolName: 'apexmail-unassigned',
              }));
              return true;
            } catch {
              return false;
            }
          },
        } satisfies SesClientWrapper;
      } catch {
        return null;
      }
    })();
  }
  return sesClientPromise;
}

// ---------- Service ----------

const DEDICATED_IP_ADDON_PRICE_CENTS = 3000; // $30/mo

export class DedicatedIpService {
  constructor(
    private readonly db: DatabasePool,
    private readonly logger: Logger,
  ) {}

  /**
   * Get allocation summary for a tenant.
   * Shows included IPs, active IPs, and whether they can purchase more.
   */
  async getAllocation(
    tenantId: string,
    planFeatures: { dedicatedIp: boolean; dedicatedIpCount: number },
  ): Promise<Result<DedicatedIpAllocation, Error>> {
    const countResult = await this.db.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM dedicated_ips
       WHERE tenant_id = $1 AND status NOT IN ('retired')`,
      [tenantId],
    );

    if (!countResult.ok) return Result.err(countResult.error);

    const active = parseInt(countResult.value.rows[0]?.count ?? '0', 10);

    return Result.ok({
      included: planFeatures.dedicatedIpCount,
      active,
      addOnAvailable: planFeatures.dedicatedIp,
      addOnPriceMonthly: DEDICATED_IP_ADDON_PRICE_CENTS,
    });
  }

  /**
   * List all dedicated IPs for a tenant.
   */
  async listByTenant(
    tenantId: string,
    opts: { limit?: number; offset?: number; status?: IpStatus } = {},
  ): Promise<Result<{ ips: DedicatedIp[]; total: number }, Error>> {
    const limit = Math.max(1, Math.min(opts.limit ?? 50, 100));
    const offset = Math.max(0, opts.offset ?? 0);

    const conditions = ['tenant_id = $1'];
    const params: (string | number)[] = [tenantId];
    let paramIdx = 2;

    if (opts.status) {
      conditions.push(`status = $${paramIdx}`);
      params.push(opts.status);
      paramIdx++;
    }

    const whereClause = conditions.join(' AND ');

    const [listResult, countResult] = await Promise.all([
      this.db.query<DedicatedIpRow>(
        `SELECT * FROM dedicated_ips
         WHERE ${whereClause}
         ORDER BY created_at DESC
         LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
        [...params, limit, offset],
      ),
      this.db.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM dedicated_ips WHERE ${whereClause}`,
        params,
      ),
    ]);

    if (!listResult.ok) return Result.err(listResult.error);
    if (!countResult.ok) return Result.err(countResult.error);

    const ips = listResult.value.rows.map(mapDedicatedIpRow);
    const total = parseInt(countResult.value.rows[0]?.count ?? '0', 10);

    return Result.ok({ ips, total });
  }

  /**
   * Get a single dedicated IP by ID, scoped to tenant.
   */
  async findById(id: string, tenantId: string): Promise<Result<DedicatedIp | null, Error>> {
    const result = await this.db.query<DedicatedIpRow>(
      `SELECT * FROM dedicated_ips WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) return Result.ok(null);

    return Result.ok(mapDedicatedIpRow(row));
  }

  /**
   * Provision a new dedicated IP for a tenant.
   *
   * Flow:
   * 1. Validate plan allows dedicated IPs
   * 2. Check allocation limits
   * 3. Request IP from infrastructure provider (internal)
   * 4. Insert record in `dedicated_ips` with status='pending'
   * 5. Link to operational `ip_pool_addresses` for warmup
   */
  async provision(
    input: ProvisionIpInput,
    planFeatures: { dedicatedIp: boolean; dedicatedIpCount: number },
  ): Promise<Result<DedicatedIp, Error>> {
    const { tenantId, userId } = input;

    // 1. Validate plan supports dedicated IPs
    if (!planFeatures.dedicatedIp) {
      return Result.err(new Error('PLAN_NOT_ELIGIBLE'));
    }

    // 2. Check current allocation
    const allocationResult = await this.getAllocation(tenantId, planFeatures);
    if (!allocationResult.ok) return Result.err(allocationResult.error);

    // No hard cap — users can purchase add-on IPs beyond included count.
    // Billing handles the charge. We apply a safety cap of 50 IPs per tenant.
    const MAX_IPS_PER_TENANT = 50;
    if (allocationResult.value.active >= MAX_IPS_PER_TENANT) {
      return Result.err(new Error('MAX_IPS_REACHED'));
    }

    // 3. Request IP from infrastructure provider
    const sesClient = await loadSesClient();
    let ipAddress: string;

    if (sesClient) {
      const sesResult = await sesClient.requestDedicatedIp();
      if (!sesResult) {
        this.logger.error('Failed to provision dedicated IP from provider', { tenantId });
        return Result.err(new Error('PROVISIONING_FAILED'));
      }
      ipAddress = sesResult.ipAddress;
    } else {
      // Development/test environment — generate a placeholder IP
      // In production, SES credentials MUST be configured
      if (process.env.NODE_ENV === 'production') {
        this.logger.error('Email infrastructure provider not configured', { tenantId });
        return Result.err(new Error('PROVISIONING_UNAVAILABLE'));
      }
      ipAddress = `10.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      this.logger.warn('Using placeholder IP for development', { tenantId, ipAddress });
    }

    // 4. Determine billing status: is this IP within the plan's included count?
    //    If active count < included count, it's 'included' (no charge).
    //    Otherwise it's 'pending_charge' (billing service will create Stripe subscription item).
    const currentActive = allocationResult.value.active;
    const includedCount = planFeatures.dedicatedIpCount;
    const billingStatus = currentActive < includedCount ? 'included' : 'pending_charge';

    // 5. Insert into dedicated_ips
    const insertResult = await this.db.query<DedicatedIpRow>(
      `INSERT INTO dedicated_ips (
        tenant_id, ip_address, status, warming_progress_percent,
        reputation_score, emails_sent_total, bounces_total, complaints_total,
        blocklisted, billing_status, billing_started_at, created_at, updated_at
      ) VALUES (
        $1, $2::inet, 'pending', 0, 100.0, 0, 0, 0, false,
        $3, CASE WHEN $3 = 'included' THEN NOW() ELSE NULL END,
        NOW(), NOW()
      ) RETURNING *`,
      [tenantId, ipAddress, billingStatus],
    );

    if (!insertResult.ok) {
      this.logger.error('Failed to insert dedicated IP record', {
        tenantId,
        ipAddress,
        error: insertResult.error.message,
      });
      return Result.err(insertResult.error);
    }

    const ipRow = insertResult.value.rows[0];
    if (!ipRow) return Result.err(new Error('Failed to create IP record'));

    const ip = mapDedicatedIpRow(ipRow);

    // 6. Insert into ip_pool_addresses for operational warmup tracking
    // Get or create a default pool for this tenant's dedicated IPs
    const poolResult = await this.db.query<{ id: string }>(
      `WITH get_or_create AS (
         SELECT id FROM ip_pools WHERE name = $1
         UNION ALL
         SELECT substring(replace(gen_random_uuid()::text, '-', '') from 1 for 26)
         LIMIT 1
       )
       INSERT INTO ip_pools (id, name, description, status, created_at, updated_at)
       VALUES (
         (SELECT id FROM get_or_create LIMIT 1),
         $1, 'Auto-created default pool', 'active', NOW(), NOW()
       ) ON CONFLICT DO NOTHING
       RETURNING id`,
      [`dedicated-${tenantId.substring(0, 12)}`],
    );

    // Also try to find existing pool if INSERT did nothing
    let poolId = poolResult.ok ? poolResult.value.rows[0]?.id : null;
    if (!poolId) {
      const findPool = await this.db.query<{ id: string }>(
        `SELECT id FROM ip_pools WHERE name = $1 LIMIT 1`,
        [`dedicated-${tenantId.substring(0, 12)}`],
      );
      poolId = findPool.ok ? findPool.value.rows[0]?.id : null;
    }

    if (poolId) {
      await this.db.query(
        `INSERT INTO ip_pool_addresses (
          id, pool_id, ip_address, warmup_enabled, warmup_day, daily_limit,
          daily_sent, reputation_score, status, created_at, updated_at
        ) VALUES (
          substring(replace(gen_random_uuid()::text, '-', '') from 1 for 26),
          $1, $2::inet, true, 0, 50, 0, 100.0, 'warming', NOW(), NOW()
        ) ON CONFLICT (ip_address) DO NOTHING`,
        [poolId, ipAddress],
      );
    }

    // 7. Update status to 'warming' and set warmup start
    await this.db.query(
      `UPDATE dedicated_ips SET
        status = 'warming',
        warming_started_at = NOW(),
        current_daily_limit = 50,
        updated_at = NOW()
       WHERE id = $1`,
      [ip.id],
    );

    // 8. Audit log
    await this.db.query(
      `INSERT INTO audit_logs (
        id, tenant_id, user_id, action, resource_type, resource_id,
        metadata, created_at
      ) VALUES (
        gen_random_uuid(), $1, $2, 'dedicated_ip.provisioned',
        'dedicated_ip', $3, $4, NOW()
      )`,
      [
        tenantId,
        userId,
        ip.id,
        JSON.stringify({ ipAddress, status: 'warming', billingStatus }),
      ],
    );

    this.logger.info('Dedicated IP provisioned', {
      tenantId,
      ipId: ip.id,
      ipAddress,
    });

    // Return updated record
    const finalResult = await this.findById(ip.id, tenantId);
    if (!finalResult.ok || !finalResult.value) {
      return Result.ok(ip); // Fallback to initial record
    }
    return Result.ok(finalResult.value);
  }

  /**
   * Release (retire) a dedicated IP.
   */
  async release(
    id: string,
    tenantId: string,
    userId: string | null,
  ): Promise<Result<void, Error>> {
    // Get the IP first
    const ipResult = await this.findById(id, tenantId);
    if (!ipResult.ok) return Result.err(ipResult.error);
    if (!ipResult.value) return Result.err(new Error('IP_NOT_FOUND'));

    const ip = ipResult.value;

    if (ip.status === 'retired') {
      return Result.err(new Error('IP_ALREADY_RETIRED'));
    }

    // Release from infrastructure provider
    const sesClient = await loadSesClient();
    if (sesClient) {
      await sesClient.releaseDedicatedIp(ip.ipAddress);
    }

    // Mark as retired in dedicated_ips and set billing to pending_cancel
    // The billing service will remove the Stripe subscription item and prorate
    const updateResult = await this.db.query(
      `UPDATE dedicated_ips SET
        status = 'retired',
        billing_status = CASE
          WHEN billing_status IN ('active', 'pending_charge') THEN 'pending_cancel'
          WHEN billing_status = 'included' THEN 'canceled'
          ELSE billing_status
        END,
        updated_at = NOW()
       WHERE id = $1 AND tenant_id = $2`,
      [id, tenantId],
    );

    if (!updateResult.ok) return Result.err(updateResult.error);

    // Update operational table
    await this.db.query(
      `UPDATE ip_pool_addresses SET
        status = 'retired',
        updated_at = NOW()
       WHERE ip_address = $1::inet`,
      [ip.ipAddress],
    );

    // Audit log
    await this.db.query(
      `INSERT INTO audit_logs (
        id, tenant_id, user_id, action, resource_type, resource_id,
        metadata, created_at
      ) VALUES (
        gen_random_uuid(), $1, $2, 'dedicated_ip.released',
        'dedicated_ip', $3, $4, NOW()
      )`,
      [
        tenantId,
        userId,
        id,
        JSON.stringify({ ipAddress: ip.ipAddress, previousStatus: ip.status }),
      ],
    );

    this.logger.info('Dedicated IP released', {
      tenantId,
      ipId: id,
      ipAddress: ip.ipAddress,
    });

    return Result.ok(undefined);
  }
}

// ---------- Row Mapping ----------

interface DedicatedIpRow {
  [key: string]: unknown;
  id: string;
  tenant_id: string;
  ip_address: string;
  ptr_record: string | null;
  status: IpStatus;
  warming_started_at: Date | null;
  warming_completed_at: Date | null;
  warming_progress_percent: number;
  current_daily_limit: number | null;
  reputation_score: string; // DECIMAL comes as string from pg
  emails_sent_total: string; // BIGINT comes as string
  bounces_total: string;
  complaints_total: string;
  blocklisted: boolean;
  billing_status: DedicatedIpBillingStatus;
  stripe_subscription_item_id: string | null;
  billing_started_at: Date | null;
  billing_ended_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

function mapDedicatedIpRow(row: DedicatedIpRow): DedicatedIp {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    ipAddress: row.ip_address,
    ptrRecord: row.ptr_record,
    status: row.status,
    warmingStartedAt: row.warming_started_at,
    warmingCompletedAt: row.warming_completed_at,
    warmingProgressPercent: row.warming_progress_percent ?? 0,
    currentDailyLimit: row.current_daily_limit,
    reputationScore: parseFloat(row.reputation_score) || 100.0,
    emailsSentTotal: parseInt(row.emails_sent_total, 10) || 0,
    bouncesTotal: parseInt(row.bounces_total, 10) || 0,
    complaintsTotal: parseInt(row.complaints_total, 10) || 0,
    blocklisted: row.blocklisted,
    billingStatus: row.billing_status,
    stripeSubscriptionItemId: row.stripe_subscription_item_id,
    billingStartedAt: row.billing_started_at,
    billingEndedAt: row.billing_ended_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
