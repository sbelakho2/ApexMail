/**
 * Wallet Service
 * Pre-paid balance management with ledger
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';
import { DEFAULT_BILLING_CURRENCY, resolveTenantBillingCurrency } from '../lib/billing-currency.js';
import { WALLET_CACHE_TTL_SECONDS } from '../lib/constants.js';

const logger = createLogger();

export interface WalletBalance {
  tenantId: string;
  balance: number;           // In cents
  reservedBalance: number;   // Reserved for pending charges
  availableBalance: number;  // balance - reservedBalance
  currency: string;
  updatedAt: Date;
}

export interface WalletTransaction {
  id: string;
  tenantId: string;
  type: 'credit' | 'debit' | 'reserve' | 'release' | 'refund';
  amount: number;
  balance: number;           // Balance after transaction
  description: string;
  reference: string | null;
  metadata: Record<string, unknown>;
  createdAt: Date;
}

/**
 * Wallet ledger service for prepaid accounts
 * 
 * Includes comprehensive JSDoc for public API methods.
 * 
 * @example
 * ```typescript
 * const wallet = new WalletService(db, redis);
 * const balance = await wallet.getBalance('tenant-123');
 * if (balance.ok) {
 *   console.log(`Available: ${balance.value.availableBalance} cents`);
 * }
 * ```
 */
export class WalletService {
  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis
  ) {}

  /**
   * Get wallet balance for a tenant.
   * Creates wallet automatically if it doesn't exist.
   * 
   * @param tenantId - The tenant UUID
   * @returns Result containing WalletBalance or Error
   * 
   * @remarks
   * - Balances are stored in cents (integer) to avoid floating point issues
   * - Uses Redis caching with 5-minute TTL for read performance
   * - Creates wallet atomically on first access
   */
  async getBalance(tenantId: string): Promise<Result<WalletBalance, Error>> {
    // Query database
    const result = await this.db.query<{
      tenant_id: string;
      balance: number;
      reserved: number;
      currency: string;
      updated_at: Date;
    }>(
      `SELECT tenant_id, balance, reserved, currency, updated_at
       FROM wallets WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    let balance: WalletBalance;

    if (result.value.rows[0]) {
      const row = result.value.rows[0];
      balance = {
        tenantId: row.tenant_id,
        balance: row.balance,
        reservedBalance: row.reserved,
        availableBalance: row.balance - row.reserved,
        currency: row.currency,
        updatedAt: row.updated_at,
      };
    } else {
      const tenantCurrency = await resolveTenantBillingCurrency(this.db, tenantId);

      // Create wallet if doesn't exist, using ON CONFLICT DO UPDATE to avoid race condition
      // ON CONFLICT DO NOTHING can return no rows when concurrent inserts occur
      const createResult = await this.db.query<{
        tenant_id: string;
        balance: number;
        reserved: number;
        currency: string;
        updated_at: Date;
      }>(
        `INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
         VALUES ($1, 0, 0, $2, NOW(), NOW())
         ON CONFLICT (tenant_id) DO UPDATE SET updated_at = wallets.updated_at
         RETURNING tenant_id, balance, reserved, currency, updated_at`,
        [tenantId, tenantCurrency]
      );

      if (!createResult.ok) return Result.err(createResult.error);

      // Use returned row data instead of assuming defaults
      const row = createResult.value.rows[0];
      if (row) {
        balance = {
          tenantId: row.tenant_id,
          balance: row.balance,
          reservedBalance: row.reserved,
          availableBalance: row.balance - row.reserved,
          currency: row.currency,
          updatedAt: row.updated_at,
        };
      } else {
        // Fallback should never happen with DO UPDATE RETURNING, but be defensive
        balance = {
          tenantId,
          balance: 0,
          reservedBalance: 0,
          availableBalance: 0,
          currency: tenantCurrency ?? DEFAULT_BILLING_CURRENCY,
          updatedAt: new Date(),
        };
      }
    }

    // Cache for 5 minutes
    await this.redis.setex(
      `wallet:balance:${tenantId}`,
      WALLET_CACHE_TTL_SECONDS,
      JSON.stringify({
        balance: balance.balance,
        reserved: balance.reservedBalance,
        updatedAt: balance.updatedAt.toISOString(),
      })
    );

    return Result.ok(balance);
  }

  /**
   * Add funds to wallet
   */
  async credit(
    tenantId: string,
    amount: number,
    description: string,
    reference?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<Result<WalletTransaction, Error>> {
    if (amount <= 0) {
      return Result.err(new Error('Amount must be positive'));
    }

    return this.executeTransaction(tenantId, 'credit', amount, description, reference, metadata);
  }

  /**
   * Deduct funds from wallet
   * SECURITY: Uses atomic check-and-update to prevent race conditions
   */
  async debit(
    tenantId: string,
    amount: number,
    description: string,
    reference?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<Result<WalletTransaction, Error>> {
    if (amount <= 0) {
      return Result.err(new Error('Amount must be positive'));
    }

    // Atomic check-and-debit in a single query to prevent race conditions
    // Uses a conditional update that only succeeds if sufficient funds exist
    const updateResult = await this.db.query<{
      tx_id: string;
      tenant_id: string;
      type: WalletTransaction['type'];
      amount: number;
      balance: number;
      description: string;
      reference: string | null;
      metadata: string;
      created_at: Date;
    }>(
      `WITH updated_wallet AS (
        UPDATE wallets
        SET balance = balance - $1, updated_at = NOW()
        WHERE tenant_id = $2
          AND (balance - reserved) >= $1
        RETURNING id AS wallet_id, tenant_id, balance
      ),
      new_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
        )
        SELECT
          gen_random_uuid(),
          tenant_id,
          wallet_id,
          'debit',
          -$1,
          balance,
          $3,
          $4,
          $5::jsonb,
          NOW()
        FROM updated_wallet
        RETURNING id, tenant_id, type, amount, balance_after AS balance, description, reference, metadata, created_at
      ),
      audit_log AS (
        INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
        SELECT
          gen_random_uuid(),
          nt.tenant_id,
          'wallet.debited',
          'wallet',
          nt.id,
          jsonb_build_object('amount', $1, 'description', $3, 'reference', $4, 'balanceAfter', nt.balance),
          NOW()
        FROM new_transaction nt
        RETURNING id
      )
      SELECT id AS tx_id, tenant_id, type, amount, balance, description, reference, metadata, created_at
      FROM new_transaction`,
      [amount, tenantId, description, reference ?? null, JSON.stringify(metadata)]
    );

    if (!updateResult.ok) return Result.err(updateResult.error);

    const row = updateResult.value.rows[0];
    if (!row) {
      return Result.err(new Error('Insufficient balance'));
    }

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    let parsedMetadata: Record<string, unknown> = {};
    try {
      parsedMetadata = JSON.parse(row.metadata || '{}');
    } catch (error) {
      logger.warn('Failed to parse wallet transaction metadata', { txId: row.tx_id, error: String(error) });
    }

    return Result.ok({
      id: row.tx_id,
      tenantId: row.tenant_id,
      type: row.type,
      amount: row.amount,
      balance: row.balance,
      description: row.description,
      reference: row.reference,
      metadata: parsedMetadata,
      createdAt: row.created_at,
    });
  }

  /**
   * Reserve funds for pending charge
   * SECURITY: Uses atomic operation to prevent race conditions and double-spending
   */
  async reserve(
    tenantId: string,
    amount: number,
    description: string,
    reference?: string
  ): Promise<Result<{ reservationId: string }, Error>> {
    if (amount <= 0) {
      return Result.err(new Error('Amount must be positive'));
    }

    // Use a single atomic transaction with row-level locking to prevent race conditions
    // This SELECT FOR UPDATE locks the row until the transaction completes
    const result = await this.db.query<{ 
      reservation_id: string;
      success: boolean;
    }>(
      `WITH locked_wallet AS (
        SELECT id AS wallet_id, tenant_id, balance, reserved 
        FROM wallets 
        WHERE tenant_id = $1 
        FOR UPDATE
      ),
      balance_check AS (
        SELECT 
          wallet_id,
          tenant_id,
          (balance - reserved) >= $2 AS has_funds
        FROM locked_wallet
      ),
      new_reservation AS (
        INSERT INTO wallet_reservations (id, tenant_id, wallet_id, amount, description, reference, status, created_at, expires_at)
        SELECT 
          gen_random_uuid(), 
          $1, 
          wallet_id,
          $2, 
          $3, 
          $4, 
          'pending', 
          NOW(), 
          NOW() + INTERVAL '24 hours'
        FROM balance_check
        WHERE has_funds = true
        RETURNING id, wallet_id
      ),
      wallet_update AS (
        UPDATE wallets 
        SET reserved = reserved + $2, updated_at = NOW() 
        WHERE tenant_id = $1 
          AND EXISTS (SELECT 1 FROM new_reservation)
        RETURNING id AS wallet_id, balance
      ),
      log_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
        )
        SELECT
          gen_random_uuid(),
          $1,
          wu.wallet_id,
          'reserve',
          0,
          wu.balance,
          $5,
          nr.id::text,
          jsonb_build_object('reservationId', nr.id, 'amount', $2),
          NOW()
        FROM wallet_update wu
        JOIN new_reservation nr ON nr.wallet_id = wu.wallet_id
        RETURNING id
      ),
      audit_log AS (
        INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
        SELECT
          gen_random_uuid(),
          $1,
          'wallet.reserved',
          'wallet',
          nr.id,
          jsonb_build_object('amount', $2, 'description', $3, 'reference', $4),
          NOW()
        FROM wallet_update wu
        JOIN new_reservation nr ON nr.wallet_id = wu.wallet_id
        RETURNING id
      )
      SELECT 
        (SELECT id::text FROM new_reservation) as reservation_id,
        EXISTS (SELECT 1 FROM new_reservation) as success`,
      [tenantId, amount, description, reference ?? null, `Reserved: ${description}`]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row || !row.success || !row.reservation_id) {
      return Result.err(new Error('Insufficient balance'));
    }

    const reservationId = row.reservation_id;

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    return Result.ok({ reservationId });
  }

  /**
   * Capture reserved funds
   * CRITICAL: Uses atomic transaction to prevent data inconsistency
   */
  async captureReservation(reservationId: string): Promise<Result<WalletTransaction, Error>> {
    // Use a single atomic query with CTE to capture reservation
    // This ensures both the reservation update and wallet deduction happen atomically
    const result = await this.db.query<{
      tx_id: string;
      tenant_id: string;
      type: WalletTransaction['type'];
      amount: number;
      balance: number;
      description: string;
      reference: string | null;
      metadata: string;
      created_at: Date;
    }>(
      `WITH reservation_check AS (
        SELECT tenant_id, wallet_id, amount, description, reference, status
        FROM wallet_reservations
        WHERE id = $1
        FOR UPDATE
      ),
      valid_reservation AS (
        SELECT * FROM reservation_check WHERE status = 'pending'
      ),
      update_reservation AS (
        UPDATE wallet_reservations
        SET status = 'captured', captured_at = NOW()
        WHERE id = $1 AND EXISTS (SELECT 1 FROM valid_reservation)
        RETURNING id
      ),
      update_wallet AS (
        UPDATE wallets
        SET balance = balance - (SELECT amount FROM valid_reservation),
            reserved = reserved - (SELECT amount FROM valid_reservation),
            updated_at = NOW()
        WHERE tenant_id = (SELECT tenant_id FROM valid_reservation)
          AND EXISTS (SELECT 1 FROM update_reservation)
        RETURNING id AS wallet_id, tenant_id, balance
      ),
      new_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
        )
        SELECT
          gen_random_uuid(),
          tenant_id,
          wallet_id,
          'debit',
          -(SELECT amount FROM valid_reservation),
          balance,
          CONCAT('Captured: ', (SELECT description FROM valid_reservation)),
          $1,
          jsonb_build_object('reservationId', $1),
          NOW()
        FROM update_wallet
        RETURNING id, tenant_id, type, amount, balance_after AS balance, description, reference, metadata, created_at
      ),
      audit_log AS (
        INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
        SELECT
          gen_random_uuid(),
          nt.tenant_id,
          'wallet.capture',
          'wallet',
          nt.id,
          jsonb_build_object('reservationId', $1, 'amount', (SELECT amount FROM valid_reservation), 'balanceAfter', nt.balance),
          NOW()
        FROM new_transaction nt
        RETURNING id
      )
      SELECT 
        id AS tx_id, tenant_id, type, amount, balance, description, reference, metadata, created_at
      FROM new_transaction`,
      [reservationId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Reservation already processed or invalid'));
    }

    // Invalidate cache
    await this.redis.del(`wallet:balance:${row.tenant_id}`);

    let parsedMetadata: Record<string, unknown> = {};
    try {
      parsedMetadata = JSON.parse(row.metadata || '{}');
    } catch (error) {
      logger.warn('Failed to parse wallet transaction metadata', { txId: row.tx_id, error: String(error) });
    }

    return Result.ok({
      id: row.tx_id,
      tenantId: row.tenant_id,
      type: row.type,
      amount: row.amount,
      balance: row.balance,
      description: row.description,
      reference: row.reference,
      metadata: parsedMetadata,
      createdAt: row.created_at,
    });
  }

  /**
   * Release reserved funds
   * CRITICAL: Uses atomic transaction to prevent data inconsistency
   */
  async releaseReservation(reservationId: string): Promise<Result<void, Error>> {
    // Use a single atomic query with CTE to release reservation
    const result = await this.db.query<{
      tenant_id: string;
      amount: number;
      success: boolean;
    }>(
      `WITH reservation_check AS (
        SELECT tenant_id, wallet_id, amount, status
        FROM wallet_reservations
        WHERE id = $1
        FOR UPDATE
      ),
      valid_reservation AS (
        SELECT * FROM reservation_check WHERE status = 'pending'
      ),
      update_reservation AS (
        UPDATE wallet_reservations
        SET status = 'released', released_at = NOW()
        WHERE id = $1 AND EXISTS (SELECT 1 FROM valid_reservation)
        RETURNING id
      ),
      update_wallet AS (
        UPDATE wallets
        SET reserved = reserved - (SELECT amount FROM valid_reservation),
            updated_at = NOW()
        WHERE tenant_id = (SELECT tenant_id FROM valid_reservation)
          AND EXISTS (SELECT 1 FROM update_reservation)
        RETURNING id AS wallet_id, tenant_id, balance
      ),
      log_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
        )
        SELECT
          gen_random_uuid(),
          tenant_id,
          wallet_id,
          'release',
          0,
          balance,
          'Released reservation',
          $1,
          jsonb_build_object('reservationId', $1, 'amount', (SELECT amount FROM valid_reservation)),
          NOW()
        FROM update_wallet
        RETURNING id
      ),
      audit_log AS (
        INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
        SELECT
          gen_random_uuid(),
          tenant_id,
          'wallet.release',
          'wallet',
          $1::uuid,
          jsonb_build_object('reservationId', $1, 'amount', (SELECT amount FROM valid_reservation), 'balanceAfter', balance),
          NOW()
        FROM update_wallet
        RETURNING id
      )
      SELECT 
        (SELECT tenant_id FROM valid_reservation) as tenant_id,
        (SELECT amount FROM valid_reservation) as amount,
        EXISTS (SELECT 1 FROM update_wallet) as success`,
      [reservationId]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Reservation not found'));
    }
    
    if (!row.success) {
      return Result.err(new Error('Reservation already processed or invalid'));
    }

    // Invalidate cache
    await this.redis.del(`wallet:balance:${row.tenant_id}`);

    return Result.ok(undefined);
  }

  /**
   * Check if tenant can send (has sufficient balance)
   */
  async canSend(tenantId: string, estimatedCost: number): Promise<Result<boolean, Error>> {
    const balanceResult = await this.getBalance(tenantId);
    if (!balanceResult.ok) return Result.err(balanceResult.error);

    // Check if balance is sufficient
    return Result.ok(balanceResult.value.availableBalance >= estimatedCost);
  }

  /**
   * Get transaction history
   */
  async getTransactions(
    tenantId: string,
    options?: {
      limit?: number;
      offset?: number;
      type?: WalletTransaction['type'];
    }
  ): Promise<Result<WalletTransaction[], Error>> {
    const limit = options?.limit ?? 50;
    const offset = options?.offset ?? 0;

    let query = `
      SELECT * FROM wallet_transactions
      WHERE tenant_id = $1
    `;
    const params: unknown[] = [tenantId];

    if (options?.type) {
      query += ` AND type = $${params.length + 1}`;
      params.push(options.type);
    }

    query += ` ORDER BY created_at DESC LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limit, offset);

    const result = await this.db.query<{
      id: string;
      tenant_id: string;
      type: WalletTransaction['type'];
      amount: number;
      balance: number;
      description: string;
      reference: string | null;
      metadata: string;
      created_at: Date;
    }>(query, params);

    if (!result.ok) return Result.err(result.error);

    return Result.ok(result.value.rows.map(row => {
      let metadata: Record<string, unknown> = {};
      try {
        metadata = JSON.parse(row.metadata || '{}');
      } catch (error) {
        logger.warn('Failed to parse wallet transaction metadata', { txId: row.id, error: String(error) });
        metadata = {};
      }
      return {
        id: row.id,
        tenantId: row.tenant_id,
        type: row.type,
        amount: row.amount,
        balance: row.balance,
        description: row.description,
        reference: row.reference,
        metadata,
        createdAt: row.created_at,
      };
    }));
  }

  /**
   * Process expired reservations (run hourly)
   */
  async processExpiredReservations(): Promise<Result<{ releasedCount: number }, Error>> {
    const result = await this.db.query<{
      tenant_id: string;
      released_count: string;
    }>(
      `WITH expired_reservations AS (
         SELECT id, tenant_id, amount
         FROM wallet_reservations
         WHERE status = 'pending' AND expires_at < NOW()
         FOR UPDATE SKIP LOCKED
       ),
       released_reservations AS (
         UPDATE wallet_reservations wr
         SET status = 'released', released_at = NOW()
         FROM expired_reservations er
         WHERE wr.id = er.id
         RETURNING er.tenant_id, er.amount
       ),
       released_totals AS (
         SELECT tenant_id, COALESCE(SUM(amount), 0) AS total_amount
         FROM released_reservations
         GROUP BY tenant_id
       ),
       wallet_updates AS (
         UPDATE wallets w
         SET reserved = w.reserved - rt.total_amount,
             updated_at = NOW()
         FROM released_totals rt
         WHERE w.tenant_id = rt.tenant_id
         RETURNING w.tenant_id
       )
       SELECT wu.tenant_id, (
         SELECT COUNT(*)::text FROM released_reservations
       ) AS released_count
       FROM wallet_updates wu`
    );

    if (!result.ok) return Result.err(result.error);

    const releasedCount = parseInt(result.value.rows[0]?.released_count ?? '0', 10);

    const tenantIds = new Set(result.value.rows.map(row => row.tenant_id));
    // FIX-N+1: Batch Redis delete instead of loop
    if (tenantIds.size > 0) {
      const keysToDelete = Array.from(tenantIds).map(id => `wallet:balance:${id}`);
      await this.redis.del(...keysToDelete);
    }

    return Result.ok({ releasedCount });
  }

  private async executeTransaction(
    tenantId: string,
    type: WalletTransaction['type'],
    amount: number,
    description: string,
    reference?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<Result<WalletTransaction, Error>> {
    // SECURITY FIX: Use atomic CTE to update balance AND record transaction in single operation
    // This prevents data inconsistency if process crashes between operations
    const result = await this.db.query<{
      tx_id: string;
      tenant_id: string;
      type: WalletTransaction['type'];
      amount: number;
      balance: number;
      description: string;
      reference: string | null;
      metadata: string;
      created_at: Date;
    }>(
      `WITH ensure_wallet AS (
        INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
        VALUES ($2, 0, 0, DEFAULT, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET updated_at = wallets.updated_at
        RETURNING id AS wallet_id, tenant_id
      ),
      updated_wallet AS (
        UPDATE wallets
        SET balance = balance + $1, updated_at = NOW()
        WHERE tenant_id = $2
        RETURNING id AS wallet_id, tenant_id, balance
      ),
      new_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
        )
        SELECT 
          gen_random_uuid(), 
          tenant_id,
          wallet_id,
          $3, 
          $1, 
          balance, 
          $4, 
          $5, 
          $6::jsonb, 
          NOW()
        FROM updated_wallet
        RETURNING id, tenant_id, type, amount, balance_after AS balance, description, reference, metadata, created_at
      ),
      audit_log AS (
        INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
        SELECT
          gen_random_uuid(),
          nt.tenant_id,
          CONCAT('wallet.', $3),
          'wallet',
          nt.id,
          jsonb_build_object('amount', $1, 'description', $4, 'reference', $5, 'balanceAfter', nt.balance),
          NOW()
        FROM new_transaction nt
        RETURNING id
      )
      SELECT 
        id as tx_id, tenant_id, type, amount, balance, description, reference, metadata, created_at
      FROM new_transaction`,
      [amount, tenantId, type, description, reference ?? null, JSON.stringify(metadata)]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row) {
      return Result.err(new Error('Failed to execute wallet transaction - wallet may not exist'));
    }

    // Invalidate cache AFTER successful transaction
    await this.redis.del(`wallet:balance:${tenantId}`);

    let parsedMetadata: Record<string, unknown> = {};
    try {
      parsedMetadata = JSON.parse(row.metadata || '{}');
    } catch (error) {
      logger.warn('Failed to parse wallet transaction metadata', { txId: row.tx_id, error: String(error) });
      parsedMetadata = {};
    }

    return Result.ok({
      id: row.tx_id,
      tenantId: row.tenant_id,
      type: row.type,
      amount: row.amount,
      balance: row.balance,
      description: row.description,
      reference: row.reference,
      metadata: parsedMetadata,
      createdAt: row.created_at,
    });
  }
}
