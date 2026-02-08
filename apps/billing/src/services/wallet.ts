/**
 * Wallet Service
 * Pre-paid balance management with ledger
 */

import type { Redis } from 'ioredis';
import { Result } from '@apexmail/lib';
import type { DatabasePool } from '@apexmail/db';

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
 */
export class WalletService {
  constructor(
    private readonly db: DatabasePool,
    private readonly redis: Redis
  ) {}

  /**
   * Get wallet balance
   */
  async getBalance(tenantId: string): Promise<Result<WalletBalance, Error>> {
    // Try cache first
    const cachedBalance = await this.redis.get(`wallet:balance:${tenantId}`);
    if (cachedBalance) {
      try {
        const cached = JSON.parse(cachedBalance);
        return Result.ok({
          tenantId,
          balance: cached.balance,
          reservedBalance: cached.reserved,
          availableBalance: cached.balance - cached.reserved,
          currency: 'EUR',
          updatedAt: new Date(cached.updatedAt),
        });
      } catch {
        // Invalid cache, delete and fall through to database
        await this.redis.del(`wallet:balance:${tenantId}`);
      }
    }

    // Query database
    const result = await this.db.query<{
      tenant_id: string;
      balance: number;
      reserved_balance: number;
      currency: string;
      updated_at: Date;
    }>(
      `SELECT * FROM wallets WHERE tenant_id = $1`,
      [tenantId]
    );

    if (!result.ok) return Result.err(result.error);

    let balance: WalletBalance;

    if (result.value.rows[0]) {
      const row = result.value.rows[0];
      balance = {
        tenantId: row.tenant_id,
        balance: row.balance,
        reservedBalance: row.reserved_balance,
        availableBalance: row.balance - row.reserved_balance,
        currency: row.currency,
        updatedAt: row.updated_at,
      };
    } else {
      // Create wallet if doesn't exist
      const createResult = await this.db.query<{
        tenant_id: string;
        balance: number;
        reserved_balance: number;
        currency: string;
        updated_at: Date;
      }>(
        `INSERT INTO wallets (tenant_id, balance, reserved_balance, currency, created_at, updated_at)
         VALUES ($1, 0, 0, 'EUR', NOW(), NOW())
         ON CONFLICT (tenant_id) DO NOTHING
         RETURNING *`,
        [tenantId]
      );

      if (!createResult.ok) return Result.err(createResult.error);

      balance = {
        tenantId,
        balance: 0,
        reservedBalance: 0,
        availableBalance: 0,
        currency: 'EUR',
        updatedAt: new Date(),
      };
    }

    // Cache for 5 minutes
    await this.redis.setex(
      `wallet:balance:${tenantId}`,
      300,
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
      balance: number;
      updated: boolean;
    }>(
      `WITH balance_check AS (
        SELECT tenant_id, balance, reserved_balance,
               (balance - reserved_balance) >= $1 AS has_funds
        FROM wallets
        WHERE tenant_id = $2
        FOR UPDATE
      ),
      do_update AS (
        UPDATE wallets
        SET balance = balance - $1, updated_at = NOW()
        WHERE tenant_id = $2
          AND EXISTS (SELECT 1 FROM balance_check WHERE has_funds = true)
        RETURNING balance
      )
      SELECT 
        COALESCE((SELECT balance FROM do_update), 0) as balance,
        EXISTS (SELECT 1 FROM do_update) as updated`,
      [amount, tenantId]
    );

    if (!updateResult.ok) return Result.err(updateResult.error);

    const row = updateResult.value.rows[0];
    if (!row || !row.updated) {
      return Result.err(new Error('Insufficient balance'));
    }

    const newBalance = row.balance;

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    return this.recordTransaction(tenantId, 'debit', -amount, description, reference, metadata, newBalance);
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
        SELECT tenant_id, balance, reserved_balance 
        FROM wallets 
        WHERE tenant_id = $1 
        FOR UPDATE
      ),
      balance_check AS (
        SELECT 
          tenant_id,
          (balance - reserved_balance) >= $2 AS has_funds
        FROM locked_wallet
      ),
      new_reservation AS (
        INSERT INTO wallet_reservations (id, tenant_id, amount, description, reference, status, created_at, expires_at)
        SELECT 
          gen_random_uuid(), 
          $1, 
          $2, 
          $3, 
          $4, 
          'pending', 
          NOW(), 
          NOW() + INTERVAL '24 hours'
        FROM balance_check
        WHERE has_funds = true
        RETURNING id
      ),
      wallet_update AS (
        UPDATE wallets 
        SET reserved_balance = reserved_balance + $2, updated_at = NOW() 
        WHERE tenant_id = $1 
          AND EXISTS (SELECT 1 FROM new_reservation)
        RETURNING tenant_id
      )
      SELECT 
        (SELECT id FROM new_reservation) as reservation_id,
        EXISTS (SELECT 1 FROM new_reservation) as success`,
      [tenantId, amount, description, reference ?? null]
    );

    if (!result.ok) return Result.err(result.error);

    const row = result.value.rows[0];
    if (!row || !row.success || !row.reservation_id) {
      return Result.err(new Error('Insufficient balance'));
    }

    const reservationId = row.reservation_id;

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    await this.recordTransaction(tenantId, 'reserve', 0, `Reserved: ${description}`, reservationId, { reservationId, amount });

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
      tenant_id: string;
      amount: number;
      description: string;
      reference: string | null;
      new_balance: number;
      success: boolean;
    }>(
      `WITH reservation_check AS (
        SELECT tenant_id, amount, description, reference, status
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
            reserved_balance = reserved_balance - (SELECT amount FROM valid_reservation),
            updated_at = NOW()
        WHERE tenant_id = (SELECT tenant_id FROM valid_reservation)
          AND EXISTS (SELECT 1 FROM update_reservation)
        RETURNING balance
      )
      SELECT 
        (SELECT tenant_id FROM valid_reservation) as tenant_id,
        (SELECT amount FROM valid_reservation) as amount,
        (SELECT description FROM valid_reservation) as description,
        (SELECT reference FROM valid_reservation) as reference,
        (SELECT balance FROM update_wallet) as new_balance,
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

    return this.recordTransaction(
      row.tenant_id,
      'debit',
      -row.amount,
      `Captured: ${row.description}`,
      reservationId,
      { reservationId },
      row.new_balance
    );
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
        SELECT tenant_id, amount, status
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
        SET reserved_balance = reserved_balance - (SELECT amount FROM valid_reservation),
            updated_at = NOW()
        WHERE tenant_id = (SELECT tenant_id FROM valid_reservation)
          AND EXISTS (SELECT 1 FROM update_reservation)
        RETURNING tenant_id
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

    await this.recordTransaction(
      row.tenant_id,
      'release',
      0,
      'Released reservation',
      reservationId,
      { reservationId, amount: row.amount }
    );

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
      } catch {
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
      id: string;
      tenant_id: string;
      amount: number;
    }>(
      `SELECT id, tenant_id, amount FROM wallet_reservations
       WHERE status = 'pending' AND expires_at < NOW()`
    );

    if (!result.ok) return Result.err(result.error);

    for (const row of result.value.rows) {
      await this.releaseReservation(row.id);
    }

    return Result.ok({ releasedCount: result.value.rows.length });
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
      `WITH updated_wallet AS (
        UPDATE wallets
        SET balance = balance + $1, updated_at = NOW()
        WHERE tenant_id = $2
        RETURNING balance
      ),
      new_transaction AS (
        INSERT INTO wallet_transactions (
          id, tenant_id, type, amount, balance, description, reference, metadata, created_at
        )
        SELECT 
          gen_random_uuid(), 
          $2, 
          $3, 
          $1, 
          (SELECT balance FROM updated_wallet), 
          $4, 
          $5, 
          $6, 
          NOW()
        WHERE EXISTS (SELECT 1 FROM updated_wallet)
        RETURNING id, tenant_id, type, amount, balance, description, reference, metadata, created_at
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
    } catch {
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

  private async recordTransaction(
    tenantId: string,
    type: WalletTransaction['type'],
    amount: number,
    description: string,
    reference?: string,
    metadata: Record<string, unknown> = {},
    newBalance?: number
  ): Promise<Result<WalletTransaction, Error>> {
    // Get current balance if not provided
    if (newBalance === undefined) {
      const balanceResult = await this.getBalance(tenantId);
      newBalance = balanceResult.ok ? balanceResult.value.balance : 0;
    }

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
    }>(
      `INSERT INTO wallet_transactions (
        id, tenant_id, type, amount, balance, description, reference, metadata, created_at
      )
      VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, NOW())
      RETURNING *`,
      [tenantId, type, amount, newBalance, description, reference ?? null, JSON.stringify(metadata)]
    );

    if (!result.ok) return Result.err(result.error);

    if (result.value.rows.length === 0) {
      return Result.err(new Error('INSERT RETURNING produced no rows'));
    }
    const row = result.value.rows[0]!;
    let parsedMetadata: Record<string, unknown> = {};
    try {
      parsedMetadata = JSON.parse(row.metadata || '{}');
    } catch {
      parsedMetadata = {};
    }
    
    return Result.ok({
      id: row.id,
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
