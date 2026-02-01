/**
 * Wallet Service
 * Pre-paid balance management with ledger
 */

import Redis from 'ioredis';
import { Result } from '@apexmail/lib';
import { createLogger } from '@apexmail/lib/logger';
import type { DatabasePool } from '@apexmail/db';

const logger = createLogger('wallet');

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
      const cached = JSON.parse(cachedBalance);
      return Result.ok({
        tenantId,
        balance: cached.balance,
        reservedBalance: cached.reserved,
        availableBalance: cached.balance - cached.reserved,
        currency: 'EUR',
        updatedAt: new Date(cached.updatedAt),
      });
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

    // Check available balance
    const balanceResult = await this.getBalance(tenantId);
    if (!balanceResult.ok) return Result.err(balanceResult.error);

    if (balanceResult.value.availableBalance < amount) {
      return Result.err(new Error('Insufficient balance'));
    }

    return this.executeTransaction(tenantId, 'debit', -amount, description, reference, metadata);
  }

  /**
   * Reserve funds for pending charge
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

    // Check available balance
    const balanceResult = await this.getBalance(tenantId);
    if (!balanceResult.ok) return Result.err(balanceResult.error);

    if (balanceResult.value.availableBalance < amount) {
      return Result.err(new Error('Insufficient balance'));
    }

    const result = await this.db.query<{ id: string }>(
      `INSERT INTO wallet_reservations (id, tenant_id, amount, description, reference, status, created_at, expires_at)
       VALUES (gen_random_uuid(), $1, $2, $3, $4, 'pending', NOW(), NOW() + INTERVAL '24 hours')
       RETURNING id`,
      [tenantId, amount, description, reference ?? null]
    );

    if (!result.ok) return Result.err(result.error);

    const reservationId = result.value.rows[0]!.id;

    // Update reserved balance
    await this.db.query(
      `UPDATE wallets SET reserved_balance = reserved_balance + $1, updated_at = NOW() WHERE tenant_id = $2`,
      [amount, tenantId]
    );

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    await this.recordTransaction(tenantId, 'reserve', 0, `Reserved: ${description}`, reservationId, { reservationId, amount });

    return Result.ok({ reservationId });
  }

  /**
   * Capture reserved funds
   */
  async captureReservation(reservationId: string): Promise<Result<WalletTransaction, Error>> {
    const reservationResult = await this.db.query<{
      tenant_id: string;
      amount: number;
      description: string;
      reference: string | null;
      status: string;
    }>(
      `SELECT * FROM wallet_reservations WHERE id = $1`,
      [reservationId]
    );

    if (!reservationResult.ok) return Result.err(reservationResult.error);

    const reservation = reservationResult.value.rows[0];
    if (!reservation) return Result.err(new Error('Reservation not found'));

    if (reservation.status !== 'pending') {
      return Result.err(new Error('Reservation already processed'));
    }

    // Update reservation status
    await this.db.query(
      `UPDATE wallet_reservations SET status = 'captured', captured_at = NOW() WHERE id = $1`,
      [reservationId]
    );

    // Deduct from balance and reserved
    await this.db.query(
      `UPDATE wallets 
       SET balance = balance - $1, 
           reserved_balance = reserved_balance - $1,
           updated_at = NOW()
       WHERE tenant_id = $2`,
      [reservation.amount, reservation.tenant_id]
    );

    // Invalidate cache
    await this.redis.del(`wallet:balance:${reservation.tenant_id}`);

    return this.recordTransaction(
      reservation.tenant_id,
      'debit',
      -reservation.amount,
      `Captured: ${reservation.description}`,
      reservationId,
      { reservationId }
    );
  }

  /**
   * Release reserved funds
   */
  async releaseReservation(reservationId: string): Promise<Result<void, Error>> {
    const reservationResult = await this.db.query<{
      tenant_id: string;
      amount: number;
      status: string;
    }>(
      `SELECT * FROM wallet_reservations WHERE id = $1`,
      [reservationId]
    );

    if (!reservationResult.ok) return Result.err(reservationResult.error);

    const reservation = reservationResult.value.rows[0];
    if (!reservation) return Result.err(new Error('Reservation not found'));

    if (reservation.status !== 'pending') {
      return Result.err(new Error('Reservation already processed'));
    }

    // Update reservation status
    await this.db.query(
      `UPDATE wallet_reservations SET status = 'released', released_at = NOW() WHERE id = $1`,
      [reservationId]
    );

    // Release reserved balance
    await this.db.query(
      `UPDATE wallets SET reserved_balance = reserved_balance - $1, updated_at = NOW() WHERE tenant_id = $2`,
      [reservation.amount, reservation.tenant_id]
    );

    // Invalidate cache
    await this.redis.del(`wallet:balance:${reservation.tenant_id}`);

    await this.recordTransaction(
      reservation.tenant_id,
      'release',
      0,
      'Released reservation',
      reservationId,
      { reservationId, amount: reservation.amount }
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

    return Result.ok(result.value.rows.map(row => ({
      id: row.id,
      tenantId: row.tenant_id,
      type: row.type,
      amount: row.amount,
      balance: row.balance,
      description: row.description,
      reference: row.reference,
      metadata: JSON.parse(row.metadata || '{}'),
      createdAt: row.created_at,
    })));
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
    // Update balance atomically
    const updateResult = await this.db.query<{
      balance: number;
    }>(
      `UPDATE wallets
       SET balance = balance + $1, updated_at = NOW()
       WHERE tenant_id = $2
       RETURNING balance`,
      [amount, tenantId]
    );

    if (!updateResult.ok) return Result.err(updateResult.error);

    const newBalance = updateResult.value.rows[0]?.balance ?? 0;

    // Invalidate cache
    await this.redis.del(`wallet:balance:${tenantId}`);

    return this.recordTransaction(tenantId, type, amount, description, reference, metadata, newBalance);
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

    const row = result.value.rows[0]!;
    return Result.ok({
      id: row.id,
      tenantId: row.tenant_id,
      type: row.type,
      amount: row.amount,
      balance: row.balance,
      description: row.description,
      reference: row.reference,
      metadata: JSON.parse(row.metadata || '{}'),
      createdAt: row.created_at,
    });
  }
}
