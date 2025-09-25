/**
 * Cost Reservation Manager
 * Implements pessimistic locking for cost tracking to prevent overspending
 */

import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  generateSecureToken,
  sanitizeBusinessId,
  sanitizeUserId
} from './security-utils';
import { AuditLogger, AuditEventType } from './audit-logger';

export interface CostReservation {
  id: string;
  businessId: string;
  userId: string;
  taskId: string;
  agentId: string;
  estimatedCost: number;
  actualCost?: number;
  status: 'pending' | 'committed' | 'released' | 'expired';
  createdAt: number;
  expiresAt: number;
  committedAt?: number;
  releasedAt?: number;
  metadata?: Record<string, any>;
}

export interface ReservationLimits {
  daily: number;
  monthly: number;
  perTask: number;
  perUser: number;
}

export interface ReservationResult {
  success: boolean;
  reservationId?: string;
  reason?: string;
  currentSpend?: {
    daily: number;
    monthly: number;
  };
  limits?: ReservationLimits;
}

export // TODO: Consider splitting CostReservationManager into smaller, focused classes
class CostReservationManager {
  private logger: Logger;
  private kv: KVNamespace;
  private db: D1Database;
  private auditLogger: AuditLogger;
  private reservationTTL: number = 300000; // 5 minutes default
  private cleanupInterval?: NodeJS.Timeout;

  constructor(kv: KVNamespace, db: D1Database) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;
    this.auditLogger = AuditLogger.getInstance(db);
    this.startCleanupTimer();
  }

  /**
   * Reserve cost before task execution
   */
  async reserve(
    businessId: string,
    userId: string,
    taskId: string,
    agentId: string,
    estimatedCost: number,
    metadata?: Record<string, any>
  ): Promise<ReservationResult> {
    try {
      // Validate inputs
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeUserId = sanitizeUserId(userId);

      // Validate cost
      if (typeof estimatedCost !== 'number' || estimatedCost < 0 || !isFinite(estimatedCost)) {
        return {
          success: false,
          reason: 'Invalid cost amount'
        };
      }

      // Get current spend and limits
      const [currentSpend, limits] = await Promise.all([
        this.getCurrentSpend(safeBusinessId),
        this.getBusinessLimits(safeBusinessId)
      ]);

      // Calculate projected spend with reservation
      const projectedDaily = currentSpend.daily + estimatedCost;
      const projectedMonthly = currentSpend.monthly + estimatedCost;

      // Check if reservation would exceed limits
      if (projectedDaily > limits.daily) {
        await this.auditLogger.log(
          AuditEventType.COST_LIMIT_EXCEEDED,
          'high',
          safeBusinessId,
          safeUserId,
          {
            type: 'daily',
            current: currentSpend.daily,
            estimated: estimatedCost,
            projected: projectedDaily,
            limit: limits.daily
          },
          { taskId, agentId }
        );

        return {
          success: false,
          reason: `Daily cost limit would be exceeded: $${projectedDaily.toFixed(2)} > $${limits.daily}`,
          currentSpend,
          limits
        };
      }

      if (projectedMonthly > limits.monthly) {
        await this.auditLogger.log(
          AuditEventType.COST_LIMIT_EXCEEDED,
          'high',
          safeBusinessId,
          safeUserId,
          {
            type: 'monthly',
            current: currentSpend.monthly,
            estimated: estimatedCost,
            projected: projectedMonthly,
            limit: limits.monthly
          },
          { taskId, agentId }
        );

        return {
          success: false,
          reason: `Monthly cost limit would be exceeded: $${projectedMonthly.toFixed(2)} > $${limits.monthly}`,
          currentSpend,
          limits
        };
      }

      if (estimatedCost > limits.perTask) {
        return {
          success: false,
          reason: `Task cost exceeds per-task limit: $${estimatedCost.toFixed(2)} > $${limits.perTask}`,
          currentSpend,
          limits
        };
      }

      // Create reservation
      const reservation: CostReservation = {
        id: generateSecureToken(16),
        businessId: safeBusinessId,
        userId: safeUserId,
        taskId,
        agentId,
        estimatedCost,
        status: 'pending',
        createdAt: Date.now(),
        expiresAt: Date.now() + this.reservationTTL,
        metadata
      };

      // Store reservation in KV (for fast access)
      await this.kv.put(
        `reservation:${reservation.id}`,
        JSON.stringify(reservation),
        { expirationTtl: Math.ceil(this.reservationTTL / 1000) }
      );

      // Update reserved amounts in KV
      await this.updateReservedAmounts(safeBusinessId, estimatedCost, 'add');

      // Store in database for persistence
      await this.db.prepare(`
        INSERT INTO cost_reservations (
          id, business_id, user_id, task_id, agent_id,
          estimated_cost, status, created_at, expires_at, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        reservation.id,
        reservation.businessId,
        reservation.userId,
        reservation.taskId,
        reservation.agentId,
        reservation.estimatedCost,
        reservation.status,
        reservation.createdAt,
        reservation.expiresAt,
        JSON.stringify(reservation.metadata || {})
      ).run();

      // Log reservation creation
      await this.auditLogger.log(
        AuditEventType.COST_RESERVATION_CREATED,
        'low',
        safeBusinessId,
        safeUserId,
        {
          reservationId: reservation.id,
          estimatedCost,
          currentSpend,
          limits
        },
        { taskId, agentId }
      );

      this.logger.info('Cost reservation created', {
        reservationId: reservation.id,
        businessId: safeBusinessId,
        estimatedCost,
        expiresAt: reservation.expiresAt
      });

      return {
        success: true,
        reservationId: reservation.id,
        currentSpend,
        limits
      };

    } catch (error) {
      this.logger.error('Failed to create cost reservation', error, {
        businessId,
        taskId,
        estimatedCost
      });

      return {
        success: false,
        reason: 'Failed to create reservation'
      };
    }
  }

  /**
   * Commit reservation with actual cost
   */
  async commit(reservationId: string, actualCost: number): Promise<boolean> {
    try {
      // Get reservation from KV
      const reservationData = await this.kv.get(`reservation:${reservationId}`, 'json');
      if (!reservationData) {
        this.logger.warn('Reservation not found for commit', { reservationId });
        return false;
      }

      const reservation = reservationData as CostReservation;

      // Check if reservation is still valid
      if (reservation.status !== 'pending') {
        this.logger.warn('Reservation already processed', {
          reservationId,
          status: reservation.status
        });
        return false;
      }

      if (Date.now() > reservation.expiresAt) {
        this.logger.warn('Reservation expired', {
          reservationId,
          expiredAt: reservation.expiresAt
        });
        return false;
      }

      // Update reservation status
      reservation.status = 'committed';
      reservation.actualCost = actualCost;
      reservation.committedAt = Date.now();

      // Update in KV
      await this.kv.put(
        `reservation:${reservationId}`,
        JSON.stringify(reservation),
        { expirationTtl: 3600 } // Keep for 1 hour after commit
      );

      // Update in database
      await this.db.prepare(`
        UPDATE cost_reservations
        SET status = 'committed',
            actual_cost = ?,
            committed_at = ?
        WHERE id = ?
      `).bind(actualCost, reservation.committedAt, reservationId).run();

      // Adjust reserved amounts (remove estimated, actual cost will be tracked separately)
      await this.updateReservedAmounts(reservation.businessId, reservation.estimatedCost, 'subtract');

      // If actual cost differs significantly from estimate, log it
      const difference = Math.abs(actualCost - reservation.estimatedCost);
      const percentDifference = (difference / reservation.estimatedCost) * 100;

      if (percentDifference > 20) {
        this.logger.warn('Significant cost difference from estimate', {
          reservationId,
          estimated: reservation.estimatedCost,
          actual: actualCost,
          difference,
          percentDifference
        });
      }

      this.logger.info('Cost reservation committed', {
        reservationId,
        estimatedCost: reservation.estimatedCost,
        actualCost,
        difference
      });

      return true;

    } catch (error) {
      this.logger.error('Failed to commit reservation', error, { reservationId });
      return false;
    }
  }

  /**
   * Release reservation (on failure or cancellation)
   */
  async release(reservationId: string, reason: string = 'Task failed'): Promise<boolean> {
    try {
      // Get reservation from KV
      const reservationData = await this.kv.get(`reservation:${reservationId}`, 'json');
      if (!reservationData) {
        this.logger.warn('Reservation not found for release', { reservationId });
        return false;
      }

      const reservation = reservationData as CostReservation;

      // Check if reservation can be released
      if (reservation.status !== 'pending') {
        this.logger.warn('Cannot release non-pending reservation', {
          reservationId,
          status: reservation.status
        });
        return false;
      }

      // Update reservation status
      reservation.status = 'released';
      reservation.releasedAt = Date.now();

      // Remove from KV (no longer needed)
      await this.kv.delete(`reservation:${reservationId}`);

      // Update in database
      await this.db.prepare(`
        UPDATE cost_reservations
        SET status = 'released',
            released_at = ?,
            metadata = json_patch(metadata, ?)
        WHERE id = ?
      `).bind(
        reservation.releasedAt,
        JSON.stringify({ releaseReason: reason }),
        reservationId
      ).run();

      // Return reserved amount
      await this.updateReservedAmounts(reservation.businessId, reservation.estimatedCost, 'subtract');

      // Log release
      await this.auditLogger.log(
        AuditEventType.COST_RESERVATION_RELEASED,
        'low',
        reservation.businessId,
        reservation.userId,
        {
          reservationId,
          estimatedCost: reservation.estimatedCost,
          reason
        },
        { taskId: reservation.taskId, agentId: reservation.agentId }
      );

      this.logger.info('Cost reservation released', {
        reservationId,
        estimatedCost: reservation.estimatedCost,
        reason
      });

      return true;

    } catch (error) {
      this.logger.error('Failed to release reservation', error, { reservationId });
      return false;
    }
  }

  /**
   * Get current spend including reservations
   */
  async getCurrentSpendWithReservations(businessId: string): Promise<{
    daily: number;
    monthly: number;
    reserved: number;
  }> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);

      // Get actual spend
      const [daily, monthly] = await Promise.all([
        this.getDailySpend(safeBusinessId),
        this.getMonthlySpend(safeBusinessId)
      ]);

      // Get reserved amount
      const reservedKey = `reserved:${safeBusinessId}`;
      const reserved = await this.kv.get(reservedKey, 'json') as { amount: number } || { amount: 0 };

      return {
        daily: daily + reserved.amount,
        monthly: monthly + reserved.amount,
        reserved: reserved.amount
      };

    } catch (error) {
      this.logger.error('Failed to get spend with reservations', error, { businessId });
      return { daily: 0, monthly: 0, reserved: 0 };
    }
  }

  /**
   * Clean up expired reservations
   */
  private async cleanupExpiredReservations(): Promise<void> {
    try {
      const now = Date.now();

      // Find expired pending reservations
      const result = await this.db.prepare(`
        SELECT id, business_id, estimated_cost
        FROM cost_reservations
        WHERE status = 'pending'
        AND expires_at < ?
        LIMIT 100
      `).bind(now).all();

      const expired = result.results || [];

      for (const reservation of expired) {
        // Release the reservation
        await this.release(reservation.id as string, 'Expired');
      }

      if (expired.length > 0) {
        this.logger.info('Cleaned up expired reservations', {
          count: expired.length
        });
      }

    } catch (error) {
      this.logger.error('Failed to cleanup expired reservations', error);
    }
  }

  /**
   * Update reserved amounts in KV
   */
  private async updateReservedAmounts(
    businessId: string,
    amount: number,
    operation: 'add' | 'subtract'
  ): Promise<void> {
    const key = `reserved:${businessId}`;
    const current = await this.kv.get(key, 'json') as { amount: number } || { amount: 0 };

    const newAmount = operation === 'add'
      ? current.amount + amount
      : Math.max(0, current.amount - amount);

    await this.kv.put(key, JSON.stringify({ amount: newAmount }), {
      expirationTtl: 86400 // 24 hours
    });
  }

  /**
   * Get current actual spend (not including reservations)
   */
  private async getCurrentSpend(businessId: string): Promise<{ daily: number; monthly: number }> {
    const [daily, monthly] = await Promise.all([
      this.getDailySpend(businessId),
      this.getMonthlySpend(businessId)
    ]);

    return { daily, monthly };
  }

  /**
   * Get daily spend from database
   */
  private async getDailySpend(businessId: string): Promise<number> {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);

    const result = await this.db.prepare(`
      SELECT SUM(cost) as total
      FROM agent_costs
      WHERE business_id = ?
      AND timestamp >= ?
    `).bind(businessId, startOfDay.getTime()).first();

    return (result?.total as number) || 0;
  }

  /**
   * Get monthly spend from database
   */
  private async getMonthlySpend(businessId: string): Promise<number> {
    const startOfMonth = new Date();
    startOfMonth.setDate(1);
    startOfMonth.setHours(0, 0, 0, 0);

    const result = await this.db.prepare(`
      SELECT SUM(cost) as total
      FROM agent_costs
      WHERE business_id = ?
      AND timestamp >= ?
    `).bind(businessId, startOfMonth.getTime()).first();

    return (result?.total as number) || 0;
  }

  /**
   * Get business cost limits
   */
  private async getBusinessLimits(businessId: string): Promise<ReservationLimits> {
    // First check for custom limits in database
    const result = await this.db.prepare(`
      SELECT daily_limit, monthly_limit, per_task_limit, per_user_limit
      FROM business_cost_limits
      WHERE business_id = ?
    `).bind(businessId).first();

    if (result) {
      return {
        daily: (result.daily_limit as number) || 100,
        monthly: (result.monthly_limit as number) || 2000,
        perTask: (result.per_task_limit as number) || 10,
        perUser: (result.per_user_limit as number) || 50
      };
    }

    // Return defaults
    return {
      daily: 100,
      monthly: 2000,
      perTask: 10,
      perUser: 50
    };
  }

  /**
   * Start cleanup timer for expired reservations
   */
  private startCleanupTimer(): void {
    // Run cleanup every 5 minutes
    this.cleanupInterval = setInterval(async () => {
      await this.cleanupExpiredReservations();
    }, 300000) as any;
  }

  /**
   * Shutdown and cleanup
   */
  async shutdown(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
    await this.cleanupExpiredReservations();
    this.logger.info('Cost reservation manager shutdown completed');
  }
}

// Add the table schema for cost_reservations
export const COST_RESERVATION_SCHEMA = `
CREATE TABLE IF NOT EXISTS cost_reservations (
  id TEXT PRIMARY KEY,
  business_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  estimated_cost REAL NOT NULL,
  actual_cost REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  committed_at INTEGER,
  released_at INTEGER,
  metadata TEXT,

  INDEX idx_cost_reservations_business_status (business_id, status),
  INDEX idx_cost_reservations_expires (expires_at) WHERE status = 'pending',
  INDEX idx_cost_reservations_task (task_id)
);

CREATE TABLE IF NOT EXISTS business_cost_limits (
  business_id TEXT PRIMARY KEY,
  daily_limit REAL NOT NULL DEFAULT 100.0,
  monthly_limit REAL NOT NULL DEFAULT 2000.0,
  per_task_limit REAL NOT NULL DEFAULT 10.0,
  per_user_limit REAL NOT NULL DEFAULT 50.0,
  currency TEXT DEFAULT 'USD',
  updated_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
  updated_by TEXT
);
`;