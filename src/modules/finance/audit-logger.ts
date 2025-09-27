/**
 * Finance Audit Logger
 * Specialized audit logging for financial transactions
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { AuditAction, AuditTrail } from './types';
import { validateBusinessId } from './utils';

export class FinanceAuditLogger {
  private logger: Logger;
  private db: D1Database;
  private hashCache = new Map<string, string>();

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Log an audit action
   */
  async logAction(
    entityType: AuditTrail['entityType'],
    entityId: string,
    action: AuditAction,
    businessId: string,
    userId: string,
    changes?: Record<string, any>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      const validBusinessId = validateBusinessId(businessId);
      const now = Date.now();

      const auditRecord: Omit<AuditTrail, 'id'> = {
        entityType,
        entityId,
        action,
        changes,
        performedBy: userId,
        performedAt: now,
        ipAddress,
        userAgent,
        businessId: validBusinessId
      };

      const auditId = `audit_${now}_${Math.random().toString(36).substring(2, 9)}`;

      // Calculate integrity hash
      const previousHash = await this.getLastAuditHash(validBusinessId);
      const currentHash = await this.calculateAuditHash(auditRecord, previousHash);

      await this.db.prepare(`
        INSERT INTO finance_audit_log (
          id, entity_type, entity_id, action, changes,
          performed_by, performed_at, ip_address, user_agent,
          business_id, previous_hash, current_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        auditId,
        entityType,
        entityId,
        action,
        changes ? JSON.stringify(changes) : null,
        userId,
        now,
        ipAddress || null,
        userAgent || null,
        validBusinessId,
        previousHash || null,
        currentHash
      ).run();

      // Cache the hash for next use
      this.hashCache.set(validBusinessId, currentHash);

      this.logger.debug('Finance audit logged', {
        auditId,
        entityType,
        entityId,
        action,
        businessId: validBusinessId
      });

    } catch (error: any) {
      this.logger.error('Failed to log finance audit', error, {
        entityType,
        entityId,
        action,
        businessId
      });
      // Don't throw - audit logging should not break main operations
    }
  }

  /**
   * Get audit trail for entity
   */
  async getAuditTrail(
    entityType: AuditTrail['entityType'],
    entityId: string,
    businessId: string,
    options?: {
      startDate?: number;
      endDate?: number;
      actions?: AuditAction[];
      limit?: number;
      offset?: number;
    }
  ): Promise<{ records: AuditTrail[]; total: number }> {
    const validBusinessId = validateBusinessId(businessId);

    let whereConditions = [
      'entity_type = ?',
      'entity_id = ?',
      'business_id = ?'
    ];
    let params: (string | number)[] = [entityType, entityId, validBusinessId];

    if (options?.startDate) {
      whereConditions.push('performed_at >= ?');
      params.push(options.startDate);
    }

    if (options?.endDate) {
      whereConditions.push('performed_at <= ?');
      params.push(options.endDate);
    }

    if (options?.actions && options.actions.length > 0) {
      const placeholders = options.actions.map(() => '?').join(',');
      whereConditions.push(`action IN (${placeholders})`);
      params.push(...options.actions);
    }

    const whereClause = whereConditions.join(' AND ');

    // Get total count
    const countResult = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM finance_audit_log
      WHERE ${whereClause}
    `).bind(...params).first();

    const total = (countResult?.count as number) || 0;

    // Get records
    let query = `
      SELECT * FROM finance_audit_log
      WHERE ${whereClause}
      ORDER BY performed_at DESC
    `;

    if (options?.limit) {
      query += ` LIMIT ${options.limit}`;
      if (options?.offset) {
        query += ` OFFSET ${options.offset}`;
      }
    }

    const result = await this.db.prepare(query).bind(...params).all();

    const records = (result.results || []).map((row: any) => this.mapToAuditTrail(row));

    return { records, total };
  }

  /**
   * Get business audit summary
   */
  async getBusinessAuditSummary(
    businessId: string,
    startDate?: number,
    endDate?: number
  ): Promise<{
    totalActions: number;
    actionsByType: Record<AuditAction, number>;
    entityActivity: Record<string, number>;
    userActivity: Record<string, number>;
    recentActivity: AuditTrail[];
  }> {
    const validBusinessId = validateBusinessId(businessId);

    let whereCondition = 'business_id = ?';
    let params: (string | number)[] = [validBusinessId];

    if (startDate) {
      whereCondition += ' AND performed_at >= ?';
      params.push(startDate);
    }

    if (endDate) {
      whereCondition += ' AND performed_at <= ?';
      params.push(endDate);
    }

    // Get action summary
    const actionsResult = await this.db.prepare(`
      SELECT action, COUNT(*) as count
      FROM finance_audit_log
      WHERE ${whereCondition}
      GROUP BY action
    `).bind(...params).all();

    const actionsByType: Record<AuditAction, number> = {} as any;
    let totalActions = 0;

    for (const row of actionsResult.results || []) {
      const action = row.action as AuditAction;
      const count = row.count as number;
      actionsByType[action] = count;
      totalActions += count;
    }

    // Get entity activity
    const entitiesResult = await this.db.prepare(`
      SELECT entity_type, COUNT(*) as count
      FROM finance_audit_log
      WHERE ${whereCondition}
      GROUP BY entity_type
      ORDER BY count DESC
    `).bind(...params).all();

    const entityActivity: Record<string, number> = {};
    for (const row of entitiesResult.results || []) {
      entityActivity[row.entity_type as string] = row.count as number;
    }

    // Get user activity
    const usersResult = await this.db.prepare(`
      SELECT performed_by, COUNT(*) as count
      FROM finance_audit_log
      WHERE ${whereCondition}
      GROUP BY performed_by
      ORDER BY count DESC
      LIMIT 10
    `).bind(...params).all();

    const userActivity: Record<string, number> = {};
    for (const row of usersResult.results || []) {
      userActivity[row.performed_by as string] = row.count as number;
    }

    // Get recent activity
    const recentResult = await this.db.prepare(`
      SELECT * FROM finance_audit_log
      WHERE ${whereCondition}
      ORDER BY performed_at DESC
      LIMIT 20
    `).bind(...params).all();

    const recentActivity = (recentResult.results || []).map((row: any) => this.mapToAuditTrail(row));

    return {
      totalActions,
      actionsByType,
      entityActivity,
      userActivity,
      recentActivity
    };
  }

  /**
   * Verify audit trail integrity
   */
  async verifyIntegrity(
    businessId: string,
    startDate?: number,
    endDate?: number
  ): Promise<{
    valid: boolean;
    totalRecords: number;
    invalidRecords: string[];
    missingHashes: number;
  }> {
    const validBusinessId = validateBusinessId(businessId);

    let whereCondition = 'business_id = ?';
    let params: (string | number)[] = [validBusinessId];

    if (startDate) {
      whereCondition += ' AND performed_at >= ?';
      params.push(startDate);
    }

    if (endDate) {
      whereCondition += ' AND performed_at <= ?';
      params.push(endDate);
    }

    const result = await this.db.prepare(`
      SELECT id, entity_type, entity_id, action, changes,
             performed_by, performed_at, ip_address, user_agent,
             business_id, previous_hash, current_hash
      FROM finance_audit_log
      WHERE ${whereCondition}
      ORDER BY performed_at ASC
    `).bind(...params).all();

    const records = result.results || [];
    let valid = true;
    const invalidRecords: string[] = [];
    let missingHashes = 0;
    let previousHash: string | null = null;

    for (const row of records) {
      if (!row.current_hash) {
        missingHashes++;
        continue;
      }

      // Reconstruct audit record for hash verification
      const auditRecord = {
        entityType: row.entity_type,
        entityId: row.entity_id,
        action: row.action,
        changes: row.changes ? JSON.parse(row.changes as string) : undefined,
        performedBy: row.performed_by,
        performedAt: row.performed_at,
        ipAddress: row.ip_address || undefined,
        userAgent: row.user_agent || undefined,
        businessId: row.business_id
      };

      const expectedHash = await this.calculateAuditHash(auditRecord, previousHash);

      if (expectedHash !== row.current_hash) {
        valid = false;
        invalidRecords.push(row.id as string);
      }

      // Check previous hash linkage
      if (row.previous_hash !== previousHash) {
        valid = false;
        invalidRecords.push(row.id as string);
      }

      previousHash = row.current_hash as string;
    }

    return {
      valid,
      totalRecords: records.length,
      invalidRecords,
      missingHashes
    };
  }

  /**
   * Get last audit hash for business
   */
  private async getLastAuditHash(businessId: string): Promise<string | null> {
    // Check cache first
    if (this.hashCache.has(businessId)) {
      return this.hashCache.get(businessId)!;
    }

    const result = await this.db.prepare(`
      SELECT current_hash FROM finance_audit_log
      WHERE business_id = ?
      ORDER BY performed_at DESC, id DESC
      LIMIT 1
    `).bind(businessId).first();

    const hash = result?.current_hash as string | null;
    if (hash) {
      this.hashCache.set(businessId, hash);
    }

    return hash;
  }

  /**
   * Calculate audit hash for integrity
   */
  private async calculateAuditHash(
    auditRecord: Omit<AuditTrail, 'id'>,
    previousHash: string | null
  ): Promise<string> {
    // Create deterministic string from audit record
    const hashData = {
      entityType: auditRecord.entityType,
      entityId: auditRecord.entityId,
      action: auditRecord.action,
      changes: auditRecord.changes || null,
      performedBy: auditRecord.performedBy,
      performedAt: auditRecord.performedAt,
      businessId: auditRecord.businessId,
      previousHash: previousHash || null
    };

    const dataString = JSON.stringify(hashData, Object.keys(hashData).sort());

    // Use Web Crypto API for hashing
    const encoder = new TextEncoder();
    const data = encoder.encode(dataString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b: any) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Map database row to AuditTrail
   */
  private mapToAuditTrail(row: Record<string, any>): AuditTrail {
    return {
      id: row.id,
      entityType: row.entity_type,
      entityId: row.entity_id,
      action: row.action,
      changes: row.changes ? JSON.parse(row.changes) : undefined,
      performedBy: row.performed_by,
      performedAt: row.performed_at,
      ipAddress: row.ip_address || undefined,
      userAgent: row.user_agent || undefined,
      businessId: row.business_id
    };
  }

  /**
   * Log journal entry creation
   */
  async logJournalEntryCreated(
    journalEntryId: string,
    businessId: string,
    userId: string,
    journalEntry: {
      entryNumber: string;
      description: string;
      lines?: Array<{ debit?: number; credit?: number }>;
    }
  ): Promise<void> {
    await this.logAction(
      'journal',
      journalEntryId,
      AuditAction.CREATE,
      businessId,
      userId,
      {
        entryNumber: journalEntry.entryNumber,
        description: journalEntry.description,
        amount: journalEntry.lines?.reduce((sum: number, line) => sum + (line.debit || 0), 0),
        lineCount: journalEntry.lines?.length || 0
      }
    );
  }

  /**
   * Log journal entry posted
   */
  async logJournalEntryPosted(
    journalEntryId: string,
    businessId: string,
    userId: string,
    entryNumber: string
  ): Promise<void> {
    await this.logAction(
      'journal',
      journalEntryId,
      AuditAction.POST,
      businessId,
      userId,
      { entryNumber }
    );
  }

  /**
   * Log period closing
   */
  async logPeriodClosed(
    periodId: string,
    businessId: string,
    userId: string,
    periodName: string,
    closingEntries?: number
  ): Promise<void> {
    await this.logAction(
      'period',
      periodId,
      AuditAction.CLOSE_PERIOD,
      businessId,
      userId,
      {
        periodName,
        closingEntries: closingEntries || 0,
        closedAt: Date.now()
      }
    );
  }

  /**
   * Log account creation
   */
  async logAccountCreated(
    accountId: string,
    businessId: string,
    userId: string,
    account: {
      name: string;
      code: string;
      type: string;
      parentId?: string;
    }
  ): Promise<void> {
    await this.logAction(
      'account',
      accountId,
      AuditAction.CREATE,
      businessId,
      userId,
      {
        code: account.code,
        name: account.name,
        type: account.type,
        category: account.category
      }
    );
  }

  /**
   * Clear hash cache
   */
  clearCache(): void {
    this.hashCache.clear();
  }
}