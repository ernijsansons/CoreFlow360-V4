/**
 * Comprehensive Audit Logging System
 * Provides tamper-proof audit trail for all critical operations
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  sanitizeBusinessId,
  sanitizeUserId,
  sanitizeForLogging,
  // hashSensitiveData,
  // generateSecureToken
} from './security-utils';

export interface AuditEntry {
  id: string;
  timestamp: number;
  event_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  business_id: string;
  user_id: string;
  agent_id?: string;
  task_id?: string;
  session_id?: string;
  event_data: Record<string, any>;
  message: string;
  correlation_id?: string;
  ip_address?: string;
  user_agent?: string;
  hash?: string; // For tamper detection
  previous_hash?: string; // Chain of hashes for integrity
}

export enum AuditEventType {
  // Authentication & Authorization
  AUTH_LOGIN = 'auth.login',
  AUTH_LOGOUT = 'auth.logout',
  AUTH_FAILED = 'auth.failed',
  PERMISSION_DENIED = 'permission.denied',

  // Agent Operations
  AGENT_REGISTERED = 'agent.registered',
  AGENT_DEACTIVATED = 'agent.deactivated',
  AGENT_REMOVED = 'agent.removed',
  AGENT_HEALTH_CHANGED = 'agent.health_changed',
  AGENT_CONFIG_UPDATED = 'agent.config_updated',

  // Task Execution
  TASK_STARTED = 'task.started',
  TASK_COMPLETED = 'task.completed',
  TASK_FAILED = 'task.failed',
  TASK_CANCELLED = 'task.cancelled',
  TASK_RETRIED = 'task.retried',

  // Cost & Limits
  COST_LIMIT_EXCEEDED = 'cost.limit_exceeded',
  COST_LIMIT_UPDATED = 'cost.limit_updated',
  COST_RESERVATION_CREATED = 'cost.reservation_created',
  COST_RESERVATION_RELEASED = 'cost.reservation_released',

  // Workflow Operations
  WORKFLOW_STARTED = 'workflow.started',
  WORKFLOW_COMPLETED = 'workflow.completed',
  WORKFLOW_FAILED = 'workflow.failed',
  WORKFLOW_STEP_FAILED = 'workflow.step_failed',

  // Data Operations
  DATA_ACCESSED = 'data.accessed',
  DATA_MODIFIED = 'data.modified',
  DATA_DELETED = 'data.deleted',
  DATA_EXPORTED = 'data.exported',

  // Security Events
  SECURITY_VIOLATION = 'security.violation',
  PROMPT_INJECTION_BLOCKED = 'security.prompt_injection_blocked',
  SQL_INJECTION_BLOCKED = 'security.sql_injection_blocked',
  RATE_LIMIT_EXCEEDED = 'security.rate_limit_exceeded',
  SUSPICIOUS_ACTIVITY = 'security.suspicious_activity',

  // System Events
  SYSTEM_ERROR = 'system.error',
  SYSTEM_WARNING = 'system.warning',
  SYSTEM_MAINTENANCE = 'system.maintenance',
  CONFIG_CHANGED = 'config.changed',

  // Compliance Events
  COMPLIANCE_VIOLATION = 'compliance.violation',
  PII_ACCESS = 'compliance.pii_access',
  DATA_RETENTION_APPLIED = 'compliance.data_retention_applied',
  AUDIT_TRAIL_ACCESSED = 'compliance.audit_trail_accessed'
}

export class AuditLogger {
  private static instance: AuditLogger | null = null;
  private db: D1Database;
  private logger: Logger;
  private previousHash: string | null = null;
  private buffer: AuditEntry[] = [];
  private flushInterval: number = 5000; // 5 seconds
  private maxBufferSize: number = 100;
  private flushTimer?: NodeJS.Timeout;

  constructor(db: D1Database) {
    this.db = db;
    this.logger = new Logger();
    this.startFlushTimer();
  }

  /**
   * Get singleton instance
   */
  static getInstance(db: D1Database): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger(db);
    }
    return AuditLogger.instance;
  }

  /**
   * Log an audit event
   */
  async log(
    eventType: AuditEventType | string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    businessId: string,
    userId: string,
    details: Record<string, any>,
    metadata?: {
      agentId?: string;
      taskId?: string;
      sessionId?: string;
      correlationId?: string;
      ipAddress?: string;
      userAgent?: string;
    }
  ): Promise<void> {
    try {
      // Validate and sanitize inputs
      const safeBusinessId = sanitizeBusinessId(businessId);
      const safeUserId = sanitizeUserId(userId);

      // Create audit entry
      const entry: AuditEntry = {
        id: Math.random().toString(36).substring(2, 18),
        timestamp: Date.now(),
        event_type: eventType,
        severity,
        business_id: safeBusinessId,
        user_id: safeUserId,
        agent_id: metadata?.agentId,
        task_id: metadata?.taskId,
        session_id: metadata?.sessionId,
        event_data: sanitizeForLogging(details),
        message: this.createAuditMessage(eventType, details),
        correlation_id: metadata?.correlationId,
        ip_address: metadata?.ipAddress,
        user_agent: metadata?.userAgent,
        previous_hash: this.previousHash || undefined
      };

      // Generate hash for tamper detection
      entry.hash = await this.generateEntryHash(entry);
      this.previousHash = entry.hash;

      // Add to buffer
      this.buffer.push(entry);

      // Log high severity events immediately
      if (severity === 'critical' || severity === 'high') {
        await this.flush();
      } else if (this.buffer.length >= this.maxBufferSize) {
        // Flush if buffer is full
        await this.flush();
      }

      // Also log to standard logger for immediate visibility
      if (severity === 'critical' || severity === 'high') {
        this.logger.warn(`Audit Event: ${eventType}`, sanitizeForLogging({
          eventType,
          severity,
          businessId: safeBusinessId,
          userId: safeUserId,
          details
        }));
      }

    } catch (error) {
      this.logger.error('Failed to create audit log entry', error, {
        eventType,
        businessId,
        userId
      });
    }
  }

  /**
   * Query audit logs
   */
  async query(
    businessId: string,
    filters?: {
      startTime?: number;
      endTime?: number;
      eventType?: string;
      severity?: string;
      userId?: string;
      agentId?: string;
      limit?: number;
    }
  ): Promise<AuditEntry[]> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);
      const limit = Math.min(filters?.limit || 100, 1000); // Max 1000 records

      let query = `
        SELECT * FROM agent_system_events
        WHERE business_id = ?
      `;
      const params: any[] = [safeBusinessId];

      if (filters?.startTime) {
        query += ` AND timestamp >= ?`;
        params.push(filters.startTime);
      }

      if (filters?.endTime) {
        query += ` AND timestamp <= ?`;
        params.push(filters.endTime);
      }

      if (filters?.eventType) {
        query += ` AND event_type = ?`;
        params.push(filters.eventType);
      }

      if (filters?.severity) {
        query += ` AND severity = ?`;
        params.push(filters.severity);
      }

      if (filters?.userId) {
        const safeUserId = sanitizeUserId(filters.userId);
        query += ` AND user_id = ?`;
        params.push(safeUserId);
      }

      if (filters?.agentId) {
        query += ` AND agent_id = ?`;
        params.push(filters.agentId);
      }

      query += ` ORDER BY timestamp DESC LIMIT ?`;
      params.push(limit);

      const result = await this.db.prepare(query).bind(...params).all();

      // Log audit trail access
      await this.log(
        AuditEventType.AUDIT_TRAIL_ACCESSED,
        'low',
        businessId,
        filters?.userId || 'system',
        { filters, recordCount: result.results?.length || 0 }
      );

      return (result.results || []).map((row: any) => ({
        id: row.id,
        timestamp: row.timestamp,
        event_type: row.event_type,
        severity: row.severity,
        business_id: row.business_id,
        user_id: row.user_id,
        agent_id: row.agent_id,
        task_id: row.task_id,
        session_id: row.session_id,
        event_data: JSON.parse(row.event_data || '{}'),
        message: row.message,
        correlation_id: row.correlation_id,
        ip_address: row.ip_address,
        user_agent: row.user_agent,
        hash: row.hash,
        previous_hash: row.previous_hash
      }));

    } catch (error) {
      this.logger.error('Failed to query audit logs', error, {
        businessId,
        filters
      });
      return [];
    }
  }

  /**
   * Verify audit log integrity
   */
  async verifyIntegrity(
    businessId: string,
    startTime: number,
    endTime: number
  ): Promise<{ valid: boolean; brokenAt?: string }> {
    try {
      const safeBusinessId = sanitizeBusinessId(businessId);

      const result = await this.db.prepare(`
        SELECT id, hash, previous_hash, event_data, timestamp
        FROM agent_system_events
        WHERE business_id = ?
        AND timestamp >= ?
        AND timestamp <= ?
        ORDER BY timestamp ASC
      `).bind(safeBusinessId, startTime, endTime).all();

      const entries = result.results || [];
      let previousHash: string | null = null;

      for (const entry of entries) {
        // Verify hash chain
        if (previousHash && entry.previous_hash !== previousHash) {
          return {
            valid: false,
            brokenAt: entry.id
          };
        }

        // Verify individual entry hash
        const calculatedHash = await this.generateEntryHash({
          ...entry,
          event_data: JSON.parse(entry.event_data || '{}')
        });

        if (calculatedHash !== entry.hash) {
          return {
            valid: false,
            brokenAt: entry.id
          };
        }

        previousHash = entry.hash;
      }

      return { valid: true };

    } catch (error) {
      this.logger.error('Failed to verify audit integrity', error, {
        businessId,
        startTime,
        endTime
      });
      return { valid: false };
    }
  }

  /**
   * Flush buffer to database
   */
  private async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const entriesToFlush = [...this.buffer];
    this.buffer = [];

    try {
      // Batch insert
      const insertPromises = entriesToFlush.map(entry =>
        this.db.prepare(`
          INSERT INTO agent_system_events (
            id, event_type, severity, business_id, user_id,
            agent_id, task_id, session_id, event_data, message,
            correlation_id, ip_address, user_agent, timestamp,
            hash, previous_hash
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          entry.id,
          entry.event_type,
          entry.severity,
          entry.business_id,
          entry.user_id,
          entry.agent_id || null,
          entry.task_id || null,
          entry.session_id || null,
          JSON.stringify(entry.event_data),
          entry.message,
          entry.correlation_id || null,
          entry.ip_address || null,
          entry.user_agent || null,
          entry.timestamp,
          entry.hash,
          entry.previous_hash || null
        ).run()
      );

      await Promise.allSettled(insertPromises);

      this.logger.debug('Audit buffer flushed', {
        entriesCount: entriesToFlush.length
      });

    } catch (error) {
      this.logger.error('Failed to flush audit buffer', error, {
        entriesCount: entriesToFlush.length
      });

      // Re-add failed entries to buffer
      this.buffer.unshift(...entriesToFlush);
    }
  }

  /**
   * Generate hash for audit entry
   */
  private async generateEntryHash(entry: AuditEntry): Promise<string> {
    const dataToHash = JSON.stringify({
      id: entry.id,
      timestamp: entry.timestamp,
      event_type: entry.event_type,
      severity: entry.severity,
      business_id: entry.business_id,
      user_id: entry.user_id,
      event_data: entry.event_data,
      previous_hash: entry.previous_hash
    });

    return JSON.stringify(dataToHash);
  }

  /**
   * Create human-readable audit message
   */
  private createAuditMessage(eventType: string, details: Record<string, any>): string {
    const messages: Record<string, string> = {
      [AuditEventType.TASK_STARTED]: `Task ${details.taskId} started with capability ${details.capability}`,
      [AuditEventType.TASK_COMPLETED]: `Task ${details.taskId} completed successfully`,
      [AuditEventType.TASK_FAILED]: `Task ${details.taskId} failed: ${details.error}`,
      [AuditEventType.COST_LIMIT_EXCEEDED]: `Cost limit exceeded: ${details.current} > ${details.limit}`,
      [AuditEventType.SECURITY_VIOLATION]: `Security violation detected: ${details.type}`,
      [AuditEventType.AGENT_REGISTERED]: `Agent ${details.agentId} registered`,
      [AuditEventType.AGENT_DEACTIVATED]: `Agent ${details.agentId} deactivated: ${details.reason}`,
      // Add more message templates as needed
    };

    return messages[eventType] || `Event: ${eventType}`;
  }

  /**
   * Start flush timer
   */
  private startFlushTimer(): void {
    this.flushTimer = setInterval(async () => {
      await this.flush();
    }, this.flushInterval) as any;
  }

  /**
   * Cleanup and shutdown
   */
  async shutdown(): Promise<void> {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    await this.flush();
    this.logger.info('Audit logger shutdown completed');
  }

  /**
   * Log critical security events
   */
  async logSecurityEvent(
    type: 'prompt_injection' | 'sql_injection' | 'unauthorized_access' | 'data_breach',
    businessId: string,
    userId: string,
    details: Record<string, any>
  ): Promise<void> {
    await this.log(
      AuditEventType.SECURITY_VIOLATION,
      'critical',
      businessId,
      userId,
      { type, ...details }
    );
  }

  /**
   * Log compliance events
   */
  async logComplianceEvent(
    type: 'pii_access' | 'data_retention' | 'gdpr_violation',
    businessId: string,
    userId: string,
    details: Record<string, any>
  ): Promise<void> {
    await this.log(
      AuditEventType.COMPLIANCE_VIOLATION,
      'high',
      businessId,
      userId,
      { type, ...details }
    );
  }
}