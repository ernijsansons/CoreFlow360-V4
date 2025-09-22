/**
 * Audit Trail Service for CoreFlow360 V4
 * Provides comprehensive audit logging for compliance and security
 */

import type { D1Database } from '@cloudflare/workers-types';
import { z } from 'zod';
import { auditLogger, type SecurityContext } from '../../shared/logger';
import { PIIRedactor, InputValidator, SecurityError } from '../../shared/security-utils';

/**
 * Audit event types
 */
export type AuditEventType =
  | 'permission_check'
  | 'permission_grant'
  | 'permission_deny'
  | 'policy_evaluation'
  | 'cache_invalidation'
  | 'user_login'
  | 'user_logout'
  | 'business_switch'
  | 'data_access'
  | 'data_modification'
  | 'data_deletion'
  | 'system_configuration'
  | 'security_violation'
  | 'compliance_event';

/**
 * Audit severity levels
 */
export type AuditSeverity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Audit entry interface
 */
export interface AuditEntry {
  id: string;
  timestamp: string;
  correlationId: string;
  eventType: AuditEventType;
  severity: AuditSeverity;
  userId: string;
  businessId: string;
  sessionId?: string;
  ipAddress: string;
  userAgent: string;
  operation: string;
  resource?: {
    type: string;
    id?: string;
    attributes?: Record<string, unknown>;
  };
  result: 'success' | 'failure' | 'partial';
  details: Record<string, unknown>;
  securityImpact?: {
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    indicators: string[];
    mitigated: boolean;
  };
  compliance?: {
    regulations: string[];
    dataTypes: string[];
    retention: {
      category: string;
      expiresAt: string;
    };
  };
}

/**
 * Audit entry validation schema
 */
const AuditEntrySchema = z.object({
  eventType: z.enum([
    'permission_check',
    'permission_grant',
    'permission_deny',
    'policy_evaluation',
    'cache_invalidation',
    'user_login',
    'user_logout',
    'business_switch',
    'data_access',
    'data_modification',
    'data_deletion',
    'system_configuration',
    'security_violation',
    'compliance_event',
  ]),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  operation: z.string().min(1).max(255),
  result: z.enum(['success', 'failure', 'partial']),
  details: z.record(z.unknown()),
});

/**
 * Audit service configuration
 */
export interface AuditServiceConfig {
  enableImmediateWrite: boolean;
  enableBatching: boolean;
  batchSize: number;
  batchInterval: number;
  retentionDays: number;
  compressionThreshold: number;
  enableEncryption: boolean;
}

/**
 * Default audit service configuration
 */
const DEFAULT_CONFIG: AuditServiceConfig = {
  enableImmediateWrite: true,
  enableBatching: true,
  batchSize: 100,
  batchInterval: 30000, // 30 seconds
  retentionDays: 2555, // 7 years for compliance
  compressionThreshold: 1000, // bytes
  enableEncryption: false, // Would require encryption key management
};

/**
 * Audit service for secure, compliant logging
 */
export // TODO: Consider splitting AuditService into smaller, focused classes
class AuditService {
  private db: D1Database;
  private config: AuditServiceConfig;
  private batchBuffer: AuditEntry[] = [];
  private batchTimer?: NodeJS.Timeout;
  private stats = {
    entriesCreated: 0,
    entriesBatched: 0,
    batchesWritten: 0,
    errors: 0,
    lastBatchWrite: 0,
  };

  constructor(db: D1Database, config?: Partial<AuditServiceConfig>) {
    this.db = db;
    this.config = { ...DEFAULT_CONFIG, ...config };

    if (this.config.enableBatching) {
      this.startBatchTimer();
    }
  }

  /**
   * Log permission check audit event
   */
  async logPermissionCheck(params: {
    capability: string;
    resource?: {
      type: string;
      id?: string;
      attributes?: Record<string, unknown>;
    };
    result: 'allow' | 'deny';
    reason: string;
    evaluationTimeMs: number;
    cacheHit: boolean;
    fastPath?: string;
    securityContext: SecurityContext;
  }): Promise<void> {
    const entry = await this.createAuditEntry({
      eventType: params.result === 'allow' ? 'permission_grant' : 'permission_deny',
      severity: params.result === 'deny' ? 'medium' : 'low',
      operation: `permission_check:${params.capability}`,
      result: 'success',
      resource: params.resource,
      details: {
        capability: params.capability,
        reason: params.reason,
        evaluationTimeMs: params.evaluationTimeMs,
        cacheHit: params.cacheHit,
        fastPath: params.fastPath,
        allowed: params.result === 'allow',
      },
      securityContext: params.securityContext,
    });

    await this.writeAuditEntry(entry);
  }

  /**
   * Log data access audit event
   */
  async logDataAccess(params: {
    resource: {
      type: string;
      id?: string;
      attributes?: Record<string, unknown>;
    };
    operation: 'read' | 'list' | 'search';
    result: 'success' | 'failure';
    recordCount?: number;
    securityContext: SecurityContext;
  }): Promise<void> {
    const entry = await this.createAuditEntry({
      eventType: 'data_access',
      severity: 'low',
      operation: `data_access:${params.operation}:${params.resource.type}`,
      result: params.result,
      resource: params.resource,
      details: {
        operation: params.operation,
        recordCount: params.recordCount,
        resourceType: params.resource.type,
      },
      securityContext: params.securityContext,
      compliance: {
        regulations: ['GDPR', 'SOX'],
        dataTypes: ['business_data'],
        retention: {
          category: 'access_log',
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
        },
      },
    });

    await this.writeAuditEntry(entry);
  }

  /**
   * Log data modification audit event
   */
  async logDataModification(params: {
    resource: {
      type: string;
      id?: string;
      attributes?: Record<string, unknown>;
    };
    operation: 'create' | 'update' | 'delete';
    changes?: {
      before?: Record<string, unknown>;
      after?: Record<string, unknown>;
      fields: string[];
    };
    result: 'success' | 'failure' | 'partial';
    securityContext: SecurityContext;
  }): Promise<void> {
    const severity: AuditSeverity =
      params.operation === 'delete' ? 'high' :
      params.operation === 'update' ? 'medium' : 'low';

    const entry = await this.createAuditEntry({
      eventType: 'data_modification',
      severity,
      operation: `data_modification:${params.operation}:${params.resource.type}`,
      result: params.result,
      resource: params.resource,
      details: {
        operation: params.operation,
        changes: params.changes ? this.sanitizeChanges(params.changes) : undefined,
        resourceType: params.resource.type,
      },
      securityContext: params.securityContext,
      compliance: {
        regulations: ['GDPR', 'SOX', 'HIPAA'],
        dataTypes: ['business_data', 'personal_data'],
        retention: {
          category: 'modification_log',
          expiresAt: new Date(Date.now() + 7 * 365 * 24 * 60 * 60 * 1000).toISOString(), // 7 years
        },
      },
    });

    await this.writeAuditEntry(entry);
  }

  /**
   * Log security violation
   */
  async logSecurityViolation(params: {
    violation: string;
    severity: AuditSeverity;
    indicators: string[];
    mitigated: boolean;
    details: Record<string, unknown>;
    securityContext: SecurityContext;
  }): Promise<void> {
    const entry = await this.createAuditEntry({
      eventType: 'security_violation',
      severity: params.severity,
      operation: `security_violation:${params.violation}`,
      result: params.mitigated ? 'success' : 'failure',
      details: params.details,
      securityContext: params.securityContext,
      securityImpact: {
        riskLevel: params.severity,
        indicators: params.indicators,
        mitigated: params.mitigated,
      },
      compliance: {
        regulations: ['GDPR', 'SOX', 'PCI-DSS'],
        dataTypes: ['security_data'],
        retention: {
          category: 'security_incident',
          expiresAt: new Date(Date.now() + 7 * 365 * 24 * 60 * 60 * 1000).toISOString(), // 7 years
        },
      },
    });

    // Immediate write for security violations
    await this.writeAuditEntry(entry, true);
  }

  /**
   * Log user authentication event
   */
  async logAuthentication(params: {
    event: 'login' | 'logout' | 'failed_login' | 'session_timeout';
    result: 'success' | 'failure';
    method?: string;
    failureReason?: string;
    securityContext: SecurityContext;
  }): Promise<void> {
    const severity: AuditSeverity =
      params.event === 'failed_login' ? 'medium' :
      params.result === 'failure' ? 'medium' : 'low';

    const entry = await this.createAuditEntry({
      eventType: params.event === 'login' ? 'user_login' : 'user_logout',
      severity,
      operation: `authentication:${params.event}`,
      result: params.result,
      details: {
        event: params.event,
        method: params.method,
        failureReason: params.failureReason,
      },
      securityContext: params.securityContext,
      compliance: {
        regulations: ['GDPR', 'SOX'],
        dataTypes: ['authentication_data'],
        retention: {
          category: 'authentication_log',
          expiresAt: new Date(Date.now() + 2 * 365 * 24 * 60 * 60 * 1000).toISOString(), // 2 years
        },
      },
    });

    await this.writeAuditEntry(entry);
  }

  /**
   * Log business switching event
   */
  async logBusinessSwitch(params: {
    fromBusinessId?: string;
    toBusinessId: string;
    result: 'success' | 'failure';
    switchTimeMs: number;
    securityContext: SecurityContext;
  }): Promise<void> {
    const entry = await this.createAuditEntry({
      eventType: 'business_switch',
      severity: 'medium',
      operation: 'business_switch',
      result: params.result,
      details: {
        fromBusinessId: params.fromBusinessId ?
          PIIRedactor.redactUserId(params.fromBusinessId) : undefined,
        toBusinessId: PIIRedactor.redactUserId(params.toBusinessId),
        switchTimeMs: params.switchTimeMs,
      },
      securityContext: params.securityContext,
      compliance: {
        regulations: ['GDPR', 'SOX'],
        dataTypes: ['business_data'],
        retention: {
          category: 'business_access',
          expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year
        },
      },
    });

    await this.writeAuditEntry(entry);
  }

  /**
   * Create audit entry with common fields
   */
  private async createAuditEntry(params: {
    eventType: AuditEventType;
    severity: AuditSeverity;
    operation: string;
    result: 'success' | 'failure' | 'partial';
    resource?: {
      type: string;
      id?: string;
      attributes?: Record<string, unknown>;
    };
    details: Record<string, unknown>;
    securityContext: SecurityContext;
    securityImpact?: AuditEntry['securityImpact'];
    compliance?: AuditEntry['compliance'];
  }): Promise<AuditEntry> {
    // Validate audit entry parameters
    AuditEntrySchema.parse({
      eventType: params.eventType,
      severity: params.severity,
      operation: params.operation,
      result: params.result,
      details: params.details,
    });

    const id = this.generateAuditId();
    const timestamp = new Date().toISOString();

    const entry: AuditEntry = {
      id,
      timestamp,
      correlationId: params.securityContext.correlationId,
      eventType: params.eventType,
      severity: params.severity,
      userId: PIIRedactor.redactUserId(params.securityContext.userId),
      businessId: PIIRedactor.redactUserId(params.securityContext.businessId),
      sessionId: PIIRedactor.redactSessionId(params.securityContext.sessionId),
      ipAddress: params.securityContext.ipAddress,
      userAgent: params.securityContext.userAgent,
      operation: params.operation,
      result: params.result,
      details: this.sanitizeDetails(params.details),
    };

    if (params.resource) {
      entry.resource = {
        type: params.resource.type,
        id: params.resource.id ? PIIRedactor.redactUserId(params.resource.id) : undefined,
        attributes: params.resource.attributes ?
          this.sanitizeDetails(params.resource.attributes) : undefined,
      };
    }

    if (params.securityImpact) {
      entry.securityImpact = params.securityImpact;
    }

    if (params.compliance) {
      entry.compliance = params.compliance;
    }

    return entry;
  }

  /**
   * Write audit entry to database
   */
  private async writeAuditEntry(entry: AuditEntry, immediate = false): Promise<void> {
    try {
      this.stats.entriesCreated++;

      if (immediate || !this.config.enableBatching) {
        await this.writeEntryToDB(entry);
      } else {
        // SECURITY FIX: Prevent unbounded array growth
        const MAX_BUFFER_SIZE = 1000;

        if (this.batchBuffer.length >= MAX_BUFFER_SIZE) {
          auditLogger.warn('Audit buffer at maximum capacity, forcing flush', {
            bufferSize: this.batchBuffer.length,
            maxSize: MAX_BUFFER_SIZE
          });
          await this.flushBatch();
        }

        this.batchBuffer.push(entry);
        this.stats.entriesBatched++;

        if (this.batchBuffer.length >= this.config.batchSize) {
          await this.flushBatch();
        }
      }

      // Log to structured logger as well
      auditLogger.audit(
        entry.operation,
        entry.resource,
        {
          auditId: entry.id,
          eventType: entry.eventType,
          severity: entry.severity,
          result: entry.result,
          details: entry.details,
        },
        {
          correlationId: entry.correlationId,
          userId: entry.userId,
          businessId: entry.businessId,
          sessionId: entry.sessionId || '',
          ipAddress: entry.ipAddress,
          userAgent: entry.userAgent,
          operation: entry.operation,
          timestamp: Date.now(),
        }
      );

    } catch (error) {
      this.stats.errors++;
      auditLogger.error('Failed to write audit entry', error, { auditEntry: entry });
      throw new SecurityError('Audit logging failed', {
        code: 'AUDIT_WRITE_FAILED',
        auditId: entry.id,
        operation: entry.operation,
      });
    }
  }

  /**
   * Write entry to database
   */
  private async writeEntryToDB(entry: AuditEntry): Promise<void> {
    const serializedDetails = JSON.stringify(entry.details);
    const serializedResource = entry.resource ? JSON.stringify(entry.resource) : null;
    const serializedSecurityImpact = entry.securityImpact ? JSON.stringify(entry.securityImpact) : null;
    const serializedCompliance = entry.compliance ? JSON.stringify(entry.compliance) : null;

    await this.db
      .prepare(`
        INSERT INTO audit_logs (
          id, timestamp, correlation_id, event_type, severity,
          user_id, business_id, session_id, ip_address, user_agent,
          operation, resource, result, details,
          security_impact, compliance, created_at
        ) VALUES (
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?,
          ?, ?, ?, ?,
          ?, ?, ?
        )
      `)
      .bind(
        entry.id,
        entry.timestamp,
        entry.correlationId,
        entry.eventType,
        entry.severity,
        entry.userId,
        entry.businessId,
        entry.sessionId,
        entry.ipAddress,
        entry.userAgent,
        entry.operation,
        serializedResource,
        entry.result,
        serializedDetails,
        serializedSecurityImpact,
        serializedCompliance,
        new Date().toISOString()
      )
      .run();
  }

  /**
   * Flush batch buffer to database
   */
  private async flushBatch(): Promise<void> {
    if (this.batchBuffer.length === 0) return;

    try {
      const batch = [...this.batchBuffer];
      this.batchBuffer = [];

      // Use transaction for batch insert
      const statements = batch.map(entry => {
        const serializedDetails = JSON.stringify(entry.details);
        const serializedResource = entry.resource ? JSON.stringify(entry.resource) : null;
        const serializedSecurityImpact = entry.securityImpact ? JSON.stringify(entry.securityImpact) : null;
        const serializedCompliance = entry.compliance ? JSON.stringify(entry.compliance) : null;

        return this.db
          .prepare(`
            INSERT INTO audit_logs (
              id, timestamp, correlation_id, event_type, severity,
              user_id, business_id, session_id, ip_address, user_agent,
              operation, resource, result, details,
              security_impact, compliance, created_at
            ) VALUES (
              ?, ?, ?, ?, ?,
              ?, ?, ?, ?, ?,
              ?, ?, ?, ?,
              ?, ?, ?
            )
          `)
          .bind(
            entry.id,
            entry.timestamp,
            entry.correlationId,
            entry.eventType,
            entry.severity,
            entry.userId,
            entry.businessId,
            entry.sessionId,
            entry.ipAddress,
            entry.userAgent,
            entry.operation,
            serializedResource,
            entry.result,
            serializedDetails,
            serializedSecurityImpact,
            serializedCompliance,
            new Date().toISOString()
          );
      });

      await this.db.batch(statements);

      this.stats.batchesWritten++;
      this.stats.lastBatchWrite = Date.now();

    } catch (error) {
      this.stats.errors++;
      auditLogger.error('Failed to flush audit batch', error, { batchSize: this.batchBuffer.length });
      throw error;
    }
  }

  /**
   * Start batch timer
   */
  private startBatchTimer(): void {
    this.batchTimer = setInterval(async () => {
      try {
        await this.flushBatch();
      } catch (error) {
        auditLogger.error('Batch timer flush failed', error);
      }
    }, this.config.batchInterval);
  }

  /**
   * Sanitize audit details for storage
   */
  private sanitizeDetails(details: Record<string, unknown>): Record<string, unknown> {
    return PIIRedactor.redactSensitiveData(details);
  }

  /**
   * Sanitize change data for audit
   */
  private sanitizeChanges(changes: {
    before?: Record<string, unknown>;
    after?: Record<string, unknown>;
    fields: string[];
  }): typeof changes {
    return {
      before: changes.before ? this.sanitizeDetails(changes.before) : undefined,
      after: changes.after ? this.sanitizeDetails(changes.after) : undefined,
      fields: changes.fields,
    };
  }

  /**
   * Generate unique audit ID
   */
  private generateAuditId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 5);
    return `audit_${timestamp}_${random}`;
  }

  /**
   * Get audit statistics
   */
  getStatistics(): typeof this.stats & { bufferSize: number } {
    return {
      ...this.stats,
      bufferSize: this.batchBuffer.length,
    };
  }

  /**
   * Query audit logs (for admin/compliance)
   */
  async queryAuditLogs(params: {
    businessId?: string;
    userId?: string;
    eventType?: AuditEventType;
    severity?: AuditSeverity;
    fromDate?: string;
    toDate?: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    logs: AuditEntry[];
    total: number;
  }> {
    let whereClause = 'WHERE 1=1';
    const bindValues: any[] = [];

    if (params.businessId) {
      whereClause += ' AND business_id = ?';
      bindValues.push(PIIRedactor.redactUserId(params.businessId));
    }

    if (params.userId) {
      whereClause += ' AND user_id = ?';
      bindValues.push(PIIRedactor.redactUserId(params.userId));
    }

    if (params.eventType) {
      whereClause += ' AND event_type = ?';
      bindValues.push(params.eventType);
    }

    if (params.severity) {
      whereClause += ' AND severity = ?';
      bindValues.push(params.severity);
    }

    if (params.fromDate) {
      whereClause += ' AND timestamp >= ?';
      bindValues.push(params.fromDate);
    }

    if (params.toDate) {
      whereClause += ' AND timestamp <= ?';
      bindValues.push(params.toDate);
    }

    const limit = Math.min(params.limit || 100, 1000); // Max 1000 records
    const offset = params.offset || 0;

    // Get total count
    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as count FROM audit_logs ${whereClause}`)
      .bind(...bindValues)
      .first<{ count: number }>();

    const total = countResult?.count || 0;

    // Get logs
    const logsResult = await this.db
      .prepare(`
        SELECT * FROM audit_logs
        ${whereClause}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
      `)
      .bind(...bindValues, limit, offset)
      .all();

    const logs = (logsResult.results || []).map(row => this.deserializeAuditEntry(row as any));

    return { logs, total };
  }

  /**
   * Deserialize audit entry from database
   */
  private deserializeAuditEntry(row: any): AuditEntry {
    return {
      id: row.id,
      timestamp: row.timestamp,
      correlationId: row.correlation_id,
      eventType: row.event_type,
      severity: row.severity,
      userId: row.user_id,
      businessId: row.business_id,
      sessionId: row.session_id,
      ipAddress: row.ip_address,
      userAgent: row.user_agent,
      operation: row.operation,
      resource: row.resource ? JSON.parse(row.resource) : undefined,
      result: row.result,
      details: JSON.parse(row.details),
      securityImpact: row.security_impact ? JSON.parse(row.security_impact) : undefined,
      compliance: row.compliance ? JSON.parse(row.compliance) : undefined,
    };
  }

  /**
   * Cleanup and destroy service
   */
  async destroy(): Promise<void> {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
    }

    // Flush remaining entries
    await this.flushBatch();
  }
}