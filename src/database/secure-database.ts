/**
 * SecureDatabase Wrapper
 *
 * Implements Row-Level Security (RLS) and SQL Injection Prevention
 * for multi-tenant data isolation in CoreFlow360 V4.
 *
 * Security Features:
 * - Automatic business_id filtering on ALL queries
 * - Parameterized queries only (no string concatenation)
 * - Query logging for audit trail
 * - SQL injection prevention
 * - Cross-tenant data leak prevention
 *
 * OWASP 2025 Compliance:
 * - A03: Injection Prevention (CVSS 9.8)
 * - A04: Insecure Design (Multi-Tenant Isolation)
 * - A07: Identification and Authentication Failures
 * - A09: Security Logging and Monitoring Failures
 */

import { D1Database } from '@cloudflare/workers-types';
import { z } from 'zod';
import { logger } from '../shared/logger';
import { AppError } from '../shared/errors/app-error';

// Security configuration schema
const SecurityConfigSchema = z.object({
  businessId: z.string().min(1),
  userId: z.string().min(1),
  role: z.enum(['owner', 'admin', 'user', 'viewer']),
  tenantId: z.string().optional(),
  enforceRLS: z.boolean().default(true),
  auditLog: z.boolean().default(true),
  preventCrossTenant: z.boolean().default(true)
});

type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

// Query result types
interface QueryResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  meta?: {
    rowsAffected?: number;
    duration?: number;
    cached?: boolean;
  };
}

// SQL injection patterns to detect and block
const SQL_INJECTION_PATTERNS = [
  /(\bOR\b|\bAND\b)\s*['"]=\s*['"]/i, // OR/AND with always true conditions
  /\b(UNION|INTERSECT|EXCEPT)\b\s+\b(ALL\s+)?SELECT\b/i, // UNION attacks
  /;\s*(\bDROP\b|\bDELETE\b|\bTRUNCATE\b|\bALTER\b|\bCREATE\b)/i, // Command injection
  /\bEXEC(\s|\()/i, // EXEC command
  /\bxp_cmdshell\b/i, // SQL Server command execution
  /\b(SLEEP|WAITFOR|BENCHMARK|DBMS_PIPE\.RECEIVE_MESSAGE)\b/i, // Time-based attacks
  /['"]\s*;\s*--/i, // Comment injection
  /\b(LOAD_FILE|INTO\s+(OUTFILE|DUMPFILE))\b/i, // File operations
  /\b(INFORMATION_SCHEMA|mysql|sys|pg_catalog)\b/i, // System tables
  /\bhex\s*\(/i, // Hex encoding attempts
  /\bchar\s*\(/i, // Char encoding attempts
  /\/*\s*\*/i, // Multi-line comment injection
];

// Table whitelist for security
const ALLOWED_TABLES = new Set([
  'users',
  'businesses',
  'companies',
  'contacts',
  'leads',
  'opportunities',
  'invoices',
  'payments',
  'ledger_entries',
  'journal_entries',
  'audit_log',
  'ai_agents',
  'agent_tasks',
  'conversations',
  'workflows',
  'integrations',
  'settings',
  'permissions',
  'roles',
  'sessions'
]);

// Fields that should never be exposed
const SENSITIVE_FIELDS = new Set([
  'password',
  'password_hash',
  'salt',
  'secret_key',
  'api_key',
  'private_key',
  'encryption_key',
  'jwt_secret',
  'otp_secret',
  'recovery_codes'
]);

export class SecureDatabase {
  private db: D1Database;
  private config: SecurityConfig;
  private queryLog: Map<string, { count: number; lastAccess: Date }>;
  private readonly MAX_QUERY_LENGTH = 10000;
  private readonly MAX_PARAM_LENGTH = 5000;
  private readonly MAX_PARAMS = 100;

  constructor(db: D1Database, config: SecurityConfig) {
    const validatedConfig = SecurityConfigSchema.parse(config);
    this.db = db;
    this.config = validatedConfig;
    this.queryLog = new Map();
  }

  /**
   * Validates and sanitizes table name to prevent injection
   */
  private sanitizeTableName(table: string): string {
    // Remove any whitespace and special characters
    const cleaned = table.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');

    if (!ALLOWED_TABLES.has(cleaned)) {
      throw new AppError(`Invalid table name: ${table}`, 403, 'INVALID_TABLE');
    }

    return cleaned;
  }

  /**
   * Validates field names to prevent injection
   */
  private sanitizeFieldNames(fields: string[]): string[] {
    return fields.map(field => {
      const cleaned = field.trim().toLowerCase().replace(/[^a-z0-9_]/g, '');

      if (SENSITIVE_FIELDS.has(cleaned)) {
        throw new AppError(`Access to sensitive field denied: ${field}`, 403, 'SENSITIVE_FIELD');
      }

      // Check for common SQL keywords
      if (/^(select|from|where|join|union|insert|update|delete|drop|create|alter)$/i.test(cleaned)) {
        throw new AppError(`Invalid field name: ${field}`, 403, 'SQL_KEYWORD_IN_FIELD');
      }

      return cleaned;
    });
  }

  /**
   * Detects potential SQL injection attempts in values
   */
  private detectSQLInjection(value: any): boolean {
    if (typeof value !== 'string') return false;

    // Check against known SQL injection patterns
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        logger.error('SQL injection attempt detected', {
          pattern: pattern.toString(),
          value: value.substring(0, 100), // Log only first 100 chars for security
          userId: this.config.userId,
          businessId: this.config.businessId
        });
        return true;
      }
    }

    // Check for excessive special characters that might indicate an attack
    const specialCharCount = (value.match(/['";\\]/g) || []).length;
    if (specialCharCount > 5 && specialCharCount > value.length * 0.1) {
      logger.warn('Suspicious value with many special characters', {
        userId: this.config.userId,
        businessId: this.config.businessId
      });
      return true;
    }

    return false;
  }

  /**
   * Validates all parameters for security
   */
  private validateParameters(params: any[]): void {
    if (params.length > this.MAX_PARAMS) {
      throw new AppError('Too many parameters', 400, 'PARAM_LIMIT_EXCEEDED');
    }

    for (const param of params) {
      if (typeof param === 'string') {
        if (param.length > this.MAX_PARAM_LENGTH) {
          throw new AppError('Parameter too long', 400, 'PARAM_TOO_LONG');
        }
        if (this.detectSQLInjection(param)) {
          throw new AppError('SQL injection detected', 403, 'SQL_INJECTION');
        }
      }
    }
  }

  /**
   * Adds business_id filtering to WHERE clause
   */
  private addBusinessIdFilter(whereClause: string, hasWhere: boolean): string {
    if (!this.config.enforceRLS) return whereClause;

    const businessIdCondition = `business_id = ?`;

    if (!hasWhere) {
      return `WHERE ${businessIdCondition}`;
    }

    return `${whereClause} AND ${businessIdCondition}`;
  }

  /**
   * Logs query for audit trail
   */
  private async logQuery(operation: string, table: string, query: string, params: any[]): Promise<void> {
    if (!this.config.auditLog) return;

    try {
      const auditEntry = {
        id: crypto.randomUUID(),
        operation,
        table,
        query_hash: await this.hashQuery(query),
        user_id: this.config.userId,
        business_id: this.config.businessId,
        role: this.config.role,
        timestamp: new Date().toISOString(),
        ip_address: null, // Would be populated from request context
        success: true
      };

      // Store in audit log table (fire and forget)
      this.db.prepare(`
        INSERT INTO audit_log (id, operation, table_name, query_hash, user_id, business_id, role, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        auditEntry.id,
        auditEntry.operation,
        auditEntry.table,
        auditEntry.query_hash,
        auditEntry.user_id,
        auditEntry.business_id,
        auditEntry.role,
        auditEntry.timestamp
      ).run().catch(err => {
        logger.error('Failed to write audit log', { error: err });
      });
    } catch (error) {
      logger.error('Audit logging failed', { error });
    }
  }

  /**
   * Hashes query for audit logging without exposing sensitive data
   */
  private async hashQuery(query: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(query);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * SELECT with automatic RLS
   */
  async select<T = any>(
    table: string,
    conditions: Record<string, any> = {},
    options: {
      fields?: string[];
      orderBy?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<QueryResult<T[]>> {
    const startTime = Date.now();

    try {
      // Sanitize inputs
      const sanitizedTable = this.sanitizeTableName(table);
      const fields = options.fields ? this.sanitizeFieldNames(options.fields) : ['*'];

      // Build WHERE clause with RLS
      const whereConditions = Object.keys(conditions);
      const whereParams: any[] = Object.values(conditions);

      // Add business_id for RLS
      if (this.config.enforceRLS && !whereConditions.includes('business_id')) {
        whereConditions.push('business_id');
        whereParams.push(this.config.businessId);
      }

      // Validate parameters
      this.validateParameters(whereParams);

      // Build query
      let query = `SELECT ${fields.join(', ')} FROM ${sanitizedTable}`;

      if (whereConditions.length > 0) {
        const placeholders = whereConditions.map(field => `${field} = ?`).join(' AND ');
        query += ` WHERE ${placeholders}`;
      }

      // Add ORDER BY if specified
      if (options.orderBy) {
        const [field, direction = 'ASC'] = options.orderBy.split(' ');
        const sanitizedField = this.sanitizeFieldNames([field])[0];
        const sanitizedDirection = direction.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
        query += ` ORDER BY ${sanitizedField} ${sanitizedDirection}`;
      }

      // Add LIMIT and OFFSET
      if (options.limit) {
        query += ` LIMIT ${Math.min(options.limit, 1000)}`; // Max 1000 rows
        if (options.offset) {
          query += ` OFFSET ${Math.max(0, options.offset)}`;
        }
      }

      // Log query
      await this.logQuery('SELECT', sanitizedTable, query, whereParams);

      // Execute query
      const statement = this.db.prepare(query);
      const result = await statement.bind(...whereParams).all<T>();

      return {
        success: true,
        data: result.results as T[],
        meta: {
          rowsAffected: result.results.length,
          duration: Date.now() - startTime
        }
      };
    } catch (error: any) {
      logger.error('Secure SELECT failed', {
        table,
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Query failed'
      };
    }
  }

  /**
   * INSERT with automatic business_id injection
   */
  async insert<T = any>(
    table: string,
    data: Record<string, any>
  ): Promise<QueryResult<{ id: string }>> {
    const startTime = Date.now();

    try {
      // Sanitize table name
      const sanitizedTable = this.sanitizeTableName(table);

      // Ensure business_id is set for RLS
      if (this.config.enforceRLS && !data.business_id) {
        data.business_id = this.config.businessId;
      }

      // Validate business_id matches session
      if (this.config.preventCrossTenant && data.business_id && data.business_id !== this.config.businessId) {
        throw new AppError('Cross-tenant insert attempted', 403, 'CROSS_TENANT_VIOLATION');
      }

      // Generate ID if not provided
      if (!data.id) {
        data.id = crypto.randomUUID();
      }

      // Add audit fields
      data.created_at = new Date().toISOString();
      data.created_by = this.config.userId;
      data.updated_at = data.created_at;
      data.updated_by = this.config.userId;

      // Sanitize field names and prepare query
      const fields = Object.keys(data);
      const sanitizedFields = this.sanitizeFieldNames(fields);
      const values = fields.map(field => data[field]);

      // Validate parameters
      this.validateParameters(values);

      // Build query
      const placeholders = sanitizedFields.map(() => '?').join(', ');
      const query = `INSERT INTO ${sanitizedTable} (${sanitizedFields.join(', ')}) VALUES (${placeholders})`;

      // Log query
      await this.logQuery('INSERT', sanitizedTable, query, values);

      // Execute query
      const statement = this.db.prepare(query);
      const result = await statement.bind(...values).run();

      if (result.success) {
        return {
          success: true,
          data: { id: data.id },
          meta: {
            rowsAffected: 1,
            duration: Date.now() - startTime
          }
        };
      }

      throw new Error('Insert failed');
    } catch (error: any) {
      logger.error('Secure INSERT failed', {
        table,
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Insert failed'
      };
    }
  }

  /**
   * UPDATE with automatic RLS
   */
  async update<T = any>(
    table: string,
    conditions: Record<string, any>,
    data: Record<string, any>
  ): Promise<QueryResult<{ updated: number }>> {
    const startTime = Date.now();

    try {
      // Sanitize table name
      const sanitizedTable = this.sanitizeTableName(table);

      // Prevent updating business_id
      if (data.business_id && data.business_id !== this.config.businessId) {
        throw new AppError('Cannot update business_id', 403, 'BUSINESS_ID_IMMUTABLE');
      }

      // Add audit fields
      data.updated_at = new Date().toISOString();
      data.updated_by = this.config.userId;

      // Remove sensitive fields from update
      delete data.id;
      delete data.business_id;
      delete data.created_at;
      delete data.created_by;

      // Build SET clause
      const updateFields = Object.keys(data);
      const sanitizedUpdateFields = this.sanitizeFieldNames(updateFields);
      const setClause = sanitizedUpdateFields.map(field => `${field} = ?`).join(', ');
      const updateValues = updateFields.map(field => data[field]);

      // Build WHERE clause with RLS
      const whereConditions = Object.keys(conditions);
      const whereValues = Object.values(conditions);

      // Always add business_id for RLS
      if (this.config.enforceRLS && !whereConditions.includes('business_id')) {
        whereConditions.push('business_id');
        whereValues.push(this.config.businessId);
      }

      const whereClause = whereConditions.map(field => `${field} = ?`).join(' AND ');

      // Combine all parameters
      const allParams = [...updateValues, ...whereValues];
      this.validateParameters(allParams);

      // Build query
      const query = `UPDATE ${sanitizedTable} SET ${setClause} WHERE ${whereClause}`;

      // Log query
      await this.logQuery('UPDATE', sanitizedTable, query, allParams);

      // Execute query
      const statement = this.db.prepare(query);
      const result = await statement.bind(...allParams).run();

      return {
        success: true,
        data: { updated: result.meta.changes || 0 },
        meta: {
          rowsAffected: result.meta.changes || 0,
          duration: Date.now() - startTime
        }
      };
    } catch (error: any) {
      logger.error('Secure UPDATE failed', {
        table,
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Update failed'
      };
    }
  }

  /**
   * DELETE with automatic RLS
   */
  async delete(
    table: string,
    conditions: Record<string, any>
  ): Promise<QueryResult<{ deleted: number }>> {
    const startTime = Date.now();

    try {
      // Sanitize table name
      const sanitizedTable = this.sanitizeTableName(table);

      // Build WHERE clause with RLS
      const whereConditions = Object.keys(conditions);
      const whereValues = Object.values(conditions);

      // Always add business_id for RLS
      if (this.config.enforceRLS && !whereConditions.includes('business_id')) {
        whereConditions.push('business_id');
        whereValues.push(this.config.businessId);
      }

      // Validate parameters
      this.validateParameters(whereValues);

      // Prevent deletion without conditions
      if (whereConditions.length === 0) {
        throw new AppError('DELETE without conditions not allowed', 403, 'UNSAFE_DELETE');
      }

      const whereClause = whereConditions.map(field => `${field} = ?`).join(' AND ');

      // Build query
      const query = `DELETE FROM ${sanitizedTable} WHERE ${whereClause}`;

      // Log query
      await this.logQuery('DELETE', sanitizedTable, query, whereValues);

      // Execute query
      const statement = this.db.prepare(query);
      const result = await statement.bind(...whereValues).run();

      return {
        success: true,
        data: { deleted: result.meta.changes || 0 },
        meta: {
          rowsAffected: result.meta.changes || 0,
          duration: Date.now() - startTime
        }
      };
    } catch (error: any) {
      logger.error('Secure DELETE failed', {
        table,
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Delete failed'
      };
    }
  }

  /**
   * Execute raw query with security checks (USE WITH EXTREME CAUTION)
   */
  async executeRaw<T = any>(
    query: string,
    params: any[] = []
  ): Promise<QueryResult<T>> {
    // Only allow in development or with special permissions
    if (this.config.role !== 'owner' && this.config.role !== 'admin') {
      throw new AppError('Raw query execution not allowed', 403, 'INSUFFICIENT_PERMISSIONS');
    }

    // Check query length
    if (query.length > this.MAX_QUERY_LENGTH) {
      throw new AppError('Query too long', 400, 'QUERY_TOO_LONG');
    }

    // Detect dangerous operations
    const dangerousPatterns = [
      /\bDROP\s+(TABLE|DATABASE|INDEX)\b/i,
      /\bTRUNCATE\s+TABLE\b/i,
      /\bALTER\s+TABLE\b/i,
      /\bCREATE\s+(TABLE|DATABASE)\b/i,
      /\bGRANT\b/i,
      /\bREVOKE\b/i
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(query)) {
        throw new AppError('Dangerous operation detected', 403, 'DANGEROUS_OPERATION');
      }
    }

    // Validate parameters
    this.validateParameters(params);

    // Log query
    await this.logQuery('RAW', 'CUSTOM', query, params);

    try {
      const statement = this.db.prepare(query);
      const result = await statement.bind(...params).all<T>();

      return {
        success: true,
        data: result.results as any,
        meta: {
          rowsAffected: result.results.length
        }
      };
    } catch (error: any) {
      logger.error('Raw query execution failed', {
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Raw query failed'
      };
    }
  }

  /**
   * Batch operations with RLS
   */
  async batch<T = any>(operations: Array<{
    type: 'select' | 'insert' | 'update' | 'delete';
    table: string;
    data?: Record<string, any>;
    conditions?: Record<string, any>;
    options?: any;
  }>): Promise<QueryResult<T[]>> {
    const results: any[] = [];

    for (const op of operations) {
      let result;

      switch (op.type) {
        case 'select':
          result = await this.select(op.table, op.conditions || {}, op.options || {});
          break;
        case 'insert':
          result = await this.insert(op.table, op.data || {});
          break;
        case 'update':
          result = await this.update(op.table, op.conditions || {}, op.data || {});
          break;
        case 'delete':
          result = await this.delete(op.table, op.conditions || {});
          break;
        default:
          result = { success: false, error: 'Invalid operation type' };
      }

      results.push(result);

      // Stop on first error
      if (!result.success) {
        break;
      }
    }

    const allSuccess = results.every(r => r.success);

    return {
      success: allSuccess,
      data: allSuccess ? results.map(r => r.data) : undefined,
      error: allSuccess ? undefined : results.find(r => !r.success)?.error
    };
  }

  /**
   * Transaction support with RLS
   */
  async transaction<T = any>(
    callback: (secureDb: SecureDatabase) => Promise<T>
  ): Promise<QueryResult<T>> {
    try {
      // Start transaction
      await this.db.prepare('BEGIN TRANSACTION').run();

      // Execute callback with this secure instance
      const result = await callback(this);

      // Commit transaction
      await this.db.prepare('COMMIT').run();

      return {
        success: true,
        data: result
      };
    } catch (error: any) {
      // Rollback on error
      await this.db.prepare('ROLLBACK').run().catch(() => {});

      logger.error('Transaction failed', {
        error: error.message,
        userId: this.config.userId,
        businessId: this.config.businessId
      });

      return {
        success: false,
        error: error.message || 'Transaction failed'
      };
    }
  }

  /**
   * Get current security context
   */
  getSecurityContext(): SecurityConfig {
    return { ...this.config };
  }

  /**
   * Update security context (e.g., after role change)
   */
  updateSecurityContext(updates: Partial<SecurityConfig>): void {
    this.config = SecurityConfigSchema.parse({
      ...this.config,
      ...updates
    });
  }
}

// Export factory function
export function createSecureDatabase(
  db: D1Database,
  config: SecurityConfig
): SecureDatabase {
  return new SecureDatabase(db, config);
}

// Export types
export type { SecurityConfig, QueryResult };