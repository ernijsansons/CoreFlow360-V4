/**
 * Secure Database Wrapper with Tenant Isolation
 * CRITICAL SECURITY MODULE - Enforces row-level security on ALL database operations
 *
 * This wrapper intercepts all database queries and ensures:
 * - Automatic business_id injection
 * - Cross-tenant access prevention
 * - Query validation and sanitization
 * - Comprehensive audit logging
 *
 * @security-level CRITICAL
 * @cvss-protection 9.8 (Prevents cross-tenant data access)
 */

import { Logger } from '../shared/logger';
import { tenantIsolation, TenantSecurityContext } from '../shared/security/tenant-isolation-layer';
import type { D1Database } from '../cloudflare/types/cloudflare';
import type { Env } from '../types/env';

export interface SecureDatabaseOptions {
  env: Env;
  context: TenantSecurityContext;
  enableAudit?: boolean;
  enableCache?: boolean;
  maxRetries?: number;
}

export interface QueryResult<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  violations?: any[];
  executionTime?: number;
}

/**
 * Secure Database Wrapper
 * Enforces tenant isolation on ALL database operations
 */
export class SecureDatabase {
  private readonly logger: Logger;
  private readonly db: D1Database;
  private readonly context: TenantSecurityContext;
  private readonly enableAudit: boolean;
  private readonly queryCount: number = 0;
  private readonly violations: any[] = [];

  constructor(private readonly options: SecureDatabaseOptions) {
    this.logger = new Logger({ component: 'SecureDatabase' });
    this.db = options.env.DB;
    this.context = options.context;
    this.enableAudit = options.enableAudit ?? true;
  }

  /**
   * Execute a SELECT query with automatic tenant isolation
   */
  async query<T = any>(
    sql: string,
    params: any[] = []
  ): Promise<QueryResult<T[]>> {
    const startTime = performance.now();

    try {
      // Validate tenant context
      const contextValidation = await tenantIsolation.validateTenantContext(
        this.context,
        this.options.env
      );

      if (!contextValidation.valid) {
        this.logViolation('QUERY', sql, contextValidation.violations);
        return {
          success: false,
          error: 'Tenant validation failed',
          violations: contextValidation.violations
        };
      }

      // Secure the query
      const secured = tenantIsolation.secureQuery(sql, params, this.context);

      if (!secured.secure) {
        this.logViolation('QUERY', sql, secured.violations);
        return {
          success: false,
          error: 'Query security validation failed',
          violations: secured.violations
        };
      }

      // Execute secured query
      const result = await this.db
        .prepare(secured.query)
        .bind(...secured.params)
        .all();

      // Validate results don't contain cross-tenant data
      const validatedResults = this.validateResults(result.results as T[]);

      // Audit log
      if (this.enableAudit) {
        await this.auditQuery('SELECT', secured.query, secured.params, true);
      }

      return {
        success: true,
        data: validatedResults,
        executionTime: performance.now() - startTime
      };

    } catch (error) {
      this.logger.error('Secure query execution failed', {
        error: error instanceof Error ? error.message : String(error),
        sql,
        businessId: this.context.businessId
      });

      if (this.enableAudit) {
        await this.auditQuery('SELECT', sql, params, false, error);
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Query execution failed',
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Execute a single SELECT query with tenant isolation
   */
  async queryFirst<T = any>(
    sql: string,
    params: any[] = []
  ): Promise<QueryResult<T | null>> {
    const result = await this.query<T>(sql, params);

    if (!result.success) {
      return result as QueryResult<T | null>;
    }

    return {
      success: true,
      data: result.data && result.data.length > 0 ? result.data[0] : null,
      executionTime: result.executionTime
    };
  }

  /**
   * Execute an INSERT with automatic business_id injection
   */
  async insert(
    table: string,
    data: Record<string, any>
  ): Promise<QueryResult<{ id: string; changes: number }>> {
    const startTime = performance.now();

    try {
      // Validate tenant context
      const contextValidation = await tenantIsolation.validateTenantContext(
        this.context,
        this.options.env
      );

      if (!contextValidation.valid) {
        this.logViolation('INSERT', table, contextValidation.violations);
        return {
          success: false,
          error: 'Tenant validation failed',
          violations: contextValidation.violations
        };
      }

      // Validate and secure data
      const dataValidation = tenantIsolation.validateData(
        data,
        table,
        'INSERT',
        this.context
      );

      if (!dataValidation.valid) {
        this.logViolation('INSERT', table, dataValidation.violations);
        return {
          success: false,
          error: 'Data validation failed',
          violations: dataValidation.violations
        };
      }

      // Ensure business_id is set
      if (!data.business_id) {
        data.business_id = this.context.businessId;
      }

      // Add audit fields
      data.created_by = this.context.userId;
      data.created_at = new Date().toISOString();

      // Build INSERT query
      const columns = Object.keys(data);
      const placeholders = columns.map(() => '?').join(', ');
      const sql = `INSERT INTO ${this.sanitizeTableName(table)} (${columns.join(', ')}) VALUES (${placeholders})`;
      const params = Object.values(data);

      // Execute query
      const result = await this.db
        .prepare(sql)
        .bind(...params)
        .run();

      // Audit log
      if (this.enableAudit) {
        await this.auditQuery('INSERT', sql, params, result.success);
      }

      return {
        success: result.success,
        data: {
          id: data.id || String(result.meta?.last_row_id),
          changes: result.meta?.changes || 0
        },
        executionTime: performance.now() - startTime
      };

    } catch (error) {
      this.logger.error('Secure insert failed', {
        error: error instanceof Error ? error.message : String(error),
        table,
        businessId: this.context.businessId
      });

      if (this.enableAudit) {
        await this.auditQuery('INSERT', table, [], false, error);
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Insert failed',
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Execute an UPDATE with tenant isolation
   */
  async update(
    table: string,
    data: Record<string, any>,
    where: Record<string, any>
  ): Promise<QueryResult<{ changes: number }>> {
    const startTime = performance.now();

    try {
      // Validate tenant context
      const contextValidation = await tenantIsolation.validateTenantContext(
        this.context,
        this.options.env
      );

      if (!contextValidation.valid) {
        this.logViolation('UPDATE', table, contextValidation.violations);
        return {
          success: false,
          error: 'Tenant validation failed',
          violations: contextValidation.violations
        };
      }

      // Validate data
      const dataValidation = tenantIsolation.validateData(
        data,
        table,
        'UPDATE',
        this.context
      );

      if (!dataValidation.valid) {
        this.logViolation('UPDATE', table, dataValidation.violations);
        return {
          success: false,
          error: 'Data validation failed',
          violations: dataValidation.violations
        };
      }

      // Ensure business_id in WHERE clause
      where.business_id = this.context.businessId;

      // Add audit fields
      data.updated_by = this.context.userId;
      data.updated_at = new Date().toISOString();

      // Remove business_id from update data (should never change)
      delete data.business_id;

      // Build UPDATE query
      const setClause = Object.keys(data)
        .map(key => `${key} = ?`)
        .join(', ');
      const whereClause = Object.keys(where)
        .map(key => `${key} = ?`)
        .join(' AND ');

      const sql = `UPDATE ${this.sanitizeTableName(table)} SET ${setClause} WHERE ${whereClause}`;
      const params = [...Object.values(data), ...Object.values(where)];

      // Execute query
      const result = await this.db
        .prepare(sql)
        .bind(...params)
        .run();

      // Audit log
      if (this.enableAudit) {
        await this.auditQuery('UPDATE', sql, params, result.success);
      }

      return {
        success: result.success,
        data: { changes: result.meta?.changes || 0 },
        executionTime: performance.now() - startTime
      };

    } catch (error) {
      this.logger.error('Secure update failed', {
        error: error instanceof Error ? error.message : String(error),
        table,
        businessId: this.context.businessId
      });

      if (this.enableAudit) {
        await this.auditQuery('UPDATE', table, [], false, error);
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Update failed',
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Execute a DELETE with tenant isolation
   */
  async delete(
    table: string,
    where: Record<string, any>
  ): Promise<QueryResult<{ changes: number }>> {
    const startTime = performance.now();

    try {
      // Validate tenant context
      const contextValidation = await tenantIsolation.validateTenantContext(
        this.context,
        this.options.env
      );

      if (!contextValidation.valid) {
        this.logViolation('DELETE', table, contextValidation.violations);
        return {
          success: false,
          error: 'Tenant validation failed',
          violations: contextValidation.violations
        };
      }

      // Ensure business_id in WHERE clause
      where.business_id = this.context.businessId;

      // Build DELETE query
      const whereClause = Object.keys(where)
        .map(key => `${key} = ?`)
        .join(' AND ');

      const sql = `DELETE FROM ${this.sanitizeTableName(table)} WHERE ${whereClause}`;
      const params = Object.values(where);

      // Execute query
      const result = await this.db
        .prepare(sql)
        .bind(...params)
        .run();

      // Audit log
      if (this.enableAudit) {
        await this.auditQuery('DELETE', sql, params, result.success);
      }

      return {
        success: result.success,
        data: { changes: result.meta?.changes || 0 },
        executionTime: performance.now() - startTime
      };

    } catch (error) {
      this.logger.error('Secure delete failed', {
        error: error instanceof Error ? error.message : String(error),
        table,
        businessId: this.context.businessId
      });

      if (this.enableAudit) {
        await this.auditQuery('DELETE', table, [], false, error);
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Delete failed',
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Execute a batch of operations with tenant isolation
   */
  async batch(
    operations: Array<{
      type: 'query' | 'insert' | 'update' | 'delete';
      table?: string;
      sql?: string;
      data?: Record<string, any>;
      where?: Record<string, any>;
      params?: any[];
    }>
  ): Promise<QueryResult<{ totalChanges: number; results: any[] }>> {
    const startTime = performance.now();
    const results: any[] = [];
    let totalChanges = 0;

    try {
      // Validate tenant context once
      const contextValidation = await tenantIsolation.validateTenantContext(
        this.context,
        this.options.env
      );

      if (!contextValidation.valid) {
        this.logViolation('BATCH', 'multiple', contextValidation.violations);
        return {
          success: false,
          error: 'Tenant validation failed',
          violations: contextValidation.violations
        };
      }

      // Process each operation
      for (const op of operations) {
        let result: QueryResult<any>;

        switch (op.type) {
          case 'query':
            if (!op.sql) throw new Error('SQL required for query operation');
            result = await this.query(op.sql, op.params || []);
            break;

          case 'insert':
            if (!op.table || !op.data) {
              throw new Error('Table and data required for insert operation');
            }
            result = await this.insert(op.table, op.data);
            break;

          case 'update':
            if (!op.table || !op.data || !op.where) {
              throw new Error('Table, data, and where required for update operation');
            }
            result = await this.update(op.table, op.data, op.where);
            break;

          case 'delete':
            if (!op.table || !op.where) {
              throw new Error('Table and where required for delete operation');
            }
            result = await this.delete(op.table, op.where);
            break;

          default:
            throw new Error(`Unknown operation type: ${op.type}`);
        }

        if (!result.success) {
          // Fail entire batch on any error
          return {
            success: false,
            error: `Batch operation failed: ${result.error}`,
            violations: result.violations
          };
        }

        results.push(result.data);

        if (result.data && typeof result.data === 'object' && 'changes' in result.data) {
          totalChanges += result.data.changes;
        }
      }

      return {
        success: true,
        data: { totalChanges, results },
        executionTime: performance.now() - startTime
      };

    } catch (error) {
      this.logger.error('Batch operation failed', {
        error: error instanceof Error ? error.message : String(error),
        businessId: this.context.businessId
      });

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Batch operation failed',
        executionTime: performance.now() - startTime
      };
    }
  }

  /**
   * Validate results don't contain cross-tenant data
   */
  private validateResults<T>(results: T[]): T[] {
    const validated: T[] = [];

    for (const row of results) {
      if (typeof row === 'object' && row !== null) {
        const record = row as any;

        // Check if row has business_id and it matches context
        if ('business_id' in record) {
          if (record.business_id === this.context.businessId) {
            validated.push(row);
          } else {
            // Critical violation - cross-tenant data leaked
            this.logger.error('CRITICAL: Cross-tenant data detected in results', {
              expectedBusinessId: this.context.businessId,
              actualBusinessId: record.business_id,
              userId: this.context.userId
            });

            // Record violation but don't return the data
            this.violations.push({
              type: 'data_leakage',
              severity: 'critical',
              timestamp: new Date(),
              businessId: this.context.businessId,
              description: 'Cross-tenant data detected in query results'
            });
          }
        } else {
          // Row doesn't have business_id - might be aggregated data or system table
          validated.push(row);
        }
      } else {
        // Primitive value (count, sum, etc.)
        validated.push(row);
      }
    }

    return validated;
  }

  /**
   * Sanitize table name to prevent injection
   */
  private sanitizeTableName(table: string): string {
    // Only allow alphanumeric and underscores
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    return table;
  }

  /**
   * Log security violations
   */
  private logViolation(operation: string, target: string, violations: any[]): void {
    this.violations.push(...violations);

    this.logger.error('Security violation detected', {
      operation,
      target,
      businessId: this.context.businessId,
      userId: this.context.userId,
      violations: violations.map(v => ({
        type: v.type,
        severity: v.severity,
        description: v.description
      }))
    });
  }

  /**
   * Audit query execution
   */
  private async auditQuery(
    operation: string,
    sql: string,
    params: any[],
    success: boolean,
    error?: any
  ): Promise<void> {
    try {
      const auditEntry = {
        id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        business_id: this.context.businessId,
        user_id: this.context.userId,
        session_id: this.context.sessionId,
        operation,
        sql: sql.substring(0, 1000), // Truncate for storage
        params_count: params.length,
        success,
        error: error ? String(error) : null,
        ip_address: this.context.ipAddress,
        user_agent: this.context.userAgent
      };

      // Store audit log (fire and forget to not impact performance)
      this.options.env.DB.prepare(`
        INSERT INTO audit_logs (
          id, timestamp, business_id, user_id, operation,
          details, success, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        auditEntry.id,
        auditEntry.timestamp,
        auditEntry.business_id,
        auditEntry.user_id,
        auditEntry.operation,
        JSON.stringify(auditEntry),
        auditEntry.success ? 1 : 0
      ).run().catch(err => {
        this.logger.error('Failed to write audit log', { error: err });
      });

    } catch (error) {
      this.logger.error('Audit logging failed', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Get database statistics
   */
  getStatistics(): {
    queryCount: number;
    violationCount: number;
    violations: any[];
  } {
    return {
      queryCount: this.queryCount,
      violationCount: this.violations.length,
      violations: this.violations
    };
  }

  /**
   * Clear violation history (for testing)
   */
  clearViolations(): void {
    this.violations.length = 0;
  }
}

/**
 * Factory function to create secure database instance
 */
export function createSecureDatabase(
  env: Env,
  context: TenantSecurityContext
): SecureDatabase {
  return new SecureDatabase({ env, context });
}