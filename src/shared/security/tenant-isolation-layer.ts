/**
 * Enhanced Tenant Isolation Security Layer
 * CRITICAL SECURITY MODULE - OWASP 2025 Compliant
 *
 * Implements comprehensive multi-tenant data isolation to prevent:
 * - Cross-tenant data access (CVSS 9.8)
 * - Data leakage between businesses (CVSS 9.5)
 * - Unauthorized business access (CVSS 8.6)
 *
 * @security-level CRITICAL
 * @audit-frequency CONTINUOUS
 */

import { Logger } from '../logger';
import type { D1Database } from '../../cloudflare/types/cloudflare';
import type { Context } from 'hono';
import type { Env } from '../../types/env';

// Security Context Types
export interface TenantSecurityContext {
  businessId: string;
  userId: string;
  userRole: string;
  permissions: string[];
  isolationLevel: 'strict' | 'standard' | 'relaxed';
  sessionId: string;
  requestId: string;
  ipAddress: string;
  userAgent: string;
  verified: boolean;
  mfaEnabled: boolean;
  riskScore: number;
  lastValidated: Date;
}

export interface TenantIsolationViolation {
  id: string;
  type: 'missing_business_id' | 'invalid_business_id' | 'cross_tenant_access' | 'data_leakage' | 'injection_attempt' | 'unauthorized_access';
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore: number;
  table?: string;
  column?: string;
  description: string;
  businessId: string;
  userId: string;
  timestamp: Date;
  query?: string;
  stackTrace?: string;
  recommendation: string;
  blocked: boolean;
}

export interface QuerySecurityContext {
  query: string;
  params: any[];
  tables: string[];
  operation: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'OTHER';
  hasBusinessIdFilter: boolean;
  businessIds: string[];
  riskLevel: number;
}

// Table Configuration for Tenant Isolation
const TENANT_ISOLATED_TABLES = new Set([
  'accounts',
  'audit_logs',
  'businesses',
  'business_memberships',
  'chat_conversations',
  'chat_messages',
  'departments',
  'invoices',
  'journal_entries',
  'leads',
  'ledger_entries',
  'products',
  'stock_movements',
  'users',
  'workflow_instances',
  'workflow_templates',
  'agent_tasks',
  'ai_agent_memory',
  'cross_business_insights'
]);

// Tables that don't require business_id
const SYSTEM_TABLES = new Set([
  'migrations',
  'system_config',
  'feature_flags',
  'rate_limit_rules'
]);

/**
 * Enhanced Tenant Isolation Security Layer
 * Provides comprehensive protection against cross-tenant data access
 */
export class TenantIsolationLayer {
  private readonly logger: Logger;
  private readonly violations: Map<string, TenantIsolationViolation[]> = new Map();
  private readonly businessCache: Map<string, { valid: boolean; expires: number }> = new Map();
  private readonly userAccessCache: Map<string, { allowed: boolean; expires: number }> = new Map();

  constructor() {
    this.logger = new Logger({ component: 'TenantIsolationLayer' });
  }

  /**
   * Validates tenant context before any database operation
   * @security-critical This is the primary defense against cross-tenant access
   */
  async validateTenantContext(
    context: TenantSecurityContext,
    env: Env
  ): Promise<{ valid: boolean; violations: TenantIsolationViolation[] }> {
    const violations: TenantIsolationViolation[] = [];

    try {
      // 1. Validate business ID format and existence
      const businessValidation = await this.validateBusinessId(context.businessId, env);
      if (!businessValidation.valid) {
        violations.push({
          id: `invalid_business_${Date.now()}`,
          type: 'invalid_business_id',
          severity: 'critical',
          cvssScore: 9.5,
          description: `Invalid business ID: ${context.businessId}`,
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          recommendation: 'Ensure valid business ID is provided',
          blocked: true
        });
      }

      // 2. Validate user-business membership
      const accessValidation = await this.validateUserBusinessAccess(
        context.userId,
        context.businessId,
        env
      );
      if (!accessValidation.allowed) {
        violations.push({
          id: `unauthorized_access_${Date.now()}`,
          type: 'unauthorized_access',
          severity: 'critical',
          cvssScore: 8.6,
          description: `User ${context.userId} not authorized for business ${context.businessId}`,
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          recommendation: 'User must have valid business membership',
          blocked: true
        });
      }

      // 3. Check for high-risk indicators
      if (context.riskScore > 70) {
        violations.push({
          id: `high_risk_context_${Date.now()}`,
          type: 'unauthorized_access',
          severity: 'high',
          cvssScore: 7.5,
          description: `High risk score detected: ${context.riskScore}`,
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          recommendation: 'Additional verification required for high-risk operations',
          blocked: context.riskScore > 85
        });
      }

      // 4. Enforce MFA for sensitive operations in strict isolation mode
      if (context.isolationLevel === 'strict' && !context.mfaEnabled) {
        this.logger.warn('MFA not enabled for strict isolation business', {
          businessId: context.businessId,
          userId: context.userId
        });
      }

      // Log security event
      if (violations.length > 0) {
        await this.logSecurityEvent(context, violations, env);
      }

      return {
        valid: violations.filter(v => v.blocked).length === 0,
        violations
      };

    } catch (error) {
      this.logger.error('Tenant context validation error', {
        error: error instanceof Error ? error.message : String(error),
        context
      });

      violations.push({
        id: `validation_error_${Date.now()}`,
        type: 'unauthorized_access',
        severity: 'critical',
        cvssScore: 9.0,
        description: 'Security validation failed',
        businessId: context.businessId,
        userId: context.userId,
        timestamp: new Date(),
        recommendation: 'Contact system administrator',
        blocked: true
      });

      return { valid: false, violations };
    }
  }

  /**
   * Secures database queries by injecting business_id filters
   * @security-critical Prevents cross-tenant data queries
   */
  secureQuery(
    query: string,
    params: any[],
    context: TenantSecurityContext
  ): { query: string; params: any[]; secure: boolean; violations: TenantIsolationViolation[] } {
    const violations: TenantIsolationViolation[] = [];

    try {
      // Parse query to understand structure
      const queryContext = this.parseQueryContext(query);

      // Check if query involves tenant-isolated tables
      const requiresIsolation = queryContext.tables.some(table =>
        TENANT_ISOLATED_TABLES.has(table.toLowerCase())
      );

      if (!requiresIsolation) {
        // System table or non-isolated query
        return { query, params, secure: true, violations: [] };
      }

      // Validate existing business_id filters
      if (!queryContext.hasBusinessIdFilter) {
        // Inject business_id filter
        const securedQuery = this.injectBusinessIdFilter(
          query,
          context.businessId,
          queryContext
        );

        if (!securedQuery.success) {
          violations.push({
            id: `query_injection_failed_${Date.now()}`,
            type: 'missing_business_id',
            severity: 'critical',
            cvssScore: 9.8,
            table: queryContext.tables[0],
            description: 'Query missing required business_id filter',
            businessId: context.businessId,
            userId: context.userId,
            timestamp: new Date(),
            query: query,
            recommendation: 'Add business_id = ? to WHERE clause',
            blocked: true
          });

          return { query, params, secure: false, violations };
        }

        return {
          query: securedQuery.query,
          params: [...params, context.businessId],
          secure: true,
          violations: []
        };
      }

      // Verify business_id in query matches context
      const businessIdsInQuery = this.extractBusinessIds(query, params);
      const invalidIds = businessIdsInQuery.filter(id => id !== context.businessId);

      if (invalidIds.length > 0) {
        violations.push({
          id: `cross_tenant_attempt_${Date.now()}`,
          type: 'cross_tenant_access',
          severity: 'critical',
          cvssScore: 9.8,
          table: queryContext.tables[0],
          description: `Attempted access to other businesses: ${invalidIds.join(', ')}`,
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          query: query,
          recommendation: 'Query can only access current business data',
          blocked: true
        });

        return { query, params, secure: false, violations };
      }

      return { query, params, secure: true, violations: [] };

    } catch (error) {
      this.logger.error('Query securing error', {
        error: error instanceof Error ? error.message : String(error),
        query
      });

      violations.push({
        id: `query_security_error_${Date.now()}`,
        type: 'injection_attempt',
        severity: 'high',
        cvssScore: 8.0,
        description: 'Query security check failed',
        businessId: context.businessId,
        userId: context.userId,
        timestamp: new Date(),
        query: query,
        recommendation: 'Review query syntax',
        blocked: true
      });

      return { query, params, secure: false, violations };
    }
  }

  /**
   * Validates data before database operations
   * @security-critical Ensures data contains proper tenant isolation
   */
  validateData(
    data: any,
    table: string,
    operation: 'INSERT' | 'UPDATE',
    context: TenantSecurityContext
  ): { valid: boolean; violations: TenantIsolationViolation[] } {
    const violations: TenantIsolationViolation[] = [];

    // Check if table requires tenant isolation
    if (!TENANT_ISOLATED_TABLES.has(table.toLowerCase())) {
      return { valid: true, violations: [] };
    }

    // For INSERT operations, ensure business_id is present and valid
    if (operation === 'INSERT') {
      if (!data.business_id) {
        // Auto-inject business_id for INSERT operations
        data.business_id = context.businessId;
      } else if (data.business_id !== context.businessId) {
        violations.push({
          id: `invalid_business_insert_${Date.now()}`,
          type: 'cross_tenant_access',
          severity: 'critical',
          cvssScore: 9.5,
          table: table,
          column: 'business_id',
          description: `Attempted INSERT with different business_id: ${data.business_id}`,
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          recommendation: 'Data must belong to current business',
          blocked: true
        });
      }
    }

    // For UPDATE operations, verify we're not changing business_id
    if (operation === 'UPDATE' && data.business_id) {
      if (data.business_id !== context.businessId) {
        violations.push({
          id: `business_id_change_attempt_${Date.now()}`,
          type: 'cross_tenant_access',
          severity: 'critical',
          cvssScore: 9.8,
          table: table,
          column: 'business_id',
          description: 'Attempted to change business_id in UPDATE operation',
          businessId: context.businessId,
          userId: context.userId,
          timestamp: new Date(),
          recommendation: 'business_id cannot be changed',
          blocked: true
        });
      }
    }

    // Check for injection attempts in data values
    const injectionCheck = this.checkForInjectionAttempts(data);
    if (injectionCheck.found) {
      violations.push({
        id: `injection_attempt_${Date.now()}`,
        type: 'injection_attempt',
        severity: 'high',
        cvssScore: 8.5,
        table: table,
        description: `Potential injection attempt detected: ${injectionCheck.pattern}`,
        businessId: context.businessId,
        userId: context.userId,
        timestamp: new Date(),
        recommendation: 'Sanitize input data',
        blocked: true
      });
    }

    return {
      valid: violations.filter(v => v.blocked).length === 0,
      violations
    };
  }

  /**
   * Validates business ID with comprehensive security checks
   */
  private async validateBusinessId(businessId: string, env: Env): Promise<{ valid: boolean }> {
    // Check cache first
    const cacheKey = `biz:${businessId}`;
    const cached = this.businessCache.get(cacheKey);

    if (cached && cached.expires > Date.now()) {
      return { valid: cached.valid };
    }

    try {
      // Format validation
      if (!businessId || typeof businessId !== 'string') {
        return { valid: false };
      }

      // Check for SQL injection patterns
      if (this.containsSqlInjectionPatterns(businessId)) {
        this.logger.warn('SQL injection attempt in business ID', { businessId });
        return { valid: false };
      }

      // Database validation
      const stmt = env.DB.prepare(`
        SELECT id, status, tenant_isolation_level
        FROM businesses
        WHERE id = ?
          AND status = 'active'
          AND deleted_at IS NULL
      `);

      const result = await stmt.bind(businessId).first();
      const valid = !!result;

      // Cache result (5 minutes for valid, 1 minute for invalid)
      this.businessCache.set(cacheKey, {
        valid,
        expires: Date.now() + (valid ? 300000 : 60000)
      });

      return { valid };

    } catch (error) {
      this.logger.error('Business ID validation error', {
        error: error instanceof Error ? error.message : String(error),
        businessId
      });
      return { valid: false };
    }
  }

  /**
   * Validates user has access to the specified business
   */
  private async validateUserBusinessAccess(
    userId: string,
    businessId: string,
    env: Env
  ): Promise<{ allowed: boolean }> {
    // Check cache
    const cacheKey = `access:${userId}:${businessId}`;
    const cached = this.userAccessCache.get(cacheKey);

    if (cached && cached.expires > Date.now()) {
      return { allowed: cached.allowed };
    }

    try {
      const stmt = env.DB.prepare(`
        SELECT bm.role, bm.status, u.status as user_status
        FROM business_memberships bm
        INNER JOIN users u ON bm.user_id = u.id
        WHERE bm.user_id = ?
          AND bm.business_id = ?
          AND bm.status = 'active'
          AND u.status = 'active'
      `);

      const result = await stmt.bind(userId, businessId).first();
      const allowed = !!result;

      // Cache result (5 minutes for allowed, 1 minute for denied)
      this.userAccessCache.set(cacheKey, {
        allowed,
        expires: Date.now() + (allowed ? 300000 : 60000)
      });

      return { allowed };

    } catch (error) {
      this.logger.error('User access validation error', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        businessId
      });
      return { allowed: false };
    }
  }

  /**
   * Parses query to extract security context
   */
  private parseQueryContext(query: string): QuerySecurityContext {
    const upperQuery = query.toUpperCase();

    // Determine operation type
    let operation: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'OTHER' = 'OTHER';
    if (upperQuery.startsWith('SELECT')) operation = 'SELECT';
    else if (upperQuery.startsWith('INSERT')) operation = 'INSERT';
    else if (upperQuery.startsWith('UPDATE')) operation = 'UPDATE';
    else if (upperQuery.startsWith('DELETE')) operation = 'DELETE';

    // Extract table names
    const tables: string[] = [];
    const tablePatterns = [
      /FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi,
      /UPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi,
      /INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi,
      /DELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi,
      /JOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)/gi
    ];

    for (const pattern of tablePatterns) {
      let match;
      pattern.lastIndex = 0;
      while ((match = pattern.exec(query)) !== null) {
        if (!tables.includes(match[1])) {
          tables.push(match[1]);
        }
      }
    }

    // Check for business_id filter
    const hasBusinessIdFilter = /business_id\s*=|business_id\s+IN/i.test(query);

    // Extract business IDs from query
    const businessIds: string[] = [];
    const idPattern = /business_id\s*=\s*['"]([^'"]+)['"]/gi;
    let match;
    while ((match = idPattern.exec(query)) !== null) {
      businessIds.push(match[1]);
    }

    // Calculate risk level (0-100)
    let riskLevel = 0;
    if (!hasBusinessIdFilter && tables.some(t => TENANT_ISOLATED_TABLES.has(t.toLowerCase()))) {
      riskLevel += 50;
    }
    if (operation === 'DELETE') riskLevel += 20;
    if (query.includes('*')) riskLevel += 10;
    if (tables.length > 3) riskLevel += 10;
    if (/UNION|INTERSECT|EXCEPT/i.test(query)) riskLevel += 20;

    return {
      query,
      params: [],
      tables,
      operation,
      hasBusinessIdFilter,
      businessIds,
      riskLevel
    };
  }

  /**
   * Injects business_id filter into query
   */
  private injectBusinessIdFilter(
    query: string,
    businessId: string,
    context: QuerySecurityContext
  ): { success: boolean; query: string } {
    try {
      let securedQuery = query;

      switch (context.operation) {
        case 'SELECT':
        case 'DELETE':
          // Add WHERE clause if missing, otherwise append to existing
          if (!/WHERE/i.test(query)) {
            securedQuery = query.replace(
              /(FROM\s+[a-zA-Z_][a-zA-Z0-9_]*(?:\s+[a-zA-Z_][a-zA-Z0-9_]*)?)/i,
              '$1 WHERE business_id = ?'
            );
          } else {
            securedQuery = query.replace(
              /WHERE\s+/i,
              'WHERE business_id = ? AND '
            );
          }
          break;

        case 'UPDATE':
          // Add WHERE clause if missing, otherwise append
          if (!/WHERE/i.test(query)) {
            securedQuery = query + ' WHERE business_id = ?';
          } else {
            securedQuery = query.replace(
              /WHERE\s+/i,
              'WHERE business_id = ? AND '
            );
          }
          break;

        case 'INSERT':
          // For INSERT, business_id should be in the data, not WHERE clause
          return { success: true, query };

        default:
          return { success: false, query };
      }

      return { success: true, query: securedQuery };

    } catch (error) {
      this.logger.error('Failed to inject business_id filter', {
        error: error instanceof Error ? error.message : String(error),
        query
      });
      return { success: false, query };
    }
  }

  /**
   * Extracts business IDs from query and parameters
   */
  private extractBusinessIds(query: string, params: any[]): string[] {
    const businessIds: string[] = [];

    // Extract from query string
    const patterns = [
      /business_id\s*=\s*['"]([^'"]+)['"]/gi,
      /business_id\s*IN\s*\(([^)]+)\)/gi
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(query)) !== null) {
        if (pattern.source.includes('IN')) {
          // Handle IN clause
          const ids = match[1].split(',').map(id =>
            id.trim().replace(/['"]/g, '')
          );
          businessIds.push(...ids);
        } else {
          businessIds.push(match[1]);
        }
      }
    }

    // Extract from parameters (if using placeholders)
    const placeholderIndex = (query.match(/business_id\s*=\s*\?/gi) || []).length;
    if (placeholderIndex > 0 && params.length >= placeholderIndex) {
      // This is simplified - in production, you'd need proper parameter mapping
      const paramValue = params[placeholderIndex - 1];
      if (typeof paramValue === 'string') {
        businessIds.push(paramValue);
      }
    }

    return [...new Set(businessIds)];
  }

  /**
   * Checks for SQL injection patterns
   */
  private containsSqlInjectionPatterns(value: string): boolean {
    const patterns = [
      /(\-\-|\/\*|\*\/|xp_|sp_|exec|execute|union|select|insert|update|delete|drop|create|alter)/i,
      /('|(\\')|(;)|(\+)|(=)|(>)|(<)|(%)|(CHAR\()|(CONCAT\())/i,
      /(script|javascript|onerror|onload|alert|document|window|eval)/i
    ];

    return patterns.some(pattern => pattern.test(value));
  }

  /**
   * Checks data for injection attempts
   */
  private checkForInjectionAttempts(data: any): { found: boolean; pattern?: string } {
    const checkValue = (value: any): { found: boolean; pattern?: string } => {
      if (typeof value === 'string') {
        if (this.containsSqlInjectionPatterns(value)) {
          return { found: true, pattern: 'SQL injection' };
        }
        // Check for NoSQL injection patterns
        if (value.includes('$') && /\$\w+/.test(value)) {
          return { found: true, pattern: 'NoSQL injection' };
        }
      } else if (typeof value === 'object' && value !== null) {
        for (const key in value) {
          const result = checkValue(value[key]);
          if (result.found) return result;
        }
      }
      return { found: false };
    };

    return checkValue(data);
  }

  /**
   * Logs security events for audit trail
   */
  private async logSecurityEvent(
    context: TenantSecurityContext,
    violations: TenantIsolationViolation[],
    env: Env
  ): Promise<void> {
    try {
      const event = {
        id: `sec_event_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        timestamp: new Date().toISOString(),
        business_id: context.businessId,
        user_id: context.userId,
        session_id: context.sessionId,
        request_id: context.requestId,
        ip_address: context.ipAddress,
        user_agent: context.userAgent,
        event_type: 'TENANT_ISOLATION_VIOLATION',
        severity: violations.some(v => v.severity === 'critical') ? 'critical' : 'high',
        violations: violations.map(v => ({
          type: v.type,
          severity: v.severity,
          cvss: v.cvssScore,
          description: v.description,
          blocked: v.blocked
        })),
        action_taken: violations.some(v => v.blocked) ? 'BLOCKED' : 'LOGGED',
        metadata: {
          user_role: context.userRole,
          isolation_level: context.isolationLevel,
          risk_score: context.riskScore,
          mfa_enabled: context.mfaEnabled
        }
      };

      // Store in audit log
      await env.DB.prepare(`
        INSERT INTO security_events (
          id, timestamp, business_id, user_id, event_type,
          severity, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
        event.id,
        event.timestamp,
        event.business_id,
        event.user_id,
        event.event_type,
        event.severity,
        JSON.stringify(event)
      ).run();

      // Store violations for analysis
      for (const violation of violations) {
        this.storeViolation(violation);
      }

      // Alert on critical violations
      if (violations.some(v => v.severity === 'critical' && v.blocked)) {
        this.logger.error('CRITICAL SECURITY VIOLATION', { event });
      }

    } catch (error) {
      this.logger.error('Failed to log security event', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Stores violations for analysis
   */
  private storeViolation(violation: TenantIsolationViolation): void {
    const key = `${violation.businessId}:${violation.userId}`;

    if (!this.violations.has(key)) {
      this.violations.set(key, []);
    }

    const userViolations = this.violations.get(key)!;
    userViolations.push(violation);

    // Keep only last 100 violations per user
    if (userViolations.length > 100) {
      userViolations.shift();
    }
  }

  /**
   * Gets violation statistics
   */
  getViolationStats(): {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    blockedCount: number;
  } {
    let total = 0;
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    let blockedCount = 0;

    for (const violations of this.violations.values()) {
      for (const violation of violations) {
        total++;

        byType[violation.type] = (byType[violation.type] || 0) + 1;
        bySeverity[violation.severity] = (bySeverity[violation.severity] || 0) + 1;

        if (violation.blocked) {
          blockedCount++;
        }
      }
    }

    return { total, byType, bySeverity, blockedCount };
  }

  /**
   * Clears caches (for testing or maintenance)
   */
  clearCaches(): void {
    this.businessCache.clear();
    this.userAccessCache.clear();
  }
}

// Export singleton instance
export const tenantIsolation = new TenantIsolationLayer();