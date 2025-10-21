import { Logger } from '../shared/logger';
const logger = new Logger({ component: 'tenant-isolation' });

/**
 * Comprehensive Tenant Isolation System - Fortune 50 Level Security
 * 
 * SECURITY FIXES IMPLEMENTED:
 * - CVSS 8.7 Tenant Isolation Bypass Prevention
 * - Multi-layer business ID validation
 * - Database-level tenant isolation enforcement
 * - Cross-tenant access prevention
 * - Comprehensive audit logging for violations
 * - Fail-secure approach to tenant validation
 */

import { SecurityError } from '../shared/errors/app-error';

export interface TenantContext {
  userId: string;
  businessId: string;
  userRole: string;
  permissions: string[];
  sessionId: string;
  ipAddress: string;
  userAgent: string;
}

export interface TenantValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  businessId: string;
  userId: string;
  accessLevel: 'read' | 'write' | 'admin';
}

export interface BusinessIdValidation {
  formatValid: boolean;
  existsInDatabase: boolean;
  userHasAccess: boolean;
  isActive: boolean;
  isDeleted: boolean;
}

/**
 * Comprehensive Tenant Isolation Manager
 * Implements defense-in-depth tenant isolation with multiple validation layers
 */
export class TenantIsolationManager {
  private static readonly BUSINESS_ID_PATTERN = /^biz_[a-zA-Z0-9_-]{8,32}$/;
  private static readonly USER_ID_PATTERN = /^usr_[a-zA-Z0-9_-]{8,32}$/;
  private static readonly MAX_BUSINESS_ID_LENGTH = 32;
  private static readonly MIN_BUSINESS_ID_LENGTH = 8;

  /**
   * Validate tenant access with comprehensive security checks
   */
  static async validateTenantAccess(
    userId: string,
    businessId: string,
    resource: string,
    action: 'read' | 'write' | 'delete' | 'admin',
    db: any,
    context: TenantContext
  ): Promise<TenantValidationResult> {
    const result: TenantValidationResult = {
      isValid: false,
      errors: [],
      warnings: [],
      businessId: '',
      userId: '',
      accessLevel: 'read'
    };

    try {
      // Layer 1: Format validation
      const formatValidation = this.validateBusinessIdFormat(businessId);
      if (!formatValidation.isValid) {
        result.errors.push(`Invalid business ID format: ${formatValidation.error}`);
        await this.logTenantViolation('INVALID_FORMAT', userId, businessId, context);
        return result;
      }

      // Layer 2: Database existence validation
      const dbValidation = await this.validateBusinessIdInDatabase(businessId, db);
      if (!dbValidation.existsInDatabase) {
        result.errors.push('Business ID does not exist in database');
        await this.logTenantViolation('NONEXISTENT_BUSINESS', userId, businessId, context);
        return result;
      }

      if (dbValidation.isDeleted) {
        result.errors.push('Business ID has been deleted');
        await this.logTenantViolation('DELETED_BUSINESS', userId, businessId, context);
        return result;
      }

      if (!dbValidation.isActive) {
        result.errors.push('Business ID is inactive');
        await this.logTenantViolation('INACTIVE_BUSINESS', userId, businessId, context);
        return result;
      }

      // Layer 3: User membership validation
      const membershipValidation = await this.validateUserBusinessMembership(userId, businessId, db);
      if (!membershipValidation.isValid) {
        result.errors.push('User is not a member of this business');
        await this.logTenantViolation('UNAUTHORIZED_MEMBERSHIP', userId, businessId, context);
        return result;
      }

      // Layer 4: Resource access validation
      const resourceValidation = await this.validateResourceAccess(userId, businessId, resource, action, db);
      if (!resourceValidation.isValid) {
        result.errors.push(`User does not have ${action} access to ${resource}`);
        await this.logTenantViolation('INSUFFICIENT_PERMISSIONS', userId, businessId, context);
        return result;
      }

      // Layer 5: Session validation
      const sessionValidation = await this.validateSessionContext(context, db);
      if (!sessionValidation.isValid) {
        result.errors.push('Invalid session context');
        await this.logTenantViolation('INVALID_SESSION', userId, businessId, context);
        return result;
      }

      // All validations passed
      result.isValid = true;
      result.businessId = businessId;
      result.userId = userId;
      result.accessLevel = resourceValidation.accessLevel;

      // Log successful access
      await this.logTenantAccess('SUCCESSFUL_ACCESS', userId, businessId, context);

      return result;

    } catch (error: any) {
      result.errors.push(`Tenant validation error: ${error.message}`);
      await this.logTenantViolation('VALIDATION_ERROR', userId, businessId, context);
      return result;
    }
  }

  /**
   * Validate business ID format with comprehensive checks
   */
  static validateBusinessIdFormat(businessId: string): { isValid: boolean; error?: string } {
    if (!businessId) {
      return { isValid: false, error: 'Business ID is required' };
    }

    if (typeof businessId !== 'string') {
      return { isValid: false, error: 'Business ID must be a string' };
    }

    if (businessId.length < this.MIN_BUSINESS_ID_LENGTH) {
      return { isValid: false, error: `Business ID must be at least ${this.MIN_BUSINESS_ID_LENGTH} characters` };
    }

    if (businessId.length > this.MAX_BUSINESS_ID_LENGTH) {
      return { isValid: false, error: `Business ID must be no more than ${this.MAX_BUSINESS_ID_LENGTH} characters` };
    }

    if (!this.BUSINESS_ID_PATTERN.test(businessId)) {
      return { isValid: false, error: 'Business ID must match pattern: biz_[a-zA-Z0-9_-]{8,32}' };
    }

    // Check for common injection patterns
    if (this.containsInjectionPatterns(businessId)) {
      return { isValid: false, error: 'Business ID contains potentially dangerous patterns' };
    }

    return { isValid: true };
  }

  /**
   * Validate business ID exists in database
   */
  static async validateBusinessIdInDatabase(businessId: string, db: any): Promise<BusinessIdValidation> {
    try {
      const result = await db.prepare(`
        SELECT id, is_active, deleted_at, created_at, updated_at
        FROM businesses 
        WHERE id = ? AND deleted_at IS NULL
      `).bind(businessId).first();

      return {
        formatValid: true,
        existsInDatabase: !!result,
        userHasAccess: false, // Will be validated separately
        isActive: result?.is_active === 1,
        isDeleted: !!result?.deleted_at
      };
    } catch (error: any) {
      throw new SecurityError(`Database validation failed: ${error.message}`);
    }
  }

  /**
   * Validate user membership in business
   */
  static async validateUserBusinessMembership(userId: string, businessId: string, db: any): Promise<{ isValid: boolean; role?: string; permissions?: string[] }> {
    try {
      const result = await db.prepare(`
        SELECT u.id, u.business_id, u.role, u.permissions, u.is_active, u.deleted_at
        FROM users u
        WHERE u.id = ? AND u.business_id = ? AND u.deleted_at IS NULL
      `).bind(userId, businessId).first();

      if (!result) {
        return { isValid: false };
      }

      if (result.is_active !== 1) {
        return { isValid: false };
      }

      return {
        isValid: true,
        role: result.role,
        permissions: JSON.parse(result.permissions || '[]')
      };
    } catch (error: any) {
      throw new SecurityError(`User membership validation failed: ${error.message}`);
    }
  }

  /**
   * Validate resource access permissions
   */
  static async validateResourceAccess(
    userId: string,
    businessId: string,
    resource: string,
    action: string,
    db: any
  ): Promise<{ isValid: boolean; accessLevel: 'read' | 'write' | 'admin' }> {
    try {
      // Get user permissions
      const userResult = await db.prepare(`
        SELECT role, permissions
        FROM users
        WHERE id = ? AND business_id = ? AND deleted_at IS NULL
      `).bind(userId, businessId).first();

      if (!userResult) {
        return { isValid: false, accessLevel: 'read' };
      }

      const permissions = JSON.parse(userResult.permissions || '[]');
      const role = userResult.role;

      // Check role-based access
      if (role === 'admin') {
        return { isValid: true, accessLevel: 'admin' };
      }

      if (role === 'manager' && ['read', 'write'].includes(action)) {
        return { isValid: true, accessLevel: 'write' };
      }

      if (role === 'user' && action === 'read') {
        return { isValid: true, accessLevel: 'read' };
      }

      // Check specific permissions
      const requiredPermission = `${resource}:${action}`;
      if (permissions.includes(requiredPermission)) {
        return { isValid: true, accessLevel: action as any };
      }

      return { isValid: false, accessLevel: 'read' };

    } catch (error: any) {
      throw new SecurityError(`Resource access validation failed: ${error.message}`);
    }
  }

  /**
   * Validate session context
   */
  static async validateSessionContext(context: TenantContext, db: any): Promise<{ isValid: boolean; error?: string }> {
    try {
      // Validate session exists and is active
      const sessionResult = await db.prepare(`
        SELECT id, user_id, business_id, expires_at, is_active
        FROM sessions
        WHERE id = ? AND user_id = ? AND business_id = ? AND expires_at > ? AND is_active = 1
      `).bind(context.sessionId, context.userId, context.businessId, Date.now()).first();

      if (!sessionResult) {
        return { isValid: false, error: 'Invalid or expired session' };
      }

      // Validate IP address consistency (optional, can be disabled for mobile users)
      if (context.ipAddress && sessionResult.ip_address && sessionResult.ip_address !== context.ipAddress) {
        // Log potential session hijacking attempt
        await this.logTenantViolation('IP_MISMATCH', context.userId, context.businessId, context);
        // Don't fail validation for IP mismatch, just log it
      }

      return { isValid: true };

    } catch (error: any) {
      return { isValid: false, error: `Session validation failed: ${error.message}` };
    }
  }

  /**
   * Inject business ID into database queries
   */
  static injectBusinessIdFilter(query: string, businessId: string): string {
    // This is a simplified version - in production, use a proper query builder
    if (query.includes('WHERE')) {
      return query.replace('WHERE', `WHERE business_id = '${businessId}' AND`);
    } else {
      return query + ` WHERE business_id = '${businessId}'`;
    }
  }

  /**
   * Create secure database query with tenant isolation
   */
  static createSecureQuery(
    baseQuery: string,
    businessId: string,
    params: any[] = []
  ): { query: string; params: any[] } {
    // Validate business ID format first
    const formatValidation = this.validateBusinessIdFormat(businessId);
    if (!formatValidation.isValid) {
      throw new SecurityError(`Invalid business ID: ${formatValidation.error}`);
    }

    // Add business_id parameter
    const secureParams = [businessId, ...params];
    
    // Inject business_id filter
    let secureQuery = baseQuery;
    if (baseQuery.includes('WHERE')) {
      secureQuery = baseQuery.replace('WHERE', 'WHERE business_id = ? AND');
    } else {
      secureQuery = baseQuery + ' WHERE business_id = ?';
    }

    return { query: secureQuery, params: secureParams };
  }

  /**
   * Check for injection patterns in business ID
   */
  private static containsInjectionPatterns(businessId: string): boolean {
    const dangerousPatterns = [
      /['"]/,           // Quotes
      /;/,              // Semicolons
      /--/,             // SQL comments
      /\/*/,            // SQL block comments
      /union/i,         // SQL UNION
      /select/i,        // SQL SELECT
      /insert/i,        // SQL INSERT
      /update/i,        // SQL UPDATE
      /delete/i,        // SQL DELETE
      /drop/i,          // SQL DROP
      /script/i,        // XSS patterns
      /javascript/i,    // XSS patterns
      /<script/i,       // XSS patterns
      /onload/i,        // XSS patterns
      /onerror/i,       // XSS patterns
    ];

    return dangerousPatterns.some(pattern => pattern.test(businessId));
  }

  /**
   * Log tenant access violations
   */
  private static async logTenantViolation(
    violationType: string,
    userId: string,
    businessId: string,
    context: TenantContext
  ): Promise<void> {
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType: 'TENANT_VIOLATION',
      violationType,
      userId,
      businessId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      sessionId: context.sessionId,
      severity: 'HIGH',
      details: {
        attemptedAccess: businessId,
        userRole: context.userRole,
        permissions: context.permissions
      }
    };

    // In production, this would be sent to a secure logging service
    logger.error('TENANT ISOLATION VIOLATION:', logEntry);
    
    // Could also send to external monitoring service
    // await this.sendToMonitoringService(logEntry);
  }

  /**
   * Log successful tenant access
   */
  private static async logTenantAccess(
    accessType: string,
    userId: string,
    businessId: string,
    context: TenantContext
  ): Promise<void> {
    const logEntry = {
      timestamp: new Date().toISOString(),
      eventType: 'TENANT_ACCESS',
      accessType,
      userId,
      businessId,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      sessionId: context.sessionId,
      severity: 'INFO'
    };

    // In production, this would be sent to audit logging service
    logger.info('TENANT ACCESS:', logEntry);
  }
}

/**
 * Middleware for automatic tenant isolation
 */
export function createTenantIsolationMiddleware(db: any) {
  return async (c: any, next: () => Promise<void>) => {
    const userId = c.get('userId');
    const businessId = c.get('businessId');
    const resource = c.req.url.split('/').pop() || 'unknown';
    const action = c.req.method.toLowerCase();

    if (!userId || !businessId) {
      return c.json({ error: 'Missing user or business context' }, 400);
    }

    const context: TenantContext = {
      userId,
      businessId,
      userRole: c.get('userRole') || 'user',
      permissions: c.get('permissions') || [],
      sessionId: c.get('sessionId') || '',
      ipAddress: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || 'unknown',
      userAgent: c.req.header('User-Agent') || 'unknown'
    };

    const validation = await TenantIsolationManager.validateTenantAccess(
      userId,
      businessId,
      resource,
      action as any,
      db,
      context
    );

    if (!validation.isValid) {
      return c.json({ 
        error: 'Access denied', 
        details: validation.errors 
      }, 403);
    }

    // Add validation result to context
    c.set('tenantValidation', validation);
    await next();
  };
}
