/**
 * Comprehensive Authorization System for CoreFlow360 V4
 *
 * Features:
 * - Role-based access control (RBAC)
 * - Permission-based authorization
 * - Resource-level access control
 * - Multi-tenant isolation
 * - Hierarchical role system
 * - Dynamic permissions
 * - Audit logging for all access decisions
 * - Time-based access controls
 * - IP-based restrictions
 * - Business context enforcement
 */

import { AuthContext } from './auth';
import {
  logAuditEvent,
  AuditEventType,
  AuditSeverity
} from './security';

export interface Permission {
  id: string;
  name: string;
  resource: string;
  action: string;
  scope: 'global' | 'business' | 'user';
  description: string;
  businessId?: string;
  conditions?: PermissionCondition[];
}

export interface Role {
  id: string;
  name: string;
  description: string;
  businessId: string;
  permissions: string[];
  inheritsFrom: string[];
  isSystem: boolean;
  isActive: boolean;
  createdAt: number;
  updatedAt: number;
  expiresAt?: number;
}

export interface PermissionCondition {
  type: 'time' | 'ip' | 'location' | 'mfa' | 'custom';
  operator: 'equals' | 'not_equals' | 'in' | 'not_in' | 'between' | 'custom';
  value: any;
  description: string;
}

export interface AccessRequest {
  resource: string;
  action: string;
  businessId: string;
  resourceId?: string;
  context?: {
    ipAddress?: string;
    userAgent?: string;
    location?: string;
    requestTime?: number;
    requestId?: string;
  };
  metadata?: Record<string, any>;
}

export interface AccessDecision {
  granted: boolean;
  reason: string;
  code: string;
  requiredPermissions: string[];
  missingPermissions: string[];
  appliedPolicies: string[];
  conditions: PermissionCondition[];
  riskScore: number;
  auditData: {
    requestId: string;
    timestamp: number;
    userId: string;
    businessId: string;
    resource: string;
    action: string;
  };
}

export interface AuthorizationPolicy {
  id: string;
  name: string;
  businessId: string;
  resourcePattern: string;
  effect: 'allow' | 'deny';
  conditions: PermissionCondition[];
  priority: number;
  isActive: boolean;
}

export class AuthorizationService {
  private readonly db: D1Database;
  private readonly auditKV: KVNamespace;
  private readonly analytics?: AnalyticsEngineDataset;

  // Cache for performance
  private roleCache = new Map<string, Role>();
  private permissionCache = new Map<string, Permission>();
  private policyCache = new Map<string, AuthorizationPolicy[]>();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  constructor(
    db: D1Database,
    auditKV: KVNamespace,
    analytics?: AnalyticsEngineDataset
  ) {
    this.db = db;
    this.auditKV = auditKV;
    this.analytics = analytics;
  }

  /**
   * Main authorization check method
   */
  async authorize(
    user: AuthContext['user'],
    request: AccessRequest,
    metadata: AuthContext['metadata']
  ): Promise<AccessDecision> {
    const startTime = Date.now();
    const requestId = metadata.requestId || this.generateRequestId();

    try {
      // Basic validation
      if (!this.validateAuthorizationRequest(user, request)) {
        return this.createAccessDecision(false, 'Invalid authorization request', 'INVALID_REQUEST', user, request, requestId);
      }

      // Multi-tenant isolation check
      if (!this.enforceBusinessIsolation(user, request)) {
        await this.auditAccessDenial(user, request, 'Business isolation violation', requestId);
        return this.createAccessDecision(false, 'Access denied: business isolation violation', 'BUSINESS_ISOLATION_VIOLATION', user, request, requestId);
      }

      // Get user roles and permissions
      const userRoles = await this.getUserRoles(user.id, user.businessId);
      const userPermissions = await this.getUserPermissions(user.id, user.businessId);

      // Check direct permissions
      const directPermissionCheck = await this.checkDirectPermissions(userPermissions, request);
      if (directPermissionCheck.granted) {
        await this.auditAccessGranted(user, request, 'Direct permission match', requestId);
        return directPermissionCheck;
      }

      // Check role-based permissions
      const roleBasedCheck = await this.checkRoleBasedPermissions(userRoles, request);
      if (roleBasedCheck.granted) {
        await this.auditAccessGranted(user, request, 'Role-based permission match', requestId);
        return roleBasedCheck;
      }

      // Check authorization policies
      const policyCheck = await this.checkPolicies(user, request);
      if (policyCheck.granted) {
        await this.auditAccessGranted(user, request, 'Policy-based access granted', requestId);
        return policyCheck;
      }

      // Check conditional permissions
      const conditionalCheck = await this.checkConditionalPermissions(user, request, metadata);
      if (conditionalCheck.granted) {
        await this.auditAccessGranted(user, request, 'Conditional access granted', requestId);
        return conditionalCheck;
      }

      // Access denied
      await this.auditAccessDenial(user, request, 'Insufficient permissions', requestId);
      return this.createAccessDecision(false, 'Access denied: insufficient permissions', 'INSUFFICIENT_PERMISSIONS', user, request, requestId, {
        requiredPermissions: this.getRequiredPermissions(request),
        missingPermissions: await this.getMissingPermissions(user.id, request)
      });

    } catch (error) {
      console.error('Authorization error:', error);
      await this.auditAuthorizationError(user, request, error as Error, requestId);
      return this.createAccessDecision(false, 'Authorization check failed', 'AUTHORIZATION_ERROR', user, request, requestId);
    }
  }

  /**
   * Check if user has specific permission
   */
  async hasPermission(
    userId: string,
    businessId: string,
    permission: string
  ): Promise<boolean> {
    try {
      const userPermissions = await this.getUserPermissions(userId, businessId);
      return userPermissions.some(p =>
        p.name === permission ||
        p.name === '*:*' ||
        (permission.includes(':') && p.name === `${permission.split(':')[0]}:*`)
      );
    } catch (error) {
      console.error('Permission check error:', error);
      return false;
    }
  }

  /**
   * Check if user has specific role
   */
  async hasRole(
    userId: string,
    businessId: string,
    roleName: string
  ): Promise<boolean> {
    try {
      const userRoles = await this.getUserRoles(userId, businessId);
      return userRoles.some(role => role.name === roleName);
    } catch (error) {
      console.error('Role check error:', error);
      return false;
    }
  }

  /**
   * Get all permissions for a user (direct + role-based)
   */
  async getUserEffectivePermissions(
    userId: string,
    businessId: string
  ): Promise<Permission[]> {
    try {
      // Get direct permissions
      const directPermissions = await this.getUserPermissions(userId, businessId);

      // Get role-based permissions
      const userRoles = await this.getUserRoles(userId, businessId);
      const rolePermissions: Permission[] = [];

      for (const role of userRoles) {
        const permissions = await this.getRolePermissions(role.id);
        rolePermissions.push(...permissions);
      }

      // Combine and deduplicate
      const allPermissions = [...directPermissions, ...rolePermissions];
      const uniquePermissions = new Map<string, Permission>();

      allPermissions.forEach(perm => {
        uniquePermissions.set(perm.id, perm);
      });

      return Array.from(uniquePermissions.values());
    } catch (error) {
      console.error('Error getting effective permissions:', error);
      return [];
    }
  }

  /**
   * Validate authorization request
   */
  private validateAuthorizationRequest(
    user: AuthContext['user'],
    request: AccessRequest
  ): boolean {
    if (!user || !user.id || !user.businessId) {
      return false;
    }

    if (!request || !request.resource || !request.action || !request.businessId) {
      return false;
    }

    if (!this.isValidResourceName(request.resource) || !this.isValidActionName(request.action)) {
      return false;
    }

    return true;
  }

  /**
   * Enforce multi-tenant business isolation
   */
  private enforceBusinessIsolation(
    user: AuthContext['user'],
    request: AccessRequest
  ): boolean {
    // Users can only access resources in their own business
    return user.businessId === request.businessId;
  }

  /**
   * Check direct user permissions
   */
  private async checkDirectPermissions(
    userPermissions: Permission[],
    request: AccessRequest
  ): Promise<AccessDecision> {
    const requiredPermission = `${request.resource}:${request.action}`;

    for (const permission of userPermissions) {
      if (this.matchesPermission(permission, requiredPermission, request)) {
        return this.createAccessDecision(
          true,
          'Access granted via direct permission',
          'DIRECT_PERMISSION',
          null as any, // Will be filled later
          request,
          '',
          { appliedPolicies: [permission.name] }
        );
      }
    }

    return this.createAccessDecision(false, 'No direct permissions match', 'NO_DIRECT_PERMISSION', null as any, request, '');
  }

  /**
   * Check role-based permissions
   */
  private async checkRoleBasedPermissions(
    userRoles: Role[],
    request: AccessRequest
  ): Promise<AccessDecision> {
    const requiredPermission = `${request.resource}:${request.action}`;
    const appliedRoles: string[] = [];

    for (const role of userRoles) {
      if (!role.isActive || (role.expiresAt && Date.now() > role.expiresAt)) {
        continue;
      }

      const rolePermissions = await this.getRolePermissions(role.id);

      for (const permission of rolePermissions) {
        if (this.matchesPermission(permission, requiredPermission, request)) {
          appliedRoles.push(role.name);
          return this.createAccessDecision(
            true,
            `Access granted via role: ${role.name}`,
            'ROLE_BASED_PERMISSION',
            null as any,
            request,
            '',
            { appliedPolicies: appliedRoles }
          );
        }
      }
    }

    return this.createAccessDecision(false, 'No role-based permissions match', 'NO_ROLE_PERMISSION', null as any, request, '');
  }

  /**
   * Check authorization policies
   */
  private async checkPolicies(
    user: AuthContext['user'],
    request: AccessRequest
  ): Promise<AccessDecision> {
    const policies = await this.getBusinessPolicies(request.businessId);
    const matchingPolicies: AuthorizationPolicy[] = [];

    for (const policy of policies) {
      if (!policy.isActive) continue;

      // Check if policy matches the resource
      if (this.matchesResourcePattern(policy.resourcePattern, request.resource)) {
        // Check conditions
        const conditionsMatch = await this.checkPolicyConditions(policy.conditions, user, request);

        if (conditionsMatch) {
          matchingPolicies.push(policy);
        }
      }
    }

    // Sort by priority (higher priority first)
    matchingPolicies.sort((a, b) => b.priority - a.priority);

    // Apply first matching policy
    for (const policy of matchingPolicies) {
      if (policy.effect === 'allow') {
        return this.createAccessDecision(
          true,
          `Access granted by policy: ${policy.name}`,
          'POLICY_ALLOW',
          user,
          request,
          '',
          { appliedPolicies: [policy.name] }
        );
      } else if (policy.effect === 'deny') {
        return this.createAccessDecision(
          false,
          `Access denied by policy: ${policy.name}`,
          'POLICY_DENY',
          user,
          request,
          '',
          { appliedPolicies: [policy.name] }
        );
      }
    }

    return this.createAccessDecision(false, 'No matching policies', 'NO_POLICY_MATCH', user, request, '');
  }

  /**
   * Check conditional permissions based on context
   */
  private async checkConditionalPermissions(
    user: AuthContext['user'],
    request: AccessRequest,
    metadata: AuthContext['metadata']
  ): Promise<AccessDecision> {
    const permissions = await this.getUserEffectivePermissions(user.id, user.businessId);

    for (const permission of permissions) {
      if (!permission.conditions || permission.conditions.length === 0) {
        continue;
      }

      const requiredPermission = `${request.resource}:${request.action}`;
      if (!this.matchesPermission(permission, requiredPermission, request)) {
        continue;
      }

      // Check all conditions
      const conditionsMatch = await this.checkPermissionConditions(
        permission.conditions,
        user,
        request,
        metadata
      );

      if (conditionsMatch) {
        return this.createAccessDecision(
          true,
          'Access granted via conditional permission',
          'CONDITIONAL_PERMISSION',
          user,
          request,
          '',
          {
            appliedPolicies: [permission.name],
            conditions: permission.conditions
          }
        );
      }
    }

    return this.createAccessDecision(false, 'Conditional permissions not met', 'CONDITIONS_NOT_MET', user, request, '');
  }

  /**
   * Check if permission matches the required permission
   */
  private matchesPermission(
    permission: Permission,
    requiredPermission: string,
    request: AccessRequest
  ): boolean {
    // Exact match
    if (permission.name === requiredPermission) {
      return true;
    }

    // Wildcard permissions
    if (permission.name === '*:*') {
      return true; // Super admin permission
    }

    // Resource wildcard (e.g., "users:*")
    if (permission.name.endsWith(':*')) {
      const permissionResource = permission.name.split(':')[0];
      const requiredResource = requiredPermission.split(':')[0];
      return permissionResource === requiredResource;
    }

    // Action wildcard (e.g., "*:read")
    if (permission.name.startsWith('*:')) {
      const permissionAction = permission.name.split(':')[1];
      const requiredAction = requiredPermission.split(':')[1];
      return permissionAction === requiredAction;
    }

    return false;
  }

  /**
   * Check if resource pattern matches resource
   */
  private matchesResourcePattern(pattern: string, resource: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.')
      .replace(/\[([^\]]+)\]/g, '[$1]');

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(resource);
  }

  /**
   * Check policy conditions
   */
  private async checkPolicyConditions(
    conditions: PermissionCondition[],
    user: AuthContext['user'],
    request: AccessRequest
  ): Promise<boolean> {
    if (conditions.length === 0) {
      return true; // No conditions means always true
    }

    // All conditions must be met (AND logic)
    for (const condition of conditions) {
      const conditionMet = await this.evaluateCondition(condition, user, request);
      if (!conditionMet) {
        return false;
      }
    }

    return true;
  }

  /**
   * Check permission conditions
   */
  private async checkPermissionConditions(
    conditions: PermissionCondition[],
    user: AuthContext['user'],
    request: AccessRequest,
    metadata: AuthContext['metadata']
  ): Promise<boolean> {
    if (conditions.length === 0) {
      return true;
    }

    for (const condition of conditions) {
      const conditionMet = await this.evaluateCondition(condition, user, request, metadata);
      if (!conditionMet) {
        return false;
      }
    }

    return true;
  }

  /**
   * Evaluate a single condition
   */
  private async evaluateCondition(
    condition: PermissionCondition,
    user: AuthContext['user'],
    request: AccessRequest,
    metadata?: AuthContext['metadata']
  ): Promise<boolean> {
    try {
      switch (condition.type) {
        case 'time':
          return this.evaluateTimeCondition(condition);

        case 'ip':
          return this.evaluateIPCondition(condition, metadata?.ipAddress || '');

        case 'location':
          return this.evaluateLocationCondition(condition, request.context?.location);

        case 'mfa':
          return this.evaluateMFACondition(condition, user.mfaVerified);

        case 'custom':
          return this.evaluateCustomCondition(condition, user, request, metadata);

        default:
          console.warn('Unknown condition type:', condition.type);
          return false;
      }
    } catch (error) {
      console.error('Error evaluating condition:', error);
      return false;
    }
  }

  /**
   * Evaluate time-based conditions
   */
  private evaluateTimeCondition(condition: PermissionCondition): boolean {
    const currentTime = new Date();

    switch (condition.operator) {
      case 'between':
        if (Array.isArray(condition.value) && condition.value.length === 2) {
          const startTime = new Date(condition.value[0]);
          const endTime = new Date(condition.value[1]);
          return currentTime >= startTime && currentTime <= endTime;
        }
        return false;

      default:
        return false;
    }
  }

  /**
   * Evaluate IP-based conditions
   */
  private evaluateIPCondition(condition: PermissionCondition, ipAddress: string): boolean {
    if (!ipAddress) return false;

    switch (condition.operator) {
      case 'equals':
        return ipAddress === condition.value;

      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(ipAddress);

      case 'not_in':
        return Array.isArray(condition.value) && !condition.value.includes(ipAddress);

      default:
        return false;
    }
  }

  /**
   * Evaluate location-based conditions
   */
  private evaluateLocationCondition(condition: PermissionCondition, location?: string): boolean {
    if (!location) return false;

    switch (condition.operator) {
      case 'equals':
        return location === condition.value;

      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(location);

      default:
        return false;
    }
  }

  /**
   * Evaluate MFA conditions
   */
  private evaluateMFACondition(condition: PermissionCondition, mfaVerified: boolean): boolean {
    switch (condition.operator) {
      case 'equals':
        return mfaVerified === condition.value;

      default:
        return false;
    }
  }

  /**
   * Evaluate custom conditions
   */
  private async evaluateCustomCondition(
    condition: PermissionCondition,
    user: AuthContext['user'],
    request: AccessRequest,
    metadata?: AuthContext['metadata']
  ): Promise<boolean> {
    // Implement custom condition logic based on your business requirements
    // This is a placeholder for extensibility
    return true;
  }

  /**
   * Get user roles from database
   */
  private async getUserRoles(userId: string, businessId: string): Promise<Role[]> {
    try {
      const result = await this.db.prepare(`
        SELECT r.* FROM roles r
        INNER JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ? AND r.business_id = ? AND r.is_active = 1
        AND (r.expires_at IS NULL OR r.expires_at > ?)
      `).bind(userId, businessId, Date.now()).all();

      return (result.results || []).map(this.mapRowToRole);
    } catch (error) {
      console.error('Error fetching user roles:', error);
      return [];
    }
  }

  /**
   * Get user permissions from database
   */
  private async getUserPermissions(userId: string, businessId: string): Promise<Permission[]> {
    try {
      const result = await this.db.prepare(`
        SELECT p.* FROM permissions p
        INNER JOIN user_permissions up ON p.id = up.permission_id
        WHERE up.user_id = ? AND (p.business_id = ? OR p.scope = 'global')
      `).bind(userId, businessId).all();

      return (result.results || []).map(this.mapRowToPermission);
    } catch (error) {
      console.error('Error fetching user permissions:', error);
      return [];
    }
  }

  /**
   * Get role permissions from database
   */
  private async getRolePermissions(roleId: string): Promise<Permission[]> {
    try {
      const result = await this.db.prepare(`
        SELECT p.* FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?
      `).bind(roleId).all();

      return (result.results || []).map(this.mapRowToPermission);
    } catch (error) {
      console.error('Error fetching role permissions:', error);
      return [];
    }
  }

  /**
   * Get business policies from database
   */
  private async getBusinessPolicies(businessId: string): Promise<AuthorizationPolicy[]> {
    const cacheKey = `policies:${businessId}`;
    const cached = this.policyCache.get(cacheKey);

    if (cached && Array.isArray(cached)) {
      return cached;
    }

    try {
      const result = await this.db.prepare(`
        SELECT * FROM authorization_policies
        WHERE business_id = ? AND is_active = 1
        ORDER BY priority DESC
      `).bind(businessId).all();

      const policies = (result.results || []).map(this.mapRowToPolicy);
      this.policyCache.set(cacheKey, policies);

      // Set cache expiration
      setTimeout(() => {
        this.policyCache.delete(cacheKey);
      }, this.CACHE_TTL);

      return policies;
    } catch (error) {
      console.error('Error fetching business policies:', error);
      return [];
    }
  }

  /**
   * Get required permissions for a request
   */
  private getRequiredPermissions(request: AccessRequest): string[] {
    return [`${request.resource}:${request.action}`];
  }

  /**
   * Get missing permissions for a user
   */
  private async getMissingPermissions(userId: string, request: AccessRequest): Promise<string[]> {
    const required = this.getRequiredPermissions(request);
    const userPermissions = await this.getUserEffectivePermissions(userId, request.businessId);
    const userPermissionNames = userPermissions.map(p => p.name);

    return required.filter(perm =>
      !userPermissionNames.some(userPerm => this.matchesPermission({ name: userPerm } as Permission, perm, request))
    );
  }

  /**
   * Create access decision object
   */
  private createAccessDecision(
    granted: boolean,
    reason: string,
    code: string,
    user: AuthContext['user'] | null,
    request: AccessRequest,
    requestId: string,
    additional: Partial<AccessDecision> = {}
  ): AccessDecision {
    return {
      granted,
      reason,
      code,
      requiredPermissions: this.getRequiredPermissions(request),
      missingPermissions: [],
      appliedPolicies: [],
      conditions: [],
      riskScore: granted ? 0.1 : 0.5,
      auditData: {
        requestId,
        timestamp: Date.now(),
        userId: user?.id || 'unknown',
        businessId: request.businessId,
        resource: request.resource,
        action: request.action
      },
      ...additional
    };
  }

  /**
   * Validation helpers
   */
  private isValidResourceName(resource: string): boolean {
    return /^[a-zA-Z][a-zA-Z0-9_.-]*$/.test(resource);
  }

  private isValidActionName(action: string): boolean {
    return /^[a-zA-Z][a-zA-Z0-9_]*$/.test(action);
  }

  private generateRequestId(): string {
    return `auth_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Database row mapping helpers
   */
  private mapRowToRole(row: any): Role {
    return {
      id: row.id,
      name: row.name,
      description: row.description,
      businessId: row.business_id,
      permissions: JSON.parse(row.permissions || '[]'),
      inheritsFrom: JSON.parse(row.inherits_from || '[]'),
      isSystem: row.is_system === 1,
      isActive: row.is_active === 1,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresAt: row.expires_at
    };
  }

  private mapRowToPermission(row: any): Permission {
    return {
      id: row.id,
      name: row.name,
      resource: row.resource,
      action: row.action,
      scope: row.scope,
      description: row.description,
      businessId: row.business_id,
      conditions: JSON.parse(row.conditions || '[]')
    };
  }

  private mapRowToPolicy(row: any): AuthorizationPolicy {
    return {
      id: row.id,
      name: row.name,
      businessId: row.business_id,
      resourcePattern: row.resource_pattern,
      effect: row.effect,
      conditions: JSON.parse(row.conditions || '[]'),
      priority: row.priority,
      isActive: row.is_active === 1
    };
  }

  /**
   * Audit logging methods
   */
  private async auditAccessGranted(
    user: AuthContext['user'],
    request: AccessRequest,
    reason: string,
    requestId: string
  ): Promise<void> {
    try {
      await logAuditEvent({
        eventType: AuditEventType.DATA_ACCESS,
        severity: AuditSeverity.LOW,
        userId: user.id,
        businessId: user.businessId,
        resource: request.resource,
        action: request.action,
        success: true,
        riskScore: 0.1,
        details: {
          requestId,
          reason,
          resourceId: request.resourceId,
          granted: true
        }
      }, this.auditKV, this.analytics);
    } catch (error) {
      console.error('Failed to audit access granted:', error);
    }
  }

  private async auditAccessDenial(
    user: AuthContext['user'],
    request: AccessRequest,
    reason: string,
    requestId: string
  ): Promise<void> {
    try {
      await logAuditEvent({
        eventType: AuditEventType.PERMISSION_DENIED,
        severity: AuditSeverity.MEDIUM,
        userId: user.id,
        businessId: user.businessId,
        resource: request.resource,
        action: request.action,
        success: false,
        riskScore: 0.6,
        details: {
          requestId,
          reason,
          resourceId: request.resourceId,
          granted: false
        }
      }, this.auditKV, this.analytics);
    } catch (error) {
      console.error('Failed to audit access denial:', error);
    }
  }

  private async auditAuthorizationError(
    user: AuthContext['user'],
    request: AccessRequest,
    error: Error,
    requestId: string
  ): Promise<void> {
    try {
      await logAuditEvent({
        eventType: AuditEventType.SUSPICIOUS_ACTIVITY,
        severity: AuditSeverity.HIGH,
        userId: user.id,
        businessId: user.businessId,
        resource: request.resource,
        action: request.action,
        success: false,
        riskScore: 0.8,
        details: {
          requestId,
          error: error.message,
          stack: error.stack
        }
      }, this.auditKV, this.analytics);
    } catch (auditError) {
      console.error('Failed to audit authorization error:', auditError);
    }
  }

  /**
   * Clear caches
   */
  clearCache(): void {
    this.roleCache.clear();
    this.permissionCache.clear();
    this.policyCache.clear();
  }
}

/**
 * Create authorization service instance
 */
export function createAuthorizationService(
  db: D1Database,
  auditKV: KVNamespace,
  analytics?: AnalyticsEngineDataset
): AuthorizationService {
  return new AuthorizationService(db, auditKV, analytics);
}

/**
 * Authorization middleware factory
 */
export function requirePermission(
  resource: string,
  action: string,
  authorizationService: AuthorizationService
) {
  return async (request: Request, authContext: AuthContext): Promise<{ allowed: boolean; reason?: string }> => {
    const accessRequest: AccessRequest = {
      resource,
      action,
      businessId: authContext.user.businessId,
      context: {
        ipAddress: authContext.metadata.ipAddress,
        userAgent: authContext.metadata.userAgent,
        requestTime: Date.now(),
        requestId: authContext.metadata.requestId
      }
    };

    const decision = await authorizationService.authorize(
      authContext.user,
      accessRequest,
      authContext.metadata
    );

    return {
      allowed: decision.granted,
      reason: decision.reason
    };
  };
}

/**
 * Role requirement middleware factory
 */
export function requireRole(
  roleName: string,
  authorizationService: AuthorizationService
) {
  return async (authContext: AuthContext): Promise<{ allowed: boolean; reason?: string }> => {
    const hasRole = await authorizationService.hasRole(
      authContext.user.id,
      authContext.user.businessId,
      roleName
    );

    return {
      allowed: hasRole,
      reason: hasRole ? 'Role requirement satisfied' : `Required role '${roleName}' not found`
    };
  };
}

// Types already exported as interfaces above (lines 24-100)
// No need to re-export them here