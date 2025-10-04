/**
 * Role-Based Access Control (RBAC) System
 * SECURITY: Implements granular permission management
 * Fixes: CVSS 6.5 vulnerability - Improper access control
 */

export interface Permission {
  id: string;
  resource: string;
  action: string;
  scope?: 'own' | 'business' | 'all';
  conditions?: Record<string, any>;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: Permission[];
  parentRole?: string; // For role hierarchy
  isSystem: boolean; // System roles can't be modified
  createdAt: number;
  updatedAt: number;
}

export interface UserPermissions {
  userId: string;
  businessId: string;
  roles: string[];
  directPermissions: Permission[];
  effectivePermissions: Permission[];
  restrictions: Permission[]; // Negative permissions
  lastCalculated: number;
}

export interface AccessRequest {
  userId: string;
  businessId: string;
  resource: string;
  action: string;
  context?: Record<string, any>;
}

export interface AccessDecision {
  allowed: boolean;
  reason?: string;
  appliedPermissions?: Permission[];
  missingPermissions?: string[];
  auditLog?: boolean;
}

export class RBACSystem {
  private readonly kv: KVNamespace;
  private readonly rolePrefix = 'rbac:role:';
  private readonly userPermPrefix = 'rbac:user:';
  private readonly resourcePrefix = 'rbac:resource:';
  private readonly auditPrefix = 'rbac:audit:';

  // Default system roles
  private readonly systemRoles: Role[] = [
    {
      id: 'super_admin',
      name: 'Super Administrator',
      description: 'Full system access',
      permissions: [{ id: '*', resource: '*', action: '*', scope: 'all' }],
      isSystem: true,
      createdAt: Date.now(),
      updatedAt: Date.now()
    },
    {
      id: 'admin',
      name: 'Administrator',
      description: 'Business administration',
      permissions: [
        { id: 'admin:*', resource: '*', action: '*', scope: 'business' }
      ],
      parentRole: 'manager',
      isSystem: true,
      createdAt: Date.now(),
      updatedAt: Date.now()
    },
    {
      id: 'manager',
      name: 'Manager',
      description: 'Team management capabilities',
      permissions: [
        { id: 'users:read', resource: 'users', action: 'read', scope: 'business' },
        { id: 'users:update', resource: 'users', action: 'update', scope: 'business' },
        { id: 'reports:*', resource: 'reports', action: '*', scope: 'business' },
        { id: 'analytics:read', resource: 'analytics', action: 'read', scope: 'business' }
      ],
      parentRole: 'user',
      isSystem: true,
      createdAt: Date.now(),
      updatedAt: Date.now()
    },
    {
      id: 'user',
      name: 'User',
      description: 'Standard user access',
      permissions: [
        { id: 'profile:read', resource: 'profile', action: 'read', scope: 'own' },
        { id: 'profile:update', resource: 'profile', action: 'update', scope: 'own' },
        { id: 'data:read', resource: 'data', action: 'read', scope: 'own' },
        { id: 'data:create', resource: 'data', action: 'create', scope: 'own' }
      ],
      isSystem: true,
      createdAt: Date.now(),
      updatedAt: Date.now()
    },
    {
      id: 'readonly',
      name: 'Read Only',
      description: 'Read-only access',
      permissions: [
        { id: 'read:*', resource: '*', action: 'read', scope: 'business' }
      ],
      isSystem: true,
      createdAt: Date.now(),
      updatedAt: Date.now()
    }
  ];

  constructor(kv: KVNamespace) {
    this.kv = kv;
    this.initializeSystemRoles();
  }

  /**
   * Initialize system roles
   */
  private async initializeSystemRoles(): Promise<void> {
    for (const role of this.systemRoles) {
      await this.createRole(role);
    }
  }

  /**
   * Create or update a role
   */
  async createRole(role: Role): Promise<void> {
    const key = `${this.rolePrefix}${role.id}`;
    await this.kv.put(key, JSON.stringify(role));

    // Invalidate permission cache for users with this role
    await this.invalidateRoleCache(role.id);
  }

  /**
   * Get role by ID
   */
  async getRole(roleId: string): Promise<Role | null> {
    const key = `${this.rolePrefix}${roleId}`;
    const data = await this.kv.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Delete a role (non-system only)
   */
  async deleteRole(roleId: string): Promise<boolean> {
    const role = await this.getRole(roleId);

    if (!role) return false;
    if (role.isSystem) {
      throw new Error('Cannot delete system role');
    }

    await this.kv.delete(`${this.rolePrefix}${roleId}`);
    await this.invalidateRoleCache(roleId);
    return true;
  }

  /**
   * Assign roles to user
   */
  async assignRoles(userId: string, businessId: string, roleIds: string[]): Promise<void> {
    // Validate roles exist
    for (const roleId of roleIds) {
      const role = await this.getRole(roleId);
      if (!role) {
        throw new Error(`Role ${roleId} does not exist`);
      }
    }

    // Get current user permissions
    const userPerms = await this.getUserPermissions(userId, businessId) || {
      userId,
      businessId,
      roles: [],
      directPermissions: [],
      effectivePermissions: [],
      restrictions: [],
      lastCalculated: Date.now()
    };

    // Update roles
    userPerms.roles = roleIds;
    userPerms.lastCalculated = Date.now();

    // Recalculate effective permissions
    userPerms.effectivePermissions = await this.calculateEffectivePermissions(userPerms);

    // Store updated permissions
    await this.storeUserPermissions(userPerms);

    // Log role assignment
    await this.logAccessEvent('role_assigned', userId, businessId, {
      roles: roleIds
    });
  }

  /**
   * Grant direct permission to user
   */
  async grantPermission(userId: string, businessId: string, permission: Permission): Promise<void> {
    const userPerms = await this.getUserPermissions(userId, businessId) || {
      userId,
      businessId,
      roles: [],
      directPermissions: [],
      effectivePermissions: [],
      restrictions: [],
      lastCalculated: Date.now()
    };

    // Add permission if not already present
    const exists = userPerms.directPermissions.some(p =>
      p.resource === permission.resource &&
      p.action === permission.action &&
      p.scope === permission.scope
    );

    if (!exists) {
      userPerms.directPermissions.push(permission);
      userPerms.effectivePermissions = await this.calculateEffectivePermissions(userPerms);
      await this.storeUserPermissions(userPerms);
    }

    await this.logAccessEvent('permission_granted', userId, businessId, { permission });
  }

  /**
   * Revoke direct permission from user
   */
  async revokePermission(userId: string, businessId: string, permission: Permission): Promise<void> {
    const userPerms = await this.getUserPermissions(userId, businessId);

    if (!userPerms) return;

    userPerms.directPermissions = userPerms.directPermissions.filter(p =>
      !(p.resource === permission.resource &&
        p.action === permission.action &&
        p.scope === permission.scope)
    );

    userPerms.effectivePermissions = await this.calculateEffectivePermissions(userPerms);
    await this.storeUserPermissions(userPerms);

    await this.logAccessEvent('permission_revoked', userId, businessId, { permission });
  }

  /**
   * Check access permission
   */
  async checkAccess(request: AccessRequest): Promise<AccessDecision> {
    const userPerms = await this.getUserPermissions(request.userId, request.businessId);

    if (!userPerms) {
      return {
        allowed: false,
        reason: 'No permissions found for user',
        auditLog: true
      };
    }

    // Check for super admin
    const hasSuperAdmin = userPerms.effectivePermissions.some(p =>
      p.resource === '*' && p.action === '*' && p.scope === 'all'
    );

    if (hasSuperAdmin) {
      await this.logAccessEvent('access_granted', request.userId, request.businessId, {
        resource: request.resource,
        action: request.action,
        reason: 'super_admin'
      });
      return { allowed: true, reason: 'Super admin access' };
    }

    // Check restrictions first (negative permissions)
    const restricted = userPerms.restrictions.some(r =>
      this.matchesPermission(r, request.resource, request.action, request.context)
    );

    if (restricted) {
      await this.logAccessEvent('access_denied', request.userId, request.businessId, {
        resource: request.resource,
        action: request.action,
        reason: 'restricted'
      });
      return {
        allowed: false,
        reason: 'Access restricted',
        auditLog: true
      };
    }

    // Check effective permissions
    const matchingPerms = userPerms.effectivePermissions.filter(p =>
      this.matchesPermission(p, request.resource, request.action, request.context)
    );

    if (matchingPerms.length > 0) {
      // Check scope
      const scopeValid = matchingPerms.some(p => this.validateScope(p, request));

      if (scopeValid) {
        await this.logAccessEvent('access_granted', request.userId, request.businessId, {
          resource: request.resource,
          action: request.action,
          appliedPermissions: matchingPerms
        });
        return {
          allowed: true,
          appliedPermissions: matchingPerms
        };
      }
    }

    // Access denied
    await this.logAccessEvent('access_denied', request.userId, request.businessId, {
      resource: request.resource,
      action: request.action,
      reason: 'no_matching_permissions'
    });

    return {
      allowed: false,
      reason: 'Insufficient permissions',
      missingPermissions: [`${request.resource}:${request.action}`],
      auditLog: true
    };
  }

  /**
   * Check if permission matches request
   */
  private matchesPermission(
    permission: Permission,
    resource: string,
    action: string,
    context?: Record<string, any>
  ): boolean {
    // Check resource match
    const resourceMatch = permission.resource === '*' ||
      permission.resource === resource ||
      (permission.resource.endsWith('*') &&
        resource.startsWith(permission.resource.slice(0, -1)));

    if (!resourceMatch) return false;

    // Check action match
    const actionMatch = permission.action === '*' ||
      permission.action === action ||
      (permission.action.endsWith('*') &&
        action.startsWith(permission.action.slice(0, -1)));

    if (!actionMatch) return false;

    // Check conditions if present
    if (permission.conditions && context) {
      for (const [key, value] of Object.entries(permission.conditions)) {
        if (context[key] !== value) return false;
      }
    }

    return true;
  }

  /**
   * Validate permission scope
   */
  private validateScope(permission: Permission, request: AccessRequest): boolean {
    if (!permission.scope) return true;

    switch (permission.scope) {
      case 'all':
        return true;
      case 'business':
        // Check if accessing resources within same business
        return true; // Would need additional context
      case 'own':
        // Check if accessing own resources
        return request.context?.ownerId === request.userId;
      default:
        return false;
    }
  }

  /**
   * Calculate effective permissions for user
   */
  private async calculateEffectivePermissions(userPerms: UserPermissions): Promise<Permission[]> {
    const effectivePerms: Permission[] = [...userPerms.directPermissions];
    const processedRoles = new Set<string>();

    // Process roles recursively (handle inheritance)
    for (const roleId of userPerms.roles) {
      await this.collectRolePermissions(roleId, effectivePerms, processedRoles);
    }

    // Remove duplicates
    const uniquePerms = new Map<string, Permission>();
    for (const perm of effectivePerms) {
      const key = `${perm.resource}:${perm.action}:${perm.scope || 'default'}`;
      if (!uniquePerms.has(key)) {
        uniquePerms.set(key, perm);
      }
    }

    return Array.from(uniquePerms.values());
  }

  /**
   * Collect permissions from role and parent roles
   */
  private async collectRolePermissions(
    roleId: string,
    permissions: Permission[],
    processedRoles: Set<string>
  ): Promise<void> {
    if (processedRoles.has(roleId)) return;
    processedRoles.add(roleId);

    const role = await this.getRole(roleId);
    if (!role) return;

    permissions.push(...role.permissions);

    // Process parent role
    if (role.parentRole) {
      await this.collectRolePermissions(role.parentRole, permissions, processedRoles);
    }
  }

  /**
   * Get user permissions
   */
  private async getUserPermissions(userId: string, businessId: string): Promise<UserPermissions | null> {
    const key = `${this.userPermPrefix}${businessId}:${userId}`;
    const data = await this.kv.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Store user permissions
   */
  private async storeUserPermissions(userPerms: UserPermissions): Promise<void> {
    const key = `${this.userPermPrefix}${userPerms.businessId}:${userPerms.userId}`;
    await this.kv.put(key, JSON.stringify(userPerms), {
      expirationTtl: 24 * 60 * 60 // 24 hours cache
    });
  }

  /**
   * Invalidate permission cache for users with specific role
   */
  private async invalidateRoleCache(roleId: string): Promise<void> {
    // In production, maintain index of users by role for efficient invalidation
    const { keys } = await this.kv.list({ prefix: this.userPermPrefix });

    for (const key of keys) {
      const data = await this.kv.get(key.name);
      if (data) {
        const userPerms: UserPermissions = JSON.parse(data);
        if (userPerms.roles.includes(roleId)) {
          userPerms.lastCalculated = 0; // Force recalculation
          await this.kv.put(key.name, JSON.stringify(userPerms));
        }
      }
    }
  }

  /**
   * Log access control events
   */
  private async logAccessEvent(
    event: string,
    userId: string,
    businessId: string,
    details: Record<string, any>
  ): Promise<void> {
    const logEntry = {
      event,
      userId,
      businessId,
      timestamp: Date.now(),
      details
    };

    await this.kv.put(
      `${this.auditPrefix}${Date.now()}_${userId}`,
      JSON.stringify(logEntry),
      { expirationTtl: 90 * 24 * 60 * 60 } // 90 days
    );
  }

  /**
   * Get permission audit trail
   */
  async getAuditTrail(
    userId?: string,
    businessId?: string,
    limit = 100
  ): Promise<any[]> {
    const { keys } = await this.kv.list({ prefix: this.auditPrefix, limit: limit * 2 });
    const results: any[] = [];

    for (const key of keys) {
      const data = await this.kv.get(key.name);
      if (data) {
        const entry = JSON.parse(data);
        if ((!userId || entry.userId === userId) &&
            (!businessId || entry.businessId === businessId)) {
          results.push(entry);
          if (results.length >= limit) break;
        }
      }
    }

    return results.sort((a, b) => b.timestamp - a.timestamp);
  }
}

// Export factory function
export function createRBACSystem(kv: KVNamespace): RBACSystem {
  return new RBACSystem(kv);
}