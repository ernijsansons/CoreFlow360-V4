/**
 * ABAC (Attribute-Based Access Control) Module Entry Point
 *
 * Provides comprehensive permission management with:
 * - <10ms evaluation time through fast-path optimization
 * - Multi-layer caching with KV storage
 * - Policy-based evaluation for complex rules
 * - Performance monitoring and health checks
 * - Subject/Resource/Capability model
 */

export { ABACService } from './service';
export { PermissionResolver } from './permission-resolver';
export { FastPathEvaluator } from './fast-path';
export { PolicyEvaluator } from './policy-evaluator';
export { PermissionCache } from './cache';
export { PerformanceMonitor } from './performance-monitor';
export { capabilityRegistry, CapabilityRegistry } from './capability-registry';
export { ABACPermissionEngine, PermissionEngine } from './permission-engine';

export type {
  Subject,
  Resource,
  Action,
  Capability,
  OrgRole,
  DepartmentRole,
  DepartmentType,
  PolicyRule,
  EvaluationResult,
  PermissionBundle,
  CapabilityDefinition,
  SubjectCondition,
  ResourceCondition,
  ContextCondition,
} from './types';

export {
  ROLE_HIERARCHY,
  DEFAULT_CAPABILITIES,
  DEPARTMENT_CAPABILITIES,
  CapabilitySchema,
  PolicyRuleSchema,
  CheckPermissionRequestSchema,
} from './types';

/**
 * Create a new ABAC service instance
 */
export function createABACService(
  kv: any, // KVNamespace from @cloudflare/workers-types
  policies: any[] = []
): ABACService {
  return new ABACService(kv, policies);
}

/**
 * Utility functions for common ABAC operations
 */
export const ABACUtils = {
  /**
   * Create a subject from user data
   */
  createSubject(userData: {
    userId: string;
    businessId: string;
    orgRole: string;
    deptRoles?: any[];
    attributes?: any;
    context?: any;
  }): Subject {
    return {
      userId: userData.userId,
      businessId: userData.businessId,
      orgRole: userData.orgRole as OrgRole,
      deptRoles: userData.deptRoles || [],
      attributes: {
        email: '',
        canApproveTransactions: false,
        spendingLimit: 0,
        joinedAt: new Date().toISOString(),
        isVerified: true,
        mfaEnabled: false,
        ...userData.attributes,
      },
      context: {
        ipAddress: '127.0.0.1',
        userAgent: 'unknown',
        sessionId: 'session_' + Date.now(),
        requestTime: Date.now(),
        ...userData.context,
      },
    };
  },

  /**
   * Create a resource from resource data
   */
  createResource(resourceData: {
    type: string;
    id?: string;
    businessId: string;
    attributes?: any;
  }): Resource {
    return {
      type: resourceData.type,
      id: resourceData.id,
      businessId: resourceData.businessId,
      attributes: resourceData.attributes || {},
    };
  },

  /**
   * Validate capability format
   */
  isValidCapability(capability: string): boolean {
    return CapabilityRegistry.isValidCapability(capability);
  },

  /**
   * Parse capability string
   */
  parseCapability(capability: string) {
    return CapabilityRegistry.parseCapability(capability);
  },

  /**
   * Generate default policies for a business
   */
  generateDefaultPolicies(businessId: string): PolicyRule[] {
    return [
      {
        id: `${businessId}_owner_all`,
        name: 'Business Owner - Full Access',
        description: 'Business owners have full access to all resources',
        priority: 1,
        conditions: {
          subject: {
            orgRole: 'owner',
          },
        },
        effect: 'allow' as const,
        capabilities: ['*.*.*'],
      },
      {
        id: `${businessId}_mfa_required`,
        name: 'MFA Required for Critical Operations',
        description: 'Multi-factor authentication required for high-risk operations',
        priority: 10,
        conditions: {
          subject: {
            attributes: {
              mfaEnabled: { operator: 'eq', value: false },
            },
          },
        },
        effect: 'deny' as const,
        capabilities: [
          'finance.*.delete',
          'hr.payroll.approve',
          'system.settings.update',
          'system.users.delete',
        ],
        constraints: {
          requireMFA: true,
        },
      },
      {
        id: `${businessId}_business_isolation`,
        name: 'Business Isolation',
        description: 'Users can only access resources in their business',
        priority: 5,
        conditions: {
          resource: {
            attributes: {
              businessId: { operator: 'ne', value: businessId },
            },
          },
        },
        effect: 'deny' as const,
        capabilities: ['*.*.*'],
      },
    ];
  },

  /**
   * Common capability patterns
   */
  CommonCapabilities: {
    DASHBOARD_READ: 'dashboard.analytics.read' as Capability,
    PROFILE_UPDATE: 'profile.settings.update' as Capability,
    NOTIFICATIONS_READ: 'notifications.alerts.read' as Capability,

    // Finance
    INVOICE_CREATE: 'finance.invoice.create' as Capability,
    INVOICE_READ: 'finance.invoice.read' as Capability,
    INVOICE_UPDATE: 'finance.invoice.update' as Capability,
    INVOICE_DELETE: 'finance.invoice.delete' as Capability,
    INVOICE_APPROVE: 'finance.invoice.approve' as Capability,

    // HR
    EMPLOYEE_CREATE: 'hr.employee.create' as Capability,
    EMPLOYEE_READ: 'hr.employee.read' as Capability,
    EMPLOYEE_UPDATE: 'hr.employee.update' as Capability,
    PAYROLL_APPROVE: 'hr.payroll.approve' as Capability,

    // System
    SETTINGS_UPDATE: 'system.settings.update' as Capability,
    USERS_DELETE: 'system.users.delete' as Capability,

    // Reports
    FINANCIAL_EXPORT: 'reports.financial.export' as Capability,
    ANALYTICS_READ: 'reports.analytics.read' as Capability,
  },

  /**
   * Performance targets and thresholds
   */
  PerformanceTargets: {
    EVALUATION_TIME_MS: 10,
    CACHE_HIT_RATE_PERCENT: 80,
    SLOW_QUERY_THRESHOLD_MS: 25,
    ERROR_RATE_THRESHOLD_PERCENT: 1,
  },
};