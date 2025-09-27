import type {
  Subject,
  Resource,
  Action,
  Capability,
  OrgRole,
  DepartmentRole,
  EvaluationResult,
} from './types';
import { ROLE_HIERARCHY, DEFAULT_CAPABILITIES, DEPARTMENT_CAPABILITIES } from './types';
import { capabilityRegistry } from './capability-registry';

/**
 * Fast-path permission evaluator
 * Optimized for <10ms evaluation time
 */
export class FastPathEvaluator {
  /**
   * Fast evaluation path with short-circuits
   */
  evaluate(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): EvaluationResult | null {
    const startTime = performance.now();

    // Fast path 1: Owner always allowed (except for some critical operations)
    if (subject.orgRole === 'owner') {
      return this.createResult(true, 'owner', performance.now() - startTime);
    }

    // Fast path 2: Check department head permissions
    const deptResult = this.evaluateDepartmentRoles(subject, capability, resource);
    if (deptResult !== null) {
      return this.createResult(
        deptResult,
        'dept',
        performance.now() - startTime
      );
    }

    // Fast path 3: Check org role permissions
    const orgResult = this.evaluateOrgRole(subject, capability, resource);
    if (orgResult !== null) {
      return this.createResult(
        orgResult,
        'org',
        performance.now() - startTime
      );
    }

    // No fast path matched
    return null;
  }

  /**
   * Evaluate based on department roles
   */
  private evaluateDepartmentRoles(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): boolean | null {
    // Parse capability
    const parsed = capabilityRegistry.parseCapability(capability);
    if (!parsed) return null;

    // Check each department role
    for (const deptRole of subject.deptRoles) {
      // Department head has full access to their department
      if (deptRole.role === 'head') {
        const deptCapabilities = DEPARTMENT_CAPABILITIES[deptRole.departmentType];
        if (deptCapabilities) {
          // Check if capability matches department patterns
          for (const pattern of deptCapabilities) {
            if (this.matchCapability(capability, pattern)) {
              // Additional check: resource belongs to department
              if (resource && resource.attributes.departmentId) {
                if (resource.attributes.departmentId === deptRole.departmentId) {
                  return true;
                }
              } else {
                return true;
              }
            }
          }
        }
      }

      // Department manager has limited access
      if (deptRole.role === 'manager' || deptRole.role === 'supervisor') {
        // Check specific permissions assigned to the role
        if (deptRole.permissions?.includes(capability)) {
          // Verify department context
          if (resource && resource.attributes.departmentId) {
            if (resource.attributes.departmentId === deptRole.departmentId) {
              return true;
            }
          } else {
            return true;
          }
        }
      }
    }

    return null;
  }

  /**
   * Evaluate based on org role
   */
  private evaluateOrgRole(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): boolean | null {
    const roleCapabilities = DEFAULT_CAPABILITIES[subject.orgRole];
    if (!roleCapabilities) return null;

    // Check each capability pattern
    for (const pattern of roleCapabilities) {
      if (this.matchCapability(capability, pattern)) {
        // Additional checks based on role
        return this.applyRoleConstraints(subject, capability, resource);
      }
    }

    return null;
  }

  /**
   * Apply role-specific constraints
   */
  private applyRoleConstraints(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): boolean {
    // Get capability definition
    const capDef = capabilityRegistry.get(capability);

    // Check MFA requirement
    if (capDef?.requiresMFA && !subject.attributes.mfaEnabled) {
      return false;
    }

    // Role-specific constraints
    switch (subject.orgRole) {
      case 'director':
        // Directors can't delete system resources
        if (capability.startsWith('system.') && capability.endsWith('.delete')) {
          return false;
        }
        break;

      case 'manager':
        // Managers have spending limits
        if (resource?.attributes.amount) {
          if (resource.attributes.amount > subject.attributes.spendingLimit) {
            return false;
          }
        }
        // Managers can only manage their own department
        if (resource?.attributes.departmentId) {
          if (resource.attributes.departmentId !== subject.attributes.department) {
            return false;
          }
        }
        break;

      case 'employee':
        // Employees can only modify their own resources
        if (capability.includes('.update') || capability.includes('.delete')) {
          if (resource?.attributes.ownerId !== subject.userId) {
            return false;
          }
        }
        break;

      case 'viewer':
        // Viewers can only read
        if (!capability.endsWith('.read')) {
          return false;
        }
        break;
    }

    return true;
  }

  /**
   * Match capability against pattern (supports wildcards)
   */
  private matchCapability(capability: Capability, pattern: string): boolean {
    if (pattern === '*.*.*') return true;

    const capParts = capability.split('.');
    const patParts = pattern.split('.');

    if (capParts.length !== 3 || patParts.length !== 3) {
      return false;
    }

    for (let i = 0; i < 3; i++) {
      if (patParts[i] !== '*' && patParts[i] !== capParts[i]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Create evaluation result
   */
  private createResult(
    allowed: boolean,
    fastPath: 'owner' | 'dept' | 'org',
    evaluationTimeMs: number
  ): EvaluationResult {
    return {
      allowed,
      matched: [],
      denied: [],
      evaluationTimeMs,
      cacheHit: false,
      fastPath,
      reason: `Fast path: ${fastPath} role evaluation`,
    };
  }

  /**
   * Check if subject has higher role than target
   */
  canManageUser(subject: Subject, targetOrgRole: OrgRole): boolean {
    const subjectLevel = ROLE_HIERARCHY[subject.orgRole];
    const targetLevel = ROLE_HIERARCHY[targetOrgRole];

    return subjectLevel > targetLevel;
  }

  /**
   * Check if subject can access business
   */
  canAccessBusiness(subject: Subject, businessId: string): boolean {
    return subject.businessId === businessId;
  }

  /**
   * Get all capabilities for subject (for caching)
   */
  getAllCapabilities(subject: Subject): Set<Capability> {
    const capabilities = new Set<Capability>();

    // Add org role capabilities
    const orgCaps = DEFAULT_CAPABILITIES[subject.orgRole] || [];
    orgCaps.forEach((cap: any) => {
      if (cap === '*.*.*') {
        // Add all registered capabilities
        capabilityRegistry.exportAll().forEach((def: any) => {
          capabilities.add(def.capability);
        });
      } else {
        // Expand wildcard patterns
        const expanded = this.expandWildcardPattern(cap);
        expanded.forEach((c: any) => capabilities.add(c));
      }
    });

    // Add department capabilities
    subject.deptRoles.forEach((deptRole: any) => {
      const deptCaps = DEPARTMENT_CAPABILITIES[deptRole.departmentType as keyof typeof DEPARTMENT_CAPABILITIES] || [];
      deptCaps.forEach((cap: any) => {
        const expanded = this.expandWildcardPattern(cap);
        expanded.forEach((c: any) => capabilities.add(c));
      });

      // Add specific permissions
      deptRole.permissions?.forEach((p: any) => capabilities.add(p));
    });

    return capabilities;
  }

  /**
   * Expand wildcard pattern to actual capabilities
   */
  private expandWildcardPattern(pattern: string): Capability[] {
    if (!pattern.includes('*')) {
      return [pattern];
    }

    return capabilityRegistry.matchPattern(pattern);
  }

  /**
   * Optimize subject for fast evaluation (precompute)
   */
  optimizeSubject(subject: Subject): {
    isOwner: boolean;
    isDepartmentHead: boolean;
    hasManagerRole: boolean;
    capabilities: Set<Capability>;
    departments: Set<string>;
  } {
    return {
      isOwner: subject.orgRole === 'owner',
      isDepartmentHead: subject.deptRoles.some(r => r.role === 'head'),
      hasManagerRole:
        subject.orgRole === 'manager' ||
        subject.deptRoles.some(r =>
          ['manager', 'supervisor'].includes(r.role)
        ),
      capabilities: this.getAllCapabilities(subject),
      departments: new Set(subject.deptRoles.map((r: any) => r.departmentId)),
    };
  }
}