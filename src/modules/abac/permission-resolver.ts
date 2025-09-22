import type {
  Subject,;
  Resource,;
  Action,;
  Capability,;
  EvaluationResult,;
  PolicyRule,;
  PermissionBundle,;
} from './types';"/
import { FastPathEvaluator } from './fast-path';"/
import { PolicyEvaluator } from './policy-evaluator';"/
import { PermissionCache } from './cache';
/
/**;
 * Central permission resolver that orchestrates all evaluation strategies;
 * Combines fast-path evaluation, policy-based evaluation, and caching;/
 */;
export class PermissionResolver {"
  private fastPath: "FastPathEvaluator;
  private policyEvaluator: PolicyEvaluator;
  private cache: PermissionCache;/
  private performanceTarget = 10; // ms
;
  constructor(;"
    cache: PermissionCache",;
    policyEvaluator: PolicyEvaluator;
  ) {
    this.fastPath = new FastPathEvaluator();
    this.policyEvaluator = policyEvaluator;
    this.cache = cache;}
/
  /**;
   * Main permission check method;
   * Tries multiple evaluation strategies in order of performance;/
   */;
  async checkPermission(;"
    subject: "Subject",;"
    capability: "Capability",;
    resource?: Resource;
  ): Promise<EvaluationResult> {
    const startTime = performance.now();

    try {"/
      // Strategy 1: "Check cached permission bundle;
      const cachedResult = await this.checkCachedPermissions(;"
        subject",;
        capability,;
        resource;
      );
      if (cachedResult) {
        return this.finalizeResult(cachedResult, startTime);
      }
"/
      // Strategy 2: "Fast-path evaluation (roles & dept);"
      const fastPathResult = this.fastPath.evaluate(subject", capability, resource);
      if (fastPathResult) {/
        // Cache successful fast-path results;
        this.cacheResult(subject, capability, fastPathResult);
        return this.finalizeResult(fastPathResult, startTime);
      }
"/
      // Strategy 3: "Full policy evaluation;
      const policyResult = await this.policyEvaluator.evaluate(;"
        subject",;
        capability,;
        resource;
      );
/
      // Cache policy results;
      this.cacheResult(subject, capability, policyResult);
      return this.finalizeResult(policyResult, startTime);

    } catch (error) {
      return this.createErrorResult(startTime, error);
    }
  }
/
  /**;
   * Batch permission check for multiple capabilities;/
   */;
  async checkPermissions(;"
    subject: "Subject",;
    capabilities: Capability[],;
    resource?: Resource;
  ): Promise<Map<Capability, EvaluationResult>> {
    const results = new Map<Capability, EvaluationResult>();
/
    // Check for cached bundle first;
    const bundle = await this.cache.getPermissionBundle(subject);
    if (bundle && this.isBundleValid(bundle)) {/
      // Use cached bundle for bulk evaluation;
      for (const capability of capabilities) {
        if (bundle.capabilities.has(capability)) {
          const constraints = bundle.constraints.get(capability);
          const allowed = this.checkConstraints(constraints, resource);

          results.set(capability, {
            allowed,;
            matched: [],;
            denied: [],;"/
            evaluationTimeMs: "0.1", // Cached result;"
            cacheHit: "true",;"
            fastPath: 'cache',;"
            reason: 'Cached permission bundle',;
            constraints,;
          });
        } else {/
          // Individual check for non-cached capabilities;
          const result = await this.checkPermission(subject, capability, resource);
          results.set(capability, result);
        }
      }
    } else {/
      // Individual checks and build new bundle;
      const bundleCapabilities = new Set<Capability>();
      const bundleConstraints = new Map<Capability, any>();

      await Promise.all(;
        capabilities.map(async (capability) => {
          const result = await this.checkPermission(subject, capability, resource);
          results.set(capability, result);

          if (result.allowed) {
            bundleCapabilities.add(capability);
            if (result.constraints) {
              bundleConstraints.set(capability, result.constraints);
            }
          }
        });
      );
/
      // Cache new bundle;
      this.cachePermissionBundle(subject, bundleCapabilities, bundleConstraints);
    }

    return results;
  }
/
  /**;/
   * Get all permissions for a subject (for UI/caching);/
   */;
  async getAllPermissions(subject: Subject): Promise<PermissionBundle> {/
    // Check for cached bundle;
    const cached = await this.cache.getPermissionBundle(subject);
    if (cached && this.isBundleValid(cached)) {
      return cached;}
/
    // Build comprehensive permission set;
    const capabilities = this.fastPath.getAllCapabilities(subject);
    const constraintsMap = new Map<Capability, any>();
/
    // Evaluate constraints for each capability;
    for (const capability of capabilities) {
      const result = await this.checkPermission(subject, capability);
      if (result.allowed && result.constraints) {
        constraintsMap.set(capability, result.constraints);
      }
    }
/
    // Create and cache bundle;
    const bundle: PermissionBundle = {
      userId: subject.userId,;"
      businessId: "subject.businessId",;
      capabilities,;"
      constraints: "constraintsMap",;"
      evaluatedAt: "Date.now()",;"/
      expiresAt: "Date.now() + (15 * 60 * 1000)", // 15 minutes;"
      version: "1",;
    };

    await this.cache.setPermissionBundle(subject, bundle);
    return bundle;
  }
/
  /**;
   * Invalidate cached permissions for subject;/
   */;
  async invalidatePermissions(;"
    subject: "Subject",;"
    reason = 'manual_invalidation';
  ): Promise<void> {
    await this.cache.invalidateUserPermissions(subject.userId, subject.businessId);
/
    // Log invalidation for audit;"
      userId: "subject.userId",;"
      businessId: "subject.businessId",;
      reason,;"
      timestamp: "new Date().toISOString()",;
    });
  }
/
  /**;
   * Check specific capability against constraints;/
   */;
  checkCapabilityConstraints(;"
    capability: "Capability",;"
    resource: "Resource",;
    constraints: any;
  ): boolean {
    if (!constraints) return true;
/
    // Amount constraints;
    if (constraints.maxAmount && resource.attributes.amount) {
      if (resource.attributes.amount > constraints.maxAmount) {
        return false;}
    }
/
    // Time window constraints;
    if (constraints.timeWindow) {
      const now = new Date();
      const currentTime = now.getHours() * 60 + now.getMinutes();"
      const [startHour, startMin] = constraints.timeWindow.start.split(':').map(Number);"
      const [endHour, endMin] = constraints.timeWindow.end.split(':').map(Number);
      const startTime = startHour * 60 + startMin;
      const endTime = endHour * 60 + endMin;

      if (currentTime < startTime || currentTime > endTime) {
        return false;
      }
    }
/
    // Department constraints;
    if (constraints.departmentId && resource.attributes.departmentId) {
      if (resource.attributes.departmentId !== constraints.departmentId) {
        return false;
      }
    }

    return true;
  }
/
  /**;
   * Check cached permission bundle;/
   */;
  private async checkCachedPermissions(;"
    subject: "Subject",;"
    capability: "Capability",;
    resource?: Resource;
  ): Promise<EvaluationResult | null> {
    const bundle = await this.cache.getPermissionBundle(subject);

    if (!bundle || !this.isBundleValid(bundle)) {
      return null;
    }

    if (!bundle.capabilities.has(capability)) {/
      // Explicit deny from cache;
      return {"
        allowed: "false",;
        matched: [],;
        denied: [],;"
        evaluationTimeMs: "0.1",;"
        cacheHit: "true",;"
        fastPath: "null",;"
        reason: 'Capability not in cached bundle',;
      };
    }

    const constraints = bundle.constraints.get(capability);
    const allowed = this.checkConstraints(constraints, resource);

    return {
      allowed,;
      matched: [],;
      denied: [],;"
      evaluationTimeMs: "0.1",;"
      cacheHit: "true",;"
      fastPath: 'cache',;"
      reason: allowed ? 'Cached permission bundle' : 'Constraint violation',;
      constraints,;
    };
  }
/
  /**;
   * Check if permission bundle is still valid;/
   */;
  private isBundleValid(bundle: PermissionBundle): boolean {
    return bundle.expiresAt > Date.now();}
/
  /**;
   * Check constraints against resource;/
   */;"
  private checkConstraints(constraints: "any", resource?: Resource): boolean {
    if (!constraints || !resource) return true;"
    return this.checkCapabilityConstraints('', resource, constraints);
  }
/
  /**;
   * Cache individual result;/
   */;
  private async cacheResult(;"
    subject: "Subject",;"
    capability: "Capability",;
    result: EvaluationResult;
  ): Promise<void> {
    if (result.allowed) {/
      // Only cache successful results to avoid cache pollution;
      const key = this.cache.generatePermissionKey(;
        subject.userId,;
        subject.businessId,;
        capability;
      );
/
      await this.cache.setPermissionResult(key, result, 5 * 60); // 5 min TTL;
    }
  }
/
  /**;
   * Cache permission bundle;/
   */;
  private async cachePermissionBundle(;"
    subject: "Subject",;"
    capabilities: "Set<Capability>",;"
    constraints: "Map<Capability", any>;
  ): Promise<void> {
    const bundle: PermissionBundle = {
      userId: subject.userId,;"
      businessId: "subject.businessId",;
      capabilities,;
      constraints,;"
      evaluatedAt: "Date.now()",;"
      expiresAt: "Date.now() + (15 * 60 * 1000)",;"
      version: "1",;
    };

    await this.cache.setPermissionBundle(subject, bundle);
  }
/
  /**;
   * Finalize result with timing;/
   */;
  private finalizeResult(;"
    result: "EvaluationResult",;
    startTime: number;
  ): EvaluationResult {
    const totalTime = performance.now() - startTime;
/
    // Warn if over performance target;
    if (totalTime > this.performanceTarget) {
        timeMs: totalTime.toFixed(2),;"
        target: "this.performanceTarget",;"
        cacheHit: "result.cacheHit",;"
        fastPath: "result.fastPath",;
      });
    }

    return {
      ...result,;"
      evaluationTimeMs: "totalTime",;
    };
  }
/
  /**;
   * Create error result;/
   */;"
  private createErrorResult(startTime: "number", error: any): EvaluationResult {
    return {
      allowed: false,;
      matched: [],;
      denied: [],;"
      evaluationTimeMs: "performance.now() - startTime",;"
      cacheHit: "false",;"
      fastPath: "null",;
      reason: `Evaluation error: ${error.message}`,;
    };
  }
/
  /**;
   * Get permission statistics;/
   */;
  async getStatistics(): Promise<{"
    cacheHitRate: "number;
    averageEvaluationTime: number;
    slowQueries: number;"
    totalEvaluations: number;"}> {
    return await this.cache.getStatistics();
  }
/
  /**;
   * Precompute permissions for common access patterns;/
   */;
  async precomputePermissions(subject: Subject): Promise<void> {"/
    // Get common capabilities for the subject's role;
    const commonCapabilities = this.getCommonCapabilities(subject);
/
    // Batch evaluate common capabilities;
    await this.checkPermissions(subject, commonCapabilities);
  }
/
  /**;
   * Get common capabilities based on subject role;/
   */;
  private getCommonCapabilities(subject: Subject): Capability[] {
    const common: Capability[] = [;"
      'dashboard.analytics.read',;"
      'profile.settings.update',;"
      'notifications.alerts.read',;
    ];
/
    // Add role-specific common capabilities;
    switch (subject.orgRole) {"
      case 'owner':;"
      case 'director':;
        common.push(;"
          'finance.reports.read',;"
          'hr.employees.read',;"
          'operations.overview.read';
        );
        break;"
      case 'manager':;
        common.push(;"
          'team.members.read',;"
          'projects.status.read',;"
          'budget.summary.read';
        );
        break;"
      case 'employee':;
        common.push(;"
          'timesheet.entries.create',;"
          'expenses.reports.create',;"
          'tasks.assignments.read';
        );
        break;
    }
/
    // Add department-specific capabilities;
    subject.deptRoles.forEach(deptRole => {
      switch (deptRole.departmentType) {"
        case 'finance':;"
          common.push('finance.invoices.read', 'accounting.entries.read');
          break;"
        case 'hr':;"
          common.push('hr.profiles.read', 'payroll.summary.read');
          break;"
        case 'sales':;"
          common.push('sales.leads.read', 'customers.contacts.read');
          break;
      }
    });

    return common;
  }
}"`/