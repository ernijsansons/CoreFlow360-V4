/**
 * ABAC Permission Engine
 * Unified interface for permission checking and policy evaluation
 * Re-exports and combines PermissionResolver and PolicyEvaluator functionality
 */

import { PermissionResolver } from './permission-resolver';
import { PolicyEvaluator } from './policy-evaluator';
import { ABACCache } from './cache';
import type {
  Subject,
  Resource,
  Action,
  Capability,
  EvaluationResult,
  PolicyRule,
  PermissionBundle,
} from './types';

/**
 * Main ABAC Permission Engine
 * Provides unified interface for all permission checking operations
 */
export class ABACPermissionEngine {
  private resolver: PermissionResolver;
  private evaluator: PolicyEvaluator;
  private cache: ABACCache;

  constructor(policies: PolicyRule[] = [], ttl: number = 300) {
    this.cache = new ABACCache({ defaultTTL: ttl * 1000 }); // Convert seconds to milliseconds
    this.evaluator = new PolicyEvaluator(policies);
    this.resolver = new PermissionResolver(this.cache, this.evaluator);
  }

  /**
   * Check if subject has permission for capability on resource
   */
  async checkPermission(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<EvaluationResult> {
    return this.resolver.checkPermission(subject, capability, resource);
  }

  /**
   * Check multiple permissions at once
   */
  async checkPermissions(
    subject: Subject,
    capabilities: Capability[],
    resource?: Resource
  ): Promise<Map<Capability, EvaluationResult>> {
    const results = new Map<Capability, EvaluationResult>();

    await Promise.all(
      capabilities.map(async (capability) => {
        const result = await this.checkPermission(subject, capability, resource);
        results.set(capability, result);
      })
    );

    return results;
  }

  /**
   * Get permission bundle for subject (for caching)
   */
  async getPermissionBundle(
    subject: Subject,
    context?: Record<string, unknown>
  ): Promise<PermissionBundle> {
    // Get all capabilities for this subject's roles by evaluating all known capabilities
    // This is a placeholder - in production, you'd query all capabilities from a registry
    const capabilities = new Set<Capability>();

    const now = Date.now();
    return {
      userId: subject.userId,
      businessId: subject.businessId,
      capabilities,
      constraints: new Map(),
      evaluatedAt: now,
      expiresAt: now + 300000, // 5 minutes
      version: 1,
    };
  }

  /**
   * Load or update policies
   */
  loadPolicies(policies: PolicyRule[]): void {
    // Clear existing policies and reload
    this.evaluator = new PolicyEvaluator(policies);
    this.resolver = new PermissionResolver(this.cache, this.evaluator);
  }

  /**
   * Clear permission cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return this.cache.getStats();
  }
}

// Re-export for backward compatibility
export { PermissionResolver, PolicyEvaluator, ABACCache };
export type {
  Subject,
  Resource,
  Action,
  Capability,
  EvaluationResult,
  PolicyRule,
  PermissionBundle,
} from './types';
