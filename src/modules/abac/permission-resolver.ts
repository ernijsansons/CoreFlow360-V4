import type {
  Subject,
  Resource,
  Action,
  Capability,
  EvaluationResult,
  PolicyRule,
  PermissionBundle,
} from './types';
import { FastPathEvaluator } from './fast-path';
import { PolicyEvaluator } from './policy-evaluator';
import { ABACCache } from './cache';

/**
 * Central permission resolver that orchestrates all evaluation strategies
 * Combines fast-path evaluation, policy-based evaluation, and caching
 */
export class PermissionResolver {
  private fastPath: FastPathEvaluator;
  private policyEvaluator: PolicyEvaluator;
  private cache: ABACCache;
  private performanceTarget = 10; // ms

  constructor(
    cache: ABACCache,
    policyEvaluator: PolicyEvaluator
  ) {
    this.fastPath = new FastPathEvaluator();
    this.policyEvaluator = policyEvaluator;
    this.cache = cache;
  }

  /**
   * Main permission check method
   * Tries multiple evaluation strategies in order of performance
   */
  async checkPermission(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<EvaluationResult> {
    const startTime = performance.now();

    try {
      // Strategy 1: Check cached permission bundle
      const cachedResult = await this.checkCachedPermissions(
        subject,
        capability,
        resource
      );
      if (cachedResult) {
        return this.createResult(cachedResult, startTime, 'cache');
      }

      // Strategy 2: Fast-path evaluation for common patterns
      const fastPathResult = await this.fastPath.evaluate(
        subject,
        capability,
        resource
      );
      if (fastPathResult) {
        await this.cacheResult(subject, capability, resource, fastPathResult as any);
        return this.createResult(fastPathResult as any, startTime, 'fast-path');
      }

      // Strategy 3: Full policy evaluation
      const policyResult = await this.policyEvaluator.evaluate(
        subject,
        capability,
        resource
      );
      
        await this.cacheResult(subject, capability, resource, policyResult as any);
      return this.createResult(policyResult as any, startTime, 'policy');

    } catch (error) {
      return this.createErrorResult(error, startTime);
    }
  }

  /**
   * Check if permission is granted for multiple capabilities at once
   */
  async checkMultiplePermissions(
    subject: Subject,
    capabilities: Capability[],
    resource?: Resource
  ): Promise<Map<Capability, EvaluationResult>> {
    const results = new Map<Capability, EvaluationResult>();
    
    // Try to get all from cache first
    const cachedBundle = await (this.cache as any).getBundle((subject as any).id);
    if (cachedBundle) {
      for (const capability of capabilities) {
        const cachedResult = this.checkCachedBundle(cachedBundle, capability, resource);
        if (cachedResult) {
          results.set(capability, this.createResult(cachedResult, performance.now(), 'cache'));
        }
      }
    }

    // Check remaining capabilities individually
    const remainingCapabilities = capabilities.filter(cap => !results.has(cap));
    for (const capability of remainingCapabilities) {
      const result = await this.checkPermission(subject, capability, resource);
      results.set(capability, result);
    }

    return results;
  }

  /**
   * Get all permissions for a subject
   */
  async getAllPermissions(subject: Subject): Promise<PermissionBundle> {
    const cachedBundle = await (this.cache as any).getBundle((subject as any).id);
    if (cachedBundle) {
      return cachedBundle;
    }

    // Generate fresh bundle
    const bundle = await (this.policyEvaluator as any).generateBundle(subject);
    await (this.cache as any).setBundle((subject as any).id, bundle);
    
    return bundle;
  }

  /**
   * Check if subject has any of the specified capabilities
   */
  async hasAnyPermission(
    subject: Subject,
    capabilities: Capability[],
    resource?: Resource
  ): Promise<boolean> {
    for (const capability of capabilities) {
      const result = await this.checkPermission(subject, capability, resource);
      if ((result as any).granted) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if subject has all of the specified capabilities
   */
  async hasAllPermissions(
    subject: Subject,
    capabilities: Capability[],
    resource?: Resource
  ): Promise<boolean> {
    for (const capability of capabilities) {
      const result = await this.checkPermission(subject, capability, resource);
      if (!(result as any).granted) {
        return false;
      }
    }
    return true;
  }

  /**
   * Invalidate cached permissions for a subject
   */
  async invalidateSubject(subjectId: string): Promise<void> {
    await (this.cache as any).invalidate(subjectId);
  }

  /**
   * Invalidate all cached permissions
   */
  async invalidateAll(): Promise<void> {
    await (this.cache as any).clear();
  }

  /**
   * Get performance metrics
   */
  getPerformanceMetrics(): {
    averageResponseTime: number;
    cacheHitRate: number;
    fastPathHitRate: number;
    policyEvaluationRate: number;
  } {
    return {
      averageResponseTime: (this.fastPath as any).getAverageResponseTime(),
      cacheHitRate: (this.cache as any).getHitRate(),
      fastPathHitRate: (this.fastPath as any).getHitRate(),
      policyEvaluationRate: (this.policyEvaluator as any).getEvaluationRate()
    };
  }

  private async checkCachedPermissions(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<boolean | null> {
    const bundle = await (this.cache as any).getBundle((subject as any).id);
    if (!bundle) {
      return null;
    }

    return this.checkCachedBundle(bundle, capability, resource);
  }

  private checkCachedBundle(
    bundle: PermissionBundle,
    capability: Capability,
    resource?: Resource
  ): boolean | null {
    // Check direct capability match
    if (bundle.capabilities.has(capability)) {
      return true;
    }

    // Check resource-specific permissions
    if (resource && (bundle as any).resourcePermissions) {
      const resourcePerms = (bundle as any).resourcePermissions.get((resource as any).id);
      if (resourcePerms?.has(capability)) {
        return true;
      }
    }

    // Check role-based permissions
    for (const role of (bundle as any).roles) {
      if (role.capabilities.has(capability)) {
        return true;
      }
    }

    return false;
  }

  private async cacheResult(
    subject: Subject,
    capability: Capability,
    resource: Resource | undefined,
    granted: boolean
  ): Promise<void> {
    // Update bundle in cache
    const bundle = await (this.cache as any).getBundle((subject as any).id);
    if (bundle) {
      bundle.capabilities.add(capability);
      if (resource && (bundle as any).resourcePermissions) {
        const resourcePerms = bundle.resourcePermissions.get(resource.id) || new Set();
        resourcePerms.add(capability);
        bundle.resourcePermissions.set(resource.id, resourcePerms);
      }
      await (this.cache as any).setBundle((subject as any).id, bundle);
    }
  }

  private createResult(
    granted: boolean,
    startTime: number,
    strategy: string
  ): EvaluationResult {
    const duration = performance.now() - startTime;
    
    return {
      allowed: false,
      matched: false,
      denied: true,
      evaluationTimeMs: duration,
      strategy: strategy,
      timestamp: new Date()
    } as any;
  }

  private createErrorResult(error: unknown, startTime: number): EvaluationResult {
    const duration = performance.now() - startTime;
    
    return {
      allowed: false,
      matched: false,
      denied: true,
      evaluationTimeMs: duration,
      strategy: 'error',
      timestamp: new Date(),
      error: error instanceof Error ? error.message : 'Unknown error'
    } as any;
  }
}

