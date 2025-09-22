import type { KVNamespace } from '@cloudflare/workers-types';
import type {
  Subject,
  Resource,
  Capability,
  EvaluationResult,
  PolicyRule,
  PermissionBundle,
} from './types';
import { PermissionResolver } from './permission-resolver';
import { PolicyEvaluator } from './policy-evaluator';
import { PermissionCache } from './cache';
import { PerformanceMonitor } from './performance-monitor';

/**
 * Main ABAC service that orchestrates all components
 * Provides the primary interface for permission checks
 */
export // TODO: Consider splitting ABACService into smaller, focused classes
class ABACService {
  private resolver: PermissionResolver;
  private cache: PermissionCache;
  private monitor: PerformanceMonitor;
  private policyEvaluator: PolicyEvaluator;

  constructor(
    kv: KVNamespace,
    policies: PolicyRule[] = []
  ) {
    this.cache = new PermissionCache(kv);
    this.monitor = new PerformanceMonitor(kv);
    this.policyEvaluator = new PolicyEvaluator(policies);
    this.resolver = new PermissionResolver(this.cache, this.policyEvaluator);
  }

  /**
   * Main permission check interface
   */
  async checkPermission(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<EvaluationResult> {
    const startTime = performance.now();

    try {
      const result = await this.resolver.checkPermission(subject, capability, resource);

      // Record performance metrics
      this.monitor.recordEvaluation(
        result.evaluationTimeMs,
        result.cacheHit,
        result.fastPath,
        result.allowed,
        {
          userId: subject.userId,
          businessId: subject.businessId,
          capability,
        }
      );

      return result;

    } catch (error) {

      // Record error in monitoring
      this.monitor.recordEvaluation(
        performance.now() - startTime,
        false,
        null,
        false,
        {
          userId: subject.userId,
          businessId: subject.businessId,
          capability,
          error: error instanceof Error ? error.message : 'Unknown error',
        }
      );

      // Return safe default (deny)
      return {
        allowed: false,
        matched: [],
        denied: [],
        evaluationTimeMs: performance.now() - startTime,
        cacheHit: false,
        fastPath: null,
        reason: `System error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  /**
   * Batch permission check
   */
  async checkPermissions(
    subject: Subject,
    capabilities: Capability[],
    resource?: Resource
  ): Promise<Map<Capability, EvaluationResult>> {
    const startTime = performance.now();

    try {
      const results = await this.resolver.checkPermissions(subject, capabilities, resource);

      // Record aggregate metrics
      const totalTime = performance.now() - startTime;
      const avgTime = totalTime / capabilities.length;
      const cacheHits = Array.from(results.values()).filter(r => r.cacheHit).length;
      const avgCacheHit = cacheHits > 0;

      this.monitor.recordEvaluation(
        avgTime,
        avgCacheHit,
        'batch',
        true,
        {
          userId: subject.userId,
          businessId: subject.businessId,
          capabilityCount: capabilities.length,
        }
      );

      return results;

    } catch (error) {

      // Return error results for all capabilities
      const errorResults = new Map<Capability, EvaluationResult>();
      capabilities.forEach(capability => {
        errorResults.set(capability, {
          allowed: false,
          matched: [],
          denied: [],
          evaluationTimeMs: 0,
          cacheHit: false,
          fastPath: null,
          reason: `Batch evaluation error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        });
      });

      return errorResults;
    }
  }

  /**
   * Get all permissions for a subject (for UI/admin)
   */
  async getAllPermissions(subject: Subject): Promise<PermissionBundle> {
    return await this.resolver.getAllPermissions(subject);
  }

  /**
   * Invalidate cached permissions
   */
  async invalidatePermissions(
    subject: Subject,
    reason = 'manual_invalidation'
  ): Promise<void> {
    await this.resolver.invalidatePermissions(subject, reason);
  }

  /**
   * Precompute permissions for better performance
   */
  async precomputePermissions(subject: Subject): Promise<void> {
    await this.resolver.precomputePermissions(subject);
  }

  /**
   * Policy management
   */
  async addPolicy(policy: PolicyRule): Promise<void> {
    this.policyEvaluator.addPolicy(policy);

    // Invalidate all cached permissions since policies changed
  }

  async removePolicy(policyId: string): Promise<boolean> {
    const removed = this.policyEvaluator.removePolicy(policyId);

    if (removed) {
    }

    return removed;
  }

  async loadPolicies(policies: PolicyRule[]): Promise<void> {
    this.policyEvaluator.loadPolicies(policies);
  }

  /**
   * Performance and health monitoring
   */
  getPerformanceStatistics(): any {
    return this.monitor.getStatistics();
  }

  getHealthReport(): any {
    return this.monitor.getHealthReport();
  }

  async getPerformanceTrends(hours = 24): Promise<any> {
    return await this.monitor.getPerformanceTrends(hours);
  }

  exportMetrics(): any {
    return this.monitor.exportMetrics();
  }

  /**
   * Administrative functions
   */
  async getSystemStatistics(): Promise<{
    abac: any;
    cache: any;
    policies: any;
    performance: any;
  }> {
    return {
      abac: {
        totalEvaluations: this.monitor.getStatistics().current.totalEvaluations,
        averageTime: this.monitor.getStatistics().current.averageEvaluationTime,
        healthStatus: this.monitor.getHealthReport().status,
      },
      cache: await this.cache.getStatistics(),
      policies: this.policyEvaluator.getStatistics(),
      performance: this.monitor.getStatistics(),
    };
  }

  async clearCache(): Promise<void> {
    // Clear monitoring metrics
    this.monitor.clearMetrics();

  }

  /**
   * Warm cache with common permissions
   */
  async warmCache(subjects: Subject[]): Promise<void> {
    const commonCapabilities = [
      'dashboard.analytics.read',
      'profile.settings.update',
      'notifications.alerts.read',
    ];

    await this.cache.warmCache(subjects, commonCapabilities);
  }

  /**
   * Health check for the ABAC service
   */
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'unhealthy';
    details: {
      cache: any;
      policies: any;
      performance: any;
    };
    timestamp: string;
  }> {
    const healthReport = this.monitor.getHealthReport();
    const cacheHealth = this.cache.getHealthStatus();
    const policyStats = this.policyEvaluator.getStatistics();

    return {
      status: healthReport.status,
      details: {
        cache: cacheHealth,
        policies: {
          totalPolicies: policyStats.totalPolicies,
          allowPolicies: policyStats.allowPolicies,
          denyPolicies: policyStats.denyPolicies,
        },
        performance: {
          averageEvaluationTime: healthReport.metrics.averageResponseTime,
          cacheHitRate: healthReport.metrics.cacheEfficiency,
          throughput: healthReport.metrics.throughput,
        },
      },
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Capability introspection - what can a subject do?
   */
  async introspectCapabilities(
    subject: Subject,
    resourceType?: string
  ): Promise<{
    allowed: Capability[];
    denied: Capability[];
    conditional: Array<{
      capability: Capability;
      constraints: any;
    }>;
  }> {
    const bundle = await this.getAllPermissions(subject);
    const allowed: Capability[] = [];
    const denied: Capability[] = [];
    const conditional: Array<{ capability: Capability; constraints: any }> = [];

    for (const capability of bundle.capabilities) {
      const constraints = bundle.constraints.get(capability);

      if (constraints && Object.keys(constraints).length > 0) {
        conditional.push({ capability, constraints });
      } else {
        allowed.push(capability);
      }
    }

    return { allowed, denied, conditional };
  }

  /**
   * Capability discovery - what permissions exist for a resource?
   */
  async discoverCapabilities(resourceType: string): Promise<{
    available: Capability[];
    descriptions: Record<Capability, string>;
  }> {
    // This would integrate with the capability registry
    // For now, return a basic set based on resource type

    const baseActions = ['create', 'read', 'update', 'delete'];
    const available = baseActions.map(action =>
      `${this.getModuleForResource(resourceType)}.${resourceType}.${action}` as Capability
    );

    const descriptions: Record<Capability, string> = {};
    available.forEach(cap => {
      const [module, resource, action] = cap.split('.');
      descriptions[cap] = `${action.charAt(0).toUpperCase() + action.slice(1)} ${resource} in ${module} module`;
    });

    return { available, descriptions };
  }

  /**
   * Permission debugging - why was a permission granted/denied?
   */
  async debugPermission(
    subject: Subject,
    capability: Capability,
    resource?: Resource
  ): Promise<{
    result: EvaluationResult;
    debug: {
      fastPathAttempted: boolean;
      fastPathResult?: any;
      policiesEvaluated: number;
      cacheChecked: boolean;
      evaluationPath: string[];
      constraints: any;
    };
  }> {
    // This would require instrumenting the evaluation process
    // For now, perform a standard evaluation and return debug info

    const result = await this.checkPermission(subject, capability, resource);

    return {
      result,
      debug: {
        fastPathAttempted: true,
        fastPathResult: result.fastPath ? 'success' : 'no_match',
        policiesEvaluated: result.matched.length + result.denied.length,
        cacheChecked: result.cacheHit,
        evaluationPath: [
          'cache_check',
          result.fastPath ? 'fast_path' : 'policy_evaluation',
          'constraint_check',
        ],
        constraints: result.constraints,
      },
    };
  }

  /**
   * Helper method to determine module for resource type
   */
  private getModuleForResource(resourceType: string): string {
    const moduleMap: Record<string, string> = {
      'invoice': 'finance',
      'employee': 'hr',
      'inventory': 'operations',
      'quote': 'sales',
      'purchase': 'procurement',
      'user': 'system',
      'report': 'reports',
      'task': 'workflow',
    };

    return moduleMap[resourceType] || 'general';
  }
}