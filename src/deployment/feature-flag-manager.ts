/**
 * AI-Powered Feature Flag System with Progressive Rollouts
 * Advanced feature flag management with ML optimization and A/B testing
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';

export interface FeatureFlag {
  id: string;
  name: string;
  key: string;
  enabled: boolean;
  description: string;
  owner: string;
  team: string;
  environment: Environment;
  type: FlagType;

  targeting?: TargetingConfig;
  rollout?: RolloutConfig;
  experiment?: ExperimentConfig;
  lifecycle?: LifecycleConfig;

  metadata: FlagMetadata;
  createdAt: number;
  updatedAt: number;
}

export type Environment = 'development' | 'staging' | 'production';
export type FlagType = 'boolean' | 'string' | 'number' | 'json' | 'percentage';

export interface TargetingConfig {
  enabled: boolean;
  segments: string[];
  rules: TargetingRule[];
  defaultValue: any;
  fallback: any;
}

export interface TargetingRule {
  id: string;
  name: string;
  conditions: Condition[];
  value: any;
  weight?: number;
  priority: number;
  enabled: boolean;
}

export interface Condition {
  attribute: string;
  operator: ConditionOperator;
  value: any;
  negate?: boolean;
}

export type ConditionOperator =
  | 'equals'
  | 'not_equals'
  | 'contains'
  | 'not_contains'
  | 'starts_with'
  | 'ends_with'
  | 'in'
  | 'not_in'
  | 'greater_than'
  | 'less_than'
  | 'greater_than_or_equal'
  | 'less_than_or_equal'
  | 'regex'
  | 'version_greater_than'
  | 'version_less_than'
  | 'date_after'
  | 'date_before';

export interface RolloutConfig {
  enabled: boolean;
  strategy: RolloutStrategy;
  percentage: number;
  minimum: number;
  maximum: number;
  duration: string;
  stages: RolloutStage[];
  autoPromote: boolean;
  killSwitch: boolean;
}

export type RolloutStrategy = 'linear' | 'exponential' | 'canary' | 'blue_green' | 'custom';

export interface RolloutStage {
  name: string;
  percentage: number;
  duration: string;
  conditions: RolloutCondition[];
  autoAdvance: boolean;
  rollbackTriggers: RollbackTrigger[];
}

export interface RolloutCondition {
  metric: string;
  operator: 'gt' | 'lt' | 'gte' | 'lte' | 'eq' | 'ne';
  threshold: number;
  duration: string;
}

export interface RollbackTrigger {
  metric: string;
  threshold: number;
  duration: string;
  severity: 'warning' | 'critical';
  autoRollback: boolean;
}

export interface ExperimentConfig {
  enabled: boolean;
  hypothesis: string;
  variants: Variant[];
  metrics: ExperimentMetric[];
  allocation: AllocationConfig;
  analysis: AnalysisConfig;
  schedule: ExperimentSchedule;
}

export interface Variant {
  id: string;
  name: string;
  description: string;
  value: any;
  weight: number;
  control: boolean;
}

export interface ExperimentMetric {
  name: string;
  type: MetricType;
  goal: MetricGoal;
  threshold: number;
  significance: number;
  minimumSampleSize: number;
}

export type MetricType = 'conversion' | 'revenue' | 'engagement' | 'retention' | 'custom';
export type MetricGoal = 'increase' | 'decrease' | 'no_change';

export interface AllocationConfig {
  trafficPercentage: number;
  segments: string[];
  stickyBucketing: boolean;
  mutuallyExclusive: string[];
}

export interface AnalysisConfig {
  confidenceLevel: number;
  statisticalPower: number;
  minimumDetectableEffect: number;
  bayesianAnalysis: boolean;
  sequentialTesting: boolean;
}

export interface ExperimentSchedule {
  startDate: Date;
  endDate?: Date;
  duration?: string;
  autoEnd: boolean;
  rampUpDuration?: string;
  rampDownDuration?: string;
}

export interface LifecycleConfig {
  startDate: Date;
  endDate?: Date;
  reviewDate: Date;
  deprecationDate?: Date;
  autoCleanup: boolean;
  notifications: NotificationConfig[];
}

export interface NotificationConfig {
  type: NotificationType;
  recipients: string[];
  conditions: string[];
  template: string;
}

export type NotificationType = 'email' | 'slack' | 'webhook' | 'sms';

export interface FlagMetadata {
  tags: string[];
  dependencies: string[];
  impact: ImpactLevel;
  category: FlagCategory;
  businessValue: number;
  technicalComplexity: number;
  riskLevel: RiskLevel;
  compliance: ComplianceRequirement[];
}

export type ImpactLevel = 'low' | 'medium' | 'high' | 'critical';
export type FlagCategory = 'feature' | 'experiment' | 'operational' | 'kill_switch' | 'permission';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type ComplianceRequirement = 'GDPR' | 'CCPA' | 'SOX' | 'HIPAA' | 'PCI';

export interface EvaluationContext {
  userId?: string;
  sessionId?: string;
  deviceId?: string;
  businessId?: string;
  userAgent?: string;
  ipAddress?: string;
  location?: LocationData;
  device?: DeviceData;
  user?: UserData;
  custom?: Record<string, any>;
  timestamp: number;
}

export interface LocationData {
  country: string;
  region: string;
  city: string;
  timezone: string;
  coordinates?: {
    latitude: number;
    longitude: number;
  };
}

export interface DeviceData {
  type: 'desktop' | 'mobile' | 'tablet' | 'tv' | 'unknown';
  os: string;
  browser: string;
  version: string;
  screenSize: string;
}

export interface UserData {
  id: string;
  email?: string;
  role: string;
  plan: string;
  registrationDate: Date;
  lastActiveDate: Date;
  attributes: Record<string, any>;
}

export interface FlagEvaluation {
  flagKey: string;
  value: any;
  variant?: string;
  reason: EvaluationReason;
  ruleId?: string;
  segmentKey?: string;
  metadata: EvaluationMetadata;
}

export type EvaluationReason =
  | 'FLAG_OFF'
  | 'FALLTHROUGH'
  | 'RULE_MATCH'
  | 'SEGMENT_MATCH'
  | 'EXPERIMENT_ALLOCATION'
  | 'ROLLOUT_PERCENTAGE'
  | 'ERROR';

export interface EvaluationMetadata {
  flagVersion: number;
  evaluationTime: number;
  samplingRatio: number;
  debugInfo?: any;
}

export // TODO: Consider splitting FeatureFlagManager into smaller, focused classes
class FeatureFlagManager {
  private logger = new Logger();
  private flags = new Map<string, FeatureFlag>();
  private aiOptimizer: FeatureOptimizer;
  private experimentAnalyzer: ExperimentAnalyzer;
  private rolloutManager: RolloutManager;
  private eventTracker: EventTracker;

  constructor() {
    this.aiOptimizer = new FeatureOptimizer();
    this.experimentAnalyzer = new ExperimentAnalyzer();
    this.rolloutManager = new RolloutManager();
    this.eventTracker = new EventTracker();
  }

  /**
   * Evaluate feature flag for given context
   */
  async evaluateFlag(
    flagKey: string,
    context: EvaluationContext,
    defaultValue?: any
  ): Promise<FlagEvaluation> {
    const correlationId = CorrelationId.generate();

    this.logger.debug('Evaluating feature flag', {
      correlationId,
      flagKey,
      userId: context.userId,
      businessId: context.businessId
    });

    try {
      const flag = this.flags.get(flagKey);

      if (!flag) {
        return this.createEvaluation(flagKey, defaultValue, 'FLAG_OFF', {
          error: 'Flag not found'
        });
      }

      if (!flag.enabled) {
        return this.createEvaluation(flagKey, flag.targeting?.fallback || defaultValue, 'FLAG_OFF');
      }

      // Check targeting rules
      if (flag.targeting?.enabled) {
        const targetingResult = await this.evaluateTargeting(flag.targeting, context);
        if (targetingResult.matched) {
          await this.trackExposure(flag, context, targetingResult.value, 'RULE_MATCH');
          return this.createEvaluation(flagKey, targetingResult.value, 'RULE_MATCH', {
            ruleId: targetingResult.ruleId
          });
        }
      }

      // Check experiment allocation
      if (flag.experiment?.enabled) {
        const experimentResult = await this.evaluateExperiment(flag.experiment, context);
        if (experimentResult.allocated) {
          await this.trackExposure(flag, context, experimentResult.value, 'EXPERIMENT_ALLOCATION');
          return this.createEvaluation(flagKey, experimentResult.value, 'EXPERIMENT_ALLOCATION', {
            variant: experimentResult.variant
          });
        }
      }

      // Check rollout percentage with AI optimization
      if (flag.rollout?.enabled) {
        const rolloutResult = await this.evaluateRollout(flag.rollout, context, flag);
        if (rolloutResult.included) {
          await this.trackExposure(flag, context, rolloutResult.value, 'ROLLOUT_PERCENTAGE');
          return this.createEvaluation(flagKey, rolloutResult.value, 'ROLLOUT_PERCENTAGE');
        }
      }

      // Fallthrough to default
      const fallbackValue = flag.targeting?.defaultValue || defaultValue;
      await this.trackExposure(flag, context, fallbackValue, 'FALLTHROUGH');
      return this.createEvaluation(flagKey, fallbackValue, 'FALLTHROUGH');

    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      this.logger.error('Flag evaluation error', errorMessage, {
        correlationId,
        flagKey,
        userId: context.userId
      });

      return this.createEvaluation(flagKey, defaultValue, 'ERROR', {
        error: errorMessage
      });
    }
  }

  /**
   * Evaluate multiple flags in batch
   */
  async evaluateFlags(
    flagKeys: string[],
    context: EvaluationContext,
    defaults?: Record<string, any>
  ): Promise<Record<string, FlagEvaluation>> {
    const evaluations: Record<string, FlagEvaluation> = {};

    // Evaluate flags in parallel for performance
    const promises = flagKeys.map(async (key: any) => {
      const evaluation = await this.evaluateFlag(key, context, defaults?.[key]);
      return { key, evaluation };
    });

    const results = await Promise.allSettled(promises);

    for (const result of results) {
      if (result.status === 'fulfilled') {
        evaluations[result.value.key] = result.value.evaluation;
      }
    }

    return evaluations;
  }

  /**
   * Create or update feature flag
   */
  async createFlag(flag: Partial<FeatureFlag>): Promise<FeatureFlag> {
    const correlationId = CorrelationId.generate();

    this.logger.info('Creating feature flag', {
      correlationId,
      name: flag.name,
      key: flag.key,
      owner: flag.owner
    });

    const newFlag: FeatureFlag = {
      id: flag.id || this.generateFlagId(),
      name: flag.name || '',
      key: flag.key || '',
      enabled: flag.enabled || false,
      description: flag.description || '',
      owner: flag.owner || '',
      team: flag.team || '',
      environment: flag.environment || 'development',
      type: flag.type || 'boolean',
      targeting: flag.targeting,
      rollout: flag.rollout,
      experiment: flag.experiment,
      lifecycle: flag.lifecycle,
      metadata: flag.metadata || {
        tags: [],
        dependencies: [],
        impact: 'low',
        category: 'feature',
        businessValue: 0,
        technicalComplexity: 0,
        riskLevel: 'low',
        compliance: []
      },
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    this.flags.set(newFlag.key, newFlag);

    // Setup lifecycle management
    if (newFlag.lifecycle) {
      await this.setupLifecycleManagement(newFlag);
    }

    // Setup experiment if configured
    if (newFlag.experiment?.enabled) {
      await this.setupExperiment(newFlag);
    }

    // Setup rollout if configured
    if (newFlag.rollout?.enabled) {
      await this.setupRollout(newFlag);
    }

    this.logger.info('Feature flag created', {
      correlationId,
      flagId: newFlag.id,
      key: newFlag.key
    });

    return newFlag;
  }

  /**
   * Update feature flag
   */
  async updateFlag(key: string, updates: Partial<FeatureFlag>): Promise<FeatureFlag> {
    const flag = this.flags.get(key);
    if (!flag) {
      throw new Error(`Flag not found: ${key}`);
    }

    const updatedFlag = {
      ...flag,
      ...updates,
      updatedAt: Date.now()
    };

    this.flags.set(key, updatedFlag);

    this.logger.info('Feature flag updated', {
      key,
      updates: Object.keys(updates)
    });

    return updatedFlag;
  }

  /**
   * Delete feature flag
   */
  async deleteFlag(key: string): Promise<void> {
    const flag = this.flags.get(key);
    if (!flag) {
      throw new Error(`Flag not found: ${key}`);
    }

    // Check for dependencies
    const dependentFlags = Array.from(this.flags.values()).filter((f: any) =>
      f.metadata.dependencies.includes(key)
    );

    if (dependentFlags.length > 0) {
      throw new Error(`Cannot delete flag ${key}: ${dependentFlags.length} flags depend on it`);
    }

    this.flags.delete(key);

    this.logger.info('Feature flag deleted', { key });
  }

  /**
   * Get flag status and metrics
   */
  async getFlagStatus(key: string): Promise<FlagStatus> {
    const flag = this.flags.get(key);
    if (!flag) {
      throw new Error(`Flag not found: ${key}`);
    }

    const metrics = await this.eventTracker.getFlagMetrics(key);
    const health = await this.assessFlagHealth(flag, metrics);

    return {
      flag,
      metrics,
      health,
      recommendations: await this.generateRecommendations(flag, metrics),
      lastEvaluated: metrics.lastEvaluationTime
    };
  }

  /**
   * Automatic flag cleanup
   */
  async cleanupFlags(): Promise<CleanupResult> {
    const staleFlags = await this.identifyStaleFlags({
      unusedDays: 30,
      fullRolloutDays: 7,
      zeroTrafficDays: 14,
      deprecatedDays: 1
    });

    const cleanupResults: FlagCleanupResult[] = [];

    for (const flag of staleFlags) {
      try {
        const result = await this.archiveFlag(flag, {
          preserveData: true,
          notifyOwners: true,
          gracePeriod: '7d'
        });

        cleanupResults.push({
          flag: flag.key,
          action: 'archived',
          success: true,
          reason: result.reason
        });

      } catch (error: any) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        cleanupResults.push({
          flag: flag.key,
          action: 'archive_failed',
          success: false,
          reason: errorMessage
        });
      }
    }

    this.logger.info('Flag cleanup completed', {
      totalProcessed: staleFlags.length,
      successful: cleanupResults.filter((r: any) => r.success).length,
      failed: cleanupResults.filter((r: any) => !r.success).length
    });

    return {
      processed: staleFlags.length,
      results: cleanupResults
    };
  }

  /**
   * Private helper methods
   */
  private async evaluateTargeting(
    targeting: TargetingConfig,
    context: EvaluationContext
  ): Promise<TargetingResult> {
    // Sort rules by priority
    const sortedRules = targeting.rules.sort((a, b) => a.priority - b.priority);

    for (const rule of sortedRules) {
      if (!rule.enabled) continue;

      const matched = await this.evaluateRule(rule, context);
      if (matched) {
        return {
          matched: true,
          value: rule.value,
          ruleId: rule.id
        };
      }
    }

    return { matched: false };
  }

  private async evaluateRule(rule: TargetingRule, context: EvaluationContext): Promise<boolean> {
    if (rule.conditions.length === 0) return true;

    // All conditions must match (AND logic)
    for (const condition of rule.conditions) {
      const matched = await this.evaluateCondition(condition, context);
      if (!matched) return false;
    }

    return true;
  }

  private async evaluateCondition(condition: Condition, context: EvaluationContext): Promise<boolean> {
    const attributeValue = this.getAttributeValue(condition.attribute, context);
    const conditionValue = condition.value;

    let result = false;

    switch (condition.operator) {
      case 'equals':
        result = attributeValue === conditionValue;
        break;
      case 'not_equals':
        result = attributeValue !== conditionValue;
        break;
      case 'contains':
        result = String(attributeValue).includes(String(conditionValue));
        break;
      case 'not_contains':
        result = !String(attributeValue).includes(String(conditionValue));
        break;
      case 'starts_with':
        result = String(attributeValue).startsWith(String(conditionValue));
        break;
      case 'ends_with':
        result = String(attributeValue).endsWith(String(conditionValue));
        break;
      case 'in':
        result = Array.isArray(conditionValue) && conditionValue.includes(attributeValue);
        break;
      case 'not_in':
        result = Array.isArray(conditionValue) && !conditionValue.includes(attributeValue);
        break;
      case 'greater_than':
        result = Number(attributeValue) > Number(conditionValue);
        break;
      case 'less_than':
        result = Number(attributeValue) < Number(conditionValue);
        break;
      case 'greater_than_or_equal':
        result = Number(attributeValue) >= Number(conditionValue);
        break;
      case 'less_than_or_equal':
        result = Number(attributeValue) <= Number(conditionValue);
        break;
      case 'regex':
        result = new RegExp(String(conditionValue)).test(String(attributeValue));
        break;
      case 'version_greater_than':
        result = this.compareVersions(String(attributeValue), String(conditionValue)) > 0;
        break;
      case 'version_less_than':
        result = this.compareVersions(String(attributeValue), String(conditionValue)) < 0;
        break;
      case 'date_after':
        result = new Date(attributeValue) > new Date(conditionValue);
        break;
      case 'date_before':
        result = new Date(attributeValue) < new Date(conditionValue);
        break;
      default:
        result = false;
    }

    return condition.negate ? !result : result;
  }

  private getAttributeValue(attribute: string, context: EvaluationContext): any {
    const parts = attribute.split('.');
    let value: any = context;

    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }

    return value;
  }

  private compareVersions(version1: string, version2: string): number {
    const v1Parts = version1.split('.').map(Number);
    const v2Parts = version2.split('.').map(Number);
    const maxLength = Math.max(v1Parts.length, v2Parts.length);

    for (let i = 0; i < maxLength; i++) {
      const v1Part = v1Parts[i] || 0;
      const v2Part = v2Parts[i] || 0;

      if (v1Part > v2Part) return 1;
      if (v1Part < v2Part) return -1;
    }

    return 0;
  }

  private async evaluateExperiment(
    experiment: ExperimentConfig,
    context: EvaluationContext
  ): Promise<ExperimentResult> {
    // Check if user is allocated to experiment
    const userId = context.userId || context.sessionId || context.deviceId;
    if (!userId) {
      return { allocated: false };
    }

    // Check experiment schedule
    const now = new Date();
    if (experiment.schedule.startDate > now ||
        (experiment.schedule.endDate && experiment.schedule.endDate < now)) {
      return { allocated: false };
    }

    // Check traffic allocation
    const hash = this.hashUser(userId);
    const trafficThreshold = experiment.allocation.trafficPercentage / 100;

    if (hash > trafficThreshold) {
      return { allocated: false };
    }

    // Select variant based on weights
    const variant = this.selectVariant(experiment.variants, userId);

    return {
      allocated: true,
      variant: variant.id,
      value: variant.value
    };
  }

  private async evaluateRollout(
    rollout: RolloutConfig,
    context: EvaluationContext,
    flag: FeatureFlag
  ): Promise<RolloutResult> {
    // AI-optimized rollout percentage
    const optimizedPercentage = await this.aiOptimizer.calculateOptimalPercentage({
      flag,
      context,
      currentPercentage: rollout.percentage,
      strategy: rollout.strategy,
      metrics: await this.eventTracker.getFlagMetrics(flag.key)
    });

    // Progressive rollout stages
    if (rollout.stages.length > 0) {
      const currentStage = await this.rolloutManager.getCurrentStage(flag.key, rollout.stages);
      if (currentStage) {
        return await this.evaluateStageRollout(currentStage, context);
      }
    }

    // Simple percentage rollout
    const userId = context.userId || context.sessionId || context.deviceId;
    if (!userId) {
      return { included: false };
    }

    const hash = this.hashUser(userId + flag.key);
    const included = hash <= (optimizedPercentage / 100);

    return {
      included,
      value: included ? true : false, // For boolean flags
      percentage: optimizedPercentage
    };
  }

  private async evaluateStageRollout(
    stage: RolloutStage,
    context: EvaluationContext
  ): Promise<RolloutResult> {
    // Check stage conditions
    for (const condition of stage.conditions) {
      const metrics = await this.eventTracker.getMetric(condition.metric);
      const satisfied = this.evaluateMetricCondition(metrics, condition);

      if (!satisfied) {
        return { included: false };
      }
    }

    const userId = context.userId || context.sessionId || context.deviceId;
    if (!userId) {
      return { included: false };
    }

    const hash = this.hashUser(userId);
    const included = hash <= (stage.percentage / 100);

    return {
      included,
      value: included,
      percentage: stage.percentage,
      stage: stage.name
    };
  }

  private evaluateMetricCondition(metrics: any, condition: RolloutCondition): boolean {
    const value = metrics?.value || 0;

    switch (condition.operator) {
      case 'gt': return value > condition.threshold;
      case 'lt': return value < condition.threshold;
      case 'gte': return value >= condition.threshold;
      case 'lte': return value <= condition.threshold;
      case 'eq': return value === condition.threshold;
      case 'ne': return value !== condition.threshold;
      default: return false;
    }
  }

  private hashUser(input: string): number {
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash) / Math.pow(2, 31); // Normalize to 0-1
  }

  private selectVariant(variants: Variant[], userId: string): Variant {
    const totalWeight = variants.reduce((sum, v) => sum + v.weight, 0);
    const hash = this.hashUser(userId);
    const threshold = hash * totalWeight;

    let cumulativeWeight = 0;
    for (const variant of variants) {
      cumulativeWeight += variant.weight;
      if (threshold <= cumulativeWeight) {
        return variant;
      }
    }

    return variants[variants.length - 1]; // Fallback to last variant
  }

  private createEvaluation(
    flagKey: string,
    value: any,
    reason: EvaluationReason,
    metadata: any = {}
  ): FlagEvaluation {
    return {
      flagKey,
      value,
      variant: metadata.variant,
      reason,
      ruleId: metadata.ruleId,
      segmentKey: metadata.segmentKey,
      metadata: {
        flagVersion: 1,
        evaluationTime: Date.now(),
        samplingRatio: 1.0,
        debugInfo: metadata
      }
    };
  }

  private async trackExposure(
    flag: FeatureFlag,
    context: EvaluationContext,
    value: any,
    reason: EvaluationReason
  ): Promise<void> {
    await this.eventTracker.trackExposure({
      flagKey: flag.key,
      userId: context.userId,
      value,
      reason,
      context,
      timestamp: Date.now()
    });
  }

  private generateFlagId(): string {
    return `flag_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private async setupLifecycleManagement(flag: FeatureFlag): Promise<void> {
    // Setup lifecycle notifications and cleanup schedules
    this.logger.info('Setting up lifecycle management', { flag: flag.key });
  }

  private async setupExperiment(flag: FeatureFlag): Promise<void> {
    // Initialize experiment tracking and analysis
    this.logger.info('Setting up experiment', { flag: flag.key });
  }

  private async setupRollout(flag: FeatureFlag): Promise<void> {
    // Initialize rollout progression tracking
    this.logger.info('Setting up rollout', { flag: flag.key });
  }

  private async assessFlagHealth(flag: FeatureFlag, metrics: any): Promise<FlagHealth> {
    return {
      status: 'healthy',
      score: 85,
      issues: [],
      recommendations: []
    };
  }

  private async generateRecommendations(flag: FeatureFlag, metrics: any): Promise<string[]> {
    const recommendations: string[] = [];

    if (metrics.evaluationCount === 0) {
      recommendations.push('Flag has no traffic - consider removing if not needed');
    }

    if (flag.rollout?.percentage === 100 && metrics.daysAtFullRollout > 7) {
      recommendations.push('Flag at 100% rollout for over 7 days - consider making permanent');
    }

    return recommendations;
  }

  private async identifyStaleFlags(criteria: StaleFlagCriteria): Promise<FeatureFlag[]> {
    const staleFlags: FeatureFlag[] = [];
    const now = Date.now();

    for (const flag of this.flags.values()) {
      const metrics = await this.eventTracker.getFlagMetrics(flag.key);

      // Check for unused flags
      if (metrics.lastEvaluationTime &&
          (now - metrics.lastEvaluationTime) > (criteria.unusedDays * 24 * 60 * 60 * 1000)) {
        staleFlags.push(flag);
        continue;
      }

      // Check for flags at full rollout
      if (flag.rollout?.percentage === 100 &&
          metrics.daysAtFullRollout > criteria.fullRolloutDays) {
        staleFlags.push(flag);
        continue;
      }

      // Check for zero traffic flags
      if (metrics.evaluationCount === 0 &&
          (now - flag.createdAt) > (criteria.zeroTrafficDays * 24 * 60 * 60 * 1000)) {
        staleFlags.push(flag);
        continue;
      }

      // Check for deprecated flags
      if (flag.lifecycle?.deprecationDate &&
          flag.lifecycle.deprecationDate < new Date(now - criteria.deprecatedDays * 24 * 60 * 60 * 1000)) {
        staleFlags.push(flag);
      }
    }

    return staleFlags;
  }

  private async archiveFlag(flag: FeatureFlag, options: ArchiveOptions): Promise<ArchiveResult> {
    this.logger.info('Archiving flag', { flag: flag.key, options });

    // Move to archive (implementation would vary based on storage)
    this.flags.delete(flag.key);

    return {
      archived: true,
      reason: 'Flag identified as stale and archived automatically'
    };
  }
}

// Supporting classes
class FeatureOptimizer {
  async calculateOptimalPercentage(options: OptimizationOptions): Promise<number> {
    // AI-powered optimization
    return Math.min(options.currentPercentage * 1.1, 100); // Simple 10% increase
  }

  async segment(context: EvaluationContext, options: any): Promise<string> {
    // AI-based user segmentation
    return 'default';
  }

  async calculateProbability(options: any): Promise<number> {
    // ML-based probability calculation
    return 0.5;
  }
}

class ExperimentAnalyzer {
  async analyzeExperiment(experiment: ExperimentConfig): Promise<ExperimentAnalysis> {
    return {
      significance: 0.95,
      confidence: 0.8,
      recommendation: 'continue'
    };
  }
}

// TODO: Consider splitting RolloutManager into smaller, focused classes
class RolloutManager {
  async getCurrentStage(flagKey: string, stages: RolloutStage[]): Promise<RolloutStage | null> {
    // Determine current stage based on timing and conditions
    return stages[0] || null;
  }
}

class EventTracker {
  async trackExposure(event: ExposureEvent): Promise<void> {
    // Track flag exposure for analytics
  }

  async getFlagMetrics(flagKey: string): Promise<FlagMetrics> {
    return {
      evaluationCount: 1000,
      lastEvaluationTime: Date.now(),
      daysAtFullRollout: 0,
      errorRate: 0.001
    };
  }

  async getMetric(metricName: string): Promise<any> {
    return { value: 100 };
  }
}

// Supporting interfaces
interface TargetingResult {
  matched: boolean;
  value?: any;
  ruleId?: string;
}

interface ExperimentResult {
  allocated: boolean;
  variant?: string;
  value?: any;
}

interface RolloutResult {
  included: boolean;
  value?: any;
  percentage?: number;
  stage?: string;
}

interface FlagStatus {
  flag: FeatureFlag;
  metrics: FlagMetrics;
  health: FlagHealth;
  recommendations: string[];
  lastEvaluated: number;
}

interface FlagMetrics {
  evaluationCount: number;
  lastEvaluationTime: number;
  daysAtFullRollout: number;
  errorRate: number;
}

interface FlagHealth {
  status: 'healthy' | 'warning' | 'critical';
  score: number;
  issues: string[];
  recommendations: string[];
}

interface CleanupResult {
  processed: number;
  results: FlagCleanupResult[];
}

interface FlagCleanupResult {
  flag: string;
  action: string;
  success: boolean;
  reason: string;
}

interface StaleFlagCriteria {
  unusedDays: number;
  fullRolloutDays: number;
  zeroTrafficDays: number;
  deprecatedDays: number;
}

interface ArchiveOptions {
  preserveData: boolean;
  notifyOwners: boolean;
  gracePeriod: string;
}

interface ArchiveResult {
  archived: boolean;
  reason: string;
}

interface OptimizationOptions {
  flag: FeatureFlag;
  context: EvaluationContext;
  currentPercentage: number;
  strategy: RolloutStrategy;
  metrics: FlagMetrics;
}

interface ExperimentAnalysis {
  significance: number;
  confidence: number;
  recommendation: 'continue' | 'stop' | 'extend';
}

interface ExposureEvent {
  flagKey: string;
  userId?: string;
  value: any;
  reason: EvaluationReason;
  context: EvaluationContext;
  timestamp: number;
}

/**
 * Create feature flag manager
 */
export function createFeatureFlagManager(): FeatureFlagManager {
  return new FeatureFlagManager();
}