/**
 * Configuration Service
 * Dynamic configuration management with feature flags and A/B testing
 */

import { Logger } from '../../shared/logger';
import type { KVNamespace, D1Database } from '@cloudflare/workers-types';
import { validateBusinessId, sanitizeUserId } from './security-utils';

export interface ConfigValue {
  key: string;
  value: any;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description?: string;
  defaultValue?: any;
  constraints?: ConfigConstraints;
  metadata?: Record<string, any>;
  version: number;
  updatedAt: number;
  updatedBy?: string;
}

export interface ConfigConstraints {
  min?: number;
  max?: number;
  enum?: any[];
  pattern?: string;
  required?: boolean;
}

export interface FeatureFlag {
  key: string;
  enabled: boolean;
  rolloutPercentage: number;
  conditions?: FlagCondition[];
  variants?: FlagVariant[];
  metadata?: Record<string, any>;
  createdAt: number;
  updatedAt: number;
}

export interface FlagCondition {
  type: 'user' | 'business' | 'department' | 'custom';
  operator: 'in' | 'not_in' | 'equals' | 'contains';
  values: string[];
}

export interface FlagVariant {
  name: string;
  weight: number;
  value?: any;
  overrides?: Record<string, any>;
}

export interface ABTest {
  id: string;
  name: string;
  status: 'draft' | 'running' | 'paused' | 'completed';
  variants: TestVariant[];
  metrics: string[];
  startDate: number;
  endDate?: number;
  sampleSize?: number;
  results?: TestResults;
}

export interface TestVariant {
  id: string;
  name: string;
  allocation: number;
  config: Record<string, any>;
  participants: number;
  conversions: number;
}

export interface TestResults {
  winner?: string;
  confidence: number;
  uplift: number;
  significanceLevel: number;
}

export interface ConfigContext {
  businessId?: string;
  userId?: string;
  department?: string;
  environment?: string;
  version?: string;
  metadata?: Record<string, any>;
}

export // TODO: Consider splitting ConfigService into smaller, focused classes
class ConfigService {
  private logger: Logger;
  private kv: KVNamespace;
  private db?: D1Database;

  private configCache = new Map<string, ConfigValue>();
  private flagCache = new Map<string, FeatureFlag>();
  private testCache = new Map<string, ABTest>();

  private cacheExpiry = 300000; // 5 minutes
  private lastCacheUpdate = 0;

  private changeListeners = new Map<string, Set<ConfigChangeListener>>();

  constructor(kv: KVNamespace, db?: D1Database) {
    this.logger = new Logger();
    this.kv = kv;
    this.db = db;

    this.loadConfiguration();
  }

  /**
   * Get configuration value
   */
  async get<T = any>(
    key: string,
    context?: ConfigContext,
    defaultValue?: T
  ): Promise<T> {
    // Check cache first
    let config = this.configCache.get(key);

    if (!config || this.isCacheExpired()) {
      config = await this.loadConfigValue(key) || undefined;
      if (config) {
        this.configCache.set(key, config);
      }
    }

    if (!config) {
      if (defaultValue !== undefined) {
        return defaultValue;
      }
      throw new Error(`Configuration key not found: ${key}`);
    }

    // Apply context-specific overrides
    let value = config.value;

    if (context) {
      const override = await this.getOverride(key, context);
      if (override !== undefined) {
        value = override;
      }
    }

    // Validate against constraints
    if (config.constraints) {
      this.validateConstraints(value, config.constraints);
    }

    return value as T;
  }

  /**
   * Set configuration value
   */
  async set(
    key: string,
    value: any,
    options: {
      description?: string;
      constraints?: ConfigConstraints;
      updatedBy?: string;
    } = {}
  ): Promise<void> {
    const type = this.detectType(value);

    const config: ConfigValue = {
      key,
      value,
      type,
      description: options.description,
      constraints: options.constraints,
      version: Date.now(),
      updatedAt: Date.now(),
      updatedBy: options.updatedBy
    };

    // Validate constraints
    if (config.constraints) {
      this.validateConstraints(value, config.constraints);
    }

    // Save to KV
    await this.kv.put(`config:${key}`, JSON.stringify(config), {
      expirationTtl: 86400 // 24 hours
    });

    // Save to database
    if (this.db) {
      await this.db.prepare(`
        INSERT OR REPLACE INTO configurations (
          key, value, type, description, constraints,
          version, updated_at, updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        key,
        JSON.stringify(value),
        type,
        options.description || null,
        JSON.stringify(options.constraints || {}),
        config.version,
        config.updatedAt,
        options.updatedBy || null
      ).run();
    }

    // Update cache
    this.configCache.set(key, config);

    // Notify listeners
    this.notifyListeners(key, value, config);

    this.logger.info('Configuration updated', { key, type, version: config.version });
  }

  /**
   * Check feature flag
   */
  async isEnabled(
    flagKey: string,
    context: ConfigContext
  ): Promise<boolean> {
    const flag = await this.getFeatureFlag(flagKey);

    if (!flag) {
      return false;
    }

    if (!flag.enabled) {
      return false;
    }

    // Check conditions
    if (flag.conditions && flag.conditions.length > 0) {
      const conditionsMet = this.evaluateConditions(flag.conditions, context);
      if (!conditionsMet) {
        return false;
      }
    }

    // Check rollout percentage
    if (flag.rolloutPercentage < 100) {
      const hash = this.hashContext(context);
      const bucket = Math.abs(hash) % 100;
      return bucket < flag.rolloutPercentage;
    }

    return true;
  }

  /**
   * Get feature flag variant
   */
  async getVariant(
    flagKey: string,
    context: ConfigContext
  ): Promise<FlagVariant | null> {
    const flag = await this.getFeatureFlag(flagKey);

    if (!flag || !flag.enabled || !flag.variants || flag.variants.length === 0) {
      return null;
    }

    // Check if flag is enabled for this context
    const enabled = await this.isEnabled(flagKey, context);
    if (!enabled) {
      return null;
    }

    // Select variant based on weights
    const hash = this.hashContext(context);
    const bucket = (Math.abs(hash) % 100) / 100;

    let accumulator = 0;
    for (const variant of flag.variants) {
      accumulator += variant.weight;
      if (bucket < accumulator) {
        return variant;
      }
    }

    return flag.variants[0]; // Default to first variant
  }

  /**
   * Create or update feature flag
   */
  async setFeatureFlag(
    key: string,
    flag: Omit<FeatureFlag, 'key' | 'createdAt' | 'updatedAt'>
  ): Promise<void> {
    const now = Date.now();

    const featureFlag: FeatureFlag = {
      ...flag,
      key,
      createdAt: now,
      updatedAt: now
    };

    // Save to KV
    await this.kv.put(`flag:${key}`, JSON.stringify(featureFlag));

    // Save to database
    if (this.db) {
      await this.db.prepare(`
        INSERT OR REPLACE INTO feature_flags (
          key, enabled, rollout_percentage, conditions,
          variants, metadata, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        key,
        flag.enabled ? 1 : 0,
        flag.rolloutPercentage,
        JSON.stringify(flag.conditions || []),
        JSON.stringify(flag.variants || []),
        JSON.stringify(flag.metadata || {}),
        now,
        now
      ).run();
    }

    // Update cache
    this.flagCache.set(key, featureFlag);

    this.logger.info('Feature flag updated', {
      key,
      enabled: flag.enabled,
      rollout: flag.rolloutPercentage
    });
  }

  /**
   * Create A/B test
   */
  async createABTest(test: Omit<ABTest, 'id' | 'results'>): Promise<string> {
    const testId = `test_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    const abTest: ABTest = {
      ...test,
      id: testId
    };

    // Validate variant allocations sum to 100
    const totalAllocation = test.variants.reduce((sum, v) => sum + v.allocation, 0);
    if (Math.abs(totalAllocation - 100) > 0.01) {
      throw new Error('Variant allocations must sum to 100%');
    }

    // Save to KV
    await this.kv.put(`abtest:${testId}`, JSON.stringify(abTest));

    // Save to database
    if (this.db) {
      await this.db.prepare(`
        INSERT INTO ab_tests (
          id, name, status, variants, metrics,
          start_date, end_date, sample_size
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        testId,
        test.name,
        test.status,
        JSON.stringify(test.variants),
        JSON.stringify(test.metrics),
        test.startDate,
        test.endDate || null,
        test.sampleSize || null
      ).run();
    }

    // Update cache
    this.testCache.set(testId, abTest);

    this.logger.info('A/B test created', {
      testId,
      name: test.name,
      variants: test.variants.length
    });

    return testId;
  }

  /**
   * Get test variant for user
   */
  async getTestVariant(
    testId: string,
    context: ConfigContext
  ): Promise<TestVariant | null> {
    const test = await this.getABTest(testId);

    if (!test || test.status !== 'running') {
      return null;
    }

    // Check if test has ended
    if (test.endDate && Date.now() > test.endDate) {
      return null;
    }

    // Deterministic assignment based on user/business
    const hash = this.hashContext(context);
    const bucket = (Math.abs(hash) % 100) / 100;

    let accumulator = 0;
    for (const variant of test.variants) {
      accumulator += variant.allocation / 100;
      if (bucket < accumulator) {
        // Record participation
        await this.recordTestParticipation(testId, variant.id, context);
        return variant;
      }
    }

    return test.variants[0]; // Default to control
  }

  /**
   * Record test conversion
   */
  async recordConversion(
    testId: string,
    variantId: string,
    context: ConfigContext,
    value: number = 1
  ): Promise<void> {
    if (!this.db) return;

    await this.db.prepare(`
      INSERT INTO ab_test_events (
        test_id, variant_id, event_type, business_id,
        user_id, value, timestamp
      ) VALUES (?, ?, 'conversion', ?, ?, ?, ?)
    `).bind(
      testId,
      variantId,
      context.businessId || null,
      context.userId || null,
      value,
      Date.now()
    ).run();

    this.logger.debug('Conversion recorded', { testId, variantId, value });
  }

  /**
   * Get test results
   */
  async getTestResults(testId: string): Promise<TestResults | null> {
    if (!this.db) return null;

    const test = await this.getABTest(testId);
    if (!test) return null;

    // Get event data
    const result = await this.db.prepare(`
      SELECT
        variant_id,
        COUNT(DISTINCT CASE WHEN event_type = 'participation' THEN user_id END) as participants,
        COUNT(CASE WHEN event_type = 'conversion' THEN 1 END) as conversions,
        SUM(CASE WHEN event_type = 'conversion' THEN value ELSE 0 END) as conversion_value
      FROM ab_test_events
      WHERE test_id = ?
      GROUP BY variant_id
    `).bind(testId).all();

    const variantStats = new Map<string, any>();
    for (const row of result.results || []) {
      variantStats.set(row.variant_id as string, row);
    }

    // Calculate statistical significance
    // Simplified - in production use proper statistical tests
    let maxConversionRate = 0;
    let winner = '';

    for (const variant of test.variants) {
      const stats = variantStats.get(variant.id);
      if (stats) {
        variant.participants = stats.participants as number;
        variant.conversions = stats.conversions as number;

        const conversionRate = variant.participants > 0
          ? variant.conversions / variant.participants
          : 0;

        if (conversionRate > maxConversionRate) {
          maxConversionRate = conversionRate;
          winner = variant.id;
        }
      }
    }

    // Simple confidence calculation
    const totalParticipants = test.variants.reduce((sum, v) => sum + v.participants, 0);
    const confidence = totalParticipants > 100 ? 0.95 : totalParticipants / 100 * 0.95;

    return {
      winner,
      confidence,
      uplift: maxConversionRate,
      significanceLevel: 0.05
    };
  }

  /**
   * Register change listener
   */
  onConfigChange(key: string, listener: ConfigChangeListener): () => void {
    const listeners = this.changeListeners.get(key) || new Set();
    listeners.add(listener);
    this.changeListeners.set(key, listeners);

    // Return unsubscribe function
    return () => {
      listeners.delete(listener);
      if (listeners.size === 0) {
        this.changeListeners.delete(key);
      }
    };
  }

  /**
   * Private helper methods
   */

  private async loadConfiguration(): Promise<void> {
    if (!this.db) return;

    try {
      // Load configurations
      const configs = await this.db.prepare(`
        SELECT * FROM configurations
        ORDER BY updated_at DESC
        LIMIT 100
      `).all();

      for (const row of configs.results || []) {
        const config: ConfigValue = {
          key: row.key as string,
          value: JSON.parse(row.value as string),
          type: row.type as any,
          description: row.description as string | undefined,
          constraints: row.constraints ? JSON.parse(row.constraints as string) : undefined,
          version: row.version as number,
          updatedAt: row.updated_at as number,
          updatedBy: row.updated_by as string | undefined
        };
        this.configCache.set(config.key, config);
      }

      // Load feature flags
      const flags = await this.db.prepare(`
        SELECT * FROM feature_flags
        WHERE enabled = 1
      `).all();

      for (const row of flags.results || []) {
        const flag: FeatureFlag = {
          key: row.key as string,
          enabled: (row.enabled as number) === 1,
          rolloutPercentage: row.rollout_percentage as number,
          conditions: row.conditions ? JSON.parse(row.conditions as string) : [],
          variants: row.variants ? JSON.parse(row.variants as string) : [],
          metadata: row.metadata ? JSON.parse(row.metadata as string) : {},
          createdAt: row.created_at as number,
          updatedAt: row.updated_at as number
        };
        this.flagCache.set(flag.key, flag);
      }

      this.lastCacheUpdate = Date.now();
      this.logger.info('Configuration loaded', {
        configs: this.configCache.size,
        flags: this.flagCache.size
      });

    } catch (error: any) {
      this.logger.error('Failed to load configuration', error);
    }
  }

  private async loadConfigValue(key: string): Promise<ConfigValue | null> {
    // Try KV first
    const kvData = await this.kv.get(`config:${key}`, 'json');
    if (kvData) {
      return kvData as ConfigValue;
    }

    // Try database
    if (this.db) {
      const result = await this.db.prepare(`
        SELECT * FROM configurations WHERE key = ?
      `).bind(key).first();

      if (result) {
        return {
          key: result.key as string,
          value: JSON.parse(result.value as string),
          type: result.type as any,
          description: result.description as string | undefined,
          constraints: result.constraints ? JSON.parse(result.constraints as string) : undefined,
          version: result.version as number,
          updatedAt: result.updated_at as number,
          updatedBy: result.updated_by as string | undefined
        };
      }
    }

    return null;
  }

  private async getFeatureFlag(key: string): Promise<FeatureFlag | null> {
    // Check cache
    let flag = this.flagCache.get(key);

    if (!flag || this.isCacheExpired()) {
      // Load from KV
      const kvData = await this.kv.get(`flag:${key}`, 'json');
      if (kvData) {
        flag = kvData as FeatureFlag;
        this.flagCache.set(key, flag);
      }
    }

    return flag || null;
  }

  private async getABTest(testId: string): Promise<ABTest | null> {
    // Check cache
    let test = this.testCache.get(testId);

    if (!test) {
      // Load from KV
      const kvData = await this.kv.get(`abtest:${testId}`, 'json');
      if (kvData) {
        test = kvData as ABTest;
        this.testCache.set(testId, test);
      }
    }

    return test || null;
  }

  private async getOverride(
    key: string,
    context: ConfigContext
  ): Promise<any | undefined> {
    if (!this.db) return undefined;

    const result = await this.db.prepare(`
      SELECT value FROM configuration_overrides
      WHERE key = ? AND business_id = ?
      ORDER BY priority DESC
      LIMIT 1
    `).bind(key, context.businessId || '').first();

    if (result) {
      return JSON.parse(result.value as string);
    }

    return undefined;
  }

  private async recordTestParticipation(
    testId: string,
    variantId: string,
    context: ConfigContext
  ): Promise<void> {
    if (!this.db) return;

    await this.db.prepare(`
      INSERT OR IGNORE INTO ab_test_events (
        test_id, variant_id, event_type, business_id,
        user_id, value, timestamp
      ) VALUES (?, ?, 'participation', ?, ?, 0, ?)
    `).bind(
      testId,
      variantId,
      context.businessId || null,
      context.userId || null,
      Date.now()
    ).run();
  }

  private evaluateConditions(
    conditions: FlagCondition[],
    context: ConfigContext
  ): boolean {
    for (const condition of conditions) {
      const contextValue = this.getContextValue(condition.type, context);

      if (!contextValue) {
        return false;
      }

      const matches = this.evaluateCondition(condition, contextValue);
      if (!matches) {
        return false;
      }
    }

    return true;
  }

  private getContextValue(
    type: FlagCondition['type'],
    context: ConfigContext
  ): string | undefined {
    switch (type) {
      case 'user':
        return context.userId;
      case 'business':
        return context.businessId;
      case 'department':
        return context.department;
      case 'custom':
        return context.metadata?.customValue;
      default:
        return undefined;
    }
  }

  private evaluateCondition(
    condition: FlagCondition,
    value: string
  ): boolean {
    switch (condition.operator) {
      case 'in':
        return condition.values.includes(value);
      case 'not_in':
        return !condition.values.includes(value);
      case 'equals':
        return condition.values[0] === value;
      case 'contains':
        return condition.values.some(v => value.includes(v));
      default:
        return false;
    }
  }

  private validateConstraints(value: any, constraints: ConfigConstraints): void {
    if (constraints.required && value === undefined) {
      throw new Error('Value is required');
    }

    if (typeof value === 'number') {
      if (constraints.min !== undefined && value < constraints.min) {
        throw new Error(`Value must be at least ${constraints.min}`);
      }
      if (constraints.max !== undefined && value > constraints.max) {
        throw new Error(`Value must be at most ${constraints.max}`);
      }
    }

    if (constraints.enum && !constraints.enum.includes(value)) {
      throw new Error(`Value must be one of: ${constraints.enum.join(', ')}`);
    }

    if (constraints.pattern && typeof value === 'string') {
      const regex = new RegExp(constraints.pattern);
      if (!regex.test(value)) {
        throw new Error(`Value does not match pattern: ${constraints.pattern}`);
      }
    }
  }

  private detectType(value: any): ConfigValue['type'] {
    if (Array.isArray(value)) return 'array';
    if (value === null || value === undefined) return 'object';
    if (typeof value === 'object') return 'object';
    if (typeof value === 'string') return 'string';
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';
    return 'string';
  }

  private hashContext(context: ConfigContext): number {
    const str = `${context.businessId || ''}:${context.userId || ''}:${context.department || ''}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash;
  }

  private isCacheExpired(): boolean {
    return Date.now() - this.lastCacheUpdate > this.cacheExpiry;
  }

  private notifyListeners(key: string, value: any, config: ConfigValue): void {
    const listeners = this.changeListeners.get(key);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(value, config);
        } catch (error: any) {
          this.logger.error('Config change listener failed', error, { key });
        }
      }
    }
  }
}

type ConfigChangeListener = (value: any, config: ConfigValue) => void;