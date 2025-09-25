/**
 * Application Startup Validator
 * Validates all critical environment and configuration before startup
 */

import { EnvironmentValidator } from './environment-validator';
import { SecurityError } from './error-handler';
import type { Env } from '../types/env';

export class StartupValidator {
  /**
   * Validates the entire application environment and configuration
   */
  static validateAppStartup(env: Env): void {

    try {
      // Validate environment variables
      const { required, optional } = EnvironmentValidator.validate(env);

      // Validate database connections
      this.validateDatabaseBindings(env);

      // Validate KV namespaces
      this.validateKVBindings(env);

      // Validate Durable Objects
      this.validateDurableObjectBindings(env);

      // Validate external service bindings
      this.validateServiceBindings(env);


    } catch (error) {
      throw new SecurityError('Application startup validation failed', {
        code: 'STARTUP_VALIDATION_FAILED',
        originalError: error instanceof Error ? error.message : String(error)
      });
    }
  }

  /**
   * Validates database bindings are present
   */
  private static validateDatabaseBindings(env: Env): void {
    const requiredDatabases = ['DB_MAIN'];
    const optionalDatabases = ['DB', 'DB_ANALYTICS'];

    for (const dbName of requiredDatabases) {
      if (!env[dbName as keyof Env]) {
        throw new SecurityError(`Required database binding missing: ${dbName}`);
      }
    }

    const configuredOptional = optionalDatabases.filter(db => env[db as keyof Env]);
  }

  /**
   * Validates KV namespace bindings are present
   */
  private static validateKVBindings(env: Env): void {
    const requiredKV = ['KV_SESSION'];
    const optionalKV = ['KV_CACHE', 'KV_CONFIG', 'WORKFLOW_STORAGE', 'SSE_METRICS'];

    for (const kvName of requiredKV) {
      if (!env[kvName as keyof Env]) {
        throw new SecurityError(`Required KV namespace binding missing: ${kvName}`);
      }
    }

    const configuredOptional = optionalKV.filter(kv => env[kv as keyof Env]);
  }

  /**
   * Validates Durable Object bindings are present
   */
  private static validateDurableObjectBindings(env: Env): void {
    const requiredDOs = ['USER_SESSION'];
    const optionalDOs = [
      'WORKFLOW_ENGINE',
      'WORKFLOW_ORCHESTRATOR',
      'SSE_STREAM_MANAGER',
      'REALTIME_SYNC',
      'DASHBOARD_STREAM',
      'WORKFLOW_EXECUTOR',
      'WORKFLOW_COLLABORATION'
    ];

    for (const doName of requiredDOs) {
      if (!env[doName as keyof Env]) {
        throw new SecurityError(`Required Durable Object binding missing: ${doName}`);
      }
    }

    const configuredOptional = optionalDOs.filter(dobj => env[dobj as keyof Env]);
  }

  /**
   * Validates external service bindings
   */
  private static validateServiceBindings(env: Env): void {
    const requiredServices: string[] = [];
    const optionalServices = ['AUTH_SERVICE', 'NOTIFICATION_SERVICE'];

    for (const serviceName of requiredServices) {
      if (!env[serviceName as keyof Env]) {
        throw new SecurityError(`Required service binding missing: ${serviceName}`);
      }
    }

    const configuredOptional = optionalServices.filter(service => env[service as keyof Env]);
  }

  /**
   * Validates AI and analytics bindings
   */
  private static validateAIBindings(env: Env): void {
    if (!env.AI) {
    }

    if (!env.ANALYTICS) {
    }
  }

  /**
   * Validates queue bindings
   */
  private static validateQueueBindings(env: Env): void {
    const requiredQueues: string[] = [];
    const optionalQueues = ['TASK_QUEUE', 'EMAIL_QUEUE', 'WEBHOOK_QUEUE'];

    for (const queueName of requiredQueues) {
      if (!env[queueName as keyof Env]) {
        throw new SecurityError(`Required queue binding missing: ${queueName}`);
      }
    }

    const configuredOptional = optionalQueues.filter(queue => env[queue as keyof Env]);
  }

  /**
   * Performance validation check
   */
  static validatePerformanceConfig(env: Env): void {
    const warnings: string[] = [];

    // Check log level for performance impact
    if (env.LOG_LEVEL === 'debug' && env.ENVIRONMENT === 'production') {
      warnings.push('Debug logging in production may impact performance');
    }

    // Validate cache configuration
    if (!env.KV_CACHE && env.ENVIRONMENT === 'production') {
      warnings.push('No cache binding configured - performance may be degraded');
    }

    if (warnings.length > 0) {
    }
  }

  /**
   * Security validation check
   */
  static validateSecurityConfig(env: Env): void {
    const warnings: string[] = [];

    // Check for development mode in production
    if (env.ENVIRONMENT === 'production') {
      if (env.LOG_LEVEL === 'debug') {
        warnings.push('Debug logging in production may leak sensitive information');
      }
    }

    // Check for missing security features
    if (!env.RATE_LIMITER) {
      warnings.push('Rate limiter not configured - DoS protection may be limited');
    }

    if (warnings.length > 0) {
    }
  }

  /**
   * Complete validation with all checks
   */
  static validateComplete(env: Env): void {
    this.validateAppStartup(env);
    this.validateAIBindings(env);
    this.validateQueueBindings(env);
    this.validatePerformanceConfig(env);
    this.validateSecurityConfig(env);

  }
}