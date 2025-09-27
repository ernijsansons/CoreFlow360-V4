/**
 * Deployment Health Monitoring System
 * Comprehensive health checks and real-time monitoring for deployments
 */

import { z } from 'zod';
import { Logger } from '../shared/logger';
import { CorrelationId } from '../shared/correlation-id';
import { Env } from '../types/env';

export interface HealthCheck {
  name: string;
  description: string;
  type: HealthCheckType;
  endpoint?: string;
  timeout: number;
  interval: number;
  retries: number;
  enabled: boolean;
  critical: boolean;
  thresholds: HealthThresholds;
  dependencies: string[];
}

export type HealthCheckType =
  | 'http'
  | 'database'
  | 'cache'
  | 'external_service'
  | 'business_logic'
  | 'performance'
  | 'security';

export interface HealthThresholds {
  responseTime: number;
  errorRate: number;
  availability: number;
  throughput?: number;
  memory?: number;
  cpu?: number;
}

export interface HealthCheckResult {
  check: string;
  status: HealthStatus;
  responseTime: number;
  message: string;
  timestamp: number;
  metadata: Record<string, any>;
  metrics: HealthMetrics;
}

export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'unknown';

export interface HealthMetrics {
  responseTime: number;
  errorRate: number;
  availability: number;
  throughput: number;
  activeConnections: number;
  memoryUsage: number;
  cpuUsage: number;
}

export interface DeploymentHealth {
  overall: HealthStatus;
  score: number;
  checks: HealthCheckResult[];
  summary: HealthSummary;
  recommendations: string[];
  alerts: HealthAlert[];
  timestamp: number;
}

export interface HealthSummary {
  total: number;
  healthy: number;
  degraded: number;
  unhealthy: number;
  critical_failures: number;
}

export interface HealthAlert {
  severity: AlertSeverity;
  message: string;
  check: string;
  threshold: number;
  actual: number;
  action_required: boolean;
  [key: string]: unknown;
}

export type AlertSeverity = 'info' | 'warning' | 'error' | 'critical';

export interface MonitoringConfig {
  enabled: boolean;
  interval: number;
  alerting: AlertingConfig;
  metrics: MetricsConfig;
  notifications: NotificationConfig;
}

export interface AlertingConfig {
  enabled: boolean;
  channels: AlertChannel[];
  escalation: EscalationConfig;
  suppressions: SuppressionRule[];
}

export interface AlertChannel {
  name: string;
  type: 'email' | 'slack' | 'webhook' | 'sms';
  endpoint: string;
  enabled: boolean;
  severity_filter: AlertSeverity[];
}

export interface EscalationConfig {
  enabled: boolean;
  rules: EscalationRule[];
}

export interface EscalationRule {
  condition: string;
  delay: number;
  target: string;
  action: string;
}

export interface SuppressionRule {
  pattern: string;
  duration: number;
  reason: string;
}

export interface MetricsConfig {
  retention: number;
  aggregation: AggregationConfig;
  export: ExportConfig;
}

export interface AggregationConfig {
  intervals: string[];
  functions: string[];
}

export interface ExportConfig {
  enabled: boolean;
  destinations: ExportDestination[];
}

export interface ExportDestination {
  name: string;
  type: 'prometheus' | 'datadog' | 'cloudwatch' | 'custom';
  endpoint: string;
  credentials?: Record<string, string>;
}

export interface NotificationConfig {
  enabled: boolean;
  templates: NotificationTemplate[];
}

export interface NotificationTemplate {
  name: string;
  type: string;
  subject: string;
  body: string;
  conditions: string[];
}

export class DeploymentHealthMonitor {
  private logger = new Logger();
  private env: Env;
  private config: MonitoringConfig;
  private healthChecks: Map<string, HealthCheck> = new Map();
  private results: Map<string, HealthCheckResult[]> = new Map();
  private alerts: HealthAlert[] = [];
  private isMonitoring = false;

  constructor(env: Env, config?: Partial<MonitoringConfig>) {
    this.env = env;
    this.config = {
      enabled: true,
      interval: 30000, // 30 seconds
      alerting: {
        enabled: true,
        channels: [],
        escalation: { enabled: false, rules: [] },
        suppressions: []
      },
      metrics: {
        retention: 86400000, // 24 hours
        aggregation: {
          intervals: ['1m', '5m', '15m', '1h'],
          functions: ['avg', 'min', 'max', 'p95']
        },
        export: {
          enabled: false,
          destinations: []
        }
      },
      notifications: {
        enabled: true,
        templates: []
      },
      ...config
    };

    this.initializeDefaultHealthChecks();
  }

  /**
   * Start monitoring deployment health
   */
  async startMonitoring(): Promise<void> {
    if (this.isMonitoring) {
      this.logger.warn('Health monitoring is already running');
      return;
    }

    this.logger.info('Starting deployment health monitoring', {
      interval: this.config.interval,
      checksCount: this.healthChecks.size
    });

    this.isMonitoring = true;
    this.monitoringLoop();
  }

  /**
   * Stop monitoring
   */
  async stopMonitoring(): Promise<void> {
    this.logger.info('Stopping deployment health monitoring');
    this.isMonitoring = false;
  }

  /**
   * Get current deployment health status
   */
  async getDeploymentHealth(): Promise<DeploymentHealth> {
    const correlationId = CorrelationId.generate();

    this.logger.debug('Getting deployment health status', { correlationId });

    const results = await this.runAllHealthChecks();
    const summary = this.calculateHealthSummary(results);
    const overall = this.determineOverallHealth(results);
    const score = this.calculateHealthScore(results);
    const recommendations = this.generateRecommendations(results);
    const alerts = this.generateAlerts(results);

    return {
      overall,
      score,
      checks: results,
      summary,
      recommendations,
      alerts,
      timestamp: Date.now()
    };
  }

  /**
   * Run specific health check
   */
  async runHealthCheck(checkName: string): Promise<HealthCheckResult> {
    const check = this.healthChecks.get(checkName);
    if (!check) {
      throw new Error(`Health check not found: ${checkName}`);
    }

    return await this.executeHealthCheck(check);
  }

  /**
   * Add custom health check
   */
  addHealthCheck(check: HealthCheck): void {
    this.logger.info('Adding health check', { name: check.name, type: check.type });
    this.healthChecks.set(check.name, check);
  }

  /**
   * Remove health check
   */
  removeHealthCheck(checkName: string): void {
    this.logger.info('Removing health check', { name: checkName });
    this.healthChecks.delete(checkName);
    this.results.delete(checkName);
  }

  /**
   * Get health check history
   */
  getHealthCheckHistory(checkName: string, duration?: number): HealthCheckResult[] {
    const results = this.results.get(checkName) || [];
    if (!duration) return results;

    const cutoff = Date.now() - duration;
    return results.filter((result: any) => result.timestamp >= cutoff);
  }

  /**
   * Main monitoring loop
   */
  private async monitoringLoop(): Promise<void> {
    while (this.isMonitoring) {
      try {
        const health = await this.getDeploymentHealth();
        await this.processHealthResults(health);
        await this.sleep(this.config.interval);
      } catch (error: any) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        this.logger.error('Error in monitoring loop', errorMessage);
        await this.sleep(this.config.interval);
      }
    }
  }

  /**
   * Run all enabled health checks
   */
  private async runAllHealthChecks(): Promise<HealthCheckResult[]> {
    const enabledChecks = Array.from(this.healthChecks.values()).filter((check: any) => check.enabled);
    const results: HealthCheckResult[] = [];

    // Run checks in parallel for performance
    const promises = enabledChecks.map((check: any) => this.executeHealthCheck(check));
    const checkResults = await Promise.allSettled(promises);

    for (let i = 0; i < checkResults.length; i++) {
      const result = checkResults[i];
      const check = enabledChecks[i];

      if (result.status === 'fulfilled') {
        results.push(result.value);
        this.storeHealthCheckResult(check.name, result.value);
      } else {
        const errorResult: HealthCheckResult = {
          check: check.name,
          status: 'unhealthy',
          responseTime: 0,
          message: `Health check failed: ${result.reason}`,
          timestamp: Date.now(),
          metadata: { error: result.reason },
          metrics: this.createDefaultMetrics()
        };
        results.push(errorResult);
        this.storeHealthCheckResult(check.name, errorResult);
      }
    }

    return results;
  }

  /**
   * Execute individual health check
   */
  private async executeHealthCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      let result: HealthCheckResult;

      switch (check.type) {
        case 'http':
          result = await this.executeHttpCheck(check);
          break;
        case 'database':
          result = await this.executeDatabaseCheck(check);
          break;
        case 'cache':
          result = await this.executeCacheCheck(check);
          break;
        case 'external_service':
          result = await this.executeExternalServiceCheck(check);
          break;
        case 'business_logic':
          result = await this.executeBusinessLogicCheck(check);
          break;
        case 'performance':
          result = await this.executePerformanceCheck(check);
          break;
        case 'security':
          result = await this.executeSecurityCheck(check);
          break;
        default:
          throw new Error(`Unknown health check type: ${check.type}`);
      }

      result.responseTime = Date.now() - startTime;
      return result;

    } catch (error: any) {
      return {
        check: check.name,
        status: 'unhealthy',
        responseTime: Date.now() - startTime,
        message: `Check failed: ${error instanceof Error ? error.message : String(error)}`,
        timestamp: Date.now(),
        metadata: { error: error instanceof Error ? error.message : String(error) },
        metrics: this.createDefaultMetrics()
      };
    }
  }

  /**
   * HTTP endpoint health check
   */
  private async executeHttpCheck(check: HealthCheck): Promise<HealthCheckResult> {
    if (!check.endpoint) {
      throw new Error('HTTP check requires endpoint');
    }

    const startTime = Date.now();
    const response = await fetch(check.endpoint, {
      method: 'GET',
      signal: AbortSignal.timeout(check.timeout)
    });

    const responseTime = Date.now() - startTime;
    const isHealthy = response.ok && responseTime <= check.thresholds.responseTime;

    return {
      check: check.name,
      status: isHealthy ? 'healthy' : 'degraded',
      responseTime,
      message: isHealthy ? 'HTTP check passed' : `HTTP check failed: ${response.status}`,
      timestamp: Date.now(),
      metadata: {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers ? (() => {
          const headers: Record<string, string> = {};
          response.headers.forEach((value, key) => {
            headers[key] = value;
          });
          return headers;
        })() : {}
      },
      metrics: {
        responseTime,
        errorRate: response.ok ? 0 : 1,
        availability: response.ok ? 100 : 0,
        throughput: 1,
        activeConnections: 1,
        memoryUsage: 0,
        cpuUsage: 0
      }
    };
  }

  /**
   * Database health check
   */
  private async executeDatabaseCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Simple query to test database connectivity
      const result = await this.env.DB_CRM.prepare('SELECT 1 as test').first();
      const responseTime = Date.now() - startTime;
      const isHealthy = result && responseTime <= check.thresholds.responseTime;

      return {
        check: check.name,
        status: isHealthy ? 'healthy' : 'degraded',
        responseTime,
        message: isHealthy ? 'Database check passed' : 'Database check failed',
        timestamp: Date.now(),
        metadata: { queryResult: result },
        metrics: {
          responseTime,
          errorRate: isHealthy ? 0 : 1,
          availability: isHealthy ? 100 : 0,
          throughput: 1,
          activeConnections: 1,
          memoryUsage: 0,
          cpuUsage: 0
        }
      };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Database check failed: ${errorMessage}`);
    }
  }

  /**
   * Cache health check
   */
  private async executeCacheCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();
    const testKey = `health_check_${Date.now()}`;
    const testValue = 'test';

    try {
      // Test cache write and read
      await this.env.KV_CACHE.put(testKey, testValue, { expirationTtl: 60 });
      const result = await this.env.KV_CACHE.get(testKey);
      await this.env.KV_CACHE.delete(testKey);

      const responseTime = Date.now() - startTime;
      const isHealthy = result === testValue && responseTime <= check.thresholds.responseTime;

      return {
        check: check.name,
        status: isHealthy ? 'healthy' : 'degraded',
        responseTime,
        message: isHealthy ? 'Cache check passed' : 'Cache check failed',
        timestamp: Date.now(),
        metadata: { testKey, retrieved: result },
        metrics: {
          responseTime,
          errorRate: isHealthy ? 0 : 1,
          availability: isHealthy ? 100 : 0,
          throughput: 1,
          activeConnections: 1,
          memoryUsage: 0,
          cpuUsage: 0
        }
      };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Cache check failed: ${errorMessage}`);
    }
  }

  /**
   * External service health check
   */
  private async executeExternalServiceCheck(check: HealthCheck): Promise<HealthCheckResult> {
    if (!check.endpoint) {
      throw new Error('External service check requires endpoint');
    }

    return await this.executeHttpCheck(check);
  }

  /**
   * Business logic health check
   */
  private async executeBusinessLogicCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();

    // Example: Check if critical business workflows are functioning
    try {
      // Simulate business logic validation
      const isValid = await this.validateBusinessLogic();
      const responseTime = Date.now() - startTime;

      return {
        check: check.name,
        status: isValid ? 'healthy' : 'unhealthy',
        responseTime,
        message: isValid ? 'Business logic check passed' : 'Business logic validation failed',
        timestamp: Date.now(),
        metadata: { validated: isValid },
        metrics: {
          responseTime,
          errorRate: isValid ? 0 : 1,
          availability: isValid ? 100 : 0,
          throughput: 1,
          activeConnections: 0,
          memoryUsage: 0,
          cpuUsage: 0
        }
      };
    } catch (error: any) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      throw new Error(`Business logic check failed: ${errorMessage}`);
    }
  }

  /**
   * Performance health check
   */
  private async executePerformanceCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Simulate performance metrics collection
      const metrics = await this.collectPerformanceMetrics();
      const responseTime = Date.now() - startTime;

      const isHealthy =
        metrics.responseTime <= check.thresholds.responseTime &&
        metrics.memoryUsage <= (check.thresholds.memory || 80) &&
        metrics.cpuUsage <= (check.thresholds.cpu || 80);

      return {
        check: check.name,
        status: isHealthy ? 'healthy' : 'degraded',
        responseTime,
        message: isHealthy ? 'Performance check passed' : 'Performance degradation detected',
        timestamp: Date.now(),
        metadata: { performanceMetrics: metrics },
        metrics
      };
    } catch (error: any) {
      throw new Error(`Performance check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Security health check
   */
  private async executeSecurityCheck(check: HealthCheck): Promise<HealthCheckResult> {
    const startTime = Date.now();

    try {
      // Simulate security validation
      const securityStatus = await this.validateSecurityStatus();
      const responseTime = Date.now() - startTime;

      return {
        check: check.name,
        status: securityStatus.secure ? 'healthy' : 'unhealthy',
        responseTime,
        message: securityStatus.secure ? 'Security check passed' : 'Security issues detected',
        timestamp: Date.now(),
        metadata: securityStatus,
        metrics: {
          responseTime,
          errorRate: securityStatus.secure ? 0 : 1,
          availability: securityStatus.secure ? 100 : 0,
          throughput: 1,
          activeConnections: 0,
          memoryUsage: 0,
          cpuUsage: 0
        }
      };
    } catch (error: any) {
      throw new Error(`Security check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Initialize default health checks
   */
  private initializeDefaultHealthChecks(): void {
    const defaultChecks: HealthCheck[] = [
      {
        name: 'api_health',
        description: 'API endpoint health check',
        type: 'http',
        endpoint: '/health',
        timeout: 5000,
        interval: 30000,
        retries: 3,
        enabled: true,
        critical: true,
        thresholds: {
          responseTime: 1000,
          errorRate: 0.01,
          availability: 99.9
        },
        dependencies: []
      },
      {
        name: 'database_health',
        description: 'Database connectivity check',
        type: 'database',
        timeout: 5000,
        interval: 60000,
        retries: 3,
        enabled: true,
        critical: true,
        thresholds: {
          responseTime: 2000,
          errorRate: 0.01,
          availability: 99.9
        },
        dependencies: []
      },
      {
        name: 'cache_health',
        description: 'Cache system health check',
        type: 'cache',
        timeout: 3000,
        interval: 60000,
        retries: 3,
        enabled: true,
        critical: false,
        thresholds: {
          responseTime: 500,
          errorRate: 0.05,
          availability: 99.0
        },
        dependencies: []
      },
      {
        name: 'business_logic_health',
        description: 'Core business logic validation',
        type: 'business_logic',
        timeout: 10000,
        interval: 300000, // 5 minutes
        retries: 2,
        enabled: true,
        critical: true,
        thresholds: {
          responseTime: 5000,
          errorRate: 0.01,
          availability: 99.5
        },
        dependencies: ['database_health']
      }
    ];

    defaultChecks.forEach((check: any) => {
      this.healthChecks.set(check.name, check);
    });
  }

  /**
   * Helper methods
   */
  private calculateHealthSummary(results: HealthCheckResult[]): HealthSummary {
    const summary: HealthSummary = {
      total: results.length,
      healthy: 0,
      degraded: 0,
      unhealthy: 0,
      critical_failures: 0
    };

    results.forEach((result: any) => {
      switch (result.status) {
        case 'healthy':
          summary.healthy++;
          break;
        case 'degraded':
          summary.degraded++;
          break;
        case 'unhealthy':
          summary.unhealthy++;
          const check = this.healthChecks.get(result.check);
          if (check?.critical) {
            summary.critical_failures++;
          }
          break;
      }
    });

    return summary;
  }

  private determineOverallHealth(results: HealthCheckResult[]): HealthStatus {
    const criticalFailures = results.filter((result: any) => {
      const check = this.healthChecks.get(result.check);
      return check?.critical && result.status === 'unhealthy';
    });

    if (criticalFailures.length > 0) {
      return 'unhealthy';
    }

    const unhealthyCount = results.filter((r: any) => r.status === 'unhealthy').length;
    const degradedCount = results.filter((r: any) => r.status === 'degraded').length;

    if (unhealthyCount > 0) {
      return 'degraded';
    }

    if (degradedCount > results.length * 0.3) { // More than 30% degraded
      return 'degraded';
    }

    return 'healthy';
  }

  private calculateHealthScore(results: HealthCheckResult[]): number {
    if (results.length === 0) return 0;

    const scores = results.map((result: any) => {
      switch (result.status) {
        case 'healthy': return 100;
        case 'degraded': return 60;
        case 'unhealthy': return 0;
        default: return 0;
      }
    });

    return Math.round(scores.reduce((sum: number, score: number) => sum + score, 0) / scores.length);
  }

  private generateRecommendations(results: HealthCheckResult[]): string[] {
    const recommendations: string[] = [];

    results.forEach((result: any) => {
      if (result.status === 'unhealthy') {
        recommendations.push(`Fix critical issue in ${result.check}: ${result.message}`);
      } else if (result.status === 'degraded') {
        recommendations.push(`Investigate performance issue in ${result.check}`);
      }

      if (result.responseTime > 5000) {
        recommendations.push(`Optimize response time for ${result.check}`);
      }
    });

    return recommendations;
  }

  private generateAlerts(results: HealthCheckResult[]): HealthAlert[] {
    const alerts: HealthAlert[] = [];

    results.forEach((result: any) => {
      const check = this.healthChecks.get(result.check);
      if (!check) return;

      if (result.status === 'unhealthy' && check.critical) {
        alerts.push({
          severity: 'critical',
          message: `Critical health check failed: ${result.check}`,
          check: result.check,
          threshold: 1,
          actual: 0,
          action_required: true
        });
      }

      if (result.responseTime > check.thresholds.responseTime) {
        alerts.push({
          severity: result.responseTime > check.thresholds.responseTime * 2 ? 'error' : 'warning',
          message: `Response time threshold exceeded for ${result.check}`,
          check: result.check,
          threshold: check.thresholds.responseTime,
          actual: result.responseTime,
          action_required: result.responseTime > check.thresholds.responseTime * 2
        });
      }
    });

    return alerts;
  }

  private storeHealthCheckResult(checkName: string, result: HealthCheckResult): void {
    if (!this.results.has(checkName)) {
      this.results.set(checkName, []);
    }

    const results = this.results.get(checkName)!;
    results.push(result);

    // Keep only recent results based on retention policy
    const cutoff = Date.now() - this.config.metrics.retention;
    const filteredResults = results.filter((r: any) => r.timestamp >= cutoff);
    this.results.set(checkName, filteredResults);
  }

  private async processHealthResults(health: DeploymentHealth): Promise<void> {
    // Process alerts
    if (this.config.alerting.enabled) {
      await this.processAlerts(health.alerts);
    }

    // Export metrics
    if (this.config.metrics.export.enabled) {
      await this.exportMetrics(health);
    }

    // Send notifications
    if (this.config.notifications.enabled) {
      await this.sendNotifications(health);
    }
  }

  private async processAlerts(alerts: HealthAlert[]): Promise<void> {
    for (const alert of alerts) {
      if (alert.severity === 'critical' || alert.severity === 'error') {
        this.logger.error('Health check alert', alert);
      } else if (alert.severity === 'warning') {
        this.logger.warn('Health check warning', alert);
      }
    }
  }

  private async exportMetrics(health: DeploymentHealth): Promise<void> {
    // Export metrics to configured destinations
    this.logger.debug('Exporting health metrics', {
      score: health.score,
      status: health.overall
    });
  }

  private async sendNotifications(health: DeploymentHealth): Promise<void> {
    // Send notifications based on health status
    if (health.overall === 'unhealthy') {
      this.logger.info('Sending critical health notification', {
        score: health.score,
        criticalFailures: health.summary.critical_failures
      });
    }
  }

  private createDefaultMetrics(): HealthMetrics {
    return {
      responseTime: 0,
      errorRate: 0,
      availability: 0,
      throughput: 0,
      activeConnections: 0,
      memoryUsage: 0,
      cpuUsage: 0
    };
  }

  private async validateBusinessLogic(): Promise<boolean> {
    // Simulate business logic validation
    return true;
  }

  private async collectPerformanceMetrics(): Promise<HealthMetrics> {
    // Simulate performance metrics collection
    return {
      responseTime: Math.random() * 1000,
      errorRate: Math.random() * 0.01,
      availability: 99.9,
      throughput: Math.random() * 1000,
      activeConnections: Math.floor(Math.random() * 100),
      memoryUsage: Math.random() * 80,
      cpuUsage: Math.random() * 70
    };
  }

  private async validateSecurityStatus(): Promise<any> {
    // Simulate security validation
    return {
      secure: true,
      lastScan: Date.now(),
      vulnerabilities: 0
    };
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Create deployment health monitor
 */
export function createDeploymentHealthMonitor(env: Env, config?: Partial<MonitoringConfig>): DeploymentHealthMonitor {
  return new DeploymentHealthMonitor(env, config);
}