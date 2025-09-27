/**
 * Comprehensive Monitoring and Observability Service
 * Collects metrics, traces, and logs for system health monitoring
 */

import { Logger } from './logger';
import { correlationManager, TraceSpan, TraceContext } from './correlation-id';
import { circuitBreakerRegistry } from './circuit-breaker';

export interface MetricPoint {
  name: string;
  value: number;
  timestamp: number;
  tags: Record<string, string>;
  type: 'counter' | 'gauge' | 'histogram' | 'timer';
}

export interface Alert {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  threshold: number;
  currentValue: number;
  triggeredAt: number;
  resolvedAt?: number;
  correlationId?: string;
  metadata: Record<string, any>;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  score: number; // 0-100
  checks: Array<{
    name: string;
    status: 'pass' | 'warn' | 'fail';
    latency?: number;
    message?: string;
    details?: Record<string, any>;
  }>;
  timestamp: number;
}

export interface PerformanceMetrics {
  requestsPerSecond: number;
  averageLatency: number;
  p95Latency: number;
  p99Latency: number;
  errorRate: number;
  activeConnections: number;
  memoryUsage?: number;
  cpuUsage?: number;
}

export // TODO: Consider splitting MonitoringService into smaller, focused classes
class MonitoringService {
  private static instance: MonitoringService;
  private logger: Logger;
  private metrics: Map<string, MetricPoint[]> = new Map();
  private alerts: Map<string, Alert> = new Map();
  private healthChecks: Map<string, () => Promise<boolean>> = new Map();
  private performanceBuffer: Array<{ timestamp: number; latency: number; success: boolean }> = [];
  private readonly MAX_METRIC_POINTS = 1000;
  private readonly MAX_PERFORMANCE_BUFFER = 500;

  private constructor() {
    this.logger = new Logger();
    this.setupDefaultHealthChecks();
    this.startMetricCollection();
  }

  static getInstance(): MonitoringService {
    if (!this.instance) {
      this.instance = new MonitoringService();
    }
    return this.instance;
  }

  /**
   * Record a metric point
   */
  recordMetric(
    name: string,
    value: number,
    type: 'counter' | 'gauge' | 'histogram' | 'timer' = 'gauge',
    tags: Record<string, string> = {}
  ): void {
    const point: MetricPoint = {
      name,
      value,
      timestamp: Date.now(),
      tags,
      type
    };

    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }

    const points = this.metrics.get(name)!;
    points.push(point);

    // Keep only recent points
    if (points.length > this.MAX_METRIC_POINTS) {
      points.splice(0, points.length - this.MAX_METRIC_POINTS);
    }

    this.logger.debug('Metric recorded', {
      name,
      value,
      type,
      tags
    });
  }

  /**
   * Record request performance
   */
  recordRequest(latency: number, success: boolean, tags: Record<string, string> = {}): void {
    this.performanceBuffer.push({
      timestamp: Date.now(),
      latency,
      success
    });

    // Keep buffer size manageable
    if (this.performanceBuffer.length > this.MAX_PERFORMANCE_BUFFER) {
      this.performanceBuffer.shift();
    }

    // Record metrics
    this.recordMetric('request.latency', latency, 'timer', tags);
    this.recordMetric('request.count', 1, 'counter', {
      ...tags,
      status: success ? 'success' : 'error'
    });
  }

  /**
   * Create or update an alert
   */
  createAlert(
    name: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    message: string,
    threshold: number,
    currentValue: number,
    correlationId?: string,
    metadata: Record<string, any> = {}
  ): Alert {
    const id = `alert_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

    const alert: Alert = {
      id,
      name,
      severity,
      message,
      threshold,
      currentValue,
      triggeredAt: Date.now(),
      correlationId,
      metadata
    };

    this.alerts.set(id, alert);

    this.logger.warn(`${severity.toUpperCase()} ALERT: ${name}`, {
      alertId: id,
      message,
      threshold,
      currentValue,
      correlationId,
      metadata
    });

    return alert;
  }

  /**
   * Resolve an alert
   */
  resolveAlert(alertId: string): boolean {
    const alert = this.alerts.get(alertId);
    if (!alert || alert.resolvedAt) {
      return false;
    }

    alert.resolvedAt = Date.now();

    this.logger.info('Alert resolved', {
      alertId,
      name: alert.name,
      duration: alert.resolvedAt - alert.triggeredAt
    });

    return true;
  }

  /**
   * Get active alerts
   */
  getActiveAlerts(): Alert[] {
    return Array.from(this.alerts.values())
      .filter((alert: any) => !alert.resolvedAt)
      .sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return severityOrder[a.severity] - severityOrder[b.severity];
      });
  }

  /**
   * Get recent metrics for a specific metric name
   */
  getMetrics(name: string, limit: number = 100): MetricPoint[] {
    const points = this.metrics.get(name) || [];
    return points.slice(-limit);
  }

  /**
   * Get aggregated performance metrics
   */
  getPerformanceMetrics(timeWindowMs: number = 5 * 60 * 1000): PerformanceMetrics {
    const cutoff = Date.now() - timeWindowMs;
    const recentRequests = this.performanceBuffer.filter((r: any) => r.timestamp >= cutoff);

    if (recentRequests.length === 0) {
      return {
        requestsPerSecond: 0,
        averageLatency: 0,
        p95Latency: 0,
        p99Latency: 0,
        errorRate: 0,
        activeConnections: 0
      };
    }

    const latencies = recentRequests.map((r: any) => r.latency).sort((a, b) => a - b);
    const errors = recentRequests.filter((r: any) => !r.success).length;
    const timeSpanSeconds = timeWindowMs / 1000;

    return {
      requestsPerSecond: recentRequests.length / timeSpanSeconds,
      averageLatency: latencies.reduce((sum, l) => sum + l, 0) / latencies.length,
      p95Latency: latencies[Math.floor(latencies.length * 0.95)] || 0,
      p99Latency: latencies[Math.floor(latencies.length * 0.99)] || 0,
      errorRate: (errors / recentRequests.length) * 100,
      activeConnections: this.getActiveConnectionCount()
    };
  }

  /**
   * Perform comprehensive system health check
   */
  async performHealthCheck(): Promise<SystemHealth> {
    const checks: Array<{
      name: string;
      status: 'pass' | 'warn' | 'fail';
      latency?: number;
      message?: string;
      details?: Record<string, any>;
    }> = [];

    let totalScore = 0;
    let maxScore = 0;

    // Run all registered health checks
    for (const [name, checkFunction] of this.healthChecks) {
      const startTime = Date.now();
      maxScore += 100;

      try {
        const result = await Promise.race([
          checkFunction(),
          new Promise<boolean>((_, reject) =>
            setTimeout(() => reject(new Error('Health check timeout')), 10000)
          )
        ]);

        const latency = Date.now() - startTime;

        if (result) {
          checks.push({ name, status: 'pass', latency });
          totalScore += 100;
        } else {
          checks.push({ name, status: 'warn', latency, message: 'Check returned false' });
          totalScore += 50;
        }

      } catch (error: any) {
        const latency = Date.now() - startTime;
        checks.push({
          name,
          status: 'fail',
          latency,
          message: error instanceof Error ? error.message : 'Unknown error'
        });
        // No score added for failed checks
      }
    }

    // Check circuit breaker status
    const circuitBreakerHealth = circuitBreakerRegistry.getHealthStatus();
    maxScore += 100;

    if (circuitBreakerHealth.unhealthy.length === 0) {
      checks.push({
        name: 'circuit_breakers',
        status: 'pass',
        details: { healthyBreakers: circuitBreakerHealth.healthy.length }
      });
      totalScore += 100;
    } else {
      checks.push({
        name: 'circuit_breakers',
        status: 'warn',
        message: `${circuitBreakerHealth.unhealthy.length} circuit breakers unhealthy`,
        details: {
          healthy: circuitBreakerHealth.healthy,
          unhealthy: circuitBreakerHealth.unhealthy
        }
      });
      totalScore += 50;
    }

    // Check active alerts
    const activeAlerts = this.getActiveAlerts();
    const criticalAlerts = activeAlerts.filter((a: any) => a.severity === 'critical').length;
    const highAlerts = activeAlerts.filter((a: any) => a.severity === 'high').length;

    maxScore += 100;
    if (criticalAlerts === 0 && highAlerts === 0) {
      checks.push({
        name: 'alerts',
        status: 'pass',
        details: { totalAlerts: activeAlerts.length }
      });
      totalScore += 100;
    } else if (criticalAlerts === 0) {
      checks.push({
        name: 'alerts',
        status: 'warn',
        message: `${highAlerts} high-severity alerts active`,
        details: { highAlerts, totalAlerts: activeAlerts.length }
      });
      totalScore += 70;
    } else {
      checks.push({
        name: 'alerts',
        status: 'fail',
        message: `${criticalAlerts} critical alerts active`,
        details: { criticalAlerts, highAlerts, totalAlerts: activeAlerts.length }
      });
      // No score for critical alerts
    }

    const score = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
    let status: 'healthy' | 'degraded' | 'unhealthy';

    if (score >= 90) status = 'healthy';
    else if (score >= 70) status = 'degraded';
    else status = 'unhealthy';

    return {
      status,
      score,
      checks,
      timestamp: Date.now()
    };
  }

  /**
   * Register a custom health check
   */
  registerHealthCheck(name: string, checkFunction: () => Promise<boolean>): void {
    this.healthChecks.set(name, checkFunction);
    this.logger.debug('Health check registered', { name });
  }

  /**
   * Get system overview with key metrics
   */
  getSystemOverview(): {
    health: SystemHealth;
    performance: PerformanceMetrics;
    tracing: ReturnType<typeof correlationManager.getStats>;
    alerts: { active: number; critical: number; high: number };
    uptime: number;
  } {
    const startTime = process.env.CF_WORKER_START_TIME
      ? parseInt(process.env.CF_WORKER_START_TIME)
      : Date.now() - 60000; // Fallback to 1 minute ago

    return {
      health: {
        status: 'healthy', // Will be updated by periodic health checks
        score: 100,
        checks: [],
        timestamp: Date.now()
      },
      performance: this.getPerformanceMetrics(),
      tracing: correlationManager.getStats(),
      alerts: this.getAlertSummary(),
      uptime: Date.now() - startTime
    };
  }

  /**
   * Monitor trace completion and detect long-running operations
   */
  monitorTrace(correlationId: string): void {
    setTimeout(() => {
      const trace = correlationManager.getTrace(correlationId);

      if (trace.spans.some(span => span.status === 'pending')) {
        this.createAlert(
          'long_running_operation',
          'medium',
          `Trace ${correlationId} has operations running longer than expected`,
          30000, // 30 seconds threshold
          Date.now() - Math.min(...trace.spans.map((s: any) => s.startTime)),
          correlationId,
          { spanCount: trace.spanCount, activeSpans: trace.spans.filter((s: any) => s.status === 'pending').length }
        );
      }
    }, 30000); // Check after 30 seconds
  }

  private setupDefaultHealthChecks(): void {
    // Memory usage check (if available)
    this.registerHealthCheck('memory_usage', async () => {
      try {
        // In Workers, we don't have direct access to memory stats
        // This is a placeholder for when such APIs become available
        return true;
      } catch {
        return false;
      }
    });

    // Correlation manager health
    this.registerHealthCheck('correlation_manager', async () => {
      const stats = correlationManager.getStats();
      return stats.activeTraces < 1000; // Reasonable limit
    });
  }

  private startMetricCollection(): void {
    // Collect system metrics every 30 seconds
    setInterval(() => {
      this.collectSystemMetrics();
    }, 30000);

    // Clean up old metrics every 10 minutes
    setInterval(() => {
      this.cleanupOldMetrics();
    }, 10 * 60 * 1000);
  }

  private collectSystemMetrics(): void {
    const now = Date.now();

    // Circuit breaker metrics
    const cbMetrics = circuitBreakerRegistry.getAllMetrics();
    for (const [name, metrics] of Object.entries(cbMetrics)) {
      this.recordMetric(`circuit_breaker.failure_rate`, metrics.failureRate, 'gauge', { circuit: name });
      this.recordMetric(`circuit_breaker.requests`, metrics.totalRequests, 'counter', { circuit: name });
    }

    // Tracing metrics
    const tracingStats = correlationManager.getStats();
    this.recordMetric('tracing.active_traces', tracingStats.activeTraces, 'gauge');
    this.recordMetric('tracing.active_spans', tracingStats.activeSpans, 'gauge');

    // Alert metrics
    const alertSummary = this.getAlertSummary();
    this.recordMetric('alerts.active', alertSummary.active, 'gauge');
    this.recordMetric('alerts.critical', alertSummary.critical, 'gauge');
  }

  private cleanupOldMetrics(): void {
    const cutoff = Date.now() - (60 * 60 * 1000); // 1 hour
    let cleaned = 0;

    for (const [name, points] of this.metrics) {
      const filtered = points.filter((p: any) => p.timestamp >= cutoff);
      if (filtered.length !== points.length) {
        this.metrics.set(name, filtered);
        cleaned += points.length - filtered.length;
      }
    }

    if (cleaned > 0) {
      this.logger.debug('Cleaned up old metrics', { pointsRemoved: cleaned });
    }
  }

  private getActiveConnectionCount(): number {
    // Placeholder - in a real implementation, this would track active connections
    return 0;
  }

  private getAlertSummary(): { active: number; critical: number; high: number } {
    const activeAlerts = this.getActiveAlerts();
    return {
      active: activeAlerts.length,
      critical: activeAlerts.filter((a: any) => a.severity === 'critical').length,
      high: activeAlerts.filter((a: any) => a.severity === 'high').length
    };
  }
}

// Global monitoring service instance
export const monitoringService = MonitoringService.getInstance();

// Utility function to monitor async operations
export async function withMonitoring<T>(
  operationName: string,
  operation: () => Promise<T>,
  tags: Record<string, string> = {}
): Promise<T> {
  const startTime = Date.now();

  try {
    const result = await operation();
    const latency = Date.now() - startTime;

    monitoringService.recordRequest(latency, true, { operation: operationName, ...tags });
    return result;

  } catch (error: any) {
    const latency = Date.now() - startTime;

    monitoringService.recordRequest(latency, false, { operation: operationName, ...tags });

    // Create alert for repeated failures
    const recentFailures = monitoringService.getMetrics('request.count')
      .filter((m: any) => m.tags.operation === operationName && m.tags.status === 'error')
      .filter((m: any) => m.timestamp >= Date.now() - 5 * 60 * 1000) // Last 5 minutes
      .length;

    if (recentFailures >= 5) {
      monitoringService.createAlert(
        'operation_failure_rate',
        'high',
        `Operation ${operationName} has failed ${recentFailures} times in the last 5 minutes`,
        5,
        recentFailures,
        undefined,
        { operation: operationName }
      );
    }

    throw error;
  }
}