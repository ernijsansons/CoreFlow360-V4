/**
 * Performance Monitoring and Observability System
 * Tracks application metrics, performance, and health status
 */

import { Context } from 'hono';

export interface PerformanceMetrics {
  requestId: string;
  timestamp: number;
  duration: number;
  statusCode: number;
  method: string;
  path: string;
  userAgent?: string;
  cpuUsage?: number;
  memoryUsage?: number;
  dbQueries?: number;
  cacheHits?: number;
  cacheMisses?: number;
  errorCount?: number;
}

export interface HealthMetrics {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: number;
  uptime: number;
  requestsPerSecond: number;
  averageResponseTime: number;
  errorRate: number;
  memoryUsage: {
    used: number;
    total: number;
    percentage: number;
  };
  services: ServiceHealth[];
}

export interface ServiceHealth {
  name: string;
  status: 'up' | 'down' | 'degraded';
  lastCheck: number;
  responseTime?: number;
  errorRate?: number;
  details?: Record<string, any>;
}

export interface AlertConfig {
  responseTimeThreshold: number; // milliseconds
  errorRateThreshold: number; // percentage
  memoryThreshold: number; // percentage
  requestRateThreshold: number; // requests per second
}

export class PerformanceMonitor {
  private readonly kv?: KVNamespace;
  private readonly analytics?: AnalyticsEngineDataset;
  private readonly metricsPrefix = 'metrics:';
  private readonly healthPrefix = 'health:';
  private readonly alertConfig: AlertConfig;
  private readonly startTime = Date.now();

  // In-memory metrics for current window
  private requestCount = 0;
  private errorCount = 0;
  private totalDuration = 0;
  private metrics: PerformanceMetrics[] = [];
  private lastHealthCheck = 0;

  constructor(
    alertConfig?: Partial<AlertConfig>,
    kv?: KVNamespace,
    analytics?: AnalyticsEngineDataset
  ) {
    this.alertConfig = {
      responseTimeThreshold: alertConfig?.responseTimeThreshold || 1000, // 1 second
      errorRateThreshold: alertConfig?.errorRateThreshold || 5, // 5%
      memoryThreshold: alertConfig?.memoryThreshold || 90, // 90%
      requestRateThreshold: alertConfig?.requestRateThreshold || 100 // 100 RPS
    };
    this.kv = kv;
    this.analytics = analytics;
  }

  /**
   * Performance monitoring middleware
   */
  middleware() {
    return async (c: Context, next: () => Promise<void>) => {
      const startTime = Date.now();
      const requestId = c.get('requestId') || crypto.randomUUID();

      // Track request
      this.requestCount++;

      try {
        await next();

        // Record metrics
        const duration = Date.now() - startTime;
        this.recordMetrics({
          requestId,
          timestamp: Date.now(),
          duration,
          statusCode: c.res.status,
          method: c.req.method,
          path: c.req.path,
          userAgent: c.req.header('User-Agent')
        });

        // Check for slow requests
        if (duration > this.alertConfig.responseTimeThreshold) {
          await this.alert('slow_request', {
            requestId,
            duration,
            threshold: this.alertConfig.responseTimeThreshold,
            path: c.req.path
          });
        }

      } catch (error) {
        // Record error
        this.errorCount++;
        const duration = Date.now() - startTime;

        this.recordMetrics({
          requestId,
          timestamp: Date.now(),
          duration,
          statusCode: 500,
          method: c.req.method,
          path: c.req.path,
          errorCount: 1
        });

        throw error;
      }
    };
  }

  /**
   * Record performance metrics
   */
  private recordMetrics(metrics: PerformanceMetrics): void {
    this.totalDuration += metrics.duration;
    this.metrics.push(metrics);

    // Keep only last 1000 metrics in memory
    if (this.metrics.length > 1000) {
      this.metrics.shift();
    }

    // Write to storage asynchronously
    this.persistMetrics(metrics);

    // Check thresholds
    this.checkThresholds();
  }

  /**
   * Persist metrics to storage
   */
  private async persistMetrics(metrics: PerformanceMetrics): Promise<void> {
    if (this.kv) {
      try {
        const key = `${this.metricsPrefix}${metrics.timestamp}_${metrics.requestId}`;
        await this.kv.put(key, JSON.stringify(metrics), {
          expirationTtl: 24 * 60 * 60 // 24 hours
        });
      } catch (error) {
        console.error('Failed to persist metrics:', error);
      }
    }

    if (this.analytics) {
      try {
        await this.analytics.writeDataPoint({
          indexes: [
            metrics.method,
            metrics.path,
            metrics.statusCode.toString()
          ],
          blobs: [
            metrics.requestId,
            metrics.userAgent || '',
            JSON.stringify(metrics)
          ],
          doubles: [
            metrics.timestamp,
            metrics.duration,
            metrics.statusCode
          ]
        });
      } catch (error) {
        console.error('Failed to write to analytics:', error);
      }
    }
  }

  /**
   * Check performance thresholds
   */
  private checkThresholds(): void {
    const now = Date.now();

    // Calculate error rate
    const errorRate = this.requestCount > 0
      ? (this.errorCount / this.requestCount) * 100
      : 0;

    if (errorRate > this.alertConfig.errorRateThreshold) {
      this.alert('high_error_rate', {
        errorRate,
        threshold: this.alertConfig.errorRateThreshold,
        requestCount: this.requestCount,
        errorCount: this.errorCount
      });
    }

    // Calculate average response time
    const avgResponseTime = this.requestCount > 0
      ? this.totalDuration / this.requestCount
      : 0;

    if (avgResponseTime > this.alertConfig.responseTimeThreshold) {
      this.alert('high_response_time', {
        avgResponseTime,
        threshold: this.alertConfig.responseTimeThreshold
      });
    }

    // Check request rate (requests in last second)
    const recentRequests = this.metrics.filter(m =>
      m.timestamp > now - 1000
    ).length;

    if (recentRequests > this.alertConfig.requestRateThreshold) {
      this.alert('high_request_rate', {
        requestsPerSecond: recentRequests,
        threshold: this.alertConfig.requestRateThreshold
      });
    }
  }

  /**
   * Generate health metrics
   */
  async getHealthMetrics(): Promise<HealthMetrics> {
    const now = Date.now();
    const uptime = now - this.startTime;

    // Calculate metrics
    const requestsPerSecond = this.metrics.filter(m =>
      m.timestamp > now - 1000
    ).length;

    const avgResponseTime = this.requestCount > 0
      ? this.totalDuration / this.requestCount
      : 0;

    const errorRate = this.requestCount > 0
      ? (this.errorCount / this.requestCount) * 100
      : 0;

    // Memory usage (if available in environment)
    const memoryUsage = this.getMemoryUsage();

    // Check service health
    const services = await this.checkServices();

    // Determine overall health status
    let status: HealthMetrics['status'] = 'healthy';

    if (errorRate > this.alertConfig.errorRateThreshold ||
        avgResponseTime > this.alertConfig.responseTimeThreshold ||
        memoryUsage.percentage > this.alertConfig.memoryThreshold) {
      status = 'degraded';
    }

    if (errorRate > this.alertConfig.errorRateThreshold * 2 ||
        services.some(s => s.status === 'down')) {
      status = 'unhealthy';
    }

    const health: HealthMetrics = {
      status,
      timestamp: now,
      uptime,
      requestsPerSecond,
      averageResponseTime: avgResponseTime,
      errorRate,
      memoryUsage,
      services
    };

    // Store health metrics
    if (this.kv) {
      await this.kv.put(
        `${this.healthPrefix}${now}`,
        JSON.stringify(health),
        { expirationTtl: 7 * 24 * 60 * 60 } // 7 days
      );
    }

    this.lastHealthCheck = now;
    return health;
  }

  /**
   * Get memory usage
   */
  private getMemoryUsage(): HealthMetrics['memoryUsage'] {
    // In Cloudflare Workers, memory info might not be available
    // This is a placeholder implementation
    const used = (global as any).process?.memoryUsage?.().heapUsed || 0;
    const total = (global as any).process?.memoryUsage?.().heapTotal || 128 * 1024 * 1024; // 128 MB default

    return {
      used,
      total,
      percentage: total > 0 ? (used / total) * 100 : 0
    };
  }

  /**
   * Check service health
   */
  private async checkServices(): Promise<ServiceHealth[]> {
    const services: ServiceHealth[] = [];

    // Check database
    services.push(await this.checkDatabase());

    // Check KV store
    if (this.kv) {
      services.push(await this.checkKVStore());
    }

    // Check external APIs (placeholder)
    services.push(await this.checkExternalAPIs());

    return services;
  }

  /**
   * Check database health
   */
  private async checkDatabase(): Promise<ServiceHealth> {
    const startTime = Date.now();

    try {
      // Perform health check query (placeholder)
      // In real implementation, execute a simple query
      const responseTime = Date.now() - startTime;

      return {
        name: 'database',
        status: responseTime < 100 ? 'up' : 'degraded',
        lastCheck: Date.now(),
        responseTime
      };
    } catch (error) {
      return {
        name: 'database',
        status: 'down',
        lastCheck: Date.now(),
        details: { error: (error as Error).message }
      };
    }
  }

  /**
   * Check KV store health
   */
  private async checkKVStore(): Promise<ServiceHealth> {
    const startTime = Date.now();

    try {
      // Test KV operation
      const testKey = 'health:check:test';
      await this.kv!.put(testKey, Date.now().toString(), { expirationTtl: 60 });
      const value = await this.kv!.get(testKey);

      const responseTime = Date.now() - startTime;

      return {
        name: 'kv_store',
        status: value ? 'up' : 'degraded',
        lastCheck: Date.now(),
        responseTime
      };
    } catch (error) {
      return {
        name: 'kv_store',
        status: 'down',
        lastCheck: Date.now(),
        details: { error: (error as Error).message }
      };
    }
  }

  /**
   * Check external APIs
   */
  private async checkExternalAPIs(): Promise<ServiceHealth> {
    // Placeholder for external API checks
    return {
      name: 'external_apis',
      status: 'up',
      lastCheck: Date.now(),
      responseTime: 50
    };
  }

  /**
   * Send alert
   */
  private async alert(type: string, details: Record<string, any>): Promise<void> {
    const alert = {
      type,
      timestamp: Date.now(),
      details,
      severity: this.getAlertSeverity(type)
    };

    console.warn('[ALERT]', JSON.stringify(alert, null, 2));

    // Store alert
    if (this.kv) {
      await this.kv.put(
        `alert:${alert.timestamp}_${type}`,
        JSON.stringify(alert),
        { expirationTtl: 30 * 24 * 60 * 60 } // 30 days
      );
    }

    // In production, send to alerting service (PagerDuty, etc.)
  }

  /**
   * Get alert severity
   */
  private getAlertSeverity(type: string): 'low' | 'medium' | 'high' | 'critical' {
    const severityMap: Record<string, 'low' | 'medium' | 'high' | 'critical'> = {
      slow_request: 'low',
      high_response_time: 'medium',
      high_error_rate: 'high',
      high_request_rate: 'medium',
      service_down: 'critical'
    };

    return severityMap[type] || 'medium';
  }

  /**
   * Get performance summary
   */
  async getPerformanceSummary(minutes = 5): Promise<{
    totalRequests: number;
    averageResponseTime: number;
    errorRate: number;
    slowRequests: number;
    topEndpoints: Array<{ path: string; count: number; avgTime: number }>;
  }> {
    const cutoff = Date.now() - (minutes * 60 * 1000);
    const recentMetrics = this.metrics.filter(m => m.timestamp > cutoff);

    const totalRequests = recentMetrics.length;
    const errors = recentMetrics.filter(m => m.statusCode >= 400).length;
    const errorRate = totalRequests > 0 ? (errors / totalRequests) * 100 : 0;

    const totalTime = recentMetrics.reduce((sum, m) => sum + m.duration, 0);
    const averageResponseTime = totalRequests > 0 ? totalTime / totalRequests : 0;

    const slowRequests = recentMetrics.filter(m =>
      m.duration > this.alertConfig.responseTimeThreshold
    ).length;

    // Calculate top endpoints
    const endpointStats = new Map<string, { count: number; totalTime: number }>();

    for (const metric of recentMetrics) {
      const stats = endpointStats.get(metric.path) || { count: 0, totalTime: 0 };
      stats.count++;
      stats.totalTime += metric.duration;
      endpointStats.set(metric.path, stats);
    }

    const topEndpoints = Array.from(endpointStats.entries())
      .map(([path, stats]) => ({
        path,
        count: stats.count,
        avgTime: stats.totalTime / stats.count
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return {
      totalRequests,
      averageResponseTime,
      errorRate,
      slowRequests,
      topEndpoints
    };
  }

  /**
   * Reset metrics (for testing)
   */
  reset(): void {
    this.requestCount = 0;
    this.errorCount = 0;
    this.totalDuration = 0;
    this.metrics = [];
  }
}

// Export factory function
export function createPerformanceMonitor(
  alertConfig?: Partial<AlertConfig>,
  kv?: KVNamespace,
  analytics?: AnalyticsEngineDataset
): PerformanceMonitor {
  return new PerformanceMonitor(alertConfig, kv, analytics);
}