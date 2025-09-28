/**
 * Comprehensive Performance Monitoring Service
 * Tracks database queries, cache performance, API response times, and overall system health
 */

import { CacheService, EnhancedCacheStats } from '../cache/cache-service';
import { CRMDatabase } from '../database/crm-database';
import { Logger } from '../shared/logger';
import type { Env } from '../types/env';

export interface PerformanceMetrics {
  timestamp: number;
  database: DatabasePerformanceMetrics;
  cache: EnhancedCacheStats;
  api: APIPerformanceMetrics;
  system: SystemPerformanceMetrics;
  targets: PerformanceTargets;
  score: number;
}

export interface DatabasePerformanceMetrics {
  queryCount: number;
  avgQueryTime: number;
  slowQueries: Array<{ query: string; avgTime: number; count: number }>;
  connectionPoolUtilization: number;
  cacheHitRate: number;
  nPlusOneQueries: number;
  indexEfficiency: number;
}

export interface APIPerformanceMetrics {
  totalRequests: number;
  avgResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  errorRate: number;
  throughput: number;
  endpointStats: Map<string, EndpointStats>;
}

export interface EndpointStats {
  path: string;
  method: string;
  requestCount: number;
  avgResponseTime: number;
  errorCount: number;
  lastAccessed: number;
}

export interface SystemPerformanceMetrics {
  memoryUsage: number;
  cpuUsage: number;
  networkLatency: number;
  diskIO: number;
  uptime: number;
}

export interface PerformanceTargets {
  cacheHitRate: number; // 85%
  apiResponseTimeP95: number; // 100ms
  databaseQueryAvgTime: number; // 50ms
  errorRate: number; // <1%
  throughput: number; // requests/second
}

export class PerformanceMonitor {
  private logger: Logger;
  private cacheService: CacheService;
  private database: CRMDatabase;
  private metrics: PerformanceMetrics;
  private responseTimeBuffer: number[] = [];
  private endpointStats: Map<string, EndpointStats> = new Map();
  private readonly BUFFER_SIZE = 1000;
  private readonly MONITORING_INTERVAL = 60000; // 1 minute

  private readonly PERFORMANCE_TARGETS: PerformanceTargets = {
    cacheHitRate: 85,
    apiResponseTimeP95: 100,
    databaseQueryAvgTime: 50,
    errorRate: 1,
    throughput: 100
  };

  constructor(env: Env, cacheService: CacheService, database: CRMDatabase) {
    this.logger = new Logger({ component: 'performance-monitor' });
    this.cacheService = cacheService;
    this.database = database;

    this.metrics = this.initializeMetrics();
    this.startMonitoring();
  }

  private initializeMetrics(): PerformanceMetrics {
    return {
      timestamp: Date.now(),
      database: {
        queryCount: 0,
        avgQueryTime: 0,
        slowQueries: [],
        connectionPoolUtilization: 0,
        cacheHitRate: 0,
        nPlusOneQueries: 0,
        indexEfficiency: 0
      },
      cache: {
        l1Hits: 0,
        l2Hits: 0,
        totalHits: 0,
        misses: 0,
        totalRequests: 0,
        hitRate: 0,
        l1HitRate: 0,
        l2HitRate: 0,
        avgResponseTime: 0,
        requestsPerHour: 0,
        invalidations: 0,
        priorityCacheSize: 0,
        warmupQueueSize: 0,
        uptime: 0,
        memoryUsage: 0
      },
      api: {
        totalRequests: 0,
        avgResponseTime: 0,
        p95ResponseTime: 0,
        p99ResponseTime: 0,
        errorRate: 0,
        throughput: 0,
        endpointStats: new Map()
      },
      system: {
        memoryUsage: 0,
        cpuUsage: 0,
        networkLatency: 0,
        diskIO: 0,
        uptime: 0
      },
      targets: this.PERFORMANCE_TARGETS,
      score: 0
    };
  }

  /**
   * Start monitoring background tasks
   */
  private startMonitoring(): void {
    setInterval(() => {
      this.collectMetrics();
    }, this.MONITORING_INTERVAL);

    // Log performance summary every 5 minutes
    setInterval(() => {
      this.logPerformanceSummary();
    }, 300000);

    this.logger.info('Performance monitoring started', {
      interval: this.MONITORING_INTERVAL,
      targets: this.PERFORMANCE_TARGETS
    });
  }

  /**
   * Record API request metrics
   */
  recordAPIRequest(
    path: string,
    method: string,
    responseTime: number,
    statusCode: number
  ): void {
    const endpointKey = `${method}:${path}`;
    const existing = this.endpointStats.get(endpointKey) || {
      path,
      method,
      requestCount: 0,
      avgResponseTime: 0,
      errorCount: 0,
      lastAccessed: Date.now()
    };

    existing.requestCount++;
    existing.avgResponseTime = (existing.avgResponseTime * (existing.requestCount - 1) + responseTime) / existing.requestCount;
    existing.lastAccessed = Date.now();

    if (statusCode >= 400) {
      existing.errorCount++;
    }

    this.endpointStats.set(endpointKey, existing);

    // Add to response time buffer for percentile calculations
    this.responseTimeBuffer.push(responseTime);
    if (this.responseTimeBuffer.length > this.BUFFER_SIZE) {
      this.responseTimeBuffer.shift();
    }
  }

  /**
   * Record database query performance
   */
  recordDatabaseQuery(query: string, executionTime: number, fromCache: boolean): void {
    // This would be called from the database layer
    // For now, we'll track it in the metrics collection
  }

  /**
   * Collect comprehensive performance metrics
   */
  private async collectMetrics(): Promise<void> {
    try {
      const timestamp = Date.now();

      // Collect database metrics
      const databaseMetrics = await this.collectDatabaseMetrics();

      // Collect cache metrics
      const cacheMetrics = await this.cacheService.getStats();

      // Collect API metrics
      const apiMetrics = this.collectAPIMetrics();

      // Collect system metrics
      const systemMetrics = this.collectSystemMetrics();

      // Calculate performance score
      const score = this.calculatePerformanceScore(
        databaseMetrics,
        cacheMetrics,
        apiMetrics
      );

      this.metrics = {
        timestamp,
        database: databaseMetrics,
        cache: cacheMetrics,
        api: apiMetrics,
        system: systemMetrics,
        targets: this.PERFORMANCE_TARGETS,
        score
      };

      // Alert on performance issues
      this.checkPerformanceAlerts();

    } catch (error: any) {
      this.logger.error('Failed to collect performance metrics', error);
    }
  }

  /**
   * Collect database performance metrics
   */
  private async collectDatabaseMetrics(): Promise<DatabasePerformanceMetrics> {
    try {
      const dbStats = await this.database.getPerformanceStats();

      return {
        queryCount: dbStats.queryCount,
        avgQueryTime: dbStats.avgQueryTime,
        slowQueries: dbStats.slowQueries,
        connectionPoolUtilization: 75, // Simulated - D1 doesn't have traditional pools
        cacheHitRate: dbStats.cacheHitRate,
        nPlusOneQueries: 0, // Would need to implement detection
        indexEfficiency: this.calculateIndexEfficiency(dbStats.slowQueries)
      };
    } catch (error: any) {
      this.logger.warn('Failed to collect database metrics', error);
      return this.metrics.database;
    }
  }

  /**
   * Calculate index efficiency based on slow queries
   */
  private calculateIndexEfficiency(slowQueries: Array<{ query: string; avgTime: number; count: number }>): number {
    if (slowQueries.length === 0) return 100;

    // Simple heuristic: fewer slow queries = better index efficiency
    const maxSlowQueries = 10;
    const efficiency = Math.max(0, 100 - (slowQueries.length / maxSlowQueries) * 100);
    return Math.round(efficiency);
  }

  /**
   * Collect API performance metrics
   */
  private collectAPIMetrics(): APIPerformanceMetrics {
    const totalRequests = Array.from(this.endpointStats.values())
      .reduce((sum, stats) => sum + stats.requestCount, 0);

    const totalErrors = Array.from(this.endpointStats.values())
      .reduce((sum, stats) => sum + stats.errorCount, 0);

    const avgResponseTime = this.calculateAverageResponseTime();
    const p95ResponseTime = this.calculatePercentile(95);
    const p99ResponseTime = this.calculatePercentile(99);
    const errorRate = totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;

    // Calculate throughput (requests per second over last minute)
    const oneMinuteAgo = Date.now() - 60000;
    const recentRequests = Array.from(this.endpointStats.values())
      .filter(stats => stats.lastAccessed > oneMinuteAgo)
      .reduce((sum, stats) => sum + stats.requestCount, 0);

    const throughput = recentRequests / 60;

    return {
      totalRequests,
      avgResponseTime,
      p95ResponseTime,
      p99ResponseTime,
      errorRate,
      throughput,
      endpointStats: new Map(this.endpointStats)
    };
  }

  /**
   * Calculate average response time from buffer
   */
  private calculateAverageResponseTime(): number {
    if (this.responseTimeBuffer.length === 0) return 0;

    const sum = this.responseTimeBuffer.reduce((a, b) => a + b, 0);
    return Math.round(sum / this.responseTimeBuffer.length);
  }

  /**
   * Calculate response time percentile
   */
  private calculatePercentile(percentile: number): number {
    if (this.responseTimeBuffer.length === 0) return 0;

    const sorted = [...this.responseTimeBuffer].sort((a, b) => a - b);
    const index = Math.ceil((percentile / 100) * sorted.length) - 1;
    return Math.round(sorted[Math.max(0, index)]);
  }

  /**
   * Collect system performance metrics
   */
  private collectSystemMetrics(): SystemPerformanceMetrics {
    // In a real implementation, these would come from system monitoring
    return {
      memoryUsage: this.estimateMemoryUsage(),
      cpuUsage: 0, // Not available in Cloudflare Workers
      networkLatency: 0, // Would need to implement ping tests
      diskIO: 0, // Not applicable for Cloudflare Workers
      uptime: Date.now() - this.metrics.timestamp
    };
  }

  /**
   * Estimate memory usage
   */
  private estimateMemoryUsage(): number {
    // Rough estimation based on cache sizes and buffers
    const bufferMemory = this.responseTimeBuffer.length * 8; // 8 bytes per number
    const endpointMemory = this.endpointStats.size * 200; // ~200 bytes per endpoint
    const cacheMemory = this.metrics.cache.memoryUsage || 0;

    return bufferMemory + endpointMemory + cacheMemory;
  }

  /**
   * Calculate overall performance score (0-100)
   */
  private calculatePerformanceScore(
    dbMetrics: DatabasePerformanceMetrics,
    cacheMetrics: EnhancedCacheStats,
    apiMetrics: APIPerformanceMetrics
  ): number {
    let score = 100;

    // Cache hit rate (25% of score)
    const cacheHitRateScore = Math.min(100, (cacheMetrics.hitRate / this.PERFORMANCE_TARGETS.cacheHitRate) * 100);
    score = score * 0.75 + cacheHitRateScore * 0.25;

    // API response time (30% of score)
    const responseTimeScore = apiMetrics.p95ResponseTime <= this.PERFORMANCE_TARGETS.apiResponseTimeP95
      ? 100
      : Math.max(0, 100 - ((apiMetrics.p95ResponseTime - this.PERFORMANCE_TARGETS.apiResponseTimeP95) / this.PERFORMANCE_TARGETS.apiResponseTimeP95) * 100);
    score = score * 0.7 + responseTimeScore * 0.3;

    // Database performance (25% of score)
    const dbScore = dbMetrics.avgQueryTime <= this.PERFORMANCE_TARGETS.databaseQueryAvgTime
      ? 100
      : Math.max(0, 100 - ((dbMetrics.avgQueryTime - this.PERFORMANCE_TARGETS.databaseQueryAvgTime) / this.PERFORMANCE_TARGETS.databaseQueryAvgTime) * 100);
    score = score * 0.75 + dbScore * 0.25;

    // Error rate (20% of score)
    const errorScore = apiMetrics.errorRate <= this.PERFORMANCE_TARGETS.errorRate
      ? 100
      : Math.max(0, 100 - (apiMetrics.errorRate - this.PERFORMANCE_TARGETS.errorRate) * 10);
    score = score * 0.8 + errorScore * 0.2;

    return Math.round(Math.max(0, Math.min(100, score)));
  }

  /**
   * Check for performance alerts
   */
  private checkPerformanceAlerts(): void {
    const alerts: string[] = [];

    // Cache hit rate alert
    if (this.metrics.cache.hitRate < this.PERFORMANCE_TARGETS.cacheHitRate * 0.8) {
      alerts.push(`Low cache hit rate: ${this.metrics.cache.hitRate.toFixed(1)}% (target: ${this.PERFORMANCE_TARGETS.cacheHitRate}%)`);
    }

    // API response time alert
    if (this.metrics.api.p95ResponseTime > this.PERFORMANCE_TARGETS.apiResponseTimeP95 * 1.5) {
      alerts.push(`High API response time: ${this.metrics.api.p95ResponseTime}ms P95 (target: ${this.PERFORMANCE_TARGETS.apiResponseTimeP95}ms)`);
    }

    // Database performance alert
    if (this.metrics.database.avgQueryTime > this.PERFORMANCE_TARGETS.databaseQueryAvgTime * 2) {
      alerts.push(`Slow database queries: ${this.metrics.database.avgQueryTime}ms avg (target: ${this.PERFORMANCE_TARGETS.databaseQueryAvgTime}ms)`);
    }

    // Error rate alert
    if (this.metrics.api.errorRate > this.PERFORMANCE_TARGETS.errorRate * 2) {
      alerts.push(`High error rate: ${this.metrics.api.errorRate.toFixed(1)}% (target: <${this.PERFORMANCE_TARGETS.errorRate}%)`);
    }

    // Log alerts
    if (alerts.length > 0) {
      this.logger.warn('Performance alerts detected', { alerts, score: this.metrics.score });
    }
  }

  /**
   * Log performance summary
   */
  private logPerformanceSummary(): void {
    this.logger.info('Performance Summary', {
      score: this.metrics.score,
      cacheHitRate: this.metrics.cache.hitRate.toFixed(1) + '%',
      apiResponseTimeP95: this.metrics.api.p95ResponseTime + 'ms',
      dbAvgQueryTime: this.metrics.database.avgQueryTime + 'ms',
      errorRate: this.metrics.api.errorRate.toFixed(2) + '%',
      throughput: this.metrics.api.throughput.toFixed(1) + ' req/s',
      slowQueries: this.metrics.database.slowQueries.length,
      memoryUsage: this.formatBytes(this.metrics.system.memoryUsage)
    });
  }

  /**
   * Format bytes for human-readable output
   */
  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Get current performance metrics
   */
  getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  /**
   * Get performance report for API endpoint
   */
  getPerformanceReport(): {
    summary: {
      score: number;
      status: 'excellent' | 'good' | 'fair' | 'poor';
      recommendations: string[];
    };
    metrics: PerformanceMetrics;
  } {
    const score = this.metrics.score;
    let status: 'excellent' | 'good' | 'fair' | 'poor';
    const recommendations: string[] = [];

    if (score >= 90) {
      status = 'excellent';
    } else if (score >= 75) {
      status = 'good';
    } else if (score >= 60) {
      status = 'fair';
    } else {
      status = 'poor';
    }

    // Generate recommendations
    if (this.metrics.cache.hitRate < this.PERFORMANCE_TARGETS.cacheHitRate) {
      recommendations.push(`Improve cache hit rate from ${this.metrics.cache.hitRate.toFixed(1)}% to ${this.PERFORMANCE_TARGETS.cacheHitRate}%`);
    }

    if (this.metrics.api.p95ResponseTime > this.PERFORMANCE_TARGETS.apiResponseTimeP95) {
      recommendations.push(`Optimize API response times from ${this.metrics.api.p95ResponseTime}ms to under ${this.PERFORMANCE_TARGETS.apiResponseTimeP95}ms`);
    }

    if (this.metrics.database.avgQueryTime > this.PERFORMANCE_TARGETS.databaseQueryAvgTime) {
      recommendations.push(`Optimize database queries from ${this.metrics.database.avgQueryTime}ms to under ${this.PERFORMANCE_TARGETS.databaseQueryAvgTime}ms`);
    }

    if (this.metrics.database.slowQueries.length > 5) {
      recommendations.push(`Address ${this.metrics.database.slowQueries.length} slow queries with indexing or optimization`);
    }

    if (this.metrics.api.errorRate > this.PERFORMANCE_TARGETS.errorRate) {
      recommendations.push(`Reduce error rate from ${this.metrics.api.errorRate.toFixed(1)}% to under ${this.PERFORMANCE_TARGETS.errorRate}%`);
    }

    return {
      summary: {
        score,
        status,
        recommendations
      },
      metrics: this.metrics
    };
  }

  /**
   * Reset all metrics
   */
  reset(): void {
    this.metrics = this.initializeMetrics();
    this.responseTimeBuffer = [];
    this.endpointStats.clear();
    this.logger.info('Performance metrics reset');
  }
}

/**
 * Performance monitoring middleware for API requests
 */
export function createPerformanceMiddleware(monitor: PerformanceMonitor) {
  return async (request: Request, next: () => Promise<Response>): Promise<Response> => {
    const startTime = performance.now();
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      const response = await next();
      const responseTime = performance.now() - startTime;

      monitor.recordAPIRequest(path, method, responseTime, response.status);

      return response;
    } catch (error) {
      const responseTime = performance.now() - startTime;
      monitor.recordAPIRequest(path, method, responseTime, 500);
      throw error;
    }
  };
}