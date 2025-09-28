/**
 * Database Performance Monitor - Single Responsibility Principle Compliant
 * Focused solely on tracking and analyzing database query performance
 */

import { IPerformanceMonitor } from '../repositories/interfaces';
import { Logger } from '../../shared/logger';

interface QueryMetric {
  totalTime: number;
  count: number;
  avgTime: number;
  minTime: number;
  maxTime: number;
  cacheHits: number;
  lastExecuted: number;
}

interface SlowQuery {
  query: string;
  avgTime: number;
  count: number;
  maxTime: number;
  lastSeen: number;
}

export class DatabasePerformanceMonitor implements IPerformanceMonitor {
  private readonly logger: Logger;
  private readonly metrics = new Map<string, QueryMetric>();
  private readonly slowQueryThreshold: number = 50; // 50ms
  private readonly maxMetricsSize: number = 1000;
  private readonly cleanupInterval: number = 300000; // 5 minutes
  private cleanupTimer?: number;

  // Global performance statistics
  private globalStats = {
    totalQueries: 0,
    totalTime: 0,
    cacheHits: 0,
    slowQueries: 0,
    errors: 0,
    startTime: Date.now()
  };

  constructor(slowQueryThreshold: number = 50) {
    this.logger = new Logger();
    this.slowQueryThreshold = slowQueryThreshold;
    this.startCleanupTimer();
  }

  trackQuery(query: string, executionTime: number, fromCache: boolean = false): void {
    const queryKey = this.normalizeQuery(query);
    const now = Date.now();

    // Update global statistics
    this.globalStats.totalQueries++;
    this.globalStats.totalTime += executionTime;

    if (fromCache) {
      this.globalStats.cacheHits++;
    }

    if (executionTime > this.slowQueryThreshold) {
      this.globalStats.slowQueries++;
    }

    // Update or create query-specific metrics
    const existing = this.metrics.get(queryKey);

    if (existing) {
      existing.totalTime += executionTime;
      existing.count++;
      existing.avgTime = existing.totalTime / existing.count;
      existing.minTime = Math.min(existing.minTime, executionTime);
      existing.maxTime = Math.max(existing.maxTime, executionTime);
      existing.lastExecuted = now;

      if (fromCache) {
        existing.cacheHits++;
      }
    } else {
      // Prevent memory issues by limiting metrics size
      if (this.metrics.size >= this.maxMetricsSize) {
        this.cleanupOldMetrics();
      }

      this.metrics.set(queryKey, {
        totalTime: executionTime,
        count: 1,
        avgTime: executionTime,
        minTime: executionTime,
        maxTime: executionTime,
        cacheHits: fromCache ? 1 : 0,
        lastExecuted: now
      });
    }

    // Log slow queries immediately
    if (executionTime > this.slowQueryThreshold) {
      this.logger.warn('Slow query detected', {
        query: queryKey.substring(0, 100) + '...',
        executionTime: Math.round(executionTime),
        fromCache,
        avgTime: existing ? Math.round(existing.avgTime) : executionTime
      });
    }

    // Log cache hits for debugging
    if (fromCache) {
      this.logger.debug('Cache hit recorded', {
        query: queryKey.substring(0, 50) + '...',
        savedTime: Math.round(executionTime)
      });
    }
  }

  getSlowQueries(threshold: number = this.slowQueryThreshold): SlowQuery[] {
    const slowQueries: SlowQuery[] = [];

    for (const [query, metric] of this.metrics.entries()) {
      if (metric.avgTime > threshold) {
        slowQueries.push({
          query: query.substring(0, 80) + (query.length > 80 ? '...' : ''),
          avgTime: Math.round(metric.avgTime * 100) / 100,
          count: metric.count,
          maxTime: Math.round(metric.maxTime * 100) / 100,
          lastSeen: metric.lastExecuted
        });
      }
    }

    // Sort by average time descending
    return slowQueries
      .sort((a, b) => b.avgTime - a.avgTime)
      .slice(0, 20); // Return top 20 slow queries
  }

  getStats(): {
    queryCount: number;
    avgQueryTime: number;
    slowQueries: SlowQuery[];
    cacheHitRate: number;
    queriesPerSecond: number;
    uptime: number;
  } {
    const avgQueryTime = this.globalStats.totalQueries > 0
      ? this.globalStats.totalTime / this.globalStats.totalQueries
      : 0;

    const cacheHitRate = this.globalStats.totalQueries > 0
      ? (this.globalStats.cacheHits / this.globalStats.totalQueries) * 100
      : 0;

    const uptimeSeconds = (Date.now() - this.globalStats.startTime) / 1000;
    const queriesPerSecond = uptimeSeconds > 0
      ? this.globalStats.totalQueries / uptimeSeconds
      : 0;

    return {
      queryCount: this.globalStats.totalQueries,
      avgQueryTime: Math.round(avgQueryTime * 100) / 100,
      slowQueries: this.getSlowQueries(),
      cacheHitRate: Math.round(cacheHitRate * 100) / 100,
      queriesPerSecond: Math.round(queriesPerSecond * 100) / 100,
      uptime: Math.round(uptimeSeconds)
    };
  }

  logMetrics(): void {
    const stats = this.getStats();
    const slowQueryCount = stats.slowQueries.length;

    this.logger.info('Database performance metrics', {
      totalQueries: stats.queryCount,
      avgQueryTime: stats.avgQueryTime,
      cacheHitRate: stats.cacheHitRate,
      queriesPerSecond: stats.queriesPerSecond,
      slowQueryCount,
      uptime: `${Math.floor(stats.uptime / 60)}m ${stats.uptime % 60}s`,
      metricsSize: this.metrics.size
    });

    // Log top slow queries if any exist
    if (slowQueryCount > 0) {
      this.logger.warn('Top slow queries detected', {
        count: slowQueryCount,
        queries: stats.slowQueries.slice(0, 5).map(q => ({
          query: q.query,
          avgTime: q.avgTime,
          count: q.count
        }))
      });
    }

    // Performance alerts
    if (stats.avgQueryTime > 100) {
      this.logger.error('High average query time detected', {
        avgQueryTime: stats.avgQueryTime,
        totalQueries: stats.queryCount
      });
    }

    if (stats.cacheHitRate < 30 && stats.queryCount > 100) {
      this.logger.warn('Low cache hit rate detected', {
        cacheHitRate: stats.cacheHitRate,
        totalQueries: stats.queryCount
      });
    }
  }

  // Get detailed metrics for a specific query pattern
  getQueryMetrics(queryPattern: string): QueryMetric | null {
    const normalizedPattern = this.normalizeQuery(queryPattern);
    return this.metrics.get(normalizedPattern) || null;
  }

  // Get performance summary for reporting
  getPerformanceSummary(): {
    overview: {
      totalQueries: number;
      avgResponseTime: number;
      cacheHitRate: number;
      slowQueryRate: number;
      uptime: number;
    };
    topSlowQueries: SlowQuery[];
    queryDistribution: Array<{ type: string; count: number; percentage: number }>;
    hourlyStats: Array<{ hour: number; queries: number; avgTime: number }>;
  } {
    const stats = this.getStats();
    const slowQueryRate = this.globalStats.totalQueries > 0
      ? (this.globalStats.slowQueries / this.globalStats.totalQueries) * 100
      : 0;

    // Analyze query distribution
    const queryTypes = new Map<string, number>();
    for (const [query, metric] of this.metrics.entries()) {
      const type = this.getQueryType(query);
      queryTypes.set(type, (queryTypes.get(type) || 0) + metric.count);
    }

    const queryDistribution = Array.from(queryTypes.entries()).map(([type, count]) => ({
      type,
      count,
      percentage: Math.round((count / this.globalStats.totalQueries) * 100 * 100) / 100
    }));

    // TODO: Implement hourly stats tracking for more detailed analysis
    const hourlyStats: Array<{ hour: number; queries: number; avgTime: number }> = [];

    return {
      overview: {
        totalQueries: this.globalStats.totalQueries,
        avgResponseTime: stats.avgQueryTime,
        cacheHitRate: stats.cacheHitRate,
        slowQueryRate: Math.round(slowQueryRate * 100) / 100,
        uptime: stats.uptime
      },
      topSlowQueries: stats.slowQueries.slice(0, 10),
      queryDistribution: queryDistribution.sort((a, b) => b.count - a.count),
      hourlyStats
    };
  }

  // Reset all metrics
  resetMetrics(): void {
    this.metrics.clear();
    this.globalStats = {
      totalQueries: 0,
      totalTime: 0,
      cacheHits: 0,
      slowQueries: 0,
      errors: 0,
      startTime: Date.now()
    };

    this.logger.info('Database performance metrics reset');
  }

  // Track database errors
  trackError(query: string, error: Error, executionTime: number): void {
    this.globalStats.errors++;

    this.logger.error('Database query error tracked', {
      query: this.normalizeQuery(query).substring(0, 100) + '...',
      error: error.message,
      executionTime: Math.round(executionTime)
    });

    // Track the failed query in metrics with special handling
    this.trackQuery(`ERROR: ${query}`, executionTime, false);
  }

  // Get cache efficiency metrics
  getCacheEfficiency(): {
    totalQueries: number;
    cacheHits: number;
    cacheMisses: number;
    hitRate: number;
    missRate: number;
    averageTimeSaved: number;
  } {
    const cacheMisses = this.globalStats.totalQueries - this.globalStats.cacheHits;
    const hitRate = this.globalStats.totalQueries > 0
      ? (this.globalStats.cacheHits / this.globalStats.totalQueries) * 100
      : 0;
    const missRate = 100 - hitRate;

    // Estimate time saved by caching (rough approximation)
    const averageTimeSaved = this.globalStats.cacheHits > 0
      ? (this.globalStats.totalTime / this.globalStats.totalQueries) * 0.8 // Assume 80% time saved
      : 0;

    return {
      totalQueries: this.globalStats.totalQueries,
      cacheHits: this.globalStats.cacheHits,
      cacheMisses,
      hitRate: Math.round(hitRate * 100) / 100,
      missRate: Math.round(missRate * 100) / 100,
      averageTimeSaved: Math.round(averageTimeSaved * 100) / 100
    };
  }

  // Cleanup and utility methods
  private normalizeQuery(query: string): string {
    // Normalize query for consistent tracking
    return query
      .replace(/\s+/g, ' ')
      .replace(/\?/g, '?') // Keep parameter placeholders
      .replace(/\d+/g, 'N') // Replace numbers with N
      .replace(/'[^']*'/g, "'?'") // Replace string literals
      .trim()
      .substring(0, 200); // Limit length
  }

  private getQueryType(query: string): string {
    const upperQuery = query.toUpperCase();

    if (upperQuery.startsWith('SELECT')) return 'SELECT';
    if (upperQuery.startsWith('INSERT')) return 'INSERT';
    if (upperQuery.startsWith('UPDATE')) return 'UPDATE';
    if (upperQuery.startsWith('DELETE')) return 'DELETE';
    if (upperQuery.startsWith('CREATE')) return 'CREATE';
    if (upperQuery.startsWith('ALTER')) return 'ALTER';
    if (upperQuery.startsWith('DROP')) return 'DROP';

    return 'OTHER';
  }

  private cleanupOldMetrics(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    let cleaned = 0;

    for (const [query, metric] of this.metrics.entries()) {
      // Remove metrics older than 24 hours and with low usage
      if (now - metric.lastExecuted > maxAge && metric.count < 5) {
        this.metrics.delete(query);
        cleaned++;
      }
    }

    // If still too large, remove least used queries
    if (this.metrics.size > this.maxMetricsSize * 0.8) {
      const entries = Array.from(this.metrics.entries())
        .sort((a, b) => a[1].count - b[1].count);

      const toRemove = Math.floor(this.metrics.size * 0.2); // Remove 20%
      for (let i = 0; i < toRemove; i++) {
        this.metrics.delete(entries[i][0]);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug('Cleaned up old performance metrics', {
        cleaned,
        remaining: this.metrics.size
      });
    }
  }

  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupOldMetrics();
      this.logMetrics();
    }, this.cleanupInterval) as any;
  }

  // Cleanup resources
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }
    this.metrics.clear();
  }
}