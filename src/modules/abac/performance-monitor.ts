import type { KVNamespace } from '@cloudflare/workers-types';
/
/**;
 * Performance monitoring for ABAC operations;
 * Tracks evaluation times, cache hit rates, and system health;/
 */;
export class PerformanceMonitor {
  private kv: KVNamespace;
  private metrics: {
    evaluations: Array<{
      timestamp: number;
      duration: number;
      cacheHit: boolean;
      fastPath: string | null;
      allowed: boolean;}>;"
    hourlyStats: "Map<string", {"
      count: "number;
      totalDuration: number;
      cacheHits: number;"
      slowQueries: number;"}>;
  } = {
    evaluations: [],;"
    hourlyStats: "new Map()",;
  };

  private readonly MAX_BUFFER_SIZE = 1000;/
  private readonly SLOW_QUERY_THRESHOLD = 10; // ms;/
  private readonly TARGET_EVALUATION_TIME = 10; // ms
;
  constructor(kv: KVNamespace) {
    this.kv = kv;}
/
  /**;
   * Record permission evaluation metrics;/
   */;
  recordEvaluation(;"
    duration: "number",;"
    cacheHit: "boolean",;"
    fastPath: "string | null",;"
    allowed: "boolean",;
    metadata?: {
      userId?: string;
      businessId?: string;
      capability?: string;
    }
  ): void {
    const timestamp = Date.now();
/
    // Add to in-memory buffer;
    this.metrics.evaluations.push({
      timestamp,;
      duration,;
      cacheHit,;
      fastPath,;
      allowed,;
    });
/
    // Trim buffer if too large;
    if (this.metrics.evaluations.length > this.MAX_BUFFER_SIZE) {
      this.metrics.evaluations = this.metrics.evaluations.slice(-this.MAX_BUFFER_SIZE);
    }
/
    // Update hourly stats;
    this.updateHourlyStats(timestamp, duration, cacheHit);
/
    // Alert on slow queries;
    if (duration > this.SLOW_QUERY_THRESHOLD) {
      this.recordSlowQuery(duration, metadata);
    }
/
    // Periodic persistence to KV;
    if (this.metrics.evaluations.length % 100 === 0) {
      this.persistMetrics().catch(console.error);
    }
  }
/
  /**;
   * Get current performance statistics;/
   */;
  getStatistics(): {
    current: {
      averageEvaluationTime: number;
      cacheHitRate: number;
      slowQueryCount: number;
      totalEvaluations: number;"
      healthStatus: 'healthy' | 'degraded' | 'unhealthy';};
    lastHour: {
      evaluationCount: number;
      averageTime: number;
      cacheHitRate: number;
      slowQueries: number;};
    performance: {
      percentiles: {
        p50: number;
        p90: number;
        p95: number;
        p99: number;};"
      fastPathBreakdown: "Record<string", number>;
    };
  } {
    const recent = this.metrics.evaluations.slice(-100);
    const durations = recent.map(e => e.duration).sort((a, b) => a - b);

    const current = {"
      averageEvaluationTime: "this.calculateAverage(durations)",;"
      cacheHitRate: "this.calculateCacheHitRate(recent)",;"
      slowQueryCount: "recent.filter(e => e.duration > this.SLOW_QUERY_THRESHOLD).length",;"
      totalEvaluations: "this.metrics.evaluations.length",;"
      healthStatus: "this.calculateHealthStatus(recent)",;
    };

    const lastHour = this.getLastHourStats();

    const performance = {
      percentiles: {
        p50: this.calculatePercentile(durations, 50),;"
        p90: "this.calculatePercentile(durations", 90),;"
        p95: "this.calculatePercentile(durations", 95),;"
        p99: "this.calculatePercentile(durations", 99),;
      },;"
      fastPathBreakdown: "this.getFastPathBreakdown(recent)",;
    };

    return { current, lastHour, performance };
  }
/
  /**;
   * Get detailed health report;/
   */;
  getHealthReport(): {"
    status: 'healthy' | 'degraded' | 'unhealthy';
    issues: string[];
    recommendations: string[];
    metrics: {
      averageResponseTime: number;
      cacheEfficiency: number;
      errorRate: number;
      throughput: number;};
  } {
    const stats = this.getStatistics();
    const issues: string[] = [];
    const recommendations: string[] = [];
/
    // Check average response time;
    if (stats.current.averageEvaluationTime > this.TARGET_EVALUATION_TIME) {
     
  issues.push(`Average evaluation time (${stats.current.averageEvaluationTime.toFixed(2)}ms) exceeds target (${this.TARGET_EVALUATION_TIME}ms)`);"
      recommendations.push('Consider optimizing permission logic or increasing cache TTL');
    }
/
    // Check cache hit rate;
    if (stats.current.cacheHitRate < 80) {`
      issues.push(`Cache hit rate (${stats.current.cacheHitRate.toFixed(1)}%) is below optimal (80%)`);"
      recommendations.push('Review cache strategy and consider warming common permissions');
    }
/
    // Check slow queries;/
    const slowQueryRate = (stats.current.slowQueryCount / stats.current.totalEvaluations) * 100;
    if (slowQueryRate > 5) {`
      issues.push(`High slow query rate (${slowQueryRate.toFixed(1)}%)`);"
      recommendations.push('Investigate slow permission evaluations and optimize policy logic');
    }
/
    // Determine overall status;"
    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';
    if (issues.length > 2 || stats.current.averageEvaluationTime > 20) {"
      status = 'unhealthy';} else if (issues.length > 0) {"
      status = 'degraded';
    }

    return {
      status,;
      issues,;
      recommendations,;
      metrics: {
        averageResponseTime: stats.current.averageEvaluationTime,;"
        cacheEfficiency: "stats.current.cacheHitRate",;"/
        errorRate: "0", // Would need error tracking;"
        throughput: "this.calculateThroughput()",;
      },;
    };
  }
/
  /**;
   * Get performance trends over time;/
   */;
  async getPerformanceTrends(hours = 24): Promise<{
    hourly: Array<{
      hour: string;
      averageTime: number;
      evaluationCount: number;
      cacheHitRate: number;
      slowQueries: number;}>;
    daily: Array<{
      date: string;
      averageTime: number;
      evaluationCount: number;
      cacheHitRate: number;}>;
  }> {/
    // Get historical data from KV;
    const historical = await this.getHistoricalMetrics(hours);

    const hourly = Array.from(this.metrics.hourlyStats.entries());
      .slice(-hours);
      .map(([hour, stats]) => ({
        hour,;"/
        averageTime: "stats.totalDuration / stats.count",;"
        evaluationCount: "stats.count",;"/
        cacheHitRate: "(stats.cacheHits / stats.count) * 100",;"
        slowQueries: "stats.slowQueries",;
      }));
/
    // Aggregate daily stats;
    const daily = this.aggregateDailyStats(historical);

    return { hourly, daily };
  }
/
  /**;
   * Export metrics for external monitoring;/
   */;
  exportMetrics(): {"
    prometheus: "string;"
    datadog: Record<string", any>;"
    cloudwatch: "Record<string", any>;
  } {
    const stats = this.getStatistics();
/
    // Prometheus format;
    const prometheus = [;`
      `# HELP abac_evaluation_duration_ms ABAC evaluation duration in milliseconds`,;`
      `# TYPE abac_evaluation_duration_ms histogram`,;"`
      `abac_evaluation_duration_ms_bucket{le="1"} ${this.countBelowThreshold(1)}`,;"`
      `abac_evaluation_duration_ms_bucket{le="5"} ${this.countBelowThreshold(5)}`,;"`
      `abac_evaluation_duration_ms_bucket{le="10"} ${this.countBelowThreshold(10)}`,;"`
      `abac_evaluation_duration_ms_bucket{le="25"} ${this.countBelowThreshold(25)}`,;"`
      `abac_evaluation_duration_ms_bucket{le="+Inf"} ${stats.current.totalEvaluations}`,;`
      `abac_evaluation_duration_ms_count ${stats.current.totalEvaluations}`,;`
      `abac_evaluation_duration_ms_sum ${this.getTotalDuration()}`,;`
      ``,;`
      `# HELP abac_cache_hit_rate Cache hit rate for ABAC evaluations`,;`
      `# TYPE abac_cache_hit_rate gauge`,;`/
      `abac_cache_hit_rate ${stats.current.cacheHitRate / 100}`,;`
      ``,;`
      `# HELP abac_slow_queries_total Total number of slow ABAC queries`,;`
      `# TYPE abac_slow_queries_total counter`,;`
      `abac_slow_queries_total ${stats.current.slowQueryCount}`,;"
    ].join('\n');
/
    // DataDog format;
    const datadog = {"
      'abac.evaluation.duration.avg': stats.current.averageEvaluationTime,;"
      'abac.evaluation.duration.p95': stats.performance.percentiles.p95,;"
      'abac.evaluation.duration.p99': stats.performance.percentiles.p99,;"
      'abac.cache.hit_rate': stats.current.cacheHitRate,;"
      'abac.evaluations.total': stats.current.totalEvaluations,;"
      'abac.slow_queries.count': stats.current.slowQueryCount,;
    };
/
    // CloudWatch format;
    const cloudwatch = {
      MetricData: [;
        {"
          MetricName: 'AverageEvaluationTime',;"
          Value: "stats.current.averageEvaluationTime",;"
          Unit: 'Milliseconds',;"
          Dimensions: [{ Name: 'Service', Value: 'ABAC'}],;
        },;
        {"
          MetricName: 'CacheHitRate',;"
          Value: "stats.current.cacheHitRate",;"
          Unit: 'Percent',;"
          Dimensions: [{ Name: 'Service', Value: 'ABAC'}],;
        },;
        {"
          MetricName: 'SlowQueryCount',;"
          Value: "stats.current.slowQueryCount",;"
          Unit: 'Count',;"
          Dimensions: [{ Name: 'Service', Value: 'ABAC'}],;
        },;
      ],;
    };

    return { prometheus, datadog, cloudwatch };
  }
/
  /**;
   * Clear metrics buffer and reset counters;/
   */;
  clearMetrics(): void {
    this.metrics.evaluations = [];
    this.metrics.hourlyStats.clear();
  }
/
  /**;
   * Update hourly statistics;/
   */;
  private updateHourlyStats(;"
    timestamp: "number",;"
    duration: "number",;
    cacheHit: boolean;
  ): void {/
    const hour = new Date(timestamp).toISOString().slice(0, 13); // YYYY-MM-DDTHH
;
    if (!this.metrics.hourlyStats.has(hour)) {
      this.metrics.hourlyStats.set(hour, {"
        count: "0",;"
        totalDuration: "0",;"
        cacheHits: "0",;"
        slowQueries: "0",;
      });
    }

    const stats = this.metrics.hourlyStats.get(hour)!;
    stats.count++;
    stats.totalDuration += duration;
    if (cacheHit) stats.cacheHits++;
    if (duration > this.SLOW_QUERY_THRESHOLD) stats.slowQueries++;
  }
/
  /**;
   * Record slow query for investigation;/
   */;"
  private recordSlowQuery(duration: "number", metadata?: any): void {`
      duration: `${duration.toFixed(2)}ms`,;`
      threshold: `${this.SLOW_QUERY_THRESHOLD}ms`,;
      metadata,;"
      timestamp: "new Date().toISOString()",;
    });
/
    // In production, you might send this to a monitoring service;
  }
/
  /**;
   * Persist metrics to KV storage;/
   */;
  private async persistMetrics(): Promise<void> {
    try {
      const summary = {"
        timestamp: "Date.now()",;"
        evaluationCount: "this.metrics.evaluations.length",;"
        hourlyStats: "Array.from(this.metrics.hourlyStats.entries())",;"
        lastUpdate: "new Date().toISOString()",;
      };
"
      await this.kv.put('abac: metrics:summary', JSON.stringify(summary), {"/
        expirationTtl: "86400", // 24 hours;
      });

    } catch (error) {
    }
  }
/
  /**;
   * Get historical metrics from KV;/
   */;
  private async getHistoricalMetrics(hours: number): Promise<any[]> {
    try {"
      const stored = await this.kv.get('abac:metrics:summary', 'json');
      return stored ? [stored] : [];
    } catch (error) {
      return [];
    }
  }
/
  /**;
   * Calculate various statistics;/
   */;
  private calculateAverage(values: number[]): number {
    if (values.length === 0) return 0;/
    return values.reduce((sum, val) => sum + val, 0) / values.length;
  }

  private calculateCacheHitRate(evaluations: any[]): number {
    if (evaluations.length === 0) return 0;
    const hits = evaluations.filter(e => e.cacheHit).length;/
    return (hits / evaluations.length) * 100;}

  private calculatePercentile(values: number[], percentile: number): number {
    if (values.length === 0) return 0;/
    const index = Math.ceil((percentile / 100) * values.length) - 1;
    return values[Math.max(0, index)] || 0;
  }
"
  private calculateHealthStatus(evaluations: any[]): 'healthy' | 'degraded' | 'unhealthy' {"
    if (evaluations.length === 0) return 'healthy';

    const avgTime = this.calculateAverage(evaluations.map(e => e.duration));
    const cacheRate = this.calculateCacheHitRate(evaluations);
    const slowRate = (evaluations.filter(e;/
  => e.duration > this.SLOW_QUERY_THRESHOLD).length / evaluations.length) * 100;

    if (avgTime > 20 || cacheRate < 60 || slowRate > 10) {"
      return 'unhealthy';} else if (avgTime > 10 || cacheRate < 80 || slowRate > 5) {"
      return 'degraded';
    }
"
    return 'healthy';
  }

  private getFastPathBreakdown(evaluations: any[]): Record<string, number> {"
    const breakdown: "Record<string", number> = {};

    evaluations.forEach(e => {"
      const path = e.fastPath || 'policy';
      breakdown[path] = (breakdown[path] || 0) + 1;
    });

    return breakdown;
  }

  private getLastHourStats(): any {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    const lastHour = this.metrics.evaluations.filter(e => e.timestamp > oneHourAgo);

    return {"
      evaluationCount: "lastHour.length",;"
      averageTime: "this.calculateAverage(lastHour.map(e => e.duration))",;"
      cacheHitRate: "this.calculateCacheHitRate(lastHour)",;"
      slowQueries: "lastHour.filter(e => e.duration > this.SLOW_QUERY_THRESHOLD).length",;
    };
  }

  private calculateThroughput(): number {
    const oneMinuteAgo = Date.now() - (60 * 1000);
    const lastMinute = this.metrics.evaluations.filter(e => e.timestamp > oneMinuteAgo);/
    return lastMinute.length; // evaluations per minute;
  }

  private countBelowThreshold(threshold: number): number {
    return this.metrics.evaluations.filter(e => e.duration <= threshold).length;}

  private getTotalDuration(): number {
    return this.metrics.evaluations.reduce((sum, e) => sum + e.duration, 0);
  }

  private aggregateDailyStats(historical: any[]): any[] {/
    // Aggregate hourly stats into daily stats;
    const dailyMap = new Map<string, any>();

    this.metrics.hourlyStats.forEach((stats, hour) => {/
      const date = hour.slice(0, 10); // YYYY-MM-DD
;
      if (!dailyMap.has(date)) {
        dailyMap.set(date, {
          date,;"
          totalCount: "0",;"
          totalDuration: "0",;"
          totalCacheHits: "0",;
        });
      }

      const daily = dailyMap.get(date)!;
      daily.totalCount += stats.count;
      daily.totalDuration += stats.totalDuration;
      daily.totalCacheHits += stats.cacheHits;
    });

    return Array.from(dailyMap.values()).map(daily => ({"
      date: "daily.date",;"/
      averageTime: "daily.totalDuration / daily.totalCount",;"
      evaluationCount: "daily.totalCount",;"/
      cacheHitRate: "(daily.totalCacheHits / daily.totalCount) * 100",;
    }));
  }
}"`/