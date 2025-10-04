/**
 * Performance monitoring for business switching
 */
export class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private readonly maxSamples = 100;

  /**
   * Start timing an operation
   */
  startTimer(operationId: string): () => number {
    const startTime = performance.now();

    return () => {
      const duration = performance.now() - startTime;
      this.recordMetric(operationId, duration);
      return duration;
    };
  }

  /**
   * Record a metric
   */
  recordMetric(operation: string, duration: number): void {
    const samples = this.metrics.get(operation) || [];
    samples.push(duration);

    // Keep only recent samples
    if (samples.length > this.maxSamples) {
      samples.shift();
    }

    this.metrics.set(operation, samples);
  }

  /**
   * Get statistics for an operation
   */
  getStats(operation: string): {
    count: number;
    min: number;
    max: number;
    avg: number;
    p50: number;
    p95: number;
    p99: number;
  } | null {
    const samples = this.metrics.get(operation);
    if (!samples || samples.length === 0) {
      return null;
    }

    const sortedSamples = [...samples].sort((a, b) => a - b);
    const count = sortedSamples.length;
    const min = sortedSamples[0];
    const max = sortedSamples[count - 1];
    const avg = sortedSamples.reduce((sum, val) => sum + val, 0) / count;
    const p50 = this.percentile(sortedSamples, 50);
    const p95 = this.percentile(sortedSamples, 95);
    const p99 = this.percentile(sortedSamples, 99);

    return {
      count,
      min,
      max,
      avg,
      p50,
      p95,
      p99,
    };
  }

  /**
   * Get all metrics
   */
  getAllMetrics(): Map<string, number[]> {
    return new Map(this.metrics);
  }

  /**
   * Clear metrics for an operation
   */
  clearMetrics(operation: string): void {
    this.metrics.delete(operation);
  }

  /**
   * Clear all metrics
   */
  clearAllMetrics(): void {
    this.metrics.clear();
  }

  /**
   * Get performance summary
   */
  getPerformanceSummary(): {
    totalOperations: number;
    averagePerformance: number;
    slowestOperation: string | null;
    fastestOperation: string | null;
    operations: Array<{
      operation: string;
      count: number;
      avg: number;
      p95: number;
    }>;
  } {
    const operations: Array<{
      operation: string;
      count: number;
      avg: number;
      p95: number;
    }> = [];

    let totalOperations = 0;
    let totalDuration = 0;
    let slowestOperation: string | null = null;
    let fastestOperation: string | null = null;
    let slowestAvg = 0;
    let fastestAvg = Infinity;

    for (const [operation, samples] of this.metrics) {
      const stats = this.getStats(operation);
      if (stats) {
        operations.push({
          operation,
          count: stats.count,
          avg: stats.avg,
          p95: stats.p95,
        });

        totalOperations += stats.count;
        totalDuration += stats.avg * stats.count;

        if (stats.avg > slowestAvg) {
          slowestAvg = stats.avg;
          slowestOperation = operation;
        }

        if (stats.avg < fastestAvg) {
          fastestAvg = stats.avg;
          fastestOperation = operation;
        }
      }
    }

    const averagePerformance = totalOperations > 0 ? totalDuration / totalOperations : 0;

    return {
      totalOperations,
      averagePerformance,
      slowestOperation,
      fastestOperation,
      operations: operations.sort((a, b) => b.avg - a.avg),
    };
  }

  /**
   * Check if performance is within acceptable limits
   */
  isPerformanceAcceptable(
    operation: string,
    maxDuration: number = 1000
  ): boolean {
    const stats = this.getStats(operation);
    if (!stats) {
      return true; // No data means no performance issues
    }

    return stats.p95 <= maxDuration;
  }

  /**
   * Get performance alerts
   */
  getPerformanceAlerts(
    thresholds: Record<string, number> = {}
  ): Array<{
    operation: string;
    currentP95: number;
    threshold: number;
    severity: 'warning' | 'critical';
  }> {
    const alerts: Array<{
      operation: string;
      currentP95: number;
      threshold: number;
      severity: 'warning' | 'critical';
    }> = [];

    const defaultThresholds = {
      'business_switch': 2000,
      'context_load': 1000,
      'permission_check': 500,
      'data_sync': 3000,
    };

    const allThresholds: Record<string, number> = { ...defaultThresholds, ...thresholds };

    for (const [operation, samples] of this.metrics) {
      const stats = this.getStats(operation);
      if (!stats) continue;

      const threshold = allThresholds[operation] || 1000;
      const severity = stats.p95 > threshold * 2 ? 'critical' : 'warning';

      if (stats.p95 > threshold) {
        alerts.push({
          operation,
          currentP95: stats.p95,
          threshold,
          severity,
        });
      }
    }

    return alerts.sort((a, b) => b.currentP95 - a.currentP95);
  }

  /**
   * Export metrics data
   */
  exportMetrics(): {
    timestamp: number;
    metrics: Record<string, {
      samples: number[];
      stats: {
        count: number;
        min: number;
        max: number;
        avg: number;
        p50: number;
        p95: number;
        p99: number;
      };
    }>;
  } {
    const exportedMetrics: Record<string, {
      samples: number[];
      stats: {
        count: number;
        min: number;
        max: number;
        avg: number;
        p50: number;
        p95: number;
        p99: number;
      };
    }> = {};

    for (const [operation, samples] of this.metrics) {
      const stats = this.getStats(operation);
      if (stats) {
        exportedMetrics[operation] = {
          samples: [...samples],
          stats,
        };
      }
    }

    return {
      timestamp: Date.now(),
      metrics: exportedMetrics,
    };
  }

  /**
   * Import metrics data
   */
  importMetrics(data: {
    timestamp: number;
    metrics: Record<string, {
      samples: number[];
      stats: {
        count: number;
        min: number;
        max: number;
        avg: number;
        p50: number;
        p95: number;
        p99: number;
      };
    }>;
  }): void {
    for (const [operation, data] of Object.entries(data.metrics)) {
      this.metrics.set(operation, [...data.samples]);
    }
  }

  /**
   * Calculate percentile
   */
  private percentile(sortedArray: number[], percentile: number): number {
    const index = (percentile / 100) * (sortedArray.length - 1);
    const lower = Math.floor(index);
    const upper = Math.ceil(index);
    const weight = index % 1;

    if (upper >= sortedArray.length) {
      return sortedArray[sortedArray.length - 1];
    }

    return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
  }

  /**
   * Get memory usage
   */
  getMemoryUsage(): {
    metricsCount: number;
    totalSamples: number;
    estimatedMemoryKB: number;
  } {
    let totalSamples = 0;
    for (const samples of this.metrics.values()) {
      totalSamples += samples.length;
    }

    // Rough estimate: each number is 8 bytes, plus Map overhead
    const estimatedMemoryKB = (totalSamples * 8 + this.metrics.size * 100) / 1024;

    return {
      metricsCount: this.metrics.size,
      totalSamples,
      estimatedMemoryKB: Math.round(estimatedMemoryKB * 100) / 100,
    };
  }

  /**
   * Cleanup old metrics
   */
  cleanupOldMetrics(maxAgeMs: number = 3600000): void {
    const cutoffTime = Date.now() - maxAgeMs;
    
    for (const [operation, samples] of this.metrics) {
      // This is a simplified cleanup - in a real implementation,
      // you'd want to track timestamps for each sample
      if (samples.length > this.maxSamples) {
        const cleanedSamples = samples.slice(-this.maxSamples);
        this.metrics.set(operation, cleanedSamples);
      }
    }
  }

  /**
   * Reset performance monitor
   */
  reset(): void {
    this.metrics.clear();
  }
}

