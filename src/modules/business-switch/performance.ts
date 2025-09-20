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

    const sorted = [...samples].sort((a, b) => a - b);
    const count = sorted.length;

    return {
      count,
      min: sorted[0]!,
      max: sorted[count - 1]!,
      avg: samples.reduce((a, b) => a + b, 0) / count,
      p50: this.percentile(sorted, 0.5),
      p95: this.percentile(sorted, 0.95),
      p99: this.percentile(sorted, 0.99),
    };
  }

  /**
   * Calculate percentile
   */
  private percentile(sorted: number[], p: number): number {
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[Math.max(0, index)]!;
  }

  /**
   * Get all metrics
   */
  getAllStats(): Record<string, any> {
    const stats: Record<string, any> = {};

    for (const [operation, _] of this.metrics) {
      stats[operation] = this.getStats(operation);
    }

    return stats;
  }

  /**
   * Clear metrics
   */
  clear(): void {
    this.metrics.clear();
  }

  /**
   * Log slow operations
   */
  logSlowOperation(
    operation: string,
    duration: number,
    threshold: number,
    metadata?: Record<string, any>
  ): void {
    if (duration > threshold) {
      console.warn(`Slow operation detected: ${operation}`, {
        duration: `${duration.toFixed(2)}ms`,
        threshold: `${threshold}ms`,
        ...metadata,
      });
    }
  }

  /**
   * Create a detailed performance report
   */
  generateReport(): string {
    const stats = this.getAllStats();
    const report: string[] = ['=== Performance Report ==='];

    for (const [operation, stat] of Object.entries(stats)) {
      if (stat) {
        report.push(`\n${operation}:`);
        report.push(`  Samples: ${stat.count}`);
        report.push(`  Min: ${stat.min.toFixed(2)}ms`);
        report.push(`  Avg: ${stat.avg.toFixed(2)}ms`);
        report.push(`  P50: ${stat.p50.toFixed(2)}ms`);
        report.push(`  P95: ${stat.p95.toFixed(2)}ms`);
        report.push(`  P99: ${stat.p99.toFixed(2)}ms`);
        report.push(`  Max: ${stat.max.toFixed(2)}ms`);
      }
    }

    return report.join('\n');
  }
}

/**
 * Performance logger for structured logging
 */
export class PerformanceLogger {
  private logs: Array<{
    timestamp: number;
    operation: string;
    duration: number;
    metadata: Record<string, any>;
  }> = [];

  /**
   * Log a performance event
   */
  log(operation: string, duration: number, metadata?: Record<string, any>): void {
    this.logs.push({
      timestamp: Date.now(),
      operation,
      duration,
      metadata: metadata || {},
    });

    // Limit log size
    if (this.logs.length > 1000) {
      this.logs.shift();
    }

    // Also log to console in development
    if (process.env.NODE_ENV === 'development') {
      console.log(`[PERF] ${operation}: ${duration.toFixed(2)}ms`, metadata);
    }
  }

  /**
   * Get recent logs
   */
  getRecentLogs(count: number = 100): typeof this.logs {
    return this.logs.slice(-count);
  }

  /**
   * Export logs for analysis
   */
  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Clear logs
   */
  clear(): void {
    this.logs = [];
  }
}

/**
 * Track business switch performance
 */
export class SwitchPerformanceTracker {
  private monitor: PerformanceMonitor;
  private logger: PerformanceLogger;

  constructor() {
    this.monitor = new PerformanceMonitor();
    this.logger = new PerformanceLogger();
  }

  /**
   * Track a complete switch operation
   */
  trackSwitch(
    userId: string,
    fromBusinessId: string,
    toBusinessId: string
  ): {
    recordStep: (step: string) => () => void;
    complete: () => void;
  } {
    const operationId = `switch_${Date.now()}`;
    const steps: Record<string, number> = {};
    const totalTimer = this.monitor.startTimer('business_switch_total');

    return {
      recordStep: (step: string) => {
        const stepTimer = this.monitor.startTimer(`business_switch_${step}`);

        return () => {
          const duration = stepTimer();
          steps[step] = duration;

          this.logger.log(`business_switch_${step}`, duration, {
            operationId,
            userId,
            fromBusinessId,
            toBusinessId,
          });

          // Log slow steps
          this.monitor.logSlowOperation(
            `business_switch_${step}`,
            duration,
            50, // 50ms threshold for individual steps
            { operationId, userId }
          );
        };
      },

      complete: () => {
        const totalDuration = totalTimer();

        this.logger.log('business_switch_complete', totalDuration, {
          operationId,
          userId,
          fromBusinessId,
          toBusinessId,
          steps,
        });

        // Log if total time exceeds 100ms
        if (totalDuration > 100) {
          console.warn('Business switch exceeded 100ms target', {
            totalDuration: `${totalDuration.toFixed(2)}ms`,
            steps,
          });
        }

        // Send metrics to analytics
        this.sendToAnalytics({
          event: 'business_switch',
          duration: totalDuration,
          userId,
          fromBusinessId,
          toBusinessId,
          steps,
        });
      },
    };
  }

  /**
   * Get performance statistics
   */
  getStatistics(): Record<string, any> {
    return this.monitor.getAllStats();
  }

  /**
   * Get performance report
   */
  getReport(): string {
    return this.monitor.generateReport();
  }

  /**
   * Send metrics to analytics (placeholder)
   */
  private sendToAnalytics(data: any): void {
    // In production, this would send to Analytics Engine or external service
    if (process.env.NODE_ENV === 'production') {
      // analytics.track('business_switch', data);
    }
  }
}

// Global instance for singleton usage
export const switchPerformanceTracker = new SwitchPerformanceTracker();