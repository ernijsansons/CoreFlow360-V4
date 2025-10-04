/**
 * Observability Service - Application monitoring and metrics
 */

import type { Env } from '../types/environment';

export interface Metrics {
  requestCount: number;
  errorCount: number;
  avgResponseTime: number;
  activeConnections: number;
}

export class ObservabilityService {
  private metrics: Metrics = {
    requestCount: 0,
    errorCount: 0,
    avgResponseTime: 0,
    activeConnections: 0
  };

  constructor(private env: Env) {}

  /**
   * Record a request metric
   */
  recordRequest(duration: number, isError: boolean = false): void {
    this.metrics.requestCount++;
    if (isError) {
      this.metrics.errorCount++;
    }

    // Calculate rolling average
    const currentTotal = this.metrics.avgResponseTime * (this.metrics.requestCount - 1);
    this.metrics.avgResponseTime = (currentTotal + duration) / this.metrics.requestCount;
  }

  /**
   * Get current metrics
   */
  getMetrics(): Metrics {
    return { ...this.metrics };
  }

  /**
   * Track connection
   */
  trackConnection(connected: boolean): void {
    if (connected) {
      this.metrics.activeConnections++;
    } else {
      this.metrics.activeConnections = Math.max(0, this.metrics.activeConnections - 1);
    }
  }

  /**
   * Reset metrics
   */
  resetMetrics(): void {
    this.metrics = {
      requestCount: 0,
      errorCount: 0,
      avgResponseTime: 0,
      activeConnections: 0
    };
  }

  /**
   * Flush metrics to storage (if analytics binding available)
   */
  async flush(): Promise<void> {
    try {
      // If analytics engine is available, write metrics
      if (this.env.ANALYTICS || this.env.PERFORMANCE_ANALYTICS) {
        const analytics = this.env.ANALYTICS || this.env.PERFORMANCE_ANALYTICS;
        await analytics?.writeDataPoint({
          blobs: ['observability_metrics'],
          doubles: [
            this.metrics.requestCount,
            this.metrics.errorCount,
            this.metrics.avgResponseTime,
            this.metrics.activeConnections
          ],
          indexes: ['metrics']
        });
      }

      // Reset after flush
      this.resetMetrics();
    } catch (error) {
      console.error('Failed to flush observability metrics:', error);
      // Don't throw - metrics flushing is non-critical
    }
  }
}