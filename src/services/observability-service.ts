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
}