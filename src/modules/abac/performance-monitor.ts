/**
 * ABAC Performance Monitor
 * Monitors and optimizes performance of Attribute-Based Access Control system
 */
import { Logger } from '../../shared/logger';

interface PerformanceMetrics {
  totalRequests: number;
  averageResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
  errorRate: number;
  cacheHitRate: number;
  memoryUsage: number;
  cpuUsage: number;
  throughput: number;
  latency: number;
}

interface PerformanceThresholds {
  maxResponseTime: number;
  maxErrorRate: number;
  minCacheHitRate: number;
  maxMemoryUsage: number;
  maxCpuUsage: number;
  minThroughput: number;
  maxLatency: number;
}

interface PerformanceAlert {
  id: string;
  type: 'response_time' | 'error_rate' | 'cache_hit_rate' | 'memory_usage' | 'cpu_usage' | 'throughput' | 'latency';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  value: number;
  threshold: number;
  timestamp: Date;
  resolved: boolean;
  resolvedAt?: Date;
}

interface PerformanceReport {
  timestamp: Date;
  metrics: PerformanceMetrics;
  alerts: PerformanceAlert[];
  recommendations: string[];
  healthScore: number;
  trends: PerformanceTrends;
}

interface PerformanceTrends {
  responseTime: 'improving' | 'stable' | 'degrading';
  errorRate: 'improving' | 'stable' | 'degrading';
  cacheHitRate: 'improving' | 'stable' | 'degrading';
  memoryUsage: 'improving' | 'stable' | 'degrading';
  throughput: 'improving' | 'stable' | 'degrading';
}

interface RequestMetrics {
  requestId: string;
  startTime: number;
  endTime: number;
  duration: number;
  success: boolean;
  error?: string;
  cacheHit: boolean;
  memoryUsed: number;
  cpuUsed: number;
}

export class ABACPerformanceMonitor {
  private logger: Logger;
  private metrics: PerformanceMetrics;
  private thresholds: PerformanceThresholds;
  private alerts: Map<string, PerformanceAlert> = new Map();
  private requestHistory: RequestMetrics[] = [];
  private maxHistorySize: number = 10000;
  private isMonitoring: boolean = false;
  private monitoringInterval?: NodeJS.Timeout;

  constructor(config?: Partial<PerformanceThresholds>) {
    this.logger = new Logger({ component: 'abac-performance-monitor' });
    
    this.thresholds = {
      maxResponseTime: 1000, // 1 second
      maxErrorRate: 0.05, // 5%
      minCacheHitRate: 0.8, // 80%
      maxMemoryUsage: 100 * 1024 * 1024, // 100MB
      maxCpuUsage: 0.8, // 80%
      minThroughput: 100, // 100 requests per second
      maxLatency: 500, // 500ms
      ...config
    };

    this.metrics = {
      totalRequests: 0,
      averageResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
      errorRate: 0,
      cacheHitRate: 0,
      memoryUsage: 0,
      cpuUsage: 0,
      throughput: 0,
      latency: 0
    };
  }

  startMonitoring(intervalMs: number = 60000): void {
    if (this.isMonitoring) {
      this.logger.warn('Performance monitoring already started');
      return;
    }

    this.isMonitoring = true;
    this.monitoringInterval = setInterval(() => {
      this.updateMetrics();
      this.checkThresholds();
    }, intervalMs);

    this.logger.info('Performance monitoring started', { intervalMs });
  }

  stopMonitoring(): void {
    if (!this.isMonitoring) {
      this.logger.warn('Performance monitoring not started');
      return;
    }

    this.isMonitoring = false;
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = undefined;
    }

    this.logger.info('Performance monitoring stopped');
  }

  recordRequest(metrics: Omit<RequestMetrics, 'duration'>): void {
    const requestMetrics: RequestMetrics = {
      ...metrics,
      duration: metrics.endTime - metrics.startTime
    };

    this.requestHistory.push(requestMetrics);

    // Keep history size manageable
    if (this.requestHistory.length > this.maxHistorySize) {
      this.requestHistory = this.requestHistory.slice(-this.maxHistorySize);
    }

    this.logger.debug('Request metrics recorded', {
      requestId: requestMetrics.requestId,
      duration: requestMetrics.duration,
      success: requestMetrics.success,
      cacheHit: requestMetrics.cacheHit
    });
  }

  getMetrics(): PerformanceMetrics {
    return { ...this.metrics };
  }

  getAlerts(): PerformanceAlert[] {
    return Array.from(this.alerts.values()).filter(alert => !alert.resolved);
  }

  getAllAlerts(): PerformanceAlert[] {
    return Array.from(this.alerts.values());
  }

  getReport(): PerformanceReport {
    const trends = this.calculateTrends();
    const healthScore = this.calculateHealthScore();
    const recommendations = this.generateRecommendations();

    return {
      timestamp: new Date(),
      metrics: this.getMetrics(),
      alerts: this.getAlerts(),
      recommendations,
      healthScore,
      trends
    };
  }

  private updateMetrics(): void {
    if (this.requestHistory.length === 0) {
      return;
    }

    const now = Date.now();
    const recentRequests = this.requestHistory.filter(
      req => now - req.endTime < 60000 // Last minute
    );

    if (recentRequests.length === 0) {
      return;
    }

    // Calculate response times
    const responseTimes = recentRequests.map(req => req.duration);
    responseTimes.sort((a, b) => a - b);

    this.metrics.totalRequests = this.requestHistory.length;
    this.metrics.averageResponseTime = responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length;
    this.metrics.p95ResponseTime = this.percentile(responseTimes, 95);
    this.metrics.p99ResponseTime = this.percentile(responseTimes, 99);

    // Calculate error rate
    const errorCount = recentRequests.filter(req => !req.success).length;
    this.metrics.errorRate = errorCount / recentRequests.length;

    // Calculate cache hit rate
    const cacheHits = recentRequests.filter(req => req.cacheHit).length;
    this.metrics.cacheHitRate = cacheHits / recentRequests.length;

    // Calculate memory usage
    this.metrics.memoryUsage = process.memoryUsage().heapUsed;

    // Calculate CPU usage (simplified)
    this.metrics.cpuUsage = this.calculateCpuUsage();

    // Calculate throughput
    this.metrics.throughput = recentRequests.length / 60; // requests per second

    // Calculate latency
    this.metrics.latency = this.metrics.averageResponseTime;

    this.logger.debug('Metrics updated', {
      totalRequests: this.metrics.totalRequests,
      averageResponseTime: this.metrics.averageResponseTime,
      errorRate: this.metrics.errorRate,
      cacheHitRate: this.metrics.cacheHitRate
    });
  }

  private checkThresholds(): void {
    const checks = [
      {
        type: 'response_time' as const,
        value: this.metrics.averageResponseTime,
        threshold: this.thresholds.maxResponseTime,
        operator: 'gt'
      },
      {
        type: 'error_rate' as const,
        value: this.metrics.errorRate,
        threshold: this.thresholds.maxErrorRate,
        operator: 'gt'
      },
      {
        type: 'cache_hit_rate' as const,
        value: this.metrics.cacheHitRate,
        threshold: this.thresholds.minCacheHitRate,
        operator: 'lt'
      },
      {
        type: 'memory_usage' as const,
        value: this.metrics.memoryUsage,
        threshold: this.thresholds.maxMemoryUsage,
        operator: 'gt'
      },
      {
        type: 'cpu_usage' as const,
        value: this.metrics.cpuUsage,
        threshold: this.thresholds.maxCpuUsage,
        operator: 'gt'
      },
      {
        type: 'throughput' as const,
        value: this.metrics.throughput,
        threshold: this.thresholds.minThroughput,
        operator: 'lt'
      },
      {
        type: 'latency' as const,
        value: this.metrics.latency,
        threshold: this.thresholds.maxLatency,
        operator: 'gt'
      }
    ];

    for (const check of checks) {
      const isViolated = check.operator === 'gt' 
        ? check.value > check.threshold
        : check.value < check.threshold;

      if (isViolated) {
        this.createAlert(check.type, check.value, check.threshold);
      } else {
        this.resolveAlert(check.type);
      }
    }
  }

  private createAlert(
    type: PerformanceAlert['type'],
    value: number,
    threshold: number
  ): void {
    const alertId = `${type}_${Date.now()}`;
    const existingAlert = Array.from(this.alerts.values())
      .find(alert => alert.type === type && !alert.resolved);

    if (existingAlert) {
      return; // Alert already exists
    }

    const severity = this.calculateSeverity(type, value, threshold);
    const message = this.generateAlertMessage(type, value, threshold, severity);

    const alert: PerformanceAlert = {
      id: alertId,
      type,
      severity,
      message,
      value,
      threshold,
      timestamp: new Date(),
      resolved: false
    };

    this.alerts.set(alertId, alert);

    this.logger.warn('Performance alert created', {
      type,
      severity,
      value,
      threshold,
      message
    });
  }

  private resolveAlert(type: PerformanceAlert['type']): void {
    const existingAlert = Array.from(this.alerts.values())
      .find(alert => alert.type === type && !alert.resolved);

    if (existingAlert) {
      existingAlert.resolved = true;
      existingAlert.resolvedAt = new Date();

      this.logger.info('Performance alert resolved', {
        type,
        alertId: existingAlert.id
      });
    }
  }

  private calculateSeverity(
    type: PerformanceAlert['type'],
    value: number,
    threshold: number
  ): PerformanceAlert['severity'] {
    const ratio = Math.abs(value - threshold) / threshold;

    if (ratio > 2) return 'critical';
    if (ratio > 1) return 'high';
    if (ratio > 0.5) return 'medium';
    return 'low';
  }

  private generateAlertMessage(
    type: PerformanceAlert['type'],
    value: number,
    threshold: number,
    severity: PerformanceAlert['severity']
  ): string {
    const messages = {
      response_time: `Average response time ${value.toFixed(2)}ms exceeds threshold ${threshold}ms`,
      error_rate: `Error rate ${(value * 100).toFixed(2)}% exceeds threshold ${(threshold * 100).toFixed(2)}%`,
      cache_hit_rate: `Cache hit rate ${(value * 100).toFixed(2)}% below threshold ${(threshold * 100).toFixed(2)}%`,
      memory_usage: `Memory usage ${(value / 1024 / 1024).toFixed(2)}MB exceeds threshold ${(threshold / 1024 / 1024).toFixed(2)}MB`,
      cpu_usage: `CPU usage ${(value * 100).toFixed(2)}% exceeds threshold ${(threshold * 100).toFixed(2)}%`,
      throughput: `Throughput ${value.toFixed(2)} req/s below threshold ${threshold} req/s`,
      latency: `Latency ${value.toFixed(2)}ms exceeds threshold ${threshold}ms`
    };

    return messages[type] || `Performance threshold violated for ${type}`;
  }

  private calculateTrends(): PerformanceTrends {
    const recent = this.requestHistory.slice(-100); // Last 100 requests
    const older = this.requestHistory.slice(-200, -100); // Previous 100 requests

    if (recent.length < 10 || older.length < 10) {
      return {
        responseTime: 'stable',
        errorRate: 'stable',
        cacheHitRate: 'stable',
        memoryUsage: 'stable',
        throughput: 'stable'
      };
    }

    const recentAvgResponseTime = recent.reduce((sum, req) => sum + req.duration, 0) / recent.length;
    const olderAvgResponseTime = older.reduce((sum, req) => sum + req.duration, 0) / older.length;

    const recentErrorRate = recent.filter(req => !req.success).length / recent.length;
    const olderErrorRate = older.filter(req => !req.success).length / older.length;

    const recentCacheHitRate = recent.filter(req => req.cacheHit).length / recent.length;
    const olderCacheHitRate = older.filter(req => req.cacheHit).length / older.length;

    const recentThroughput = recent.length / 60;
    const olderThroughput = older.length / 60;

    return {
      responseTime: this.calculateTrend(recentAvgResponseTime, olderAvgResponseTime, false),
      errorRate: this.calculateTrend(recentErrorRate, olderErrorRate, false),
      cacheHitRate: this.calculateTrend(recentCacheHitRate, olderCacheHitRate, true),
      memoryUsage: 'stable', // Would need more sophisticated tracking
      throughput: this.calculateTrend(recentThroughput, olderThroughput, true)
    };
  }

  private calculateTrend(
    recent: number,
    older: number,
    higherIsBetter: boolean
  ): 'improving' | 'stable' | 'degrading' {
    const change = (recent - older) / older;
    const threshold = 0.1; // 10% change threshold

    if (Math.abs(change) < threshold) {
      return 'stable';
    }

    const isImproving = higherIsBetter ? change > 0 : change < 0;
    return isImproving ? 'improving' : 'degrading';
  }

  private calculateHealthScore(): number {
    let score = 100;

    // Deduct points for threshold violations
    const alerts = this.getAlerts();
    for (const alert of alerts) {
      const severityPenalty = {
        low: 5,
        medium: 10,
        high: 20,
        critical: 40
      };
      score -= severityPenalty[alert.severity];
    }

    // Deduct points for poor metrics
    if (this.metrics.errorRate > 0.1) score -= 20;
    if (this.metrics.cacheHitRate < 0.5) score -= 15;
    if (this.metrics.averageResponseTime > 2000) score -= 25;

    return Math.max(0, Math.min(100, score));
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];

    if (this.metrics.cacheHitRate < 0.8) {
      recommendations.push('Consider increasing cache TTL or improving cache key strategies');
    }

    if (this.metrics.averageResponseTime > 1000) {
      recommendations.push('Optimize database queries and consider adding indexes');
    }

    if (this.metrics.errorRate > 0.05) {
      recommendations.push('Investigate and fix error sources to improve reliability');
    }

    if (this.metrics.memoryUsage > 50 * 1024 * 1024) {
      recommendations.push('Consider implementing memory cleanup or increasing memory limits');
    }

    if (this.metrics.throughput < 50) {
      recommendations.push('Scale horizontally or optimize request processing');
    }

    return recommendations;
  }

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

  private calculateCpuUsage(): number {
    // Simplified CPU usage calculation
    // In a real implementation, you would use system metrics
    return Math.random() * 0.5; // Mock value
  }

  // Configuration methods
  updateThresholds(newThresholds: Partial<PerformanceThresholds>): void {
    this.thresholds = { ...this.thresholds, ...newThresholds };
    this.logger.info('Performance thresholds updated', { newThresholds });
  }

  getThresholds(): PerformanceThresholds {
    return { ...this.thresholds };
  }

  // Utility methods
  clearHistory(): void {
    this.requestHistory = [];
    this.logger.info('Request history cleared');
  }

  clearAlerts(): void {
    this.alerts.clear();
    this.logger.info('Performance alerts cleared');
  }

  isHealthy(): boolean {
    const healthScore = this.calculateHealthScore();
    return healthScore >= 70; // Consider healthy if score >= 70
  }

  getStatus(): {
    monitoring: boolean;
    healthy: boolean;
    metrics: PerformanceMetrics;
    alertCount: number;
    healthScore: number;
  } {
    return {
      monitoring: this.isMonitoring,
      healthy: this.isHealthy(),
      metrics: this.getMetrics(),
      alertCount: this.getAlerts().length,
      healthScore: this.calculateHealthScore()
    };
  }
}

