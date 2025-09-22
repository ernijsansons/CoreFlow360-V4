/**
 * Stream Metrics and Monitoring System
 * Provides real-time performance monitoring and health checking
 */

import {
  StreamMetrics,
  StreamState,
  StreamAnalytics,
  ConnectionQuality,
  SSEStreamConfig
} from './types';
import { Logger } from '../../shared/logger';

interface MetricsAggregation {
  totalStreams: number;
  activeStreams: number;
  completedStreams: number;
  errorStreams: number;
  averageLatency: number;
  averageThroughput: number;
  errorRate: number;
  uptime: number;
}

interface PerformanceAlert {
  id: string;
  streamId?: string;
  type: 'latency' | 'throughput' | 'error_rate' | 'memory' | 'connection';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  threshold: number;
  actualValue: number;
  timestamp: number;
  correlationId?: string;
}

export class StreamMetricsCollector {
  private logger: Logger;
  private metrics: Map<string, StreamMetrics> = new Map();
  private aggregatedMetrics: MetricsAggregation;
  private alerts: PerformanceAlert[] = [];
  private startTime: number;

  // Performance thresholds
  private readonly thresholds = {
    firstTokenLatency: 150, // ms
    averageTokenLatency: 50, // ms
    throughputMinimum: 10, // tokens/second
    errorRateMaximum: 0.05, // 5%
    bufferUsageMaximum: 0.8, // 80% of buffer
    memoryUsageMaximum: 100 * 1024 * 1024, // 100MB
    connectionLatencyMaximum: 1000 // ms
  };

  constructor() {
    this.logger = new Logger();
    this.startTime = Date.now();
    this.aggregatedMetrics = {
      totalStreams: 0,
      activeStreams: 0,
      completedStreams: 0,
      errorStreams: 0,
      averageLatency: 0,
      averageThroughput: 0,
      errorRate: 0,
      uptime: 0
    };

    this.startPeriodicMetricsCollection();
  }

  /**
   * Records metrics for a stream
   */
  recordStreamMetrics(streamId: string, metrics: StreamMetrics): void {
    this.metrics.set(streamId, metrics);
    this.updateAggregatedMetrics();
    this.checkPerformanceAlerts(streamId, metrics);
  }

  /**
   * Records stream completion
   */
  recordStreamCompletion(streamId: string, reason: 'complete' | 'error' | 'timeout' | 'cancelled'): void {
    const metrics = this.metrics.get(streamId);
    if (!metrics) return;

    metrics.endTime = Date.now();

    if (reason === 'complete') {
      this.aggregatedMetrics.completedStreams++;
    } else {
      this.aggregatedMetrics.errorStreams++;
    }

    this.aggregatedMetrics.activeStreams = Math.max(0, this.aggregatedMetrics.activeStreams - 1);
    this.updateAggregatedMetrics();

    this.logger.info('Stream completed', {
      streamId,
      reason,
      duration: metrics.endTime - metrics.startTime,
      totalTokens: metrics.totalTokens,
      tokensPerSecond: metrics.tokensPerSecond,
      errorRate: metrics.errorRate
    });
  }

  /**
   * Gets current aggregated metrics
   */
  getAggregatedMetrics(): MetricsAggregation {
    this.aggregatedMetrics.uptime = Date.now() - this.startTime;
    return { ...this.aggregatedMetrics };
  }

  /**
   * Gets metrics for specific stream
   */
  getStreamMetrics(streamId: string): StreamMetrics | undefined {
    return this.metrics.get(streamId);
  }

  /**
   * Gets recent performance alerts
   */
  getRecentAlerts(since?: number): PerformanceAlert[] {
    const cutoff = since || Date.now() - 3600000; // Last hour by default
    return this.alerts.filter(alert => alert.timestamp > cutoff);
  }

  /**
   * Creates analytics report for a stream
   */
  createStreamAnalytics(streamId: string, state: StreamState): StreamAnalytics | null {
    const metrics = this.metrics.get(streamId);
    if (!metrics) return null;

    const connectionQuality = this.assessConnectionQuality(metrics, state);

    return {
      streamId,
      userId: 'user-id', // Will be passed from stream config
      businessId: 'business-id', // Will be passed from stream config
      model: 'ai-model', // Will be passed from stream config

      // Performance data
      timeToFirstToken: metrics.timeToFirstToken || 0,
      averageTokenLatency: metrics.averageTokenLatency,
      tokensPerSecond: metrics.tokensPerSecond,
      totalDuration: (metrics.endTime || Date.now()) - metrics.startTime,

      // Quality data
      successRate: 1 - metrics.errorRate,
      errorCount: metrics.retryCount,
      retryCount: metrics.retryCount,

      // Usage data
      totalTokens: metrics.totalTokens,
      totalBytes: metrics.totalBytes,

      // Connection data
      connectionQuality,
      clientInfo: state.clientInfo,

      // Timestamps
      startTime: metrics.startTime,
      endTime: metrics.endTime || Date.now()
    };
  }

  /**
   * Exports metrics to external monitoring system
   */
  exportMetrics(format: 'prometheus' | 'json' | 'csv' = 'json'): string {
    const data = {
      timestamp: Date.now(),
      aggregated: this.aggregatedMetrics,
      streams: Array.from(this.metrics.entries()).map(([id, metrics]) => ({
        streamId: id,
        ...metrics
      })),
      alerts: this.getRecentAlerts()
    };

    switch (format) {
      case 'prometheus':
        return this.formatPrometheusMetrics(data);
      case 'csv':
        return this.formatCSVMetrics(data);
      case 'json':
      default:
        return JSON.stringify(data, null, 2);
    }
  }

  /**
   * Updates aggregated metrics
   */
  private updateAggregatedMetrics(): void {
    const allMetrics = Array.from(this.metrics.values());

    if (allMetrics.length === 0) return;

    this.aggregatedMetrics.totalStreams = allMetrics.length;
    this.aggregatedMetrics.activeStreams = allMetrics.filter(m => !m.endTime).length;

    const completedMetrics = allMetrics.filter(m => m.endTime);

    if (completedMetrics.length > 0) {
      this.aggregatedMetrics.averageLatency =
        completedMetrics.reduce((sum, m) => sum + m.averageTokenLatency, 0) / completedMetrics.length;

      this.aggregatedMetrics.averageThroughput =
        completedMetrics.reduce((sum, m) => sum + m.tokensPerSecond, 0) / completedMetrics.length;

      this.aggregatedMetrics.errorRate =
        completedMetrics.reduce((sum, m) => sum + m.errorRate, 0) / completedMetrics.length;
    }
  }

  /**
   * Checks for performance alerts
   */
  private checkPerformanceAlerts(streamId: string, metrics: StreamMetrics): void {
    const alerts: PerformanceAlert[] = [];

    // First token latency alert
    if (metrics.timeToFirstToken && metrics.timeToFirstToken > this.thresholds.firstTokenLatency) {
      alerts.push({
        id: `latency-first-token-${streamId}`,
        streamId,
        type: 'latency',
        severity: metrics.timeToFirstToken > this.thresholds.firstTokenLatency * 2 ? 'high' : 'medium',
        message: `First token latency exceeded threshold`,
        threshold: this.thresholds.firstTokenLatency,
        actualValue: metrics.timeToFirstToken,
        timestamp: Date.now()
      });
    }

    // Average token latency alert
    if (metrics.averageTokenLatency > this.thresholds.averageTokenLatency) {
      alerts.push({
        id: `latency-average-${streamId}`,
        streamId,
        type: 'latency',
        severity: metrics.averageTokenLatency > this.thresholds.averageTokenLatency * 2 ? 'high' : 'medium',
        message: `Average token latency exceeded threshold`,
        threshold: this.thresholds.averageTokenLatency,
        actualValue: metrics.averageTokenLatency,
        timestamp: Date.now()
      });
    }

    // Throughput alert
    if (metrics.tokensPerSecond < this.thresholds.throughputMinimum) {
      alerts.push({
        id: `throughput-${streamId}`,
        streamId,
        type: 'throughput',
        severity: metrics.tokensPerSecond < this.thresholds.throughputMinimum * 0.5 ? 'high' : 'medium',
        message: `Token throughput below minimum threshold`,
        threshold: this.thresholds.throughputMinimum,
        actualValue: metrics.tokensPerSecond,
        timestamp: Date.now()
      });
    }

    // Error rate alert
    if (metrics.errorRate > this.thresholds.errorRateMaximum) {
      alerts.push({
        id: `error-rate-${streamId}`,
        streamId,
        type: 'error_rate',
        severity: metrics.errorRate > this.thresholds.errorRateMaximum * 2 ? 'critical' : 'high',
        message: `Error rate exceeded acceptable threshold`,
        threshold: this.thresholds.errorRateMaximum,
        actualValue: metrics.errorRate,
        timestamp: Date.now()
      });
    }

    // Buffer usage alert
    if (metrics.peakBufferUsage > this.thresholds.bufferUsageMaximum * 100) {
      alerts.push({
        id: `buffer-usage-${streamId}`,
        streamId,
        type: 'memory',
        severity: metrics.peakBufferUsage > this.thresholds.bufferUsageMaximum * 150 ? 'high' : 'medium',
        message: `Buffer usage exceeded threshold`,
        threshold: this.thresholds.bufferUsageMaximum * 100,
        actualValue: metrics.peakBufferUsage,
        timestamp: Date.now()
      });
    }

    // Add alerts and log them
    for (const alert of alerts) {
      this.alerts.push(alert);
      this.logger.warn('Performance alert triggered', {
        alert: alert.type,
        severity: alert.severity,
        streamId,
        threshold: alert.threshold,
        actualValue: alert.actualValue,
        message: alert.message
      });
    }

    // Cleanup old alerts (keep last 1000)
    if (this.alerts.length > 1000) {
      this.alerts = this.alerts.slice(-1000);
    }
  }

  /**
   * Assesses connection quality based on metrics
   */
  private assessConnectionQuality(metrics: StreamMetrics, state: StreamState): ConnectionQuality {
    const latency = metrics.averageTokenLatency;
    const jitter = Math.abs(metrics.averageTokenLatency - (metrics.timeToFirstToken || 0));
    const packetLoss = metrics.droppedEventCount / Math.max(1, metrics.totalTokens + metrics.totalChunks);
    const bandwidth = metrics.totalBytes /
  Math.max(1, (metrics.endTime || Date.now()) - metrics.startTime) * 1000; // bytes/sec

    let stability: ConnectionQuality['stability'];
    if (latency < 50 && jitter < 20 && packetLoss < 0.01) {
      stability = 'excellent';
    } else if (latency < 100 && jitter < 50 && packetLoss < 0.05) {
      stability = 'good';
    } else if (latency < 200 && jitter < 100 && packetLoss < 0.1) {
      stability = 'fair';
    } else {
      stability = 'poor';
    }

    // Recommend configuration based on quality
    const recommendedConfig: Partial<SSEStreamConfig> = {};
    if (stability === 'poor') {
      recommendedConfig.bufferSize = Math.max(2048, metrics.peakBufferUsage * 2);
      recommendedConfig.retryBackoffMs = 2000;
      recommendedConfig.heartbeatInterval = 30000; // Longer intervals for poor connections
    } else if (stability === 'fair') {
      recommendedConfig.bufferSize = Math.max(1536, metrics.peakBufferUsage * 1.5);
      recommendedConfig.retryBackoffMs = 1500;
    }

    return {
      latency,
      jitter,
      packetLoss,
      bandwidth,
      stability,
      recommendedConfig
    };
  }

  /**
   * Starts periodic metrics collection and cleanup
   */
  private startPeriodicMetricsCollection(): void {
    // Update aggregated metrics every 30 seconds
    setInterval(() => {
      this.updateAggregatedMetrics();
      this.cleanupOldMetrics();
    }, 30000);

    // Log metrics summary every 5 minutes
    setInterval(() => {
      this.logger.info('Metrics summary', {
        aggregated: this.getAggregatedMetrics(),
        activeAlerts: this.getRecentAlerts(Date.now() - 300000).length // Last 5 minutes
      });
    }, 300000);
  }

  /**
   * Cleans up old metrics to prevent memory leaks
   */
  private cleanupOldMetrics(): void {
    const cutoff = Date.now() - 3600000; // Keep metrics for 1 hour

    for (const [streamId, metrics] of this.metrics.entries()) {
      if (metrics.endTime && metrics.endTime < cutoff) {
        this.metrics.delete(streamId);
      }
    }

    // Clean up old alerts
    this.alerts = this.alerts.filter(alert => alert.timestamp > cutoff);
  }

  /**
   * Formats metrics for Prometheus monitoring
   */
  private formatPrometheusMetrics(data: any): string {
    const lines: string[] = [];

    lines.push(`# HELP sse_streams_total Total number of SSE streams`);
    lines.push(`# TYPE sse_streams_total counter`);
    lines.push(`sse_streams_total ${data.aggregated.totalStreams}`);

    lines.push(`# HELP sse_streams_active Currently active SSE streams`);
    lines.push(`# TYPE sse_streams_active gauge`);
    lines.push(`sse_streams_active ${data.aggregated.activeStreams}`);

    lines.push(`# HELP sse_average_latency_ms Average token latency in milliseconds`);
    lines.push(`# TYPE sse_average_latency_ms gauge`);
    lines.push(`sse_average_latency_ms ${data.aggregated.averageLatency}`);

    lines.push(`# HELP sse_throughput_tokens_per_second Average throughput in tokens per second`);
    lines.push(`# TYPE sse_throughput_tokens_per_second gauge`);
    lines.push(`sse_throughput_tokens_per_second ${data.aggregated.averageThroughput}`);

    lines.push(`# HELP sse_error_rate Error rate as percentage`);
    lines.push(`# TYPE sse_error_rate gauge`);
    lines.push(`sse_error_rate ${data.aggregated.errorRate}`);

    return lines.join('\n');
  }

  /**
   * Formats metrics for CSV export
   */
  private formatCSVMetrics(data: any): string {
    const headers = [
      'timestamp', 'streamId', 'startTime', 'endTime', 'totalTokens',
      'totalChunks', 'totalBytes', 'averageTokenLatency', 'tokensPerSecond',
      'errorRate', 'retryCount', 'droppedEventCount'
    ];

    const rows = [headers.join(',')];

    for (const stream of data.streams) {
      const row = [
        data.timestamp,
        stream.streamId,
        stream.startTime,
        stream.endTime || '',
        stream.totalTokens,
        stream.totalChunks,
        stream.totalBytes,
        stream.averageTokenLatency,
        stream.tokensPerSecond,
        stream.errorRate,
        stream.retryCount,
        stream.droppedEventCount
      ];
      rows.push(row.join(','));
    }

    return rows.join('\n');
  }
}