/**
 * SSE Stream Manager for handling multiple concurrent AI response streams
 * Manages lifecycle, backpressure, heartbeats, and error recovery
 */

import type { KVNamespace } from '@cloudflare/workers-types';
import {
  type SSEStreamConfig,
  type StreamState,
  type StreamManagerState,
  type AnySSEEvent,
  type ErrorData,
  type HeartbeatData,
  type StreamMetrics,
  type ConnectionQuality,
  DEFAULT_SSE_CONFIG,
  StreamConfigSchema,
} from './types';
import { SecurityLimits, SecurityError, CorrelationId } from '../../shared/security-utils';
import { performanceLogger, abacLogger } from '../../shared/logger';

/**
 * Stream manager for handling multiple concurrent SSE streams
 */
export // TODO: Consider splitting SSEStreamManager into smaller, focused classes
class SSEStreamManager {
  private kv: KVNamespace;
  private state: StreamManagerState;
  private cleanupTimer?: NodeJS.Timeout;
  private heartbeatTimer?: NodeJS.Timeout;
  private readonly CLEANUP_INTERVAL = 60000; // 1 minute
  private readonly MAX_INACTIVE_TIME = 300000; // 5 minutes

  // Circuit breaker for error handling
  private circuitBreaker = {
    isOpen: false,
    errorCount: 0,
    lastFailureTime: 0,
    errorThreshold: 10,
    resetTimeout: 30000,
  };

  constructor(kv: KVNamespace) {
    this.kv = kv;
    this.state = {
      activeStreams: new Map(),
      userStreams: new Map(),
      totalStreamsCreated: 0,
      totalStreamsCompleted: 0,
      totalErrors: 0,
      lastCleanup: Date.now(),
    };

    this.startCleanupTimer();
    this.startHeartbeatTimer();
  }

  /**
   * Create a new SSE stream with validation and limits
   */
  async createStream(config: SSEStreamConfig): Promise<{
    streamId: string;
    response: Response;
    controller: SSEStreamController;
  }> {
    const startTime = performance.now();

    try {
      // Validate configuration
      const validatedConfig = StreamConfigSchema.parse(config);

      // Check circuit breaker
      if (this.isCircuitBreakerOpen()) {
        throw new SecurityError('Stream service unavailable', {
          code: 'CIRCUIT_BREAKER_OPEN',
          correlationId: config.correlationId,
        });
      }

      // Check user stream limits
      await this.enforceUserLimits(config.userId, config.maxConcurrentStreams);

      // Create stream state
      const streamState: StreamState = {
        streamId: config.streamId,
        status: 'starting',
        startTime: Date.now(),
        lastActivityTime: Date.now(),
        tokenCount: 0,
        chunkCount: 0,
        errorCount: 0,
        retryCount: 0,
        bytesTransferred: 0,
        averageTokenTime: 0,
        tokensPerSecond: 0,
        clientInfo: {
          userAgent: 'unknown',
          ipAddress: 'unknown',
          connectionId: CorrelationId.generate(),
        },
        bufferUsage: 0,
        droppedEvents: 0,
        lastHeartbeat: Date.now(),
        missedHeartbeats: 0,
      };

      // Import the SSEStreamController from the separate file
      const { SSEStreamController } = await import('./stream-controller');

      // Create the stream controller
      const controller = new SSEStreamController(validatedConfig, streamState, this);

      // Register stream
      this.registerStream(config.userId, streamState);

      // Create SSE response
      const response = new Response(controller.createStream(), {
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': 'Cache-Control',
          'X-Stream-ID': config.streamId,
          'X-Correlation-ID': config.correlationId,
        },
      });

      const duration = performance.now() - startTime;
      performanceLogger.performance(
        'sse_stream_create',
        duration,
        {
          streamId: config.streamId,
          userId: config.userId,
          businessId: config.businessId,
        }
      );

      this.state.totalStreamsCreated++;
      this.recordCircuitBreakerSuccess();

      return {
        streamId: config.streamId,
        response,
        controller,
      };

    } catch (error) {
      const duration = performance.now() - startTime;
      this.handleError(error, 'createStream', duration);
      throw error;
    }
  }

  /**
   * Get stream state by ID
   */
  getStreamState(streamId: string): StreamState | undefined {
    return this.state.activeStreams.get(streamId);
  }

  /**
   * Get all streams for a user
   */
  getUserStreams(userId: string): StreamState[] {
    const streamIds = this.state.userStreams.get(userId) || new Set();
    return Array.from(streamIds)
      .map(id => this.state.activeStreams.get(id))
      .filter(Boolean) as StreamState[];
  }

  /**
   * Terminate a specific stream
   */
  async terminateStream(streamId: string, reason: string): Promise<boolean> {
    const streamState = this.state.activeStreams.get(streamId);
    if (!streamState) return false;

    try {
      streamState.status = 'ended';
      streamState.lastActivityTime = Date.now();

      // Remove from tracking
      this.unregisterStream(streamState);

      // Persist final metrics
      await this.persistStreamMetrics(streamState);

      abacLogger.info('Stream terminated', {
        streamId,
        reason,
        duration: Date.now() - streamState.startTime,
        tokenCount: streamState.tokenCount,
      });

      return true;

    } catch (error) {
      abacLogger.error('Failed to terminate stream', error, { streamId, reason });
      return false;
    }
  }

  /**
   * Terminate all streams for a user
   */
  async terminateUserStreams(userId: string, reason: string): Promise<number> {
    const userStreams = this.getUserStreams(userId);
    let terminated = 0;

    for (const stream of userStreams) {
      const success = await this.terminateStream(stream.streamId, reason);
      if (success) terminated++;
    }

    return terminated;
  }

  /**
   * Get system health and metrics
   */
  getSystemHealth(): {
    status: 'healthy' | 'degraded' | 'unhealthy';
    activeStreams: number;
    totalStreamsCreated: number;
    totalStreamsCompleted: number;
    errorRate: number;
    averageStreamDuration: number;
    circuitBreakerStatus: {
      isOpen: boolean;
      errorCount: number;
      lastFailureTime: number;
    };
    memoryUsage: {
      activeStreams: number;
      estimatedMemoryMB: number;
    };
  } {
    const totalStreams = this.state.totalStreamsCreated;
    const errorRate = totalStreams > 0 ? (this.state.totalErrors / totalStreams) * 100 : 0;

    // Calculate average stream duration
    const activeStreams = Array.from(this.state.activeStreams.values());
    const avgDuration = activeStreams.length > 0
      ? activeStreams.reduce((sum, stream) => sum + (Date.now() - stream.startTime), 0) / activeStreams.length
      : 0;

    // Estimate memory usage (rough calculation)
    const estimatedMemoryMB = (activeStreams.length * 0.5) + (this.state.activeStreams.size * 0.1);

    let status: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

    if (
      this.circuitBreaker.isOpen ||
      errorRate > 10 ||
      activeStreams.length > 100 ||
      estimatedMemoryMB > 100
    ) {
      status = 'unhealthy';
    } else if (
      errorRate > 5 ||
      activeStreams.length > 50 ||
      avgDuration > 300000 // 5 minutes
    ) {
      status = 'degraded';
    }

    return {
      status,
      activeStreams: this.state.activeStreams.size,
      totalStreamsCreated: this.state.totalStreamsCreated,
      totalStreamsCompleted: this.state.totalStreamsCompleted,
      errorRate,
      averageStreamDuration: avgDuration,
      circuitBreakerStatus: {
        isOpen: this.circuitBreaker.isOpen,
        errorCount: this.circuitBreaker.errorCount,
        lastFailureTime: this.circuitBreaker.lastFailureTime,
      },
      memoryUsage: {
        activeStreams: activeStreams.length,
        estimatedMemoryMB,
      },
    };
  }

  /**
   * Analyze connection quality and suggest optimal configuration
   */
  analyzeConnectionQuality(streamState: StreamState): ConnectionQuality {
    const avgLatency = streamState.averageTokenTime;
    const jitter = this.calculateJitter(streamState);
    const packetLoss = streamState.droppedEvents / Math.max(streamState.tokenCount, 1);

    let stability: ConnectionQuality['stability'] = 'excellent';
    let bandwidth = 1000; // Estimate based on throughput

    if (avgLatency > 1000 || jitter > 500 || packetLoss > 0.1) {
      stability = 'poor';
      bandwidth = 100;
    } else if (avgLatency > 500 || jitter > 200 || packetLoss > 0.05) {
      stability = 'fair';
      bandwidth = 300;
    } else if (avgLatency > 200 || jitter > 100 || packetLoss > 0.01) {
      stability = 'good';
      bandwidth = 500;
    }

    // Generate recommended configuration based on connection quality
    const recommendedConfig: Partial<SSEStreamConfig> = {
      heartbeatInterval: stability === 'poor' ? 10000 : 15000,
      bufferSize: stability === 'poor' ? 2048 : 1024,
      maxRetries: stability === 'poor' ? 5 : 3,
      retryBackoffMs: stability === 'poor' ? 2000 : 1000,
      enableCompression: stability === 'poor',
    };

    return {
      latency: avgLatency,
      jitter,
      packetLoss,
      bandwidth,
      stability,
      recommendedConfig,
    };
  }

  /**
   * Export stream analytics for monitoring
   */
  async exportStreamAnalytics(timeWindowMs = 3600000): Promise<{
    summary: {
      totalStreams: number;
      completedStreams: number;
      errorRate: number;
      averageTokensPerSecond: number;
      averageTimeToFirstToken: number;
    };
    detailedMetrics: StreamMetrics[];
  }> {
    try {
      const cutoff = Date.now() - timeWindowMs;
      const recentMetrics = await this.getRecentMetrics(cutoff);

      const summary = {
        totalStreams: recentMetrics.length,
        completedStreams: recentMetrics.filter(m => m.endTime).length,
        errorRate: recentMetrics.length > 0
          ? (recentMetrics.reduce((sum, m) => sum + m.errorRate, 0) / recentMetrics.length) * 100
          : 0,
        averageTokensPerSecond: recentMetrics.length > 0
          ? recentMetrics.reduce((sum, m) => sum + m.tokensPerSecond, 0) / recentMetrics.length
          : 0,
        averageTimeToFirstToken: recentMetrics.length > 0
          ? recentMetrics.reduce((sum, m) => sum + (m.timeToFirstToken || 0), 0) / recentMetrics.length
          : 0,
      };

      return {
        summary,
        detailedMetrics: recentMetrics,
      };

    } catch (error) {
      abacLogger.error('Failed to export stream analytics', error);
      throw new SecurityError('Analytics export failed', {
        code: 'ANALYTICS_EXPORT_FAILED',
        timeWindowMs,
      });
    }
  }

  /**
   * Private methods for internal management
   */

  private async enforceUserLimits(userId: string, maxConcurrentStreams: number): Promise<void> {
    const userStreamIds = this.state.userStreams.get(userId) || new Set();

    if (userStreamIds.size >= maxConcurrentStreams) {
      throw new SecurityError('Concurrent stream limit exceeded', {
        code: 'STREAM_LIMIT_EXCEEDED',
        userId,
        currentStreams: userStreamIds.size,
        maxStreams: maxConcurrentStreams,
      });
    }

    // Additional security limits
    SecurityLimits.validateRequestLimits({
      batchSize: userStreamIds.size + 1,
    });
  }

  private registerStream(userId: string, streamState: StreamState): void {
    this.state.activeStreams.set(streamState.streamId, streamState);

    if (!this.state.userStreams.has(userId)) {
      this.state.userStreams.set(userId, new Set());
    }
    this.state.userStreams.get(userId)!.add(streamState.streamId);
  }

  private unregisterStream(streamState: StreamState): void {
    this.state.activeStreams.delete(streamState.streamId);

    // Find and remove from user streams
    for (const [userId, streamIds] of this.state.userStreams.entries()) {
      if (streamIds.has(streamState.streamId)) {
        streamIds.delete(streamState.streamId);
        if (streamIds.size === 0) {
          this.state.userStreams.delete(userId);
        }
        break;
      }
    }

    this.state.totalStreamsCompleted++;
  }

  private startCleanupTimer(): void {
    this.cleanupTimer = setInterval(() => {
      this.cleanupInactiveStreams().catch(error => {
        abacLogger.error('Cleanup timer error', error);
      });
    }, this.CLEANUP_INTERVAL);
  }

  private startHeartbeatTimer(): void {
    this.heartbeatTimer = setInterval(() => {
      this.sendHeartbeats().catch(error => {
        abacLogger.error('Heartbeat timer error', error);
      });
    }, 15000); // Send heartbeats every 15 seconds
  }

  private async cleanupInactiveStreams(): Promise<void> {
    const now = Date.now();
    const cutoff = now - this.MAX_INACTIVE_TIME;
    const streamsToCleanup: StreamState[] = [];

    for (const stream of this.state.activeStreams.values()) {
      if (stream.lastActivityTime < cutoff || stream.status === 'error') {
        streamsToCleanup.push(stream);
      }
    }

    for (const stream of streamsToCleanup) {
      await this.terminateStream(stream.streamId, 'inactive_cleanup');
    }

    this.state.lastCleanup = now;

    if (streamsToCleanup.length > 0) {
      abacLogger.info('Cleaned up inactive streams', {
        cleanedUp: streamsToCleanup.length,
        remaining: this.state.activeStreams.size,
      });
    }
  }

  private async sendHeartbeats(): Promise<void> {
    const heartbeatData: HeartbeatData = {
      timestamp: Date.now(),
      uptime: Date.now() - (this.state.lastCleanup - this.CLEANUP_INTERVAL),
      activeStreams: this.state.activeStreams.size,
      serverHealth: this.getSystemHealth().status,
    };

    // In a real implementation, you would send heartbeats to active streams
    // For now, just update the heartbeat timestamp in stream states
    for (const stream of this.state.activeStreams.values()) {
      stream.lastHeartbeat = heartbeatData.timestamp;
    }
  }

  private isCircuitBreakerOpen(): boolean {
    const now = Date.now();

    // Reset circuit breaker if timeout has passed
    if (
      this.circuitBreaker.isOpen &&
      now - this.circuitBreaker.lastFailureTime > this.circuitBreaker.resetTimeout
    ) {
      this.circuitBreaker.isOpen = false;
      this.circuitBreaker.errorCount = 0;
      abacLogger.info('Stream circuit breaker reset');
    }

    return this.circuitBreaker.isOpen;
  }

  private recordCircuitBreakerSuccess(): void {
    if (this.circuitBreaker.errorCount > 0) {
      this.circuitBreaker.errorCount = Math.max(0, this.circuitBreaker.errorCount - 1);
    }
  }

  private handleError(error: unknown, operation: string, duration: number): void {
    this.state.totalErrors++;
    this.circuitBreaker.errorCount++;
    this.circuitBreaker.lastFailureTime = Date.now();

    // Open circuit breaker if error threshold exceeded
    if (this.circuitBreaker.errorCount >= this.circuitBreaker.errorThreshold) {
      this.circuitBreaker.isOpen = true;
      abacLogger.error('Stream circuit breaker opened', error, {
        operation,
        errorCount: this.circuitBreaker.errorCount,
        duration,
      });
    } else {
      abacLogger.warn('Stream operation failed', error, {
        operation,
        errorCount: this.circuitBreaker.errorCount,
        duration,
      });
    }
  }

  private calculateJitter(streamState: StreamState): number {
    // Simplified jitter calculation based on token timing variance
    return streamState.averageTokenTime * 0.1; // 10% of average time as estimate
  }

  private async persistStreamMetrics(streamState: StreamState): Promise<void> {
    try {
      const metrics: StreamMetrics = {
        streamId: streamState.streamId,
        startTime: streamState.startTime,
        endTime: Date.now(),
        firstTokenTime: streamState.firstTokenTime,
        totalTokens: streamState.tokenCount,
        totalChunks: streamState.chunkCount,
        totalBytes: streamState.bytesTransferred,
        averageTokenLatency: streamState.averageTokenTime,
        tokensPerSecond: streamState.tokensPerSecond,
        timeToFirstToken: streamState.firstTokenTime ? streamState.firstTokenTime - streamState.startTime : undefined,
        errorRate: streamState.errorCount / Math.max(streamState.tokenCount, 1),
        retryCount: streamState.retryCount,
        droppedEventCount: streamState.droppedEvents,
        bufferOverflowCount: 0, // Would track this separately
        heartbeatCount: Math.floor((Date.now() - streamState.startTime) / 15000),
        missedHeartbeats: streamState.missedHeartbeats,
        reconnectCount: streamState.retryCount,
        peakBufferUsage: streamState.bufferUsage,
        averageBufferUsage: streamState.bufferUsage * 0.7, // Estimate
        memoryUsage: 1024 * 1024, // 1MB estimate per stream
      };

      const key = `stream_metrics:${streamState.streamId}`;
      await this.kv.put(key, JSON.stringify(metrics), {
        expirationTtl: 86400, // 24 hours
      });

    } catch (error) {
      abacLogger.warn('Failed to persist stream metrics', error, {
        streamId: streamState.streamId,
      });
    }
  }

  private async getRecentMetrics(cutoffTime: number): Promise<StreamMetrics[]> {
    // In a real implementation, you would query KV for recent metrics
    // For now, return empty array
    return [];
  }

  /**
   * Cleanup and shutdown
   */
  async destroy(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
    }

    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
    }

    // Terminate all active streams
    const activeStreamIds = Array.from(this.state.activeStreams.keys());
    await Promise.allSettled(
      activeStreamIds.map(id => this.terminateStream(id, 'server_shutdown'))
    );

    abacLogger.info('SSE Stream Manager destroyed', {
      terminatedStreams: activeStreamIds.length,
    });
  }
}

// Note: SSEStreamController is now in ./stream-controller.ts