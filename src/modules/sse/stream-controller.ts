/**
 * SSE Stream Controller for individual stream management
 * Handles AI response streaming with backpressure and error recovery
 */

import {
  SSEStreamConfig,
  SSEEvent,
  TokenEvent,
  ChunkEvent,
  StreamStartEvent,
  StreamEndEvent,
  ErrorEvent,
  HeartbeatEvent,
  StreamState,
  BackpressureConfig,
  StreamMetrics
} from './types';
import { Logger } from '../../shared/logger';
import { SecurityError } from '../../shared/security-utils';

export class SSEStreamController {
  private readonly config: SSEStreamConfig;
  private readonly state: StreamState;
  private readonly logger: Logger;
  private encoder = new TextEncoder();
  private heartbeatTimer?: number;
  private cleanupTimer?: number;
  private buffer: SSEEvent[] = [];
  private isWriting = false;
  private metrics: StreamMetrics;
  private abortController: AbortController;

  constructor(
    config: SSEStreamConfig,
    state: StreamState,
    private manager: any
  ) {
    this.config = config;
    this.state = state;
    this.logger = new Logger();
    this.abortController = new AbortController();

    this.metrics = {
      streamId: config.streamId,
      startTime: Date.now(),
      totalTokens: 0,
      totalChunks: 0,
      totalBytes: 0,
      averageTokenLatency: 0,
      tokensPerSecond: 0,
      errorRate: 0,
      retryCount: 0,
      droppedEventCount: 0,
      bufferOverflowCount: 0,
      heartbeatCount: 0,
      missedHeartbeats: 0,
      reconnectCount: 0,
      peakBufferUsage: 0,
      averageBufferUsage: 0,
      memoryUsage: 0
    };
  }

  /**
   * Creates readable stream for SSE events with backpressure handling
   */
  createStream(): ReadableStream<Uint8Array> {
    return new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.startHeartbeat();
        this.startCleanupTimer();
        this.sendStreamStart(controller);
      },

      pull: (controller) => {
        return this.processBuffer(controller);
      },

      cancel: () => {
        this.cleanup();
      }
    }, {
      highWaterMark: this.config.bufferSize,
      size: (chunk) => chunk.length
    });
  }

  /**
   * Sends SSE event with backpressure handling
   */
  async sendEvent(event: SSEEvent): Promise<void> {
    if (this.state.status === 'ended' || this.state.status === 'error') {
      return;
    }

    this.updateMetrics(event);

    // Apply backpressure if buffer is full
    if (this.buffer.length >= this.config.bufferSize) {
      await this.handleBackpressure(event);
      return;
    }

    this.buffer.push(event);
    this.state.lastActivityTime = Date.now();
  }

  /**
   * Sends token streaming event
   */
  async sendToken(token: string, position: number, isComplete = false): Promise<void> {
    const tokenEvent: TokenEvent = {
      id: this.generateEventId(),
      event: 'token',
      data: {
        token,
        position,
        isComplete,
        finishReason: isComplete ? 'stop' : undefined
      },
      timestamp: Date.now()
    };

    await this.sendEvent(tokenEvent);

    // Track first token timing for performance metrics
    if (!this.state.firstTokenTime) {
      this.state.firstTokenTime = Date.now();
      this.metrics.timeToFirstToken = this.state.firstTokenTime - this.metrics.startTime;

      // Log if first token exceeds target
      if (this.metrics.timeToFirstToken > this.config.firstTokenTimeout) {
        this.logger.warn('First token exceeded target time', {
          streamId: this.config.streamId,
          actualTime: this.metrics.timeToFirstToken,
          targetTime: this.config.firstTokenTimeout,
          correlationId: this.config.correlationId
        });
      }
    }
  }

  /**
   * Sends chunk streaming event
   */
  async sendChunk(chunk: string, position: number, totalChunks?: number): Promise<void> {
    const chunkEvent: ChunkEvent = {
      id: this.generateEventId(),
      event: 'chunk',
      data: {
        chunk,
        position,
        totalChunks,
        encoding: 'utf8'
      },
      timestamp: Date.now()
    };

    await this.sendEvent(chunkEvent);
  }

  /**
   * Sends error event with automatic retry logic
   */
  async sendError(error: Error, retryable = true): Promise<void> {
    this.state.errorCount++;
    this.metrics.retryCount++;

    const errorEvent: ErrorEvent = {
      id: this.generateEventId(),
      event: 'error',
      data: {
        code: 'STREAM_ERROR',
        message: error.message,
        retryable,
        retryAfter: retryable ? this.config.retryBackoffMs : undefined,
        correlationId: this.config.correlationId,
        context: {
          streamId: this.config.streamId,
          userId: this.config.userId,
          businessId: this.config.businessId
        }
      },
      timestamp: Date.now(),
      retry: retryable ? this.config.retryBackoffMs : undefined
    };

    await this.sendEvent(errorEvent);

    // Auto-retry if configured and under retry limit
    if (retryable && this.state.retryCount < this.config.maxRetries) {
      setTimeout(() => {
        this.handleErrorRecovery(error);
      }, this.config.retryBackoffMs * Math.pow(2, this.state.retryCount));
    } else if (this.state.retryCount >= this.config.maxRetries) {
      this.endStream('error', `Max retries exceeded: ${error.message}`);
    }
  }

  /**
   * Ends the stream with completion status
   */
  async endStream(reason: 'complete' | 'stopped' | 'error' | 'timeout' | 'cancelled' = 'complete', details?: string): Promise<void> {
    if (this.state.status === 'ended') return;

    this.state.status = 'ended';
    const endTime = Date.now();
    const totalTime = endTime - this.metrics.startTime;

    this.metrics.endTime = endTime;
    this.metrics.tokensPerSecond = this.metrics.totalTokens / (totalTime / 1000);

    const endEvent: StreamEndEvent = {
      id: this.generateEventId(),
      event: 'stream_end',
      data: {
        streamId: this.config.streamId,
        reason,
        totalTokens: this.metrics.totalTokens,
        totalTime,
        tokensPerSecond: this.metrics.tokensPerSecond,
        firstTokenTime: this.metrics.timeToFirstToken
      },
      timestamp: Date.now()
    };

    await this.sendEvent(endEvent);

    this.logger.info('Stream ended', {
      streamId: this.config.streamId,
      reason,
      details,
      metrics: this.metrics,
      correlationId: this.config.correlationId
    });

    this.cleanup();
  }

  /**
   * Handles backpressure by applying configured strategy
   */
  private async handleBackpressure(event: SSEEvent): Promise<void> {
    this.metrics.bufferOverflowCount++;

    switch (this.config.enableBackpressure ? 'drop_oldest' : 'drop_newest') {
      case 'drop_oldest':
        // Remove oldest events to make room
        const dropped = this.buffer.splice(0, Math.floor(this.config.bufferSize * 0.2));
        this.metrics.droppedEventCount += dropped.length;
        this.buffer.push(event);
        break;

      case 'drop_newest':
        // Drop the new event
        this.metrics.droppedEventCount++;
        break;

      case 'pause_stream':
        // Pause until buffer clears (simple implementation)
        this.state.status = 'paused';
        await new Promise(resolve => setTimeout(resolve, 100));
        this.state.status = 'active';
        this.buffer.push(event);
        break;

      default:
        this.buffer.push(event);
    }

    this.logger.warn('Backpressure applied', {
      streamId: this.config.streamId,
      bufferSize: this.buffer.length,
      droppedEvents: this.metrics.droppedEventCount,
      correlationId: this.config.correlationId
    });
  }

  /**
   * Processes buffered events and writes to stream
   */
  private async processBuffer(controller: ReadableStreamDefaultController<Uint8Array>): Promise<void> {
    if (this.isWriting || this.buffer.length === 0) {
      return;
    }

    this.isWriting = true;

    try {
      while (this.buffer.length > 0 && !controller.desiredSize || controller.desiredSize > 0) {
        const event = this.buffer.shift()!;
        const sseData = this.formatSSEEvent(event);
        const chunk = this.encoder.encode(sseData);

        controller.enqueue(chunk);
        this.metrics.totalBytes += chunk.length;
        this.state.bytesTransferred += chunk.length;
      }
    } finally {
      this.isWriting = false;
    }
  }

  /**
   * Formats event as SSE protocol data
   */
  private formatSSEEvent(event: SSEEvent): string {
    const lines = [
      `id: ${event.id}`,
      `event: ${event.event}`,
      `data: ${JSON.stringify(event.data)}`,
    ];

    if (event.retry) {
      lines.push(`retry: ${event.retry}`);
    }

    return lines.join('\n') + '\n\n';
  }

  /**
   * Starts heartbeat mechanism
   */
  private startHeartbeat(): void {
    if (!this.config.enableHeartbeat) return;

    this.heartbeatTimer = setInterval(() => {
      this.sendHeartbeat();
    }, this.config.heartbeatInterval) as any;
  }

  /**
   * Sends heartbeat event
   */
  private async sendHeartbeat(): Promise<void> {
    const heartbeatEvent: HeartbeatEvent = {
      id: this.generateEventId(),
      event: 'heartbeat',
      data: {
        timestamp: Date.now(),
        uptime: Date.now() - this.metrics.startTime,
        activeStreams: 1,
        serverHealth: 'healthy'
      },
      timestamp: Date.now()
    };

    await this.sendEvent(heartbeatEvent);
    this.metrics.heartbeatCount++;
    this.state.lastHeartbeat = Date.now();
  }

  /**
   * Starts cleanup timer for stream timeout
   */
  private startCleanupTimer(): void {
    this.cleanupTimer = setTimeout(() => {
      this.endStream('timeout', 'Stream exceeded maximum duration');
    }, this.config.maxStreamDuration) as any;
  }

  /**
   * Sends stream start event
   */
  private sendStreamStart(controller: ReadableStreamDefaultController<Uint8Array>): void {
    const startEvent: StreamStartEvent = {
      id: this.generateEventId(),
      event: 'stream_start',
      data: {
        streamId: this.config.streamId,
        model: 'ai-model', // Will be provided by AI service integration
        conversationId: this.config.correlationId,
        maxTokens: 4096 // Default, will be configurable
      },
      timestamp: Date.now()
    };

    const sseData = this.formatSSEEvent(startEvent);
    const chunk = this.encoder.encode(sseData);
    controller.enqueue(chunk);

    this.state.status = 'active';
    this.logger.info('Stream started', {
      streamId: this.config.streamId,
      userId: this.config.userId,
      businessId: this.config.businessId,
      correlationId: this.config.correlationId
    });
  }

  /**
   * Handles error recovery based on configuration
   */
  private handleErrorRecovery(error: Error): void {
    this.state.retryCount++;

    switch (this.config.errorRecoveryMode) {
      case 'reconnect':
        // Reset stream state and continue
        this.state.status = 'active';
        this.state.errorCount = 0;
        break;

      case 'continue':
        // Continue with current stream
        this.state.status = 'active';
        break;

      case 'fail':
        // End stream on any error
        this.endStream('error', error.message);
        break;
    }
  }

  /**
   * Updates performance metrics
   */
  private updateMetrics(event: SSEEvent): void {
    switch (event.event) {
      case 'token':
        this.metrics.totalTokens++;
        this.state.tokenCount++;
        break;

      case 'chunk':
        this.metrics.totalChunks++;
        this.state.chunkCount++;
        break;
    }

    // Update buffer usage metrics
    this.metrics.peakBufferUsage = Math.max(this.metrics.peakBufferUsage, this.buffer.length);
    this.metrics.averageBufferUsage = (this.metrics.averageBufferUsage + this.buffer.length) / 2;
    this.state.bufferUsage = this.buffer.length;

    // Update token timing
    if (this.state.firstTokenTime && this.metrics.totalTokens > 0) {
      const elapsed = Date.now() - this.state.firstTokenTime;
      this.metrics.averageTokenLatency = elapsed / this.metrics.totalTokens;
      this.state.averageTokenTime = this.metrics.averageTokenLatency;
      this.metrics.tokensPerSecond = this.metrics.totalTokens / (elapsed / 1000);
      this.state.tokensPerSecond = this.metrics.tokensPerSecond;
    }
  }

  /**
   * Generates unique event ID
   */
  private generateEventId(): string {
    return `${this.config.streamId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Cleanup resources
   */
  private cleanup(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = undefined;
    }

    if (this.cleanupTimer) {
      clearTimeout(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }

    this.abortController.abort();
    this.manager?.removeStream(this.config.streamId);
  }

  /**
   * Get current stream metrics
   */
  getMetrics(): StreamMetrics {
    return { ...this.metrics };
  }

  /**
   * Get current stream state
   */
  getState(): StreamState {
    return { ...this.state };
  }
}