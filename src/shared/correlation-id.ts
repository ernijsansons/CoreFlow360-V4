/**
 * Correlation ID System for Request Tracing
 * Provides end-to-end tracing across all system components
 */

import { Logger } from './logger';

export interface TraceContext {
  correlationId: string;
  parentId?: string;
  operationId: string;
  userId?: string;
  businessId?: string;
  sessionId?: string;
  requestId?: string;
  userAgent?: string;
  ipAddress?: string;
  startTime: number;
  metadata?: Record<string, any>;
}

export interface TraceSpan {
  spanId: string;
  correlationId: string;
  parentSpanId?: string;
  operationName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  status: 'pending' | 'success' | 'error';
  tags: Record<string, any>;
  logs: Array<{
    timestamp: number;
    level: string;
    message: string;
    fields?: Record<string, any>;
  }>;
  error?: {
    message: string;
    stack?: string;
    code?: string;
  };
}

export interface TracingConfig {
  enabled: boolean;
  samplingRate: number; // 0.0 to 1.0
  maxSpansPerTrace: number;
  spanRetentionMs: number;
}

// TODO: Consider splitting CorrelationIdManager into smaller, focused classes
export class CorrelationIdManager {
  private static instance: CorrelationIdManager;
  private logger: Logger;
  private config: TracingConfig;
  private activeSpans: Map<string, TraceSpan> = new Map();
  private traceContexts: Map<string, TraceContext> = new Map();
  private spanHierarchy: Map<string, string[]> = new Map(); // correlationId -> spanIds

  private constructor(config: TracingConfig) {
    this.logger = new Logger();
    this.config = config;
    this.setupCleanupTimer();
  }

  static getInstance(config?: TracingConfig): CorrelationIdManager {
    if (!this.instance) {
      this.instance = new CorrelationIdManager(config || {
        enabled: true,
        samplingRate: 1.0,
        maxSpansPerTrace: 100,
        spanRetentionMs: 24 * 60 * 60 * 1000 // 24 hours
      });
    }
    return this.instance;
  }

  /**
   * Generate a new correlation ID
   */
  generateCorrelationId(): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 10);
    return `cf_${timestamp}_${random}`;
  }

  /**
   * Generate a new span ID
   */
  generateSpanId(): string {
    return Math.random().toString(36).substring(2, 18);
  }

  /**
   * Create a new trace context
   */
  createTraceContext(request: Request, additionalMetadata?: Record<string, any>): TraceContext {
    const correlationId = this.extractCorrelationId(request) || this.generateCorrelationId();
    const operationId = this.generateSpanId();

    const context: TraceContext = {
      correlationId,
      operationId,
      startTime: Date.now(),
      userAgent: request.headers.get('user-agent') || undefined,
      ipAddress: request.headers.get('cf-connecting-ip') ||
                 request.headers.get('x-forwarded-for') ||
                 undefined,
      requestId: request.headers.get('x-request-id') || undefined,
      metadata: additionalMetadata
    };

    this.traceContexts.set(correlationId, context);

    this.logger.debug('Trace context created', {
      correlationId,
      operationId,
      hasMetadata: !!additionalMetadata
    });

    return context;
  }

  /**
   * Start a new span
   */
  startSpan(
    operationName: string,
    correlationId: string,
    parentSpanId?: string,
    tags: Record<string, any> = {}
  ): TraceSpan {
    if (!this.config.enabled) {
      return this.createNoOpSpan(operationName, correlationId);
    }

    // Check sampling rate
    if (Math.random() > this.config.samplingRate) {
      return this.createNoOpSpan(operationName, correlationId);
    }

    const spanId = this.generateSpanId();
    const span: TraceSpan = {
      spanId,
      correlationId,
      parentSpanId,
      operationName,
      startTime: Date.now(),
      status: 'pending',
      tags: { ...tags },
      logs: []
    };

    this.activeSpans.set(spanId, span);

    // Track span hierarchy
    if (!this.spanHierarchy.has(correlationId)) {
      this.spanHierarchy.set(correlationId, []);
    }
    this.spanHierarchy.get(correlationId)!.push(spanId);

    // Check span limit per trace
    const spansInTrace = this.spanHierarchy.get(correlationId)!.length;
    if (spansInTrace > this.config.maxSpansPerTrace) {
      this.logger.warn('Maximum spans per trace exceeded', {
        correlationId,
        spanCount: spansInTrace,
        maxSpans: this.config.maxSpansPerTrace
      });
    }

    this.logger.debug('Span started', {
      spanId,
      correlationId,
      operationName,
      parentSpanId,
      tags
    });

    return span;
  }

  /**
   * Finish a span
   */
  finishSpan(spanId: string, status: 'success' | 'error' = 'success', error?: Error): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      this.logger.warn('Attempted to finish unknown span', { spanId });
      return;
    }

    span.endTime = Date.now();
    span.duration = span.endTime - span.startTime;
    span.status = status;

    if (error) {
      span.error = {
        message: error.message,
        stack: error.stack,
        code: (error as any).code
      };
    }

    this.logger.debug('Span finished', {
      spanId,
      correlationId: span.correlationId,
      operationName: span.operationName,
      duration: span.duration,
      status,
      hasError: !!error
    });

    // Keep span for a while for querying, then remove
    setTimeout(() => {
      this.activeSpans.delete(spanId);
    }, this.config.spanRetentionMs);
  }

  /**
   * Add log entry to a span
   */
  addSpanLog(spanId: string, level: string, message: string, fields?: Record<string, any>): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      return;
    }

    span.logs.push({
      timestamp: Date.now(),
      level,
      message,
      fields
    });

    // Limit log entries per span
    if (span.logs.length > 50) {
      span.logs.shift(); // Remove oldest log
    }
  }

  /**
   * Add tags to a span
   */
  addSpanTags(spanId: string, tags: Record<string, any>): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      return;
    }

    Object.assign(span.tags, tags);
  }

  /**
   * Get trace information
   */
  getTrace(correlationId: string): {
    context?: TraceContext;
    spans: TraceSpan[];
    totalDuration?: number;
    spanCount: number;
  } {
    const context = this.traceContexts.get(correlationId);
    const spanIds = this.spanHierarchy.get(correlationId) || [];
    const spans = spanIds.map(id => this.activeSpans.get(id)).filter(Boolean) as TraceSpan[];

    const completedSpans = spans.filter(s => s.endTime);
    const totalDuration = completedSpans.length > 0
      ? Math.max(...completedSpans.map(s => s.endTime!)) - Math.min(...spans.map(s => s.startTime))
      : undefined;

    return {
      context,
      spans,
      totalDuration,
      spanCount: spans.length
    };
  }

  /**
   * Get all active traces
   */
  getActiveTraces(): Array<{
    correlationId: string;
    context: TraceContext;
    activeSpans: number;
    totalSpans: number;
  }> {
    const traces: Array<{
      correlationId: string;
      context: TraceContext;
      activeSpans: number;
      totalSpans: number;
    }> = [];

    for (const [correlationId, context] of this.traceContexts) {
      const spanIds = this.spanHierarchy.get(correlationId) || [];
      const activeSpans = spanIds.filter(id => {
        const span = this.activeSpans.get(id);
        return span && span.status === 'pending';
      }).length;

      traces.push({
        correlationId,
        context,
        activeSpans,
        totalSpans: spanIds.length
      });
    }

    return traces;
  }

  /**
   * Extract correlation ID from request headers
   */
  private extractCorrelationId(request: Request): string | null {
    return request.headers.get('x-correlation-id') ||
           request.headers.get('x-trace-id') ||
           request.headers.get('x-request-id') ||
           null;
  }

  /**
   * Create a no-op span for when tracing is disabled or not sampled
   */
  private createNoOpSpan(operationName: string, correlationId: string): TraceSpan {
    return {
      spanId: 'noop',
      correlationId,
      operationName,
      startTime: Date.now(),
      status: 'success',
      tags: {},
      logs: []
    };
  }

  /**
   * Setup cleanup timer for old traces
   */
  private setupCleanupTimer(): void {
    // Clean up old traces every hour
    setInterval(() => {
      this.cleanupOldTraces();
    }, 60 * 60 * 1000);
  }

  /**
   * Clean up old traces and spans
   */
  private cleanupOldTraces(): void {
    const cutoffTime = Date.now() - this.config.spanRetentionMs;
    let cleaned = 0;

    for (const [correlationId, context] of this.traceContexts) {
      if (context.startTime < cutoffTime) {
        // Remove trace context
        this.traceContexts.delete(correlationId);

        // Remove associated spans
        const spanIds = this.spanHierarchy.get(correlationId) || [];
        for (const spanId of spanIds) {
          this.activeSpans.delete(spanId);
        }
        this.spanHierarchy.delete(correlationId);

        cleaned++;
      }
    }

    if (cleaned > 0) {
      this.logger.debug('Cleaned up old traces', {
        tracesRemoved: cleaned,
        cutoffTime: new Date(cutoffTime).toISOString()
      });
    }
  }

  /**
   * Get tracing statistics
   */
  getStats(): {
    activeTraces: number;
    activeSpans: number;
    totalSpanHierarchies: number;
    enabled: boolean;
    samplingRate: number;
  } {
    return {
      activeTraces: this.traceContexts.size,
      activeSpans: this.activeSpans.size,
      totalSpanHierarchies: this.spanHierarchy.size,
      enabled: this.config.enabled,
      samplingRate: this.config.samplingRate
    };
  }
}

/**
 * Utility function to wrap async operations with tracing
 */
export async function withTracing<T>(
  operationName: string,
  correlationId: string,
  operation: (span: TraceSpan) => Promise<T>,
  parentSpanId?: string,
  tags?: Record<string, any>
): Promise<T> {
  const manager = CorrelationIdManager.getInstance();
  const span = manager.startSpan(operationName, correlationId, parentSpanId, tags);

  try {
    const result = await operation(span);
    manager.finishSpan(span.spanId, 'success');
    return result;
  } catch (error) {
    manager.finishSpan(span.spanId, 'error', error as Error);
    throw error;
  }
}

/**
 * Middleware for automatic correlation ID injection
 */
export function createCorrelationMiddleware(config?: Partial<TracingConfig>) {
  const manager = CorrelationIdManager.getInstance({
    enabled: true,
    samplingRate: 1.0,
    maxSpansPerTrace: 100,
    spanRetentionMs: 24 * 60 * 60 * 1000,
    ...config
  });

  return {
    /**
     * Process incoming request and create trace context
     */
    processRequest: (request: Request, additionalMetadata?: Record<string, any>) => {
      return manager.createTraceContext(request, additionalMetadata);
    },

    /**
     * Add correlation ID to response headers
     */
    addResponseHeaders: (response: Response, correlationId: string): Response => {
      const newHeaders = new Headers(response.headers);
      newHeaders.set('x-correlation-id', correlationId);
      newHeaders.set('x-trace-id', correlationId);

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
      });
    },

    /**
     * Create request headers for outgoing calls
     */
    createOutgoingHeaders: (correlationId: string): Record<string, string> => {
      return {
        'x-correlation-id': correlationId,
        'x-trace-id': correlationId
      };
    }
  };
}

// Global correlation manager instance
export const correlationManager = CorrelationIdManager.getInstance();

// Static utility class for backwards compatibility
export class CorrelationId {
  /**
   * Generate a new correlation ID
   */
  static generate(): string {
    return correlationManager.generateCorrelationId();
  }
}

// Export types and utilities
export type { TraceContext, TraceSpan, TracingConfig };