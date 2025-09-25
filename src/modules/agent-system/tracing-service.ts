/**
 * Distributed Tracing Service
 * Tracks requests across services with OpenTelemetry integration
 */

import { Logger } from '../../shared/logger';
import type { D1Database } from '@cloudflare/workers-types';

export interface TraceContext {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  flags: number;
  baggage?: Record<string, string>;
}

export interface Span {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  operationName: string;
  serviceName: string;
  startTime: number;
  endTime?: number;
  duration?: number;
  status: 'ok' | 'error' | 'cancelled';
  attributes: Record<string, any>;
  events: SpanEvent[];
  links: SpanLink[];
  error?: Error;
}

export interface SpanEvent {
  name: string;
  timestamp: number;
  attributes?: Record<string, any>;
}

export interface SpanLink {
  traceId: string;
  spanId: string;
  attributes?: Record<string, any>;
}

export interface TracingConfig {
  serviceName: string;
  samplingRate: number;
  maxSpansPerTrace: number;
  exportInterval: number;
  enableAutoInstrumentation: boolean;
}

export // TODO: Consider splitting TracingService into smaller, focused classes
class TracingService {
  private logger: Logger;
  private db?: D1Database;
  private config: TracingConfig;
  private activeSpans = new Map<string, Span>();
  private completedSpans: Span[] = [];
  private exportInterval?: NodeJS.Timeout;
  private spanIdCounter = 0;

  constructor(config: Partial<TracingConfig> = {}, db?: D1Database) {
    this.logger = new Logger();
    this.db = db;
    this.config = {
      serviceName: 'agent-system',
      samplingRate: 1.0,
      maxSpansPerTrace: 1000,
      exportInterval: 5000,
      enableAutoInstrumentation: true,
      ...config
    };

    this.startExporter();
  }

  /**
   * Create a new trace context
   */
  createTraceContext(parentContext?: TraceContext): TraceContext {
    const traceId = parentContext?.traceId || this.generateTraceId();
    const spanId = this.generateSpanId();

    return {
      traceId,
      spanId,
      parentSpanId: parentContext?.spanId,
      flags: this.shouldSample() ? 1 : 0,
      baggage: parentContext?.baggage || {}
    };
  }

  /**
   * Start a new span
   */
  startSpan(
    operationName: string,
    context?: TraceContext,
    attributes: Record<string, any> = {}
  ): Span {
    const traceContext = context || this.createTraceContext();

    const span: Span = {
      traceId: traceContext.traceId,
      spanId: traceContext.spanId,
      parentSpanId: traceContext.parentSpanId,
      operationName,
      serviceName: this.config.serviceName,
      startTime: Date.now(),
      status: 'ok',
      attributes: {
        ...attributes,
        'service.name': this.config.serviceName,
        'span.kind': attributes.kind || 'internal'
      },
      events: [],
      links: []
    };

    this.activeSpans.set(span.spanId, span);

    this.logger.debug('Span started', {
      traceId: span.traceId,
      spanId: span.spanId,
      operation: operationName
    });

    return span;
  }

  /**
   * End a span
   */
  endSpan(spanId: string, error?: Error): void {
    const span = this.activeSpans.get(spanId);
    if (!span) {
      this.logger.warn('Attempted to end non-existent span', { spanId });
      return;
    }

    span.endTime = Date.now();
    span.duration = span.endTime - span.startTime;

    if (error) {
      span.status = 'error';
      span.error = error;
      span.attributes['error'] = true;
      span.attributes['error.type'] = error.name;
      span.attributes['error.message'] = error.message;
      if (error.stack) {
        span.attributes['error.stack'] = error.stack;
      }
    }

    this.activeSpans.delete(spanId);
    this.completedSpans.push(span);

    this.logger.debug('Span ended', {
      traceId: span.traceId,
      spanId: span.spanId,
      duration: span.duration,
      status: span.status
    });

    // Check if we should export
    if (this.completedSpans.length >= 100) {
      this.exportSpans().catch(error => {
        this.logger.error('Failed to export spans', error);
      });
    }
  }

  /**
   * Add event to span
   */
  addSpanEvent(spanId: string, name: string, attributes?: Record<string, any>): void {
    const span = this.activeSpans.get(spanId);
    if (!span) return;

    span.events.push({
      name,
      timestamp: Date.now(),
      attributes
    });
  }

  /**
   * Add link to span
   */
  addSpanLink(spanId: string, link: SpanLink): void {
    const span = this.activeSpans.get(spanId);
    if (!span) return;

    span.links.push(link);
  }

  /**
   * Set span attributes
   */
  setSpanAttributes(spanId: string, attributes: Record<string, any>): void {
    const span = this.activeSpans.get(spanId);
    if (!span) return;

    Object.assign(span.attributes, attributes);
  }

  /**
   * Instrument async function with tracing
   */
  instrument<T extends (...args: any[]) => Promise<any>>(
    fn: T,
    operationName: string,
    extractContext?: (args: Parameters<T>) => TraceContext | undefined
  ): T {
    return (async (...args: Parameters<T>) => {
      const context = extractContext ? extractContext(args) : undefined;
      const span = this.startSpan(operationName, context);

      try {
        const result = await fn(...args);
        this.endSpan(span.spanId);
        return result;
      } catch (error) {
        this.endSpan(span.spanId, error as Error);
        throw error;
      }
    }) as T;
  }

  /**
   * Create child span
   */
  createChildSpan(parentSpan: Span, operationName: string): Span {
    return this.startSpan(
      operationName,
      {
        traceId: parentSpan.traceId,
        spanId: this.generateSpanId(),
        parentSpanId: parentSpan.spanId,
        flags: 1
      }
    );
  }

  /**
   * Extract trace context from headers
   */
  extractContext(headers: Headers | Record<string, string>): TraceContext | undefined {
    const traceParent = this.getHeader(headers, 'traceparent');
    if (!traceParent) return undefined;

    // Parse W3C Trace Context format
    const parts = traceParent.split('-');
    if (parts.length !== 4) return undefined;

    const [version, traceId, spanId, flags] = parts;

    // Parse baggage
    const baggageHeader = this.getHeader(headers, 'baggage');
    const baggage: Record<string, string> = {};

    if (baggageHeader) {
      baggageHeader.split(',').forEach(item => {
        const [key, value] = item.trim().split('=');
        if (key && value) {
          baggage[key] = decodeURIComponent(value);
        }
      });
    }

    return {
      traceId,
      spanId,
      flags: parseInt(flags, 16),
      baggage
    };
  }

  /**
   * Inject trace context into headers
   */
  injectContext(context: TraceContext, headers: Headers | Record<string, string>): void {
    // W3C Trace Context format
    const traceParent = `00-${context.traceId}-${context.spanId}-${context.flags.toString(16).padStart(2, '0')}`;

    if (headers instanceof Headers) {
      headers.set('traceparent', traceParent);

      if (context.baggage && Object.keys(context.baggage).length > 0) {
        const baggageItems = Object.entries(context.baggage)
          .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
          .join(',');
        headers.set('baggage', baggageItems);
      }
    } else {
      headers['traceparent'] = traceParent;

      if (context.baggage && Object.keys(context.baggage).length > 0) {
        const baggageItems = Object.entries(context.baggage)
          .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
          .join(',');
        headers['baggage'] = baggageItems;
      }
    }
  }

  /**
   * Get trace graph for a trace ID
   */
  async getTraceGraph(traceId: string): Promise<{
    spans: Span[];
    rootSpan?: Span;
    tree: Map<string, Span[]>;
  }> {
    const spans = await this.getTraceSpans(traceId);

    // Build parent-child relationship tree
    const tree = new Map<string, Span[]>();
    let rootSpan: Span | undefined;

    for (const span of spans) {
      if (!span.parentSpanId) {
        rootSpan = span;
      } else {
        const siblings = tree.get(span.parentSpanId) || [];
        siblings.push(span);
        tree.set(span.parentSpanId, siblings);
      }
    }

    return { spans, rootSpan, tree };
  }

  /**
   * Get all spans for a trace
   */
  private async getTraceSpans(traceId: string): Promise<Span[]> {
    const spans: Span[] = [];

    // Get from active spans
    for (const span of this.activeSpans.values()) {
      if (span.traceId === traceId) {
        spans.push(span);
      }
    }

    // Get from completed spans
    for (const span of this.completedSpans) {
      if (span.traceId === traceId) {
        spans.push(span);
      }
    }

    // Get from database if available
    if (this.db) {
      try {
        const result = await this.db.prepare(`
          SELECT * FROM trace_spans
          WHERE trace_id = ?
          ORDER BY start_time ASC
        `).bind(traceId).all();

        const dbSpans = (result.results || []).map(row => this.deserializeSpan(row));
        spans.push(...dbSpans);
      } catch (error) {
        this.logger.error('Failed to fetch spans from database', error);
      }
    }

    return spans;
  }

  /**
   * Export spans to storage
   */
  private async exportSpans(): Promise<void> {
    if (this.completedSpans.length === 0) return;

    const spansToExport = [...this.completedSpans];
    this.completedSpans = [];

    if (!this.db) {
      this.logger.warn('No database configured for span export');
      return;
    }

    try {
      const batch = this.db.batch([]);

      for (const span of spansToExport) {
        batch.push(
          this.db.prepare(`
            INSERT OR REPLACE INTO trace_spans (
              trace_id, span_id, parent_span_id, operation_name,
              service_name, start_time, end_time, duration,
              status, attributes, events, links
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).bind(
            span.traceId,
            span.spanId,
            span.parentSpanId || null,
            span.operationName,
            span.serviceName,
            span.startTime,
            span.endTime || null,
            span.duration || null,
            span.status,
            JSON.stringify(span.attributes),
            JSON.stringify(span.events),
            JSON.stringify(span.links)
          )
        );
      }

      await this.db.batch(batch);

      this.logger.info('Exported spans', { count: spansToExport.length });

    } catch (error) {
      this.logger.error('Failed to export spans', error);
      // Re-add spans to be exported later
      this.completedSpans.push(...spansToExport);
    }
  }

  /**
   * Deserialize span from database
   */
  private deserializeSpan(row: any): Span {
    return {
      traceId: row.trace_id,
      spanId: row.span_id,
      parentSpanId: row.parent_span_id || undefined,
      operationName: row.operation_name,
      serviceName: row.service_name,
      startTime: row.start_time,
      endTime: row.end_time || undefined,
      duration: row.duration || undefined,
      status: row.status,
      attributes: JSON.parse(row.attributes || '{}'),
      events: JSON.parse(row.events || '[]'),
      links: JSON.parse(row.links || '[]')
    };
  }

  /**
   * Generate trace ID
   */
  private generateTraceId(): string {
    // 32 hex characters (128 bits)
    const buffer = new Uint8Array(16);
    crypto.getRandomValues(buffer);
    return Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Generate span ID
   */
  private generateSpanId(): string {
    // 16 hex characters (64 bits)
    const buffer = new Uint8Array(8);
    crypto.getRandomValues(buffer);
    return Array.from(buffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Check if should sample
   */
  private shouldSample(): boolean {
    return Math.random() < this.config.samplingRate;
  }

  /**
   * Get header value
   */
  private getHeader(headers: Headers | Record<string, string>, name: string): string | undefined {
    if (headers instanceof Headers) {
      return headers.get(name) || undefined;
    }
    return headers[name];
  }

  /**
   * Start exporter interval
   */
  private startExporter(): void {
    this.exportInterval = setInterval(() => {
      this.exportSpans().catch(error => {
        this.logger.error('Export interval failed', error);
      });
    }, this.config.exportInterval) as any;
  }

  /**
   * Get metrics
   */
  getMetrics(): {
    activeSpans: number;
    completedSpans: number;
    totalExported: number;
  } {
    return {
      activeSpans: this.activeSpans.size,
      completedSpans: this.completedSpans.length,
      totalExported: 0 // Would track this separately
    };
  }

  /**
   * Shutdown tracing
   */
  async shutdown(): Promise<void> {
    if (this.exportInterval) {
      clearInterval(this.exportInterval);
    }

    // Export remaining spans
    await this.exportSpans();

    // End all active spans
    for (const [spanId, span] of this.activeSpans) {
      this.endSpan(spanId, new Error('Tracing shutdown'));
    }

    this.logger.info('Tracing service shutdown');
  }
}

/**
 * Trace context propagation utilities
 */
export class TraceContextPropagator {
  /**
   * Create context for Cloudflare Workers
   */
  static fromCloudflareRequest(request: Request): TraceContext | undefined {
    const tracingService = new TracingService();
    return tracingService.extractContext(request.headers);
  }

  /**
   * Add context to fetch request
   */
  static addToFetch(url: string, init: RequestInit, context: TraceContext): RequestInit {
    const headers = new Headers(init.headers || {});
    const tracingService = new TracingService();
    tracingService.injectContext(context, headers);

    return {
      ...init,
      headers
    };
  }
}

/**
 * Database schema for traces
 */
export const TRACE_SCHEMA = `
CREATE TABLE IF NOT EXISTS trace_spans (
  trace_id TEXT NOT NULL,
  span_id TEXT NOT NULL,
  parent_span_id TEXT,
  operation_name TEXT NOT NULL,
  service_name TEXT NOT NULL,
  start_time INTEGER NOT NULL,
  end_time INTEGER,
  duration INTEGER,
  status TEXT NOT NULL,
  attributes TEXT,
  events TEXT,
  links TEXT,

  PRIMARY KEY (trace_id, span_id),
  INDEX idx_trace_spans_trace (trace_id),
  INDEX idx_trace_spans_time (start_time DESC),
  INDEX idx_trace_spans_operation (operation_name),
  INDEX idx_trace_spans_status (status) WHERE status = 'error'
);
`;