import { Span, TraceContext, LogEntry } from '../../types/telemetry';
import { TelemetryCollector } from './collector';

interface TraceConfig {
  samplingRate: number;
  maxSpanDuration: number;
  enableBaggage: boolean;
  exportInterval: number;
}

interface SpanBuilder {
  setOperationName(name: string): SpanBuilder;
  setTag(key: string, value: any): SpanBuilder;
  setParent(parent: Span | TraceContext): SpanBuilder;
  start(): Span;
}

export class DistributedTracing {
  private collector: TelemetryCollector;
  private activeSpans: Map<string, Span> = new Map();
  private config: TraceConfig;
  private samplingDecisions: Map<string, boolean> = new Map();

  constructor(collector: TelemetryCollector, config: Partial<TraceConfig> = {}) {
    this.collector = collector;
    this.config = {
      samplingRate: 0.1, // 10% sampling
      maxSpanDuration: 300000, // 5 minutes
      enableBaggage: true,
      exportInterval: 5000, // 5 seconds
      ...config
    };

    this.startExportTimer();
  }

  createSpan(operationName: string): SpanBuilder {
    return new SpanBuilderImpl(this, operationName);
  }

  startSpan(operationName: string, parent?: Span | TraceContext): Span {
    const traceId = parent?.traceId || this.generateTraceId();
    const spanId = this.generateSpanId();
    const parentSpanId = parent?.spanId;

    // Sampling decision
    if (!this.shouldSample(traceId)) {
      return this.createNoOpSpan(traceId, spanId, parentSpanId);
    }

    const span: Span = {
      traceId,
      spanId,
      parentSpanId,
      operationName,
      startTime: Date.now(),
      tags: {},
      logs: [],
      status: 'ok'
    };

    this.activeSpans.set(spanId, span);
    return span;
  }

  finishSpan(span: Span, error?: Error): void {
    if (!span.endTime) {
      span.endTime = Date.now();
      span.duration = span.endTime - span.startTime;
    }

    if (error) {
      span.status = 'error';
      span.tags.error = true;
      span.tags['error.message'] = error.message;
      span.tags['error.stack'] = error.stack;
    }

    this.activeSpans.delete(span.spanId);
    this.collector.collectSpan(span);
  }

  addLog(span: Span, fields: Record<string, any>): void {
    span.logs.push({
      timestamp: Date.now(),
      fields
    });
  }

  setTag(span: Span, key: string, value: any): void {
    span.tags[key] = value;
  }

  setBaggage(span: Span, key: string, value: string): void {
    if (!this.config.enableBaggage) return;

    if (!span.tags.baggage) {
      span.tags.baggage = {};
    }
    span.tags.baggage[key] = value;
  }

  getBaggage(span: Span, key: string): string | undefined {
    return span.tags.baggage?.[key];
  }

  injectContext(span: Span): Record<string, string> {
    const headers: Record<string, string> = {};

    // W3C Trace Context
    headers['traceparent'] = `00-${span.traceId}-${span.spanId}-01`;

    if (span.tags.baggage && Object.keys(span.tags.baggage).length > 0) {
      headers['tracestate'] = Object.entries(span.tags.baggage)
        .map(([k, v]) => `${k}=${v}`)
        .join(',');
    }

    return headers;
  }

  extractContext(headers: Record<string, string>): TraceContext | null {
    const traceparent = headers['traceparent'] || headers['Traceparent'];
    if (!traceparent) return null;

    const parts = traceparent.split('-');
    if (parts.length !== 4 || parts[0] !== '00') return null;

    const baggage: Record<string, string> = {};
    const tracestate = headers['tracestate'] || headers['Tracestate'];
    if (tracestate) {
      tracestate.split(',').forEach((pair: any) => {
        const [key, value] = pair.split('=');
        if (key && value) {
          baggage[key.trim()] = value.trim();
        }
      });
    }

    return {
      traceId: parts[1],
      spanId: parts[2],
      baggage
    };
  }

  async instrument<T>(
    operationName: string,
    operation: (span: Span) => Promise<T> | T,
    parent?: Span | TraceContext
  ): Promise<T> {
    const span = this.startSpan(operationName, parent);

    try {
      const result = await operation(span);
      this.finishSpan(span);
      return result;
    } catch (error: any) {
      this.finishSpan(span, error as Error);
      throw error;
    }
  }

  instrumentSync<T>(
    operationName: string,
    operation: (span: Span) => T,
    parent?: Span | TraceContext
  ): T {
    const span = this.startSpan(operationName, parent);

    try {
      const result = operation(span);
      this.finishSpan(span);
      return result;
    } catch (error: any) {
      this.finishSpan(span, error as Error);
      throw error;
    }
  }

  createFlameGraph(traceId: string): Promise<any> {
    return this.collector.query(`
      SELECT
        span_id,
        parent_span_id,
        JSONExtract(properties, 'operationName', 'String') as operation_name,
        JSONExtract(metrics, 'startTime', 'UInt64') as start_time,
        JSONExtract(metrics, 'duration', 'UInt64') as duration
      FROM telemetry_events
      WHERE trace_id = '${traceId}'
        AND event_type = 'span'
      ORDER BY start_time
    `);
  }

  async getCriticalPath(traceId: string): Promise<Span[]> {
    const spans = await this.collector.query(`
      SELECT *
      FROM telemetry_events
      WHERE trace_id = '${traceId}'
        AND event_type = 'span'
      ORDER BY JSONExtract(metrics, 'startTime', 'UInt64')
    `);

    // Build span tree and find critical path
    const spanMap = new Map<string, any>();
    const rootSpans: any[] = [];

    spans.forEach((span: any) => {
      const spanData = {
        ...span,
        children: []
      };
      spanMap.set(span.span_id, spanData);

      if (!span.parent_span_id) {
        rootSpans.push(spanData);
      }
    });

    // Link children to parents
    spans.forEach((span: any) => {
      if (span.parent_span_id) {
        const parent = spanMap.get(span.parent_span_id);
        if (parent) {
          parent.children.push(spanMap.get(span.span_id));
        }
      }
    });

    // Find critical path (longest duration chain)
    const findCriticalPath = (span: any, path: any[] = []): any[] => {
      const currentPath = [...path, span];

      if (span.children.length === 0) {
        return currentPath;
      }

      let longestPath = currentPath;
      let maxDuration = 0;

      span.children.forEach((child: any) => {
        const childPath = findCriticalPath(child, currentPath);
        const totalDuration = childPath.reduce((sum: number, s: any) =>
          sum + (JSON.parse(s.metrics).duration || 0), 0);

        if (totalDuration > maxDuration) {
          maxDuration = totalDuration;
          longestPath = childPath;
        }
      });

      return longestPath;
    };

    if (rootSpans.length === 0) return [];

    const criticalPath = findCriticalPath(rootSpans[0]);
    return criticalPath.map((span: any) => this.convertToSpan(span));
  }

  private convertToSpan(dbSpan: any): Span {
    const properties = JSON.parse(dbSpan.properties);
    const metrics = JSON.parse(dbSpan.metrics);

    return {
      traceId: dbSpan.trace_id,
      spanId: dbSpan.span_id,
      parentSpanId: dbSpan.parent_span_id,
      operationName: properties.operationName,
      startTime: metrics.startTime,
      endTime: metrics.endTime,
      duration: metrics.duration,
      tags: properties,
      logs: [],
      status: 'ok'
    };
  }

  async analyzeTraceAnomalies(traceId: string): Promise<any[]> {
    const spans = await this.collector.query(`
      SELECT
        span_id,
        JSONExtract(properties, 'operationName', 'String') as operation_name,
        JSONExtract(metrics, 'duration', 'UInt64') as duration
      FROM telemetry_events
      WHERE trace_id = '${traceId}'
        AND event_type = 'span'
    `);

    const anomalies: any[] = [];

    // Check for unusually long spans
    const avgDurations = new Map<string, number>();
    const spanCounts = new Map<string, number>();

    // Get historical data for comparison
    const historicalSpans = await this.collector.query(`
      SELECT
        JSONExtract(properties, 'operationName', 'String') as operation_name,
        AVG(JSONExtract(metrics, 'duration', 'UInt64')) as avg_duration
      FROM telemetry_events
      WHERE event_type = 'span'
        AND event_time >= now() - INTERVAL 7 DAY
      GROUP BY operation_name
    `);

    historicalSpans.forEach((row: any) => {
      avgDurations.set(row.operation_name, row.avg_duration);
    });

    spans.forEach((span: any) => {
      const avgDuration = avgDurations.get(span.operation_name);
      if (avgDuration && span.duration > avgDuration * 3) {
        anomalies.push({
          type: 'slow_span',
          spanId: span.span_id,
          operationName: span.operation_name,
          duration: span.duration,
          expectedDuration: avgDuration,
          severity: span.duration > avgDuration * 5 ? 'high' : 'medium'
        });
      }
    });

    return anomalies;
  }

  private shouldSample(traceId: string): boolean {
    if (this.samplingDecisions.has(traceId)) {
      return this.samplingDecisions.get(traceId)!;
    }

    const decision = Math.random() < this.config.samplingRate;
    this.samplingDecisions.set(traceId, decision);

    // Clean up old decisions
    if (this.samplingDecisions.size > 10000) {
      const keys = Array.from(this.samplingDecisions.keys());
      keys.slice(0, 5000).forEach((key: any) => this.samplingDecisions.delete(key));
    }

    return decision;
  }

  private generateTraceId(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)),
      b => b.toString(16).padStart(2, '0')).join('');
  }

  private generateSpanId(): string {
    return Array.from(crypto.getRandomValues(new Uint8Array(8)),
      b => b.toString(16).padStart(2, '0')).join('');
  }

  private createNoOpSpan(traceId: string, spanId: string, parentSpanId?: string): Span {
    return {
      traceId,
      spanId,
      parentSpanId,
      operationName: 'noop',
      startTime: Date.now(),
      tags: { sampled: false },
      logs: [],
      status: 'ok'
    };
  }

  private startExportTimer(): void {
    setInterval(() => {
      this.exportPendingSpans();
    }, this.config.exportInterval);
  }

  private async exportPendingSpans(): Promise<void> {
    const expiredSpans: Span[] = [];
    const now = Date.now();

    for (const [spanId, span] of this.activeSpans) {
      if (now - span.startTime > this.config.maxSpanDuration) {
        span.endTime = now;
        span.duration = span.endTime - span.startTime;
        span.tags.timeout = true;
        expiredSpans.push(span);
        this.activeSpans.delete(spanId);
      }
    }

    await Promise.all(
      expiredSpans.map((span: any) => this.collector.collectSpan(span))
    );
  }

  getActiveSpanCount(): number {
    return this.activeSpans.size;
  }

  getTraceMetrics(): any {
    return {
      activeSpans: this.activeSpans.size,
      samplingRate: this.config.samplingRate,
      samplingDecisions: this.samplingDecisions.size
    };
  }
}

class SpanBuilderImpl implements SpanBuilder {
  private tracer: DistributedTracing;
  private operationName: string;
  private tags: Record<string, any> = {};
  private parent?: Span | TraceContext;

  constructor(tracer: DistributedTracing, operationName: string) {
    this.tracer = tracer;
    this.operationName = operationName;
  }

  setOperationName(name: string): SpanBuilder {
    this.operationName = name;
    return this;
  }

  setTag(key: string, value: any): SpanBuilder {
    this.tags[key] = value;
    return this;
  }

  setParent(parent: Span | TraceContext): SpanBuilder {
    this.parent = parent;
    return this;
  }

  start(): Span {
    const span = this.tracer.startSpan(this.operationName, this.parent);

    Object.entries(this.tags).forEach(([key, value]) => {
      this.tracer.setTag(span, key, value);
    });

    return span;
  }
}

export function withTracing<T extends any[], R>(
  tracer: DistributedTracing,
  operationName: string,
  fn: (...args: T) => Promise<R>
): (...args: T) => Promise<R> {
  return async (...args: T): Promise<R> => {
    return tracer.instrument(operationName, async (span: any) => {
      return fn(...args);
    });
  };
}

export function tracingMiddleware(tracer: DistributedTracing) {
  return async (request: Request, env: any, ctx: any, next: () => Promise<Response>): Promise<Response> => {
    const context = tracer.extractContext(Object.fromEntries(request.headers.entries()));
    const operationName = `${request.method} ${new URL(request.url).pathname}`;

    return tracer.instrument(operationName, async (span: any) => {
      tracer.setTag(span, 'http.method', request.method);
      tracer.setTag(span, 'http.url', request.url);
      tracer.setTag(span, 'component', 'http-server');

      try {
        const response = await next();

        tracer.setTag(span, 'http.status_code', response.status);
        tracer.setTag(span, 'http.status_text', response.statusText);

        if (response.status >= 400) {
          span.status = 'error';
          tracer.setTag(span, 'error', true);
        }

        // Inject trace context into response headers
        const traceHeaders = tracer.injectContext(span);
        Object.entries(traceHeaders).forEach(([key, value]) => {
          response.headers.set(key, value);
        });

        return response;
      } catch (error: any) {
        span.status = 'error';
        tracer.setTag(span, 'error', true);
        tracer.setTag(span, 'error.message', (error as Error).message);
        throw error;
      }
    }, context);
  };
}