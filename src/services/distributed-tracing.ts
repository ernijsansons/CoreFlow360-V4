// CoreFlow360 V4 - Distributed Tracing System
import { TraceContext, Span, Trace, LogEvent } from '../types/observability';
import { TelemetryCollector } from './telemetry-collector';

export class DistributedTracing {
  private db: D1Database;
  private telemetryCollector: TelemetryCollector;
  private currentSpan?: Span;

  constructor(env: any) {
    this.db = env.DB;
    this.telemetryCollector = new TelemetryCollector(env);
  }

  // W3C Trace Context implementation
  generateTraceId(): string {
    // Generate 16-byte trace ID as hex string
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  generateSpanId(): string {
    // Generate 8-byte span ID as hex string
    const array = new Uint8Array(8);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  parseTraceContext(headers: Headers): TraceContext | null {
    const traceparent = headers.get('traceparent');
    if (!traceparent) return null;

    // Parse W3C traceparent header: version-traceId-spanId-flags
    const parts = traceparent.split('-');
    if (parts.length !== 4) return null;

    const [version, traceId, spanId, flagsHex] = parts;
    if (version !== '00') return null; // Only support version 00

    const flags = parseInt(flagsHex, 16);
    const baggage: Record<string, string> = {};

    // Parse baggage header
    const baggageHeader = headers.get('baggage');
    if (baggageHeader) {
      const pairs = baggageHeader.split(',');
      for (const pair of pairs) {
        const [key, value] = pair.trim().split('=');
        if (key && value) {
          baggage[key] = decodeURIComponent(value);
        }
      }
    }

    return {
      traceId,
      spanId,
      flags,
      baggage
    };
  }

  createTraceContext(traceId: string, spanId: string, flags: number = 1): TraceContext {
    return {
      traceId,
      spanId,
      flags,
      baggage: {}
    };
  }

  toTraceParent(context: TraceContext): string {
    const flagsHex = context.flags.toString(16).padStart(2, '0');
    return `00-${context.traceId}-${context.spanId}-${flagsHex}`;
  }

  toBaggageHeader(context: TraceContext): string {
    const pairs = Object.entries(context.baggage).map(([key, value]) => 
      `${key}=${encodeURIComponent(value)}`
    );
    return pairs.join(',');
  }

  // Span management
  startSpan(
    name: string,
    parentContext?: TraceContext,
    attributes: Record<string, any> = {}
  ): Span {
    const traceId = parentContext?.traceId || this.generateTraceId();
    const spanId = this.generateSpanId();
    const parentSpanId = parentContext?.spanId;

    const span: Span = {
      spanId,
      traceId,
      parentSpanId,
      serviceName: 'coreflow360',
      operationName: name,
      startTime: new Date(),
      endTime: undefined,
      durationMs: undefined,
      status: 'ok',
      statusMessage: undefined,
      spanKind: 'internal',
      tags: {
        ...attributes,
        'span.kind': 'internal',
        'service.name': 'coreflow360',
        'service.version': '4.0.0'
      },
      logs: []
    };

    this.currentSpan = span;
    return span;
  }

  endSpan(span: Span, status: 'ok' | 'error' = 'ok', error?: Error): void {
    span.endTime = new Date();
    span.durationMs = span.endTime.getTime() - span.startTime.getTime();
    span.status = status;

    if (error) {
      span.tags['error'] = true;
      span.tags['error.message'] = error.message;
      span.tags['error.type'] = error.name;
      if (error.stack) {
        span.tags['error.stack'] = error.stack;
      }
    }

    // Send span to telemetry collector
    this.telemetryCollector.collectSpan(span);

    // Clear current span if it's the one being ended
    if (this.currentSpan?.spanId === span.spanId) {
      this.currentSpan = undefined;
    }
  }

  addSpanEvent(span: Span, name: string, attributes: Record<string, any> = {}): void {
    const event: LogEvent = {
      timestamp: new Date(),
      fields: {
        name,
        ...attributes
      }
    };
    span.logs.push(event);
  }

  addSpanAttribute(span: Span, key: string, value: any): void {
    span.tags[key] = value;
  }

  // Trace management
  async createTrace(traceId: string, businessId: string): Promise<Trace> {
    const trace: Trace = {
      traceId,
      businessId,
      userId: undefined,
      serviceName: 'coreflow360',
      operationName: 'trace',
      startTime: new Date(),
      endTime: undefined,
      durationMs: undefined,
      status: 'ok',
      spans: [],
      tags: {
        'trace.business_id': businessId,
        'trace.service': 'coreflow360'
      }
    };

    // Store trace in database
    await this.db.prepare(`
      INSERT INTO traces (
        id, business_id, start_time, end_time, duration, status, attributes
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      trace.traceId,
      trace.businessId,
      trace.startTime.toISOString(),
      trace.endTime?.toISOString(),
      trace.durationMs,
      trace.status,
      JSON.stringify(trace.tags)
    ).run();

    return trace;
  }

  async endTrace(traceId: string, status: 'ok' | 'error' = 'ok'): Promise<void> {
    const endTime = new Date();
    
    // Get trace from database
    const result = await this.db.prepare(`
      SELECT * FROM traces WHERE id = ?
    `).bind(traceId).first();

    if (!result) return;

    const startTime = new Date(result.start_time as string);
    const duration = endTime.getTime() - startTime.getTime();

    // Update trace
    await this.db.prepare(`
      UPDATE traces SET
        end_time = ?, duration = ?, status = ?
      WHERE id = ?
    `).bind(endTime.toISOString(), duration, status, traceId).run();
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    const result = await this.db.prepare(`
      SELECT * FROM traces WHERE id = ?
    `).bind(traceId).first();

    if (!result) return null;

    // Get spans for this trace
    const spansResult = await this.db.prepare(`
      SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time
    `).bind(traceId).all();

    const spans = spansResult.results.map(row => ({
      spanId: row.id as string,
      traceId: row.trace_id as string,
      parentSpanId: row.parent_span_id as string,
      serviceName: 'coreflow360',
      operationName: row.name as string,
      startTime: new Date(row.start_time as string),
      endTime: row.end_time ? new Date(row.end_time as string) : undefined,
      durationMs: row.duration as number,
      status: row.status as 'ok' | 'error' | 'timeout',
      statusMessage: undefined,
      spanKind: 'internal' as const,
      tags: JSON.parse(row.attributes as string),
      logs: JSON.parse(row.events as string)
    }));

    return {
      traceId: result.id as string,
      businessId: result.business_id as string,
      userId: undefined,
      serviceName: 'coreflow360',
      operationName: 'trace',
      startTime: new Date(result.start_time as string),
      endTime: result.end_time ? new Date(result.end_time as string) : undefined,
      durationMs: result.duration as number,
      status: result.status as 'ok' | 'error' | 'timeout',
      spans,
      tags: JSON.parse(result.attributes as string)
    };
  }

  async getTraces(
    businessId: string,
    filters: {
      startTime?: number;
      endTime?: number;
      status?: string;
      limit?: number;
    } = {}
  ): Promise<Trace[]> {
    let query = 'SELECT * FROM traces WHERE business_id = ?';
    const params: any[] = [businessId];

    if (filters.startTime) {
      query += ' AND start_time >= ?';
      params.push(filters.startTime);
    }

    if (filters.endTime) {
      query += ' AND end_time <= ?';
      params.push(filters.endTime);
    }

    if (filters.status) {
      query += ' AND status = ?';
      params.push(filters.status);
    }

    query += ' ORDER BY start_time DESC';

    if (filters.limit) {
      query += ' LIMIT ?';
      params.push(filters.limit);
    }

    const result = await this.db.prepare(query).bind(...params).all();

    return result.results.map(row => ({
      traceId: row.id as string,
      businessId: row.business_id as string,
      userId: undefined,
      serviceName: 'coreflow360',
      operationName: 'trace',
      startTime: new Date(row.start_time as string),
      endTime: row.end_time ? new Date(row.end_time as string) : undefined,
      durationMs: row.duration as number,
      status: row.status as 'ok' | 'error' | 'timeout',
      spans: [], // Would load spans separately for performance
      tags: JSON.parse(row.attributes as string)
    }));
  }

  // Span storage
  async storeSpan(span: Span): Promise<void> {
    await this.db.prepare(`
      INSERT INTO spans (
        id, trace_id, parent_span_id, name, start_time, end_time,
        duration, status, attributes, events, links, resource
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      span.spanId,
      span.traceId,
      span.parentSpanId,
      span.operationName,
      span.startTime.toISOString(),
      span.endTime?.toISOString(),
      span.durationMs,
      span.status,
      JSON.stringify(span.tags),
      JSON.stringify(span.logs),
      JSON.stringify([]), // links
      JSON.stringify({}) // resource
    ).run();
  }

  // Trace analysis
  async analyzeTrace(traceId: string): Promise<{
    totalSpans: number;
    duration: number;
    errorSpans: number;
    slowSpans: number;
    criticalPath: string[];
    bottlenecks: string[];
  }> {
    const trace = await this.getTrace(traceId);
    if (!trace) {
      throw new Error('Trace not found');
    }

    const totalSpans = trace.spans.length;
    const errorSpans = trace.spans.filter(s => s.status === 'error').length;
    const slowSpans = trace.spans.filter(s => (s.durationMs || 0) > 1000).length; // > 1 second

    // Find critical path (longest path through the trace)
    const criticalPath = this.findCriticalPath(trace.spans);
    
    // Find bottlenecks (spans with high duration)
    const bottlenecks = trace.spans
      .filter(s => (s.durationMs || 0) > 500) // > 500ms
      .map(s => s.operationName)
      .sort((a, b) => {
        const spanA = trace.spans.find(s => s.operationName === a);
        const spanB = trace.spans.find(s => s.operationName === b);
        return (spanB?.durationMs || 0) - (spanA?.durationMs || 0);
      });

    return {
      totalSpans,
      duration: trace.durationMs || 0,
      errorSpans,
      slowSpans,
      criticalPath,
      bottlenecks
    };
  }

  private findCriticalPath(spans: Span[]): string[] {
    // Simple critical path algorithm
    // In a real implementation, this would be more sophisticated
    const rootSpans = spans.filter(s => !s.parentSpanId);
    if (rootSpans.length === 0) return [];

    const path: string[] = [];
    let currentSpan = rootSpans[0]; // Start with first root span

    while (currentSpan) {
      path.push(currentSpan.operationName);
      
      // Find child span with longest duration
      const childSpans = spans.filter(s => s.parentSpanId === currentSpan.spanId);
      if (childSpans.length === 0) break;

      currentSpan = childSpans.reduce((longest, current) => 
        (current.durationMs || 0) > (longest.durationMs || 0) ? current : longest
      );
    }

    return path;
  }

  // Performance monitoring
  async getTraceMetrics(businessId: string, timeRange: { start: number; end: number }): Promise<{
    totalTraces: number;
    averageDuration: number;
    errorRate: number;
    p95Duration: number;
    p99Duration: number;
  }> {
    const result = await this.db.prepare(`
      SELECT 
        COUNT(*) as total_traces,
        AVG(duration) as avg_duration,
        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as error_count
      FROM traces 
      WHERE business_id = ? AND start_time >= ? AND start_time <= ?
    `).bind(businessId, timeRange.start, timeRange.end).first();

    const durations = await this.db.prepare(`
      SELECT duration FROM traces 
      WHERE business_id = ? AND start_time >= ? AND start_time <= ?
      ORDER BY duration
    `).bind(businessId, timeRange.start, timeRange.end).all();

    const durationsArray = durations.results.map(row => row.duration);
    const p95Index = Math.floor(durationsArray.length * 0.95);
    const p99Index = Math.floor(durationsArray.length * 0.99);

    return {
      totalTraces: result.total_traces as number,
      averageDuration: (result.avg_duration as number) || 0,
      errorRate: (result.total_traces as number) > 0 ? (result.error_count as number) / (result.total_traces as number) : 0,
      p95Duration: (durationsArray[p95Index] as number) || 0,
      p99Duration: (durationsArray[p99Index] as number) || 0
    };
  }

  // Health check
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    try {
      // Test database connection
      await this.db.prepare('SELECT 1').first();
      
      return {
        status: 'healthy',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      };
    }
  }
}
