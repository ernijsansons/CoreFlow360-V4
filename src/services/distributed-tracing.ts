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

  createTraceHeaders(context: TraceContext): Record<string, string> {
    const headers: Record<string, string> = {
      'traceparent': `00-${context.traceId}-${context.spanId}-${context.flags.toString(16).padStart(2, '0')}`
    };

    if (context.baggage && Object.keys(context.baggage).length > 0) {
      const baggageStr = Object.entries(context.baggage)
        .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
        .join(',');
      headers['baggage'] = baggageStr;
    }

    return headers;
  }

  async startSpan(
    operationName: string,
    options: {
      serviceName: string;
      parentContext?: TraceContext;
      spanKind?: 'client' | 'server' | 'internal' | 'producer' | 'consumer';
      tags?: Record<string, any>;
    }
  ): Promise<Span> {
    const traceId = options.parentContext?.traceId || this.generateTraceId();
    const spanId = this.generateSpanId();
    const parentSpanId = options.parentContext?.spanId;

    const span: Span = {
      spanId,
      traceId,
      parentSpanId,
      serviceName: options.serviceName,
      operationName,
      startTime: new Date(),
      status: 'ok',
      spanKind: options.spanKind || 'internal',
      tags: options.tags || {},
      logs: []
    };

    this.currentSpan = span;

    // If this is a root span, create trace record
    if (!parentSpanId) {
      await this.createTrace(span);
    }

    return span;
  }

  async finishSpan(span: Span): Promise<void> {
    span.endTime = new Date();
    span.durationMs = span.endTime.getTime() - span.startTime.getTime();

    // Persist span
    await this.telemetryCollector.collectSpan(span);

    // Update trace duration if this is a root span
    if (!span.parentSpanId) {
      await this.updateTrace(span.traceId, span.endTime, span.durationMs, span.status);
    }

    if (this.currentSpan?.spanId === span.spanId) {
      this.currentSpan = undefined;
    }
  }

  async addSpanLog(span: Span, fields: Record<string, any>): Promise<void> {
    const logEvent: LogEvent = {
      timestamp: new Date(),
      fields
    };

    span.logs.push(logEvent);
  }

  async setSpanTag(span: Span, key: string, value: any): Promise<void> {
    span.tags[key] = value;
  }

  async setSpanStatus(span: Span, status: 'ok' | 'error' | 'timeout', message?: string): Promise<void> {
    span.status = status;
    span.statusMessage = message;
  }

  private async createTrace(span: Span): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO traces (
        trace_id, business_id, user_id, service_name, operation_name,
        start_time, status, tags
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      span.traceId,
      span.tags.businessId || '',
      span.tags.userId || '',
      span.serviceName,
      span.operationName,
      span.startTime.toISOString(),
      span.status,
      JSON.stringify(span.tags)
    ).run();
  }

  private async updateTrace(traceId: string, endTime: Date, durationMs: number, status: string): Promise<void> {
    const stmt = this.db.prepare(`
      UPDATE traces
      SET end_time = ?, duration_ms = ?, status = ?
      WHERE trace_id = ?
    `);

    await stmt.bind(
      endTime.toISOString(),
      durationMs,
      status,
      traceId
    ).run();
  }

  async getTrace(traceId: string): Promise<Trace | null> {
    // Get trace metadata
    const traceResult = await this.db.prepare(`
      SELECT * FROM traces WHERE trace_id = ?
    `).bind(traceId).first();

    if (!traceResult) return null;

    // Get all spans for this trace
    const spansResult = await this.db.prepare(`
      SELECT * FROM spans WHERE trace_id = ? ORDER BY start_time
    `).bind(traceId).all();

    const spans: Span[] = spansResult.results.map(row => ({
      spanId: row.span_id,
      traceId: row.trace_id,
      parentSpanId: row.parent_span_id,
      serviceName: row.service_name,
      operationName: row.operation_name,
      startTime: new Date(row.start_time),
      endTime: row.end_time ? new Date(row.end_time) : undefined,
      durationMs: row.duration_ms,
      status: row.status,
      statusMessage: row.status_message,
      spanKind: row.span_kind,
      tags: JSON.parse(row.tags || '{}'),
      logs: JSON.parse(row.logs || '[]')
    }));

    return {
      traceId: traceResult.trace_id,
      businessId: traceResult.business_id,
      userId: traceResult.user_id,
      serviceName: traceResult.service_name,
      operationName: traceResult.operation_name,
      startTime: new Date(traceResult.start_time),
      endTime: traceResult.end_time ? new Date(traceResult.end_time) : undefined,
      durationMs: traceResult.duration_ms,
      status: traceResult.status,
      statusMessage: traceResult.status_message,
      tags: JSON.parse(traceResult.tags || '{}'),
      spans
    };
  }

  async searchTraces(options: {
    businessId: string;
    serviceName?: string;
    operationName?: string;
    tags?: Record<string, string>;
    minDuration?: number;
    maxDuration?: number;
    startTime?: Date;
    endTime?: Date;
    limit?: number;
    hasErrors?: boolean;
  }): Promise<Trace[]> {
    let sql = `
      SELECT * FROM traces
      WHERE business_id = ?
    `;
    const params: any[] = [options.businessId];

    if (options.serviceName) {
      sql += ' AND service_name = ?';
      params.push(options.serviceName);
    }

    if (options.operationName) {
      sql += ' AND operation_name = ?';
      params.push(options.operationName);
    }

    if (options.minDuration) {
      sql += ' AND duration_ms >= ?';
      params.push(options.minDuration);
    }

    if (options.maxDuration) {
      sql += ' AND duration_ms <= ?';
      params.push(options.maxDuration);
    }

    if (options.startTime) {
      sql += ' AND start_time >= ?';
      params.push(options.startTime.toISOString());
    }

    if (options.endTime) {
      sql += ' AND start_time <= ?';
      params.push(options.endTime.toISOString());
    }

    if (options.hasErrors) {
      sql += ' AND status = "error"';
    }

    sql += ' ORDER BY start_time DESC';

    if (options.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const result = await this.db.prepare(sql).bind(...params).all();

    // Convert to full Trace objects (without spans for performance)
    return result.results.map(row => ({
      traceId: row.trace_id,
      businessId: row.business_id,
      userId: row.user_id,
      serviceName: row.service_name,
      operationName: row.operation_name,
      startTime: new Date(row.start_time),
      endTime: row.end_time ? new Date(row.end_time) : undefined,
      durationMs: row.duration_ms,
      status: row.status,
      statusMessage: row.status_message,
      tags: JSON.parse(row.tags || '{}'),
      spans: [] // Populated separately when needed
    }));
  }

  async getSpansByParent(traceId: string, parentSpanId?: string): Promise<Span[]> {
    const sql = parentSpanId
      ? 'SELECT * FROM spans WHERE trace_id = ? AND parent_span_id = ?'
      : 'SELECT * FROM spans WHERE trace_id = ? AND parent_span_id IS NULL';

    const params = parentSpanId ? [traceId, parentSpanId] : [traceId];
    const result = await this.db.prepare(sql).bind(...params).all();

    return result.results.map(row => ({
      spanId: row.span_id,
      traceId: row.trace_id,
      parentSpanId: row.parent_span_id,
      serviceName: row.service_name,
      operationName: row.operation_name,
      startTime: new Date(row.start_time),
      endTime: row.end_time ? new Date(row.end_time) : undefined,
      durationMs: row.duration_ms,
      status: row.status,
      statusMessage: row.status_message,
      spanKind: row.span_kind,
      tags: JSON.parse(row.tags || '{}'),
      logs: JSON.parse(row.logs || '[]')
    }));
  }

  async getCriticalPath(traceId: string): Promise<Span[]> {
    const trace = await this.getTrace(traceId);
    if (!trace) return [];

    // Build span hierarchy
    const spanMap = new Map<string, Span>();
    const children = new Map<string, Span[]>();

    for (const span of trace.spans) {
      spanMap.set(span.spanId, span);

      if (span.parentSpanId) {
        if (!children.has(span.parentSpanId)) {
          children.set(span.parentSpanId, []);
        }
        children.get(span.parentSpanId)!.push(span);
      }
    }

    // Find critical path (longest path through the trace)
    const findCriticalPath = (span: Span): Span[] => {
      const childSpans = children.get(span.spanId) || [];
      if (childSpans.length === 0) {
        return [span];
      }

      let longestPath: Span[] = [];
      let maxDuration = 0;

      for (const child of childSpans) {
        const childPath = findCriticalPath(child);
        const pathDuration = childPath.reduce((sum, s) => sum + (s.durationMs || 0), 0);

        if (pathDuration > maxDuration) {
          maxDuration = pathDuration;
          longestPath = childPath;
        }
      }

      return [span, ...longestPath];
    };

    // Find root span
    const rootSpan = trace.spans.find(s => !s.parentSpanId);
    if (!rootSpan) return [];

    return findCriticalPath(rootSpan);
  }

  async detectAnomalies(businessId: string, lookbackHours: number = 24): Promise<any[]> {
    const since = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

    // Detect traces with unusual duration
    const avgDurations = await this.db.prepare(`
      SELECT
        service_name,
        operation_name,
        AVG(duration_ms) as avg_duration,
        STDDEV(duration_ms) as stddev_duration
      FROM traces
      WHERE business_id = ?
        AND start_time >= ?
        AND duration_ms IS NOT NULL
      GROUP BY service_name, operation_name
      HAVING COUNT(*) >= 10
    `).bind(businessId, since.toISOString()).all();

    const anomalies = [];

    for (const baseline of avgDurations.results) {
      // Find recent traces that exceed 3 standard deviations
      const threshold = baseline.avg_duration + (3 * baseline.stddev_duration);

      const anomalousTraces = await this.db.prepare(`
        SELECT * FROM traces
        WHERE business_id = ?
          AND service_name = ?
          AND operation_name = ?
          AND start_time >= ?
          AND duration_ms > ?
        ORDER BY duration_ms DESC
        LIMIT 10
      `).bind(
        businessId,
        baseline.service_name,
        baseline.operation_name,
        since.toISOString(),
        threshold
      ).all();

      for (const trace of anomalousTraces.results) {
        anomalies.push({
          type: 'slow_trace',
          traceId: trace.trace_id,
          serviceName: trace.service_name,
          operationName: trace.operation_name,
          duration: trace.duration_ms,
          expectedDuration: baseline.avg_duration,
          severity: trace.duration_ms > threshold * 2 ? 'high' : 'medium',
          timestamp: trace.start_time
        });
      }
    }

    // Detect error patterns
    const errorTraces = await this.db.prepare(`
      SELECT
        service_name,
        operation_name,
        COUNT(*) as error_count,
        MAX(start_time) as latest_error
      FROM traces
      WHERE business_id = ?
        AND start_time >= ?
        AND status = 'error'
      GROUP BY service_name, operation_name
      HAVING error_count >= 5
      ORDER BY error_count DESC
    `).bind(businessId, since.toISOString()).all();

    for (const errorPattern of errorTraces.results) {
      anomalies.push({
        type: 'error_pattern',
        serviceName: errorPattern.service_name,
        operationName: errorPattern.operation_name,
        errorCount: errorPattern.error_count,
        latestError: errorPattern.latest_error,
        severity: errorPattern.error_count > 20 ? 'high' : 'medium'
      });
    }

    return anomalies;
  }

  async generateFlameGraph(traceId: string): Promise<any> {
    const trace = await this.getTrace(traceId);
    if (!trace) return null;

    // Convert spans to flame graph format
    const flamegraph = {
      name: `${trace.serviceName}:${trace.operationName}`,
      value: trace.durationMs || 0,
      children: []
    };

    const spanMap = new Map<string, any>();
    const rootNodes: any[] = [];

    // Create nodes for each span
    for (const span of trace.spans) {
      const node = {
        name: `${span.serviceName}:${span.operationName}`,
        value: span.durationMs || 0,
        spanId: span.spanId,
        children: [],
        tags: span.tags,
        status: span.status
      };

      spanMap.set(span.spanId, node);

      if (!span.parentSpanId) {
        rootNodes.push(node);
      }
    }

    // Build hierarchy
    for (const span of trace.spans) {
      if (span.parentSpanId) {
        const parent = spanMap.get(span.parentSpanId);
        const child = spanMap.get(span.spanId);
        if (parent && child) {
          parent.children.push(child);
        }
      }
    }

    // If multiple root nodes, create a virtual root
    if (rootNodes.length === 1) {
      return rootNodes[0];
    } else {
      return {
        name: 'Root',
        value: trace.durationMs || 0,
        children: rootNodes
      };
    }
  }

  async exportTraceToJaeger(traceId: string): Promise<any> {
    const trace = await this.getTrace(traceId);
    if (!trace) return null;

    // Convert to Jaeger format
    return {
      traceID: traceId,
      spans: trace.spans.map(span => ({
        traceID: span.traceId,
        spanID: span.spanId,
        parentSpanID: span.parentSpanId || '',
        operationName: span.operationName,
        startTime: span.startTime.getTime() * 1000, // microseconds
        duration: (span.durationMs || 0) * 1000, // microseconds
        tags: Object.entries(span.tags).map(([key, value]) => ({
          key,
          type: typeof value === 'string' ? 'string' : 'number',
          value: String(value)
        })),
        logs: span.logs.map(log => ({
          timestamp: log.timestamp.getTime() * 1000,
          fields: Object.entries(log.fields).map(([key, value]) => ({
            key,
            value: String(value)
          }))
        })),
        process: {
          serviceName: span.serviceName,
          tags: []
        }
      })),
      processes: {
        [trace.serviceName]: {
          serviceName: trace.serviceName,
          tags: []
        }
      }
    };
  }

  // Middleware for automatic span creation
  createTracingMiddleware() {
    return async (request: Request, env: any, ctx: ExecutionContext) => {
      const traceContext = this.parseTraceContext(request.headers);
      const span = await this.startSpan(
        `${request.method} ${new URL(request.url).pathname}`,
        {
          serviceName: 'coreflow360',
          parentContext: traceContext,
          spanKind: 'server',
          tags: {
            'http.method': request.method,
            'http.url': request.url,
            'http.scheme': new URL(request.url).protocol.slice(0, -1),
            'http.host': new URL(request.url).hostname,
            'http.target': new URL(request.url).pathname + new URL(request.url).search
          }
        }
      );

      try {
        // Continue with request processing
        const response = await ctx.next();

        await this.setSpanTag(span, 'http.status_code', response.status);
        await this.setSpanStatus(
          span,
          response.status >= 400 ? 'error' : 'ok',
          response.status >= 400 ? `HTTP ${response.status}` : undefined
        );

        return response;

      } catch (error) {
        await this.setSpanStatus(span, 'error', error instanceof Error ? error.message : 'Unknown error');
        await this.addSpanLog(span, {
          level: 'error',
          message: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });

        throw error;

      } finally {
        await this.finishSpan(span);
      }
    };
  }
}