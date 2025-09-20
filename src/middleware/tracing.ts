import { Context, Next } from 'hono';

export interface TraceContext {
  requestId: string;
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  businessId?: string;
  userId?: string;
  startTime: number;
}

/**
 * Request tracing middleware
 */
export async function tracingMiddleware(c: Context, next: Next) {
  // Generate or extract trace IDs
  const traceHeader = c.req.header('X-Trace-Id');
  const requestId = c.req.header('X-Request-Id') || crypto.randomUUID();
  const traceId = traceHeader || crypto.randomUUID();
  const spanId = crypto.randomUUID().substring(0, 16);
  const parentSpanId = c.req.header('X-Parent-Span-Id');

  // Set trace context
  const traceContext: TraceContext = {
    requestId,
    traceId,
    spanId,
    parentSpanId,
    startTime: Date.now(),
  };

  c.set('requestId', requestId);
  c.set('traceId', traceId);
  c.set('spanId', spanId);
  c.set('startTime', traceContext.startTime);
  c.set('traceContext', traceContext);

  // Add trace headers to response
  c.header('X-Request-Id', requestId);
  c.header('X-Trace-Id', traceId);
  c.header('X-Span-Id', spanId);

  try {
    await next();
  } finally {
    // Log request completion
    const duration = Date.now() - traceContext.startTime;
    c.header('X-Response-Time', `${duration}ms`);

    // Log to analytics if available
    if (c.env?.ANALYTICS) {
      c.env.ANALYTICS.writeDataPoint({
        blobs: [
          c.req.method,
          c.req.url,
          c.res.status.toString(),
          duration.toString(),
        ],
        doubles: [duration, c.res.status],
        indexes: [requestId],
      });
    }
  }
}

/**
 * Performance monitoring middleware
 */
export async function performanceMiddleware(c: Context, next: Next) {
  const marks: Record<string, number> = {};

  // Mark request start
  marks.requestStart = performance.now();

  // Override execute to track database timing
  const originalPrepare = c.env?.DB_MAIN?.prepare;
  if (originalPrepare) {
    c.env.DB_MAIN.prepare = function(...args: any[]) {
      const statement = originalPrepare.apply(this, args);
      const originalRun = statement.run;
      const originalFirst = statement.first;
      const originalAll = statement.all;

      statement.run = async function(...runArgs: any[]) {
        const start = performance.now();
        const result = await originalRun.apply(this, runArgs);
        marks.dbTime = (marks.dbTime || 0) + (performance.now() - start);
        marks.dbQueries = (marks.dbQueries || 0) + 1;
        return result;
      };

      statement.first = async function(...firstArgs: any[]) {
        const start = performance.now();
        const result = await originalFirst.apply(this, firstArgs);
        marks.dbTime = (marks.dbTime || 0) + (performance.now() - start);
        marks.dbQueries = (marks.dbQueries || 0) + 1;
        return result;
      };

      statement.all = async function(...allArgs: any[]) {
        const start = performance.now();
        const result = await originalAll.apply(this, allArgs);
        marks.dbTime = (marks.dbTime || 0) + (performance.now() - start);
        marks.dbQueries = (marks.dbQueries || 0) + 1;
        return result;
      };

      return statement;
    };
  }

  await next();

  // Calculate timings
  marks.requestEnd = performance.now();
  marks.totalTime = marks.requestEnd - marks.requestStart;

  // Add performance headers
  c.header('Server-Timing', Object.entries(marks)
    .filter(([key]) => key.includes('Time') || key.includes('Queries'))
    .map(([key, value]) => `${key};dur=${value}`)
    .join(', '));

  // Restore original prepare
  if (originalPrepare && c.env?.DB_MAIN) {
    c.env.DB_MAIN.prepare = originalPrepare;
  }
}