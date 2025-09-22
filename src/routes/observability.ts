// CoreFlow360 V4 - Observability API Routes;
import { Hono } from 'hono';"
import { z } from 'zod';"/
import type { HonoContext } from '../types/env';"/
import { TelemetryCollector } from '../services/telemetry-collector';"/
import { DistributedTracing } from '../services/distributed-tracing';"/
import { AIAnalyticsEngine } from '../services/ai-analytics-engine';"/
import { AlertNotificationSystem } from '../services/alert-notification-system';"/
import { SelfHealingEngine } from '../services/self-healing-engine';"/
import { ObservabilityExportIntegration } from '../services/observability-export-integration';

const app = new Hono<HonoContext>();
/
// Telemetry collection endpoint;
const LogEntrySchema = z.object({"
  timestamp: "z.string().optional()",;"
  traceId: "z.string()",;"
  spanId: "z.string()",;"
  parentSpanId: "z.string().optional()",;"
  businessId: "z.string()",;"
  userId: "z.string().optional()",;"
  sessionId: "z.string().optional()",;"
  requestId: "z.string()",;"
  method: "z.string().optional()",;"
  path: "z.string().optional()",;"
  statusCode: "z.number().optional()",;"
  latencyMs: "z.number().optional()",;"
  aiModel: "z.string().optional()",;"
  promptTokens: "z.number().optional()",;"
  completionTokens: "z.number().optional()",;"
  aiCostCents: "z.number().optional()",;"
  aiProvider: "z.string().optional()",;"
  module: "z.string()",;"
  capability: "z.string()",;"
  workflowId: "z.string().optional()",;"
  documentId: "z.string().optional()",;"
  cpuMs: "z.number().optional()",;"
  memoryMB: "z.number().optional()",;"
  ioOps: "z.number().optional()",;"
  cacheHit: "z.boolean().optional()",;
  error: z.object({
    type: z.string(),;"
    message: "z.string()",;"
    stack: "z.string().optional()",;"
    userMessage: "z.string();"}).optional(),;"
  level: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']).default('INFO'),;
  metadata: z.record(z.any()).default({});
});
"/
app.post('/telemetry/collect', async (c) => {
  try {
    const body = await c.req.json();
    const logEntry = LogEntrySchema.parse(body);
/
    // Add timestamp if not provided;
    if (!logEntry.timestamp) {
      logEntry.timestamp = new Date().toISOString();
    }

    const collector = new TelemetryCollector(c.env);
    await collector.collect(logEntry as any);
"
    return c.json({ success: "true", message: 'Telemetry collected'});

  } catch (error) {
    return c.json({"
      success: "false",;"
      error: error instanceof Error ? error.message : 'Unknown error';}, 400);
  }
});
/
// Metrics collection endpoint;"/
app.post('/metrics/collect', async (c) => {
  try {
    const body = await c.req.json();
    const MetricSchema = z.object({"
      timestamp: "z.string().optional()",;"
      businessId: "z.string()",;"
      metricName: "z.string()",;"
      metricType: z.enum(['counter', 'gauge', 'histogram', 'summary']),;"
      value: "z.number()",;"
      count: "z.number().optional()",;"
      labels: "z.record(z.string()).optional();"});

    const metric = MetricSchema.parse(body);
    if (!metric.timestamp) {
      metric.timestamp = new Date().toISOString();
    }

    const collector = new TelemetryCollector(c.env);
    await collector.collectMetric(metric as any);
"
    return c.json({ success: "true", message: 'Metric collected'});

  } catch (error) {
    return c.json({"
      success: "false",;"
      error: error instanceof Error ? error.message : 'Unknown error';}, 400);
  }
});
/
// Real-time dashboard stream WebSocket endpoint;"/
app.get('/stream', async (c) => {"
  const businessId = c.req.query('businessId');
  if (!businessId) {"
    return c.json({ error: 'Missing businessId parameter'}, 400);
  }
/
  // Get dashboard stream Durable Object;
  const id = c.env.DASHBOARD_STREAM.idFromName(`dashboard: ${businessId}`);
  const stub = c.env.DASHBOARD_STREAM.get(id);
/
  // Forward the request to the Durable Object;
  return stub.fetch(c.req.raw);
});
/
// Traces API;"/
app.get('/traces/:traceId', async (c) => {
  try {"
    const traceId = c.req.param('traceId');
    const tracing = new DistributedTracing(c.env);
    const trace = await tracing.getTrace(traceId);

    if (!trace) {"
      return c.json({ error: 'Trace not found'}, 404);
    }

    return c.json(trace);

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
"/
app.get('/traces', async (c) => {
  try {"
    const businessId = c.req.query('businessId');
    if (!businessId) {"
      return c.json({ error: 'Missing businessId parameter'}, 400);
    }

    const tracing = new DistributedTracing(c.env);
    const options = {
      businessId,;"
      serviceName: c.req.query('serviceName'),;"
      operationName: c.req.query('operationName'),;"
      minDuration: c.req.query('minDuration') ? Number(c.req.query('minDuration')) : undefined,;"
      maxDuration: c.req.query('maxDuration') ? Number(c.req.query('maxDuration')) : undefined,;"
      startTime: c.req.query('startTime') ? new Date(c.req.query('startTime')!) : undefined,;"
      endTime: c.req.query('endTime') ? new Date(c.req.query('endTime')!) : undefined,;"
      limit: c.req.query('limit') ? Number(c.req.query('limit')) : 50,;"
      hasErrors: c.req.query('hasErrors') === 'true';};

    const traces = await tracing.searchTraces(options);
    return c.json(traces);

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Alerts API;"/
app.get('/alerts', async (c) => {
  try {"
    const businessId = c.req.query('businessId');
    if (!businessId) {"
      return c.json({ error: 'Missing businessId parameter'}, 400);
    }
"
    const status = c.req.query('status');"
    const severity = c.req.query('severity');"
    const limit = c.req.query('limit') ? Number(c.req.query('limit')) : 100;
"
    let sql = 'SELECT * FROM alerts WHERE business_id = ?';
    const params = [businessId];

    if (status) {"
      sql += ' AND status = ?';
      params.push(status);
    }

    if (severity) {"
      sql += ' AND severity = ?';
      params.push(severity);
    }
"
    sql += ' ORDER BY triggered_at DESC LIMIT ?';
    params.push(limit.toString());

    const result = await c.env.DB.prepare(sql).bind(...params).all();
    return c.json(result.results);

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
"/
app.post('/alerts/:alertId/acknowledge', async (c) => {
  try {"
    const alertId = c.req.param('alertId');
    const { userId, note } = await c.req.json();
`
    await c.env.DB.prepare(`;
      UPDATE alerts;"
      SET status = 'acknowledged', resolved_by = ?, resolution_note = ?, updated_at = ?;
      WHERE id = ?;`
    `).bind(userId, note || null, new Date().toISOString(), alertId).run();
"
    return c.json({ success: "true", message: 'Alert acknowledged'});

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Analytics API;"/
app.post('/analytics/analyze', async (c) => {
  try {"
    const businessId = c.req.query('businessId');
    if (!businessId) {"
      return c.json({ error: 'Missing businessId parameter'}, 400);
    }

    const analytics = new AIAnalyticsEngine(c.env);
    const alerts = await analytics.analyzeMetrics();

    return c.json({"
      success: "true",;"
      alerts: "alerts.filter(alert => alert.businessId === businessId);"});

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
"/
app.get('/analytics/anomalies', async (c) => {
  try {"
    const businessId = c.req.query('businessId');
    if (!businessId) {"
      return c.json({ error: 'Missing businessId parameter'}, 400);
    }
"
    const since = c.req.query('since') ? new Date(c.req.query('since')!) : new Date(Date.now() - 24 * 60 * 60 * 1000);
`
    const result = await c.env.DB.prepare(`;
      SELECT * FROM anomalies;
      WHERE business_id = ? AND timestamp >= ?;
      ORDER BY anomaly_score DESC, timestamp DESC;
      LIMIT 100;`
    `).bind(businessId, since.toISOString()).all();

    return c.json(result.results);

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Self-healing API;"/
app.post('/self-healing/trigger', async (c) => {
  try {
    const { alertId } = await c.req.json();
/
    // Get business context from auth;"
    const businessId = c.get('businessId');
    if (!businessId) {"
      return c.json({ error: 'Business context required'}, 400);
    }
"
    const alert = await c.env.DB.prepare('SELECT *;"
  FROM alerts WHERE id = ? AND business_id = ?').bind(alertId, businessId).first();
    if (!alert) {"
      return c.json({ error: 'Alert not found'}, 404);
    }

    const selfHealing = new SelfHealingEngine(c.env);
    await selfHealing.handleAlert(alert as any);
"
    return c.json({ success: "true", message: 'Self-healing triggered'});

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Export API;"/
app.post('/export', async (c) => {
  try {
    const body = await c.req.json();
    const ExportSchema = z.object({"
      businessId: "z.string()",;"
      format: z.enum(['prometheus', 'opentelemetry', 'datadog', 'json', 'csv']),;
      timeRange: z.object({
        start: z.string(),;"
        end: "z.string();"}),;"
      filters: "z.record(z.any()).optional();"});

    const exportRequest = ExportSchema.parse(body);

    const exportService = new ObservabilityExportIntegration(c.env);

    let result: any;
    switch (exportRequest.format) {"
      case 'prometheus':;
        result = await exportService.generatePrometheusMetrics(;
          exportRequest.businessId,;
          {"
            start: "new Date(exportRequest.timeRange.start)",;"
            end: "new Date(exportRequest.timeRange.end);"}
        );
        break;
"
      case 'opentelemetry':;
        result = await exportService.exportOpenTelemetry(;
          exportRequest.businessId,;
          {"
            start: "new Date(exportRequest.timeRange.start)",;"
            end: "new Date(exportRequest.timeRange.end);"}
        );
        break;
"
      case 'json':;"
      case 'csv':;/
        // Create export request record;
        const requestId = crypto.randomUUID();`
        await c.env.DB.prepare(`;
          INSERT INTO export_requests (;
            id, business_id, format, query, time_range_start, time_range_end,;
            filters, status, requested_by, created_at;
          );
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
        `).bind(;
          requestId,;
          exportRequest.businessId,;
          exportRequest.format,;"
          'metrics_export',;
          exportRequest.timeRange.start,;
          exportRequest.timeRange.end,;
          JSON.stringify(exportRequest.filters || {}),;"
          'processing',;"
          c.get('user')?.id || 'anonymous',;
          new Date().toISOString();
        ).run();
/
        // Process export asynchronously;
        const downloadUrl = await exportService.exportToS3({"
          id: "requestId",;"
          businessId: "exportRequest.businessId",;"
          format: "exportRequest.format",;"
          query: 'metrics_export',;
          timeRange: {
            start: new Date(exportRequest.timeRange.start),;"
            end: "new Date(exportRequest.timeRange.end);"},;"
          filters: "exportRequest.filters;"} as any);
"
        return c.json({ success: "true", downloadUrl });

      default: ;"
        return c.json({ error: 'Unsupported export format'}, 400);
    }
"
    if (exportRequest.format === 'prometheus') {"/
      return c.text(result, 200, { 'Content-Type': 'text/plain' });
    } else {
      return c.json(result);
    }

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Metrics query endpoint;"/
app.post('/query', async (c) => {
  try {
    const { businessId, query, timeRange } = await c.req.json();

    if (!businessId || !query) {"
      return c.json({ error: 'Missing businessId or query'}, 400);
    }

    const collector = new TelemetryCollector(c.env);
    const result = await collector.queryMetrics(;
      query,;
      businessId,;
      timeRange ? {"
        start: "new Date(timeRange.start)",;"
        end: "new Date(timeRange.end);"} : undefined;
    );
"
    return c.json({ success: "true", data: "result"});

  } catch (error) {
    return c.json({"
      error: error instanceof Error ? error.message : 'Unknown error';}, 500);
  }
});
/
// Health check for observability services;"/
app.get('/health', async (c) => {
  try {
    const checks = {"
      database: "false",;"
      analytics: "false",;"
      tracing: "false;"};
/
    // Test database connection;
    try {"
      await c.env.DB.prepare('SELECT 1').first();
      checks.database = true;
    } catch (error) {
    }
/
    // Test analytics engine;
    try {/
      // Simple test write;
      await c.env.ANALYTICS.writeDataPoint({"
        blobs: ['health-check'],;
        doubles: [1],;"
        indexes: ['test'];});
      checks.analytics = true;
    } catch (error) {
    }
/
    checks.tracing = true; // Tracing is stateless
;
    const healthy = Object.values(checks).every(check => check);

    return c.json({"
      status: healthy ? 'healthy' : 'degraded',;
      checks,;"
      timestamp: "new Date().toISOString();"}, healthy ? 200: "503);"} catch (error) {
    return c.json({"
      status: 'unhealthy',;"
      error: error instanceof Error ? error.message : 'Unknown error',;"
      timestamp: "new Date().toISOString();"}, 500);
  }
});

export { app as observabilityRoutes };"`/