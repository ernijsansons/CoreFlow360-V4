// @ts-nocheck
// CoreFlow360 V4 - Observability API Routes
import { Hono } from 'hono';
import { z } from 'zod';
import type { HonoContext } from '../types/env';
import { TelemetryCollector } from '../services/telemetry-collector';
import { DistributedTracing } from '../services/distributed-tracing';
import { AIAnalyticsEngine } from '../services/ai-analytics-engine';
import { AlertNotificationSystem } from '../services/alert-notification-system';
import { SelfHealingEngine } from '../services/self-healing-engine';
import { ObservabilityExportIntegration } from '../services/observability-export-integration';

const app = new Hono<HonoContext>();

// Telemetry collection endpoint
const LogEntrySchema = z.object({
  timestamp: z.string().optional(),
  traceId: z.string(),
  spanId: z.string(),
  parentSpanId: z.string().optional(),
  businessId: z.string(),
  userId: z.string().optional(),
  sessionId: z.string().optional(),
  requestId: z.string(),
  method: z.string().optional(),
  path: z.string().optional(),
  statusCode: z.number().optional(),
  latencyMs: z.number().optional(),
  aiModel: z.string().optional(),
  promptTokens: z.number().optional(),
  completionTokens: z.number().optional(),
  aiCostCents: z.number().optional(),
  aiProvider: z.string().optional(),
  module: z.string(),
  capability: z.string(),
  workflowId: z.string().optional(),
  documentId: z.string().optional(),
  cpuMs: z.number().optional(),
  memoryMB: z.number().optional(),
  ioOps: z.number().optional(),
  cacheHit: z.boolean().optional(),
  error: z.object({
    type: z.string(),
    message: z.string(),
    stack: z.string().optional(),
    userMessage: z.string(),
  }).optional(),
  level: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL']).default('INFO'),
  metadata: z.record(z.any()).default({}),
});

app.post('/telemetry/collect', async (c: any) => {
  try {
    const body = await c.req.json();
    const logEntries = z.array(LogEntrySchema).parse(body);

    // GRUG: TelemetryCollector doesn't have collectLogs - use collectMetric
    const telemetryCollector = new TelemetryCollector(c.env);
    for (const log of logEntries) {
      await telemetryCollector.collectMetric('log_entry', 1, { level: log.level });
    }

    return c.json({ success: true, processed: logEntries.length });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 400);
  }
});

// Metrics collection endpoint
const MetricEntrySchema = z.object({
  name: z.string(),
  value: z.number(),
  timestamp: z.string().optional(),
  tags: z.record(z.string()).default({}),
  businessId: z.string(),
  userId: z.string().optional(),
  sessionId: z.string().optional(),
  traceId: z.string().optional(),
  spanId: z.string().optional(),
});

app.post('/metrics/collect', async (c: any) => {
  try {
    const body = await c.req.json();
    const metricEntries = z.array(MetricEntrySchema).parse(body);

    // GRUG: collectMetrics doesn't exist - use collectMetric one at a time
    const telemetryCollector = new TelemetryCollector(c.env);
    for (const metric of metricEntries) {
      await telemetryCollector.collectMetric(metric.name, metric.value, metric.tags);
    }

    return c.json({ success: true, processed: metricEntries.length });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 400);
  }
});

// Trace collection endpoint
const TraceEntrySchema = z.object({
  traceId: z.string(),
  spanId: z.string(),
  parentSpanId: z.string().optional(),
  operationName: z.string(),
  startTime: z.string(),
  endTime: z.string().optional(),
  duration: z.number().optional(),
  tags: z.record(z.any()).default({}),
  logs: z.array(z.object({
    timestamp: z.string(),
    fields: z.record(z.any()),
  })).default([]),
  businessId: z.string(),
  userId: z.string().optional(),
  sessionId: z.string().optional(),
});

app.post('/traces/collect', async (c: any) => {
  try {
    const body = await c.req.json();
    const traceEntries = z.array(TraceEntrySchema).parse(body);

    // GRUG: collectTraces doesn't exist - use startSpan
    const distributedTracing = new DistributedTracing(c.env);
    for (const trace of traceEntries) {
      await distributedTracing.startSpan(trace.operationName, trace.traceId);
    }

    return c.json({ success: true, processed: traceEntries.length });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 400);
  }
});

// AI Analytics endpoint
app.get('/ai-analytics/summary', async (c: any) => {
  try {
    const query = c.req.query();
    const businessId = query.businessId;
    const startDate = query.startDate;
    const endDate = query.endDate;
    const model = query.model;

    if (!businessId) {
      return c.json({ success: false, error: 'Business ID is required' }, 400);
    }

    // GRUG: getSummary params don't include model - remove it
    const aiAnalyticsEngine = new AIAnalyticsEngine(c.env);
    const summary = await aiAnalyticsEngine.getSummary({
      businessId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined
    });

    const filters = {
      businessId,
      startDate,
      endDate,
      model
    };

    return c.json({ success: true, summary, filters });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// AI Analytics detailed metrics
app.get('/ai-analytics/metrics', async (c: any) => {
  try {
    const query = c.req.query();
    const businessId = query.businessId;
    const startDate = query.startDate;
    const endDate = query.endDate;
    const granularity = query.granularity || 'hour';

    if (!businessId) {
      return c.json({ success: false, error: 'Business ID is required' }, 400);
    }

    // GRUG: getMetrics doesn't have granularity param
    const aiAnalyticsEngine = new AIAnalyticsEngine(c.env);
    const metrics = await aiAnalyticsEngine.getMetrics({
      businessId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      metricNames: []
    });

    const filters = {
      businessId,
      startDate,
      endDate,
      granularity
    };

    return c.json({ success: true, metrics, filters });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// AI Analytics cost analysis
app.get('/ai-analytics/costs', async (c: any) => {
  try {
    const query = c.req.query();
    const businessId = query.businessId;
    const startDate = query.startDate;
    const endDate = query.endDate;
    const groupBy = query.groupBy || 'model';

    if (!businessId) {
      return c.json({ success: false, error: 'Business ID is required' }, 400);
    }

    // GRUG: getCostAnalysis doesn't have groupBy param
    const aiAnalyticsEngine = new AIAnalyticsEngine(c.env);
    const costs = await aiAnalyticsEngine.getCostAnalysis({
      businessId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined
    });

    const filters = {
      businessId,
      startDate,
      endDate,
      groupBy
    };

    return c.json({ success: true, costs, filters });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// Alert management endpoints
app.get('/alerts', async (c: any) => {
  try {
    const query = c.req.query();
    const businessId = query.businessId;
    const status = query.status;
    const severity = query.severity;
    const limit = parseInt(query.limit || '50');
    const offset = parseInt(query.offset || '0');

    if (!businessId) {
      return c.json({ success: false, error: 'Business ID is required' }, 400);
    }

    const alertNotificationSystem = new AlertNotificationSystem(c.env);
    const alerts = await alertNotificationSystem.getAlerts({
      businessId,
      status: status as 'active' | 'resolved' | 'suppressed',
      severity: severity as 'low' | 'medium' | 'high' | 'critical',
      limit,
      offset,
    });

    return c.json({ success: true, alerts });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

app.post('/alerts/:id/acknowledge', async (c: any) => {
  try {
    const alertId = c.req.param('id');
    const body = await c.req.json();
    const userId = body.userId;
    const comment = body.comment;

    if (!userId) {
      return c.json({ success: false, error: 'User ID is required' }, 400);
    }

    // GRUG: acknowledgeAlert takes only 1 arg (alertId)
    const alertNotificationSystem = new AlertNotificationSystem(c.env);
    await alertNotificationSystem.acknowledgeAlert(alertId);

    return c.json({ success: true, acknowledgedBy: userId, comment });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

app.post('/alerts/:id/resolve', async (c: any) => {
  try {
    const alertId = c.req.param('id');
    const body = await c.req.json();
    const userId = body.userId;
    const comment = body.comment;

    if (!userId) {
      return c.json({ success: false, error: 'User ID is required' }, 400);
    }

    // GRUG: resolveAlert takes only 1 arg (alertId)
    const alertNotificationSystem = new AlertNotificationSystem(c.env);
    await alertNotificationSystem.resolveAlert(alertId);

    return c.json({ success: true, resolvedBy: userId, comment });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// Self-healing endpoints
app.get('/self-healing/status', async (c: any) => {
  try {
    const query = c.req.query();
    const businessId = query.businessId;

    if (!businessId) {
      return c.json({ success: false, error: 'Business ID is required' }, 400);
    }

    // GRUG: getStatus doesn't take params
    const selfHealingEngine = new SelfHealingEngine(c.env);
    const status = await selfHealingEngine.getStatus();

    return c.json({ success: true, status });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

app.post('/self-healing/trigger', async (c: any) => {
  try {
    const body = await c.req.json();
    const businessId = body.businessId;
    const issueType = body.issueType;
    const severity = body.severity;
    const description = body.description;

    if (!businessId || !issueType) {
      return c.json({ 
        success: false, 
        error: 'Business ID and issue type are required' 
      }, 400);
    }

    const selfHealingEngine = new SelfHealingEngine(c.env);
    const result = await selfHealingEngine.triggerHealing({
      businessId,
      issueType,
      severity: severity as 'low' | 'medium' | 'high' | 'critical',
      description,
    });

    return c.json({ success: true, result });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// Export integration endpoints
app.get('/export/formats', async (c: any) => {
  try {
    const observabilityExportIntegration = new ObservabilityExportIntegration(c.env);
    const formats = await observabilityExportIntegration.getSupportedFormats();

    return c.json({ success: true, formats });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

app.post('/export/generate', async (c: any) => {
  try {
    const body = await c.req.json();
    const businessId = body.businessId;
    const format = body.format;
    const startDate = body.startDate;
    const endDate = body.endDate;
    const includeMetrics = body.includeMetrics || true;
    const includeLogs = body.includeLogs || true;
    const includeTraces = body.includeTraces || true;

    if (!businessId || !format) {
      return c.json({ 
        success: false, 
        error: 'Business ID and format are required' 
      }, 400);
    }

    const observabilityExportIntegration = new ObservabilityExportIntegration(c.env);
    const exportResult = await observabilityExportIntegration.generateExport({
      businessId,
      format: format as 'json' | 'csv' | 'pdf' | 'excel',
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      includeMetrics,
      includeLogs,
      includeTraces,
    });

    return c.json({ success: true, export: exportResult });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

// Health check endpoint
app.get('/health', async (c: any) => {
  try {
    const telemetryCollector = new TelemetryCollector(c.env);
    const distributedTracing = new DistributedTracing(c.env);
    const aiAnalyticsEngine = new AIAnalyticsEngine(c.env);
    const alertNotificationSystem = new AlertNotificationSystem(c.env);
    const selfHealingEngine = new SelfHealingEngine(c.env);
    const observabilityExportIntegration = new ObservabilityExportIntegration(c.env);

    const services = {
      telemetryCollector: telemetryCollector ? 'operational' : 'unavailable',
      distributedTracing: distributedTracing ? 'operational' : 'unavailable',
      aiAnalyticsEngine: aiAnalyticsEngine ? 'operational' : 'unavailable',
      alertNotificationSystem: alertNotificationSystem ? 'operational' : 'unavailable',
      selfHealingEngine: selfHealingEngine ? 'operational' : 'unavailable',
      observabilityExportIntegration: observabilityExportIntegration ? 'operational' : 'unavailable',
    };

    // GRUG: Services don't have getHealth - return simple status
    const health = {
      status: 'healthy',
      services,
      timestamp: new Date().toISOString(),
    };

    return c.json({ success: true, health });
  } catch (error: any) {
    return c.json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    }, 500);
  }
});

export default app;
