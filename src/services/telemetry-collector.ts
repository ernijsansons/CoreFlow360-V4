// CoreFlow360 V4 - Telemetry Collector Service
import {
  LogEntry,
  MetricPoint,
  TraceContext,
  Span,
  AnalyticsEnginePoint,
  CostTrackingEntry,
  ServicePerformance
} from '../types/observability';
import { getAIClient } from './ai-client';

export class TelemetryCollector {
  private env: any;
  private db: D1Database;
  private analyticsEngine: AnalyticsEngineDataset;

  constructor(env: any) {
    this.env = env;
    this.db = env.DB;
    this.analyticsEngine = env.ANALYTICS;
  }

  async collect(entry: LogEntry): Promise<void> {
    try {
      // Write to D1 for persistence and complex queries
      await this.persistLogEntry(entry);

      // Write to Analytics Engine for real-time metrics
      await this.writeToAnalyticsEngine(entry);

      // Stream to ClickHouse for complex analytics (if configured)
      if (this.env.CLICKHOUSE_ENDPOINT) {
        await this.streamToClickhouse(entry);
      }

      // Check alert rules
      await this.checkAlertRules(entry);

      // Update cost tracking if AI-related
      if (entry.aiCostCents && entry.aiCostCents > 0) {
        await this.trackCost(entry);
      }

    } catch (error: any) {
      // Don't throw - telemetry failures shouldn't break the main flow
    }
  }

  private async persistLogEntry(entry: LogEntry): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO log_entries (
        timestamp, trace_id, span_id, parent_span_id, business_id, user_id, session_id,
        request_id, method, path, status_code, latency_ms,
        ai_model, prompt_tokens, completion_tokens, ai_cost_cents, ai_provider,
        module, capability, workflow_id, document_id,
        cpu_ms, memory_mb, io_ops, cache_hit,
        error_type, error_message, error_stack, error_user_message,
        level, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      entry.timestamp,
      entry.traceId,
      entry.spanId,
      entry.parentSpanId,
      entry.businessId,
      entry.userId,
      entry.sessionId,
      entry.requestId,
      entry.method,
      entry.path,
      entry.statusCode,
      entry.latencyMs,
      entry.aiModel,
      entry.promptTokens,
      entry.completionTokens,
      entry.aiCostCents,
      entry.aiProvider,
      entry.module,
      entry.capability,
      entry.workflowId,
      entry.documentId,
      entry.cpuMs,
      entry.memoryMB,
      entry.ioOps,
      entry.cacheHit,
      entry.error?.type,
      entry.error?.message,
      entry.error?.stack,
      entry.error?.userMessage,
      entry.level,
      JSON.stringify(entry.metadata)
    ).run();
  }

  private async writeToAnalyticsEngine(entry: LogEntry): Promise<void> {
    const point: AnalyticsEnginePoint = {
      blobs: [
        entry.traceId,
        entry.businessId,
        entry.module,
        entry.capability,
        entry.level,
        entry.aiProvider || '',
        entry.aiModel || ''
      ],
      doubles: [
        entry.latencyMs || 0,
        entry.aiCostCents || 0,
        entry.statusCode || 0,
        entry.cpuMs || 0,
        entry.memoryMB || 0,
        entry.promptTokens || 0,
        entry.completionTokens || 0
      ],
      indexes: [
        entry.userId || '',
        entry.sessionId || '',
        entry.requestId,
        entry.workflowId || '',
        entry.error?.type || ''
      ]
    };

    await this.analyticsEngine.writeDataPoint(point);
  }

  private async streamToClickhouse(entry: LogEntry): Promise<void> {
    const clickhouseData = {
      timestamp: entry.timestamp,
      trace_id: entry.traceId,
      span_id: entry.spanId,
      business_id: entry.businessId,
      user_id: entry.userId || '',
      module: entry.module,
      capability: entry.capability,
      latency_ms: entry.latencyMs || 0,
      status_code: entry.statusCode || 0,
      error_type: entry.error?.type || '',
      ai_cost_cents: entry.aiCostCents || 0,
      metadata: JSON.stringify(entry.metadata)
    };

    await fetch(this.env.CLICKHOUSE_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.env.CLICKHOUSE_TOKEN}`
      },
      body: JSON.stringify(clickhouseData)
    });
  }

  async collectMetric(metric: MetricPoint): Promise<void> {
    try {
      // Persist to D1
      await this.persistMetric(metric);

      // Write to Analytics Engine
      await this.writeMetricToAnalyticsEngine(metric);

      // Update aggregations
      await this.updateMetricAggregations(metric);

    } catch (error: any) {
    }
  }

  private async persistMetric(metric: MetricPoint): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO metrics (timestamp, business_id, metric_name, metric_type, value, count, labels)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      metric.timestamp,
      metric.businessId,
      metric.metricName,
      metric.metricType,
      metric.value,
      metric.count || 1,
      JSON.stringify(metric.labels || {})
    ).run();
  }

  private async writeMetricToAnalyticsEngine(metric: MetricPoint): Promise<void> {
    const point: AnalyticsEnginePoint = {
      blobs: [
        metric.businessId,
        metric.metricName,
        metric.metricType,
        JSON.stringify(metric.labels || {})
      ],
      doubles: [
        metric.value,
        metric.count || 1
      ],
      indexes: [
        metric.businessId,
        metric.metricName
      ]
    };

    await this.analyticsEngine.writeDataPoint(point);
  }

  private async updateMetricAggregations(metric: MetricPoint): Promise<void> {
    const periods = ['1m', '5m', '15m', '1h', '6h', '1d'];

    for (const period of periods) {
      await this.updateAggregationForPeriod(metric, period);
    }
  }

  private async updateAggregationForPeriod(metric: MetricPoint, period: string): Promise<void> {
    const bucketTimestamp = this.getBucketTimestamp(new Date(metric.timestamp), period);
    const labelsHash = this.hashLabels(metric.labels || {});

    // Use UPSERT to update existing aggregation or create new one
    const stmt = this.db.prepare(`
      INSERT INTO metric_aggregations (
        timestamp, business_id, metric_name, aggregation_period,
        count, sum, min, max, avg, labels_hash, labels
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(timestamp, business_id, metric_name, aggregation_period, labels_hash)
      DO UPDATE SET
        count = count + excluded.count,
        sum = sum + excluded.sum,
        min = MIN(min, excluded.min),
        max = MAX(max, excluded.max),
        avg = (sum + excluded.sum) / (count + excluded.count)
    `);

    await stmt.bind(
      bucketTimestamp.toISOString(),
      metric.businessId,
      metric.metricName,
      period,
      metric.count || 1,
      metric.value,
      metric.value,
      metric.value,
      metric.value,
      labelsHash,
      JSON.stringify(metric.labels || {})
    ).run();
  }

  private getBucketTimestamp(timestamp: Date, period: string): Date {
    const periodMs = {
      '1m': 60 * 1000,
      '5m': 5 * 60 * 1000,
      '15m': 15 * 60 * 1000,
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '1d': 24 * 60 * 60 * 1000
    };

    const ms = periodMs[period as keyof typeof periodMs];
    return new Date(Math.floor(timestamp.getTime() / ms) * ms);
  }

  private hashLabels(labels: Record<string, string>): string {
    const sorted = Object.keys(labels).sort().map((key: any) => `${key}=${labels[key]}`).join(',');
    return btoa(sorted).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }

  async collectSpan(span: Span): Promise<void> {
    try {
      // Persist span to D1
      await this.persistSpan(span);

      // Create log entry for the span
      const logEntry: LogEntry = {
        timestamp: span.startTime.toISOString(),
        traceId: span.traceId,
        spanId: span.spanId,
        parentSpanId: span.parentSpanId,
        businessId: '', // Will be set by caller
        requestId: span.tags.requestId || '',
        module: span.tags.module || span.serviceName,
        capability: span.operationName,
        latencyMs: span.durationMs,
        level: span.status === 'error' ? 'ERROR' : 'INFO',
        metadata: span.tags
      };

      await this.collect(logEntry);

    } catch (error: any) {
    }
  }

  private async persistSpan(span: Span): Promise<void> {
    const stmt = this.db.prepare(`
      INSERT INTO spans (
        span_id, trace_id, parent_span_id, service_name, operation_name,
        start_time, end_time, duration_ms, status, status_message,
        span_kind, tags, logs
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      span.spanId,
      span.traceId,
      span.parentSpanId,
      span.serviceName,
      span.operationName,
      span.startTime.toISOString(),
      span.endTime?.toISOString(),
      span.durationMs,
      span.status,
      span.statusMessage,
      span.spanKind,
      JSON.stringify(span.tags),
      JSON.stringify(span.logs)
    ).run();
  }

  private async trackCost(entry: LogEntry): Promise<void> {
    const costEntry: Partial<CostTrackingEntry> = {
      timestamp: new Date(entry.timestamp),
      businessId: entry.businessId,
      userId: entry.userId,
      workflowId: entry.workflowId,
      documentId: entry.documentId,
      module: entry.module,
      capability: entry.capability,
      aiProvider: entry.aiProvider,
      aiModel: entry.aiModel,
      promptTokens: entry.promptTokens,
      completionTokens: entry.completionTokens,
      costCents: entry.aiCostCents || 0,
      requestId: entry.requestId,
      traceId: entry.traceId,
      metadata: entry.metadata
    };

    const stmt = this.db.prepare(`
      INSERT INTO cost_tracking (
        timestamp, business_id, user_id, workflow_id, document_id,
        module, capability, ai_provider, ai_model,
        prompt_tokens, completion_tokens, cost_cents,
        request_id, trace_id, metadata
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    await stmt.bind(
      costEntry.timestamp?.toISOString(),
      costEntry.businessId,
      costEntry.userId,
      costEntry.workflowId,
      costEntry.documentId,
      costEntry.module,
      costEntry.capability,
      costEntry.aiProvider,
      costEntry.aiModel,
      costEntry.promptTokens,
      costEntry.completionTokens,
      costEntry.costCents,
      costEntry.requestId,
      costEntry.traceId,
      JSON.stringify(costEntry.metadata || {})
    ).run();
  }

  private async checkAlertRules(entry: LogEntry): Promise<void> {
    // Get active alert rules for this business
    const rules = await this.db.prepare(`
      SELECT * FROM alert_rules
      WHERE business_id = ? AND enabled = true
    `).bind(entry.businessId).all();

    for (const rule of rules.results) {
      await this.evaluateAlertRule(rule, entry);
    }
  }

  private async evaluateAlertRule(rule: any, entry: LogEntry): Promise<void> {
    try {
      // Simple threshold-based alerting
      const condition = JSON.parse(rule.condition);
      let shouldAlert = false;

      switch (condition.metric) {
        case 'latency':
          if (entry.latencyMs && rule.threshold_value) {
            shouldAlert = this.evaluateThreshold(
              entry.latencyMs,
              rule.threshold_operator,
              rule.threshold_value
            );
          }
          break;
        case 'error_rate':
          if (entry.statusCode && entry.statusCode >= 400) {
            shouldAlert = true;
          }
          break;
        case 'ai_cost':
          if (entry.aiCostCents && rule.threshold_value) {
            shouldAlert = this.evaluateThreshold(
              entry.aiCostCents,
              rule.threshold_operator,
              rule.threshold_value
            );
          }
          break;
      }

      if (shouldAlert) {
        await this.createAlert(rule, entry);
      }

    } catch (error: any) {
    }
  }

  private evaluateThreshold(value: number, operator: string, threshold: number): boolean {
    switch (operator) {
      case 'gt': return value > threshold;
      case 'gte': return value >= threshold;
      case 'lt': return value < threshold;
      case 'lte': return value <= threshold;
      case 'eq': return value === threshold;
      case 'ne': return value !== threshold;
      default: return false;
    }
  }

  private async createAlert(rule: any, entry: LogEntry): Promise<void> {
    const fingerprint = this.generateAlertFingerprint(rule, entry);

    // Check if alert already exists and is firing
    const existingAlert = await this.db.prepare(`
      SELECT id FROM alerts
      WHERE fingerprint = ? AND status = 'firing'
    `).bind(fingerprint).first();

    if (existingAlert) {
      return; // Alert already exists
    }

    const alertId = crypto.randomUUID();

    await this.db.prepare(`
      INSERT INTO alerts (
        id, rule_id, business_id, title, description, severity, status,
        triggered_at, metric_value, threshold_value, labels, annotations, fingerprint
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      alertId,
      rule.id,
      entry.businessId,
      rule.name,
      rule.description,
      rule.severity,
      'firing',
      entry.timestamp,
      entry.latencyMs || entry.aiCostCents || 0,
      rule.threshold_value,
      JSON.stringify({ module: entry.module, capability: entry.capability }),
      JSON.stringify({ traceId: entry.traceId, requestId: entry.requestId }),
      fingerprint
    ).run();

    // Send notifications
    if (rule.notification_channels) {
      const channels = JSON.parse(rule.notification_channels);
      for (const channelId of channels) {
        await this.sendAlertNotification(alertId, channelId);
      }
    }
  }

  private generateAlertFingerprint(rule: any, entry: LogEntry): string {
    const data = `${rule.id}:${entry.module}:${entry.capability}`;
    return btoa(data).replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
  }

  private async sendAlertNotification(alertId: string, channelId: string): Promise<void> {
    // This will be implemented in the alert system
  }

  async collectServicePerformance(businessId: string, serviceName: string): Promise<void> {
    // Aggregate performance metrics for the last minute
    const oneMinuteAgo = new Date(Date.now() - 60000).toISOString();
    const now = new Date().toISOString();

    const metrics = await this.db.prepare(`
      SELECT
        COUNT(*) as request_count,
        COUNT(CASE WHEN status_code >= 400 THEN 1 END) as error_count,
        AVG(latency_ms) as avg_latency_ms,
        MIN(latency_ms) as min_latency_ms,
        MAX(latency_ms) as max_latency_ms,
        AVG(cpu_ms) as avg_cpu_ms,
        AVG(memory_mb) as avg_memory_mb,
        MAX(memory_mb) as max_memory_mb
      FROM log_entries
      WHERE business_id = ?
        AND module = ?
        AND timestamp BETWEEN ? AND ?
    `).bind(businessId, serviceName, oneMinuteAgo, now).first();

    if (metrics && (metrics as any).request_count > 0) {
      const perf: Partial<ServicePerformance> = {
        timestamp: new Date(),
        businessId,
        serviceName,
        requestCount: (metrics as any).request_count,
        errorCount: (metrics as any).error_count,
        avgLatencyMs: (metrics as any).avg_latency_ms,
        avgCpuPercent: (metrics as any).avg_cpu_ms ? (metrics as any).avg_cpu_ms / 10 : undefined, // Convert to percentage
        avgMemoryMB: (metrics as any).avg_memory_mb,
        maxMemoryMB: (metrics as any).max_memory_mb,
        windowStart: new Date(oneMinuteAgo),
        windowEnd: new Date(now)
      };

      await this.db.prepare(`
        INSERT INTO service_performance (
          timestamp, business_id, service_name, request_count, error_count,
          avg_latency_ms, avg_cpu_percent, avg_memory_mb, max_memory_mb,
          window_start, window_end
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        perf.timestamp?.toISOString(),
        perf.businessId,
        perf.serviceName,
        perf.requestCount,
        perf.errorCount,
        perf.avgLatencyMs,
        perf.avgCpuPercent,
        perf.avgMemoryMB,
        perf.maxMemoryMB,
        perf.windowStart?.toISOString(),
        perf.windowEnd?.toISOString()
      ).run();
    }
  }

  async queryMetrics(query: string, businessId: string, timeRange?: { start: Date; end: Date }): Promise<any[]> {
    // Simple query interface - in production this would be more sophisticated
    let sql = query;
    const params = [businessId];

    if (timeRange) {
      sql += ' AND timestamp BETWEEN ? AND ?';
      params.push(timeRange.start.toISOString(), timeRange.end.toISOString());
    }

    const result = await this.db.prepare(sql).bind(...params).all();
    return result.results;
  }

  async exportMetrics(format: 'prometheus' | 'json' | 'csv', businessId:
  string, timeRange: { start: Date; end: Date }): Promise<string> {
    const metrics = await this.queryMetrics(`
      SELECT metric_name, value, labels, timestamp
      FROM metrics
      WHERE business_id = ?
    `, businessId, timeRange);

    switch (format) {
      case 'prometheus':
        return this.formatPrometheus(metrics);
      case 'json':
        return JSON.stringify(metrics, null, 2);
      case 'csv':
        return this.formatCSV(metrics);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  private formatPrometheus(metrics: any[]): string {
    const lines: string[] = [];

    for (const metric of metrics) {
      const labels = JSON.parse(metric.labels || '{}');
      const labelStr = Object.entries(labels)
        .map(([k, v]) => `${k}="${v}"`)
        .join(',');

      lines.push(`${metric.metric_name}{${labelStr}} ${metric.value} ${new Date(metric.timestamp).getTime()}`);
    }

    return lines.join('\n');
  }

  private formatCSV(metrics: any[]): string {
    const headers = ['metric_name', 'value', 'labels', 'timestamp'];
    const rows = metrics.map((m: any) => [
      m.metric_name,
      m.value,
      m.labels,
      m.timestamp
    ]);

    return [headers, ...rows].map((row: any) => row.join(',')).join('\n');
  }
}