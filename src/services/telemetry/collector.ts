import { LogEntry, Span, Metric, AnalyticsData, ClickhouseEvent, Alert } from '../../types/telemetry';

export class TelemetryCollector {
  private env: any;
  private clickhouseEndpoint: string;
  private alertRules: Map<string, any> = new Map();

  constructor(env: any) {
    this.env = env;
    this.clickhouseEndpoint = env.CLICKHOUSE_ENDPOINT || '';
  }

  async collect(entry: LogEntry): Promise<void> {
    try {
      await Promise.all([
        this.writeToAnalyticsEngine(entry),
        this.streamToClickhouse(entry),
        this.checkAlertRules(entry)
      ]);
    } catch (error: any) {
    }
  }

  private async writeToAnalyticsEngine(entry: LogEntry): Promise<void> {
    if (!this.env.ANALYTICS) return;

    const dataPoint = {
      blobs: [
        entry.traceId,
        entry.businessId,
        entry.module,
        entry.capability,
        entry.method,
        entry.path,
        entry.aiModel || '',
        entry.aiProvider || ''
      ],
      doubles: [
        entry.latencyMs,
        entry.aiCostCents || 0,
        entry.promptTokens || 0,
        entry.completionTokens || 0,
        entry.statusCode,
        entry.cpuMs || 0,
        entry.memoryMB || 0,
        entry.ioOps || 0
      ],
      indexes: [entry.userId, entry.sessionId, entry.requestId]
    };

    await this.env.ANALYTICS.writeDataPoint(dataPoint);
  }

  private async streamToClickhouse(entry: LogEntry): Promise<void> {
    if (!this.clickhouseEndpoint) return;

    const event: ClickhouseEvent = {
      event_time: entry.timestamp,
      business_id: entry.businessId,
      user_id: entry.userId,
      session_id: entry.sessionId,
      trace_id: entry.traceId,
      span_id: entry.spanId,
      event_type: 'log',
      event_name: `${entry.module}.${entry.capability}`,
      properties: JSON.stringify({
        method: entry.method,
        path: entry.path,
        statusCode: entry.statusCode,
        aiModel: entry.aiModel,
        aiProvider: entry.aiProvider,
        workflowId: entry.workflowId,
        documentId: entry.documentId,
        error: entry.error,
        metadata: entry.metadata
      }),
      metrics: JSON.stringify({
        latencyMs: entry.latencyMs,
        aiCostCents: entry.aiCostCents,
        promptTokens: entry.promptTokens,
        completionTokens: entry.completionTokens,
        cpuMs: entry.cpuMs,
        memoryMB: entry.memoryMB,
        ioOps: entry.ioOps,
        cacheHit: entry.cacheHit
      })
    };

    await fetch(this.clickhouseEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.env.CLICKHOUSE_TOKEN}`
      },
      body: JSON.stringify(event)
    });
  }

  async collectSpan(span: Span): Promise<void> {
    if (!this.env.ANALYTICS) return;

    const dataPoint = {
      blobs: [span.traceId, span.spanId, span.operationName],
      doubles: [span.duration || 0, span.startTime, span.endTime || 0],
      indexes: [span.parentSpanId || '', span.status]
    };

    await this.env.ANALYTICS.writeDataPoint(dataPoint);

    if (this.clickhouseEndpoint) {
      const event: ClickhouseEvent = {
        event_time: new Date(span.startTime).toISOString(),
        business_id: span.tags.businessId || '',
        user_id: span.tags.userId || '',
        session_id: span.tags.sessionId || '',
        trace_id: span.traceId,
        span_id: span.spanId,
        event_type: 'span',
        event_name: span.operationName,
        properties: JSON.stringify(span.tags),
        metrics: JSON.stringify({
          duration: span.duration,
          startTime: span.startTime,
          endTime: span.endTime
        })
      };

      await fetch(this.clickhouseEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.env.CLICKHOUSE_TOKEN}`
        },
        body: JSON.stringify(event)
      });
    }
  }

  async collectMetric(metric: Metric): Promise<void> {
    if (!this.env.ANALYTICS) return;

    const dataPoint = {
      blobs: [metric.name, metric.type, ...Object.values(metric.tags)],
      doubles: [metric.value, metric.timestamp],
      indexes: Object.keys(metric.tags)
    };

    await this.env.ANALYTICS.writeDataPoint(dataPoint);
  }

  async collectBatch(entries: LogEntry[]): Promise<void> {
    if (!this.env.ANALYTICS || entries.length === 0) return;

    const batchSize = 1000;
    for (let i = 0; i < entries.length; i += batchSize) {
      const batch = entries.slice(i, i + batchSize);
      await Promise.all(batch.map((entry: any) => this.collect(entry)));
    }
  }

  private async checkAlertRules(entry: LogEntry): Promise<void> {
    for (const [ruleId, rule] of this.alertRules) {
      if (await this.evaluateRule(rule, entry)) {
        const alert: Alert = {
          id: crypto.randomUUID(),
          name: rule.name,
          severity: rule.severity,
          status: 'firing',
          message: this.formatAlertMessage(rule, entry),
          timestamp: Date.now(),
          source: 'telemetry-collector',
          metadata: { ruleId, entry: entry.requestId },
          channels: rule.channels,
          escalationLevel: 0,
          correlatedAlerts: []
        };

        await this.triggerAlert(alert);
      }
    }
  }

  private async evaluateRule(rule: any, entry: LogEntry): Promise<boolean> {
    try {
      switch (rule.condition) {
        case 'latency_threshold':
          return entry.latencyMs > rule.threshold;
        case 'error_rate':
          return entry.statusCode >= 400;
        case 'ai_cost_threshold':
          return (entry.aiCostCents || 0) > rule.threshold;
        case 'custom':
          return this.evaluateCustomCondition(rule.expression, entry);
        default:
          return false;
      }
    } catch (error: any) {
      return false;
    }
  }

  private evaluateCustomCondition(expression: string, entry: LogEntry): boolean {
    try {
      const context = {
        latency: entry.latencyMs,
        status: entry.statusCode,
        cost: entry.aiCostCents || 0,
        tokens: (entry.promptTokens || 0) + (entry.completionTokens || 0),
        cpu: entry.cpuMs || 0,
        memory: entry.memoryMB || 0,
        module: entry.module,
        capability: entry.capability
      };

      const func = new Function('context', `with(context) { return ${expression}; }`);
      return func(context);
    } catch (error: any) {
      return false;
    }
  }

  private formatAlertMessage(rule: any, entry: LogEntry): string {
    return `Alert: ${rule.name} triggered for ${entry.module}.${entry.capability} - ${rule.description}`;
  }

  private async triggerAlert(alert: Alert): Promise<void> {
    if (this.env.ALERT_WEBHOOK) {
      await fetch(this.env.ALERT_WEBHOOK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert)
      });
    }
  }

  async query(sql: string): Promise<any[]> {
    if (!this.clickhouseEndpoint) return [];

    const response = await fetch(`${this.clickhouseEndpoint}/query`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/sql',
        'Authorization': `Bearer ${this.env.CLICKHOUSE_TOKEN}`
      },
      body: sql
    });

    return response.json();
  }

  async getMetrics(businessId: string, timeRange: { start: string; end: string }): Promise<AnalyticsData[]> {
    const sql = `
      SELECT
        toUnixTimestamp(event_time) * 1000 as timestamp,
        business_id,
        JSONExtract(metrics, 'latencyMs', 'Float64') as latency,
        JSONExtract(metrics, 'aiCostCents', 'Float64') as cost,
        JSONExtract(properties, 'statusCode', 'UInt16') as status_code,
        COUNT(*) as request_count
      FROM telemetry_events
      WHERE business_id = '${businessId}'
        AND event_time BETWEEN '${timeRange.start}' AND '${timeRange.end}'
      GROUP BY timestamp, business_id, latency, cost, status_code
      ORDER BY timestamp
    `;

    const results = await this.query(sql);
    return results.map((row: any) => ({
      timestamp: row.timestamp,
      businessId: row.business_id,
      metrics: {
        golden: {
          latency: {
            p50: row.latency,
            p95: row.latency,
            p99: row.latency,
            p999: row.latency
          },
          traffic: {
            requestsPerSecond: row.request_count,
            bytesPerSecond: 0
          },
          errors: {
            errorRate: row.status_code >= 400 ? 1 : 0,
            errorCount: row.status_code >= 400 ? row.request_count : 0
          },
          saturation: {
            cpuUsage: 0,
            memoryUsage: 0,
            diskUsage: 0
          }
        },
        business: {
          revenue: 0,
          activeUsers: 0,
          featureUsage: {},
          conversionRate: 0,
          churnRate: 0,
          customerSatisfaction: 0
        },
        ai: {
          totalTokens: 0,
          promptTokens: 0,
          completionTokens: 0,
          costCents: row.cost,
          requestCount: row.request_count,
          averageLatency: row.latency,
          errorRate: row.status_code >= 400 ? 1 : 0,
          model: '',
          provider: ''
        },
        infrastructure: {
          cpuUsagePercent: 0,
          memoryUsagePercent: 0,
          diskUsagePercent: 0,
          networkInBytes: 0,
          networkOutBytes: 0,
          activeConnections: 0,
          requestsPerSecond: row.request_count
        }
      },
      dimensions: {}
    }));
  }

  async addAlertRule(rule: any): Promise<void> {
    this.alertRules.set(rule.id, rule);
  }

  async removeAlertRule(ruleId: string): Promise<void> {
    this.alertRules.delete(ruleId);
  }

  async flush(): Promise<void> {
    // Flush any pending data
  }
}