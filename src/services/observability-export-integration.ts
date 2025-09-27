// CoreFlow360 V4 - Observability Export and Integration System
import { ExportRequest, MetricAggregation, LogEntry, Trace } from '../types/observability';

export class ObservabilityExportIntegration {
  private env: any;
  private db: D1Database;

  constructor(env: any) {
    this.env = env;
    this.db = env.DB;
  }

  // =============================================
  // PROMETHEUS METRICS ENDPOINT
  // =============================================

  async generatePrometheusMetrics(businessId: string, timeRange?: { start: Date; end: Date }): Promise<string> {
    const metrics = await this.getMetricsForExport(businessId, timeRange);
    return this.formatAsPrometheus(metrics);
  }

  private formatAsPrometheus(metrics: any[]): string {
    const lines: string[] = [];
    const metricGroups = new Map<string, any[]>();

    // Group metrics by name
    for (const metric of metrics) {
      if (!metricGroups.has(metric.metric_name)) {
        metricGroups.set(metric.metric_name, []);
      }
      metricGroups.get(metric.metric_name)!.push(metric);
    }

    // Format each metric group
    for (const [metricName, metricData] of metricGroups) {
      // Add HELP and TYPE comments
      lines.push(`# HELP ${metricName} ${this.getMetricDescription(metricName)}`);
      lines.push(`# TYPE ${metricName} ${this.getPrometheusType(metricData[0])}`);

      // Add metric samples
      for (const metric of metricData) {
        const labels = this.parseLabels(metric.labels);
        const labelStr = Object.entries(labels)
          .map(([k, v]) => `${k}="${v}"`)
          .join(',');

        const timestamp = new Date(metric.timestamp).getTime();
        lines.push(`${metricName}{${labelStr}} ${metric.value} ${timestamp}`);
      }

      lines.push(''); // Empty line between metrics
    }

    return lines.join('\n');
  }

  private getPrometheusType(metric: any): string {
    const metricType = metric.metric_type || 'gauge';
    switch (metricType) {
      case 'counter': return 'counter';
      case 'gauge': return 'gauge';
      case 'histogram': return 'histogram';
      case 'summary': return 'summary';
      default: return 'gauge';
    }
  }

  private getMetricDescription(metricName: string): string {
    const descriptions: Record<string, string> = {
      'latency': 'Request latency in milliseconds',
      'error_rate': 'Error rate percentage',
      'traffic': 'Request traffic rate',
      'cpu_usage': 'CPU usage percentage',
      'memory_usage': 'Memory usage in MB',
      'ai_cost': 'AI operation cost in cents',
      'request_count': 'Total number of requests'
    };
    return descriptions[metricName] || `CoreFlow360 metric: ${metricName}`;
  }

  // =============================================
  // OPENTELEMETRY EXPORT
  // =============================================

  async exportOpenTelemetry(businessId: string, timeRange: { start: Date; end: Date }): Promise<any> {
    const [traces, metrics, logs] = await Promise.all([
      this.getTracesForExport(businessId, timeRange),
      this.getMetricsForExport(businessId, timeRange),
      this.getLogsForExport(businessId, timeRange)
    ]);

    return {
      resourceSpans: this.formatTracesAsOTel(traces),
      resourceMetrics: this.formatMetricsAsOTel(metrics),
      resourceLogs: this.formatLogsAsOTel(logs)
    };
  }

  private formatTracesAsOTel(traces: any[]): any[] {
    const resourceSpans: any[] = [];
    const serviceGroups = new Map<string, any[]>();

    // Group traces by service
    for (const trace of traces) {
      const serviceName = trace.service_name || 'unknown';
      if (!serviceGroups.has(serviceName)) {
        serviceGroups.set(serviceName, []);
      }
      serviceGroups.get(serviceName)!.push(trace);
    }

    // Format each service group
    for (const [serviceName, serviceTraces] of serviceGroups) {
      resourceSpans.push({
        resource: {
          attributes: [
            { key: 'service.name', value: { stringValue: serviceName } },
            { key: 'service.version', value: { stringValue: '1.0.0' } }
          ]
        },
        scopeSpans: [{
          scope: {
            name: 'CoreFlow360',
            version: '4.0.0'
          },
          spans: serviceTraces.map((trace: any) => ({
            traceId: trace.trace_id,
            spanId: this.generateSpanId(),
            parentSpanId: undefined,
            name: trace.operation_name,
            kind: 'SPAN_KIND_SERVER',
            startTimeUnixNano: new Date(trace.start_time).getTime() * 1000000,
            endTimeUnixNano: trace.end_time ? new Date(trace.end_time).getTime() * 1000000 : undefined,
            attributes: Object.entries(this.parseLabels(trace.tags)).map(([key, value]) => ({
              key,
              value: { stringValue: String(value) }
            })),
            status: {
              code: trace.status === 'ok' ? 'STATUS_CODE_OK' : 'STATUS_CODE_ERROR',
              message: trace.status_message || ''
            }
          }))
        }]
      });
    }

    return resourceSpans;
  }

  private formatMetricsAsOTel(metrics: any[]): any[] {
    const resourceMetrics: any[] = [];
    const metricGroups = new Map<string, any[]>();

    // Group metrics by name
    for (const metric of metrics) {
      if (!metricGroups.has(metric.metric_name)) {
        metricGroups.set(metric.metric_name, []);
      }
      metricGroups.get(metric.metric_name)!.push(metric);
    }

    resourceMetrics.push({
      resource: {
        attributes: [
          { key: 'service.name', value: { stringValue: 'CoreFlow360' } }
        ]
      },
      scopeMetrics: [{
        scope: {
          name: 'CoreFlow360',
          version: '4.0.0'
        },
        metrics: Array.from(metricGroups.entries()).map(([metricName, metricData]) => ({
          name: metricName,
          description: this.getMetricDescription(metricName),
          unit: this.getMetricUnit(metricName),
          gauge: {
            dataPoints: metricData.map((metric: any) => ({
              attributes: Object.entries(this.parseLabels(metric.labels)).map(([key, value]) => ({
                key,
                value: { stringValue: String(value) }
              })),
              timeUnixNano: new Date(metric.timestamp).getTime() * 1000000,
              asDouble: metric.value
            }))
          }
        }))
      }]
    });

    return resourceMetrics;
  }

  private formatLogsAsOTel(logs: any[]): any[] {
    return [{
      resource: {
        attributes: [
          { key: 'service.name', value: { stringValue: 'CoreFlow360' } }
        ]
      },
      scopeLogs: [{
        scope: {
          name: 'CoreFlow360',
          version: '4.0.0'
        },
        logRecords: logs.map((log: any) => ({
          timeUnixNano: new Date(log.timestamp).getTime() * 1000000,
          severityNumber: this.getSeverityNumber(log.level),
          severityText: log.level,
          body: { stringValue: log.error_message || 'Log entry' },
          attributes: [
            { key: 'trace.id', value: { stringValue: log.trace_id } },
            { key: 'span.id', value: { stringValue: log.span_id } },
            { key: 'module', value: { stringValue: log.module } },
            { key: 'capability', value: { stringValue: log.capability } }
          ],
          traceId: log.trace_id,
          spanId: log.span_id
        }))
      }]
    }];
  }

  // =============================================
  // DATADOG INTEGRATION
  // =============================================

  async exportToDatadog(businessId: string, timeRange: { start: Date; end: Date }): Promise<void> {
    const [metrics, logs] = await Promise.all([
      this.getMetricsForExport(businessId, timeRange),
      this.getLogsForExport(businessId, timeRange)
    ]);

    // Send metrics to Datadog
    await this.sendDatadogMetrics(metrics);

    // Send logs to Datadog
    await this.sendDatadogLogs(logs);
  }

  private async sendDatadogMetrics(metrics: any[]): Promise<void> {
    const datadogMetrics = metrics.map((metric: any) => ({
      metric: metric.metric_name,
      points: [[new Date(metric.timestamp).getTime() / 1000, metric.value]],
      tags: Object.entries(this.parseLabels(metric.labels)).map(([k, v]) => `${k}:${v}`),
      host: 'coreflow360',
      type: 'gauge'
    }));

    const payload = { series: datadogMetrics };

    await fetch('https://api.datadoghq.com/api/v1/series', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'DD-API-KEY': this.env.DATADOG_API_KEY
      },
      body: JSON.stringify(payload)
    });
  }

  private async sendDatadogLogs(logs: any[]): Promise<void> {
    const datadogLogs = logs.map((log: any) => ({
      timestamp: new Date(log.timestamp).getTime(),
      status: log.level.toLowerCase(),
      message: log.error_message || 'Log entry',
      hostname: 'coreflow360',
      service: log.module,
      tags: `module:${log.module},capability:${log.capability}`,
      ddtags: `trace_id:${log.trace_id}`,
      'trace.id': log.trace_id,
      'span.id': log.span_id
    }));

    await fetch('https://http-intake.logs.datadoghq.com/v1/input/' + this.env.DATADOG_API_KEY, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(datadogLogs)
    });
  }

  // =============================================
  // GRAFANA DATA SOURCE
  // =============================================

  async handleGrafanaQuery(query: any): Promise<any> {
    const { targets, range } = query;
    const results = [];

    for (const target of targets) {
      const data = await this.executeGrafanaTarget(target, range);
      results.push(data);
    }

    return results;
  }

  private async executeGrafanaTarget(target: any, range: any): Promise<any> {
    const { expr, refId } = target;

    // Parse PromQL-like expression
    const metricName = this.parseMetricFromExpression(expr);
    const filters = this.parseFiltersFromExpression(expr);

    // Get data from database
    const startTime = new Date(range.from);
    const endTime = new Date(range.to);

    const metrics = await this.db.prepare(`
      SELECT timestamp, value, labels
      FROM metrics
      WHERE metric_name = ?
        AND timestamp BETWEEN ? AND ?
      ORDER BY timestamp
    `).bind(metricName, startTime.toISOString(), endTime.toISOString()).all();

    // Format for Grafana
    const datapoints = metrics.results.map((metric: any) => [
      metric.value,
      new Date(metric.timestamp).getTime()
    ]);

    return {
      target: expr,
      refId,
      datapoints
    };
  }

  // =============================================
  // BIGQUERY STREAMING
  // =============================================

  async streamToBigQuery(businessId: string): Promise<void> {
    // Get recent data to stream
    const since = new Date(Date.now() - 5 * 60 * 1000); // Last 5 minutes

    const [metrics, logs, traces] = await Promise.all([
      this.getMetricsForExport(businessId, { start: since, end: new Date() }),
      this.getLogsForExport(businessId, { start: since, end: new Date() }),
      this.getTracesForExport(businessId, { start: since, end: new Date() })
    ]);

    // Stream to BigQuery using the REST API
    await Promise.all([
      this.streamMetricsToBigQuery(metrics),
      this.streamLogsToBigQuery(logs),
      this.streamTracesToBigQuery(traces)
    ]);
  }

  private async streamMetricsToBigQuery(metrics: any[]): Promise<void> {
    if (metrics.length === 0) return;

    const rows = metrics.map((metric: any) => ({
      json: {
        timestamp: metric.timestamp,
        business_id: metric.business_id,
        metric_name: metric.metric_name,
        metric_type: metric.metric_type,
        value: metric.value,
        labels: JSON.stringify(metric.labels)
      }
    }));

    await this.insertToBigQuery('metrics', rows);
  }

  private async streamLogsToBigQuery(logs: any[]): Promise<void> {
    if (logs.length === 0) return;

    const rows = logs.map((log: any) => ({
      json: {
        timestamp: log.timestamp,
        business_id: log.business_id,
        trace_id: log.trace_id,
        span_id: log.span_id,
        level: log.level,
        module: log.module,
        capability: log.capability,
        message: log.error_message,
        metadata: JSON.stringify(log.metadata)
      }
    }));

    await this.insertToBigQuery('logs', rows);
  }

  private async streamTracesToBigQuery(traces: any[]): Promise<void> {
    if (traces.length === 0) return;

    const rows = traces.map((trace: any) => ({
      json: {
        trace_id: trace.trace_id,
        business_id: trace.business_id,
        service_name: trace.service_name,
        operation_name: trace.operation_name,
        start_time: trace.start_time,
        end_time: trace.end_time,
        duration_ms: trace.duration_ms,
        status: trace.status
      }
    }));

    await this.insertToBigQuery('traces', rows);
  }

  private async insertToBigQuery(tableName: string, rows: any[]): Promise<void> {
    const projectId = this.env.BIGQUERY_PROJECT_ID;
    const datasetId = this.env.BIGQUERY_DATASET_ID;

    const response = await fetch(
      `https://bigquery.googleapis.com/bigquery/v2/projects/${projectId}/datasets/${datasetId}/tables/${tableName}/insertAll`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.BIGQUERY_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ rows })
      }
    );

    if (!response.ok) {
      throw new Error(`BigQuery insert failed: ${response.statusText}`);
    }
  }

  // =============================================
  // S3/R2 BATCH EXPORTS
  // =============================================

  async exportToS3(request: ExportRequest): Promise<string> {
    const data = await this.generateExportData(request);
    const fileName = this.generateExportFileName(request);

    // Upload to S3/R2
    const uploadResponse = await fetch(`${this.env.R2_ENDPOINT}/${this.env.R2_BUCKET}/${fileName}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${this.env.R2_TOKEN}`,
        'Content-Type': this.getContentType(request.format)
      },
      body: data
    });

    if (!uploadResponse.ok) {
      throw new Error(`Failed to upload to R2: ${uploadResponse.statusText}`);
    }

    // Generate download URL
    const downloadUrl = `${this.env.R2_PUBLIC_URL}/${fileName}`;

    // Update export request status
    await this.db.prepare(`
      UPDATE export_requests
      SET status = 'completed', download_url = ?, completed_at = ?
      WHERE id = ?
    `).bind(downloadUrl, new Date().toISOString(), request.id).run();

    return downloadUrl;
  }

  // =============================================
  // COMPLIANCE REPORTING
  // =============================================

  async generateComplianceReport(businessId: string, reportType: string, period:
  { start: Date; end: Date }): Promise<any> {
    switch (reportType) {
      case 'audit_trail':
        return await this.generateAuditTrailReport(businessId, period);
      case 'sla_compliance':
        return await this.generateSLAComplianceReport(businessId, period);
      case 'cost_allocation':
        return await this.generateCostAllocationReport(businessId, period);
      case 'security_incidents':
        return await this.generateSecurityIncidentReport(businessId, period);
      default:
        throw new Error(`Unsupported report type: ${reportType}`);
    }
  }

  private async generateAuditTrailReport(businessId: string, period: { start: Date; end: Date }): Promise<any> {
    const auditLogs = await this.db.prepare(`
      SELECT * FROM audit_log
      WHERE business_id = ?
        AND timestamp BETWEEN ? AND ?
      ORDER BY timestamp DESC
    `).bind(businessId, period.start.toISOString(), period.end.toISOString()).all();

    return {
      reportType: 'audit_trail',
      businessId,
      period,
      generatedAt: new Date(),
      summary: {
        totalEvents: auditLogs.results.length,
        successfulEvents: auditLogs.results.filter((log: any) => log.success).length,
        failedEvents: auditLogs.results.filter((log: any) => !log.success).length
      },
      events: auditLogs.results
    };
  }

  private async generateSLAComplianceReport(businessId: string, period: { start: Date; end: Date }): Promise<any> {
    const serviceMetrics = await this.db.prepare(`
      SELECT
        service_name,
        AVG(avg_latency_ms) as avg_latency,
        AVG((error_count * 100.0) / request_count) as error_rate,
        SUM(request_count) as total_requests
      FROM service_performance
      WHERE business_id = ?
        AND timestamp BETWEEN ? AND ?
      GROUP BY service_name
    `).bind(businessId, period.start.toISOString(), period.end.toISOString()).all();

    const slaTargets = {
      latency: 1000, // 1 second
      errorRate: 1.0, // 1%
      availability: 99.9 // 99.9%
    };

    const compliance = serviceMetrics.results.map((service: any) => ({
      serviceName: service.service_name,
      latencyCompliance: service.avg_latency <= slaTargets.latency,
      errorRateCompliance: service.error_rate <= slaTargets.errorRate,
      metrics: {
        avgLatency: service.avg_latency,
        errorRate: service.error_rate,
        totalRequests: service.total_requests
      }
    }));

    return {
      reportType: 'sla_compliance',
      businessId,
      period,
      generatedAt: new Date(),
      slaTargets,
      compliance
    };
  }

  private async generateCostAllocationReport(businessId: string, period: { start: Date; end: Date }): Promise<any> {
    const costData = await this.db.prepare(`
      SELECT
        module,
        capability,
        ai_provider,
        ai_model,
        SUM(cost_cents) / 100.0 as total_cost,
        COUNT(*) as request_count
      FROM cost_tracking
      WHERE business_id = ?
        AND timestamp BETWEEN ? AND ?
      GROUP BY module, capability, ai_provider, ai_model
      ORDER BY total_cost DESC
    `).bind(businessId, period.start.toISOString(), period.end.toISOString()).all();

    const totalCost = costData.results.reduce((sum: number, item: any) => sum + item.total_cost, 0);

    return {
      reportType: 'cost_allocation',
      businessId,
      period,
      generatedAt: new Date(),
      summary: {
        totalCost,
        totalRequests: costData.results.reduce((sum: number, item: any) => sum + item.request_count, 0)
      },
      breakdown: costData.results
    };
  }

  private async generateSecurityIncidentReport(businessId: string, period: { start: Date; end: Date }): Promise<any> {
    const securityLogs = await this.db.prepare(`
      SELECT * FROM log_entries
      WHERE business_id = ?
        AND timestamp BETWEEN ? AND ?
        AND (level = 'CRITICAL' OR level = 'ERROR')
        AND (error_type LIKE '%security%' OR error_type LIKE '%auth%')
      ORDER BY timestamp DESC
    `).bind(businessId, period.start.toISOString(), period.end.toISOString()).all();

    return {
      reportType: 'security_incidents',
      businessId,
      period,
      generatedAt: new Date(),
      summary: {
        totalIncidents: securityLogs.results.length
      },
      incidents: securityLogs.results
    };
  }

  // =============================================
  // HELPER METHODS
  // =============================================

  private async getMetricsForExport(businessId: string, timeRange?: { start: Date; end: Date }): Promise<any[]> {
    let sql = 'SELECT * FROM metrics WHERE business_id = ?';
    const params = [businessId];

    if (timeRange) {
      sql += ' AND timestamp BETWEEN ? AND ?';
      params.push(timeRange.start.toISOString(), timeRange.end.toISOString());
    }

    sql += ' ORDER BY timestamp DESC LIMIT 10000';

    const result = await this.db.prepare(sql).bind(...params).all();
    return result.results;
  }

  private async getLogsForExport(businessId: string, timeRange: { start: Date; end: Date }): Promise<any[]> {
    const result = await this.db.prepare(`
      SELECT * FROM log_entries
      WHERE business_id = ?
        AND timestamp BETWEEN ? AND ?
      ORDER BY timestamp DESC
      LIMIT 5000
    `).bind(businessId, timeRange.start.toISOString(), timeRange.end.toISOString()).all();

    return result.results;
  }

  private async getTracesForExport(businessId: string, timeRange: { start: Date; end: Date }): Promise<any[]> {
    const result = await this.db.prepare(`
      SELECT * FROM traces
      WHERE business_id = ?
        AND start_time BETWEEN ? AND ?
      ORDER BY start_time DESC
      LIMIT 1000
    `).bind(businessId, timeRange.start.toISOString(), timeRange.end.toISOString()).all();

    return result.results;
  }

  private parseLabels(labelsJson: string | null): Record<string, string> {
    try {
      return labelsJson ? JSON.parse(labelsJson) : {};
    } catch {
      return {};
    }
  }

  private generateSpanId(): string {
    const array = new Uint8Array(8);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  private getSeverityNumber(level: string): number {
    const levels: Record<string, number> = {
      'DEBUG': 5,
      'INFO': 9,
      'WARN': 13,
      'ERROR': 17,
      'CRITICAL': 21
    };
    return levels[level] || 9;
  }

  private getMetricUnit(metricName: string): string {
    const units: Record<string, string> = {
      'latency': 'ms',
      'memory_usage': 'MB',
      'cpu_usage': '%',
      'ai_cost': 'cents',
      'request_count': '1'
    };
    return units[metricName] || '1';
  }

  private parseMetricFromExpression(expr: string): string {
    // Simple parsing - in production this would be more sophisticated
    const match = expr.match(/([a-zA-Z_][a-zA-Z0-9_]*)/);
    return match ? match[1] : 'unknown';
  }

  private parseFiltersFromExpression(expr: string): Record<string, string> {
    // Simple parsing - in production this would handle PromQL properly
    return {};
  }

  private async generateExportData(request: ExportRequest): Promise<string> {
    const data = await this.getMetricsForExport(request.businessId, request.timeRange);

    switch (request.format) {
      case 'json':
        return JSON.stringify(data, null, 2);
      case 'csv':
        return this.formatAsCSV(data);
      case 'prometheus':
        return this.formatAsPrometheus(data);
      default:
        throw new Error(`Unsupported export format: ${request.format}`);
    }
  }

  private formatAsCSV(data: any[]): string {
    if (data.length === 0) return '';

    const headers = Object.keys(data[0]);
    const rows = data.map((row: any) =>
      headers.map((header: any) => {
        const value = row[header];
        return typeof value === 'object' ? JSON.stringify(value) : String(value);
      }).join(',')
    );

    return [headers.join(','), ...rows].join('\n');
  }

  private generateExportFileName(request: ExportRequest): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    return `export-${request.businessId}-${timestamp}.${request.format}`;
  }

  private getContentType(format: string): string {
    const types: Record<string, string> = {
      'json': 'application/json',
      'csv': 'text/csv',
      'prometheus': 'text/plain'
    };
    return types[format] || 'application/octet-stream';
  }
}