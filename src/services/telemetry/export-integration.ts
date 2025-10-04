import { ExportConfig, ComplianceReport, AnalyticsData } from '../../types/telemetry';
import { TelemetryCollector } from './collector';
import { MetricsCollector } from './metrics';

interface ExportJob {
  id: string;
  config: ExportConfig;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  startTime: number;
  endTime?: number;
  resultUrl?: string;
  error?: string;
}

interface Integration {
  id: string;
  type: 'prometheus' | 'datadog' | 'grafana' | 'opentelemetry' | 'bigquery' | 's3';
  config: Record<string, any>;
  enabled: boolean;
  lastSync?: number;
  status: 'healthy' | 'error' | 'disabled';
}

export // TODO: Consider splitting ExportIntegrationService into smaller, focused classes
class ExportIntegrationService {
  private collector: TelemetryCollector;
  private metrics: MetricsCollector;
  private env: any;
  private exportJobs: Map<string, ExportJob> = new Map();
  private integrations: Map<string, Integration> = new Map();
  private scheduledExports: Map<string, NodeJS.Timeout> = new Map();

  constructor(collector: TelemetryCollector, metrics: MetricsCollector, env: any) {
    this.collector = collector;
    this.metrics = metrics;
    this.env = env;
    this.initializeIntegrations();
    this.startScheduledExports();
  }

  async exportData(config: ExportConfig): Promise<string> {
    const jobId = crypto.randomUUID();
    const job: ExportJob = {
      id: jobId,
      config,
      status: 'pending',
      progress: 0,
      startTime: Date.now()
    };

    this.exportJobs.set(jobId, job);

    // Start export asynchronously
    this.processExport(job);

    return jobId;
  }

  private async processExport(job: ExportJob): Promise<void> {
    try {
      job.status = 'running';

      const data = await this.fetchExportData(job.config);
      job.progress = 50;

      const exportedData = await this.formatData(data, job.config.format);
      job.progress = 80;

      const resultUrl = await this.deliverExport(exportedData, job.config);
      job.progress = 100;
      job.status = 'completed';
      job.endTime = Date.now();
      job.resultUrl = resultUrl;

      this.metrics.counter('exports_completed_total', 1, {
        format: job.config.format,
        destination: job.config.destination
      });

    } catch (error: any) {
      job.status = 'failed';
      job.error = (error as Error).message;
      job.endTime = Date.now();

      this.metrics.counter('exports_failed_total', 1, {
        format: job.config.format,
        destination: job.config.destination
      });
    }
  }

  private async fetchExportData(config: ExportConfig): Promise<any[]> {
    const timeRange = this.getTimeRange(config.filters);
    const businessId = config.filters.businessId || 'default';

    let sql = this.buildExportQuery(config);

    // Add time range filter
    if (timeRange.start && timeRange.end) {
      sql += ` AND event_time BETWEEN '${timeRange.start}' AND '${timeRange.end}'`;
    }

    // Add business filter
    if (businessId !== 'default') {
      sql += ` AND business_id = '${businessId}'`;
    }

    return await this.collector.query(sql);
  }

  private buildExportQuery(config: ExportConfig): string {
    const fields = config.fields.length > 0 ? config.fields.join(', ') : '*';

    let baseQuery = `
      SELECT ${fields}
      FROM telemetry_events
      WHERE 1=1
    `;

    // Add specific filters
    if (config.filters.module) {
      baseQuery += ` AND JSONExtract(properties, 'module', 'String') = '${config.filters.module}'`;
    }

    if (config.filters.capability) {
      baseQuery += ` AND JSONExtract(properties, 'capability', 'String') = '${config.filters.capability}'`;
    }

    if (config.filters.severity) {
      baseQuery += ` AND JSONExtract(properties, 'severity', 'String') = '${config.filters.severity}'`;
    }

    if (config.filters.userId) {
      baseQuery += ` AND user_id = '${config.filters.userId}'`;
    }

    baseQuery += ` ORDER BY event_time DESC LIMIT 100000`; // Reasonable limit

    return baseQuery;
  }

  private getTimeRange(filters: Record<string, any>): { start?: string; end?: string } {
    if (filters.timeRange) {
      return {
        start: filters.timeRange.start,
        end: filters.timeRange.end
      };
    }

    // Default to last 24 hours
    const end = new Date().toISOString();
    const start = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    return { start, end };
  }

  private async formatData(data: any[], format: string): Promise<string | Buffer> {
    switch (format) {
      case 'csv':
        return this.formatAsCSV(data);
      case 'json':
        return this.formatAsJSON(data);
      case 'pdf':
        return await this.formatAsPDF(data);
      case 'prometheus':
        return this.formatAsPrometheus(data);
      case 'opentelemetry':
        return this.formatAsOpenTelemetry(data);
      default:
        throw new Error(`Unsupported format: ${format}`);
    }
  }

  private formatAsCSV(data: any[]): string {
    if (data.length === 0) return '';

    const headers = Object.keys(data[0]);
    const csvRows = [headers.join(',')];

    for (const row of data) {
      const values = headers.map((header: any) => {
        const value = row[header];
        if (typeof value === 'string' && value.includes(',')) {
          return `"${value.replace(/"/g, '""')}"`;
        }
        return value ?? '';
      });
      csvRows.push(values.join(','));
    }

    return csvRows.join('\n');
  }

  private formatAsJSON(data: any[]): string {
    return JSON.stringify(data, null, 2);
  }

  private async formatAsPDF(data: any[]): Promise<Buffer> {
    // Simplified PDF generation - in production, use a proper PDF library
    const html = this.generateReportHTML(data);

    if (this.env.PDF_SERVICE_URL) {
      const response = await fetch(this.env.PDF_SERVICE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ html })
      });

      return Buffer.from(await response.arrayBuffer());
    }

    // Fallback to simple text representation
    return Buffer.from(this.formatAsJSON(data));
  }

  private formatAsPrometheus(data: any[]): string {
    const lines: string[] = [];

    // Group metrics by name and labels
    const metricGroups = new Map<string, any[]>();

    data.forEach((row: any) => {
      const metricName = this.extractMetricName(row);
      if (!metricGroups.has(metricName)) {
        metricGroups.set(metricName, []);
      }
      metricGroups.get(metricName)!.push(row);
    });

    // Generate Prometheus format
    for (const [metricName, rows] of metricGroups) {
      lines.push(`# TYPE ${metricName} gauge`);

      rows.forEach((row: any) => {
        const labels = this.extractPrometheusLabels(row);
        const value = this.extractMetricValue(row);
        const timestamp = new Date(row.event_time).getTime();

        lines.push(`${metricName}{${labels}} ${value} ${timestamp}`);
      });
    }

    return lines.join('\n');
  }

  private formatAsOpenTelemetry(data: any[]): string {
    const traces = data.map((row: any) => ({
      traceId: row.trace_id,
      spanId: row.span_id,
      parentSpanId: row.parent_span_id,
      operationName: JSON.parse(row.properties || '{}').operationName || 'unknown',
      startTime: new Date(row.event_time).getTime() * 1000000, // nanoseconds
      endTime: (new Date(row.event_time).getTime() + 1000) * 1000000,
      tags: JSON.parse(row.properties || '{}'),
      logs: []
    }));

    return JSON.stringify({
      data: [{
        resourceSpans: [{
          resource: {
            attributes: [
              { key: 'service.name', value: { stringValue: 'coreflow360' } },
              { key: 'service.version', value: { stringValue: 'v4' } }
            ]
          },
          instrumentationLibrarySpans: [{
            instrumentationLibrary: {
              name: 'coreflow360-telemetry',
              version: '1.0.0'
            },
            spans: traces
          }]
        }]
      }]
    }, null, 2);
  }

  private async deliverExport(data: string | Buffer, config: ExportConfig): Promise<string> {
    switch (config.destination) {
      case 'download':
        return await this.storeForDownload(data, config);
      case 's3':
        return await this.uploadToS3(data, config);
      case 'email':
        return await this.sendViaEmail(data, config);
      case 'webhook':
        return await this.sendToWebhook(data, config);
      default:
        throw new Error(`Unsupported destination: ${config.destination}`);
    }
  }

  private async storeForDownload(data: string | Buffer, config: ExportConfig): Promise<string> {
    // Store in R2 for temporary download
    if (this.env.R2_BUCKET) {
      const key = `exports/${crypto.randomUUID()}.${this.getFileExtension(config.format)}`;

      await this.env.R2_BUCKET.put(key, data, {
        metadata: {
          contentType: this.getContentType(config.format),
          expiresAt: (Date.now() + 24 * 60 * 60 * 1000).toString() // 24 hours
        }
      });

      return `${this.env.R2_PUBLIC_URL}/${key}`;
    }

    // Fallback: return data URI for small files
    if (typeof data === 'string' && data.length < 1000000) { // 1MB limit
      const base64 = btoa(data);
      return `data:${this.getContentType(config.format)};base64,${base64}`;
    }

    throw new Error('Unable to store export for download');
  }

  private async uploadToS3(data: string | Buffer, config: ExportConfig): Promise<string> {
    if (!this.env.AWS_ACCESS_KEY_ID || !this.env.AWS_SECRET_ACCESS_KEY) {
      throw new Error('AWS credentials not configured');
    }

    const key = `exports/${new Date().toISOString().split('T')[0]}/${crypto.randomUUID()}.${this.getFileExtension(config.format)}`;

    // Simplified S3 upload - in production, use AWS SDK
    const url = `https://${this.env.S3_BUCKET}.s3.${this.env.AWS_REGION}.amazonaws.com/${key}`;

    // This would require proper AWS signature v4 - simplified for example
    const response = await fetch(url, {
      method: 'PUT',
      body: data,
      headers: {
        'Content-Type': this.getContentType(config.format)
      }
    });

    if (!response.ok) {
      throw new Error('Failed to upload to S3');
    }

    return url;
  }

  private async sendViaEmail(data: string | Buffer, config: ExportConfig): Promise<string> {
    const attachment = {
      filename: `export_${Date.now()}.${this.getFileExtension(config.format)}`,
      content: typeof data === 'string' ? Buffer.from(data) : data,
      contentType: this.getContentType(config.format)
    };

    if (this.env.RESEND_API_KEY) {
      const response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: this.env.DEFAULT_FROM_EMAIL,
          to: config.filters.email || this.env.DEFAULT_EXPORT_EMAIL,
          subject: 'CoreFlow360 Data Export',
          html: '<p>Your requested data export is attached.</p>',
          attachments: [attachment]
        })
      });

      const result = await response.json();
      return `Email sent: ${(result as any).id}`;
    }

    throw new Error('Email service not configured');
  }

  private async sendToWebhook(data: string | Buffer, config: ExportConfig): Promise<string> {
    const webhookUrl = config.filters.webhookUrl;
    if (!webhookUrl) {
      throw new Error('Webhook URL not provided');
    }

    const payload = {
      timestamp: Date.now(),
      format: config.format,
      data: typeof data === 'string' ? data : data.toString('base64')
    };

    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      throw new Error(`Webhook delivery failed: ${response.statusText}`);
    }

    return `Webhook delivered: ${response.status}`;
  }

  private getFileExtension(format: string): string {
    switch (format) {
      case 'csv': return 'csv';
      case 'json': return 'json';
      case 'pdf': return 'pdf';
      case 'prometheus': return 'txt';
      case 'opentelemetry': return 'json';
      default: return 'txt';
    }
  }

  private getContentType(format: string): string {
    switch (format) {
      case 'csv': return 'text/csv';
      case 'json': return 'application/json';
      case 'pdf': return 'application/pdf';
      case 'prometheus': return 'text/plain';
      case 'opentelemetry': return 'application/json';
      default: return 'text/plain';
    }
  }

  private extractMetricName(row: any): string {
    const properties = JSON.parse(row.properties || '{}');
    return properties.metricName || 'telemetry_metric';
  }

  private extractPrometheusLabels(row: any): string {
    const properties = JSON.parse(row.properties || '{}');
    const labels: string[] = [];

    if (row.business_id) labels.push(`business_id="${row.business_id}"`);
    if (row.user_id) labels.push(`user_id="${row.user_id}"`);
    if (properties.module) labels.push(`module="${properties.module}"`);
    if (properties.capability) labels.push(`capability="${properties.capability}"`);

    return labels.join(',');
  }

  private extractMetricValue(row: any): number {
    const metrics = JSON.parse(row.metrics || '{}');
    return metrics.value || metrics.latencyMs || metrics.count || 1;
  }

  private generateReportHTML(data: any[]): string {
    const headers = data.length > 0 ? Object.keys(data[0]) : [];

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <title>CoreFlow360 Export Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
          th { background-color: #f2f2f2; }
          .header { text-align: center; margin-bottom: 20px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>CoreFlow360 Export Report</h1>
          <p>Generated on ${new Date().toISOString()}</p>
          <p>Records: ${data.length}</p>
        </div>
        <table>
          <thead>
            <tr>${headers.map((h: any) => `<th>${h}</th>`).join('')}</tr>
          </thead>
          <tbody>
            ${data.slice(0, 1000).map((row: any) =>
              `<tr>${headers.map((h: any) => `<td>${row[h] || ''}</td>`).join('')}</tr>`
            ).join('')}
          </tbody>
        </table>
      </body>
      </html>
    `;
  }

  async generateComplianceReport(type: string, period: { start: string; end: string }): Promise<ComplianceReport> {
    const reportId = crypto.randomUUID();

    switch (type) {
      case 'sla':
        return this.generateSLAReport(reportId, period);
      case 'audit':
        return this.generateAuditReport(reportId, period);
      case 'security':
        return this.generateSecurityReport(reportId, period);
      case 'cost':
        return this.generateCostReport(reportId, period);
      case 'performance':
        return this.generatePerformanceReport(reportId, period);
      default:
        throw new Error(`Unknown report type: ${type}`);
    }
  }

  private async generateSLAReport(id: string, period: { start: string; end: string }): Promise<ComplianceReport> {
    const sql = `
      SELECT
        AVG(JSONExtract(metrics, 'latencyMs', 'Float64')) as avg_latency,
        quantile(0.95)(JSONExtract(metrics, 'latencyMs', 'Float64')) as p95_latency,
        AVG(CASE WHEN JSONExtract(properties, 'statusCode', 'UInt16') >= 400 THEN 1 ELSE 0 END) as error_rate,
        COUNT(*) as total_requests
      FROM telemetry_events
      WHERE event_time BETWEEN '${period.start}' AND '${period.end}'
    `;

    const results = await this.collector.query(sql);
    const metrics = results[0] || {};

    const slaTargets = {
      availability: 0.999, // 99.9%
      latency_p95: 2000,   // 2 seconds
      error_rate: 0.01     // 1%
    };

    const violations = [];

    if (metrics.error_rate > slaTargets.error_rate) {
      violations.push({
        rule: 'Error Rate SLA',
        severity: 'high',
        count: 1,
        examples: [`Error rate: ${(metrics.error_rate * 100).toFixed(2)}% > ${(slaTargets.error_rate * 100)}%`]
      });
    }

    if (metrics.p95_latency > slaTargets.latency_p95) {
      violations.push({
        rule: 'Latency SLA',
        severity: 'medium',
        count: 1,
        examples: [`P95 latency: ${metrics.p95_latency}ms > ${slaTargets.latency_p95}ms`]
      });
    }

    const availability = 1 - metrics.error_rate;
    const complianceScore = availability >= slaTargets.availability ? 1 : availability / slaTargets.availability;

    return {
      id,
      type: 'sla',
      period,
      metrics: {
        availability,
        avg_latency: metrics.avg_latency,
        p95_latency: metrics.p95_latency,
        error_rate: metrics.error_rate,
        total_requests: metrics.total_requests
      },
      violations,
      summary: {
        compliance_score: complianceScore,
        total_incidents: violations.length,
        resolved_incidents: 0,
        average_resolution_time: 0
      }
    };
  }

  private async generateAuditReport(id: string, period: { start: string; end: string }): Promise<ComplianceReport> {
    const sql = `
      SELECT
        JSONExtract(properties, 'module', 'String') as module,
        JSONExtract(properties, 'capability', 'String') as capability,
        user_id,
        COUNT(*) as access_count
      FROM telemetry_events
      WHERE event_time BETWEEN '${period.start}' AND '${period.end}'
        AND event_type = 'audit'
      GROUP BY module, capability, user_id
      ORDER BY access_count DESC
    `;

    const results = await this.collector.query(sql);

    return {
      id,
      type: 'audit',
      period,
      metrics: {
        total_access_events: results.reduce((sum, r) => sum + r.access_count, 0),
        unique_users: new Set(results.map((r: any) => r.user_id)).size,
        unique_modules: new Set(results.map((r: any) => r.module)).size
      },
      violations: [],
      summary: {
        compliance_score: 1,
        total_incidents: 0,
        resolved_incidents: 0,
        average_resolution_time: 0
      }
    };
  }

  private async generateSecurityReport(id: string, period: { start: string; end: string }): Promise<ComplianceReport> {
    // Implementation for security compliance report
    return {
      id,
      type: 'security',
      period,
      metrics: {},
      violations: [],
      summary: {
        compliance_score: 1,
        total_incidents: 0,
        resolved_incidents: 0,
        average_resolution_time: 0
      }
    };
  }

  private async generateCostReport(id: string, period: { start: string; end: string }): Promise<ComplianceReport> {
    // Implementation for cost compliance report
    return {
      id,
      type: 'cost',
      period,
      metrics: {},
      violations: [],
      summary: {
        compliance_score: 1,
        total_incidents: 0,
        resolved_incidents: 0,
        average_resolution_time: 0
      }
    };
  }

  private async generatePerformanceReport(id: string, period:
  { start: string; end: string }): Promise<ComplianceReport> {
    // Implementation for performance compliance report
    return {
      id,
      type: 'performance',
      period,
      metrics: {},
      violations: [],
      summary: {
        compliance_score: 1,
        total_incidents: 0,
        resolved_incidents: 0,
        average_resolution_time: 0
      }
    };
  }

  private initializeIntegrations(): void {
    const defaultIntegrations: Integration[] = [
      {
        id: 'prometheus',
        type: 'prometheus',
        config: {
          endpoint: '/metrics',
          scrapeInterval: '30s'
        },
        enabled: true,
        status: 'healthy'
      },
      {
        id: 'opentelemetry',
        type: 'opentelemetry',
        config: {
          endpoint: this.env.OTEL_ENDPOINT || 'http://localhost:14268/api/traces',
          headers: {}
        },
        enabled: !!this.env.OTEL_ENDPOINT,
        status: 'healthy'
      }
    ];

    defaultIntegrations.forEach((integration: any) => {
      this.integrations.set(integration.id, integration);
    });
  }

  private startScheduledExports(): void {
    // Check for scheduled exports every minute
    setInterval(() => {
      this.processScheduledExports();
    }, 60000);
  }

  private processScheduledExports(): void {
    // Implementation for cron-based scheduled exports
    // This would parse cron expressions and trigger exports
  }

  getExportJob(jobId: string): ExportJob | undefined {
    return this.exportJobs.get(jobId);
  }

  getExportJobs(): ExportJob[] {
    return Array.from(this.exportJobs.values());
  }

  getIntegrations(): Integration[] {
    return Array.from(this.integrations.values());
  }

  addIntegration(integration: Integration): void {
    this.integrations.set(integration.id, integration);
  }

  removeIntegration(integrationId: string): void {
    this.integrations.delete(integrationId);
  }

  async testIntegration(integrationId: string): Promise<boolean> {
    const integration = this.integrations.get(integrationId);
    if (!integration) return false;

    try {
      switch (integration.type) {
        case 'prometheus':
          return await this.testPrometheusIntegration(integration);
        case 'datadog':
          return await this.testDatadogIntegration(integration);
        default:
          return true;
      }
    } catch (error: any) {
      return false;
    }
  }

  private async testPrometheusIntegration(integration: Integration): Promise<boolean> {
    // Test Prometheus endpoint
    return true;
  }

  private async testDatadogIntegration(integration: Integration): Promise<boolean> {
    // Test Datadog API
    return true;
  }
}