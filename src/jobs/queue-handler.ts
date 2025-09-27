// src/jobs/queue-handler.ts
import { createDatabase, Database } from '../database/db';
import { createAIService, AIService } from '../ai/ai-service';
import { createWebSocketService } from '../realtime/websocket-service';
import type {
  Message,
  D1Database,
  KVNamespace,
  R2Bucket,
  Queue
} from '../cloudflare/types/cloudflare';
import type { Env } from '../types/env';

export interface JobPayload {
  type: string;
  businessId: string;
  userId?: string;
  requestId?: string;
  data?: any;
  priority?: 'low' | 'normal' | 'high';
  retryCount?: number;
  maxRetries?: number;
  scheduledTime?: number;
}

export interface ReportJob extends JobPayload {
  type: 'generate-report';
  reportType: 'financial' | 'operational' | 'audit' | 'custom';
  reportId: string;
  requestedBy: string;
  filters?: any;
  format?: 'pdf' | 'excel' | 'csv';
}

export interface EmailJob extends JobPayload {
  type: 'send-email';
  to: string | string[];
  subject: string;
  template?: string;
  data?: any;
  attachments?: any[];
}

export interface ImportJob extends JobPayload {
  type: 'process-import';
  importId: string;
  fileUrl: string;
  mapping: any;
  validateOnly?: boolean;
}

export interface AnalyticsJob extends JobPayload {
  type: 'calculate-analytics';
  metricType: 'financial' | 'operational' | 'user' | 'custom';
  period: string;
  aggregation: 'hourly' | 'daily' | 'weekly' | 'monthly';
}

export class QueueHandler {
  private db: Database | null = null;
  private ai: AIService | null = null;

  async processJob(message: Message, env: Env): Promise<void> {
    const startTime = Date.now();
    let job: JobPayload | undefined;

    try {
      job = JSON.parse(message.body as string);

      // Initialize services
      this.db = createDatabase(env.DB, (env as any).CACHE);
      this.ai = createAIService(env.AI as any, env.ANTHROPIC_API_KEY || '', (env as any).CACHE);

      // Log job start
      await this.logJobExecution(job!, 'started', env);

      // Route to appropriate handler
      switch (job!.type) {
        case 'generate-report':
          await this.generateReport(job! as ReportJob, env);
          break;
        case 'send-email':
          await this.sendEmail(job! as EmailJob, env);
          break;
        case 'process-import':
          await this.processImport(job! as ImportJob, env);
          break;
        case 'calculate-analytics':
          await this.calculateAnalytics(job! as AnalyticsJob, env);
          break;
        case 'ai-processing':
          await this.processAI(job!, env);
          break;
        case 'data-cleanup':
          await this.dataCleanup(job!, env);
          break;
        case 'webhook-delivery':
          await this.deliverWebhook(job!, env);
          break;
        default:
          throw new Error(`Unknown job type: ${job!.type}`);
      }

      // Log successful completion
      const duration = Date.now() - startTime;
      await this.logJobExecution(job!, 'completed', env, { duration });

      // Acknowledge message
      message.ack();

    } catch (error: any) {

      // Handle retries
      const retryCount = ((job as any)?.retryCount || 0) + 1;
      const maxRetries = (job as any)?.maxRetries || 3;

      if (retryCount <= maxRetries) {
        // Retry with exponential backoff
        const delay = Math.pow(2, retryCount) * 1000; // 2s, 4s, 8s...
        setTimeout(() => message.retry(), delay);

        await this.logJobExecution(job!, 'retrying', env, {
          error: error instanceof Error ? error.message : String(error),
          retryCount,
          nextRetry: Date.now() + delay
        });
      } else {
        // Max retries exceeded
        await this.logJobExecution(job!, 'failed', env, {
          error: error instanceof Error ? error.message : String(error),
          retryCount,
          finalFailure: true
        });

        // Send to dead letter queue or error handling
        await this.handleJobFailure(job!, error instanceof Error ? error : new Error(String(error)), env);
        message.ack(); // Don't retry further
      }
    }
  }

  // Efficient report generation with streaming
  async generateReport(job: ReportJob, env: Env): Promise<void> {
    const { reportType, reportId, businessId, requestedBy, filters, format = 'pdf' } = job;

    try {
      // Notify start via WebSocket
      const ws = createWebSocketService((env as any).REALTIME, businessId);
      await ws.notifySystemEvent(businessId, 'report-generation-started', {
        reportId,
        reportType,
        requestedBy
      });

      // Get business context for AI-enhanced reports
      const business = await this.db!.getBusiness(businessId);

      // Stream data processing based on report type
      let data: any;
      let aiInsights: any = null;

      switch (reportType) {
        case 'financial':
          data = await this.getFinancialData(businessId, filters);
          break;
        case 'operational':
          data = await this.getOperationalData(businessId, filters);
          break;
        case 'audit':
          data = await this.getAuditData(businessId, filters);
          break;
        default:
          data = await this.getCustomReportData(businessId, filters);
      }

      // Generate AI insights for enhanced reports
      if (reportType !== 'audit') {
        aiInsights = await this.ai!.generateInsights(
          data,
          reportType as any,
          { businessId, industry: business?.settings?.industry }
        );
      }

      // Generate report in requested format
      let reportBuffer: ArrayBuffer;
      let mimeType: string;

      switch (format) {
        case 'pdf':
          reportBuffer = await this.generatePDF(data, aiInsights, reportType);
          mimeType = 'application/pdf';
          break;
        case 'excel':
          reportBuffer = await this.generateExcel(data, reportType);
          mimeType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
          break;
        case 'csv':
          reportBuffer = await this.generateCSV(data);
          mimeType = 'text/csv';
          break;
        default:
          throw new Error(`Unsupported format: ${format}`);
      }

      // Store in R2 with expiration
      const fileName = `${reportId}.${format}`;
      await env.R2_DOCUMENTS.put(
        `reports/${businessId}/${fileName}`,
        reportBuffer,
        {
          httpMetadata: {
            contentType: mimeType,
            cacheControl: 'public, max-age=604800' // 7 days
          },
          customMetadata: {
            businessId,
            reportType,
            requestedBy,
            generated: new Date().toISOString()
          }
        }
      );

      // Create download URL
      const reportUrl = `${env.API_BASE_URL || 'https://api.coreflow360.com'}/api/reports/${reportId}/download`;

      // Send email notification
      await this.queueEmailJob({
        type: 'send-email',
        businessId,
        to: requestedBy,
        subject: `${reportType.toUpperCase()} Report Ready - ${reportId}`,
        template: 'report-ready',
        data: {
          reportType,
          reportId,
          downloadUrl: reportUrl,
          business: business?.name || businessId,
          generatedAt: new Date().toISOString()
        }
      }, env);

      // Log successful generation
      await this.db!.logAudit(businessId, 'report_generated', requestedBy, 'reports', {
        reportId,
        reportType,
        format,
        size: reportBuffer.byteLength
      });

      // Notify completion via WebSocket
      await ws.notifySystemEvent(businessId, 'report-generation-completed', {
        reportId,
        reportType,
        downloadUrl: reportUrl,
        requestedBy
      });

    } catch (error: any) {
      // Notify failure via WebSocket
      const ws = createWebSocketService((env as any).REALTIME, businessId);
      await ws.notifySystemEvent(businessId, 'report-generation-failed', {
        reportId,
        reportType,
        error: error instanceof Error ? error.message : String(error),
        requestedBy
      });
      throw error;
    }
  }

  // Email processing with templates
  async sendEmail(job: EmailJob, env: Env): Promise<void> {
    const { businessId, to, subject, template, data = {}, attachments = [] } = job;

    try {
      // Get email service configuration
      const emailConfig = await this.getEmailConfig(businessId, env);

      // Build email content
      let htmlContent: string;
      let textContent: string;

      if (template) {
        // Use template
        const templateData = await this.loadEmailTemplate(template, env);
        htmlContent = this.renderTemplate(templateData.html, data);
        textContent = this.renderTemplate(templateData.text, data);
      } else {
        // Use data directly
        htmlContent = data.html || data.content || '';
        textContent = data.text || data.content || '';
      }

      // Send via email service (Resend, SendGrid, etc.)
      const response = await fetch(emailConfig.endpoint, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${emailConfig.apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          from: emailConfig.fromAddress,
          to: Array.isArray(to) ? to : [to],
          subject,
          html: htmlContent,
          text: textContent,
          attachments
        })
      });

      if (!response.ok) {
        throw new Error(`Email service error: ${response.status}`);
      }

      // Log successful send
      await this.db!.logAudit(businessId, 'email_sent', undefined, 'emails', {
        to: Array.isArray(to) ? to.length : 1,
        subject,
        template
      });

    } catch (error: any) {
      throw error;
    }
  }

  // Data import processing with validation
  async processImport(job: ImportJob, env: Env): Promise<void> {
    const { businessId, importId, fileUrl, mapping, validateOnly = false } = job;

    try {
      // Download file from R2 or external URL
      const response = await fetch(fileUrl);
      const fileContent = await response.text();

      // Parse CSV/Excel file
      const rows = this.parseCSV(fileContent);
      const processedData = this.mapDataFields(rows, mapping);

      // Validate data
      const validation = await this.validateImportData(processedData, mapping.table);

      if (validation.errors.length > 0 && !validateOnly) {
        throw new Error(`Validation failed: ${validation.errors.join(', ')}`);
      }

      if (!validateOnly && validation.valid) {
        // Import data in batches
        const batchSize = 100;
        for (let i = 0; i < processedData.length; i += batchSize) {
          const batch = processedData.slice(i, i + batchSize);
          await this.db!.batchInsert(mapping.table, batch);
        }

        // Notify via WebSocket
        const ws = createWebSocketService((env as any).REALTIME, businessId);
        await ws.notifyDataUpdate(businessId, mapping.table, 'import', {
          importId,
          recordsImported: processedData.length
        });
      }

      // Log import result
      await this.db!.logAudit(businessId, 'data_import', undefined, 'imports', {
        importId,
        records: processedData.length,
        errors: validation.errors.length,
        validateOnly
      });

    } catch (error: any) {
      throw error;
    }
  }

  // Analytics calculation with caching
  async calculateAnalytics(job: AnalyticsJob, env: Env): Promise<void> {
    const { businessId, metricType, period, aggregation } = job;

    try {
      // Calculate metrics based on type
      let metrics: any;

      switch (metricType) {
        case 'financial':
          metrics = await this.calculateFinancialMetrics(businessId, period, aggregation);
          break;
        case 'operational':
          metrics = await this.calculateOperationalMetrics(businessId, period, aggregation);
          break;
        case 'user':
          metrics = await this.calculateUserMetrics(businessId, period, aggregation);
          break;
        default:
          metrics = await this.calculateCustomMetrics(businessId, period, aggregation);
      }

      // Cache results
      const cacheKey = `analytics:${businessId}:${metricType}:${period}:${aggregation}`;
      await (env as any).CACHE.put(cacheKey, JSON.stringify(metrics), {
        expirationTtl: this.getAnalyticsCacheTTL(aggregation)
      });

      // Store in analytics database
      await (env as any).ANALYTICS.writeDataPoint({
        indexes: [businessId, metricType, aggregation],
        blobs: [period, JSON.stringify(metrics)],
        doubles: [Date.now(), metrics.total || 0]
      });

      // Notify via WebSocket
      const ws = createWebSocketService((env as any).REALTIME, businessId);
      await ws.notifyAnalyticsUpdate(businessId, {
        metricType,
        period,
        aggregation,
        data: metrics
      });

    } catch (error: any) {
      throw error;
    }
  }

  // AI processing jobs
  async processAI(job: JobPayload, env: Env): Promise<void> {
    const { businessId, data } = job;

    try {
      const result = await this.ai!.route({
        prompt: data.prompt,
        messages: data.messages,
        context: { businessId, ...data.context },
        complexity: data.complexity
      });

      // Store result if needed
      if (data.storeResult) {
        await (env as any).CACHE.put(`ai-result:${job.requestId}`, JSON.stringify(result), {
          expirationTtl: 3600
        });
      }

      // Notify completion
      const ws = createWebSocketService((env as any).REALTIME, businessId);
      await ws.notifyAIResponse(businessId, data.userId, job.requestId!, result);

    } catch (error: any) {
      throw error;
    }
  }

  // Data cleanup and maintenance
  async dataCleanup(job: JobPayload, env: Env): Promise<void> {
    const { businessId, data } = job;

    // Clean old audit logs
    if (data.cleanupType === 'audit-logs') {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - (data.retentionDays || 90));

      await this.db!.execute(
        'DELETE FROM audit_log WHERE business_id = ? AND timestamp < ?',
        [businessId, cutoffDate.toISOString()]
      );
    }

    // Clean cache entries
    if (data.cleanupType === 'cache') {
      // Implementation depends on cache structure
    }
  }

  // Webhook delivery with retries
  async deliverWebhook(job: JobPayload, env: Env): Promise<void> {
    const { businessId, data } = job;
    const { url, payload, headers = {}, secret } = data;

    try {
      // Add signature if secret provided
      if (secret) {
        const signature = await this.generateWebhookSignature(payload, secret);
        headers['X-Webhook-Signature'] = signature;
      }

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...headers
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Webhook delivery failed: ${response.status}`);
      }

      // Log successful delivery
      await this.db!.logAudit(businessId, 'webhook_delivered', undefined, 'webhooks', {
        url,
        status: response.status
      });

    } catch (error: any) {
      throw error;
    }
  }

  // Helper methods
  private async getFinancialData(businessId: string, filters: any): Promise<any> {
    return this.db!.query(
      `SELECT * FROM ledger_entries
       WHERE business_id = ? AND created_at BETWEEN ? AND ?`,
      [businessId, filters.startDate, filters.endDate],
      { cache: 300 }
    );
  }

  private async getOperationalData(businessId: string, filters: any): Promise<any> {
    return this.db!.getBusinessStats(businessId);
  }

  private async getAuditData(businessId: string, filters: any): Promise<any> {
    return this.db!.query(
      `SELECT * FROM audit_log
       WHERE business_id = ? AND timestamp BETWEEN ? AND ?`,
      [businessId, filters.startDate, filters.endDate]
    );
  }

  private async getCustomReportData(businessId: string, filters: any): Promise<any> {
    // Custom query based on filters
    return [];
  }

  private async generatePDF(data: any, insights?: any, reportType?: string): Promise<ArrayBuffer> {
    // PDF generation logic (could use libraries like Puppeteer or jsPDF)
    // For now, return placeholder
    const content = JSON.stringify({ data, insights, reportType });
    return new TextEncoder().encode(content).buffer;
  }

  private async generateExcel(data: any, reportType: string): Promise<ArrayBuffer> {
    // Excel generation logic
    const content = JSON.stringify({ data, reportType });
    return new TextEncoder().encode(content).buffer;
  }

  private async generateCSV(data: any[]): Promise<ArrayBuffer> {
    if (data.length === 0) return new ArrayBuffer(0);

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map((row: any) => headers.map((h: any) => row[h]).join(','))
    ].join('\n');

    return new TextEncoder().encode(csvContent).buffer;
  }

  private parseCSV(content: string): any[] {
    const lines = content.split('\n');
    const headers = lines[0].split(',');

    return lines.slice(1).map((line: any) => {
      const values = line.split(',');
      return headers.reduce((obj, header, index) => {
        obj[header.trim()] = values[index]?.trim();
        return obj;
      }, {} as any);
    });
  }

  private mapDataFields(rows: any[], mapping: any): any[] {
    return rows.map((row: any) => {
      const mapped: any = {};
      for (const [sourceField, targetField] of Object.entries(mapping.fields)) {
        mapped[targetField as string] = row[sourceField];
      }
      return mapped;
    });
  }

  private async validateImportData(data: any[], table: string): Promise<{ valid: boolean; errors: string[] }> {
    const errors: string[] = [];

    // Basic validation
    if (data.length === 0) {
      errors.push('No data to import');
    }

    // Table-specific validation
    for (const row of data) {
      if (!row.id && table !== 'audit_log') {
        errors.push('Missing required field: id');
      }
    }

    return { valid: errors.length === 0, errors };
  }

  private async calculateFinancialMetrics(businessId: string, period: string, aggregation: string): Promise<any> {
    const stats = await this.db!.getBusinessStats(businessId);
    return {
      total: stats.netBalance,
      debits: stats.totalDebits,
      credits: stats.totalCredits,
      period,
      aggregation
    };
  }

  private async calculateOperationalMetrics(businessId: string, period: string, aggregation: string): Promise<any> {
    const stats = await this.db!.getBusinessStats(businessId);
    return {
      users: stats.totalUsers,
      entries: stats.totalLedgerEntries,
      period,
      aggregation
    };
  }

  private async calculateUserMetrics(businessId: string, period: string, aggregation: string): Promise<any> {
    const users = await this.db!.getBusinessUsers(businessId);
    return {
      total: users.length,
      active: users.filter((u: any) => u.settings?.active !== false).length,
      period,
      aggregation
    };
  }

  private async calculateCustomMetrics(businessId: string, period: string, aggregation: string): Promise<any> {
    return { period, aggregation, custom: true };
  }

  private getAnalyticsCacheTTL(aggregation: string): number {
    switch (aggregation) {
      case 'hourly': return 3600;      // 1 hour
      case 'daily': return 86400;     // 24 hours
      case 'weekly': return 604800;   // 7 days
      case 'monthly': return 2592000; // 30 days
      default: return 3600;
    }
  }

  private async getEmailConfig(businessId: string, env: Env): Promise<any> {
    // Get business-specific email config or use defaults
    return {
      endpoint: 'https://api.resend.com/emails',
      apiKey: env.EMAIL_API_KEY,
      fromAddress: `noreply@${businessId}.coreflow360.com`
    };
  }

  private async loadEmailTemplate(template: string, env: Env): Promise<any> {
    // Load email template from R2 or predefined templates
    const response = await env.R2_ASSETS.get(`email-templates/${template}.json`);

    if (response) {
      return await response.json();
    }

    // Fallback templates
    return {
      html: '<h1>{{title}}</h1><p>{{content}}</p>',
      text: '{{title}}\n\n{{content}}'
    };
  }

  private renderTemplate(template: string, data: any): string {
    return template.replace(/\{\{(\w+)\}\}/g, (match, key) => data[key] || match);
  }

  private async generateWebhookSignature(payload: any, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(JSON.stringify(payload));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
    return Array.from(new Uint8Array(signature))
      .map((b: any) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  private async queueEmailJob(job: EmailJob, env: Env): Promise<void> {
    // Queue email for processing
    await env.EMAIL_QUEUE.send(JSON.stringify(job));
  }

  private async logJobExecution(job: JobPayload, status: string, env: Env, metadata?: any): Promise<void> {
    if (this.db) {
      await this.db.logAudit(job.businessId, `job_${status}`, job.userId, 'jobs', {
        jobType: job.type,
        requestId: job.requestId,
        status,
        ...metadata
      });
    }
  }

  private async handleJobFailure(job: JobPayload, error: Error, env: Env): Promise<void> {
    // Send to dead letter queue or error handling service

    // Notify via WebSocket if applicable
    if (job.businessId) {
      const ws = createWebSocketService((env as any).REALTIME, job.businessId);
      await ws.notifySystemEvent(job.businessId, 'job-failed', {
        jobType: job.type,
        requestId: job.requestId,
        error: error.message
      });
    }
  }
}

// Factory function
export function createQueueHandler(): QueueHandler {
  return new QueueHandler();
}