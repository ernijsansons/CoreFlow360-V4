/**
 * GDPR Data Export Service for Finance Module
 * Comprehensive data export capabilities for regulatory compliance
 */

import type { D1Database, R2Bucket } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { validateBusinessId } from './utils';

export interface GDPRExportRequest {
  businessId: string;
  requestedBy: string;
  requestedAt: number;
  purpose: 'user_request' | 'legal_obligation' | 'compliance_audit';
  includePersonalData: boolean;
  includeFinancialData: boolean;
  includeAuditTrails: boolean;
  dateRange?: {
    startDate: number;
    endDate: number;
  };
  exportFormat: 'JSON' | 'CSV' | 'XML';
  deliveryMethod: 'download' | 'email' | 'secure_link';
  retentionDays?: number; // How long to keep the export available
}

export interface PersonalDataRecord {
  entityType: 'customer' | 'vendor' | 'employee' | 'user';
  entityId: string;
  dataFields: Record<string, any>;
  source: string;
  collectedAt: number;
  lastModified: number;
  legalBasis: string;
  processingPurpose: string;
}

export interface FinancialDataRecord {
  recordType: 'transaction' | 'invoice' | 'payment' | 'account' | 'report';
  recordId: string;
  data: Record<string, any>;
  createdAt: number;
  lastModified: number;
  relatedPersons: string[]; // IDs of related individuals
}

export interface AuditTrailRecord {
  action: string;
  entityType: string;
  entityId: string;
  performedBy: string;
  performedAt: number;
  changes: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
}

export interface GDPRExportResult {
  exportId: string;
  status: 'generating' | 'completed' | 'failed' | 'expired';
  requestDetails: GDPRExportRequest;
  generatedAt?: number;
  completedAt?: number;
  downloadUrl?: string;
  fileSize?: number;
  recordCounts: {
    personalData: number;
    financialData: number;
    auditTrails: number;
  };
  expiresAt?: number;
  errorMessage?: string;
}

export // TODO: Consider splitting GDPRDataExportService into smaller, focused classes
class GDPRDataExportService {
  private logger: Logger;
  private db: D1Database;
  private r2Bucket?: R2Bucket;

  constructor(db: D1Database, r2Bucket?: R2Bucket) {
    this.logger = new Logger();
    this.db = db;
    this.r2Bucket = r2Bucket;
  }

  /**
   * Create a new GDPR data export request
   */
  async createExportRequest(request: GDPRExportRequest): Promise<string> {
    const validBusinessId = validateBusinessId(request.businessId);
    const exportId = `gdpr_export_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

    try {
      // Store export request
      await this.db.prepare(`
        INSERT INTO gdpr_export_requests (
          id, business_id, requested_by, requested_at, purpose,
          include_personal_data, include_financial_data, include_audit_trails,
          date_range_start, date_range_end, export_format, delivery_method,
          retention_days, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        exportId,
        validBusinessId,
        request.requestedBy,
        request.requestedAt,
        request.purpose,
        request.includePersonalData ? 1 : 0,
        request.includeFinancialData ? 1 : 0,
        request.includeAuditTrails ? 1 : 0,
        request.dateRange?.startDate || null,
        request.dateRange?.endDate || null,
        request.exportFormat,
        request.deliveryMethod,
        request.retentionDays || 30,
        'generating',
        Date.now()
      ).run();

      this.logger.info('GDPR export request created', {
        exportId,
        businessId: validBusinessId,
        requestedBy: request.requestedBy,
        purpose: request.purpose
      });

      // Start export process asynchronously
      this.processExportRequest(exportId, request).catch(error => {
        this.logger.error('GDPR export failed', error, { exportId });
        this.updateExportStatus(exportId, 'failed', error.message);
      });

      return exportId;

    } catch (error) {
      this.logger.error('Failed to create GDPR export request', error, {
        businessId: validBusinessId,
        requestedBy: request.requestedBy
      });
      throw error;
    }
  }

  /**
   * Get export request status
   */
  async getExportStatus(exportId: string, businessId: string): Promise<GDPRExportResult | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM gdpr_export_requests
        WHERE id = ? AND business_id = ?
      `).bind(exportId, validBusinessId).first();

      if (!result) {
        return null;
      }

      return this.mapToExportResult(result);

    } catch (error) {
      this.logger.error('Failed to get export status', error, {
        exportId,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * List export requests for business
   */
  async listExportRequests(
    businessId: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<GDPRExportResult[]> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM gdpr_export_requests
        WHERE business_id = ?
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
      `).bind(validBusinessId, limit, offset).all();

      return (result.results || []).map(row => this.mapToExportResult(row));

    } catch (error) {
      this.logger.error('Failed to list export requests', error, {
        businessId: validBusinessId
      });
      return [];
    }
  }

  /**
   * Delete expired export files
   */
  async cleanupExpiredExports(): Promise<void> {
    try {
      const expiredExports = await this.db.prepare(`
        SELECT id, download_url FROM gdpr_export_requests
        WHERE status = 'completed' AND expires_at < ?
      `).bind(Date.now()).all();

      for (const exportRow of expiredExports.results || []) {
        // Delete file from R2 if exists
        if (this.r2Bucket && exportRow.download_url) {
          try {
            const fileName = this.extractFileNameFromUrl(exportRow.download_url);
            await this.r2Bucket.delete(fileName);
          } catch (error) {
            this.logger.warn('Failed to delete expired export file', error, {
              exportId: exportRow.id
            });
          }
        }

        // Update status to expired
        await this.db.prepare(`
          UPDATE gdpr_export_requests
          SET status = 'expired', download_url = NULL
          WHERE id = ?
        `).bind(exportRow.id).run();
      }

      this.logger.info('Cleaned up expired exports', {
        count: expiredExports.results?.length || 0
      });

    } catch (error) {
      this.logger.error('Failed to cleanup expired exports', error);
    }
  }

  /**
   * Process export request
   */
  private async processExportRequest(exportId: string, request: GDPRExportRequest): Promise<void> {
    const startTime = Date.now();

    try {
      this.logger.info('Starting GDPR export processing', { exportId });

      // Collect data based on request
      const exportData: {
        personalData: PersonalDataRecord[];
        financialData: FinancialDataRecord[];
        auditTrails: AuditTrailRecord[];
      } = {
        personalData: [],
        financialData: [],
        auditTrails: []
      };

      if (request.includePersonalData) {
        exportData.personalData = await this.collectPersonalData(request);
      }

      if (request.includeFinancialData) {
        exportData.financialData = await this.collectFinancialData(request);
      }

      if (request.includeAuditTrails) {
        exportData.auditTrails = await this.collectAuditTrails(request);
      }

      // Generate export file
      const exportContent = this.formatExportData(exportData, request.exportFormat);
      const fileName = `gdpr_export_${exportId}.${request.exportFormat.toLowerCase()}`;

      let downloadUrl: string | null = null;

      // Upload to R2 if available
      if (this.r2Bucket) {
        await this.r2Bucket.put(fileName, exportContent, {
          httpMetadata: {
            contentType: this.getContentType(request.exportFormat),
            contentDisposition: `attachment; filename="${fileName}"`
          }
        });

        downloadUrl = `https://exports.example.com/${fileName}`;
      }

      // Calculate expiry date
      const retentionDays = request.retentionDays || 30;
      const expiresAt = Date.now() + (retentionDays * 24 * 60 * 60 * 1000);

      // Update export status
      await this.db.prepare(`
        UPDATE gdpr_export_requests
        SET status = 'completed', completed_at = ?, download_url = ?,
            file_size = ?, expires_at = ?,
            personal_data_count = ?, financial_data_count = ?, audit_trail_count = ?
        WHERE id = ?
      `).bind(
        Date.now(),
        downloadUrl,
        exportContent.length,
        expiresAt,
        exportData.personalData.length,
        exportData.financialData.length,
        exportData.auditTrails.length,
        exportId
      ).run();

      const duration = Date.now() - startTime;
      this.logger.info('GDPR export completed successfully', {
        exportId,
        duration,
        personalDataCount: exportData.personalData.length,
        financialDataCount: exportData.financialData.length,
        auditTrailCount: exportData.auditTrails.length,
        fileSize: exportContent.length
      });

    } catch (error) {
      await this.updateExportStatus(exportId, 'failed', error instanceof Error ? error.message : 'Unknown error');
      throw error;
    }
  }

  /**
   * Collect personal data
   */
  private async collectPersonalData(request: GDPRExportRequest): Promise<PersonalDataRecord[]> {
    const personalData: PersonalDataRecord[] = [];

    // Collect customer data
    const customers = await this.db.prepare(`
      SELECT * FROM customers
      WHERE business_id = ?
      ${request.dateRange ? 'AND created_at BETWEEN ? AND ?' : ''}
    `).bind(
      request.businessId,
      ...(request.dateRange ? [request.dateRange.startDate, request.dateRange.endDate] : [])
    ).all();

    for (const customer of customers.results || []) {
      personalData.push({
        entityType: 'customer',
        entityId: customer.id,
        dataFields: {
          name: customer.name,
          email: customer.email,
          phone: customer.phone,
          address: customer.address,
          taxId: customer.tax_id
        },
        source: 'customer_management',
        collectedAt: customer.created_at,
        lastModified: customer.updated_at,
        legalBasis: 'contract',
        processingPurpose: 'customer_relationship_management'
      });
    }

    // Add more personal data collection logic here for vendors, employees, etc.

    return personalData;
  }

  /**
   * Collect financial data
   */
  private async collectFinancialData(request: GDPRExportRequest): Promise<FinancialDataRecord[]> {
    const financialData: FinancialDataRecord[] = [];

    // Collect invoice data
    const invoices = await this.db.prepare(`
      SELECT * FROM invoices
      WHERE business_id = ?
      ${request.dateRange ? 'AND created_at BETWEEN ? AND ?' : ''}
    `).bind(
      request.businessId,
      ...(request.dateRange ? [request.dateRange.startDate, request.dateRange.endDate] : [])
    ).all();

    for (const invoice of invoices.results || []) {
      financialData.push({
        recordType: 'invoice',
        recordId: invoice.id,
        data: {
          invoiceNumber: invoice.invoice_number,
          customerName: invoice.customer_name,
          amount: invoice.total,
          currency: invoice.currency,
          status: invoice.status,
          issueDate: invoice.issue_date,
          dueDate: invoice.due_date
        },
        createdAt: invoice.created_at,
        lastModified: invoice.updated_at,
        relatedPersons: [invoice.customer_id]
      });
    }

    // Add more financial data collection logic here

    return financialData;
  }

  /**
   * Collect audit trails
   */
  private async collectAuditTrails(request: GDPRExportRequest): Promise<AuditTrailRecord[]> {
    const auditTrails: AuditTrailRecord[] = [];

    const audits = await this.db.prepare(`
      SELECT * FROM audit_logs
      WHERE business_id = ?
      ${request.dateRange ? 'AND created_at BETWEEN ? AND ?' : ''}
      ORDER BY created_at DESC
    `).bind(
      request.businessId,
      ...(request.dateRange ? [request.dateRange.startDate, request.dateRange.endDate] : [])
    ).all();

    for (const audit of audits.results || []) {
      auditTrails.push({
        action: audit.action,
        entityType: audit.entity_type,
        entityId: audit.entity_id,
        performedBy: audit.performed_by,
        performedAt: audit.performed_at,
        changes: audit.changes ? JSON.parse(audit.changes) : {},
        ipAddress: audit.ip_address,
        userAgent: audit.user_agent
      });
    }

    return auditTrails;
  }

  /**
   * Format export data
   */
  private formatExportData(
    data: { personalData: PersonalDataRecord[]; financialData: FinancialDataRecord[]; auditTrails: AuditTrailRecord[] },
    format: string
  ): string {
    const exportData = {
      metadata: {
        exportedAt: new Date().toISOString(),
        format,
        version: '1.0.0'
      },
      personalData: data.personalData,
      financialData: data.financialData,
      auditTrails: data.auditTrails
    };

    switch (format) {
      case 'JSON':
        return JSON.stringify(exportData, null, 2);

      case 'CSV':
        return this.convertToCSV(exportData);

      case 'XML':
        return this.convertToXML(exportData);

      default:
        throw new Error(`Unsupported export format: ${format}`);
    }
  }

  /**
   * Convert to CSV format
   */
  private convertToCSV(data: any): string {
    const sections = [];

    // Personal Data CSV
    if (data.personalData.length > 0) {
      sections.push('PERSONAL DATA\n');
      sections.push('Entity Type,Entity ID,Name,Email,Phone,Source,Collected At,Legal Basis\n');
      for (const record of data.personalData) {
        sections.push([
          record.entityType,
          record.entityId,
          record.dataFields.name || '',
          record.dataFields.email || '',
          record.dataFields.phone || '',
          record.source,
          new Date(record.collectedAt).toISOString(),
          record.legalBasis
        ].join(',') + '\n');
      }
      sections.push('\n');
    }

    // Financial Data CSV
    if (data.financialData.length > 0) {
      sections.push('FINANCIAL DATA\n');
      sections.push('Record Type,Record ID,Customer Name,Amount,Currency,Created At\n');
      for (const record of data.financialData) {
        sections.push([
          record.recordType,
          record.recordId,
          record.data.customerName || '',
          record.data.amount || '',
          record.data.currency || '',
          new Date(record.createdAt).toISOString()
        ].join(',') + '\n');
      }
      sections.push('\n');
    }

    // Audit Trails CSV
    if (data.auditTrails.length > 0) {
      sections.push('AUDIT TRAILS\n');
      sections.push('Action,Entity Type,Entity ID,Performed By,Performed At\n');
      for (const record of data.auditTrails) {
        sections.push([
          record.action,
          record.entityType,
          record.entityId,
          record.performedBy,
          new Date(record.performedAt).toISOString()
        ].join(',') + '\n');
      }
    }

    return sections.join('');
  }

  /**
   * Convert to XML format
   */
  private convertToXML(data: any): string {
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<gdpr_export>\n';
    xml += `  <metadata>\n`;
    xml += `    <exported_at>${data.metadata.exportedAt}</exported_at>\n`;
    xml += `    <format>${data.metadata.format}</format>\n`;
    xml += `    <version>${data.metadata.version}</version>\n`;
    xml += `  </metadata>\n`;

    // Add personal data
    xml += '  <personal_data>\n';
    for (const record of data.personalData) {
      xml += '    <record>\n';
      xml += `      <entity_type>${record.entityType}</entity_type>\n`;
      xml += `      <entity_id>${record.entityId}</entity_id>\n`;
      xml += `      <legal_basis>${record.legalBasis}</legal_basis>\n`;
      xml += '    </record>\n';
    }
    xml += '  </personal_data>\n';

    xml += '</gdpr_export>';
    return xml;
  }

  /**
   * Get content type for format
   */
  private getContentType(format: string): string {
    switch (format) {
      case 'JSON':
        return 'application/json';
      case 'CSV':
        return 'text/csv';
      case 'XML':
        return 'application/xml';
      default:
        return 'application/octet-stream';
    }
  }

  /**
   * Update export status
   */
  private async updateExportStatus(exportId: string, status: string, errorMessage?: string): Promise<void> {
    await this.db.prepare(`
      UPDATE gdpr_export_requests
      SET status = ?, error_message = ?, completed_at = ?
      WHERE id = ?
    `).bind(status, errorMessage || null, Date.now(), exportId).run();
  }

  /**
   * Extract filename from URL
   */
  private extractFileNameFromUrl(url: string): string {
    return url.split('/').pop() || '';
  }

  /**
   * Map database row to export result
   */
  private mapToExportResult(row: any): GDPRExportResult {
    return {
      exportId: row.id,
      status: row.status,
      requestDetails: {
        businessId: row.business_id,
        requestedBy: row.requested_by,
        requestedAt: row.requested_at,
        purpose: row.purpose,
        includePersonalData: Boolean(row.include_personal_data),
        includeFinancialData: Boolean(row.include_financial_data),
        includeAuditTrails: Boolean(row.include_audit_trails),
        dateRange: row.date_range_start ? {
          startDate: row.date_range_start,
          endDate: row.date_range_end
        } : undefined,
        exportFormat: row.export_format,
        deliveryMethod: row.delivery_method,
        retentionDays: row.retention_days
      },
      generatedAt: row.created_at,
      completedAt: row.completed_at,
      downloadUrl: row.download_url,
      fileSize: row.file_size,
      recordCounts: {
        personalData: row.personal_data_count || 0,
        financialData: row.financial_data_count || 0,
        auditTrails: row.audit_trail_count || 0
      },
      expiresAt: row.expires_at,
      errorMessage: row.error_message
    };
  }
}