/**
 * Financial Reporting Engine
 * Central orchestrator for all financial reports with business_id isolation
 */

import type { D1Database, R2Bucket } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import { FinanceAuditLogger } from './audit-logger';
import { ProfitLossGenerator } from './profit-loss-generator';
import { BalanceSheetGenerator } from './balance-sheet-generator';
import { CashFlowGenerator } from './cash-flow-generator';
import { AgingReportsGenerator } from './aging-reports-generator';
import { CustomReportBuilder } from './custom-report-builder';
import { ReportExportManager } from './report-export-manager';
import {
  FinancialReport,
  FinancialReportType,
  ReportStatus,
  GenerateReportRequest,
  GenerateCustomReportRequest,
  ReportExportRequest,
  ExportFormat,
  ReportParameters
} from './types';
import { validateBusinessId } from './utils';
import {
  generateReportRequestSchema,
  reportParametersSchema,
  exportRequestSchema,
  validateInput,
  ValidationError
} from './validation';
import {
  RateLimiter,
  RateLimitError,
  RATE_LIMIT_CONFIGS,
  createRateLimitMiddleware
} from './rate-limiter';
import {
  ErrorHandler,
  BusinessLogicError,
  DatabaseTransactionError,
  ErrorCategory,
  ErrorSeverity,
  createErrorHandler
} from './error-handler';
import {
  PerformanceMonitor,
  getGlobalMonitor,
  Trace
} from './performance-monitor';

export class FinancialReportingEngine {
  private logger: Logger;
  private db: D1Database;
  private r2Bucket?: R2Bucket;
  private kv?: KVNamespace;
  private auditLogger: FinanceAuditLogger;
  private profitLossGenerator: ProfitLossGenerator;
  private balanceSheetGenerator: BalanceSheetGenerator;
  private cashFlowGenerator: CashFlowGenerator;
  private agingReportsGenerator: AgingReportsGenerator;
  private customReportBuilder: CustomReportBuilder;
  private exportManager: ReportExportManager;
  private reportRateLimiter: RateLimiter;
  private exportRateLimiter: RateLimiter;
  private performanceMonitor: PerformanceMonitor;

  constructor(
    db: D1Database,
    auditLogger: FinanceAuditLogger,
    r2Bucket?: R2Bucket,
    kv?: KVNamespace
  ) {
    this.logger = new Logger();
    this.db = db;
    this.r2Bucket = r2Bucket;
    this.kv = kv;
    this.auditLogger = auditLogger;

    // Initialize rate limiters
    this.reportRateLimiter = new RateLimiter(RATE_LIMIT_CONFIGS.reportGeneration);
    this.exportRateLimiter = new RateLimiter(RATE_LIMIT_CONFIGS.exports);

    // Initialize performance monitor
    this.performanceMonitor = getGlobalMonitor();

    // Initialize report generators
    this.profitLossGenerator = new ProfitLossGenerator(db);
    this.balanceSheetGenerator = new BalanceSheetGenerator(db);
    this.cashFlowGenerator = new CashFlowGenerator(db);
    this.agingReportsGenerator = new AgingReportsGenerator(db);
    this.customReportBuilder = new CustomReportBuilder(db);
    this.exportManager = new ReportExportManager(r2Bucket);
  }

  /**
   * Generate financial report with strict business_id isolation
   */
  @Trace('financial-report-generation')
  async generateReport(
    request: GenerateReportRequest,
    generatedBy: string,
    businessId: string
  ): Promise<FinancialReport> {
    const errorHandler = createErrorHandler();

    return errorHandler.executeWithErrorHandling(
      async () => {
        // Validate all inputs using Zod schemas
        const validatedRequest = validateInput(generateReportRequestSchema, {
          ...request,
          businessId
        });
        const validBusinessId = validatedRequest.businessId;

        // Check rate limit
        const rateLimitResult = await this.reportRateLimiter.checkLimit(
          validBusinessId,
          generatedBy,
          'report-generation',
          this.kv
        );

        if (!rateLimitResult.allowed) {
          throw new RateLimitError(
            'Too many report generation requests',
            rateLimitResult.retryAfter || 60,
            rateLimitResult.resetTime
          );
        }

        // Validate business access
        await this.validateBusinessAccess(validBusinessId, generatedBy);

        this.logger.info('Generating financial report', {
          type: request.type,
          businessId: validBusinessId,
          generatedBy
        });

        const reportId = `rpt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;

        // Create initial report record
        let report: FinancialReport = {
          id: reportId,
          type: request.type,
          name: this.getReportName(request.type),
          parameters: request.parameters,
          generatedAt: Date.now(),
          generatedBy,
          status: ReportStatus.GENERATING,
          data: null,
          businessId: validBusinessId
        };

        // Save initial report
        if (request.saveToHistory !== false) {
          await this.saveReport(report);
        }

        try {
          // Generate report data based on type
          const businessName = await this.getBusinessName(validBusinessId);
          let reportData: any;

          switch (request.type) {
            case FinancialReportType.PROFIT_AND_LOSS:
              reportData = await this.profitLossGenerator.generateProfitLoss(
                request.parameters,
                validBusinessId,
                businessName
              );
              break;

          case FinancialReportType.BALANCE_SHEET:
            reportData = await this.balanceSheetGenerator.generateBalanceSheet(
              request.parameters,
              validBusinessId,
              businessName
            );
            break;

          case FinancialReportType.CASH_FLOW:
            reportData = await this.cashFlowGenerator.generateCashFlowStatement(
              request.parameters,
              validBusinessId,
              businessName
            );
            break;

          case FinancialReportType.AGING_RECEIVABLES:
            reportData = await this.agingReportsGenerator.generateARAgingReport(
              request.parameters,
              validBusinessId,
              businessName
            );
            break;

          case FinancialReportType.AGING_PAYABLES:
            reportData = await this.agingReportsGenerator.generateAPAgingReport(
              request.parameters,
              validBusinessId,
              businessName
            );
            break;

          case FinancialReportType.TRIAL_BALANCE:
            // Would use existing trial balance generator
            throw new Error('Trial balance report not implemented in this engine');

          default:
            throw new Error(`Unsupported report type: ${request.type}`);
        }

        // Update report with generated data
        report.data = reportData;
        report.status = ReportStatus.COMPLETED;

        // Generate exports if requested
        if (request.exportFormats && request.exportFormats.length > 0) {
          const exportUrls: Record<string, string> = {};

          for (const format of request.exportFormats) {
            try {
              const exportResult = await this.exportManager.exportReport(
                report,
                format,
                { format },
                validBusinessId
              );
              exportUrls[format.toLowerCase()] = exportResult.url;
            } catch (exportError) {
              this.logger.error('Failed to generate export', exportError, {
                reportId,
                format,
                businessId: validBusinessId
              });
            }
          }

          report.exportUrls = exportUrls;
        }

        // Save completed report
        if (request.saveToHistory !== false) {
          await this.saveReport(report);
        }

        // Log audit trail
        await this.auditLogger.logAction(
          'report',
          reportId,
          'GENERATE',
          validBusinessId,
          generatedBy,
          {
            reportType: request.type,
            parameters: request.parameters,
            exportFormats: request.exportFormats
          }
        );

        this.logger.info('Financial report generated successfully', {
          reportId,
          type: request.type,
          businessId: validBusinessId
        });

        return report;

      } catch (error) {
        // Update report status to failed
        if (report) {
          report.status = ReportStatus.FAILED;
          if (request.saveToHistory !== false) {
            try {
              await this.saveReport(report);
            } catch (saveError) {
              this.logger.error('Failed to save failed report status', saveError);
            }
          }
        }
        throw error;
      }
    },
    {
      operation: 'generateReport',
      businessId,
      userId: generatedBy,
      additionalData: { reportType: request.type }
    },
    this.db
  );
  }

  /**
   * Generate custom report with business isolation
   */
  async generateCustomReport(
    request: GenerateCustomReportRequest,
    generatedBy: string,
    businessId: string
  ): Promise<FinancialReport> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Validate business access
      await this.validateBusinessAccess(validBusinessId, generatedBy);

      // Validate that report definition belongs to this business
      const reportDefinition = await this.customReportBuilder.getReportDefinition(
        request.definitionId,
        validBusinessId
      );

      if (!reportDefinition) {
        throw new Error('Report definition not found or access denied');
      }

      this.logger.info('Generating custom report', {
        definitionId: request.definitionId,
        name: reportDefinition.name,
        businessId: validBusinessId,
        generatedBy
      });

      const report = await this.customReportBuilder.executeCustomReport(
        request.definitionId,
        request.parameters,
        validBusinessId,
        generatedBy
      );

      // Generate exports if requested
      if (request.exportFormats && request.exportFormats.length > 0) {
        const exportUrls: Record<string, string> = {};

        for (const format of request.exportFormats) {
          try {
            const exportResult = await this.exportManager.exportReport(
              report,
              format,
              { format },
              validBusinessId
            );
            exportUrls[format.toLowerCase()] = exportResult.url;
          } catch (exportError) {
            this.logger.error('Failed to generate custom report export', exportError, {
              reportId: report.id,
              format,
              businessId: validBusinessId
            });
          }
        }

        report.exportUrls = exportUrls;
      }

      // Save report if requested
      if (request.saveToHistory !== false) {
        await this.saveReport(report);
      }

      // Log audit trail
      await this.auditLogger.logAction(
        'report',
        report.id,
        'GENERATE',
        validBusinessId,
        generatedBy,
        {
          reportType: 'CUSTOM',
          definitionId: request.definitionId,
          parameters: request.parameters
        }
      );

      this.logger.info('Custom report generated successfully', {
        reportId: report.id,
        definitionId: request.definitionId,
        businessId: validBusinessId
      });

      return report;

    } catch (error) {
      this.logger.error('Failed to generate custom report', error, {
        definitionId: request.definitionId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Export existing report with business isolation
   */
  @Trace('financial-report-export')
  async exportReport(
    request: ReportExportRequest,
    exportedBy: string,
    businessId: string
  ): Promise<{ url: string; filename: string }> {
    // Validate all inputs using Zod schemas
    const validatedRequest = validateInput(exportRequestSchema, {
      ...request,
      businessId
    });
    const validBusinessId = validatedRequest.businessId;

    // Check rate limit for exports
    const rateLimitResult = await this.exportRateLimiter.checkLimit(
      validBusinessId,
      exportedBy,
      'report-export',
      this.kv
    );

    if (!rateLimitResult.allowed) {
      throw new RateLimitError(
        'Too many export requests',
        rateLimitResult.retryAfter || 60,
        rateLimitResult.resetTime
      );
    }

    try {
      // Validate business access
      await this.validateBusinessAccess(validBusinessId, exportedBy);

      // Get report and validate business ownership
      const report = await this.getReport(request.reportId, validBusinessId);
      if (!report) {
        throw new Error('Report not found or access denied');
      }

      this.logger.info('Exporting report', {
        reportId: request.reportId,
        format: request.format,
        businessId: validBusinessId
      });

      const exportResult = await this.exportManager.exportReport(
        report,
        request.format,
        request.configuration || { format: request.format },
        validBusinessId
      );

      // Log audit trail
      await this.auditLogger.logAction(
        'report',
        request.reportId,
        'EXPORT',
        validBusinessId,
        exportedBy,
        {
          format: request.format,
          filename: exportResult.filename
        }
      );

      this.logger.info('Report exported successfully', {
        reportId: request.reportId,
        format: request.format,
        filename: exportResult.filename,
        businessId: validBusinessId
      });

      return {
        url: exportResult.url,
        filename: exportResult.filename
      };

    } catch (error) {
      this.logger.error('Failed to export report', error, {
        reportId: request.reportId,
        format: request.format,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Get report with business isolation
   */
  async getReport(reportId: string, businessId: string): Promise<FinancialReport | null> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      const result = await this.db.prepare(`
        SELECT * FROM financial_reports
        WHERE id = ? AND business_id = ?
      `).bind(reportId, validBusinessId).first();

      if (!result) {
        return null;
      }

      return this.mapToFinancialReport(result);

    } catch (error) {
      this.logger.error('Failed to get report', error, {
        reportId,
        businessId: validBusinessId
      });
      return null;
    }
  }

  /**
   * List reports for business
   */
  async listReports(
    businessId: string,
    options?: {
      type?: FinancialReportType;
      status?: ReportStatus;
      startDate?: number;
      endDate?: number;
      limit?: number;
      offset?: number;
    }
  ): Promise<{ reports: FinancialReport[]; total: number }> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      let whereConditions = ['business_id = ?'];
      let params: any[] = [validBusinessId];

      if (options?.type) {
        whereConditions.push('type = ?');
        params.push(options.type);
      }

      if (options?.status) {
        whereConditions.push('status = ?');
        params.push(options.status);
      }

      if (options?.startDate) {
        whereConditions.push('generated_at >= ?');
        params.push(options.startDate);
      }

      if (options?.endDate) {
        whereConditions.push('generated_at <= ?');
        params.push(options.endDate);
      }

      const whereClause = whereConditions.join(' AND ');

      // Get total count
      const countResult = await this.db.prepare(`
        SELECT COUNT(*) as count
        FROM financial_reports
        WHERE ${whereClause}
      `).bind(...params).first();

      const total = (countResult?.count as number) || 0;

      // Get reports
      let query = `
        SELECT * FROM financial_reports
        WHERE ${whereClause}
        ORDER BY generated_at DESC
      `;

      if (options?.limit) {
        query += ` LIMIT ${options.limit}`;
        if (options?.offset) {
          query += ` OFFSET ${options.offset}`;
        }
      }

      const result = await this.db.prepare(query).bind(...params).all();

      const reports = (result.results || []).map(row => this.mapToFinancialReport(row));

      return { reports, total };

    } catch (error) {
      this.logger.error('Failed to list reports', error, {
        businessId: validBusinessId
      });
      return { reports: [], total: 0 };
    }
  }

  /**
   * Delete report with business isolation
   */
  async deleteReport(
    reportId: string,
    deletedBy: string,
    businessId: string
  ): Promise<void> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      // Validate business access
      await this.validateBusinessAccess(validBusinessId, deletedBy);

      // Verify report exists and belongs to business
      const report = await this.getReport(reportId, validBusinessId);
      if (!report) {
        throw new Error('Report not found or access denied');
      }

      // Delete from database
      await this.db.prepare(`
        DELETE FROM financial_reports
        WHERE id = ? AND business_id = ?
      `).bind(reportId, validBusinessId).run();

      // Delete exports from R2 if they exist
      if (report.exportUrls) {
        for (const [format, url] of Object.entries(report.exportUrls)) {
          try {
            const filename = url.split('/').pop() || '';
            await this.exportManager.deleteExport(reportId, filename, validBusinessId);
          } catch (exportError) {
            this.logger.warn('Failed to delete export file', exportError);
          }
        }
      }

      // Log audit trail
      await this.auditLogger.logAction(
        'report',
        reportId,
        'DELETE',
        validBusinessId,
        deletedBy,
        {
          reportType: report.type,
          reportName: report.name
        }
      );

      this.logger.info('Report deleted successfully', {
        reportId,
        businessId: validBusinessId
      });

    } catch (error) {
      this.logger.error('Failed to delete report', error, {
        reportId,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Validate business access (placeholder - would integrate with auth system)
   */
  private async validateBusinessAccess(businessId: string, userId: string): Promise<void> {
    // In a real implementation, this would verify that the user has access to the business
    // For now, we'll just validate that the businessId is properly formatted
    if (!businessId || businessId.length < 3) {
      throw new Error('Invalid business ID');
    }
  }

  /**
   * Get business name
   */
  private async getBusinessName(businessId: string): Promise<string> {
    try {
      // This would typically query a businesses table
      // For now, return a placeholder
      return `Business ${businessId.substring(0, 8)}`;
    } catch (error) {
      return 'Business';
    }
  }

  /**
   * Get report name based on type
   */
  private getReportName(type: FinancialReportType): string {
    switch (type) {
      case FinancialReportType.PROFIT_AND_LOSS:
        return 'Profit & Loss Statement';
      case FinancialReportType.BALANCE_SHEET:
        return 'Balance Sheet';
      case FinancialReportType.CASH_FLOW:
        return 'Cash Flow Statement';
      case FinancialReportType.AGING_RECEIVABLES:
        return 'Accounts Receivable Aging';
      case FinancialReportType.AGING_PAYABLES:
        return 'Accounts Payable Aging';
      case FinancialReportType.TRIAL_BALANCE:
        return 'Trial Balance';
      case FinancialReportType.GENERAL_LEDGER:
        return 'General Ledger';
      default:
        return 'Financial Report';
    }
  }

  /**
   * Save report to database
   */
  private async saveReport(report: FinancialReport): Promise<void> {
    await this.db.prepare(`
      INSERT OR REPLACE INTO financial_reports (
        id, type, name, description, parameters, generated_at,
        generated_by, status, data, export_urls, business_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      report.id,
      report.type,
      report.name,
      report.description || null,
      JSON.stringify(report.parameters),
      report.generatedAt,
      report.generatedBy,
      report.status,
      report.data ? JSON.stringify(report.data) : null,
      report.exportUrls ? JSON.stringify(report.exportUrls) : null,
      report.businessId
    ).run();
  }

  /**
   * Map database row to FinancialReport
   */
  private mapToFinancialReport(row: any): FinancialReport {
    return {
      id: row.id,
      type: row.type as FinancialReportType,
      name: row.name,
      description: row.description || undefined,
      parameters: JSON.parse(row.parameters),
      generatedAt: row.generated_at,
      generatedBy: row.generated_by,
      status: row.status as ReportStatus,
      data: row.data ? JSON.parse(row.data) : null,
      exportUrls: row.export_urls ? JSON.parse(row.export_urls) : undefined,
      businessId: row.business_id
    };
  }
}