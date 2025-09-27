/**
 * Report Export Manager
 * Handles export of financial reports to Excel/CSV with R2 storage
 */

import type { R2Bucket } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  FinancialReport,
  ExportFormat,
  ExportConfiguration,
  ProfitLossStatement,
  BalanceSheet,
  CashFlowStatement,
  AgingReportSummary,
  CustomReportResult
} from './types';
import { validateBusinessId, formatCurrency, formatDate } from './utils';

export interface ExportResult {
  url: string;
  filename: string;
  size: number;
  format: ExportFormat;
  generatedAt: number;
}

export // TODO: Consider splitting ReportExportManager into smaller, focused classes
class ReportExportManager {
  private logger: Logger;
  private r2Bucket?: R2Bucket;

  constructor(r2Bucket?: R2Bucket) {
    this.logger = new Logger();
    this.r2Bucket = r2Bucket;
  }

  /**
   * Export financial report to specified format
   */
  async exportReport(
    report: FinancialReport,
    format: ExportFormat,
    configuration: ExportConfiguration,
    businessId: string
  ): Promise<ExportResult> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Exporting financial report', {
        reportId: report.id,
        format,
        businessId: validBusinessId
      });

      let exportData: ArrayBuffer;
      let contentType: string;
      let fileExtension: string;

      switch (format) {
        case ExportFormat.EXCEL:
          exportData = await this.exportToExcel(report, configuration);
          contentType = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
          fileExtension = 'xlsx';
          break;

        case ExportFormat.CSV:
          exportData = await this.exportToCSV(report, configuration);
          contentType = 'text/csv';
          fileExtension = 'csv';
          break;

        case ExportFormat.PDF:
          exportData = await this.exportToPDF(report, configuration);
          contentType = 'application/pdf';
          fileExtension = 'pdf';
          break;

        case ExportFormat.JSON:
          exportData = await this.exportToJSON(report, configuration);
          contentType = 'application/json';
          fileExtension = 'json';
          break;

        default:
          throw new Error(`Unsupported export format: ${format}`);
      }

      // Generate filename
      const timestamp = new Date().toISOString().slice(0, 10);
      const filename = configuration.filename ||
        `${report.name.replace(/[^a-zA-Z0-9]/g, '_')}_${timestamp}.${fileExtension}`;

      // Store in R2 if available
      let url = '';
      if (this.r2Bucket) {
        const r2Key = `reports/${validBusinessId}/${report.id}/${filename}`;

        await this.r2Bucket.put(r2Key, exportData, {
          httpMetadata: {
            contentType,
            cacheControl: 'public, max-age=86400'
          },
          customMetadata: {
            reportId: report.id,
            reportType: report.type,
            format,
            businessId: validBusinessId,
            generatedAt: Date.now().toString()
          }
        });

        url = `https://your-r2-domain.com/${r2Key}`;
      }

      const result: ExportResult = {
        url,
        filename,
        size: exportData.byteLength,
        format,
        generatedAt: Date.now()
      };

      this.logger.info('Report exported successfully', {
        reportId: report.id,
        format,
        filename,
        size: result.size,
        businessId: validBusinessId
      });

      return result;

    } catch (error: any) {
      this.logger.error('Failed to export report', error, {
        reportId: report.id,
        format,
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Export to Excel format
   */
  private async exportToExcel(
    report: FinancialReport,
    configuration: ExportConfiguration
  ): Promise<ArrayBuffer> {
    // This is a simplified implementation
    // In a real implementation, you would use a library like ExcelJS or similar

    try {
      const workbookData = this.generateExcelWorkbook(report, configuration);

      // Placeholder implementation - would use actual Excel library
      const response = await fetch('https://api.excel-converter.service/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer YOUR_API_KEY'
        },
        body: JSON.stringify({
          workbook: workbookData,
          options: {
            includeHeaders: configuration.includeHeaders !== false,
            includeMetadata: configuration.includeMetadata !== false
          }
        })
      });

      if (!response.ok) {
        throw new Error(`Excel generation failed: ${response.statusText}`);
      }

      return await response.arrayBuffer();

    } catch (error: any) {
      this.logger.error('Failed to generate Excel file', error);

      // Fallback: Generate CSV and convert to Excel format
      const csvData = await this.exportToCSV(report, configuration);
      return csvData; // Would be actual Excel conversion in real implementation
    }
  }

  /**
   * Export to CSV format
   */
  private async exportToCSV(
    report: FinancialReport,
    configuration: ExportConfiguration
  ): Promise<ArrayBuffer> {
    let csvContent = '';

    // Add metadata header if requested
    if (configuration.includeMetadata !== false) {
      csvContent += this.generateCSVMetadata(report);
      csvContent += '\n\n';
    }

    // Generate CSV based on report type
    switch (report.type) {
      case 'PROFIT_AND_LOSS':
        csvContent += this.generateProfitLossCSV(report.data as ProfitLossStatement, configuration);
        break;

      case 'BALANCE_SHEET':
        csvContent += this.generateBalanceSheetCSV(report.data as BalanceSheet, configuration);
        break;

      case 'CASH_FLOW':
        csvContent += this.generateCashFlowCSV(report.data as CashFlowStatement, configuration);
        break;

      case 'AGING_RECEIVABLES':
      case 'AGING_PAYABLES':
        csvContent += this.generateAgingReportCSV(report.data as AgingReportSummary, configuration);
        break;

      case 'CUSTOM':
        csvContent += this.generateCustomReportCSV(report.data as CustomReportResult, configuration);
        break;

      default:
        throw new Error(`Unsupported report type for CSV export: ${report.type}`);
    }

    return new TextEncoder().encode(csvContent).buffer;
  }

  /**
   * Export to PDF format
   */
  private async exportToPDF(
    report: FinancialReport,
    configuration: ExportConfiguration
  ): Promise<ArrayBuffer> {
    try {
      // Generate HTML content for PDF conversion
      const htmlContent = this.generateReportHTML(report, configuration);

      // Convert HTML to PDF using external service
      const response = await fetch('https://api.htmltopdf.service/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer YOUR_API_KEY'
        },
        body: JSON.stringify({
          html: htmlContent,
          options: {
            format: 'A4',
            margin: { top: '1cm', right: '1cm', bottom: '1cm', left: '1cm' },
            printBackground: true
          }
        })
      });

      if (!response.ok) {
        throw new Error(`PDF generation failed: ${response.statusText}`);
      }

      return await response.arrayBuffer();

    } catch (error: any) {
      this.logger.error('Failed to generate PDF', error);

      // Fallback: Return a simple text-based "PDF"
      const
  fallbackContent = `PDF Export Error\n\nReport: ${report.name}\nGenerated: ${formatDate(report.generatedAt)}`;
      return new TextEncoder().encode(fallbackContent).buffer;
    }
  }

  /**
   * Export to JSON format
   */
  private async exportToJSON(
    report: FinancialReport,
    configuration: ExportConfiguration
  ): Promise<ArrayBuffer> {
    const exportData = {
      report: {
        id: report.id,
        type: report.type,
        name: report.name,
        description: report.description,
        generatedAt: report.generatedAt,
        generatedBy: report.generatedBy,
        parameters: report.parameters
      },
      data: report.data,
      metadata: configuration.includeMetadata !== false ? {
        exportedAt: Date.now(),
        format: ExportFormat.JSON,
        version: '1.0'
      } : undefined
    };

    const jsonString = JSON.stringify(exportData, null, 2);
    return new TextEncoder().encode(jsonString).buffer;
  }

  /**
   * Generate Excel workbook structure
   */
  private generateExcelWorkbook(report: FinancialReport, configuration: ExportConfiguration): any {
    // This would return actual Excel workbook structure
    // For now, returning a simplified structure
    return {
      sheets: [
        {
          name: report.name,
          data: this.convertReportDataToTabular(report),
          formatting: {
            headerStyle: {
              bold: true,
              backgroundColor: '#4472C4',
              fontColor: '#FFFFFF'
            }
          }
        }
      ],
      metadata: {
        title: report.name,
        author: 'CoreFlow360',
        created: new Date(report.generatedAt).toISOString()
      }
    };
  }

  /**
   * Generate CSV metadata header
   */
  private generateCSVMetadata(report: FinancialReport): string {
    return [
      `"Report Name","${report.name}"`,
      `"Report Type","${report.type}"`,
      `"Generated At","${formatDate(report.generatedAt)}"`,
      `"Generated By","${report.generatedBy}"`,
      `"Period","${formatDate(report.parameters.startDate)} - ${formatDate(report.parameters.endDate)}"`
    ].join('\n');
  }

  /**
   * Generate Profit & Loss CSV
   */
  private generateProfitLossCSV(data: ProfitLossStatement, configuration: ExportConfiguration): string {
    const rows: string[] = [];

    if (configuration.includeHeaders !== false) {
      rows.push('"Account","Amount"');
    }

    // Revenue section
    rows.push(`"${data.revenue.title}",""`);
    for (const account of data.revenue.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.revenue.subtotal.description}","${formatCurrency(data.revenue.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Cost of Goods Sold
    rows.push(`"${data.costOfGoodsSold.title}",""`);
    for (const account of data.costOfGoodsSold.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.costOfGoodsSold.subtotal.description}","${formatCurrency(data.costOfGoodsSold.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Gross Profit
    rows.push(`"${data.grossProfit.description}","${formatCurrency(data.grossProfit.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Operating Expenses
    rows.push(`"${data.operatingExpenses.title}",""`);
    for (const account of data.operatingExpenses.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.operatingExpenses.subtotal.description}","${formatCurrency(data.operatingExpenses.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Net Income
    rows.push(`"${data.netIncome.description}","${formatCurrency(data.netIncome.amount, data.reportInfo.currency)}"`);

    return rows.join('\n');
  }

  /**
   * Generate Balance Sheet CSV
   */
  private generateBalanceSheetCSV(data: BalanceSheet, configuration: ExportConfiguration): string {
    const rows: string[] = [];

    if (configuration.includeHeaders !== false) {
      rows.push('"Account","Amount"');
    }

    // Assets
    rows.push('"ASSETS",""');

    // Current Assets
    rows.push(`"${data.assets.currentAssets.title}",""`);
    for (const account of data.assets.currentAssets.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.assets.currentAssets.subtotal.description}","${formatCurrency(data.assets.currentAssets.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Fixed Assets
    rows.push(`"${data.assets.fixedAssets.title}",""`);
    for (const account of data.assets.fixedAssets.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.assets.fixedAssets.subtotal.description}","${formatCurrency(data.assets.fixedAssets.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Total Assets
    rows.push(`"${data.totalAssets.description}","${formatCurrency(data.totalAssets.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Liabilities
    rows.push('"LIABILITIES",""');

    // Current Liabilities
    rows.push(`"${data.liabilities.currentLiabilities.title}",""`);
    for (const account of data.liabilities.currentLiabilities.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.liabilities.currentLiabilities.subtotal.description}","${formatCurrency(data.liabilities.currentLiabilities.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Total Liabilities
    rows.push(`"${data.liabilities.totalLiabilities.description}","${formatCurrency(data.liabilities.totalLiabilities.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Equity
    rows.push('"EQUITY",""');
    rows.push(`"${data.equity.ownersEquity.title}",""`);
    for (const account of data.equity.ownersEquity.accounts) {
      rows.push(`"  ${account.description}","${formatCurrency(account.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.equity.retainedEarnings.description}","${formatCurrency(data.equity.retainedEarnings.amount, data.reportInfo.currency)}"`);
    rows.push(`"${data.equity.totalEquity.description}","${formatCurrency(data.equity.totalEquity.amount, data.reportInfo.currency)}"`);

    return rows.join('\n');
  }

  /**
   * Generate Cash Flow CSV
   */
  private generateCashFlowCSV(data: CashFlowStatement, configuration: ExportConfiguration): string {
    const rows: string[] = [];

    if (configuration.includeHeaders !== false) {
      rows.push('"Activity","Amount"');
    }

    // Operating Activities
    rows.push(`"${data.operatingActivities.title}",""`);
    for (const item of data.operatingActivities.items) {
      rows.push(`"  ${item.description}","${formatCurrency(item.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.operatingActivities.subtotal.description}","${formatCurrency(data.operatingActivities.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Investing Activities
    rows.push(`"${data.investingActivities.title}",""`);
    for (const item of data.investingActivities.items) {
      rows.push(`"  ${item.description}","${formatCurrency(item.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.investingActivities.subtotal.description}","${formatCurrency(data.investingActivities.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Financing Activities
    rows.push(`"${data.financingActivities.title}",""`);
    for (const item of data.financingActivities.items) {
      rows.push(`"  ${item.description}","${formatCurrency(item.amount, data.reportInfo.currency)}"`);
    }
    rows.push(`"${data.financingActivities.subtotal.description}","${formatCurrency(data.financingActivities.subtotal.amount, data.reportInfo.currency)}"`);
    rows.push('""');

    // Net Cash Flow
    rows.push(`"${data.netCashFlow.description}","${formatCurrency(data.netCashFlow.amount, data.reportInfo.currency)}"`);

    return rows.join('\n');
  }

  /**
   * Generate Aging Report CSV
   */
  private generateAgingReportCSV(data: AgingReportSummary, configuration: ExportConfiguration): string {
    const rows: string[] = [];

    if (configuration.includeHeaders !== false) {
      rows.push('"Customer/Vendor","Current","1-30 Days","31-60 Days","61-90 Days","Over 90 Days","Total"');
    }

    for (const detail of data.details) {
      rows.push([
        `"${detail.entityName}"`,
        `"${formatCurrency(detail.buckets.current, data.reportInfo.currency)}"`,
        `"${formatCurrency(detail.buckets.days1to30, data.reportInfo.currency)}"`,
        `"${formatCurrency(detail.buckets.days31to60, data.reportInfo.currency)}"`,
        `"${formatCurrency(detail.buckets.days61to90, data.reportInfo.currency)}"`,
        `"${formatCurrency(detail.buckets.over90Days, data.reportInfo.currency)}"`,
        `"${formatCurrency(detail.buckets.total, data.reportInfo.currency)}"`
      ].join(','));
    }

    // Add totals row
    rows.push('""');
    rows.push([
      '"TOTALS"',
      `"${formatCurrency(data.totals.current, data.reportInfo.currency)}"`,
      `"${formatCurrency(data.totals.days1to30, data.reportInfo.currency)}"`,
      `"${formatCurrency(data.totals.days31to60, data.reportInfo.currency)}"`,
      `"${formatCurrency(data.totals.days61to90, data.reportInfo.currency)}"`,
      `"${formatCurrency(data.totals.over90Days, data.reportInfo.currency)}"`,
      `"${formatCurrency(data.totals.total, data.reportInfo.currency)}"`
    ].join(','));

    return rows.join('\n');
  }

  /**
   * Generate Custom Report CSV
   */
  private generateCustomReportCSV(data: CustomReportResult, configuration: ExportConfiguration): string {
    const rows: string[] = [];

    if (configuration.includeHeaders !== false) {
      const headers = data.columns.map((col: any) => `"${col.name}"`);
      rows.push(headers.join(','));
    }

    for (const row of data.rows) {
      const values = data.columns.map((col: any) => {
        const value = row[col.id];
        if (value === null || value === undefined) {
          return '""';
        }
        if (typeof value === 'number' && col.format?.type === 'currency') {
          return `"${formatCurrency(value, col.format.currencySymbol || 'USD')}"`;
        }
        return `"${String(value)}"`;
      });
      rows.push(values.join(','));
    }

    return rows.join('\n');
  }

  /**
   * Generate HTML for PDF conversion
   */
  private generateReportHTML(report: FinancialReport, configuration: ExportConfiguration): string {
    // This would generate formatted HTML for PDF conversion
    // For now, returning a basic structure
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <title>${report.name}</title>
        <style>
          body { font-family: Arial, sans-serif; }
          .header { text-align: center; margin-bottom: 30px; }
          .data-table { width: 100%; border-collapse: collapse; }
          .data-table th, .data-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
          .data-table th { background-color: #f2f2f2; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>${report.name}</h1>
          <p>Generated: ${formatDate(report.generatedAt)}</p>
        </div>
        <div class="content">
          ${this.generateHTMLContent(report)}
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Generate HTML content based on report type
   */
  private generateHTMLContent(report: FinancialReport): string {
    // This would generate specific HTML based on report type
    return '<p>Report data would be formatted here...</p>';
  }

  /**
   * Convert report data to tabular format
   */
  private convertReportDataToTabular(report: FinancialReport): any[][] {
    // This would convert the report data to a tabular format for Excel
    // For now, returning a simple structure
    return [
      ['Report Name', report.name],
      ['Generated At', formatDate(report.generatedAt)],
      ['Report Type', report.type]
    ];
  }

  /**
   * Delete exported report from R2
   */
  async deleteExport(
    reportId: string,
    filename: string,
    businessId: string
  ): Promise<void> {
    if (!this.r2Bucket) {
      return;
    }

    const validBusinessId = validateBusinessId(businessId);

    try {
      const r2Key = `reports/${validBusinessId}/${reportId}/${filename}`;
      await this.r2Bucket.delete(r2Key);

      this.logger.info('Export deleted from R2', {
        reportId,
        filename,
        businessId: validBusinessId
      });

    } catch (error: any) {
      this.logger.error('Failed to delete export from R2', error, {
        reportId,
        filename,
        businessId: validBusinessId
      });
      throw error;
    }
  }
}