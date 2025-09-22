/**
 * Aging Reports Generator
 * Generates comprehensive aging reports for Accounts Receivable and Payable
 */

import type { D1Database } from '@cloudflare/workers-types';
import { Logger } from '../../shared/logger';
import {
  AgingReportSummary,
  AgingSummary,
  AgingDetail,
  AgingBuckets,
  AgingInvoice,
  AgingBucket,
  ReportParameters,
  ReportInfo,
  Customer,
  Invoice,
  InvoiceStatus
} from './types';
import { validateBusinessId, roundToCurrency, formatDate } from './utils';

export interface VendorBill {
  id: string;
  billNumber: string;
  vendorId: string;
  vendorName: string;
  issueDate: number;
  dueDate: number;
  total: number;
  balanceDue: number;
  status: string;
}

export class AgingReportsGenerator {
  private logger: Logger;
  private db: D1Database;

  constructor(db: D1Database) {
    this.logger = new Logger();
    this.db = db;
  }

  /**
   * Generate Accounts Receivable aging report
   */
  async generateARAgingReport(
    parameters: ReportParameters,
    businessId: string,
    businessName: string = 'Business'
  ): Promise<AgingReportSummary> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Generating AR Aging Report', {
        asOfDate: parameters.endDate,
        businessId: validBusinessId
      });

      // Generate report info
      const reportInfo = this.createReportInfo(parameters, businessName, 'Accounts Receivable');

      // Get outstanding invoices
      const outstandingInvoices = await this.getOutstandingInvoices(parameters, validBusinessId);

      // Build aging details by customer
      const details = await this.buildCustomerAgingDetails(outstandingInvoices, parameters.endDate, validBusinessId);

      // Calculate summary and totals
      const { summary, totals } = this.calculateAgingSummary(details);

      const report: AgingReportSummary = {
        reportInfo,
        summary,
        details,
        totals
      };

      this.logger.info('AR Aging Report generated successfully', {
        totalOutstanding: totals.total,
        customerCount: details.length,
        businessId: validBusinessId
      });

      return report;

    } catch (error) {
      this.logger.error('Failed to generate AR Aging Report', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Generate Accounts Payable aging report
   */
  async generateAPAgingReport(
    parameters: ReportParameters,
    businessId: string,
    businessName: string = 'Business'
  ): Promise<AgingReportSummary> {
    const validBusinessId = validateBusinessId(businessId);

    try {
      this.logger.info('Generating AP Aging Report', {
        asOfDate: parameters.endDate,
        businessId: validBusinessId
      });

      // Generate report info
      const reportInfo = this.createReportInfo(parameters, businessName, 'Accounts Payable');

      // Get outstanding bills
      const outstandingBills = await this.getOutstandingBills(parameters, validBusinessId);

      // Build aging details by vendor
      const details = await this.buildVendorAgingDetails(outstandingBills, parameters.endDate, validBusinessId);

      // Calculate summary and totals
      const { summary, totals } = this.calculateAgingSummary(details);

      const report: AgingReportSummary = {
        reportInfo,
        summary,
        details,
        totals
      };

      this.logger.info('AP Aging Report generated successfully', {
        totalOutstanding: totals.total,
        vendorCount: details.length,
        businessId: validBusinessId
      });

      return report;

    } catch (error) {
      this.logger.error('Failed to generate AP Aging Report', error, {
        businessId: validBusinessId
      });
      throw error;
    }
  }

  /**
   * Create report information header
   */
  private createReportInfo(
    parameters: ReportParameters,
    businessName: string,
    reportType: 'Accounts Receivable' | 'Accounts Payable'
  ): ReportInfo {
    return {
      title: `${reportType} Aging Report`,
      subtitle: `Outstanding ${reportType}`,
      businessName,
      periodDescription: `As of ${formatDate(parameters.endDate)}`,
      startDate: parameters.startDate,
      endDate: parameters.endDate,
      generatedAt: Date.now(),
      currency: parameters.currency || 'USD'
    };
  }

  /**
   * Get outstanding invoices for AR aging
   */
  private async getOutstandingInvoices(
    parameters: ReportParameters,
    businessId: string
  ): Promise<Invoice[]> {
    const result = await this.db.prepare(`
      SELECT
        i.id,
        i.invoice_number,
        i.customer_id,
        i.customer_name,
        i.customer_email,
        i.issue_date,
        i.due_date,
        i.total,
        i.balance_due,
        i.status,
        i.currency,
        c.email,
        c.phone,
        c.credit_limit
      FROM invoices i
      LEFT JOIN customers c ON i.customer_id = c.id
      WHERE i.business_id = ?
      AND i.status IN ('SENT', 'VIEWED', 'PARTIALLY_PAID', 'OVERDUE')
      AND i.balance_due > 0
      AND i.issue_date <= ?
      ${parameters.customerIds ? `AND i.customer_id IN (${parameters.customerIds.map(() => '?').join(',')})` : ''}
      ORDER BY i.customer_name, i.due_date
    `).bind(
      businessId,
      parameters.endDate,
      ...(parameters.customerIds || [])
    ).all();

    return (result.results || []).map(row => this.mapToInvoice(row));
  }

  /**
   * Get outstanding bills for AP aging
   */
  private async getOutstandingBills(
    parameters: ReportParameters,
    businessId: string
  ): Promise<VendorBill[]> {
    // Note: This would require a vendor bills table similar to invoices
    // For now, we'll return an empty array as a placeholder
    // In a real implementation, you'd have a vendor_bills table

    this.logger.warn('AP Aging Report: Vendor bills table not implemented', {
      businessId
    });

    return [];
  }

  /**
   * Build customer aging details
   */
  private async buildCustomerAgingDetails(
    invoices: Invoice[],
    asOfDate: number,
    businessId: string
  ): Promise<AgingDetail[]> {
    const customerMap = new Map<string, {
      customer: Customer;
      invoices: Invoice[];
    }>();

    // Group invoices by customer
    for (const invoice of invoices) {
      if (!customerMap.has(invoice.customerId)) {
        customerMap.set(invoice.customerId, {
          customer: {
            id: invoice.customerId,
            name: invoice.customerName,
            email: invoice.customerEmail,
            currency: invoice.currency,
            paymentTerms: { type: 'NET', netDays: 30, description: 'Net 30' }, // Default
            isActive: true,
            createdAt: Date.now(),
            updatedAt: Date.now(),
            businessId: businessId
          } as Customer,
          invoices: []
        });
      }

      customerMap.get(invoice.customerId)!.invoices.push(invoice);
    }

    const details: AgingDetail[] = [];

    for (const [customerId, { customer, invoices }] of customerMap) {
      const buckets: AgingBuckets = {
        current: 0,
        days1to30: 0,
        days31to60: 0,
        days61to90: 0,
        over90Days: 0,
        total: 0
      };

      const agingInvoices: AgingInvoice[] = [];

      for (const invoice of invoices) {
        const daysPastDue = Math.max(0, Math.floor((asOfDate - invoice.dueDate) / (1000 * 60 * 60 * 24)));
        const agingBucket = this.determineAgingBucket(daysPastDue);

        agingInvoices.push({
          invoiceId: invoice.id,
          invoiceNumber: invoice.invoiceNumber,
          date: invoice.issueDate,
          dueDate: invoice.dueDate,
          originalAmount: invoice.total,
          balanceAmount: invoice.balanceDue,
          daysPastDue,
          agingBucket
        });

        // Add to appropriate bucket
        switch (agingBucket) {
          case AgingBucket.CURRENT:
            buckets.current += invoice.balanceDue;
            break;
          case AgingBucket.DAYS_1_30:
            buckets.days1to30 += invoice.balanceDue;
            break;
          case AgingBucket.DAYS_31_60:
            buckets.days31to60 += invoice.balanceDue;
            break;
          case AgingBucket.DAYS_61_90:
            buckets.days61to90 += invoice.balanceDue;
            break;
          case AgingBucket.OVER_90_DAYS:
            buckets.over90Days += invoice.balanceDue;
            break;
        }

        buckets.total += invoice.balanceDue;
      }

      // Round all bucket amounts
      buckets.current = roundToCurrency(buckets.current);
      buckets.days1to30 = roundToCurrency(buckets.days1to30);
      buckets.days31to60 = roundToCurrency(buckets.days31to60);
      buckets.days61to90 = roundToCurrency(buckets.days61to90);
      buckets.over90Days = roundToCurrency(buckets.over90Days);
      buckets.total = roundToCurrency(buckets.total);

      details.push({
        entityId: customerId,
        entityName: customer.name,
        entityType: 'customer',
        contactInfo: {
          email: customer.email,
          phone: customer.phone
        },
        creditLimit: customer.creditLimit,
        buckets,
        invoices: agingInvoices
      });
    }

    // Sort by total outstanding (descending)
    details.sort((a, b) => b.buckets.total - a.buckets.total);

    return details;
  }

  /**
   * Build vendor aging details
   */
  private async buildVendorAgingDetails(
    bills: VendorBill[],
    asOfDate: number,
    businessId: string
  ): Promise<AgingDetail[]> {
    // Similar implementation to customer aging but for vendors
    // This would be implemented when vendor bills functionality is added
    return [];
  }

  /**
   * Calculate aging summary and totals
   */
  private calculateAgingSummary(details: AgingDetail[]): {
    summary: AgingSummary;
    totals: AgingBuckets;
  } {
    const totals: AgingBuckets = {
      current: 0,
      days1to30: 0,
      days31to60: 0,
      days61to90: 0,
      over90Days: 0,
      total: 0
    };

    let totalDaysOutstanding = 0;
    let totalInvoiceCount = 0;
    let largestOutstanding = {
      customerId: '',
      customerName: '',
      amount: 0
    };

    for (const detail of details) {
      // Add to totals
      totals.current += detail.buckets.current;
      totals.days1to30 += detail.buckets.days1to30;
      totals.days31to60 += detail.buckets.days31to60;
      totals.days61to90 += detail.buckets.days61to90;
      totals.over90Days += detail.buckets.over90Days;
      totals.total += detail.buckets.total;

      // Track largest outstanding
      if (detail.buckets.total > largestOutstanding.amount) {
        largestOutstanding = {
          customerId: detail.entityId,
          customerName: detail.entityName,
          amount: detail.buckets.total
        };
      }

      // Calculate weighted average days outstanding
      for (const invoice of detail.invoices) {
        totalDaysOutstanding += invoice.daysPastDue * invoice.balanceAmount;
        totalInvoiceCount++;
      }
    }

    // Round all totals
    totals.current = roundToCurrency(totals.current);
    totals.days1to30 = roundToCurrency(totals.days1to30);
    totals.days31to60 = roundToCurrency(totals.days31to60);
    totals.days61to90 = roundToCurrency(totals.days61to90);
    totals.over90Days = roundToCurrency(totals.over90Days);
    totals.total = roundToCurrency(totals.total);

    const averageDaysOutstanding = totals.total > 0 ? totalDaysOutstanding / totals.total : 0;

    const summary: AgingSummary = {
      totalOutstanding: totals.total,
      totalCustomers: details.length,
      averageDaysOutstanding: Math.round(averageDaysOutstanding),
      largestOutstanding
    };

    return { summary, totals };
  }

  /**
   * Determine aging bucket based on days past due
   */
  private determineAgingBucket(daysPastDue: number): AgingBucket {
    if (daysPastDue <= 0) {
      return AgingBucket.CURRENT;
    } else if (daysPastDue <= 30) {
      return AgingBucket.DAYS_1_30;
    } else if (daysPastDue <= 60) {
      return AgingBucket.DAYS_31_60;
    } else if (daysPastDue <= 90) {
      return AgingBucket.DAYS_61_90;
    } else {
      return AgingBucket.OVER_90_DAYS;
    }
  }

  /**
   * Get aging report with collection recommendations
   */
  async getAgingReportWithRecommendations(
    parameters: ReportParameters,
    businessId: string,
    businessName?: string
  ): Promise<AgingReportSummary & {
    recommendations: Array<{
      customerId: string;
      customerName: string;
      priority: 'HIGH' | 'MEDIUM' | 'LOW';
      action: string;
      reason: string;
      amount: number;
    }>;
  }> {
    const report = await this.generateARAgingReport(parameters, businessId, businessName);

    const recommendations = [];

    for (const detail of report.details) {
      let priority: 'HIGH' | 'MEDIUM' | 'LOW' = 'LOW';
      let action = '';
      let reason = '';

      // High priority: Over 90 days or large amounts
      if (detail.buckets.over90Days > 0 || detail.buckets.total > 10000) {
        priority = 'HIGH';
        if (detail.buckets.over90Days > 0) {
          action = 'Immediate collection action required';
          reason = `$${detail.buckets.over90Days.toFixed(2)} is over 90 days past due`;
        } else {
          action = 'Priority follow-up required';
          reason = `Large outstanding balance of $${detail.buckets.total.toFixed(2)}`;
        }
      }
      // Medium priority: 31-90 days past due
      else if (detail.buckets.days31to60 > 0 || detail.buckets.days61to90 > 0) {
        priority = 'MEDIUM';
        action = 'Send payment reminder';
        reason = `$${(detail.buckets.days31to60 + detail.buckets.days61to90).toFixed(2)} is 31+ days past due`;
      }
      // Low priority: 1-30 days past due
      else if (detail.buckets.days1to30 > 0) {
        priority = 'LOW';
        action = 'Send gentle reminder';
        reason = `$${detail.buckets.days1to30.toFixed(2)} is 1-30 days past due`;
      }

      if (action) {
        recommendations.push({
          customerId: detail.entityId,
          customerName: detail.entityName,
          priority,
          action,
          reason,
          amount: detail.buckets.total
        });
      }
    }

    // Sort recommendations by priority and amount
    recommendations.sort((a, b) => {
      const priorityOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 };
      if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
        return priorityOrder[b.priority] - priorityOrder[a.priority];
      }
      return b.amount - a.amount;
    });

    return {
      ...report,
      recommendations
    };
  }

  /**
   * Calculate aging statistics
   */
  calculateAgingStatistics(report: AgingReportSummary): {
    percentages: {
      current: number;
      days1to30: number;
      days31to60: number;
      days61to90: number;
      over90Days: number;
    };
    metrics: {
      daysOutstandingAverage: number;
      collectionEfficiency: number;
      riskScore: number;
    };
  } {
    const { totals } = report;

    // Calculate percentages
    const percentages = {
      current: totals.total > 0 ? (totals.current / totals.total) * 100 : 0,
      days1to30: totals.total > 0 ? (totals.days1to30 / totals.total) * 100 : 0,
      days31to60: totals.total > 0 ? (totals.days31to60 / totals.total) * 100 : 0,
      days61to90: totals.total > 0 ? (totals.days61to90 / totals.total) * 100 : 0,
      over90Days: totals.total > 0 ? (totals.over90Days / totals.total) * 100 : 0
    };

    // Round percentages
    for (const key in percentages) {
      percentages[key as keyof typeof
  percentages] = Math.round(percentages[key as keyof typeof percentages] * 100) / 100;
    }

    // Calculate metrics
    const daysOutstandingAverage = report.summary.averageDaysOutstanding;

    // Collection efficiency (percentage that's current or only slightly past due)
    const collectionEfficiency = percentages.current + (percentages.days1to30 * 0.5);

    // Risk score based on aging distribution (higher is worse)
    const riskScore = (percentages.days31to60 * 0.3) +
                     (percentages.days61to90 * 0.6) +
                     (percentages.over90Days * 1.0);

    return {
      percentages,
      metrics: {
        daysOutstandingAverage,
        collectionEfficiency: Math.round(collectionEfficiency * 100) / 100,
        riskScore: Math.round(riskScore * 100) / 100
      }
    };
  }

  /**
   * Map database row to Invoice
   */
  private mapToInvoice(row: any): Invoice {
    return {
      id: row.id,
      invoiceNumber: row.invoice_number,
      customerId: row.customer_id,
      customerName: row.customer_name,
      customerEmail: row.customer_email,
      issueDate: row.issue_date,
      dueDate: row.due_date,
      currency: row.currency || 'USD',
      exchangeRate: 1.0,
      subtotal: 0,
      taxTotal: 0,
      discountTotal: 0,
      total: row.total,
      balanceDue: row.balance_due,
      status: row.status as InvoiceStatus,
      terms: { type: 'NET', netDays: 30, description: 'Net 30' }, // Default
      lines: [],
      approvalRequired: false,
      createdAt: Date.now(),
      createdBy: '',
      updatedAt: Date.now(),
      businessId: ''
    } as Invoice;
  }
}